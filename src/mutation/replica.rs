//! Replication writes (standby / follow mode). The only code that writes
//! replicated data on a standby, and the promotion record.
//!
//! These methods skip the per-user permission checks of the API (the data
//! comes from the primary, where they were enforced) but keep the
//! structure of every other write:
//! - DNS changes from the primary are applied with [`replay::apply`] and
//!   written to the local changelog with the primary's offsets, payloads,
//!   actors and transaction ids, in the same SQLite transaction (so a
//!   promoted standby continues the same offset sequence).
//! - Snapshot loads, account syncs, history adoption and promotions write
//!   an audit row (`replication.*`, counts only, never secrets) in the same
//!   transaction as the data.
//!
//! The standby's own `[root]` user from its config file stays local: when
//! the primary has a user with the same name, the two are merged (the
//! primary's id, so its tokens and zone ownership apply; the local
//! password, MFA and recovery codes); otherwise the local root is kept as
//! an extra account next to the replicated ones (moved to a negative id if
//! the primary's ids would collide with it). Other replicated users never
//! carry `is_root` on a standby.

use super::accounts::AuditTx;
use super::replay;
use super::sql;
use super::{Change, MResult, MutationError, Mutator, TOKEN};
use crate::model::{Actor, ChangeEvent};
use crate::replication::data;
use crate::replication::types::*;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// The standby's `[root]` from its own config file.
#[derive(Clone)]
pub struct LocalRoot {
    pub username: String,
    pub password_hash: String,
    pub mfa_required: bool,
}

impl std::fmt::Debug for LocalRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalRoot")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// What an account sync changed (counts only; goes into the audit row).
#[derive(Debug, Default, Clone, Serialize)]
pub struct AccountsSyncSummary {
    pub users: usize,
    pub users_added: usize,
    pub users_updated: usize,
    pub users_removed: usize,
    pub tokens: usize,
    pub recovery_codes: usize,
    pub tsig_keys: usize,
    pub settings: Vec<String>,
    /// `merged` (the primary has a user named like the local root) or `local`.
    pub local_root: &'static str,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct BootstrapSummary {
    pub offset: i64,
    pub zones: usize,
    pub records: usize,
    pub members: usize,
    pub accounts: AccountsSyncSummary,
}

// ---- replication_state ----------------------------------------------------

pub(crate) const K_HISTORY: &str = "history_id";
pub(crate) const K_PARENT: &str = "parent_history_id";
pub(crate) const K_FORK: &str = "fork_offset";
pub(crate) const K_PROMOTED_AT: &str = "promoted_at";
pub(crate) const K_PROMOTED_FROM: &str = "promoted_from";
/// The primary this database is a standby of (set at bootstrap, cleared by
/// promotion). A database with this key but no `[follow]` in the config was
/// un-followed by hand: startup records a promotion.
pub(crate) const K_FOLLOWING: &str = "following";
/// Checksum of the account data last applied from the primary.
pub(crate) const K_ACCOUNTS_CHECKSUM: &str = "accounts_checksum";

fn set_state(c: &Connection, key: &str, value: Option<&str>) -> Result<()> {
    match value {
        Some(v) => c.execute(
            "INSERT INTO replication_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, v],
        )?,
        None => c.execute("DELETE FROM replication_state WHERE key = ?1", params![key])?,
    };
    Ok(())
}

fn set_history(c: &Connection, h: &History) -> Result<()> {
    set_state(c, K_HISTORY, Some(&h.history_id))?;
    set_state(c, K_PARENT, h.parent_history_id.as_deref())?;
    set_state(c, K_FORK, h.fork_offset.map(|o| o.to_string()).as_deref())?;
    set_state(c, K_PROMOTED_AT, h.promoted_at.as_deref())?;
    set_state(c, K_PROMOTED_FROM, h.promoted_from.as_deref())?;
    Ok(())
}

/// Make the next changelog offset `offset + 1`.
fn set_changelog_seq(c: &Connection, offset: i64) -> Result<()> {
    let n = c.execute(
        "UPDATE sqlite_sequence SET seq = ?1 WHERE name = 'changelog'",
        params![offset],
    )?;
    if n == 0 {
        c.execute(
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('changelog', ?1)",
            params![offset],
        )?;
    }
    Ok(())
}

/// A changelog row exactly as the primary committed it.
fn insert_changelog_row(c: &Connection, ev: &ChangeEvent) -> Result<()> {
    c.execute(
        "INSERT INTO changelog (offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command, schema)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            ev.offset,
            ev.ts,
            ev.actor,
            ev.actor_ip,
            ev.action,
            ev.entity,
            ev.zone,
            ev.entity_id,
            serde_json::to_string(&ev.payload)?,
            ev.txn,
            ev.command,
            sql::CHANGELOG_SCHEMA
        ],
    )?;
    Ok(())
}

/// Give a user a new id, carrying every reference along (foreign keys are
/// deferred for the transaction).
fn move_user_id(c: &Connection, from: i64, to: i64) -> Result<()> {
    for (table, col) in [
        ("sessions", "user_id"),
        ("recovery_codes", "user_id"),
        ("api_tokens", "user_id"),
        ("zone_members", "user_id"),
        ("zones", "owner_id"),
    ] {
        c.execute(
            &format!("UPDATE {table} SET {col} = ?2 WHERE {col} = ?1"),
            params![from, to],
        )?;
    }
    c.execute("UPDATE users SET id = ?2 WHERE id = ?1", params![from, to])?;
    Ok(())
}

// ---- account data -----------------------------------------------------------

/// Replace the local account data with the primary's (see the module docs
/// for the local root). Local-only state is kept: sessions, token
/// `last_used_*`, a later TOTP step accepted here, recovery codes used here.
fn apply_accounts(
    t: &mut AuditTx,
    acc: &AccountsSnapshot,
    root: &LocalRoot,
    source: &str,
) -> Result<AccountsSyncSummary> {
    let c = t.conn;
    c.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    let before: HashMap<i64, ReplUser> = data::users(c)?.into_iter().map(|u| (u.id, u)).collect();
    let snap_ids: HashSet<i64> = acc.users.iter().map(|u| u.id).collect();
    let mut root_id = before
        .values()
        .find(|u| u.username == root.username)
        .map(|u| u.id);
    let merged_id = acc
        .users
        .iter()
        .find(|u| u.username == root.username)
        .map(|u| u.id);
    let mut sum = AccountsSyncSummary {
        local_root: if merged_id.is_some() {
            "merged"
        } else {
            "local"
        },
        ..Default::default()
    };

    // 1. Put the local root at its final id.
    match (root_id, merged_id) {
        (Some(r), Some(m)) if r != m => {
            c.execute("DELETE FROM users WHERE id = ?1", params![m])?;
            move_user_id(c, r, m)?;
            root_id = Some(m);
        }
        (Some(r), None) if snap_ids.contains(&r) => {
            let lowest = snap_ids
                .iter()
                .chain(before.keys())
                .copied()
                .min()
                .unwrap_or(0)
                .min(0);
            move_user_id(c, r, lowest - 1)?;
            root_id = Some(lowest - 1);
        }
        _ => {}
    }

    // 2. Users the primary does not have (the local root stays).
    let now_ids: Vec<i64> = {
        let mut stmt = c.prepare("SELECT id FROM users")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for id in now_ids {
        if !snap_ids.contains(&id) && Some(id) != root_id {
            c.execute("DELETE FROM users WHERE id = ?1", params![id])?;
            sum.users_removed += 1;
        }
    }

    // 3. Insert or update every other user with the primary's values.
    for u in &acc.users {
        sum.users += 1;
        if Some(u.id) == root_id {
            continue; // the merged local root keeps its local credentials
        }
        // A stale row holding this username (ids swapped) gives it up; it
        // is rewritten with its own values in its own iteration.
        c.execute(
            "UPDATE users SET username = '~replica-' || id WHERE username = ?1 AND id <> ?2",
            params![u.username, u.id],
        )?;
        let prev = before.get(&u.id).filter(|p| p.username == u.username);
        // TOTP replay protection: a later step accepted on this node stays.
        let last_step = match prev {
            Some(p) if p.totp_secret == u.totp_secret => {
                match (p.totp_last_step, u.totp_last_step) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                }
            }
            _ => u.totp_last_step,
        };
        match prev {
            None => sum.users_added += 1,
            Some(p) => {
                let mut cmp = u.clone();
                cmp.is_root = p.is_root;
                cmp.totp_last_step = p.totp_last_step;
                if &cmp != p {
                    sum.users_updated += 1;
                }
            }
        }
        c.execute(
            "INSERT INTO users (id, username, password_hash, display_name, is_admin, is_root, mfa_required, totp_secret,
                                totp_enrolled_at, totp_last_step, disabled_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash,
                display_name = excluded.display_name, is_admin = excluded.is_admin, is_root = 0,
                mfa_required = excluded.mfa_required, totp_secret = excluded.totp_secret,
                totp_enrolled_at = excluded.totp_enrolled_at, totp_last_step = excluded.totp_last_step,
                disabled_at = excluded.disabled_at, created_at = excluded.created_at, updated_at = excluded.updated_at",
            params![
                u.id,
                u.username,
                u.password_hash,
                u.display_name,
                u.is_admin as i64,
                u.mfa_required as i64,
                u.totp_secret,
                u.totp_enrolled_at,
                last_step,
                u.disabled_at,
                u.created_at,
                u.updated_at
            ],
        )?;
    }
    // A disabled replicated user is signed out here too.
    c.execute(
        "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE disabled_at IS NOT NULL)",
        [],
    )?;

    // 4. Recovery codes (the local root's stay local). A code already used
    // on this node stays used.
    let used_here: HashMap<(i64, String), String> = data::recovery_codes(c)?
        .into_iter()
        .filter_map(|r| r.used_at.map(|u| ((r.user_id, r.code_hash), u)))
        .collect();
    c.execute(
        "DELETE FROM recovery_codes WHERE user_id IS NOT ?1",
        params![root_id],
    )?;
    for rc in &acc.recovery_codes {
        if Some(rc.user_id) == root_id {
            continue;
        }
        let used = rc
            .used_at
            .clone()
            .or_else(|| used_here.get(&(rc.user_id, rc.code_hash.clone())).cloned());
        c.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, used_at) VALUES (?1, ?2, ?3)",
            params![rc.user_id, rc.code_hash, used],
        )?;
        sum.recovery_codes += 1;
    }

    // 5. API tokens (last_used_* is local bookkeeping and kept).
    let token_ids: HashSet<i64> = acc.tokens.iter().map(|t| t.id).collect();
    let local_tokens: Vec<i64> = {
        let mut stmt = c.prepare("SELECT id FROM api_tokens")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for id in local_tokens {
        if !token_ids.contains(&id) {
            c.execute("DELETE FROM api_tokens WHERE id = ?1", params![id])?;
        }
    }
    for tk in &acc.tokens {
        c.execute(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at, revoked_at, tags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, name = excluded.name,
                token_hash = excluded.token_hash, created_at = excluded.created_at,
                revoked_at = excluded.revoked_at, tags = excluded.tags",
            params![
                tk.id,
                tk.user_id,
                tk.name,
                tk.token_hash,
                tk.created_at,
                tk.revoked_at,
                serde_json::to_string(&tk.tags)?
            ],
        )?;
        sum.tokens += 1;
    }

    // 6. Console settings and TSIG keys: the primary's, wholesale.
    c.execute("DELETE FROM settings", [])?;
    for st in &acc.settings {
        c.execute(
            "INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![st.key, st.value, st.updated_by, st.updated_at],
        )?;
        sum.settings.push(st.key.clone());
    }
    c.execute("DELETE FROM tsig_keys", [])?;
    for k in &acc.tsig_keys {
        let secret = data_encoding::BASE64
            .decode(k.secret.as_bytes())
            .with_context(|| format!("TSIG key {}: secret is not base64", k.name))?;
        c.execute(
            "INSERT INTO tsig_keys (name, algorithm, secret, zones, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                k.name,
                k.algorithm,
                secret,
                serde_json::to_string(&k.zones)?,
                k.created_by,
                k.created_at,
                k.updated_at
            ],
        )?;
        sum.tsig_keys += 1;
    }

    // The local root keeps its config credentials whatever row it now is.
    if let Some(r) = root_id {
        c.execute(
            "UPDATE users SET password_hash = ?2, mfa_required = ?3, is_admin = 1, is_root = 1, disabled_at = NULL
             WHERE id = ?1",
            params![r, root.password_hash, root.mfa_required as i64],
        )?;
    }
    set_state(c, K_ACCOUNTS_CHECKSUM, Some(&acc.checksum))?;
    t.push(
        "replication.accounts_sync",
        None,
        source,
        serde_json::to_value(&sum)?,
    );
    Ok(sum)
}

/// Replace zones, records and members with the snapshot's.
fn apply_dns(c: &Connection, snap: &Snapshot) -> Result<()> {
    c.execute_batch("DELETE FROM zone_members; DELETE FROM records; DELETE FROM zones;")?;
    for z in &snap.zones {
        sql::insert_zone(c, z)?;
    }
    for r in &snap.records {
        sql::insert_record(
            c,
            &crate::model::Record {
                id: r.id,
                zone_id: r.zone_id,
                name: r.name.clone(),
                rtype: r.rtype,
                value: r.value.clone(),
                ttl: r.ttl,
                created_at: r.created_at.clone(),
                updated_at: r.updated_at.clone(),
                expires_at: r.expires_at.clone(),
            },
        )?;
        if r.expired_noted {
            sql::mark_expired(c, r.id)?;
        }
    }
    for m in &snap.members {
        sql::upsert_member(c, m.zone_id, m.user_id, &m.role, &m.created_at)?;
    }
    Ok(())
}

/// Apply a batch of the primary's changes: each change and its changelog
/// row (same offset) in one transaction with the others.
pub(crate) fn apply_changes(
    c: &Connection,
    expected_history: &str,
    events: &[ChangeEvent],
) -> Result<i64> {
    let h = data::history(c)?;
    if h.history_id != expected_history {
        bail!(
            "local history {} is not the primary's {}",
            h.history_id,
            expected_history
        );
    }
    let mut head = data::changelog_head(c)?;
    for ev in events {
        if ev.offset != head + 1 {
            bail!(
                "offset gap: expected {} after {}, got {}",
                head + 1,
                head,
                ev.offset
            );
        }
        let change: Change = serde_json::from_value(ev.payload.clone())
            .with_context(|| format!("offset {} is not a structured change", ev.offset))?;
        replay::apply(c, &change).with_context(|| format!("applying offset {}", ev.offset))?;
        insert_changelog_row(c, ev)?;
        head = ev.offset;
    }
    Ok(head)
}

fn system(what: &str) -> Actor {
    Actor {
        name: "replication".into(),
        ip: what.into(),
    }
}

impl Mutator {
    /// Run a replication write under the write lock: `f` gets the raw
    /// connection and an [`AuditTx`] whose rows commit with it. Committed:
    /// the catalog is rebuilt and `events` (if any) published.
    async fn replica_write<T: Send + 'static>(
        &self,
        operation: &'static str,
        actor: Actor,
        f: impl for<'t> FnOnce(&mut AuditTx<'t>) -> Result<(T, Vec<ChangeEvent>)> + Send + 'static,
    ) -> MResult<T> {
        let _guard = self.lock.lock().await;
        let storage = self.storage.clone();
        let a = actor.clone();
        let joined = tokio::task::spawn_blocking(move || {
            storage.write(&TOKEN, |conn| -> Result<_> {
                let mut t = AuditTx::begin(conn);
                let out = f(&mut t)?;
                let audit = t.commit_entries(&a, operation)?;
                Ok((out, audit))
            })
        })
        .await;
        let ((out, events), audit) = match joined {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(operation, error = %format!("{e:#}"), "replication transaction rolled back; nothing committed");
                return Err(MutationError::Internal(e));
            }
            Err(j) => {
                return Err(MutationError::Internal(anyhow::anyhow!(
                    "replication write task failed: {j}"
                )))
            }
        };
        for r in &audit {
            tracing::info!(audit_id = r.id, txn = %r.txn, operation, actor = %r.actor, action = %r.action, target = %r.target, "audit");
        }
        self.refresh_catalog().await;
        self.expiry_wake.notify_one();
        for ev in events {
            self.bus.publish_change(ev);
        }
        Ok(out)
    }

    /// Standby: apply whole transactions of the primary's changelog.
    /// Returns the new local head. Fails (nothing written) on a gap, a
    /// history mismatch or a change that does not apply.
    pub async fn replica_apply(
        &self,
        primary_history: String,
        events: Vec<ChangeEvent>,
    ) -> MResult<i64> {
        if events.is_empty() {
            return Ok(self.storage.changelog_head()?);
        }
        self.replica_write("replication_apply", system("apply"), move |t| {
            let head = apply_changes(t.conn, &primary_history, &events)?;
            Ok((head, events))
        })
        .await
    }

    /// Standby: replace every replicated table with a snapshot, adopt the
    /// primary's history and continue its changelog from the snapshot offset.
    pub async fn replica_bootstrap(
        &self,
        snap: Snapshot,
        root: LocalRoot,
        source: String,
    ) -> MResult<BootstrapSummary> {
        self.replica_write("replication_bootstrap", system("bootstrap"), move |t| {
            let accounts = apply_accounts(t, &snap.accounts, &root, &source)?;
            let c = t.conn;
            apply_dns(c, &snap)?;
            c.execute("DELETE FROM changelog", [])?;
            set_changelog_seq(c, snap.offset)?;
            set_history(c, &snap.history)?;
            set_state(c, K_FOLLOWING, Some(&source))?;
            let sum = BootstrapSummary {
                offset: snap.offset,
                zones: snap.zones.len(),
                records: snap.records.len(),
                members: snap.members.len(),
                accounts,
            };
            t.push(
                "replication.bootstrap",
                None,
                &source,
                serde_json::json!({
                    "offset": sum.offset, "zones": sum.zones, "records": sum.records, "members": sum.members,
                    "history_id": snap.history.history_id,
                }),
            );
            Ok((sum, Vec::new()))
        })
        .await
    }

    /// Standby: apply the primary's account data, settings and TSIG keys.
    /// `None`: already up to date (same checksum), nothing written.
    pub async fn replica_accounts(
        &self,
        acc: AccountsSnapshot,
        root: LocalRoot,
        source: String,
    ) -> MResult<Option<AccountsSyncSummary>> {
        let st = self.storage.replication_state()?;
        if st.get(K_ACCOUNTS_CHECKSUM) == Some(&acc.checksum) {
            return Ok(None);
        }
        self.replica_write("replication_accounts_sync", system("accounts"), move |t| {
            Ok((Some(apply_accounts(t, &acc, &root, &source)?), Vec::new()))
        })
        .await
    }

    /// Standby: the primary was promoted from this node's history at or
    /// after our position; continue in its history without a snapshot.
    pub async fn replica_adopt_history(&self, h: History, source: String) -> MResult<()> {
        self.replica_write("replication_adopt_history", system("adopt"), move |t| {
            let old = data::history(t.conn)?;
            set_history(t.conn, &h)?;
            set_state(t.conn, K_FOLLOWING, Some(&source))?;
            t.push(
                "replication.adopt_history",
                None,
                &source,
                serde_json::json!({ "from": old.history_id, "to": h.history_id, "fork_offset": h.fork_offset }),
            );
            Ok(((), Vec::new()))
        })
        .await
    }

    /// Promotion: start a new history whose parent is the current one,
    /// forked at the current changelog head, and stop being a standby of
    /// `from` (the primary URL). Audited.
    pub async fn replica_promote(
        &self,
        actor: Actor,
        from: String,
        how: &'static str,
    ) -> MResult<History> {
        self.replica_write("replication_promote", actor, move |t| {
            let c = t.conn;
            let old = data::history(c)?;
            let head = data::changelog_head(c)?;
            let h = History {
                history_id: crate::auth::random_token(12),
                parent_history_id: Some(old.history_id.clone()),
                fork_offset: Some(head),
                promoted_at: Some(crate::model::now_rfc3339()),
                promoted_from: Some(from.clone()),
            };
            set_history(c, &h)?;
            set_state(c, K_FOLLOWING, None)?;
            t.push(
                "replication.promote",
                None,
                &from,
                serde_json::json!({ "old_history_id": old.history_id, "new_history_id": h.history_id, "fork_offset": head, "how": how }),
            );
            Ok((h, Vec::new()))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::accounts::Accounts;
    use super::super::{ExportDoc, ExportRecord, ExportZone, ImportMode};
    use super::*;
    use crate::cache::{Cache, Catalog};
    use crate::events::Bus;
    use crate::model::*;
    use crate::storage::Storage;
    use std::sync::Arc;

    fn node() -> (Arc<Storage>, Mutator, Accounts) {
        let storage = Arc::new(Storage::open_memory().unwrap());
        let m = Mutator::new(
            storage.clone(),
            Arc::new(Cache::new(Catalog::empty())),
            Arc::new(Bus::new(64, 64)),
            "",
            "",
        );
        let a = Accounts::new(storage.clone());
        (storage, m, a)
    }

    fn actor() -> Actor {
        Actor {
            name: "tester".into(),
            ip: "127.0.0.1".into(),
        }
    }

    fn rec(name: &str, t: RecordType, v: &str) -> RecordInput {
        RecordInput {
            name: Some(name.into()),
            rtype: Some(t),
            value: Some(v.into()),
            ..Default::default()
        }
    }

    const PRIMARY_ROOT_HASH: &str = "$argon2id$primary-root-hash";
    const STANDBY_ROOT_HASH: &str = "$argon2id$standby-root-hash";

    fn standby_root() -> LocalRoot {
        LocalRoot {
            username: "root".into(),
            password_hash: STANDBY_ROOT_HASH.into(),
            mfa_required: false,
        }
    }

    /// A primary with every kind of replicated data.
    async fn populated_primary() -> (Arc<Storage>, Mutator, Accounts) {
        let (s, m, a) = node();
        let root = a.sync_root("root", PRIMARY_ROOT_HASH, false).unwrap();
        let alice = a
            .create_user(
                &actor(),
                &NewUser {
                    username: "alice".into(),
                    password_hash: "$argon2id$alice-hash".into(),
                    display_name: "Alice".into(),
                    is_admin: false,
                    mfa_required: true,
                },
            )
            .unwrap();
        a.run(&actor(), "mfa_enroll", |t| {
            let u = t.set_mfa(alice.id, Some("ALICETOTPSECRET"))?;
            t.accept_totp_step(&u, 1000)?;
            t.set_recovery_codes(&u, &["rc-hash-1".into(), "rc-hash-2".into()])
        })
        .unwrap();
        a.create_token(&actor(), &alice, "ci", "token-hash-alice", &["ci".into()])
            .unwrap();
        a.create_token(&actor(), &root, "repl", "token-hash-root", &[])
            .unwrap();
        a.run(&actor(), "settings", |t| {
            t.set_forwarding(
                "tester",
                None,
                &crate::mutation::settings::ForwardingSettings {
                    upstreams: vec!["192.0.2.53:53".parse().unwrap()],
                    allowed_clients: vec!["10.0.0.0/8".into()],
                    timeout_ms: 1500,
                    cache_max_ttl: None,
                    cache_negative_max_ttl: None,
                },
            )?;
            t.create_tsig_key(
                "tester",
                &crate::mutation::tsig::NewTsigKey {
                    name: "k1.".into(),
                    algorithm: crate::dns::tsig::Algorithm::HmacSha256,
                    secret: b"tsig-secret-bytes".to_vec(),
                    zones: vec![],
                    imported: true,
                },
            )
        })
        .unwrap();
        m.create_zone(
            actor(),
            ZoneInput {
                name: Some("a.test".into()),
                ..Default::default()
            },
            Some(alice.id),
        )
        .await
        .unwrap();
        m.create_record(actor(), "a.test", rec("www", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        m.create_record(
            actor(),
            "a.test",
            RecordInput {
                expires_in: Some(1),
                ..rec("tmp", RecordType::A, "192.0.2.2")
            },
        )
        .await
        .unwrap();
        m.expire_due(chrono::Utc::now() + chrono::Duration::seconds(5))
            .await
            .unwrap();
        m.set_member(actor(), "a.test", root.id, ZoneRole::Viewer)
            .await
            .unwrap();
        (s, m, a)
    }

    fn snapshot(s: &Storage) -> Snapshot {
        s.read_tx(|c| data::snapshot(c, "g-1")).unwrap()
    }

    /// The replicated state of a database, normalised the way the standby
    /// legitimately differs (its root's credentials, is_root, token use).
    fn replicated(s: &Storage) -> serde_json::Value {
        let snap = snapshot(s);
        let users: Vec<serde_json::Value> = snap
            .accounts
            .users
            .iter()
            .map(|u| {
                let mut v = serde_json::to_value(u).unwrap();
                if u.username == "root" {
                    for k in ["password_hash", "display_name", "created_at", "updated_at"] {
                        v[k] = serde_json::Value::Null;
                    }
                }
                v["is_root"] = serde_json::Value::Null;
                v
            })
            .collect();
        let codes: Vec<_> = snap
            .accounts
            .recovery_codes
            .iter()
            .filter(|c| c.user_id != 1)
            .cloned()
            .collect();
        serde_json::json!({
            "offset": snap.offset, "history": snap.history, "zones": snap.zones, "records": snap.records,
            "members": snap.members, "users": users, "codes": codes, "tokens": snap.accounts.tokens,
            "settings": snap.accounts.settings, "tsig": snap.accounts.tsig_keys,
            "checksums": s.read_tx(data::zone_checksums).unwrap(),
        })
    }

    #[tokio::test]
    async fn snapshot_then_changes_reproduce_the_primary() {
        let (ps, pm, pa) = populated_primary().await;
        // The standby has its own root (different password) and a fresh history.
        let (ss, sm, sa) = node();
        sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        assert_ne!(
            ps.read_tx(data::history).unwrap().history_id,
            ss.read_tx(data::history).unwrap().history_id
        );
        let sum = sm
            .replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        assert_eq!(sum.accounts.local_root, "merged");
        assert_eq!(replicated(&ss), replicated(&ps));
        // The standby's root keeps its own password; the primary's root token works for it.
        let root = ss.get_user_by_name("root").unwrap().unwrap();
        assert_eq!(root.password_hash, STANDBY_ROOT_HASH);
        assert!(root.is_root && root.id == ps.get_user_by_name("root").unwrap().unwrap().id);
        assert!(ss.list_tokens(Some(root.id), None).unwrap().len() == 1);
        let alice = ss.get_user_by_name("alice").unwrap().unwrap();
        assert!(!alice.is_root && alice.totp_secret.as_deref() == Some("ALICETOTPSECRET"));
        assert_eq!(ss.changelog_head().unwrap(), ps.changelog_head().unwrap());

        // More changes on the primary, tailed and applied as whole batches.
        let history = ps.read_tx(data::history).unwrap().history_id;
        pm.create_record(actor(), "a.test", rec("mail", RecordType::A, "192.0.2.3"))
            .await
            .unwrap();
        pm.update_zone(
            actor(),
            "a.test",
            ZoneInput {
                refresh: Some(1234),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        pm.reap_due(chrono::Utc::now() + chrono::Duration::seconds(5))
            .await
            .unwrap();
        pm.create_zone(
            actor(),
            ZoneInput {
                name: Some("b.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        pm.delete_zone(actor(), "b.test").await.unwrap();
        let after = ss.changelog_head().unwrap();
        let batch = ps.read_tx(|c| data::changes_after(c, after, 1000)).unwrap();
        assert!(batch.iter().any(|e| e.payload["kind"] == "record_reaped"));
        sm.replica_apply(history.clone(), batch).await.unwrap();
        assert_eq!(replicated(&ss), replicated(&ps));
        // Identical changelog rows (offset, txn, payload) on both sides.
        let rows = |s: &Storage| {
            s.changelog_after(after, 1000)
                .unwrap()
                .into_iter()
                .map(|e| (e.offset, e.txn, e.payload, e.actor, e.command))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(&ss), rows(&ps));

        // Account changes: a user deleted, a token revoked, a code used here survives.
        let bob = pa
            .create_user(
                &actor(),
                &NewUser {
                    username: "bob".into(),
                    password_hash: "$argon2id$bob".into(),
                    display_name: String::new(),
                    is_admin: true,
                    mfa_required: false,
                },
            )
            .unwrap();
        let acc = ps.read_tx(|c| data::accounts(c, "g-2")).unwrap();
        sm.replica_accounts(acc, standby_root(), "https://p".into())
            .await
            .unwrap()
            .expect("changed");
        assert!(ss.get_user_by_name("bob").unwrap().is_some());
        sa.run(&actor(), "mfa_verify", |t| {
            t.use_recovery_code(&alice, "rc-hash-1")?;
            t.accept_totp_step(&alice, 2000)
        })
        .unwrap();
        pa.run(&actor(), "delete_user", |t| t.delete_user(&bob))
            .unwrap();
        let tok = ps.list_tokens(None, Some("ci")).unwrap().remove(0);
        let alice_p = ps.get_user(tok.user_id).unwrap().unwrap();
        pa.run(&actor(), "revoke", |t| t.revoke_token(&alice_p, &tok))
            .unwrap();
        let acc = ps.read_tx(|c| data::accounts(c, "g-3")).unwrap();
        let same = acc.clone();
        sm.replica_accounts(acc, standby_root(), "https://p".into())
            .await
            .unwrap()
            .expect("changed");
        assert!(ss.get_user_by_name("bob").unwrap().is_none());
        assert!(
            ss.list_tokens(None, Some("ci")).unwrap().is_empty(),
            "revoked"
        );
        // Local security state wins where it is later: the TOTP step and the used code.
        let last: i64 = ss
            .read_tx(|c| {
                Ok(c.query_row(
                    "SELECT totp_last_step FROM users WHERE username='alice'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(last, 2000);
        assert_eq!(ss.recovery_codes_left(alice.id).unwrap(), 1);
        // Same checksum again: nothing to do.
        assert!(sm
            .replica_accounts(same, standby_root(), "https://p".into())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn local_root_without_a_namesake_moves_out_of_the_way() {
        let (ps, _pm, pa) = node();
        // The primary's root is called "admin" and has id 1.
        pa.sync_root("admin", PRIMARY_ROOT_HASH, false).unwrap();
        let (ss, sm, sa) = node();
        let local = sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        assert_eq!(local.id, 1, "collides with the primary's admin");
        let sum = sm
            .replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        assert_eq!(sum.accounts.local_root, "local");
        let root = ss.get_user_by_name("root").unwrap().unwrap();
        assert!(root.id < 0 && root.is_root && root.password_hash == STANDBY_ROOT_HASH);
        let admin = ss.get_user_by_name("admin").unwrap().unwrap();
        assert_eq!(admin.id, 1);
        assert!(!admin.is_root, "only the local root is root on a standby");
        // Restart: syncing the config root again changes nothing else.
        sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        assert!(!ss.get_user(1).unwrap().unwrap().disabled_at.is_some());
    }

    #[tokio::test]
    async fn gaps_and_foreign_histories_are_refused_without_writing() {
        let (ps, pm, _) = populated_primary().await;
        let (ss, sm, sa) = node();
        sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        let history = ps.read_tx(data::history).unwrap().history_id;
        for i in 0..3 {
            pm.create_record(
                actor(),
                "a.test",
                rec(&format!("g{i}"), RecordType::A, "192.0.2.9"),
            )
            .await
            .unwrap();
        }
        let head = ss.changelog_head().unwrap();
        let batch = ps.read_tx(|c| data::changes_after(c, head, 100)).unwrap();
        assert!(batch.len() >= 6);
        // Missing the first transaction: a gap.
        let skip = batch.iter().position(|e| e.txn != batch[0].txn).unwrap();
        let err = sm
            .replica_apply(history.clone(), batch[skip..].to_vec())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
        assert_eq!(ss.changelog_head().unwrap(), head, "nothing written");
        // Another history.
        assert!(sm
            .replica_apply("other".into(), batch.clone())
            .await
            .is_err());
        assert_eq!(ss.changelog_head().unwrap(), head);
        // The right batch applies.
        sm.replica_apply(history, batch).await.unwrap();
        assert_eq!(ss.changelog_head().unwrap(), ps.changelog_head().unwrap());
    }

    #[tokio::test]
    async fn batches_never_split_a_transaction() {
        let (ps, pm, _) = populated_primary().await;
        let head = ps.changelog_head().unwrap();
        let doc = ExportDoc {
            version: 1,
            exported_at: String::new(),
            zones: vec![ExportZone {
                name: "big.test".into(),
                serial: None,
                soa_mname: None,
                soa_rname: None,
                refresh: None,
                retry: None,
                expire: None,
                minimum: None,
                default_ttl: None,
                owner: None,
                records: (0..20)
                    .map(|i| ExportRecord {
                        name: format!("h{i}"),
                        rtype: RecordType::A,
                        value: format!("198.51.100.{i}"),
                        ttl: None,
                        expires_at: None,
                    })
                    .collect(),
            }],
        };
        pm.import(actor(), doc, ImportMode::Merge, None, None)
            .await
            .unwrap();
        let one = ps.read_tx(|c| data::changes_after(c, head, 1)).unwrap();
        assert!(
            one.len() > 20,
            "the whole import transaction: {}",
            one.len()
        );
        assert!(one.iter().all(|e| e.txn == one[0].txn));
        let offs: Vec<i64> = one.iter().map(|e| e.offset).collect();
        assert_eq!(
            offs,
            (head + 1..=head + one.len() as i64).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn promotion_starts_a_child_history_at_the_head() {
        let (s, m, _) = populated_primary().await;
        let before = s.read_tx(data::history).unwrap();
        let head = s.changelog_head().unwrap();
        let h = m
            .replica_promote(actor(), "https://old".into(), "api")
            .await
            .unwrap();
        assert_ne!(h.history_id, before.history_id);
        assert_eq!(
            h.parent_history_id.as_deref(),
            Some(before.history_id.as_str())
        );
        assert_eq!(h.fork_offset, Some(head));
        assert_eq!(s.read_tx(data::history).unwrap(), h);
        let audit = s.audit_after(0, 1000).unwrap();
        let row = audit
            .iter()
            .find(|r| r.action == "replication.promote")
            .unwrap();
        assert_eq!(row.detail["fork_offset"], head);
        // The changelog continues from the same sequence.
        m.create_zone(
            actor(),
            ZoneInput {
                name: Some("new.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(s.changelog_after(head, 10).unwrap()[0].offset, head + 1);
    }

    /// A buffer the test subscriber writes to.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replication_never_logs_or_audits_secrets() {
        let (ps, _pm, _pa) = populated_primary().await;
        let (ss, sm, sa) = node();
        sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        let cap = Captured::default();
        let w = cap.clone();
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || w.clone())
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        // Other tests running in parallel may have cached "not interested"
        // for these call sites; make them ask this subscriber again.
        tracing::callsite::rebuild_interest_cache();
        let snap = snapshot(&ps);
        tracing::debug!(?snap, "debug output of a snapshot");
        sm.replica_bootstrap(snap, standby_root(), "https://p".into())
            .await
            .unwrap();
        let mut acc = ps.read_tx(|c| data::accounts(c, "g-9")).unwrap();
        acc.checksum = "changed".into();
        sm.replica_accounts(acc, standby_root(), "https://p".into())
            .await
            .unwrap();
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("replication.accounts_sync"), "{logs}");
        let audit = serde_json::to_string(&ss.audit_after(0, 1000).unwrap()).unwrap();
        let tsig_b64 = data_encoding::BASE64.encode(b"tsig-secret-bytes");
        for secret in [
            "alice-hash",
            PRIMARY_ROOT_HASH,
            STANDBY_ROOT_HASH,
            "ALICETOTPSECRET",
            "rc-hash-1",
            "token-hash-alice",
            tsig_b64.as_str(),
        ] {
            assert!(!logs.contains(secret), "log leaks {secret}");
            assert!(!audit.contains(secret), "audit leaks {secret}");
        }
    }
}
