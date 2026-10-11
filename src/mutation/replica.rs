//! Replication writes (standby / follow mode). The only code that writes
//! replicated data on a standby, and the promotion record.
//!
//! These methods skip the per-user permission checks of the API (the data
//! comes from the primary, where they were enforced) but keep the
//! structure of every other write:
//! - Changes from the primary (DNS and account) are applied with [`replay::apply`] and
//!   written to the local changelog with the primary's offsets, payloads,
//!   actors and transaction ids, in the same SQLite transaction (so a
//!   promoted standby continues the same offset sequence).
//! - A snapshot is a list of the same facts, applied with the same code.
//! - Snapshot loads, history adoption and promotions write
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
use super::{
    Change, DnsChange, DnsEvent, MResult, MutationError, Mutator, Rebuild, SecretChange, TOKEN,
};
use crate::model::{Actor, ChangeEvent};
use crate::replication::data;
use crate::replication::types::*;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;

/// The standby's `[root]` from its own config file (its credentials stay
/// in the local row, which replication never overwrites).
#[derive(Clone, Debug)]
pub struct LocalRoot {
    pub username: String,
}

/// What a snapshot load did (counts only; goes into the audit row).
#[derive(Debug, Default, Clone, Serialize)]
pub struct BootstrapSummary {
    pub offset: i64,
    pub entities: usize,
    pub zones: usize,
    pub records: usize,
    pub members: usize,
    pub users: usize,
    pub tokens: usize,
    pub tsig_keys: usize,
    pub settings: usize,
    /// Replicated users that this server had and the primary does not.
    pub users_removed: usize,
    /// `merged` (the primary has a user named like the local root) or `local`.
    pub local_root: &'static str,
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
/// Replication halted (JSON `HaltInfo`): terminal until `--prepare-standby`.
pub(crate) const K_HALTED: &str = "halted";

/// The recorded halt, if replication is halted.
pub fn halted(storage: &crate::storage::Storage) -> Option<HaltInfo> {
    storage
        .replication_state()
        .ok()?
        .get(K_HALTED)
        .and_then(|v| serde_json::from_str(v).ok())
}

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
fn insert_changelog_row(c: &Connection, ev: &ChangeEvent, class: &str) -> Result<()> {
    c.execute(
        "INSERT OR REPLACE INTO changelog (offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command, schema, class)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
            sql::CHANGELOG_SCHEMA,
            class
        ],
    )?;
    Ok(())
}

use super::acct_sql::Ctx;

// ---- snapshot ------------------------------------------------------------------

/// Load a snapshot: forget the replicated data (users are kept until the
/// end so their sessions survive, the local root always), then apply every
/// entity with the same replay code as the changelog, then remove users the
/// primary no longer has. Local sign-in state survives: a later TOTP step
/// (merged by `put_user`) and recovery codes used on this server.
fn load_snapshot(c: &Connection, snap: &Snapshot, root: &str) -> Result<BootstrapSummary> {
    c.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    let used_here: Vec<(i64, String, String)> = data::recovery_codes(c)?
        .into_iter()
        .filter_map(|r| r.used_at.map(|u| (r.user_id, r.code_hash, u)))
        .collect();
    crate::replication::tables::delete_for_snapshot(c, root)?;
    let ctx = Ctx {
        local_root: Some(root),
    };
    let mut sum = BootstrapSummary {
        offset: snap.offset,
        entities: snap.entities.len(),
        local_root: "local",
        ..Default::default()
    };
    let mut ids = std::collections::HashSet::new();
    for e in &snap.entities {
        match e {
            Change::Secret(SecretChange::UserCreated { user }) => {
                sum.users += 1;
                ids.insert(user.id);
                if user.username == root {
                    sum.local_root = "merged";
                }
            }
            Change::Dns(DnsChange::ZoneCreated { .. }) => sum.zones += 1,
            Change::Dns(DnsChange::RecordCreated { .. }) => sum.records += 1,
            Change::Dns(DnsChange::MemberSet { .. }) => sum.members += 1,
            Change::Secret(SecretChange::TokenCreated { .. }) => sum.tokens += 1,
            Change::Secret(SecretChange::TsigKeySet { .. }) => sum.tsig_keys += 1,
            Change::Secret(SecretChange::SettingSet { .. }) => sum.settings += 1,
            _ => {}
        }
        replay::apply(c, e, &ctx).with_context(|| format!("snapshot entity {e:?}"))?;
    }
    // Users the primary does not have (its merged root keeps our id).
    for u in data::users(c)? {
        if !ids.contains(&u.id) && u.username != root {
            replay::apply(
                c,
                &Change::Secret(SecretChange::UserDeleted {
                    user_id: u.id,
                    username: u.username,
                }),
                &ctx,
            )?;
            sum.users_removed += 1;
        }
    }
    for (user_id, hash, used_at) in used_here {
        replay::apply(
            c,
            &Change::Secret(SecretChange::RecoveryCodeUsed {
                user_id,
                code_hash: crate::replication::types::Hidden(hash),
                used_at,
            }),
            &ctx,
        )?;
    }
    Ok(sum)
}

/// Apply a batch of the primary's changes: each change and its changelog
/// row (same offset) in one transaction with the others.
/// Returns the new head and whether settings or TSIG keys changed.
pub(crate) fn apply_changes(
    c: &Connection,
    expected_history: &str,
    events: &[ChangeEvent],
    local_root: &str,
) -> Result<(i64, bool)> {
    c.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    let ctx = Ctx {
        local_root: Some(local_root),
    };
    let mut runtime = false;
    let h = data::history(c)?;
    if h.history_id != expected_history {
        bail!(
            "local history {} is not the primary's {}",
            h.history_id,
            expected_history
        );
    }
    // Facts are complete new state, so re-applying changes from an earlier
    // offset is harmless: a batch may start at or before our head, but not
    // after it (a gap), and must be contiguous.
    let mut head = data::changelog_head(c)?;
    if let Some(first) = events.first() {
        if first.offset > head + 1 {
            bail!(
                "offset gap: expected {} after {}, got {}",
                head + 1,
                head,
                first.offset
            );
        }
    }
    let mut prev: Option<i64> = None;
    for ev in events {
        if prev.is_some_and(|p| ev.offset != p + 1) {
            bail!(
                "offset gap inside a batch: {} after {}",
                ev.offset,
                prev.unwrap_or(0)
            );
        }
        prev = Some(ev.offset);
        let change: Change = serde_json::from_value(ev.payload.clone())
            .with_context(|| format!("offset {} is not a structured change", ev.offset))?;
        replay::apply(c, &change, &ctx)
            .with_context(|| format!("applying offset {}", ev.offset))?;
        insert_changelog_row(c, ev, change.class())?;
        runtime |= change.affects_dns_runtime();
        head = head.max(ev.offset);
    }
    Ok((head, runtime))
}

/// What `--prepare-standby` removed (counts only; goes into the audit row).
#[derive(Debug, Default, Clone, Serialize)]
pub struct PrepareSummary {
    pub zones: i64,
    pub records: i64,
    pub zone_members: i64,
    pub changelog_rows: i64,
    pub tsig_keys: i64,
    pub settings: i64,
    pub api_tokens: i64,
    pub users: i64,
    pub sessions: i64,
}

/// `rust-dns --prepare-standby` (server stopped): make this database fresh
/// so it may follow a primary. Empties zones, records, zone members, the
/// changelog, TSIG keys, console settings, API tokens, every session and
/// every user except the config root `root_username`, and forgets the
/// replication lineage (a new history id). The audit log is kept (local
/// history) and gets a `replication.prepare_standby` row naming the backup.
/// The caller writes the backup first.
pub fn prepare_standby(
    storage: &crate::storage::Storage,
    root_username: &str,
    backup: &str,
    divergence: Option<&str>,
) -> Result<PrepareSummary> {
    storage.write(&TOKEN, |c| -> Result<PrepareSummary> {
        let count = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
        let users: i64 = c.query_row(
            "SELECT COUNT(*) FROM users WHERE username <> ?1",
            params![root_username],
            |r| r.get(0),
        )?;
        let sum = PrepareSummary {
            zones: count("SELECT COUNT(*) FROM zones")?,
            records: count("SELECT COUNT(*) FROM records")?,
            zone_members: count("SELECT COUNT(*) FROM zone_members")?,
            changelog_rows: count("SELECT COUNT(*) FROM changelog")?,
            tsig_keys: count("SELECT COUNT(*) FROM tsig_keys")?,
            settings: count("SELECT COUNT(*) FROM settings")?,
            api_tokens: count("SELECT COUNT(*) FROM api_tokens")?,
            users,
            sessions: count("SELECT COUNT(*) FROM sessions")?,
        };
        let old = data::history(c)?;
        // Replicated tables per the registry; then the local stream and state.
        crate::replication::tables::delete_replicated(c, root_username)?;
        c.execute_batch(
            "DELETE FROM changelog; DELETE FROM changelog_history; DELETE FROM sessions; DELETE FROM replication_state;",
        )?;
        set_state(c, K_HISTORY, Some(&crate::auth::random_token(12)))?;
        let mut t = AuditTx::begin(c);
        let mut detail = serde_json::to_value(&sum)?;
        detail["backup"] = backup.into();
        detail["divergence_file"] = divergence.into();
        detail["old_history_id"] = old.history_id.into();
        t.push("replication.prepare_standby", None, backup, detail);
        t.commit_entries(
            &Actor {
                name: "cli".into(),
                ip: "local".into(),
            },
            "prepare_standby",
        )?;
        Ok(sum)
    })
}

fn system(what: &str) -> Actor {
    Actor {
        name: "replication".into(),
        ip: what.into(),
    }
}

impl Mutator {
    /// Run a replication write under the write lock: `f` gets the raw
    /// connection (this module is the replication writer: history,
    /// changelog rows with the primary's offsets, snapshot loads) and an
    /// [`AuditTx`] whose rows commit with it, and says how much of the
    /// catalog the write may have changed. Committed: the catalog is
    /// brought up to date (the same per-zone mechanism as a primary's
    /// commit, under the same lock) and `events` (if any) published.
    async fn replica_write<T: Send + 'static>(
        &self,
        operation: &'static str,
        actor: Actor,
        f: impl for<'t> FnOnce(&'t Connection, &mut AuditTx<'t>) -> Result<(T, Vec<DnsEvent>, Rebuild)>
            + Send
            + 'static,
    ) -> MResult<T> {
        let _guard = self.lock.lock().await;
        let storage = self.storage.clone();
        let a = actor.clone();
        let joined = tokio::task::spawn_blocking(move || {
            storage.write(&TOKEN, |conn| -> Result<_> {
                let mut t = AuditTx::begin(conn);
                let out = f(conn, &mut t)?;
                let audit = t.commit_entries(&a, operation)?;
                Ok((out, audit))
            })
        })
        .await;
        let ((out, events, rebuild), audit) = match joined {
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
        self.refresh_catalog(rebuild).await;
        self.expiry_wake.notify_one();
        for ev in events {
            self.bus.publish_change(ev);
        }
        Ok(out)
    }

    /// Standby: apply whole transactions of the primary's changelog.
    /// Returns the new local head. Fails (nothing written) on a gap, a
    /// history mismatch or a change that does not apply.
    /// Returns the new head and whether settings or TSIG keys changed.
    /// Only DNS changes are published on the event bus (account changes
    /// carry secrets).
    pub async fn replica_apply(
        &self,
        primary_history: String,
        events: Vec<ChangeEvent>,
        root: LocalRoot,
    ) -> MResult<(i64, bool)> {
        if events.is_empty() {
            return Ok((self.storage.changelog_head()?, false));
        }
        // O2: account changes that can take access away; streams on this
        // standby re-check at once after they are applied.
        let access = events.iter().any(|e| {
            matches!(
                e.payload.get("kind").and_then(|k| k.as_str()),
                Some("token_revoked" | "token_tags_set" | "user_updated" | "user_deleted")
            )
        });
        let out = self
            .replica_write("replication_apply", system("apply"), move |c, _t| {
                let out = apply_changes(c, &primary_history, &events, &root.username)?;
                // The zones to rebuild and the events to publish both derive
                // from the changes just applied.
                let changes: Vec<(ChangeEvent, Change)> = events
                    .into_iter()
                    .filter_map(|e| {
                        let c = serde_json::from_value::<Change>(e.payload.clone()).ok()?;
                        Some((e, c))
                    })
                    .collect();
                let zones = super::catalog_zones(changes.iter().map(|(_, c)| c));
                let dns = changes
                    .into_iter()
                    .filter_map(|(e, c)| match c {
                        Change::Dns(d) => Some(DnsEvent::new(e, &d)),
                        Change::Secret(_) => None,
                    })
                    .collect();
                Ok((out, dns, Rebuild::Zones(zones)))
            })
            .await?;
        if access {
            self.bus.publish_access(crate::events::AccessEvent::All);
        }
        Ok(out)
    }

    /// Standby: replace every replicated table with a snapshot, adopt the
    /// primary's history and continue its changelog from the snapshot offset.
    pub async fn replica_bootstrap(
        &self,
        snap: Snapshot,
        root: LocalRoot,
        source: String,
    ) -> MResult<BootstrapSummary> {
        self.replica_write("replication_bootstrap", system("bootstrap"), move |c, t| {
            let sum = load_snapshot(c, &snap, &root.username)?;
            // The history before the snapshot is fetched again afterwards
            // (`replica_store_history`), from this primary.
            c.execute_batch("DELETE FROM changelog; DELETE FROM changelog_history;")?;
            set_changelog_seq(c, snap.offset)?;
            set_history(c, &snap.history)?;
            set_state(c, K_FOLLOWING, Some(&source))?;
            t.push(
                "replication.bootstrap",
                None,
                &source,
                serde_json::json!({ "summary": sum, "history_id": snap.history.history_id }),
            );
            Ok((sum, Vec::new(), Rebuild::Full))
        })
        .await
        .inspect(|_| self.bus.publish_access(crate::events::AccessEvent::All))
    }

    /// Standby: keep a copy of the primary's DNS changelog rows from before
    /// the snapshot (the snapshot started `changelog` empty), for the
    /// changelog page only: rows at or above the first local `changelog`
    /// row (or the head) are ignored, and DNS rows only (the primary's
    /// changelog API never returns account rows). Not applied, not
    /// replicated, never served to standbys. Returns the rows added.
    pub async fn replica_store_history(&self, rows: Vec<ChangeEvent>) -> MResult<usize> {
        self.replica_write("replication_history", system("history"), move |c, _t| {
            let floor: i64 = c.query_row(
                "SELECT IFNULL(MIN(offset), (SELECT IFNULL(MAX(seq), 0) + 1 FROM sqlite_sequence WHERE name = 'changelog')) FROM changelog",
                [],
                |r| r.get(0),
            )?;
            let mut n = 0;
            for ev in rows.iter().filter(|e| e.offset < floor) {
                let change: Change = serde_json::from_value(ev.payload.clone())
                    .with_context(|| format!("offset {} is not a structured change", ev.offset))?;
                if !matches!(change, Change::Dns(_)) {
                    continue;
                }
                n += c.execute(
                    "INSERT OR IGNORE INTO changelog_history (offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    ],
                )?;
            }
            Ok((n, Vec::new(), Rebuild::Zones(Vec::new())))
        })
        .await
    }

    /// Where the standby's history copy continues: `(after, floor)`, fetch
    /// rows with `after < offset < floor`.
    pub fn history_window(&self) -> MResult<(i64, i64)> {
        Ok(self.storage.read_tx(|c| {
            Ok(c.query_row(
                "SELECT (SELECT IFNULL(MAX(offset), 0) FROM changelog_history),
                        IFNULL((SELECT MIN(offset) FROM changelog),
                               (SELECT IFNULL(MAX(seq), 0) + 1 FROM sqlite_sequence WHERE name = 'changelog'))",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })?)
    }

    /// Standby: stop replicating for good (until `--prepare-standby`): the
    /// data diverged from the primary. Local state only; audited.
    pub async fn replica_halt(&self, info: HaltInfo) -> MResult<()> {
        self.replica_write("replication_halt", system("halt"), move |c, t| {
            set_state(c, K_HALTED, Some(&serde_json::to_string(&info)?))?;
            t.push(
                "replication.halt",
                None,
                &info.reason,
                serde_json::json!({ "reason": info.reason, "detail": info.detail, "offset": info.offset, "report_file": info.report_file }),
            );
            Ok(((), Vec::new(), Rebuild::Full))
        })
        .await
    }

    /// Standby: the primary was promoted from this node's history at or
    /// after our position; continue in its history without a snapshot.
    pub async fn replica_adopt_history(&self, h: History, source: String) -> MResult<()> {
        self.replica_write("replication_adopt_history", system("adopt"), move |c, t| {
            let old = data::history(c)?;
            set_history(c, &h)?;
            set_state(c, K_FOLLOWING, Some(&source))?;
            t.push(
                "replication.adopt_history",
                None,
                &source,
                serde_json::json!({ "from": old.history_id, "to": h.history_id, "fork_offset": h.fork_offset }),
            );
            Ok(((), Vec::new(), Rebuild::Full))
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
        self.replica_write("replication_promote", actor, move |c, t| {
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
            Ok((h, Vec::new(), Rebuild::Full))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::accounts::{Accounts, UserChanges};
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

    /// A standby: write gate closed (its own account writes stay local),
    /// config root synced.
    fn standby_node() -> (Arc<Storage>, Mutator, Accounts) {
        let (s, m, a) = node();
        a.set_gate(m.gate());
        m.gate().close("standby");
        a.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        (s, m, a)
    }

    fn actor() -> Actor {
        Actor {
            name: "tester".into(),
            ip: "127.0.0.1".into(),
        }
    }

    fn zone_input(name: &str) -> ZoneInput {
        ZoneInput {
            name: Some(name.into()),
            ..Default::default()
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
                    // Open resolver mode travels in the snapshot too.
                    allowed_clients: vec!["0.0.0.0/0".into(), "::/0".into()],
                    timeout_ms: 1500,
                    cache_max_ttl: None,
                    cache_negative_max_ttl: None,
                    open_resolver: Some(true),
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
        // DNSSEC: the key travels as an account-class change, the flag as a zone update.
        m.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        m.set_member(actor(), "a.test", root.id, ZoneRole::Viewer)
            .await
            .unwrap();
        (s, m, a)
    }

    fn snapshot(s: &Storage) -> Snapshot {
        s.read_tx(data::snapshot).unwrap()
    }

    /// Every replicated table as both sides must have it (the registry's
    /// checksum view: per-server columns and the standby's root left out),
    /// plus history and head.
    fn replicated(s: &Storage) -> serde_json::Value {
        s.read_tx(|c| {
            let mut v = serde_json::Map::new();
            for t in crate::replication::tables::replicated_tables() {
                v.insert(
                    t.name.into(),
                    crate::replication::tables::dump(c, t, t.node_columns, Some("root"))?.into(),
                );
            }
            v.insert("history".into(), serde_json::to_value(data::history(c)?)?);
            v.insert("head".into(), data::changelog_head(c)?.into());
            Ok(serde_json::Value::Object(v))
        })
        .unwrap()
    }

    /// Tail everything the primary has after the standby's head.
    async fn tail(ps: &Storage, ss: &Storage, sm: &Mutator) -> bool {
        let history = ps.read_tx(data::history).unwrap().history_id;
        let after = ss.changelog_head().unwrap();
        let batch = ps
            .read_tx(|c| data::changes_after(c, after, 100_000))
            .unwrap();
        sm.replica_apply(history, batch, standby_root())
            .await
            .unwrap()
            .1
    }

    /// D3 on the standby: the apply path maintains the catalog per zone
    /// with the same mechanism; after every batch the standby's catalog
    /// equals a full build of its database, equals the primary's (same
    /// windows from the replicated signing epoch), and every signature
    /// (made with the standby's copy of the key) verifies.
    #[tokio::test]
    async fn a_standby_keeps_its_catalog_current_per_zone() {
        use super::super::test_support::{assert_catalog_is_current, random_dns_op};
        use rand::SeedableRng;
        let (ps, pm, _pa) = node();
        let (ss, sm, _sa) = standby_node();
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(424242);
        let mut applied = 0;
        for step in 0..220 {
            let _ = random_dns_op(&mut rng, &ps, &pm, step).await;
            // Mostly one transaction per batch, sometimes several.
            if step % 7 == 3 {
                continue;
            }
            let before = ss.changelog_head().unwrap();
            tail(&ps, &ss, &sm).await;
            applied += ss.changelog_head().unwrap() - before;
            assert_catalog_is_current(&ss, &sm, &format!("standby step {step}"));
            assert_eq!(
                sm.cache.load().describe(),
                pm.cache.load().describe(),
                "standby and primary serve the same at step {step}"
            );
        }
        tail(&ps, &ss, &sm).await;
        assert!(applied > 300, "{applied}");
        assert_eq!(replicated(&ss), replicated(&ps));
        assert!(sm.cache.load().verify_signatures() > 0);
        // A snapshot load rebuilds everything.
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        assert_catalog_is_current(&ss, &sm, "after a snapshot");
    }

    /// Changelog v2 (shadow mode): every write through the real mutation
    /// paths (DNS, accounts, settings, TSIG, DNSSEC, cascades, expiry,
    /// audit) is captured, and replaying the v2 log into an empty database
    /// reproduces every captured table exactly; nothing escaped the capture.
    #[tokio::test]
    async fn changelog_v2_captures_every_change_exactly() {
        use rand::SeedableRng;
        let (ps, pm, pa) = node();
        ps.cdc_set_leader(true);
        let leader = ps.cdc().expect("v2 attached").clone();
        // A follower database: same schema, applying the v2 log.
        // Foreign keys stay on (as rust-dns runs): the crate turns them off
        // around replays itself.
        let fs = Storage::open_memory().unwrap();
        let follower = fs.cdc().expect("v2 attached").clone();
        let mut lines = Vec::new();
        leader
            .snapshot(|mut b| {
                b.pop();
                lines.push(b);
                Ok(())
            })
            .unwrap();
        follower
            .load_snapshot(lines.into_iter().map(Ok), None, &Default::default())
            .unwrap();

        // Accounts, MFA, tokens, settings, TSIG, zones, DNSSEC, members.
        let root = pa.sync_root("root", PRIMARY_ROOT_HASH, false).unwrap();
        let alice = pa
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
        pa.run(&actor(), "mfa_enroll", |t| {
            let u = t.set_mfa(alice.id, Some("ALICETOTPSECRET"))?;
            t.accept_totp_step(&u, 1000)?;
            t.set_recovery_codes(&u, &["rc-hash-1".into(), "rc-hash-2".into()])
        })
        .unwrap();
        pa.create_token(&actor(), &alice, "ci", "token-hash-alice", &["ci".into()])
            .unwrap();
        pa.run(&actor(), "settings", |t| {
            t.set_forwarding(
                "tester",
                None,
                &crate::mutation::settings::ForwardingSettings {
                    upstreams: vec!["192.0.2.53:53".parse().unwrap()],
                    allowed_clients: vec!["10.0.0.0/8".into()],
                    timeout_ms: 1500,
                    cache_max_ttl: None,
                    cache_negative_max_ttl: None,
                    open_resolver: None,
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
        pm.create_zone(
            actor(),
            ZoneInput {
                name: Some("a.test".into()),
                ..Default::default()
            },
            Some(alice.id),
        )
        .await
        .unwrap();
        pm.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        pm.set_member(actor(), "a.test", root.id, ZoneRole::Viewer)
            .await
            .unwrap();
        pm.create_record(
            actor(),
            "a.test",
            RecordInput {
                expires_in: Some(1),
                ..rec("tmp", RecordType::A, "192.0.2.2")
            },
        )
        .await
        .unwrap();
        pm.expire_due(chrono::Utc::now() + chrono::Duration::seconds(5))
            .await
            .unwrap();
        // Random DNS operations.
        let mut rng = rand::rngs::StdRng::seed_from_u64(20261011);
        for step in 0..250 {
            let _ = crate::mutation::test_support::random_dns_op(&mut rng, &ps, &pm, step).await;
        }
        // Deleting a user and a zone (cascades), and token use bookkeeping
        // (a per-server column: not a change).
        let alice = ps.get_user_by_name("alice").unwrap().unwrap();
        pa.run(&actor(), "delete_user", |t| {
            t.delete_user(&alice).map(|_| ())
        })
        .unwrap();
        let _ = pm.delete_zone(actor(), "a.test").await;

        // Replay into the follower.
        loop {
            let pos = follower.state().unwrap().position().unwrap();
            let (txns, _) = leader.changes(&pos, 1 << 20, 1000).unwrap();
            if txns.is_empty() {
                break;
            }
            follower.apply(&txns).unwrap();
        }
        let st = leader.state().unwrap();
        assert!(
            st.broken.is_none(),
            "a write escaped the capture: {:?}",
            st.broken
        );
        assert!(st.last_txn > 100, "{}", st.last_txn);
        assert!(leader.health().unwrap().is_empty(), "{:?}", leader.health());
        let check = leader.self_check().unwrap();
        assert_eq!(check["ok"], true, "{check}");
        for t in leader.tables() {
            let a = leader.bucket_hashes(&t.name, st.last_txn, 16).unwrap();
            let b = follower.bucket_hashes(&t.name, st.last_txn, 16).unwrap();
            assert_eq!(
                a.buckets, b.buckets,
                "table {} differs after replay",
                t.name
            );
        }
        // Every captured table really was exercised.
        let c = ps.cdc().unwrap().reader().unwrap();
        for t in [
            "zones",
            "records",
            "zone_members",
            "users",
            "recovery_codes",
            "api_tokens",
            "settings",
            "tsig_keys",
            "dnssec_keys",
            "audit_log",
        ] {
            let n: i64 = c
                .query_row("SELECT count(*) FROM _cdc WHERE tbl = ?1", [t], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(n > 0, "no change captured for {t}");
        }
    }

    #[tokio::test]
    async fn snapshot_then_changes_reproduce_the_primary() {
        let (ps, pm, pa) = populated_primary().await;
        // The standby has its own root (different password) and a fresh history.
        let (ss, sm, sa) = standby_node();
        let sum = sm
            .replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        assert_eq!(sum.local_root, "merged");
        assert_eq!(replicated(&ss), replicated(&ps));
        // The standby signs with the replicated key (in memory, its own signatures).
        let pz = ps.get_zone("a.test").unwrap().unwrap();
        let key = ps.get_dnssec_key(pz.id).unwrap().unwrap();
        assert_eq!(ss.get_dnssec_key(pz.id).unwrap().unwrap(), key);
        let signed = sm.cache.load().zones["a.test."].signed.clone().unwrap();
        assert_eq!(signed.key_tag, key.key_tag);
        let fwd = crate::mutation::settings::load_forwarding(&ss)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(
            fwd.open_resolver,
            Some(true),
            "open resolver mode in the snapshot"
        );
        // The standby's root keeps its own password; the primary's root token works for it.
        let root = ss.get_user_by_name("root").unwrap().unwrap();
        assert_eq!(root.password_hash, STANDBY_ROOT_HASH);
        assert!(root.is_root && root.id == ps.get_user_by_name("root").unwrap().unwrap().id);
        assert_eq!(ss.list_tokens(Some(root.id), None).unwrap().len(), 1);
        let alice = ss.get_user_by_name("alice").unwrap().unwrap();
        assert!(!alice.is_root && alice.totp_secret.as_deref() == Some("ALICETOTPSECRET"));

        // DNS changes on the primary, tailed as whole batches.
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
        let after = ss.changelog_head().unwrap();
        tail(&ps, &ss, &sm).await;
        assert_eq!(replicated(&ss), replicated(&ps));
        let rows = |s: &Storage| {
            s.read_tx(|c| data::changelog_tail(c, after))
                .unwrap()
                .into_iter()
                .map(|e| (e.offset, e.txn, e.payload, e.actor, e.command))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(&ss), rows(&ps), "identical changelog rows");

        // Account changes arrive the same way, incrementally.
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
        pm.set_member(actor(), "a.test", bob.id, ZoneRole::Editor)
            .await
            .unwrap();
        let before = ss.changelog_head().unwrap();
        assert!(!tail(&ps, &ss, &sm).await, "no settings or TSIG change");
        assert!(ss.get_user_by_name("bob").unwrap().is_some());
        assert_eq!(replicated(&ss), replicated(&ps));
        let kinds: Vec<String> = ss
            .read_tx(|c| data::changelog_tail(c, before))
            .unwrap()
            .iter()
            .map(|e| e.payload["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            vec!["user_created", "member_set"],
            "user before its membership, one stream"
        );
        // Local sign-in state on the standby: a later TOTP step and a used code.
        sa.run(&actor(), "mfa_verify", |t| {
            t.use_recovery_code(&alice, "rc-hash-1")?;
            t.accept_totp_step(&alice, 2000)
        })
        .unwrap();
        assert_eq!(
            ss.changelog_head().unwrap(),
            ps.changelog_head().unwrap(),
            "local account writes are not changelogged on a standby"
        );
        pa.run(&actor(), "delete_user", |t| t.delete_user(&bob))
            .unwrap();
        let tok = ps.list_tokens(None, Some("ci")).unwrap().remove(0);
        let alice_p = ps.get_user(tok.user_id).unwrap().unwrap();
        pa.run(&actor(), "revoke", |t| t.revoke_token(&alice_p, &tok))
            .unwrap();
        pa.run(&actor(), "password", |t| {
            t.set_password(alice_p.id, "$argon2id$new")
        })
        .unwrap();
        pa.run(&actor(), "tsig", |t| {
            let k = crate::storage::get_tsig_key(t.conn(), "k1.")?.unwrap();
            t.update_tsig_key_zones(&k, &["a.test".into()])
        })
        .unwrap();
        assert!(tail(&ps, &ss, &sm).await, "TSIG change reported");
        assert!(ss.get_user_by_name("bob").unwrap().is_none());
        assert!(
            ss.list_tokens(None, Some("ci")).unwrap().is_empty(),
            "revoked"
        );
        assert_eq!(
            ss.get_user(alice.id).unwrap().unwrap().password_hash,
            "$argon2id$new"
        );
        assert_eq!(replicated(&ss), replicated(&ps));
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
        // The standby's root is untouched by the primary's root changes.
        pa.sync_root("root", "$argon2id$primary-root-2", false)
            .unwrap();
        tail(&ps, &ss, &sm).await;
        assert_eq!(
            ss.get_user_by_name("root").unwrap().unwrap().password_hash,
            STANDBY_ROOT_HASH
        );
    }

    /// A primary (root "admin") with an ordinary user "root" (the standby's
    /// root's namesake) that owns a signed zone, is a member of another and
    /// has a token; a standby bootstrapped from it.
    async fn namesake_pair() -> (
        (Arc<Storage>, Mutator, Accounts),
        (Arc<Storage>, Mutator, Accounts),
        User,
    ) {
        let (ps, pm, pa) = node();
        pa.sync_root("admin", PRIMARY_ROOT_HASH, false).unwrap();
        // An ordinary user on the primary named like the standby's root.
        let carol = pa
            .create_user(
                &actor(),
                &NewUser {
                    username: "root".into(),
                    password_hash: "$argon2id$x".into(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        pa.create_token(&actor(), &carol, "ci", "token-hash-carol", &[])
            .unwrap();
        pm.create_zone(actor(), zone_input("a.test"), Some(carol.id))
            .await
            .unwrap();
        pm.create_zone(actor(), zone_input("b.test"), None)
            .await
            .unwrap();
        pm.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        pm.set_member(actor(), "b.test", carol.id, ZoneRole::Editor)
            .await
            .unwrap();
        let (ss, sm, _sa) = standby_node();
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        assert_eq!(replicated(&ss), replicated(&ps));
        ((ps, pm, pa), (ss, sm, _sa), carol)
    }

    /// H2: deleting a user releases its zones and memberships as DNS
    /// changes (no serial bump, window kept), the catalog follows, and a
    /// standby that keeps the account (its local root has the same name)
    /// still ends with the primary's zone rows.
    #[tokio::test]
    async fn deleting_a_user_releases_its_zones_as_changes() {
        let ((ps, pm, pa), (ss, sm, _sa), carol) = namesake_pair().await;
        let a_before = ps.get_zone("a.test").unwrap().unwrap();
        let head = ps.changelog_head().unwrap();

        let released = pm.release_user(actor(), carol.id).await.unwrap();
        assert_eq!(released, (1, 1));
        pa.run(&actor(), "delete_user", |t| t.delete_user(&carol))
            .unwrap();
        let a_after = ps.get_zone("a.test").unwrap().unwrap();
        assert_eq!(a_after.owner_id, None);
        assert_eq!(
            (a_after.serial, &a_after.updated_at, &a_after.signed_at),
            (a_before.serial, &a_before.updated_at, &a_before.signed_at),
            "no serial bump, same signature window"
        );
        assert_eq!(
            pm.cache.load().zones["a.test."].zone.owner_id,
            None,
            "the catalog's zone row follows"
        );
        let kinds: Vec<String> = ps
            .read_tx(|c| data::changelog_tail(c, head))
            .unwrap()
            .iter()
            .map(|e| e.payload["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, ["zone_updated", "member_removed", "user_deleted"]);

        tail(&ps, &ss, &sm).await;
        assert!(
            ss.get_user_by_name("root").unwrap().is_some(),
            "the standby keeps its local root"
        );
        assert_eq!(
            replicated(&ss),
            replicated(&ps),
            "zone rows and tokens converge"
        );
        assert_eq!(sm.cache.load().describe(), pm.cache.load().describe());
        assert_eq!(sm.cache.load().zones["a.test."].zone.owner_id, None);
    }

    /// A primary of an older version deletes the user without releasing
    /// its zones first (the foreign keys clear them): a standby that keeps
    /// the account as its root clears the same rows, so it does not halt.
    #[tokio::test]
    async fn a_namesake_root_follows_a_delete_without_release() {
        let ((ps, _pm, pa), (ss, sm, _sa), carol) = namesake_pair().await;
        pa.run(&actor(), "delete_user", |t| t.delete_user(&carol))
            .unwrap();
        tail(&ps, &ss, &sm).await;
        assert!(ss.get_user_by_name("root").unwrap().is_some());
        assert_eq!(replicated(&ss), replicated(&ps));
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
        assert_eq!(sum.local_root, "local");
        let root = ss.get_user_by_name("root").unwrap().unwrap();
        assert!(root.id < 0 && root.is_root && root.password_hash == STANDBY_ROOT_HASH);
        let admin = ss.get_user_by_name("admin").unwrap().unwrap();
        assert_eq!(admin.id, 1);
        assert!(!admin.is_root, "only the local root is root on a standby");
        // Restart: syncing the config root again changes nothing else.
        sa.sync_root("root", STANDBY_ROOT_HASH, false).unwrap();
        assert!(ss.get_user(1).unwrap().unwrap().disabled_at.is_none());
    }

    #[tokio::test]
    async fn gaps_and_foreign_histories_are_refused_without_writing() {
        let (ps, pm, _) = populated_primary().await;
        let (ss, sm, _sa) = standby_node();
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
            .replica_apply(history.clone(), batch[skip..].to_vec(), standby_root())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
        assert_eq!(ss.changelog_head().unwrap(), head, "nothing written");
        // Another history.
        assert!(sm
            .replica_apply("other".into(), batch.clone(), standby_root())
            .await
            .is_err());
        assert_eq!(ss.changelog_head().unwrap(), head);
        // The right batch applies.
        sm.replica_apply(history, batch, standby_root())
            .await
            .unwrap();
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
                overrides: None,
                record_policy: None,
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

    /// Facts are complete new state: replaying from an earlier offset (an
    /// overlap with what the standby already has) changes nothing.
    #[tokio::test]
    async fn replaying_from_an_earlier_offset_is_idempotent() {
        let (ps, pm, pa) = populated_primary().await;
        let (ss, sm, _sa) = standby_node();
        let start = ps.changelog_head().unwrap();
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        pm.create_record(actor(), "a.test", rec("x", RecordType::A, "192.0.2.50"))
            .await
            .unwrap();
        pm.create_zone(actor(), zone_input("b.test"), None)
            .await
            .unwrap();
        pm.delete_record(actor(), "a.test", 1).await.unwrap();
        let u = pa
            .create_user(
                &actor(),
                &NewUser {
                    username: "zed".into(),
                    password_hash: "h".into(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        pa.run(&actor(), "pw", |t| t.set_password(u.id, "h2"))
            .unwrap();
        tail(&ps, &ss, &sm).await;
        let want = replicated(&ps);
        assert_eq!(replicated(&ss), want);
        // Everything since the snapshot again, twice.
        let history = ps.read_tx(data::history).unwrap().history_id;
        let again = ps
            .read_tx(|c| data::changes_after(c, start, 100_000))
            .unwrap();
        for _ in 0..2 {
            sm.replica_apply(history.clone(), again.clone(), standby_root())
                .await
                .unwrap();
            assert_eq!(replicated(&ss), want, "overlapping replay changed nothing");
        }
    }

    #[tokio::test]
    async fn account_change_payloads_are_scrubbed_after_retention() {
        let (ps, pm, pa) = populated_primary().await;
        pm.create_record(actor(), "a.test", rec("keep", RecordType::A, "192.0.2.9"))
            .await
            .unwrap();
        let before = ps.read_tx(|c| data::changes_after(c, 0, 100_000)).unwrap();
        assert!(before
            .iter()
            .any(|e| e.payload.to_string().contains("alice-hash")));
        // Nothing is old enough yet.
        assert_eq!(
            ps.scrub_account_changes(chrono::Utc::now() - chrono::Duration::days(1))
                .unwrap(),
            0
        );
        let n = ps
            .scrub_account_changes(chrono::Utc::now() + chrono::Duration::days(1))
            .unwrap();
        assert!(n > 5, "{n}");
        let after = ps.read_tx(|c| data::changes_after(c, 0, 100_000)).unwrap();
        assert_eq!(after.len(), before.len(), "offsets stay");
        let text = serde_json::to_string(&after).unwrap();
        for secret in [
            "alice-hash",
            "ALICETOTPSECRET",
            "token-hash-alice",
            "rc-hash-1",
        ] {
            assert!(!text.contains(secret), "{secret} survived the scrub");
        }
        assert!(after
            .iter()
            .filter(|e| e.payload["kind"] == "scrubbed")
            .all(|e| e.entity != "record" && e.entity != "zone"));
        assert!(
            after.iter().any(|e| e.payload["kind"] == "record_created"),
            "DNS rows untouched"
        );
        // A standby can never misapply a scrubbed row: it does not parse.
        let (_ss, sm, _sa) = standby_node();
        let history = ps.read_tx(data::history).unwrap().history_id;
        assert!(sm
            .replica_apply(history, after, standby_root())
            .await
            .is_err());
        let _ = pa;
    }

    #[test]
    fn older_servers_report_protocol_1() {
        let id: Identity = serde_json::from_value(serde_json::json!({
            "role": "primary", "writable": true,
            "history": { "history_id": "x", "parent_history_id": null, "fork_offset": null, "promoted_at": null, "promoted_from": null }
        }))
        .unwrap();
        assert_eq!(id.protocol, 1);
        assert_ne!(id.protocol, crate::replication::types::REPLICATION_PROTOCOL);
    }

    /// Nothing a standby does by itself changes replicated data: DNS
    /// writes and the expiry sweeper are refused by the gate; sign-in state
    /// of replicated users (TOTP step, used recovery code, sessions) lives
    /// in per-server columns or local tables; its own root is local
    /// (explicitly excluded from the checksums); renaming the root is refused.
    #[tokio::test]
    async fn local_writes_on_a_standby_never_change_replicated_data() {
        let (ps, _pm, _pa) = populated_primary().await;
        let (ss, sm, sa) = standby_node();
        sm.replica_bootstrap(snapshot(&ps), standby_root(), "https://p".into())
            .await
            .unwrap();
        let sums = |s: &Storage| {
            s.read_tx(|c| crate::replication::tables::checksums(c, "root"))
                .unwrap()
        };
        let before = sums(&ss);
        assert_eq!(before, sums(&ps), "a fresh copy matches the primary");
        // DNS writes and the sweeper's writes.
        assert!(matches!(
            sm.create_zone(actor(), zone_input("x.test"), None).await,
            Err(MutationError::ReadOnly(_))
        ));
        assert!(matches!(
            sm.expire_due(chrono::Utc::now() + chrono::Duration::days(365))
                .await,
            Err(MutationError::ReadOnly(_))
        ));
        assert!(matches!(
            sm.reap_due(chrono::Utc::now() + chrono::Duration::days(365))
                .await,
            Err(MutationError::ReadOnly(_))
        ));
        // Sign-in of a replicated user: TOTP step, recovery code, session.
        let alice = ss.get_user_by_name("alice").unwrap().unwrap();
        sa.run(&actor(), "mfa_verify", |t| {
            t.accept_totp_step(&alice, 99_999)?;
            t.use_recovery_code(&alice, "rc-hash-2")?;
            t.create_session(
                &alice,
                &Session {
                    id: 0,
                    token_hash: "sess".into(),
                    user_id: alice.id,
                    state: "active".into(),
                    pending_secret: None,
                    ip: "127.0.0.1".into(),
                    user_agent: String::new(),
                    created_at: now_rfc3339(),
                    expires_at: "2999-01-01T00:00:00.000Z".into(),
                    last_seen_at: now_rfc3339(),
                },
            )?;
            t.delete_user_sessions(&alice, "admin sign-out")
        })
        .unwrap();
        // The local root: new password and MFA setting from its config.
        sa.sync_root("root", "$argon2id$standby-root-2", true)
            .unwrap();
        let root = ss.get_user_by_name("root").unwrap().unwrap();
        assert_eq!(root.password_hash, "$argon2id$standby-root-2");
        // Renaming the root on a standby is refused (the old one is replicated).
        let err = sa.sync_root("admin", STANDBY_ROOT_HASH, false).unwrap_err();
        assert!(err.to_string().contains("--prepare-standby"), "{err}");
        assert_eq!(sums(&ss), before, "replicated tables unchanged");
        // The exclusion of the local root is explicit: counted, it differs.
        let with_root = |s: &Storage| {
            s.read_tx(|c| crate::replication::tables::checksums(c, "nobody"))
                .unwrap()
        };
        let users = |v: Vec<crate::replication::types::TableChecksum>| {
            v.into_iter().find(|t| t.table == "users").unwrap()
        };
        assert_ne!(
            users(with_root(&ss)).checksum,
            users(with_root(&ps)).checksum,
            "the standby's root differs from the primary's namesake, and that is excluded on purpose"
        );
        // Nothing was changelogged either.
        assert_eq!(ss.changelog_head().unwrap(), ps.changelog_head().unwrap());
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
        let (ps, pm, _pa) = populated_primary().await;
        let (ss, sm, _sa) = standby_node();
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
        // More account changes, applied from the changelog.
        _pa.run(&actor(), "mfa_enroll", |t| {
            let u = t.change_user(2, &UserChanges::default())?;
            t.set_mfa(u.id, Some("ALICETOTPSECRET2"))
        })
        .unwrap();
        // N1: a key rollover carries a second private key.
        pm.rollover_start(actor(), "a.test").await.unwrap();
        tail(&ps, &ss, &sm).await;
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("debug output of a snapshot"),
            "the capture works: {logs}"
        );
        // Neither the user-facing changelog nor the event bus carries account changes.
        let visible = serde_json::to_string(&ss.changelog_after(0, 100_000).unwrap()).unwrap()
            + &serde_json::to_string(&ps.changelog_after(0, 100_000).unwrap()).unwrap();
        assert!(!visible.contains("user_created") && !visible.contains("tsig_key_set"));
        let audit = serde_json::to_string(&ss.audit_after(0, 1000).unwrap()).unwrap();
        let tsig_b64 = data_encoding::BASE64.encode(b"tsig-secret-bytes");
        let pz = ps.get_zone("a.test").unwrap().unwrap();
        let stored = ps.get_dnssec_key(pz.id).unwrap().unwrap();
        let dnssec_key = stored.private_key.0.clone();
        let rollover_key = stored.rollover.as_ref().unwrap().key.private_key.0.clone();
        assert_eq!(
            ss.get_dnssec_key(pz.id).unwrap().unwrap(),
            stored,
            "replicated"
        );
        assert!(!visible.contains("dnssec_key_set"));
        for secret in [
            dnssec_key.as_str(),
            rollover_key.as_str(),
            "alice-hash",
            PRIMARY_ROOT_HASH,
            STANDBY_ROOT_HASH,
            "ALICETOTPSECRET",
            "ALICETOTPSECRET2",
            "rc-hash-1",
            "token-hash-alice",
            tsig_b64.as_str(),
        ] {
            assert!(!logs.contains(secret), "log leaks {secret}");
            assert!(!audit.contains(secret), "audit leaks {secret}");
            assert!(!visible.contains(secret), "changelog API leaks {secret}");
        }
    }
}
