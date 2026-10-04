//! The only SQL that writes the replicated account tables (users, recovery
//! codes, API tokens, console settings, TSIG keys, DNSSEC keys), one
//! private function per account `Change`.
//!
//! No write without a change, enforced by the compiler: the functions are
//! private to this file and the only way in is [`write`], which takes the
//! typed [`Change`] and returns a [`Written`] receipt. The receipt is
//! `#[must_use]` and can only be turned in two ways: [`Written::log_into`]
//! (the primary: the change joins the transaction's changelog rows) or
//! [`Written::replayed`] (a standby replaying the primary's change, whose
//! changelog row it copies; a snapshot entity). Dropping it unused does not
//! build (`-D warnings`).
//!
//! The same code runs on the primary and on a standby, so both write
//! identical rows. On a standby, [`Ctx::local_root`] names the account from
//! its own config: that account keeps its local password, MFA and recovery
//! codes (see `mutation::replica`).
//!
//! Second line: `tests::only_acct_sql_writes_account_tables` scans the
//! mutation sources and fails if any other file contains SQL that writes
//! these tables (the snapshot loader and `--prepare-standby` in
//! `replica.rs` excepted).

use super::{Change, SecretChange};
use crate::replication::data;
use crate::replication::types::{ReplSetting, ReplToken, ReplTsigKey, ReplUser};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// How a change is applied.
#[derive(Clone, Copy, Default)]
pub struct Ctx<'a> {
    /// On a standby: the username of its own config root.
    pub local_root: Option<&'a str>,
}

impl Ctx<'_> {
    /// On the primary (or in tests): write the fact as it is.
    pub fn verbatim() -> Ctx<'static> {
        Ctx { local_root: None }
    }
}

/// Proof that an account change was written to its table. It must be
/// turned in: logged (primary) or declared a replay (standby, snapshot).
#[must_use = "an account write must be changelogged (log_into) or be a replay (replayed)"]
pub(super) struct Written(());

impl Written {
    /// Primary: queue the change for the changelog rows of this transaction.
    pub(super) fn log_into(self, change: SecretChange, changes: &mut Vec<Change>) {
        changes.push(Change::Secret(change));
    }

    /// The change comes from the primary's changelog (the caller copies its
    /// row) or from a snapshot: nothing to log here.
    pub(super) fn replayed(self) {}
}

/// Apply one account-class change to its table. The only entry to the SQL
/// of this file. It takes only the secret half of [`Change`], so a DNS
/// change cannot reach it; exhaustive, so a new kind of secret change does
/// not compile until it is handled here.
pub(super) fn write(c: &Connection, ctx: &Ctx, change: &SecretChange) -> Result<Written> {
    match change {
        SecretChange::UserCreated { user } | SecretChange::UserUpdated { user } => {
            put_user(c, ctx, user)?
        }
        SecretChange::UserDeleted { user_id, username } => delete_user(c, ctx, *user_id, username)?,
        SecretChange::TotpStepAccepted { user_id, step } => totp_step(c, ctx, *user_id, *step)?,
        SecretChange::RecoveryCodesReplaced {
            user_id,
            code_hashes,
        } => recovery_codes(c, ctx, *user_id, &code_hashes.0)?,
        SecretChange::RecoveryCodeUsed {
            user_id,
            code_hash,
            used_at,
        } => recovery_code_used(c, ctx, *user_id, &code_hash.0, used_at)?,
        SecretChange::TokenCreated { token } => put_token(c, token)?,
        SecretChange::TokenTagsSet {
            token_id,
            tags,
            scope,
        } => token_tags(c, *token_id, tags, scope.as_ref())?,
        SecretChange::TokenRevoked {
            token_id,
            revoked_at,
        } => token_revoked(c, *token_id, revoked_at)?,
        SecretChange::TsigKeySet { key } => put_tsig_key(c, key)?,
        SecretChange::TsigKeyDeleted { name } => delete_tsig_key(c, name)?,
        SecretChange::SettingSet { setting } => put_setting(c, setting)?,
        SecretChange::SettingCleared { key } => delete_setting(c, key)?,
        SecretChange::DnssecKeySet { key } => put_dnssec_key(c, key)?,
        SecretChange::DnssecKeyDeleted { zone_id, .. } => delete_dnssec_key(c, *zone_id)?,
    }
    Ok(Written(()))
}

/// Next id for a new row of an AUTOINCREMENT table (ids are part of the facts).
pub(super) fn next_id(c: &Connection, table: &str) -> Result<i64> {
    let seq: i64 = c
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = ?1",
            params![table],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let max: i64 = c.query_row(
        &format!("SELECT COALESCE(MAX(id), 0) FROM {table}"),
        [],
        |r| r.get(0),
    )?;
    Ok(seq.max(max) + 1)
}

/// Give a user a new id, carrying every reference along (foreign keys are
/// deferred for the transaction).
fn move_user_id(c: &Connection, from: i64, to: i64) -> Result<()> {
    c.execute_batch("PRAGMA defer_foreign_keys = ON")?;
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

/// Is `user_id` the standby's own root account?
fn is_local_root(c: &Connection, ctx: &Ctx, user_id: i64) -> Result<bool> {
    let Some(root) = ctx.local_root else {
        return Ok(false);
    };
    let name: Option<String> = c
        .query_row(
            "SELECT username FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(name.as_deref() == Some(root))
}

/// UserCreated / UserUpdated: the row becomes `u`.
fn put_user(c: &Connection, ctx: &Ctx, u: &ReplUser) -> Result<()> {
    if let Some(root) = ctx.local_root {
        let local = data::user_by_name(c, root)?;
        if u.username == root {
            // The primary's namesake of our root: same id, local credentials.
            if let Some(r) = local {
                if r.id != u.id {
                    c.execute("DELETE FROM users WHERE id = ?1", params![u.id])?;
                    move_user_id(c, r.id, u.id)?;
                }
                return Ok(());
            }
        } else if let Some(r) = local.filter(|r| r.id == u.id) {
            // Our local-only root sits on an id the primary now uses.
            let lowest: i64 =
                c.query_row("SELECT min(COALESCE(MIN(id), 0), 0) FROM users", [], |r| {
                    r.get(0)
                })?;
            move_user_id(c, r.id, lowest - 1)?;
        }
    }
    // A stale row holding this username (ids swapped) gives it up.
    c.execute(
        "UPDATE users SET username = '~replica-' || id WHERE username = ?1 AND id <> ?2",
        params![u.username, u.id],
    )?;
    let prev = data::user_row(c, u.id)?.filter(|p| p.username == u.username);
    // TOTP replay protection: a later step accepted here is kept.
    let last_step = match &prev {
        Some(p) if p.totp_secret == u.totp_secret => match (p.totp_last_step, u.totp_last_step) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        },
        _ => u.totp_last_step,
    };
    // Only the local config root is `root` on a standby.
    let is_root = u.is_root && ctx.local_root.is_none();
    c.execute(
        "INSERT INTO users (id, username, password_hash, display_name, is_admin, is_root, mfa_required, totp_secret,
                            totp_enrolled_at, totp_last_step, disabled_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash,
            display_name = excluded.display_name, is_admin = excluded.is_admin, is_root = excluded.is_root,
            mfa_required = excluded.mfa_required, totp_secret = excluded.totp_secret,
            totp_enrolled_at = excluded.totp_enrolled_at, totp_last_step = excluded.totp_last_step,
            disabled_at = excluded.disabled_at, created_at = excluded.created_at, updated_at = excluded.updated_at",
        params![
            u.id,
            u.username,
            u.password_hash,
            u.display_name,
            u.is_admin as i64,
            is_root as i64,
            u.mfa_required as i64,
            u.totp_secret,
            u.totp_enrolled_at,
            last_step,
            u.disabled_at,
            u.created_at,
            u.updated_at
        ],
    )?;
    if u.disabled_at.is_some() {
        // A disabled account is signed out (sessions are local bookkeeping).
        c.execute("DELETE FROM sessions WHERE user_id = ?1", params![u.id])?;
    }
    Ok(())
}

fn delete_user(c: &Connection, ctx: &Ctx, user_id: i64, username: &str) -> Result<()> {
    if ctx.local_root == Some(username) {
        // Our root stays (as a local-only account), but the replicated
        // rows that the primary's foreign keys removed with the account
        // go here too, or the tables' checksums would differ and the
        // standby halt: its API tokens, and (written by a version without
        // `Mutator::release_user`) zone memberships and ownership.
        for sql in [
            "DELETE FROM api_tokens WHERE user_id = ?1",
            "DELETE FROM zone_members WHERE user_id = ?1",
            "UPDATE zones SET owner_id = NULL WHERE owner_id = ?1",
        ] {
            c.execute(sql, params![user_id])?;
        }
        return Ok(());
    }
    c.execute(
        "DELETE FROM users WHERE id = ?1 AND username = ?2",
        params![user_id, username],
    )?;
    Ok(())
}

fn totp_step(c: &Connection, ctx: &Ctx, user_id: i64, step: i64) -> Result<()> {
    if is_local_root(c, ctx, user_id)? {
        return Ok(());
    }
    c.execute(
        "UPDATE users SET totp_last_step = ?2 WHERE id = ?1 AND (totp_last_step IS NULL OR totp_last_step < ?2)",
        params![user_id, step],
    )?;
    Ok(())
}

fn recovery_codes(c: &Connection, ctx: &Ctx, user_id: i64, hashes: &[String]) -> Result<()> {
    if is_local_root(c, ctx, user_id)? {
        return Ok(());
    }
    c.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    for h in hashes {
        c.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
            params![user_id, h],
        )?;
    }
    Ok(())
}

fn recovery_code_used(
    c: &Connection,
    ctx: &Ctx,
    user_id: i64,
    hash: &str,
    used_at: &str,
) -> Result<()> {
    if is_local_root(c, ctx, user_id)? {
        return Ok(());
    }
    c.execute(
        "UPDATE recovery_codes SET used_at = ?3 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
        params![user_id, hash, used_at],
    )?;
    Ok(())
}

fn put_token(c: &Connection, t: &ReplToken) -> Result<()> {
    c.execute(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at, revoked_at, tags, scope)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, name = excluded.name,
            token_hash = excluded.token_hash, created_at = excluded.created_at,
            revoked_at = excluded.revoked_at, tags = excluded.tags, scope = excluded.scope",
        params![
            t.id,
            t.user_id,
            t.name,
            t.token_hash,
            t.created_at,
            t.revoked_at,
            serde_json::to_string(&t.tags)?,
            crate::storage::scope_column(t.scope.as_ref()),
        ],
    )?;
    Ok(())
}

fn token_tags(
    c: &Connection,
    id: i64,
    tags: &[String],
    scope: Option<&crate::model::TokenScope>,
) -> Result<()> {
    c.execute(
        "UPDATE api_tokens SET tags = ?2 WHERE id = ?1",
        params![id, serde_json::to_string(tags)?],
    )?;
    if let Some(scope) = scope {
        c.execute(
            "UPDATE api_tokens SET scope = ?2 WHERE id = ?1",
            params![id, crate::storage::scope_column(Some(scope))],
        )?;
    }
    Ok(())
}

fn token_revoked(c: &Connection, id: i64, at: &str) -> Result<()> {
    c.execute(
        "UPDATE api_tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
        params![id, at],
    )?;
    Ok(())
}

fn put_tsig_key(c: &Connection, k: &ReplTsigKey) -> Result<()> {
    let secret = data_encoding::BASE64
        .decode(k.secret.as_bytes())
        .with_context(|| format!("TSIG key {}: secret is not base64", k.name))?;
    c.execute(
        "INSERT INTO tsig_keys (name, algorithm, secret, zones, created_by, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(name) DO UPDATE SET algorithm = excluded.algorithm, secret = excluded.secret,
            zones = excluded.zones, created_by = excluded.created_by, created_at = excluded.created_at,
            updated_at = excluded.updated_at",
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
    Ok(())
}

fn delete_tsig_key(c: &Connection, name: &str) -> Result<()> {
    c.execute("DELETE FROM tsig_keys WHERE name = ?1", params![name])?;
    Ok(())
}

fn put_setting(c: &Connection, s: &ReplSetting) -> Result<()> {
    c.execute(
        "INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        params![s.key, s.value, s.updated_by, s.updated_at],
    )?;
    Ok(())
}

fn delete_setting(c: &Connection, key: &str) -> Result<()> {
    c.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
    Ok(())
}

fn put_dnssec_key(c: &Connection, k: &crate::replication::types::ReplDnssecKey) -> Result<()> {
    c.execute(
        "INSERT INTO dnssec_keys (zone_id, zone, algorithm, flags, key_tag, public_key, private_key, created_at, rollover)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(zone_id) DO UPDATE SET zone = excluded.zone, algorithm = excluded.algorithm,
            flags = excluded.flags, key_tag = excluded.key_tag, public_key = excluded.public_key,
            private_key = excluded.private_key, created_at = excluded.created_at,
            rollover = excluded.rollover",
        params![
            k.zone_id,
            k.zone,
            k.algorithm as i64,
            k.flags as i64,
            k.key_tag as i64,
            k.public_key,
            k.private_key.0,
            k.created_at,
            k.rollover.as_ref().map(serde_json::to_string).transpose()?,
        ],
    )?;
    Ok(())
}

fn delete_dnssec_key(c: &Connection, zone_id: i64) -> Result<()> {
    c.execute(
        "DELETE FROM dnssec_keys WHERE zone_id = ?1",
        params![zone_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B2: the compiler enforces "no account write without its change":
    /// the SQL functions are private, `write` is the only entry and its
    /// receipt is `#[must_use]`; the raw connection of an `AuditTx` is
    /// private to accounts.rs.
    #[test]
    fn account_tables_are_written_only_through_write() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mutation");
        let src = std::fs::read_to_string(dir.join("acct_sql.rs")).unwrap();
        let code = src.split("#[cfg(test)]").next().unwrap();
        let public: Vec<&str> = code
            .lines()
            .filter(|l| l.trim_start().starts_with("pub") && l.contains(" fn "))
            .map(|l| l.trim())
            .collect();
        for l in &public {
            assert!(
                [
                    "fn verbatim(",
                    "fn log_into(",
                    "fn replayed(",
                    "fn write(",
                    "fn next_id("
                ]
                .iter()
                .any(|ok| l.contains(ok)),
                "acct_sql exposes a write function besides `write`: {l}"
            );
        }
        assert!(code.contains("#[must_use = \"an account write must be changelogged"));
        let accounts = std::fs::read_to_string(dir.join("accounts.rs")).unwrap();
        assert!(
            accounts.contains("pub struct AuditTx<'a> {\n    conn: &'a Connection,"),
            "AuditTx.conn must stay private"
        );
        // A DNS change cannot be written here: `write` takes a
        // `SecretChange` (E2; was a runtime error before). An account
        // change is, and the receipt must be turned in.
        let s = crate::storage::Storage::open_memory().unwrap();
        let r = s.write(&crate::mutation::TOKEN, |c| -> Result<()> {
            let set = SecretChange::SettingSet {
                setting: ReplSetting {
                    key: "k".into(),
                    value: "{}".into(),
                    updated_by: "t".into(),
                    updated_at: "t".into(),
                },
            };
            let mut log = Vec::new();
            write(c, &Ctx::verbatim(), &set)?.log_into(set.clone(), &mut log);
            assert_eq!(log.len(), 1);
            write(c, &Ctx::verbatim(), &set)?.replayed();
            Ok(())
        });
        r.unwrap();
        assert!(s.get_setting("k").unwrap().is_some());
    }

    /// Structural guarantee: no file of the mutation module other than this
    /// one (and the snapshot loader / `--prepare-standby` in replica.rs)
    /// writes an account table.
    #[test]
    fn only_acct_sql_writes_account_tables() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mutation");
        let tables = [
            "users",
            "recovery_codes",
            "api_tokens",
            "settings",
            "tsig_keys",
            "dnssec_keys",
        ];
        for e in std::fs::read_dir(&dir).unwrap() {
            let path = e.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if matches!(name.as_str(), "acct_sql.rs" | "replica.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            // Test modules may seed data directly.
            let src = src
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .to_ascii_uppercase();
            for t in tables {
                let t = t.to_ascii_uppercase();
                for w in [
                    format!("INSERT INTO {t} "),
                    format!("INSERT INTO {t}("),
                    format!("UPDATE {t} "),
                    format!("DELETE FROM {t} "),
                    format!("DELETE FROM {t}\""),
                    format!("DELETE FROM {t};"),
                ] {
                    assert!(
                        !src.contains(&w),
                        "{name} writes {t} directly ({w:?}): record a Change through AuditTx::record instead"
                    );
                }
            }
        }
    }
}
