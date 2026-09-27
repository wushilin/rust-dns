//! Audited writes for users, credentials, sessions and API tokens.
//!
//! Same guarantee as the DNS changelog: every write goes through an
//! [`AuditTx`], each write method records an [`AuditEntry`], and the entries
//! are written to `audit_log` in the same SQLite transaction as the data.
//! A rolled-back operation leaves no audit row and is logged instead.
//!
//! Deliberately not audited (operational bookkeeping in `storage.rs`):
//! session `last_seen_at`, API token `last_used_at` / `last_used_ip`, and
//! pruning of expired sessions and old log rows.

use super::TOKEN;
use crate::model::*;
use crate::storage::{self as db, Storage, TokenInfo};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub action: &'static str,
    pub target_user_id: Option<i64>,
    pub target: String,
    pub detail: serde_json::Value,
}

/// A committed audit row, as stored and returned by the API.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "id": 5, "ts": "2026-01-15T10:02:11.482Z", "txn": "01J0Z8Y1QW2E", "operation": "create_user",
    "actor": "root", "actor_ip": "192.0.2.1", "action": "user_created", "target_user_id": 2,
    "target": "alice", "detail": { "username": "alice", "is_admin": false }
}))]
pub struct AuditRecord {
    pub id: i64,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub ts: String,
    /// Shared by every row written in the same transaction.
    pub txn: String,
    /// The API operation (create_user, login, revoke_token, ...).
    pub operation: String,
    pub actor: String,
    pub actor_ip: String,
    /// What happened (user_created, session_created, token_revoked, ...).
    pub action: String,
    #[schema(required = true)]
    pub target_user_id: Option<i64>,
    pub target: String,
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
}

/// The only handle an account operation gets on the database.
pub struct AuditTx<'a> {
    // Visible to sibling mutation modules (e.g. `settings`) that add audited writes.
    pub(super) conn: &'a Connection,
    entries: Vec<AuditEntry>,
}

fn user_detail(u: &User) -> serde_json::Value {
    serde_json::json!({
        "username": u.username,
        "display_name": u.display_name,
        "is_admin": u.is_admin,
        "mfa_required": u.mfa_required,
        "disabled": u.disabled_at.is_some(),
    })
}

impl<'a> AuditTx<'a> {
    pub(super) fn push(
        &mut self,
        action: &'static str,
        target_user_id: Option<i64>,
        target: &str,
        detail: serde_json::Value,
    ) {
        self.entries.push(AuditEntry {
            action,
            target_user_id,
            target: target.to_string(),
            detail,
        });
    }

    // ---- users -----------------------------------------------------------

    pub fn create_user(&mut self, u: &NewUser) -> Result<User> {
        let now = now_rfc3339();
        self.conn.execute(
            "INSERT INTO users (username, password_hash, display_name, is_admin, is_root, mfa_required, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?6)",
            params![u.username, u.password_hash, u.display_name, u.is_admin as i64, u.mfa_required as i64, now],
        )?;
        let user = db::get_user(self.conn, self.conn.last_insert_rowid())?.expect("just inserted");
        self.push(
            "user.create",
            Some(user.id),
            &user.username,
            user_detail(&user),
        );
        Ok(user)
    }

    /// Write `after` over `before`. The audit detail lists what changed;
    /// secrets are reported only as "changed".
    pub fn update_user(&mut self, before: &User, after: &User) -> Result<User> {
        self.conn.execute(
            "UPDATE users SET password_hash=?2, display_name=?3, is_admin=?4, mfa_required=?5, totp_secret=?6,
             totp_enrolled_at=?7, disabled_at=?8, updated_at=?9 WHERE id=?1",
            params![
                before.id, after.password_hash, after.display_name, after.is_admin as i64, after.mfa_required as i64,
                after.totp_secret, after.totp_enrolled_at, after.disabled_at, now_rfc3339()
            ],
        )?;
        let user = db::get_user(self.conn, before.id)?.expect("exists");
        let mut changed = serde_json::Map::new();
        if before.display_name != user.display_name {
            changed.insert(
                "display_name".into(),
                serde_json::json!([before.display_name, user.display_name]),
            );
        }
        if before.is_admin != user.is_admin {
            changed.insert(
                "is_admin".into(),
                serde_json::json!([before.is_admin, user.is_admin]),
            );
        }
        if before.mfa_required != user.mfa_required {
            changed.insert(
                "mfa_required".into(),
                serde_json::json!([before.mfa_required, user.mfa_required]),
            );
        }
        if before.disabled_at.is_some() != user.disabled_at.is_some() {
            changed.insert(
                "disabled".into(),
                serde_json::json!([before.disabled_at.is_some(), user.disabled_at.is_some()]),
            );
        }
        if before.password_hash != user.password_hash {
            changed.insert("password".into(), "changed".into());
        }
        if before.totp_secret.is_some() != user.totp_secret.is_some() {
            changed.insert(
                "mfa".into(),
                if user.totp_secret.is_some() {
                    "enrolled"
                } else {
                    "removed"
                }
                .into(),
            );
        } else if before.totp_secret != user.totp_secret {
            changed.insert("mfa".into(), "re-enrolled".into());
        }
        if !changed.is_empty() {
            self.push(
                "user.update",
                Some(user.id),
                &user.username,
                serde_json::Value::Object(changed),
            );
        }
        Ok(user)
    }

    pub fn delete_user(&mut self, u: &User) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM users WHERE id = ?1 AND is_root = 0",
            params![u.id],
        )?;
        if n > 0 {
            self.push("user.delete", Some(u.id), &u.username, user_detail(u));
        }
        Ok(n > 0)
    }

    /// Create or refresh the root user from configuration. Audited only when
    /// something actually changed.
    pub fn sync_root(
        &mut self,
        username: &str,
        password_hash: &str,
        mfa_required: bool,
    ) -> Result<User> {
        let before = self
            .conn
            .query_row(
                &format!("SELECT {} FROM users WHERE username = ?1", db::USER_COLS),
                params![username],
                db::row_to_user,
            )
            .ok();
        let demoted = self.conn.execute(
            "UPDATE users SET is_root = 0 WHERE is_root = 1 AND username <> ?1",
            params![username],
        )?;
        let now = now_rfc3339();
        self.conn.execute(
            "INSERT INTO users (username, password_hash, display_name, is_admin, is_root, mfa_required, created_at, updated_at)
             VALUES (?1, ?2, 'Root', 1, 1, ?3, ?4, ?4)
             ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1, is_root = 1,
                mfa_required = excluded.mfa_required, disabled_at = NULL,
                updated_at = CASE WHEN users.password_hash <> excluded.password_hash OR users.mfa_required <> excluded.mfa_required
                                    OR users.is_admin = 0 OR users.is_root = 0 OR users.disabled_at IS NOT NULL
                                  THEN excluded.updated_at ELSE users.updated_at END",
            params![username, password_hash, mfa_required as i64, now],
        )?;
        let user = self.conn.query_row(
            &format!("SELECT {} FROM users WHERE username = ?1", db::USER_COLS),
            params![username],
            db::row_to_user,
        )?;
        let changed = match &before {
            None => Some(serde_json::json!({ "created": true })),
            Some(b) => {
                let mut m = serde_json::Map::new();
                if b.password_hash != user.password_hash {
                    m.insert("password".into(), "changed".into());
                }
                if b.mfa_required != user.mfa_required {
                    m.insert(
                        "mfa_required".into(),
                        serde_json::json!([b.mfa_required, user.mfa_required]),
                    );
                }
                if !b.is_root || !b.is_admin || b.disabled_at.is_some() {
                    m.insert("restored".into(), true.into());
                }
                (!m.is_empty()).then_some(serde_json::Value::Object(m))
            }
        };
        if demoted > 0 {
            self.push(
                "root.demote_previous",
                None,
                username,
                serde_json::json!({ "demoted": demoted }),
            );
        }
        if let Some(detail) = changed {
            self.push("root.sync", Some(user.id), &user.username, detail);
        }
        Ok(user)
    }

    // ---- recovery codes --------------------------------------------------

    pub fn set_recovery_codes(&mut self, user: &User, hashes: &[String]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM recovery_codes WHERE user_id = ?1",
            params![user.id],
        )?;
        for h in hashes {
            self.conn.execute(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                params![user.id, h],
            )?;
        }
        self.push(
            "recovery_codes.replace",
            Some(user.id),
            &user.username,
            serde_json::json!({ "count": hashes.len() }),
        );
        Ok(())
    }

    /// Consume an unused recovery code. Audited only when a code was used.
    pub fn use_recovery_code(&mut self, user: &User, hash: &str) -> Result<bool> {
        let used = self.conn.execute(
            "UPDATE recovery_codes SET used_at = ?3 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
            params![user.id, hash, now_rfc3339()],
        )? > 0;
        if used {
            let left: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                params![user.id],
                |r| r.get(0),
            )?;
            self.push(
                "recovery_code.use",
                Some(user.id),
                &user.username,
                serde_json::json!({ "left": left }),
            );
        }
        Ok(used)
    }

    // ---- sessions ----------------------------------------------------------

    pub fn create_session(&mut self, user: &User, s: &Session) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO sessions (token_hash, user_id, state, pending_secret, ip, user_agent, created_at, expires_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![s.token_hash, s.user_id, s.state, s.pending_secret, s.ip, s.user_agent, s.created_at, s.expires_at, s.last_seen_at],
        )?;
        let id = self.conn.last_insert_rowid();
        self.push(
            "session.create",
            Some(user.id),
            &user.username,
            serde_json::json!({ "session_id": id, "state": s.state, "ip": s.ip, "user_agent": s.user_agent, "expires_at": s.expires_at }),
        );
        Ok(id)
    }

    pub fn set_session_state(
        &mut self,
        user: &User,
        s: &Session,
        state: &str,
        pending_secret: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET state = ?2, pending_secret = ?3 WHERE id = ?1",
            params![s.id, state, pending_secret],
        )?;
        self.push(
            "session.update",
            Some(user.id),
            &user.username,
            serde_json::json!({ "session_id": s.id, "from": s.state, "to": state, "enrollment_pending": pending_secret.is_some() }),
        );
        Ok(())
    }

    pub fn delete_session(&mut self, user: &User, s: &Session, reason: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?1", params![s.id])?;
        self.push(
            "session.delete",
            Some(user.id),
            &user.username,
            serde_json::json!({ "session_id": s.id, "ip": s.ip, "reason": reason }),
        );
        Ok(())
    }

    pub fn delete_user_sessions(&mut self, user: &User, reason: &str) -> Result<usize> {
        let n = self
            .conn
            .execute("DELETE FROM sessions WHERE user_id = ?1", params![user.id])?;
        self.push(
            "session.revoke_all",
            Some(user.id),
            &user.username,
            serde_json::json!({ "count": n, "reason": reason }),
        );
        Ok(n)
    }

    pub fn delete_other_sessions(&mut self, user: &User, keep: i64) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2",
            params![user.id, keep],
        )?;
        self.push(
            "session.revoke_others",
            Some(user.id),
            &user.username,
            serde_json::json!({ "count": n, "kept_session_id": keep }),
        );
        Ok(n)
    }

    // ---- API tokens ----------------------------------------------------------

    /// `tags` are normalized here too (callers should validate first to
    /// report a 400; an invalid list rolls the transaction back).
    pub fn create_token(
        &mut self,
        user: &User,
        name: &str,
        token_hash: &str,
        tags: &[String],
    ) -> Result<TokenInfo> {
        let tags = normalize_tags(tags)?;
        self.conn.execute(
            "INSERT INTO api_tokens (user_id, name, token_hash, created_at, tags) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.id, name, token_hash, now_rfc3339(), serde_json::to_string(&tags)?],
        )?;
        let id = self.conn.last_insert_rowid();
        self.push(
            "token.create",
            Some(user.id),
            &user.username,
            serde_json::json!({ "token_id": id, "name": name, "tags": tags }),
        );
        Ok(db::get_token(self.conn, id)?.expect("just inserted"))
    }

    /// Replace a token's tags. Audited (`token.update`, before and after)
    /// only when the normalized list actually changed.
    pub fn update_token_tags(
        &mut self,
        owner: &User,
        t: &TokenInfo,
        tags: &[String],
    ) -> Result<TokenInfo> {
        let tags = normalize_tags(tags)?;
        self.conn.execute(
            "UPDATE api_tokens SET tags = ?2 WHERE id = ?1",
            params![t.id, serde_json::to_string(&tags)?],
        )?;
        let after = db::get_token(self.conn, t.id)?.context("token vanished")?;
        if after.tags != t.tags {
            self.push(
                "token.update",
                Some(owner.id),
                &owner.username,
                serde_json::json!({
                    "token_id": t.id,
                    "name": t.name,
                    "tags": { "before": t.tags, "after": after.tags },
                }),
            );
        }
        Ok(after)
    }

    pub fn revoke_token(&mut self, owner: &User, t: &TokenInfo) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE api_tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![now_rfc3339(), t.id],
        )?;
        if n > 0 {
            self.push(
                "token.revoke",
                Some(owner.id),
                &owner.username,
                serde_json::json!({ "token_id": t.id, "name": t.name }),
            );
        }
        Ok(n > 0)
    }

    fn finish(self, actor: &Actor, operation: &str) -> Result<Vec<AuditRecord>> {
        let txn = crate::auth::random_token(9);
        let ts = now_rfc3339();
        let mut out = Vec::with_capacity(self.entries.len());
        for e in self.entries {
            let detail = serde_json::to_string(&e.detail)?;
            self.conn.execute(
                "INSERT INTO audit_log (ts, txn, operation, actor, actor_ip, action, target_user_id, target, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![ts, txn, operation, actor.name, actor.ip, e.action, e.target_user_id, e.target, detail],
            )?;
            out.push(AuditRecord {
                id: self.conn.last_insert_rowid(),
                ts: ts.clone(),
                txn: txn.clone(),
                operation: operation.to_string(),
                actor: actor.name.clone(),
                actor_ip: actor.ip.clone(),
                action: e.action.to_string(),
                target_user_id: e.target_user_id,
                target: e.target,
                detail: e.detail,
            });
        }
        Ok(out)
    }
}

/// Entry point for account and security writes.
pub struct Accounts {
    storage: Arc<Storage>,
}

impl Accounts {
    pub fn new(storage: Arc<Storage>) -> Self {
        Accounts { storage }
    }

    /// Run `f` as one transaction. Committed: data and audit rows are
    /// durable. Rolled back: nothing is written and the failure is logged.
    pub fn run<T>(
        &self,
        actor: &Actor,
        operation: &'static str,
        f: impl FnOnce(&mut AuditTx) -> Result<T>,
    ) -> Result<T> {
        let result = self
            .storage
            .write(&TOKEN, |conn| -> Result<(T, Vec<AuditRecord>)> {
                let mut t = AuditTx {
                    conn,
                    entries: Vec::new(),
                };
                let out = f(&mut t)?;
                let records = t.finish(actor, operation)?;
                Ok((out, records))
            });
        match result {
            Ok((out, records)) => {
                for r in &records {
                    tracing::info!(audit_id = r.id, txn = %r.txn, operation, actor = %r.actor, ip = %r.actor_ip, action = %r.action, target = %r.target, "audit");
                }
                Ok(out)
            }
            Err(e) => {
                tracing::warn!(operation, actor = %actor.name, ip = %actor.ip, error = %e, "account transaction rolled back; nothing committed, no audit entry written");
                Err(e)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn storage_for_tests(&self) -> Arc<Storage> {
        self.storage.clone()
    }

    // ---- one-step conveniences -------------------------------------------------

    pub fn create_user(&self, actor: &Actor, u: &NewUser) -> Result<User> {
        self.run(actor, "create_user", |t| t.create_user(u))
    }

    pub fn update_user(&self, actor: &Actor, before: &User, after: &User) -> Result<User> {
        self.run(actor, "update_user", |t| t.update_user(before, after))
    }

    pub fn sync_root(
        &self,
        username: &str,
        password_hash: &str,
        mfa_required: bool,
    ) -> Result<User> {
        let system = Actor {
            name: "system".into(),
            ip: "config".into(),
        };
        self.run(&system, "sync_root", |t| {
            t.sync_root(username, password_hash, mfa_required)
        })
        .context("syncing the root user from configuration")
    }

    pub fn create_token(
        &self,
        actor: &Actor,
        user: &User,
        name: &str,
        token_hash: &str,
        tags: &[String],
    ) -> Result<TokenInfo> {
        self.run(actor, "create_token", |t| {
            t.create_token(user, name, token_hash, tags)
        })
    }
}

/// Most tags one token may carry.
pub const MAX_TOKEN_TAGS: usize = 16;
/// Longest tag, in characters.
pub const MAX_TOKEN_TAG_LEN: usize = 256;

/// Validate and normalize token tags: each is trimmed and must then be 1-256
/// characters of `[A-Za-z0-9_-]` (case is kept); exact duplicates are dropped
/// and the result is sorted. At most [`MAX_TOKEN_TAGS`] distinct tags.
pub fn normalize_tags(raw: &[String]) -> Result<Vec<String>, Invalid> {
    let mut out = std::collections::BTreeSet::new();
    for t in raw {
        out.insert(normalize_tag(t)?);
    }
    if out.len() > MAX_TOKEN_TAGS {
        return Err(Invalid(format!(
            "at most {MAX_TOKEN_TAGS} tags per token (got {})",
            out.len()
        )));
    }
    Ok(out.into_iter().collect())
}

/// Validate and normalize one tag (see [`normalize_tags`]).
pub fn normalize_tag(raw: &str) -> Result<String, Invalid> {
    let t = raw.trim().to_string();
    if t.is_empty() || t.chars().count() > MAX_TOKEN_TAG_LEN {
        return Err(Invalid(format!(
            "tag '{}' must be 1-{MAX_TOKEN_TAG_LEN} characters",
            raw.trim()
        )));
    }
    if let Some(c) = t
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
    {
        return Err(Invalid(format!(
            "tag '{}' contains '{c}': only A-Z, a-z, 0-9, '_' and '-' are allowed",
            raw.trim()
        )));
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> Actor {
        Actor {
            name: "tester".into(),
            ip: "127.0.0.1".into(),
        }
    }

    fn new_user(name: &str) -> NewUser {
        NewUser {
            username: name.into(),
            password_hash: "h".into(),
            display_name: String::new(),
            is_admin: false,
            mfa_required: false,
        }
    }

    #[test]
    fn committed_writes_are_audited_in_the_same_transaction() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("alice")).unwrap();
        let mut after = u.clone();
        after.is_admin = true;
        after.password_hash = "h2".into();
        a.update_user(&actor(), &u, &after).unwrap();
        let log = s.audit_after(0, 100).unwrap();
        assert_eq!(
            log.iter().map(|r| r.action.as_str()).collect::<Vec<_>>(),
            vec!["user.create", "user.update"]
        );
        assert_eq!(log[1].detail["password"], "changed");
        assert_eq!(log[1].detail["is_admin"], serde_json::json!([false, true]));
        assert!(
            !log[1].detail.to_string().contains("h2"),
            "secrets never appear in the audit detail"
        );
    }

    #[test]
    fn rolled_back_operations_leave_no_data_and_no_audit() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        a.create_user(&actor(), &new_user("bob")).unwrap();
        let before = s.audit_after(0, 100).unwrap().len();
        // Second step fails (duplicate username): the first insert must roll back too.
        let r = a.run(&actor(), "two_users", |t| {
            t.create_user(&new_user("carol"))?;
            t.create_user(&new_user("bob"))
        });
        assert!(r.is_err());
        assert!(
            s.get_user_by_name("carol").unwrap().is_none(),
            "partial work rolled back"
        );
        assert_eq!(
            s.audit_after(0, 100).unwrap().len(),
            before,
            "no audit rows for a rolled-back transaction"
        );
    }

    #[test]
    fn root_sync_is_audited_only_when_something_changed() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        a.sync_root("root", "hash1", false).unwrap();
        a.sync_root("root", "hash1", false).unwrap();
        a.sync_root("root", "hash2", false).unwrap();
        let actions: Vec<String> = s
            .audit_after(0, 100)
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert_eq!(actions, vec!["root.sync", "root.sync"]);
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tags_are_trimmed_deduped_and_sorted() {
        assert_eq!(
            normalize_tags(&strs(&[" CI ", "home-assistant", "ci", "v1_2-X", "CI"])).unwrap(),
            strs(&["CI", "ci", "home-assistant", "v1_2-X"]),
            "case is kept; only exact duplicates are dropped"
        );
        assert_eq!(normalize_tags(&[]).unwrap(), Vec::<String>::new());
        let max: Vec<String> = (0..MAX_TOKEN_TAGS).map(|i| format!("t{i}")).collect();
        assert_eq!(normalize_tags(&max).unwrap().len(), MAX_TOKEN_TAGS);
        // 17 raw tags that dedupe to 16 are fine.
        let mut dup = max.clone();
        dup.push(" t0 ".into());
        assert_eq!(normalize_tags(&dup).unwrap().len(), MAX_TOKEN_TAGS);
        assert_eq!(normalize_tag(&"a".repeat(256)).unwrap().len(), 256);
    }

    #[test]
    fn invalid_tags_are_rejected() {
        for bad in [
            "",
            "   ",
            "has space",
            "semi;colon",
            "ünï",
            "a/b",
            "v1.2",
            &"a".repeat(257),
        ] {
            assert!(
                normalize_tags(&strs(&[bad])).is_err(),
                "'{bad}' should be rejected"
            );
        }
        let too_many: Vec<String> = (0..=MAX_TOKEN_TAGS).map(|i| format!("t{i}")).collect();
        let e = normalize_tags(&too_many).unwrap_err();
        assert!(e.0.contains("at most 16"), "{}", e.0);
    }

    #[test]
    fn token_create_and_tag_update_are_audited() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("dora")).unwrap();
        let t = a
            .create_token(&actor(), &u, "ci", "hash-1", &strs(&["deploy", "ci", "ci"]))
            .unwrap();
        assert_eq!(t.tags, strs(&["ci", "deploy"]));
        assert_eq!(t.last_used_ip, None);
        let t2 = a
            .run(&actor(), "update_token", |tx| {
                tx.update_token_tags(&u, &t, &strs(&["ansible"]))
            })
            .unwrap();
        assert_eq!(t2.tags, strs(&["ansible"]));
        // Same tags again (after normalization): no audit entry.
        a.run(&actor(), "update_token", |tx| {
            tx.update_token_tags(&u, &t2, &strs(&[" ansible "]))
        })
        .unwrap();
        // Invalid tags roll back: nothing stored, nothing audited.
        assert!(a
            .run(&actor(), "update_token", |tx| {
                tx.update_token_tags(&u, &t2, &strs(&["bad tag"]))
            })
            .is_err());
        assert!(a
            .create_token(&actor(), &u, "x", "hash-2", &strs(&["no!"]))
            .is_err());
        assert_eq!(s.get_token(t.id).unwrap().unwrap().tags, strs(&["ansible"]));
        assert_eq!(s.list_tokens(Some(u.id), None).unwrap().len(), 1);

        let log = s.audit_after(0, 100).unwrap();
        let actions: Vec<&str> = log.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(actions, vec!["user.create", "token.create", "token.update"]);
        assert_eq!(log[1].detail["tags"], serde_json::json!(["ci", "deploy"]));
        assert_eq!(log[1].detail["token_id"], t.id);
        assert_eq!(log[2].operation, "update_token");
        assert_eq!(log[2].target, "dora");
        assert_eq!(
            log[2].detail["tags"],
            serde_json::json!({ "before": ["ci", "deploy"], "after": ["ansible"] })
        );
    }
}
