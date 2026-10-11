//! Audited writes for users, credentials, sessions and API tokens.
//!
//! Same guarantee as the DNS changelog: every write goes through an
//! [`AuditTx`], each write method records an [`AuditEntry`], and the entries
//! are written to `audit_log` in the same SQLite transaction as the data.
//! A rolled-back operation leaves no audit row and is logged instead.
//!
//! Writes to replicated tables are typed `Change`s (see [`AuditTx::record`])
//! committed to the changelog in the same transaction, so a standby replays
//! them exactly like DNS changes.
//!
//! Deliberately not audited (operational bookkeeping in `storage.rs`):
//! session `last_seen_at`, API token `last_used_at` / `last_used_ip`, and
//! pruning of expired sessions and old log rows.

use super::acct_sql::{self, Ctx};
use super::{Change, SecretChange, TOKEN};
use crate::model::*;
use crate::replication::data;
use crate::replication::types::{Hidden, ReplToken, ReplUser};
use crate::storage::{self as db, Storage, TokenInfo};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
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

/// Fields an administrator may change on a user; `None` = leave as is.
#[derive(Debug, Clone, Default)]
pub struct UserChanges {
    pub display_name: Option<String>,
    pub is_admin: Option<bool>,
    pub mfa_required: Option<bool>,
    pub disabled: Option<bool>,
    pub password_hash: Option<String>,
}

/// The only handle an account operation gets on the database.
///
/// Writes to replicated tables (users, recovery codes, API tokens, console
/// settings, TSIG keys) go through [`AuditTx::record`]: it applies a typed
/// [`Change`] with the same code a standby replays it with, and queues it
/// for the changelog, which is written with the audit rows at commit.
/// The connection is private to this file: sibling modules (settings,
/// tsig) read through the methods below and can write only with `record`.
/// Sessions and the replica list are local tables, written here directly
/// (bookkeeping, audited).
pub struct AuditTx<'a> {
    conn: &'a Connection,
    entries: Vec<AuditEntry>,
    changes: Vec<Change>,
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

fn to_user(u: &ReplUser) -> User {
    User {
        id: u.id,
        username: u.username.clone(),
        password_hash: u.password_hash.clone(),
        display_name: u.display_name.clone(),
        is_admin: u.is_admin,
        is_root: u.is_root,
        mfa_required: u.mfa_required,
        totp_secret: u.totp_secret.clone(),
        totp_enrolled_at: u.totp_enrolled_at.clone(),
        disabled_at: u.disabled_at.clone(),
        created_at: u.created_at.clone(),
        updated_at: u.updated_at.clone(),
    }
}

impl<'a> AuditTx<'a> {
    /// An audited transaction on `conn` for sibling mutation modules that
    /// combine audited writes with other writes in one SQLite transaction
    /// (replication). Must be closed with [`AuditTx::commit_entries`].
    pub(super) fn begin(conn: &'a Connection) -> Self {
        AuditTx {
            conn,
            entries: Vec::new(),
            changes: Vec::new(),
        }
    }

    /// Write the collected audit rows (same transaction). Recorded changes
    /// are not changelogged on this path (replication writes its own rows).
    pub(super) fn commit_entries(self, actor: &Actor, operation: &str) -> Result<Vec<AuditRecord>> {
        let txn = crate::auth::random_token(9);
        self.finish(actor, operation, &txn, false).map(|(a, _)| a)
    }

    /// Apply an account change and queue it for the changelog. The only
    /// way to write a replicated account table (see `acct_sql`).
    pub(super) fn record(&mut self, change: SecretChange) -> Result<()> {
        acct_sql::write(self.conn, &Ctx::verbatim(), &change)?.log_into(change, &mut self.changes);
        Ok(())
    }

    // ---- reads for sibling mutation modules -------------------------------

    pub(super) fn tsig_key(&self, name: &str) -> Result<Option<db::StoredTsigKey>> {
        db::get_tsig_key(self.conn, name)
    }

    pub(super) fn has_setting(&self, key: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM settings WHERE key = ?1)",
            params![key],
            |r| r.get(0),
        )?)
    }

    /// The security settings as stored in this transaction (O6).
    pub(super) fn security(&self) -> Result<super::settings::SecuritySettings> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![super::settings::SECURITY_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match v {
            Some(v) => serde_json::from_str(&v)?,
            None => Default::default(),
        })
    }

    /// Tests: look at the transaction's state.
    #[cfg(test)]
    pub(super) fn conn(&self) -> &Connection {
        self.conn
    }

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

    fn row(&self, id: i64) -> Result<ReplUser> {
        data::user_row(self.conn, id)?.context("user not found")
    }

    // ---- users -----------------------------------------------------------

    pub fn create_user(&mut self, u: &NewUser) -> Result<User> {
        if data::user_by_name(self.conn, &u.username)?.is_some() {
            anyhow::bail!("UNIQUE constraint failed: users.username");
        }
        let now = now_rfc3339();
        let row = ReplUser {
            id: acct_sql::next_id(self.conn, "users")?,
            username: u.username.clone(),
            password_hash: u.password_hash.clone(),
            display_name: u.display_name.clone(),
            is_admin: u.is_admin,
            is_root: false,
            mfa_required: u.mfa_required,
            totp_secret: None,
            totp_enrolled_at: None,
            totp_last_step: None,
            disabled_at: None,
            created_at: now.clone(),
            updated_at: now,
            password_history: None,
        };
        self.record(SecretChange::UserCreated { user: row.clone() })?;
        let user = to_user(&row);
        self.push(
            "user.create",
            Some(user.id),
            &user.username,
            user_detail(&user),
        );
        Ok(user)
    }

    fn load_user(&self, id: i64) -> Result<User> {
        Ok(to_user(&self.row(id)?))
    }

    /// Audit what changed between two versions of a user. Secrets are
    /// reported only as "changed".
    fn audit_user_change(&mut self, before: &User, user: &User) {
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
    }

    /// Write a user's new row (when it differs) and audit the difference.
    /// O6: a new password pushes the previous one onto the password history
    /// when the security settings keep one (`password_history` > 0; read in
    /// this transaction), trimmed to that length; with none kept, a stored
    /// history is dropped at the next password change. Root keeps none.
    fn update_row(&mut self, before: ReplUser, mut after: ReplUser) -> Result<User> {
        if after == before {
            return Ok(to_user(&after));
        }
        if after.password_hash != before.password_hash {
            let keep = if after.is_root {
                0
            } else {
                self.security()?.password_history as usize
            };
            after.password_history = (keep > 0).then(|| {
                let mut h = vec![before.password_hash.clone()];
                h.extend(before.password_history.clone().unwrap_or_default());
                h.truncate(keep);
                h
            });
        }
        after.updated_at = now_rfc3339();
        self.record(SecretChange::UserUpdated {
            user: after.clone(),
        })?;
        let (b, a) = (to_user(&before), to_user(&after));
        self.audit_user_change(&b, &a);
        Ok(a)
    }

    /// Administrator edit. Only the fields set in `ch` change; the row is
    /// read inside this transaction, so a concurrent self-service change
    /// (password, MFA) is neither overwritten nor able to overwrite this one.
    pub fn change_user(&mut self, user_id: i64, ch: &UserChanges) -> Result<User> {
        let before = self.row(user_id)?;
        let mut after = before.clone();
        if let Some(d) = &ch.display_name {
            after.display_name = d.clone();
        }
        if let Some(a) = ch.is_admin {
            after.is_admin = a;
        }
        if let Some(m) = ch.mfa_required {
            after.mfa_required = m;
        }
        if let Some(d) = ch.disabled {
            after.disabled_at = if d {
                after.disabled_at.clone().or_else(|| Some(now_rfc3339()))
            } else {
                None
            };
        }
        if let Some(h) = &ch.password_hash {
            after.password_hash = h.clone();
        }
        self.update_row(before, after)
    }

    /// Set a new password hash (self-service or administrator).
    pub fn set_password(&mut self, user_id: i64, password_hash: &str) -> Result<User> {
        self.change_user(
            user_id,
            &UserChanges {
                password_hash: Some(password_hash.to_string()),
                ..UserChanges::default()
            },
        )
    }

    /// Enroll (`Some(secret)`) or remove (`None`) TOTP; the replay marker
    /// starts over with the new secret.
    pub fn set_mfa(&mut self, user_id: i64, secret: Option<&str>) -> Result<User> {
        let before = self.row(user_id)?;
        let mut after = before.clone();
        after.totp_secret = secret.map(str::to_string);
        after.totp_enrolled_at = secret.map(|_| now_rfc3339());
        after.totp_last_step = None;
        self.update_row(before, after)
    }

    /// Record that a TOTP code of time step `step` was accepted for `user`.
    /// Returns false (and writes nothing) when that step or a later one was
    /// already used: the code is a replay and must be refused.
    pub fn accept_totp_step(&mut self, user: &User, step: u64) -> Result<bool> {
        let step = step as i64;
        let row = self.row(user.id)?;
        if row.totp_secret.is_none() || row.totp_last_step.is_some_and(|l| l >= step) {
            return Ok(false);
        }
        self.record(SecretChange::TotpStepAccepted {
            user_id: user.id,
            step,
        })?;
        self.push(
            "totp.accept",
            Some(user.id),
            &user.username,
            serde_json::json!({ "step": step }),
        );
        Ok(true)
    }

    pub fn delete_user(&mut self, u: &User) -> Result<bool> {
        match data::user_row(self.conn, u.id)? {
            Some(r) if !r.is_root => {
                self.record(SecretChange::UserDeleted {
                    user_id: r.id,
                    username: r.username.clone(),
                })?;
                self.push("user.delete", Some(u.id), &u.username, user_detail(u));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Create or refresh the root user from configuration. Written (and
    /// audited) only when something actually changed.
    pub fn sync_root(
        &mut self,
        username: &str,
        password_hash: &str,
        mfa_required: bool,
    ) -> Result<User> {
        // A renamed root: the previous root account must not stay an
        // administrator with its old password. It loses root, is disabled
        // and signed out everywhere (re-enable it in the console if wanted).
        let previous: Vec<ReplUser> = data::users(self.conn)?
            .into_iter()
            .filter(|u| u.is_root && u.username != username)
            .collect();
        for p in &previous {
            tracing::warn!(previous = %p.username, new = %username, "the root account was renamed in the configuration; disabling the previous root account and signing it out");
            let mut after = p.clone();
            after.is_root = false;
            after.disabled_at = after.disabled_at.clone().or_else(|| Some(now_rfc3339()));
            self.update_row(p.clone(), after)?;
            let u = self.load_user(p.id)?;
            self.delete_user_sessions(&u, "root renamed in the configuration")?;
        }
        let before = data::user_by_name(self.conn, username)?;
        let changed = match &before {
            None => {
                let now = now_rfc3339();
                let row = ReplUser {
                    id: acct_sql::next_id(self.conn, "users")?,
                    username: username.to_string(),
                    password_hash: password_hash.to_string(),
                    display_name: "Root".into(),
                    is_admin: true,
                    is_root: true,
                    mfa_required,
                    totp_secret: None,
                    totp_enrolled_at: None,
                    totp_last_step: None,
                    disabled_at: None,
                    created_at: now.clone(),
                    updated_at: now,
                    password_history: None,
                };
                self.record(SecretChange::UserCreated { user: row })?;
                Some(serde_json::json!({ "created": true }))
            }
            Some(b) => {
                let mut after = b.clone();
                after.password_hash = password_hash.to_string();
                after.is_admin = true;
                after.is_root = true;
                after.mfa_required = mfa_required;
                after.disabled_at = None;
                let mut m = serde_json::Map::new();
                if b.password_hash != after.password_hash {
                    m.insert("password".into(), "changed".into());
                }
                if b.mfa_required != after.mfa_required {
                    m.insert(
                        "mfa_required".into(),
                        serde_json::json!([b.mfa_required, after.mfa_required]),
                    );
                }
                if !b.is_root || !b.is_admin || b.disabled_at.is_some() {
                    m.insert("restored".into(), true.into());
                }
                if after != *b {
                    after.updated_at = now_rfc3339();
                    self.record(SecretChange::UserUpdated { user: after })?;
                }
                (!m.is_empty()).then_some(serde_json::Value::Object(m))
            }
        };
        let user = self.load_user(
            data::user_by_name(self.conn, username)?
                .context("root user")?
                .id,
        )?;
        if !previous.is_empty() {
            self.push(
                "root.demote_previous",
                None,
                username,
                serde_json::json!({
                    "demoted": previous.len(),
                    "disabled": previous.iter().map(|p| &p.username).collect::<Vec<_>>(),
                }),
            );
        }
        if let Some(detail) = changed {
            self.push("root.sync", Some(user.id), &user.username, detail);
        }
        Ok(user)
    }

    // ---- recovery codes --------------------------------------------------

    pub fn set_recovery_codes(&mut self, user: &User, hashes: &[String]) -> Result<()> {
        self.record(SecretChange::RecoveryCodesReplaced {
            user_id: user.id,
            code_hashes: Hidden(hashes.to_vec()),
        })?;
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
        let unused: bool = self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM recovery_codes WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL)",
            params![user.id, hash],
            |r| r.get(0),
        )?;
        if !unused {
            return Ok(false);
        }
        self.record(SecretChange::RecoveryCodeUsed {
            user_id: user.id,
            code_hash: Hidden(hash.to_string()),
            used_at: now_rfc3339(),
        })?;
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
        Ok(true)
    }

    // ---- sessions (local bookkeeping: not replicated) ----------------------

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

    // ---- O4: sign-in failures (audit only, nothing else is written) ---------

    /// A wrong password (`login.failure`) or code (`mfa.failure`): an audit
    /// row naming the account tried (`attempted`, cut to 64 characters) and
    /// its id when it exists. Never the password or code itself.
    pub fn note_sign_in_failure(
        &mut self,
        action: SignInFailure,
        user: Option<&User>,
        attempted: &str,
        detail: serde_json::Value,
    ) {
        let target: String = attempted.chars().take(64).collect();
        self.push(action.as_str(), user.map(|u| u.id), &target, detail);
    }

    /// O5: an administrator enrolled `user`'s authenticator (the secret is
    /// in the `user_updated` change only, never here).
    pub fn note_admin_enrollment(&mut self, user: &User) {
        self.push(
            "mfa.admin_enroll",
            Some(user.id),
            &user.username,
            serde_json::json!({ "username": user.username }),
        );
    }

    // ---- replica list (local bookkeeping: not replicated) --------------------

    /// An administrator forgets a standby in the primary's replica list.
    pub fn forget_replica(&mut self, instance: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM replicas WHERE instance = ?1",
            params![instance],
        )?;
        if n > 0 {
            self.push(
                "replication.replica_forget",
                None,
                instance,
                serde_json::json!({ "instance": instance }),
            );
        }
        Ok(n > 0)
    }

    // ---- API tokens ----------------------------------------------------------

    /// `tags` are normalized here too (callers should validate first to
    /// report a 400; an invalid list rolls the transaction back).
    /// A new API token with an optional scope (M1; validated by the caller,
    /// see `api::routes::normalize_scope`; unrestricted = none).
    pub fn create_token_scoped(
        &mut self,
        user: &User,
        name: &str,
        token_hash: &str,
        tags: &[String],
        scope: Option<&crate::model::TokenScope>,
    ) -> Result<TokenInfo> {
        let tags = normalize_tags(tags)?;
        let scope = scope.filter(|s| !s.is_unrestricted()).cloned();
        let id = acct_sql::next_id(self.conn, "api_tokens")?;
        self.record(SecretChange::TokenCreated {
            token: ReplToken {
                id,
                user_id: user.id,
                name: name.to_string(),
                token_hash: token_hash.to_string(),
                created_at: now_rfc3339(),
                revoked_at: None,
                tags: tags.clone(),
                scope: scope.clone(),
            },
        })?;
        let mut detail = serde_json::json!({ "token_id": id, "name": name, "tags": tags });
        if let Some(scope) = &scope {
            detail["scope"] = serde_json::to_value(scope)?;
        }
        self.push("token.create", Some(user.id), &user.username, detail);
        Ok(db::get_token(self.conn, id)?.expect("just inserted"))
    }

    /// Replace a token's tags. Written and audited (`token.update`, before
    /// and after) only when the normalized list actually changed.
    #[cfg(test)]
    pub fn update_token_tags(
        &mut self,
        owner: &User,
        t: &TokenInfo,
        tags: &[String],
    ) -> Result<TokenInfo> {
        self.update_token(owner, t, Some(tags), None)
    }

    /// Replace a token's tags and/or (M1) its scope (`Some(unrestricted)`
    /// clears it). Written and audited (`token.update`, before and after)
    /// only when something actually changed; the change carries the
    /// resulting tags, and the resulting scope when the scope changed.
    pub fn update_token(
        &mut self,
        owner: &User,
        t: &TokenInfo,
        tags: Option<&[String]>,
        scope: Option<&crate::model::TokenScope>,
    ) -> Result<TokenInfo> {
        let current = db::get_token(self.conn, t.id)?.context("token vanished")?;
        let tags = match tags {
            Some(tags) => normalize_tags(tags)?,
            None => current.tags.clone(),
        };
        let new_scope = match scope {
            Some(s) => s.clone(),
            None => current.scope.clone().unwrap_or_default(),
        };
        let old_scope = current.scope.clone().unwrap_or_default();
        let scope_changed = new_scope != old_scope;
        if current.tags != tags || scope_changed {
            self.record(SecretChange::TokenTagsSet {
                token_id: t.id,
                tags: tags.clone(),
                scope: scope_changed.then(|| new_scope.clone()),
            })?;
            let mut detail = serde_json::json!({
                "token_id": t.id,
                "name": t.name,
            });
            if current.tags != tags {
                detail["tags"] = serde_json::json!({ "before": current.tags, "after": tags });
            }
            if scope_changed {
                detail["scope"] = serde_json::json!({ "before": old_scope, "after": new_scope });
            }
            self.push("token.update", Some(owner.id), &owner.username, detail);
        }
        db::get_token(self.conn, t.id)?.context("token vanished")
    }

    pub fn revoke_token(&mut self, owner: &User, t: &TokenInfo) -> Result<bool> {
        let current = db::get_token(self.conn, t.id)?;
        if current.is_none_or(|c| c.revoked_at.is_some()) {
            return Ok(false);
        }
        self.record(SecretChange::TokenRevoked {
            token_id: t.id,
            revoked_at: now_rfc3339(),
        })?;
        self.push(
            "token.revoke",
            Some(owner.id),
            &owner.username,
            serde_json::json!({ "token_id": t.id, "name": t.name }),
        );
        Ok(true)
    }

    /// O1: revoke every active API token of `owner` (one `token_revoked`
    /// change and one `token.revoke` audit row each, `reason` in the
    /// detail). Returns how many were revoked.
    pub fn revoke_user_tokens(&mut self, owner: &User, reason: &str) -> Result<usize> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM api_tokens WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY id",
            )?;
            let rows = stmt.query_map(params![owner.id], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for id in &ids {
            let t = db::get_token(self.conn, *id)?.context("token vanished")?;
            self.record(SecretChange::TokenRevoked {
                token_id: t.id,
                revoked_at: now_rfc3339(),
            })?;
            self.push(
                "token.revoke",
                Some(owner.id),
                &owner.username,
                serde_json::json!({ "token_id": t.id, "name": t.name, "reason": reason }),
            );
        }
        Ok(ids.len())
    }

    /// Audit rows and (when `changelog`) the recorded changes, one txn id.
    fn finish(
        self,
        actor: &Actor,
        operation: &str,
        txn: &str,
        changelog: bool,
    ) -> Result<(Vec<AuditRecord>, usize)> {
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
                txn: txn.to_string(),
                operation: operation.to_string(),
                actor: actor.name.clone(),
                actor_ip: actor.ip.clone(),
                action: e.action.to_string(),
                target_user_id: e.target_user_id,
                target: e.target,
                detail: e.detail,
            });
        }
        let mut logged = 0;
        if changelog {
            for c in &self.changes {
                super::sql::append_changelog(self.conn, actor, operation, txn, c)?;
                logged += 1;
            }
        }
        Ok((out, logged))
    }
}

/// O4: the kinds of failed sign-in step that are audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInFailure {
    /// Wrong username or password (or a disabled account).
    Password,
    /// Wrong TOTP or recovery code (sign-in, enrollment or re-check).
    Code,
}

impl SignInFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            SignInFailure::Password => "login.failure",
            SignInFailure::Code => "mfa.failure",
        }
    }
}

/// Called after every committed account transaction with its audit rows
/// and the number of changes it added to the changelog (replication uses it
/// to wake long-polling standbys).
pub type CommitHook = Box<dyn Fn(&[AuditRecord], usize) + Send + Sync>;

/// Entry point for account and security writes.
pub struct Accounts {
    storage: Arc<Storage>,
    on_commit: std::sync::OnceLock<CommitHook>,
    /// Closed on a standby: account changes made there (its own root, TOTP
    /// steps and recovery codes used at sign-in) stay local and are not
    /// added to the changelog, which mirrors the primary's offsets.
    gate: std::sync::OnceLock<Arc<super::WriteGate>>,
    /// O2: where access signals go after a commit.
    bus: std::sync::OnceLock<Arc<crate::events::Bus>>,
}

/// O2: audit actions after which a user's open streams must re-check their
/// access at once (a session or token ended or changed, the account
/// changed or is gone).
pub const ACCESS_ACTIONS: &[&str] = &[
    "session.delete",
    "session.revoke_all",
    "session.revoke_others",
    "token.revoke",
    "token.update",
    "user.update",
    "user.delete",
];

/// The access signals for a committed transaction's audit rows, one per
/// user concerned.
pub fn access_events(records: &[AuditRecord]) -> Vec<crate::events::AccessEvent> {
    let mut users: Vec<i64> = records
        .iter()
        .filter(|r| ACCESS_ACTIONS.contains(&r.action.as_str()))
        .filter_map(|r| r.target_user_id)
        .collect();
    users.sort_unstable();
    users.dedup();
    users
        .into_iter()
        .map(crate::events::AccessEvent::User)
        .collect()
}

impl Accounts {
    pub fn new(storage: Arc<Storage>) -> Self {
        Accounts {
            storage,
            on_commit: std::sync::OnceLock::new(),
            gate: std::sync::OnceLock::new(),
            bus: std::sync::OnceLock::new(),
        }
    }

    /// O2: publish access signals on `bus` after each commit (once).
    pub fn set_bus(&self, bus: Arc<crate::events::Bus>) {
        let _ = self.bus.set(bus);
    }

    /// Install the commit hook (once).
    pub fn set_commit_hook(&self, hook: CommitHook) {
        let _ = self.on_commit.set(hook);
    }

    /// Share the server's write gate (once).
    pub fn set_gate(&self, gate: Arc<super::WriteGate>) {
        let _ = self.gate.set(gate);
    }

    /// Run `f` as one transaction. Committed: data, audit rows and the
    /// account changes are durable. Rolled back: nothing is written and the
    /// failure is logged.
    pub fn run<T>(
        &self,
        actor: &Actor,
        operation: &'static str,
        f: impl FnOnce(&mut AuditTx) -> Result<T>,
    ) -> Result<T> {
        let changelog = !self.gate.get().is_some_and(|g| g.read_only());
        let result = self
            .storage
            .write(&TOKEN, |conn| -> Result<(T, Vec<AuditRecord>, usize)> {
                let mut t = AuditTx::begin(conn);
                let out = f(&mut t)?;
                let txn = crate::auth::random_token(9);
                let (records, logged) = t.finish(actor, operation, &txn, changelog)?;
                crate::storage::set_cdc_meta(serde_json::json!({
                    "actor": actor.name, "ip": actor.ip.to_string(), "command": operation, "v1_txn": txn,
                }));
                Ok((out, records, logged))
            });
        match result {
            Ok((out, records, logged)) => {
                for r in &records {
                    tracing::info!(audit_id = r.id, txn = %r.txn, operation, actor = %r.actor, ip = %r.actor_ip, action = %r.action, target = %r.target, "audit");
                }
                if let Some(hook) = self.on_commit.get() {
                    hook(&records, logged);
                }
                if let Some(bus) = self.bus.get() {
                    for ev in access_events(&records) {
                        bus.publish_access(ev);
                    }
                }
                Ok(out)
            }
            Err(e) => {
                tracing::warn!(operation, actor = %actor.name, ip = %actor.ip, error = %e, "account transaction rolled back; nothing committed, no audit entry written");
                Err(e)
            }
        }
    }

    // ---- one-step conveniences -------------------------------------------------

    pub fn create_user(&self, actor: &Actor, u: &NewUser) -> Result<User> {
        self.run(actor, "create_user", |t| t.create_user(u))
    }

    pub fn sync_root(
        &self,
        username: &str,
        password_hash: &str,
        mfa_required: bool,
    ) -> Result<User> {
        // On a standby every account except the config root mirrors the
        // primary; renaming the root would change a replicated row (the
        // previous root) and diverge. Refuse; the operator rebuilds.
        if self.gate.get().is_some_and(|g| g.read_only()) {
            let other_root: Option<String> = self.storage.read_tx(|c| {
                Ok(data::users(c)?
                    .into_iter()
                    .find(|u| u.is_root && u.username != username)
                    .map(|u| u.username))
            })?;
            if let Some(prev) = other_root {
                anyhow::bail!(
                    "[root].username changed from '{prev}' to '{username}' on a standby: the previous root is a replicated account and cannot be changed here. Keep the old name, or rebuild this standby (rust-dns --prepare-standby --yes)"
                );
            }
        }
        let system = Actor {
            name: "system".into(),
            ip: "config".into(),
        };
        self.run(&system, "sync_root", |t| {
            t.sync_root(username, password_hash, mfa_required)
        })
        .context("syncing the root user from configuration")
    }

    #[cfg(test)]
    pub fn create_token(
        &self,
        actor: &Actor,
        user: &User,
        name: &str,
        token_hash: &str,
        tags: &[String],
    ) -> Result<TokenInfo> {
        self.create_token_scoped(actor, user, name, token_hash, tags, None)
    }

    pub fn create_token_scoped(
        &self,
        actor: &Actor,
        user: &User,
        name: &str,
        token_hash: &str,
        tags: &[String],
        scope: Option<&crate::model::TokenScope>,
    ) -> Result<TokenInfo> {
        self.run(actor, "create_token", |t| {
            t.create_token_scoped(user, name, token_hash, tags, scope)
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

    /// O2: revoking a token, signing a user out or changing the account
    /// publishes an access signal for that user after the commit; a
    /// sign-in does not; nothing for a rolled-back transaction.
    #[test]
    fn access_signals_follow_committed_revocations() {
        use crate::events::{AccessEvent, Bus};
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let bus = Arc::new(Bus::new(8, 8));
        a.set_bus(bus.clone());
        let rx = bus.subscribe_access().unwrap();
        let u = a.create_user(&actor(), &new_user("alice")).unwrap();
        let t = a
            .create_token(&actor(), &u, "t", &crate::auth::sha256_hex("x"), &[])
            .unwrap();
        assert!(rx.try_recv().is_err(), "creating is not a cut-off");
        a.run(&actor(), "revoke_token", |tx| tx.revoke_token(&u, &t))
            .unwrap();
        assert_eq!(rx.try_recv().unwrap(), AccessEvent::User(u.id));
        let _ = a.run(&actor(), "update_user", |tx| -> Result<()> {
            tx.change_user(
                u.id,
                &UserChanges {
                    disabled: Some(true),
                    ..UserChanges::default()
                },
            )?;
            anyhow::bail!("rolled back")
        });
        assert!(rx.try_recv().is_err(), "nothing for a rollback");
        a.run(&actor(), "update_user", |tx| {
            tx.change_user(
                u.id,
                &UserChanges {
                    disabled: Some(true),
                    ..UserChanges::default()
                },
            )?;
            tx.delete_user_sessions(&u, "test")
        })
        .unwrap();
        assert_eq!(rx.try_recv().unwrap(), AccessEvent::User(u.id));
        assert!(rx.try_recv().is_err(), "one signal per user and commit");
        assert!(AccessEvent::All.concerns(42) && !AccessEvent::User(1).concerns(2));
    }

    /// O6: with a password history kept, each new password pushes the
    /// previous hash (newest first), trimmed to the setting; with none kept
    /// the next change drops it; root keeps none. The secret change carries
    /// the history (replicated with the row); without one the field is
    /// absent (byte-identical to before O6).
    #[test]
    fn password_history_follows_the_setting() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("alice")).unwrap();
        let set = |n: u32| {
            a.run(&actor(), "update_security", |t| {
                let sec = super::super::settings::SecuritySettings {
                    password_history: n,
                    ..Default::default()
                };
                t.set_setting(
                    super::super::settings::SECURITY_KEY,
                    "settings.security.update",
                    "tester",
                    None::<&super::super::settings::SecuritySettings>,
                    &sec,
                )
            })
            .unwrap()
        };
        let pw = |h: &str| {
            a.run(&actor(), "change_password", |t| t.set_password(u.id, h))
                .unwrap()
        };
        let history = || {
            s.read_tx(|c| data::user_row(c, u.id))
                .unwrap()
                .unwrap()
                .password_history
        };
        pw("h1");
        assert_eq!(history(), None, "nothing kept by default");
        set(2);
        pw("h2");
        assert_eq!(history(), Some(vec!["h1".to_string()]));
        pw("h3");
        pw("h4");
        assert_eq!(history(), Some(vec!["h3".to_string(), "h2".to_string()]));
        let last: String = s
            .read_tx(|c| {
                Ok(c.query_row(
                    "SELECT payload FROM changelog WHERE action = 'update' AND entity = 'user' ORDER BY offset DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(
            last.contains("\"password_history\":[\"h3\",\"h2\"]"),
            "{last}"
        );
        set(0);
        pw("h5");
        assert_eq!(history(), None, "dropped when none are kept");
        let last: String = s
            .read_tx(|c| {
                Ok(c.query_row(
                    "SELECT payload FROM changelog WHERE action = 'update' AND entity = 'user' ORDER BY offset DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(!last.contains("password_history"), "{last}");
        set(3);
        let root = a.sync_root("root", "r1", false).unwrap();
        a.sync_root("root", "r2", false).unwrap();
        let rh = s
            .read_tx(|c| data::user_row(c, root.id))
            .unwrap()
            .unwrap()
            .password_history;
        assert_eq!(rh, None, "root keeps none");
    }

    #[test]
    fn committed_writes_are_audited_in_the_same_transaction() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("alice")).unwrap();
        a.run(&actor(), "update_user", |t| {
            t.change_user(
                u.id,
                &UserChanges {
                    is_admin: Some(true),
                    password_hash: Some("h2".into()),
                    ..UserChanges::default()
                },
            )
        })
        .unwrap();
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
    /// M3 regression: a self-service write used to write every column from
    /// the caller's stale snapshot, reverting a concurrent admin change
    /// (e.g. a demotion or disable). Column updates cannot clobber.
    #[test]
    fn self_service_writes_do_not_revert_admin_changes() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("mallory")).unwrap();
        a.run(&actor(), "promote", |t| {
            t.change_user(
                u.id,
                &UserChanges {
                    is_admin: Some(true),
                    ..Default::default()
                },
            )
        })
        .unwrap();
        // The user's request loaded its snapshot (admin, enabled) ...
        let stale = s.get_user(u.id).unwrap().unwrap();
        assert!(stale.is_admin);
        // ... an administrator demotes and disables the account ...
        a.run(&actor(), "update_user", |t| {
            t.change_user(
                u.id,
                &UserChanges {
                    is_admin: Some(false),
                    disabled: Some(true),
                    ..Default::default()
                },
            )
        })
        .unwrap();
        // ... and then the user's password change and MFA enrollment commit.
        a.run(&actor(), "change_password", |t| {
            t.set_password(stale.id, "new-hash")
        })
        .unwrap();
        a.run(&actor(), "mfa_enroll", |t| {
            t.set_mfa(stale.id, Some("SECRET"))
        })
        .unwrap();
        let now = s.get_user(u.id).unwrap().unwrap();
        assert!(!now.is_admin, "demotion survives");
        assert!(now.disabled_at.is_some(), "disable survives");
        assert_eq!(now.password_hash, "new-hash");
        assert_eq!(now.totp_secret.as_deref(), Some("SECRET"));
        // And an admin edit does not undo a concurrent password change.
        a.run(&actor(), "change_password", |t| {
            t.set_password(u.id, "newer")
        })
        .unwrap();
        a.run(&actor(), "update_user", |t| {
            t.change_user(
                u.id,
                &UserChanges {
                    display_name: Some("M".into()),
                    ..Default::default()
                },
            )
        })
        .unwrap();
        assert_eq!(s.get_user(u.id).unwrap().unwrap().password_hash, "newer");
    }

    /// M6 regression: a TOTP step can be used once.
    #[test]
    fn totp_steps_cannot_be_replayed() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let u = a.create_user(&actor(), &new_user("tina")).unwrap();
        let u = a
            .run(&actor(), "mfa_enroll", |t| t.set_mfa(u.id, Some("S")))
            .unwrap();
        assert!(a
            .run(&actor(), "mfa", |t| t.accept_totp_step(&u, 100))
            .unwrap());
        assert!(
            !a.run(&actor(), "mfa", |t| t.accept_totp_step(&u, 100))
                .unwrap(),
            "same step"
        );
        assert!(
            !a.run(&actor(), "mfa", |t| t.accept_totp_step(&u, 99))
                .unwrap(),
            "older step"
        );
        assert!(a
            .run(&actor(), "mfa", |t| t.accept_totp_step(&u, 101))
            .unwrap());
        // Re-enrollment starts over.
        let u = a
            .run(&actor(), "mfa_enroll", |t| t.set_mfa(u.id, Some("S2")))
            .unwrap();
        assert!(a
            .run(&actor(), "mfa", |t| t.accept_totp_step(&u, 50))
            .unwrap());
    }

    /// L9 regression: renaming root in the config used to leave the old root
    /// as an enabled administrator with its old password.
    #[test]
    fn renamed_root_disables_the_previous_root() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let old = a.sync_root("root", "hash1", false).unwrap();
        let sess = Session {
            id: 0,
            token_hash: "t".into(),
            user_id: old.id,
            state: "active".into(),
            pending_secret: None,
            ip: "127.0.0.1".into(),
            user_agent: String::new(),
            created_at: now_rfc3339(),
            expires_at: "2999-01-01T00:00:00.000Z".into(),
            last_seen_at: now_rfc3339(),
        };
        a.run(&actor(), "login", |t| t.create_session(&old, &sess))
            .unwrap();
        let new = a.sync_root("admin", "hash2", false).unwrap();
        assert!(new.is_root && new.disabled_at.is_none());
        let old = s.get_user(old.id).unwrap().unwrap();
        assert!(!old.is_root);
        assert!(old.disabled_at.is_some(), "previous root is disabled");
        assert!(
            s.list_sessions(old.id).unwrap().is_empty(),
            "and signed out"
        );
        let log = s.audit_after(0, 100).unwrap();
        let demote = log
            .iter()
            .find(|r| r.action == "root.demote_previous")
            .unwrap();
        assert_eq!(demote.detail["disabled"], serde_json::json!(["root"]));
    }
}
