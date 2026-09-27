//! SQLite persistence. All writes go through a transaction obtained from
//! [`Storage::with_tx`]; the DNS hot path never touches this module.

use crate::model::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use std::path::Path;
use std::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    display_name     TEXT NOT NULL DEFAULT '',
    is_admin         INTEGER NOT NULL DEFAULT 0,
    is_root          INTEGER NOT NULL DEFAULT 0,
    mfa_required     INTEGER NOT NULL DEFAULT 0,
    totp_secret      TEXT,
    totp_enrolled_at TEXT,
    disabled_at      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    totp_last_step   INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT NOT NULL UNIQUE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'active',   -- active | mfa_pending | enroll_pending
    pending_secret  TEXT,
    ip              TEXT NOT NULL,
    user_agent      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL UNIQUE,
    used_at     TEXT
);
CREATE TABLE IF NOT EXISTS zones (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    owner_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    serial      INTEGER NOT NULL DEFAULT 1,
    soa_mname   TEXT NOT NULL,
    soa_rname   TEXT NOT NULL,
    refresh     INTEGER NOT NULL DEFAULT 3600,
    retry       INTEGER NOT NULL DEFAULT 600,
    expire      INTEGER NOT NULL DEFAULT 1209600,
    minimum     INTEGER NOT NULL DEFAULT 300,
    default_ttl INTEGER NOT NULL DEFAULT 300,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id     INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    expires_at  TEXT,
    expired_noted INTEGER NOT NULL DEFAULT 0,
    UNIQUE (zone_id, name, rtype, value)
);
CREATE INDEX IF NOT EXISTS records_zone ON records(zone_id);
CREATE TABLE IF NOT EXISTS zone_members (
    zone_id     INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,   -- editor | viewer
    created_at  TEXT NOT NULL,
    PRIMARY KEY (zone_id, user_id)
);
CREATE TABLE IF NOT EXISTS changelog (
    offset      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    actor_ip    TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity      TEXT NOT NULL,
    zone        TEXT NOT NULL,
    entity_id   INTEGER,
    payload     TEXT NOT NULL,
    txn         TEXT NOT NULL DEFAULT '',
    command     TEXT NOT NULL DEFAULT '',
    schema      INTEGER NOT NULL DEFAULT 1,
    -- 'dns': shown by the changelog API and websocket. 'account': account,
    -- settings and TSIG changes (contain secrets): replication API only.
    class       TEXT NOT NULL DEFAULT 'dns'
);
CREATE INDEX IF NOT EXISTS changelog_ts ON changelog(ts);
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    txn             TEXT NOT NULL,
    operation       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    actor_ip        TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_user_id  INTEGER,
    target          TEXT NOT NULL,
    detail          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);
-- Settings changed from the console/API. They override the config file; written
-- only through audited transactions (src/mutation/settings.rs).
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
-- TSIG keys (RFC 8945) for zone transfers and NOTIFY. Written only through
-- audited transactions (src/mutation/tsig.rs). The secret is kept as raw bytes
-- because HMAC needs it; it never leaves through the API except on create and
-- the audited reveal. `zones` is a JSON array of zone names; empty = all zones.
CREATE TABLE IF NOT EXISTS tsig_keys (
    name        TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL,
    secret      BLOB NOT NULL,
    zones       TEXT NOT NULL DEFAULT '[]',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
-- Replication (standby / follow mode) state: this database's history id and
-- lineage, and standby bookkeeping. Written only by src/mutation/replica.rs
-- (and the history id once, at migration).
CREATE TABLE IF NOT EXISTS replication_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT,
    last_used_ip TEXT,
    tags         TEXT NOT NULL DEFAULT '[]'
);
"#;

/// An API token (never includes the secret).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[schema(example = json!({ "id": 7, "user_id": 1, "name": "ci-deploy", "tags": ["ci", "deploy"], "created_at": "2026-01-15T09:30:00.000Z", "last_used_at": "2026-01-16T08:00:00.000Z", "last_used_ip": "192.0.2.10", "revoked_at": null }))]
pub struct TokenInfo {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    /// Labels for finding and grouping tokens (`[A-Za-z0-9_-]`, case kept,
    /// 1-256 characters each, at most 16, sorted and de-duplicated).
    #[schema(max_items = 16, example = json!(["ci", "deploy"]))]
    pub tags: Vec<String>,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
    /// Last successful authentication with this token. Refreshed at most once
    /// a minute (immediately when the client IP changes), so it may lag
    /// real use by up to 60 seconds. `null`: never used.
    #[schema(required = true, format = DateTime)]
    pub last_used_at: Option<String>,
    /// Client IP of the last successful authentication (after trusted-proxy
    /// resolution). `null`: never used.
    #[schema(required = true, example = "192.0.2.10")]
    pub last_used_ip: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub revoked_at: Option<String>,
}

/// `last_used_at` is refreshed at most this often while the IP is unchanged.
pub const TOKEN_USE_WRITE_INTERVAL_SECS: i64 = 60;

pub struct Storage {
    conn: Mutex<Connection>,
}

/// API tokens gained `last_used_ip` and `tags` (a JSON array of strings).
fn migrate_api_tokens(conn: &Connection) -> Result<()> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('api_tokens')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if cols.is_empty() {
        return Ok(()); // no api_tokens table (only in partial test databases)
    }
    for (col, ddl) in [
        (
            "last_used_ip",
            "ALTER TABLE api_tokens ADD COLUMN last_used_ip TEXT",
        ),
        (
            "tags",
            "ALTER TABLE api_tokens ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'",
        ),
    ] {
        if !cols.iter().any(|c| c == col) {
            conn.execute_batch(ddl)?;
        }
    }
    Ok(())
}

/// Users gained `totp_last_step` (TOTP replay protection).
fn migrate_users(conn: &Connection) -> Result<()> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('users')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if !cols.is_empty() && !cols.iter().any(|c| c == "totp_last_step") {
        conn.execute_batch("ALTER TABLE users ADD COLUMN totp_last_step INTEGER")?;
    }
    Ok(())
}

/// Bring databases created by older versions up to the current schema.
fn migrate(conn: &Connection) -> Result<()> {
    migrate_users(conn)?;
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('changelog')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for (col, ddl) in [
        (
            "txn",
            "ALTER TABLE changelog ADD COLUMN txn TEXT NOT NULL DEFAULT ''",
        ),
        (
            "command",
            "ALTER TABLE changelog ADD COLUMN command TEXT NOT NULL DEFAULT ''",
        ),
        (
            "schema",
            "ALTER TABLE changelog ADD COLUMN schema INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "class",
            "ALTER TABLE changelog ADD COLUMN class TEXT NOT NULL DEFAULT 'dns'",
        ),
    ] {
        if !cols.iter().any(|c| c == col) {
            conn.execute_batch(ddl)?;
        }
    }
    migrate_api_tokens(conn)?;
    let rcols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('records')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if rcols.is_empty() {
        return Ok(()); // no records table yet (only in partial test databases)
    }
    for (col, ddl) in [
        (
            "expires_at",
            "ALTER TABLE records ADD COLUMN expires_at TEXT",
        ),
        (
            "expired_noted",
            "ALTER TABLE records ADD COLUMN expired_noted INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        if !rcols.iter().any(|c| c == col) {
            conn.execute_batch(ddl)?;
        }
    }
    conn.execute_batch("CREATE INDEX IF NOT EXISTS records_expiry ON records(expires_at) WHERE expires_at IS NOT NULL")?;
    ensure_history_id(conn)?;
    Ok(())
}

/// Every database carries a random history id (see `replication`): created
/// once, here, and replaced only by a standby bootstrap or a promotion.
fn ensure_history_id(conn: &Connection) -> Result<()> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'replication_state')",
        [],
        |r| r.get(0),
    )?;
    if has_table {
        conn.execute(
            "INSERT OR IGNORE INTO replication_state (key, value) VALUES ('history_id', ?1)",
            params![crate::auth::random_token(12)],
        )?;
    }
    Ok(())
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn backup_to(&self, path: &Path) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.backup(rusqlite::MAIN_DB, path, None)
            .with_context(|| format!("backing up database to {}", path.display()))
    }

    /// Cheap liveness probe: one trivial query through the shared connection.
    /// Unlike [`Storage::check`] it does not scan the database, so it is safe
    /// to call from unauthenticated health checks.
    pub fn ping(&self) -> Result<()> {
        self.with_conn(|c| {
            let one: i64 = c.query_row("SELECT 1", [], |r| r.get(0))?;
            anyhow::ensure!(one == 1, "unexpected ping result {one}");
            Ok(())
        })
    }

    /// Full integrity check (`PRAGMA quick_check`). Scans the whole database
    /// while holding the connection lock; admin/backup use only.
    pub fn check(&self) -> Result<()> {
        self.with_conn(|c| {
            let integrity: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            anyhow::ensure!(integrity == "ok", "SQLite quick_check: {integrity}");
            let _: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            Ok(())
        })
    }

    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run `f` inside a write transaction: commit on `Ok`, roll back on `Err`
    /// (and on panic, when the transaction is dropped). Requires a
    /// [`WriteToken`](crate::mutation::WriteToken), which only the mutation
    /// module can create, so all writes to data tables go through it.
    pub fn write<T, E: From<rusqlite::Error>>(
        &self,
        _token: &crate::mutation::WriteToken,
        f: impl FnOnce(&Transaction) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Run `f` inside one read transaction, so everything it reads is one
    /// consistent state (replication snapshots and checksums).
    pub fn read_tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute_batch("BEGIN DEFERRED")?;
        let out = f(&conn);
        let _ = conn.execute_batch("COMMIT");
        out
    }

    /// The replication bookkeeping (`replication_state`) as key/value pairs.
    pub fn replication_state(&self) -> Result<std::collections::BTreeMap<String, String>> {
        self.with_conn(replication_state)
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    // ---- zones ---------------------------------------------------------

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        self.with_conn(list_zones)
    }

    pub fn get_zone(&self, name: &str) -> Result<Option<Zone>> {
        self.with_conn(|c| get_zone(c, name))
    }

    pub fn list_records(&self, zone_id: i64) -> Result<Vec<Record>> {
        self.with_conn(|c| list_records(c, zone_id))
    }

    pub fn all_records(&self) -> Result<Vec<Record>> {
        self.with_conn(all_records)
    }

    /// Server-side filtered, paged record listing. Returns (page, total matching).
    pub fn search_records(
        &self,
        zone_id: i64,
        q: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Record>, i64)> {
        self.with_conn(|c| {
            let pat = format!("%{}%", q.to_ascii_lowercase().replace('%', "\\%").replace('_', "\\_"));
            let filter = "(?2 = '' OR lower(name) LIKE ?3 ESCAPE '\\' OR lower(rtype) LIKE ?3 ESCAPE '\\' OR lower(value) LIKE ?3 ESCAPE '\\')";
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(*) FROM records WHERE zone_id = ?1 AND {filter}"),
                params![zone_id, q, pat],
                |r| r.get(0),
            )?;
            let mut stmt = c.prepare(&format!(
                "SELECT {RECORD_COLS} FROM records WHERE zone_id = ?1 AND {filter}
                 ORDER BY CASE WHEN name = '@' THEN 0 WHEN substr(name,1,1) = '*' THEN 2 ELSE 1 END, name, rtype, value LIMIT ?4 OFFSET ?5"
            ))?;
            let rows = stmt.query_map(params![zone_id, q, pat, limit as i64, offset as i64], row_to_record)?;
            Ok((rows.collect::<Result<Vec<_>, _>>()?, total))
        })
    }

    /// The earliest expiry that has not been processed yet, if any.
    pub fn next_expiry(&self) -> Result<Option<String>> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT MIN(expires_at) FROM records WHERE expires_at IS NOT NULL AND expired_noted = 0",
                [],
                |r| r.get(0),
            )?)
        })
    }

    /// Whether any record's expiry is at or before `cutoff` (something to reap).
    pub fn oldest_expiry_before(&self, cutoff: &str) -> Result<bool> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM records WHERE expires_at IS NOT NULL AND expires_at <= ?1)",
                params![cutoff],
                |r| r.get(0),
            )?)
        })
    }

    pub fn counts(&self) -> Result<(i64, i64)> {
        self.with_conn(|c| {
            let z: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            let r: i64 = c.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))?;
            Ok((z, r))
        })
    }

    // ---- changelog -----------------------------------------------------

    pub fn changelog_after(&self, after: i64, limit: usize) -> Result<Vec<ChangeEvent>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command
                 FROM changelog WHERE offset > ?1 AND class = 'dns' ORDER BY offset ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![after, limit as i64], row_to_change)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn changelog_recent(&self, limit: usize) -> Result<Vec<ChangeEvent>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command
                 FROM changelog WHERE class = 'dns' ORDER BY offset DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], row_to_change)?;
            let mut v = rows.collect::<Result<Vec<_>, _>>()?;
            v.reverse();
            Ok(v)
        })
    }

    /// `(oldest_retained_offset, latest_offset)`; both `None` when empty.
    pub fn changelog_bounds(&self) -> Result<(Option<i64>, Option<i64>)> {
        self.with_conn(|c| {
            let r: (Option<i64>, Option<i64>) = c.query_row(
                "SELECT MIN(offset), MAX(offset) FROM changelog WHERE class = 'dns'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(r)
        })
    }

    /// The next offset that will be assigned, even if the log is empty or pruned.
    pub fn changelog_head(&self) -> Result<i64> {
        self.with_conn(|c| {
            let seq: Option<i64> = c
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name = 'changelog'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(seq.unwrap_or(0))
        })
    }

    /// Retention for account changes (they carry password hashes, TOTP and
    /// TSIG secrets): replace the payload of those older than `older_than`
    /// with `{"kind":"scrubbed"}`. Offsets stay; a standby that still needs
    /// such a row gets `gap` and loads a snapshot. Bookkeeping, like pruning.
    pub fn scrub_account_changes(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let cutoff = older_than.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.with_conn(|c| {
            Ok(c.execute(
                "UPDATE changelog SET payload = '{\"kind\":\"scrubbed\"}'
                 WHERE class = 'account' AND ts < ?1 AND payload <> '{\"kind\":\"scrubbed\"}'",
                params![cutoff],
            )?)
        })
    }

    pub fn prune_changelog(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let cutoff = older_than.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.with_conn(|c| {
            let n = c.execute("DELETE FROM changelog WHERE ts < ?1", params![cutoff])?;
            Ok(n)
        })
    }

    // ---- audit log -----------------------------------------------------

    pub fn audit_after(
        &self,
        after: i64,
        limit: usize,
    ) -> Result<Vec<crate::mutation::accounts::AuditRecord>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, txn, operation, actor, actor_ip, action, target_user_id, target, detail
                 FROM audit_log WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![after, limit as i64], row_to_audit)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn audit_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::mutation::accounts::AuditRecord>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, txn, operation, actor, actor_ip, action, target_user_id, target, detail
                 FROM audit_log ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], row_to_audit)?;
            let mut v = rows.collect::<Result<Vec<_>, _>>()?;
            v.reverse();
            Ok(v)
        })
    }

    /// A console/API setting: (JSON value, updated_by, updated_at).
    /// Every TSIG key, secrets included (for the DNS keyring and reveal).
    pub fn list_tsig_keys(&self) -> Result<Vec<StoredTsigKey>> {
        self.with_conn(list_tsig_keys)
    }

    pub fn get_tsig_key(&self, name: &str) -> Result<Option<StoredTsigKey>> {
        self.with_conn(|c| get_tsig_key(c, name))
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<(String, String, String)>> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT value, updated_by, updated_at FROM settings WHERE key = ?1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
        })
    }

    pub fn prune_audit(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let cutoff = older_than.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.with_conn(|c| Ok(c.execute("DELETE FROM audit_log WHERE ts < ?1", params![cutoff])?))
    }

    // ---- users ---------------------------------------------------------

    pub fn list_users(&self) -> Result<Vec<User>> {
        self.with_conn(|c| {
            let mut stmt =
                c.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
            let rows = stmt.query_map([], row_to_user)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn get_user(&self, id: i64) -> Result<Option<User>> {
        self.with_conn(|c| get_user(c, id))
    }

    pub fn get_user_by_name(&self, username: &str) -> Result<Option<User>> {
        self.with_conn(|c| {
            Ok(c.query_row(
                &format!("SELECT {USER_COLS} FROM users WHERE username = ?1"),
                params![username],
                row_to_user,
            )
            .optional()?)
        })
    }

    // ---- sessions ------------------------------------------------------

    pub fn get_session(&self, token_hash: &str) -> Result<Option<Session>> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT id, token_hash, user_id, state, pending_secret, ip, user_agent, created_at, expires_at, last_seen_at
                 FROM sessions WHERE token_hash = ?1",
                params![token_hash],
                row_to_session,
            )
            .optional()?)
        })
    }

    pub fn get_session_by_id(&self, id: i64) -> Result<Option<Session>> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT id, token_hash, user_id, state, pending_secret, ip, user_agent, created_at, expires_at, last_seen_at
                 FROM sessions WHERE id = ?1",
                params![id],
                row_to_session,
            )
            .optional()?)
        })
    }

    pub fn touch_session(&self, id: i64) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE id = ?1",
                params![id, now_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn list_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT id, token_hash, user_id, state, pending_secret, ip, user_agent, created_at, expires_at, last_seen_at
                 FROM sessions WHERE user_id = ?1 AND state = 'active' ORDER BY last_seen_at DESC",
            )?;
            let rows = stmt.query_map(params![user_id], row_to_session)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    // ---- recovery codes ------------------------------------------------

    pub fn recovery_codes_left(&self, user_id: i64) -> Result<i64> {
        self.with_conn(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                params![user_id],
                |r| r.get(0),
            )?)
        })
    }

    pub fn prune_sessions(&self) -> Result<usize> {
        self.with_conn(|c| {
            Ok(c.execute(
                "DELETE FROM sessions WHERE expires_at < ?1",
                params![now_rfc3339()],
            )?)
        })
    }

    // ---- zone members --------------------------------------------------

    pub fn list_members(&self, zone_id: i64) -> Result<Vec<Member>> {
        self.with_conn(|c| list_members(c, zone_id))
    }

    /// All (zone_id, role) pairs a user can reach via membership.
    pub fn memberships_for_user(&self, user_id: i64) -> Result<Vec<(i64, String)>> {
        self.with_conn(|c| {
            let mut stmt =
                c.prepare("SELECT zone_id, role FROM zone_members WHERE user_id = ?1")?;
            let rows = stmt.query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    // ---- api tokens ----------------------------------------------------

    /// Active tokens, of one user or of everyone, optionally only those
    /// carrying `tag` (already normalized).
    pub fn list_tokens(&self, user_id: Option<i64>, tag: Option<&str>) -> Result<Vec<TokenInfo>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {TOKEN_COLS} FROM api_tokens
                 WHERE (?1 IS NULL OR user_id = ?1) AND revoked_at IS NULL
                   AND (?2 IS NULL OR EXISTS (SELECT 1 FROM json_each(api_tokens.tags) WHERE json_each.value = ?2))
                 ORDER BY id"
            ))?;
            let rows = stmt.query_map(params![user_id, tag], row_to_token)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn get_token(&self, id: i64) -> Result<Option<TokenInfo>> {
        self.with_conn(|c| get_token(c, id))
    }

    /// Look up an active API token by hash and record its use (time and
    /// client IP). Bookkeeping, not audited. To keep token-authenticated
    /// traffic from turning every request into a write, the single UPDATE
    /// runs only when the IP changed or `last_used_at` is older than
    /// [`TOKEN_USE_WRITE_INTERVAL_SECS`]; the returned info reflects the use.
    pub fn authenticate_token(
        &self,
        token_hash: &str,
        ip: std::net::IpAddr,
    ) -> Result<Option<TokenInfo>> {
        self.with_conn(|c| {
            let t = c
                .query_row(
                    &format!(
                        "SELECT {TOKEN_COLS} FROM api_tokens WHERE token_hash = ?1 AND revoked_at IS NULL"
                    ),
                    params![token_hash],
                    row_to_token,
                )
                .optional()?;
            let Some(mut t) = t else { return Ok(None) };
            let ip = ip.to_string();
            let now = Utc::now();
            let stale_before = (now
                - chrono::Duration::seconds(TOKEN_USE_WRITE_INTERVAL_SECS))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let stale = t.last_used_at.as_deref().is_none_or(|at| *at < *stale_before);
            if stale || t.last_used_ip.as_deref() != Some(ip.as_str()) {
                let at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                c.execute(
                    "UPDATE api_tokens SET last_used_at = ?1, last_used_ip = ?2 WHERE id = ?3",
                    params![at, ip, t.id],
                )?;
                t.last_used_at = Some(at);
                t.last_used_ip = Some(ip);
            }
            Ok(Some(t))
        })
    }
}

// ---------------------------------------------------------------------------
// Free functions usable both on a Connection and inside a Transaction
// ---------------------------------------------------------------------------

fn row_to_zone(r: &Row<'_>) -> rusqlite::Result<Zone> {
    Ok(Zone {
        id: r.get(0)?,
        name: r.get(1)?,
        serial: r.get::<_, i64>(2)? as u32,
        soa_mname: r.get(3)?,
        soa_rname: r.get(4)?,
        refresh: r.get::<_, i64>(5)? as u32,
        retry: r.get::<_, i64>(6)? as u32,
        expire: r.get::<_, i64>(7)? as u32,
        minimum: r.get::<_, i64>(8)? as u32,
        default_ttl: r.get::<_, i64>(9)? as u32,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
        owner_id: r.get(12)?,
    })
}

const ZONE_COLS: &str =
    "id, name, serial, soa_mname, soa_rname, refresh, retry, expire, minimum, default_ttl, created_at, updated_at, owner_id";

pub(crate) const USER_COLS: &str =
    "id, username, password_hash, display_name, is_admin, is_root, mfa_required, totp_secret, totp_enrolled_at, disabled_at, created_at, updated_at";

pub(crate) fn row_to_user(r: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        password_hash: r.get(2)?,
        display_name: r.get(3)?,
        is_admin: r.get::<_, i64>(4)? != 0,
        is_root: r.get::<_, i64>(5)? != 0,
        mfa_required: r.get::<_, i64>(6)? != 0,
        totp_secret: r.get(7)?,
        totp_enrolled_at: r.get(8)?,
        disabled_at: r.get(9)?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
    })
}

fn row_to_session(r: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: r.get(0)?,
        token_hash: r.get(1)?,
        user_id: r.get(2)?,
        state: r.get(3)?,
        pending_secret: r.get(4)?,
        ip: r.get(5)?,
        user_agent: r.get(6)?,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        last_seen_at: r.get(9)?,
    })
}

const TOKEN_COLS: &str =
    "id, user_id, name, created_at, last_used_at, revoked_at, last_used_ip, tags";

fn row_to_token(r: &Row<'_>) -> rusqlite::Result<TokenInfo> {
    let tags: String = r.get(7)?;
    Ok(TokenInfo {
        id: r.get(0)?,
        user_id: r.get(1)?,
        name: r.get(2)?,
        tags: serde_json::from_str(&tags).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?,
        created_at: r.get(3)?,
        last_used_at: r.get(4)?,
        last_used_ip: r.get(6)?,
        revoked_at: r.get(5)?,
    })
}

/// Any token by id, revoked or not.
pub fn get_token(c: &Connection, id: i64) -> Result<Option<TokenInfo>> {
    Ok(c.query_row(
        &format!("SELECT {TOKEN_COLS} FROM api_tokens WHERE id = ?1"),
        params![id],
        row_to_token,
    )
    .optional()?)
}

pub fn get_user(c: &Connection, id: i64) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"),
        params![id],
        row_to_user,
    )
    .optional()?)
}

pub fn list_members(c: &Connection, zone_id: i64) -> Result<Vec<Member>> {
    let mut stmt = c.prepare(
        "SELECT m.user_id, u.username, m.role, m.created_at FROM zone_members m JOIN users u ON u.id = m.user_id
         WHERE m.zone_id = ?1 ORDER BY u.username",
    )?;
    let rows = stmt.query_map(params![zone_id], |r| {
        Ok(Member {
            user_id: r.get(0)?,
            username: r.get(1)?,
            role: r.get(2)?,
            created_at: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub(crate) fn row_to_record(r: &Row<'_>) -> rusqlite::Result<Record> {
    let rtype: String = r.get(3)?;
    Ok(Record {
        id: r.get(0)?,
        zone_id: r.get(1)?,
        name: r.get(2)?,
        rtype: RecordType::parse(&rtype).unwrap_or(RecordType::TXT),
        value: r.get(4)?,
        ttl: r.get::<_, Option<i64>>(5)?.map(|t| t as u32),
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
        expires_at: r.get(8)?,
    })
}

pub(crate) const RECORD_COLS: &str =
    "id, zone_id, name, rtype, value, ttl, created_at, updated_at, expires_at";

fn row_to_audit(r: &Row<'_>) -> rusqlite::Result<crate::mutation::accounts::AuditRecord> {
    let detail: String = r.get(9)?;
    Ok(crate::mutation::accounts::AuditRecord {
        id: r.get(0)?,
        ts: r.get(1)?,
        txn: r.get(2)?,
        operation: r.get(3)?,
        actor: r.get(4)?,
        actor_ip: r.get(5)?,
        action: r.get(6)?,
        target_user_id: r.get(7)?,
        target: r.get(8)?,
        detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
    })
}

fn row_to_change(r: &Row<'_>) -> rusqlite::Result<ChangeEvent> {
    let payload: String = r.get(8)?;
    Ok(ChangeEvent {
        offset: r.get(0)?,
        ts: r.get(1)?,
        actor: r.get(2)?,
        actor_ip: r.get(3)?,
        action: r.get(4)?,
        entity: r.get(5)?,
        zone: r.get(6)?,
        entity_id: r.get(7)?,
        payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
        txn: r.get(9)?,
        command: r.get(10)?,
    })
}

pub fn list_zones(c: &Connection) -> Result<Vec<Zone>> {
    let mut stmt = c.prepare(&format!("SELECT {ZONE_COLS} FROM zones ORDER BY name"))?;
    let rows = stmt.query_map([], row_to_zone)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_zone(c: &Connection, name: &str) -> Result<Option<Zone>> {
    let z = c
        .query_row(
            &format!("SELECT {ZONE_COLS} FROM zones WHERE name = ?1"),
            params![name],
            row_to_zone,
        )
        .optional()?;
    Ok(z)
}

pub fn replication_state(c: &Connection) -> Result<std::collections::BTreeMap<String, String>> {
    let mut stmt = c.prepare("SELECT key, value FROM replication_state")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn get_zone_by_id(c: &Connection, id: i64) -> Result<Option<Zone>> {
    let z = c
        .query_row(
            &format!("SELECT {ZONE_COLS} FROM zones WHERE id = ?1"),
            params![id],
            row_to_zone,
        )
        .optional()?;
    Ok(z)
}

pub fn list_records(c: &Connection, zone_id: i64) -> Result<Vec<Record>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {RECORD_COLS} FROM records WHERE zone_id = ?1 ORDER BY name, rtype, value"
    ))?;
    let rows = stmt.query_map(params![zone_id], row_to_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn all_records(c: &Connection) -> Result<Vec<Record>> {
    let mut stmt = c.prepare(&format!("SELECT {RECORD_COLS} FROM records"))?;
    let rows = stmt.query_map([], row_to_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_record(c: &Connection, id: i64) -> Result<Option<Record>> {
    let r = c
        .query_row(
            &format!("SELECT {RECORD_COLS} FROM records WHERE id = ?1"),
            params![id],
            row_to_record,
        )
        .optional()?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_and_check_ok() {
        let s = Storage::open_memory().unwrap();
        s.ping().unwrap();
        s.check().unwrap();
    }

    #[test]
    fn migrate_adds_changelog_columns_to_old_databases() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE changelog (offset INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
             actor_ip TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, zone TEXT NOT NULL,
             entity_id INTEGER, payload TEXT NOT NULL);
             INSERT INTO changelog (ts, actor, actor_ip, action, entity, zone, payload) VALUES ('t','a','ip','create','zone','z','{}');",
        )
        .unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotent
        let (txn, schema): (String, i64) = conn
            .query_row("SELECT txn, schema FROM changelog", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let class: String = conn
            .query_row("SELECT class FROM changelog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(class, "dns", "old rows are DNS changes");
        assert_eq!(
            (txn.as_str(), schema),
            ("", 1),
            "old rows are marked schema 1"
        );
    }

    #[test]
    fn migrate_adds_token_tags_and_last_used_ip() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE changelog (offset INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
             actor_ip TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, zone TEXT NOT NULL,
             entity_id INTEGER, payload TEXT NOT NULL);
             CREATE TABLE api_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
             token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT);
             INSERT INTO api_tokens (user_id, name, token_hash, created_at) VALUES (1, 'old', 'h', 't');",
        )
        .unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotent
        let t = get_token(&conn, 1).unwrap().unwrap();
        assert_eq!(t.tags, Vec::<String>::new(), "old tokens have no tags");
        assert_eq!(t.last_used_ip, None);
    }

    fn insert_token(s: &Storage, name: &str, hash: &str, tags: &str) -> i64 {
        let c = s.conn.lock().unwrap();
        c.execute_batch(
            "INSERT OR IGNORE INTO users (username, password_hash, display_name, is_admin, is_root, mfa_required, created_at, updated_at)
             VALUES ('u', 'h', '', 0, 0, 0, 't', 't')",
        )
        .unwrap();
        c.execute(
            "INSERT INTO api_tokens (user_id, name, token_hash, created_at, tags) VALUES (1, ?1, ?2, 't', ?3)",
            params![name, hash, tags],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    #[test]
    fn list_tokens_filters_by_tag() {
        let s = Storage::open_memory().unwrap();
        let a = insert_token(&s, "a", "ha", r#"["ci","deploy"]"#);
        let b = insert_token(&s, "b", "hb", r#"["ci"]"#);
        insert_token(&s, "c", "hc", "[]");
        let ids = |tag: Option<&str>| -> Vec<i64> {
            s.list_tokens(None, tag)
                .unwrap()
                .into_iter()
                .map(|t| t.id)
                .collect()
        };
        assert_eq!(ids(None).len(), 3);
        assert_eq!(ids(Some("ci")), vec![a, b]);
        assert_eq!(ids(Some("deploy")), vec![a]);
        assert!(ids(Some("dep")).is_empty(), "exact match, not substring");
        assert!(s.list_tokens(Some(99), Some("ci")).unwrap().is_empty());
    }

    #[test]
    fn token_use_is_recorded_with_ip_and_throttled() {
        let s = Storage::open_memory().unwrap();
        let id = insert_token(&s, "a", "ha", "[]");
        let v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(s.authenticate_token("nope", v4).unwrap().is_none());
        let t = s.authenticate_token("ha", v4).unwrap().unwrap();
        assert_eq!(t.last_used_ip.as_deref(), Some("127.0.0.1"));
        let first = s.get_token(id).unwrap().unwrap();
        assert_eq!(first.last_used_ip.as_deref(), Some("127.0.0.1"));
        assert!(first.last_used_at.is_some());
        // Same IP within the interval: no write.
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.authenticate_token("ha", v4).unwrap().unwrap();
        assert_eq!(
            s.get_token(id).unwrap().unwrap().last_used_at,
            first.last_used_at
        );
        // New IP: written immediately.
        let t = s.authenticate_token("ha", v6).unwrap().unwrap();
        assert_eq!(t.last_used_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(
            s.get_token(id).unwrap().unwrap().last_used_ip.as_deref(),
            Some("2001:db8::1")
        );
        // Stale timestamp: written again even from the same IP.
        s.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE api_tokens SET last_used_at = '2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        s.authenticate_token("ha", v6).unwrap().unwrap();
        assert!(
            s.get_token(id)
                .unwrap()
                .unwrap()
                .last_used_at
                .unwrap()
                .as_str()
                > "2000-01-01T00:00:00.000Z"
        );
        // Revoked tokens do not authenticate.
        s.conn
            .lock()
            .unwrap()
            .execute("UPDATE api_tokens SET revoked_at = 't'", [])
            .unwrap();
        assert!(s.authenticate_token("ha", v4).unwrap().is_none());
    }

    #[test]
    fn online_backup_is_openable_and_consistent() {
        let source = Storage::open_memory().unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rust-dns-backup-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snapshot.db");
        source
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at)
                 VALUES ('backup.test', 'ns1.backup.test.', 'hostmaster.backup.test.', 't', 't')",
            )
            .unwrap();
        source.backup_to(&path).unwrap();
        let backup = Storage::open(&path).unwrap();
        backup.check().unwrap();
        assert_eq!(backup.counts().unwrap().0, 1);
        drop(backup);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// A TSIG key as stored. `Debug` never prints the secret.
#[derive(Clone)]
pub struct StoredTsigKey {
    /// Lowercase, absolute: `hn-secondary.`.
    pub name: String,
    /// `hmac-sha256`, `hmac-sha384`, `hmac-sha512` or `hmac-sha1`.
    pub algorithm: String,
    pub secret: Vec<u8>,
    /// Zones the key may transfer; empty = all zones.
    pub zones: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

impl std::fmt::Debug for StoredTsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("zones", &self.zones)
            .finish_non_exhaustive()
    }
}

const TSIG_COLS: &str = "name, algorithm, secret, zones, created_by, created_at, updated_at";

fn row_to_tsig_key(r: &Row) -> rusqlite::Result<StoredTsigKey> {
    let zones: String = r.get(3)?;
    Ok(StoredTsigKey {
        name: r.get(0)?,
        algorithm: r.get(1)?,
        secret: r.get(2)?,
        zones: serde_json::from_str(&zones).unwrap_or_default(),
        created_by: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

pub(crate) fn list_tsig_keys(c: &Connection) -> Result<Vec<StoredTsigKey>> {
    let mut stmt = c.prepare(&format!("SELECT {TSIG_COLS} FROM tsig_keys ORDER BY name"))?;
    let rows = stmt.query_map([], row_to_tsig_key)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub(crate) fn get_tsig_key(c: &Connection, name: &str) -> Result<Option<StoredTsigKey>> {
    Ok(c.query_row(
        &format!("SELECT {TSIG_COLS} FROM tsig_keys WHERE name = ?1"),
        params![name],
        row_to_tsig_key,
    )
    .optional()?)
}
