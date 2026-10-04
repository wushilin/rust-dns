//! SQLite persistence. The DNS hot path never touches this module.
//!
//! Two kinds of connection to the one database file (WAL mode):
//! - the write connection: data writes go through [`Storage::write`] (a
//!   transaction, only the mutation module can open one); the bookkeeping
//!   methods of this file (session `last_seen_at`, token `last_used_*`,
//!   replica tracking, pruning, scrubbing, backup) use it too;
//! - a few read connections (`PRAGMA query_only = ON`): every read
//!   (`with_read`, [`Storage::read_tx`], the catalog inputs, the API). In
//!   WAL mode a reader never waits for the writer, so a long write (a large
//!   import, a slow fsync) does not delay API reads, and a read can never
//!   write.
//!
//! A read that starts after a write committed sees it (each read runs in
//! its own read transaction, begun at its first statement).

use crate::model::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

/// Read connections per database. Reads are short; a handful lets API reads
/// go on while one connection serves a long one (a snapshot, the catalog
/// inputs, an integrity check).
const READERS: usize = 4;

/// Run blocking database work without stalling the async runtime: on a
/// multi-thread runtime worker the other tasks of this worker (DNS queries
/// among them) move to another thread first. Elsewhere (a blocking thread,
/// a current-thread test runtime, no runtime) `f` simply runs.
pub fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

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
    totp_last_step   INTEGER,
    -- O6: JSON array of previous password hashes (password history
    -- policy); NULL when none are kept.
    password_history TEXT
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
    updated_at  TEXT NOT NULL,
    -- DNSSEC signing on (1) or off (0); last so that migrated and new
    -- databases have the same column order (replication checksums).
    dnssec      INTEGER NOT NULL DEFAULT 0,
    -- DNSSEC signing epoch (see model::Zone::signed_at). NULL: unsigned, or
    -- signed by a version without it (the epoch is then updated_at).
    signed_at   TEXT,
    -- Override zone (I1): JSON of model::ZoneOverride; NULL for an
    -- ordinary authoritative zone.
    override_spec TEXT,
    -- M2: JSON of model::RecordPolicy; NULL = no record expiry policy.
    record_policy TEXT,
    -- O16: JSON of model::ZoneSettings; NULL = the server's settings.
    zone_settings TEXT,
    -- O24: 1 = signed with NSEC3 instead of NSEC; NULL = NSEC.
    nsec3 INTEGER,
    -- O27: JSON of model::ZoneSecondary; NULL = a zone of our own.
    secondary_spec TEXT
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
-- A standby's copy of the primary's DNS changelog rows from before its
-- snapshot (a snapshot starts `changelog` empty at the snapshot offset).
-- Shown with `changelog` by the changelog API and websocket; never served
-- to standbys (its offsets have holes where account rows were).
CREATE TABLE IF NOT EXISTS changelog_history (
    offset      INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    actor_ip    TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity      TEXT NOT NULL,
    zone        TEXT NOT NULL,
    entity_id   INTEGER,
    payload     TEXT NOT NULL,
    txn         TEXT NOT NULL DEFAULT '',
    command     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS changelog_history_ts ON changelog_history(ts);
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
-- DNSSEC signing keys (one combined signing key per zone). Written only
-- through typed changes (src/mutation/acct_sql.rs); the private key (base64
-- PKCS#8) is a secret like a TSIG secret: replicated as an account-class
-- change, never shown by the API, the changelog API or the logs.
CREATE TABLE IF NOT EXISTS dnssec_keys (
    zone_id     INTEGER PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    zone        TEXT NOT NULL,
    algorithm   INTEGER NOT NULL,
    flags       INTEGER NOT NULL,
    key_tag     INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    -- N1: a key rollover in progress (JSON of replication::types::Rollover,
    -- with the other key's private key); NULL otherwise.
    rollover    TEXT
);
-- Replication (standby / follow mode) state: this database's history id and
-- lineage, and standby bookkeeping. Written only by src/mutation/replica.rs
-- (and the history id once, at migration).
CREATE TABLE IF NOT EXISTS replication_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
-- Standbys that follow this server (primary side). Local bookkeeping:
-- not replicated, not changelogged (src/replication/replicas.rs).
-- O27: the data of each secondary zone as this server last transferred
-- it (every server transfers for itself). Local bookkeeping, never
-- replicated: it lets a restart serve the last good copy until it expires.
CREATE TABLE IF NOT EXISTS secondary_transfers (
    zone          TEXT PRIMARY KEY,   -- zone name (no trailing dot)
    serial        INTEGER NOT NULL,
    records       BLOB NOT NULL,      -- length-prefixed wire records
    transferred_at TEXT NOT NULL,     -- last successful transfer or refresh
    primary_addr  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replicas (
    instance    TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
-- O3: failed sign-in counters (api::guard), so a restart does not reset
-- the back-off. Local bookkeeping on each server (never replicated);
-- rows are deleted on success and pruned once forgotten.
CREATE TABLE IF NOT EXISTS login_failures (
    scope             TEXT NOT NULL,     -- 'account' | 'network'
    key               TEXT NOT NULL,     -- username, or username TAB network key (hex)
    count             INTEGER NOT NULL,
    last_ms           INTEGER NOT NULL,  -- Unix ms of the last failure
    blocked_until_ms  INTEGER NOT NULL,
    PRIMARY KEY (scope, key)
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
    tags         TEXT NOT NULL DEFAULT '[]',
    -- M1: the token's scope as JSON (`TokenScope`); NULL = unrestricted.
    scope        TEXT
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
    /// M1: how the token is limited below its owner's rights; absent =
    /// exactly the owner's rights.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<crate::model::TokenScope>,
}

/// O4: the audit rows of the sign-in log: password accepted (a new
/// session), a second factor accepted or enrolled, recovery codes used,
/// sign-outs, failed passwords and codes, sessions ended after too many
/// wrong codes.
const SIGN_IN_ROWS: &str = "(operation = 'login' AND action = 'session.create')
    OR action IN ('login.failure', 'mfa.failure')
    OR (operation IN ('mfa_verify', 'mfa_enroll') AND action IN ('session.update', 'recovery_code.use'))
    OR (operation IN ('logout', 'code_attempts_exceeded') AND action = 'session.delete')";
const SIGN_IN_FAILURE: &str =
    "action IN ('login.failure', 'mfa.failure') OR operation = 'code_attempts_exceeded'";

/// O3: one stored failed sign-in counter (see `api::guard`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginFailureRow {
    pub scope: String,
    pub key: String,
    pub count: u32,
    pub last_ms: i64,
    pub blocked_until_ms: i64,
}

/// `last_used_at` is refreshed at most this often while the IP is unchanged.
pub const TOKEN_USE_WRITE_INTERVAL_SECS: i64 = 60;

pub struct Storage {
    /// The write connection.
    conn: Mutex<Connection>,
    /// Read-only connections (`query_only`), see the module documentation.
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    /// Tests: the temporary directory of an [`Storage::open_memory`] database.
    #[cfg(test)]
    temp_dir: Option<std::path::PathBuf>,
}

#[cfg(test)]
impl Drop for Storage {
    fn drop(&mut self) {
        if let Some(d) = self.temp_dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn open_reader(path: &Path) -> Result<Connection> {
    // Not SQLITE_OPEN_READ_ONLY: such a handle cannot always attach to the
    // WAL (see `--check`); `query_only` refuses every write just the same.
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening database {} for reading", path.display()))?;
    conn.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;")?;
    Ok(conn)
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
        // M1: NULL for every existing token (unrestricted, as before).
        ("scope", "ALTER TABLE api_tokens ADD COLUMN scope TEXT"),
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
    // O6: NULL for every existing user (no history kept); nothing rewritten.
    if !cols.is_empty() && !cols.iter().any(|c| c == "password_history") {
        conn.execute_batch("ALTER TABLE users ADD COLUMN password_history TEXT")?;
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
    let zcols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('zones')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "dnssec") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN dnssec INTEGER NOT NULL DEFAULT 0")?;
    }
    // Added NULL on purpose: for a zone that is already signed the epoch
    // stays `updated_at`, so its signature window is exactly the one served
    // before the upgrade; the primary pins it at the zone's next change.
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "signed_at") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN signed_at TEXT")?;
    }
    // I1: NULL for every existing zone (all authoritative); nothing else
    // is rewritten.
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "override_spec") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN override_spec TEXT")?;
    }
    // N1: NULL for every existing key (no rollover); nothing rewritten.
    let kcols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('dnssec_keys')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if !kcols.is_empty() && !kcols.iter().any(|c| c == "rollover") {
        conn.execute_batch("ALTER TABLE dnssec_keys ADD COLUMN rollover TEXT")?;
    }
    // M2: NULL for every existing zone (no policy); nothing rewritten.
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "record_policy") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN record_policy TEXT")?;
    }
    // O16: NULL for every existing zone (the server's settings).
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "zone_settings") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN zone_settings TEXT")?;
    }
    // O24: NULL for every existing zone (NSEC); nothing rewritten.
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "nsec3") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN nsec3 INTEGER")?;
    }
    // O27: NULL for every existing zone (our own); nothing rewritten.
    if !zcols.is_empty() && !zcols.iter().any(|c| c == "secondary_spec") {
        conn.execute_batch("ALTER TABLE zones ADD COLUMN secondary_spec TEXT")?;
    }
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
    // Record checks look at one name of a zone (`records_named`).
    conn.execute_batch("CREATE INDEX IF NOT EXISTS records_zone_name ON records(zone_id, name)")?;
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
        Self::open_with(path, "FULL")
    }

    fn open_with(path: &Path, synchronous: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = {synchronous};
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;"
        ))?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        let readers = (0..READERS)
            .map(|_| open_reader(path).map(Mutex::new))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            conn: Mutex::new(conn),
            readers,
            next_reader: AtomicUsize::new(0),
            #[cfg(test)]
            temp_dir: None,
        })
    }

    /// Online backup. Runs on the write connection (a backup whose source
    /// is written through another connection restarts), so writes wait for
    /// it; reads do not.
    pub fn backup_to(&self, path: &Path) -> Result<()> {
        blocking(|| {
            let conn = self.writer();
            conn.backup(rusqlite::MAIN_DB, path, None)
                .with_context(|| format!("backing up database to {}", path.display()))
        })
    }

    /// Cheap liveness probe: one trivial query through a read connection.
    /// Unlike [`Storage::check`] it does not scan the database, so it is safe
    /// to call from unauthenticated health checks.
    pub fn ping(&self) -> Result<()> {
        self.with_read(|c| {
            let one: i64 = c.query_row("SELECT 1", [], |r| r.get(0))?;
            anyhow::ensure!(one == 1, "unexpected ping result {one}");
            Ok(())
        })
    }

    /// Full integrity check (`PRAGMA quick_check`). Scans the whole database
    /// on one read connection; admin/backup use only.
    pub fn check(&self) -> Result<()> {
        self.with_read(|c| {
            let integrity: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            anyhow::ensure!(integrity == "ok", "SQLite quick_check: {integrity}");
            let _: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            Ok(())
        })
    }

    /// Tests: a private throwaway database. A file in a temporary directory
    /// (removed on drop) rather than `:memory:`, so that the read
    /// connections see the same data and behave as in production (WAL).
    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rust-dns-test-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            crate::auth::random_token(6)
        ));
        std::fs::create_dir_all(&dir)?;
        let mut s = Self::open_with(&dir.join("test.db"), "OFF")?;
        s.temp_dir = Some(dir);
        Ok(s)
    }

    /// The write connection. One poison policy everywhere: a panic in one
    /// closure must not make every later database call panic.
    fn writer(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A free read connection, or (all busy) wait for one.
    fn reader(&self) -> MutexGuard<'_, Connection> {
        for m in &self.readers {
            match m.try_lock() {
                Ok(g) => return g,
                Err(TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        let i = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        self.readers[i].lock().unwrap_or_else(|p| p.into_inner())
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
        // Waiting for the write lock and the fsync at commit may take long:
        // never on a runtime worker's time (see [`blocking`]).
        blocking(|| {
            let mut conn = self.writer();
            let tx = conn.transaction()?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })
    }

    /// Run `f` inside one read transaction on a read connection, so
    /// everything it reads is one consistent state (replication snapshots
    /// and checksums). It cannot write: the connection is `query_only`.
    pub fn read_tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.reader();
        // A `Transaction` rolls back when dropped, also when `f` panics:
        // the connection is never left inside a transaction.
        let tx = conn.unchecked_transaction()?;
        let out = f(&tx);
        drop(tx);
        out
    }

    /// Bookkeeping write on the write connection (waits for a running
    /// write transaction).
    fn bookkeeping<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        blocking(|| f(&self.writer()))
    }

    /// Best-effort bookkeeping on a request path (`last_seen_at`,
    /// `last_used_at`): skipped while a write transaction holds the
    /// connection, so a request never waits behind a long write.
    fn bookkeeping_if_idle(&self, f: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
        let conn = match self.conn.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Ok(()),
        };
        f(&conn)
    }

    // ---- O3: failed sign-in counters (local bookkeeping) -------------------

    /// Store one counter of `api::guard` (replacing it).
    pub fn save_login_failure(&self, f: &LoginFailureRow) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "INSERT INTO login_failures (scope, key, count, last_ms, blocked_until_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(scope, key) DO UPDATE SET count = excluded.count, last_ms = excluded.last_ms,
                     blocked_until_ms = excluded.blocked_until_ms",
                params![f.scope, f.key, f.count, f.last_ms, f.blocked_until_ms],
            )?;
            Ok(())
        })
    }

    pub fn delete_login_failure(&self, scope: &str, key: &str) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "DELETE FROM login_failures WHERE scope = ?1 AND key = ?2",
                params![scope, key],
            )?;
            Ok(())
        })
    }

    /// O6: every counter of `username` (account and networks).
    pub fn delete_login_failures_of(&self, username: &str) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "DELETE FROM login_failures WHERE (scope = 'account' AND key = ?1)
                    OR (scope = 'network' AND substr(key, 1, length(?1) + 1) = ?1 || char(9))",
                params![username],
            )?;
            Ok(())
        })
    }

    pub fn load_login_failures(&self) -> Result<Vec<LoginFailureRow>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(
                "SELECT scope, key, count, last_ms, blocked_until_ms FROM login_failures ORDER BY scope, key",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(LoginFailureRow {
                    scope: r.get(0)?,
                    key: r.get(1)?,
                    count: r.get(2)?,
                    last_ms: r.get(3)?,
                    blocked_until_ms: r.get(4)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Delete counters whose last failure is older than `forgotten_before_ms`
    /// and whose wait is over at `now_ms`.
    pub fn prune_login_failures(&self, forgotten_before_ms: i64, now_ms: i64) -> Result<usize> {
        self.bookkeeping(|c| {
            Ok(c.execute(
                "DELETE FROM login_failures WHERE last_ms < ?1 AND blocked_until_ms <= ?2",
                params![forgotten_before_ms, now_ms],
            )?)
        })
    }

    /// Replica tracking (primary side): bookkeeping like token `last_used_at`,
    /// written outside the mutation module and never replicated.
    pub fn save_replica(&self, instance: &str, data: &str, last_seen: &str) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "INSERT INTO replicas (instance, data, last_seen) VALUES (?1, ?2, ?3)
                 ON CONFLICT(instance) DO UPDATE SET data = excluded.data, last_seen = excluded.last_seen",
                params![instance, data, last_seen],
            )?;
            Ok(())
        })
    }

    /// O27 bookkeeping: the transferred data of a secondary zone (local).
    pub fn save_secondary_transfer(
        &self,
        zone: &str,
        serial: u32,
        records: &[u8],
        transferred_at: &str,
        primary: &str,
    ) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "INSERT INTO secondary_transfers (zone, serial, records, transferred_at, primary_addr)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(zone) DO UPDATE SET serial = excluded.serial, records = excluded.records,
                    transferred_at = excluded.transferred_at, primary_addr = excluded.primary_addr",
                params![zone, serial as i64, records, transferred_at, primary],
            )?;
            Ok(())
        })
    }

    /// O27 bookkeeping: forget a secondary zone's data (zone deleted).
    pub fn delete_secondary_transfer(&self, zone: &str) -> Result<()> {
        self.bookkeeping(|c| {
            c.execute(
                "DELETE FROM secondary_transfers WHERE zone = ?1",
                params![zone],
            )?;
            Ok(())
        })
    }

    /// O27: every stored transfer: (zone, serial, records, transferred_at,
    /// primary).
    #[allow(clippy::type_complexity)]
    pub fn load_secondary_transfers(&self) -> Result<Vec<(String, u32, Vec<u8>, String, String)>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(
                "SELECT zone, serial, records, transferred_at, primary_addr FROM secondary_transfers",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, i64>(1)? as u32,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    pub fn load_replicas(&self) -> Result<Vec<String>> {
        self.with_read(|c| {
            let mut stmt = c.prepare("SELECT data FROM replicas ORDER BY instance")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Bookkeeping: forget replicas not seen since `cutoff`.
    pub fn prune_replicas(&self, cutoff: &str) -> Result<usize> {
        self.bookkeeping(|c| {
            Ok(c.execute("DELETE FROM replicas WHERE last_seen < ?1", params![cutoff])?)
        })
    }

    /// The replication bookkeeping (`replication_state`) as key/value pairs.
    pub fn replication_state(&self) -> Result<std::collections::BTreeMap<String, String>> {
        self.with_read(replication_state)
    }

    /// Tests only: run raw SQL on the write connection (set up or corrupt state).
    #[cfg(test)]
    pub fn exec_raw(&self, sql: &str) -> Result<()> {
        Ok(self.writer().execute_batch(sql)?)
    }

    /// A read on a read connection, in its own read transaction.
    fn with_read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.read_tx(f)
    }

    // ---- zones ---------------------------------------------------------

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        self.with_read(list_zones)
    }

    pub fn get_zone(&self, name: &str) -> Result<Option<Zone>> {
        self.with_read(|c| get_zone(c, name))
    }

    pub fn list_records(&self, zone_id: i64) -> Result<Vec<Record>> {
        self.with_read(|c| list_records(c, zone_id))
    }

    #[cfg(test)]
    pub fn all_records(&self) -> Result<Vec<Record>> {
        self.with_read(all_records)
    }

    /// Server-side filtered, paged record listing. Returns (page, total matching).
    pub fn search_records(
        &self,
        zone_id: i64,
        q: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Record>, i64)> {
        self.with_read(|c| {
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

    /// O9: records of the zones `zone_ids` whose name, value or type
    /// contains `q` (case-insensitive; empty: any), optionally only of type
    /// `rtype`; at most `limit`, by zone and name. Also the total match count.
    pub fn search_all_records(
        &self,
        zone_ids: &[i64],
        q: &str,
        rtype: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Record>, i64)> {
        if zone_ids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let ids = serde_json::to_string(zone_ids)?;
        self.with_read(|c| {
            let pat = format!(
                "%{}%",
                q.to_ascii_lowercase().replace('%', "\\%").replace('_', "\\_")
            );
            let filter = "zone_id IN (SELECT value FROM json_each(?1))
                AND (?2 = '' OR lower(name) LIKE ?3 ESCAPE '\\' OR lower(value) LIKE ?3 ESCAPE '\\' OR lower(rtype) LIKE ?3 ESCAPE '\\')
                AND (?4 IS NULL OR rtype = ?4)";
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(*) FROM records WHERE {filter}"),
                params![ids, q, pat, rtype],
                |r| r.get(0),
            )?;
            let mut stmt = c.prepare(&format!(
                "SELECT {RECORD_COLS} FROM records WHERE {filter}
                 ORDER BY zone_id, name, rtype, value LIMIT ?5"
            ))?;
            let rows = stmt.query_map(params![ids, q, pat, rtype, limit as i64], row_to_record)?;
            Ok((rows.collect::<Result<Vec<_>, _>>()?, total))
        })
    }

    /// The earliest expiry that has not been processed yet, if any.
    pub fn next_expiry(&self) -> Result<Option<String>> {
        self.with_read(|c| {
            Ok(c.query_row(
                "SELECT MIN(expires_at) FROM records WHERE expires_at IS NOT NULL AND expired_noted = 0",
                [],
                |r| r.get(0),
            )?)
        })
    }

    /// Whether any record's expiry is at or before `cutoff` (something to reap).
    pub fn oldest_expiry_before(&self, cutoff: &str) -> Result<bool> {
        self.with_read(|c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM records WHERE expires_at IS NOT NULL AND expires_at <= ?1)",
                params![cutoff],
                |r| r.get(0),
            )?)
        })
    }

    pub fn counts(&self) -> Result<(i64, i64)> {
        self.with_read(|c| {
            let z: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            let r: i64 = c.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))?;
            Ok((z, r))
        })
    }

    // ---- changelog -----------------------------------------------------

    /// DNS changelog rows after `after`: the standby's copy of the primary's
    /// history from before its snapshot (`changelog_history`, all below the
    /// first `changelog` row) followed by `changelog` itself.
    pub fn changelog_after(&self, after: i64, limit: usize) -> Result<Vec<ChangeEvent>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CHANGE_COLS} FROM changelog_history
                 WHERE offset > ?1 AND offset < {HISTORY_FLOOR} ORDER BY offset ASC LIMIT ?2"
            ))?;
            let mut v = stmt
                .query_map(params![after, limit as i64], row_to_change)?
                .collect::<Result<Vec<_>, _>>()?;
            let rest = limit.saturating_sub(v.len()) as i64;
            if rest > 0 {
                let mut stmt = c.prepare(&format!(
                    "SELECT {CHANGE_COLS} FROM changelog
                     WHERE offset > ?1 AND class = 'dns' ORDER BY offset ASC LIMIT ?2"
                ))?;
                for r in stmt.query_map(params![after, rest], row_to_change)? {
                    v.push(r?);
                }
            }
            Ok(v)
        })
    }

    pub fn changelog_recent(&self, limit: usize) -> Result<Vec<ChangeEvent>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CHANGE_COLS} FROM changelog WHERE class = 'dns' ORDER BY offset DESC LIMIT ?1"
            ))?;
            let mut v = stmt
                .query_map(params![limit as i64], row_to_change)?
                .collect::<Result<Vec<_>, _>>()?;
            let rest = limit.saturating_sub(v.len()) as i64;
            if rest > 0 {
                let mut stmt = c.prepare(&format!(
                    "SELECT {CHANGE_COLS} FROM changelog_history
                     WHERE offset < {HISTORY_FLOOR} ORDER BY offset DESC LIMIT ?1"
                ))?;
                for r in stmt.query_map(params![rest], row_to_change)? {
                    v.push(r?);
                }
            }
            v.reverse();
            Ok(v)
        })
    }

    /// `(oldest_retained_offset, latest_offset)` of the DNS changelog
    /// (history included); both `None` when empty.
    pub fn changelog_bounds(&self) -> Result<(Option<i64>, Option<i64>)> {
        self.with_read(|c| {
            let r: (Option<i64>, Option<i64>) = c.query_row(
                &format!(
                    "SELECT MIN(o), MAX(o) FROM (
                       SELECT offset AS o FROM changelog WHERE class = 'dns'
                       UNION ALL
                       SELECT offset FROM changelog_history WHERE offset < {HISTORY_FLOOR})"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(r)
        })
    }

    /// The next offset that will be assigned, even if the log is empty or pruned.
    pub fn changelog_head(&self) -> Result<i64> {
        self.with_read(|c| {
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
        self.bookkeeping(|c| {
            Ok(c.execute(
                "UPDATE changelog SET payload = '{\"kind\":\"scrubbed\"}'
                 WHERE class = 'account' AND ts < ?1 AND payload <> '{\"kind\":\"scrubbed\"}'",
                params![cutoff],
            )?)
        })
    }

    pub fn prune_changelog(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let cutoff = older_than.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.bookkeeping(|c| {
            let n = c.execute("DELETE FROM changelog WHERE ts < ?1", params![cutoff])?;
            c.execute(
                "DELETE FROM changelog_history WHERE ts < ?1",
                params![cutoff],
            )?;
            Ok(n)
        })
    }

    // ---- audit log -----------------------------------------------------

    pub fn audit_after(
        &self,
        after: i64,
        limit: usize,
    ) -> Result<Vec<crate::mutation::accounts::AuditRecord>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, txn, operation, actor, actor_ip, action, target_user_id, target, detail
                 FROM audit_log WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![after, limit as i64], row_to_audit)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// O4: sign-in related audit rows (see `SIGN_IN_ROWS`), newest first,
    /// filtered by user (the audit target), client IP, result
    /// (`success` / `failure`) and `before` (an audit id, for paging).
    pub fn audit_sign_ins(
        &self,
        user: Option<&str>,
        ip: Option<&str>,
        result: Option<&str>,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Vec<crate::mutation::accounts::AuditRecord>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT id, ts, txn, operation, actor, actor_ip, action, target_user_id, target, detail
                 FROM audit_log WHERE ({SIGN_IN_ROWS})
                   AND (?1 IS NULL OR target = ?1) AND (?2 IS NULL OR actor_ip = ?2)
                   AND (?3 IS NULL OR (CASE WHEN {SIGN_IN_FAILURE} THEN 'failure' ELSE 'success' END) = ?3)
                   AND (?4 IS NULL OR id < ?4)
                 ORDER BY id DESC LIMIT ?5"
            ))?;
            let rows = stmt.query_map(
                params![user, ip, result, before, limit as i64],
                row_to_audit,
            )?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn audit_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::mutation::accounts::AuditRecord>> {
        self.with_read(|c| {
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
        self.with_read(list_tsig_keys)
    }

    pub fn get_tsig_key(&self, name: &str) -> Result<Option<StoredTsigKey>> {
        self.with_read(|c| get_tsig_key(c, name))
    }

    /// A zone's DNSSEC key (private key included: callers must not expose it).
    /// N1: zones with a key rollover in progress.
    pub fn rollover_zones(&self) -> Result<Vec<String>> {
        self.with_read(|c| {
            let mut stmt = c.prepare(
                "SELECT z.name FROM dnssec_keys k JOIN zones z ON z.id = k.zone_id
                 WHERE k.rollover IS NOT NULL ORDER BY z.name",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<Vec<String>, _>>()?)
        })
    }

    pub fn get_dnssec_key(
        &self,
        zone_id: i64,
    ) -> Result<Option<crate::replication::types::ReplDnssecKey>> {
        self.with_read(|c| get_dnssec_key(c, zone_id))
    }

    /// Zones, records and DNSSEC keys read in one transaction (catalog build).
    pub fn catalog_inputs(
        &self,
    ) -> Result<(
        Vec<Zone>,
        Vec<Record>,
        Vec<crate::replication::types::ReplDnssecKey>,
    )> {
        self.read_tx(|c| Ok((list_zones(c)?, all_records(c)?, list_dnssec_keys(c)?)))
    }

    /// What the catalog needs to rebuild the zones `ids` (zone row, its
    /// records in id order, its DNSSEC key), read in one transaction;
    /// `None` for a zone that no longer exists.
    pub fn catalog_zone_inputs(&self, ids: &[i64]) -> Result<Vec<(i64, crate::cache::ZoneInput)>> {
        self.read_tx(|c| {
            ids.iter()
                .map(|id| {
                    let Some(zone) = get_zone_by_id(c, *id)? else {
                        return Ok((*id, None));
                    };
                    let mut stmt = c.prepare(&format!(
                        "SELECT {RECORD_COLS} FROM records WHERE zone_id = ?1 ORDER BY id"
                    ))?;
                    let records = stmt
                        .query_map(params![id], row_to_record)?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((*id, Some((zone, records, get_dnssec_key(c, *id)?))))
                })
                .collect()
        })
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<(String, String, String)>> {
        self.with_read(|c| {
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
        self.bookkeeping(|c| Ok(c.execute("DELETE FROM audit_log WHERE ts < ?1", params![cutoff])?))
    }

    // ---- users ---------------------------------------------------------

    pub fn list_users(&self) -> Result<Vec<User>> {
        self.with_read(|c| {
            let mut stmt =
                c.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
            let rows = stmt.query_map([], row_to_user)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn get_user(&self, id: i64) -> Result<Option<User>> {
        self.with_read(|c| get_user(c, id))
    }

    pub fn get_user_by_name(&self, username: &str) -> Result<Option<User>> {
        self.with_read(|c| {
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
        self.with_read(|c| {
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
        self.with_read(|c| {
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
        self.bookkeeping_if_idle(|c| {
            c.execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE id = ?1",
                params![id, now_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn list_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        self.with_read(|c| {
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
        self.with_read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                params![user_id],
                |r| r.get(0),
            )?)
        })
    }

    pub fn prune_sessions(&self) -> Result<usize> {
        self.bookkeeping(|c| {
            Ok(c.execute(
                "DELETE FROM sessions WHERE expires_at < ?1",
                params![now_rfc3339()],
            )?)
        })
    }

    // ---- zone members --------------------------------------------------

    pub fn list_members(&self, zone_id: i64) -> Result<Vec<Member>> {
        self.with_read(|c| list_members(c, zone_id))
    }

    /// All (zone_id, role) pairs a user can reach via membership.
    pub fn memberships_for_user(&self, user_id: i64) -> Result<Vec<(i64, String)>> {
        self.with_read(|c| {
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
        self.with_read(|c| {
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
        self.with_read(|c| get_token(c, id))
    }

    /// Look up an active API token by hash and record its use (time and
    /// client IP). Bookkeeping, not audited (and skipped while a write
    /// transaction is running). To keep token-authenticated
    /// traffic from turning every request into a write, the single UPDATE
    /// runs only when the IP changed or `last_used_at` is older than
    /// [`TOKEN_USE_WRITE_INTERVAL_SECS`]; the returned info reflects the use.
    pub fn authenticate_token(
        &self,
        token_hash: &str,
        ip: std::net::IpAddr,
    ) -> Result<Option<TokenInfo>> {
        let found = self.with_read(|c| {
            let mut write = false;
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
                t.last_used_at = Some(at);
                t.last_used_ip = Some(ip);
                write = true;
            }
            Ok(Some((t, write)))
        })?;
        let Some((t, write)) = found else {
            return Ok(None);
        };
        if write {
            self.bookkeeping_if_idle(|c| {
                c.execute(
                    "UPDATE api_tokens SET last_used_at = ?1, last_used_ip = ?2 WHERE id = ?3",
                    params![t.last_used_at, t.last_used_ip, t.id],
                )?;
                Ok(())
            })?;
        }
        Ok(Some(t))
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
        dnssec: r.get::<_, i64>(13)? != 0,
        signed_at: r.get(14)?,
        overrides: r
            .get::<_, Option<String>>(15)?
            .and_then(|j| serde_json::from_str(&j).ok())
            .map(Box::new),
        record_policy: r
            .get::<_, Option<String>>(16)?
            .and_then(|j| serde_json::from_str(&j).ok())
            .map(Box::new),
        settings: r
            .get::<_, Option<String>>(17)?
            .and_then(|j| serde_json::from_str(&j).ok())
            .map(Box::new),
        nsec3: r.get::<_, Option<i64>>(18)?.unwrap_or(0) != 0,
        secondary: r
            .get::<_, Option<String>>(19)?
            .and_then(|j| serde_json::from_str(&j).ok())
            .map(Box::new),
    })
}

const ZONE_COLS: &str =
    "id, name, serial, soa_mname, soa_rname, refresh, retry, expire, minimum, default_ttl, created_at, updated_at, owner_id, dnssec, signed_at, override_spec, record_policy, zone_settings, nsec3, secondary_spec";

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
    "id, user_id, name, created_at, last_used_at, revoked_at, last_used_ip, tags, scope";

/// `api_tokens.scope` as stored: NULL for an unrestricted token.
pub fn scope_column(scope: Option<&crate::model::TokenScope>) -> Option<String> {
    scope
        .filter(|s| !s.is_unrestricted())
        .map(|s| serde_json::to_string(s).expect("a scope serializes"))
}

/// `api_tokens.scope` read back (an unreadable value never widens: it is
/// an error, not "unrestricted").
pub fn parse_scope_column(
    v: Option<String>,
    idx: usize,
) -> rusqlite::Result<Option<crate::model::TokenScope>> {
    v.map(|v| {
        serde_json::from_str::<crate::model::TokenScope>(&v).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
        })
    })
    .transpose()
    .map(|s| s.filter(|s| !s.is_unrestricted()))
}

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
        scope: parse_scope_column(r.get(8)?, 8)?,
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

const CHANGE_COLS: &str =
    "offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command";

/// History rows are shown only below the first `changelog` row (never twice).
pub(crate) const HISTORY_FLOOR: &str =
    "(SELECT IFNULL(MIN(offset), 9223372036854775807) FROM changelog)";

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

/// The records of a zone at one name (relative, as stored), in id order.
pub fn records_named(c: &Connection, zone_id: i64, name: &str) -> Result<Vec<Record>> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {RECORD_COLS} FROM records WHERE zone_id = ?1 AND name = ?2 ORDER BY id"
    ))?;
    let rows = stmt.query_map(params![zone_id, name], row_to_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Every record, in id order (the order the catalog keeps them in).
pub fn all_records(c: &Connection) -> Result<Vec<Record>> {
    let mut stmt = c.prepare(&format!("SELECT {RECORD_COLS} FROM records ORDER BY id"))?;
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
    fn a_panic_in_a_read_leaves_the_connection_usable() {
        let s = std::sync::Arc::new(Storage::open_memory().unwrap());
        for _ in 0..2 {
            let s2 = s.clone();
            let r = std::thread::spawn(move || {
                let _ = s2.read_tx(|_c| -> Result<()> { panic!("boom inside a read") });
            })
            .join();
            assert!(r.is_err());
        }
        // Not left inside a transaction, and the mutex poison is tolerated:
        // reads and write transactions still work.
        s.ping().unwrap();
        assert!(s.list_zones().unwrap().is_empty());
        s.read_tx(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
            .unwrap();
        let a = crate::mutation::accounts::Accounts::new(s.clone());
        a.run(
            &crate::model::Actor {
                name: "t".into(),
                ip: "t".into(),
            },
            "probe",
            |_t| Ok(()),
        )
        .unwrap();
    }

    /// B1: reads use `query_only` connections; nothing can write through
    /// the read path, whatever SQL it runs.
    #[test]
    fn a_write_through_the_read_path_fails() {
        let s = Storage::open_memory().unwrap();
        for sql in [
            "INSERT INTO settings (key, value, updated_by, updated_at) VALUES ('k','v','a','t')",
            "DELETE FROM users",
            "CREATE TABLE x (y)",
            "UPDATE replication_state SET value = 'x'",
        ] {
            let e = s
                .read_tx(|c| Ok(c.execute_batch(sql)?))
                .expect_err("writes are refused");
            assert!(format!("{e:#}").contains("readonly"), "{sql}: {e:#}");
        }
        // Every read connection is read-only, not just the first.
        let guards: Vec<_> = (0..READERS).map(|_| s.reader()).collect();
        for g in &guards {
            assert!(g.execute_batch("DELETE FROM zones").is_err());
            let q: i64 = g.query_row("PRAGMA query_only", [], |r| r.get(0)).unwrap();
            assert_eq!(q, 1);
        }
        drop(guards);
        assert!(s.get_setting("k").unwrap().is_none());
    }

    /// B1: a read that starts after a commit sees it (the catalog rebuild
    /// after a commit relies on this), on every read connection; and a
    /// read transaction keeps its snapshot while writes go on.
    #[test]
    fn reads_see_committed_writes_and_keep_their_snapshot() {
        let s = Storage::open_memory().unwrap();
        let add = |name: &str| {
            s.exec_raw(&format!(
                "INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at) VALUES ('{name}','n.','h.','t','t')"
            ))
            .unwrap()
        };
        for i in 0..(READERS * 3) {
            add(&format!("z{i}.test"));
            // Rotate through the readers by holding some of them.
            let held: Vec<_> = (0..(i % READERS)).map(|_| s.reader()).collect();
            assert_eq!(s.counts().unwrap().0, i as i64 + 1, "read-your-writes");
            drop(held);
        }
        let n = READERS as i64 * 3;
        s.read_tx(|c| {
            let before: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            add("later.test"); // commits on the write connection meanwhile
            let after: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            assert_eq!((before, after), (n, n), "one consistent state");
            Ok(())
        })
        .unwrap();
        assert_eq!(s.counts().unwrap().0, n + 1);
    }

    /// B1/B3: readers do not wait for a write transaction, and request-path
    /// bookkeeping is skipped instead of waiting.
    #[test]
    fn reads_and_request_bookkeeping_do_not_wait_for_a_long_write() {
        let s = std::sync::Arc::new(Storage::open_memory().unwrap());
        let id = insert_token(&s, "a", "ha", "[]");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let s2 = s.clone();
        let writer = std::thread::spawn(move || {
            let mut c = s2.conn.lock().unwrap();
            let tx = c.transaction().unwrap();
            tx.execute(
                "INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at) VALUES ('w.test','n.','h.','t','t')",
                [],
            )
            .unwrap();
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            tx.commit().unwrap();
        });
        started_rx.recv().unwrap();
        let t0 = std::time::Instant::now();
        for _ in 0..50 {
            assert_eq!(s.counts().unwrap().0, 0, "uncommitted data is not visible");
            assert!(s.get_token(id).unwrap().is_some());
        }
        // Token use during the write: authenticated, the timestamp write skipped.
        let t = s
            .authenticate_token("ha", "127.0.0.1".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(t.last_used_at.is_some());
        s.touch_session(1).unwrap();
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "reads waited for the writer: {:?}",
            t0.elapsed()
        );
        assert!(s.get_token(id).unwrap().unwrap().last_used_at.is_none());
        release_tx.send(()).unwrap();
        writer.join().unwrap();
        assert_eq!(s.counts().unwrap().0, 1);
        // Idle again: the use is recorded.
        s.authenticate_token("ha", "127.0.0.1".parse().unwrap())
            .unwrap();
        assert!(s.get_token(id).unwrap().unwrap().last_used_at.is_some());
    }

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

    /// D1: a database of the version before `signed_at` gains the column,
    /// empty: nothing about an already signed zone changes at the upgrade.
    #[test]
    fn migrate_adds_the_signing_epoch_empty() {
        // The zones table as the previous version (3884ba8) created it.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE changelog (offset INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
             actor_ip TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, zone TEXT NOT NULL,
             entity_id INTEGER, payload TEXT NOT NULL);
             CREATE TABLE zones (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, owner_id INTEGER,
                serial INTEGER NOT NULL DEFAULT 1, soa_mname TEXT NOT NULL, soa_rname TEXT NOT NULL,
                refresh INTEGER NOT NULL DEFAULT 3600, retry INTEGER NOT NULL DEFAULT 600,
                expire INTEGER NOT NULL DEFAULT 1209600, minimum INTEGER NOT NULL DEFAULT 300,
                default_ttl INTEGER NOT NULL DEFAULT 300, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                -- DNSSEC signing on (1) or off (0)
                dnssec INTEGER NOT NULL DEFAULT 0
             );
             INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at, dnssec)
             VALUES ('old.test', 'n.', 'h.', 't', '2026-09-20T10:00:00.000Z', 1);",
        )
        .unwrap();
        let cols = |c: &Connection| -> Vec<String> {
            c.prepare("SELECT name FROM pragma_table_info('zones')")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert!(!cols(&conn).contains(&"signed_at".to_string()));
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotent
        let c = cols(&conn);
        assert_eq!(
            &c[c.len() - 6..],
            &[
                "signed_at".to_string(),
                "override_spec".to_string(),
                "record_policy".to_string(),
                "zone_settings".to_string(),
                "nsec3".to_string(),
                "secondary_spec".to_string()
            ],
            "added at the end, in the order of the fresh schema"
        );
        assert!(get_zone(&conn, "old.test")
            .unwrap()
            .unwrap()
            .settings
            .is_none());
        assert!(!get_zone(&conn, "old.test").unwrap().unwrap().nsec3);
        assert!(get_zone(&conn, "old.test")
            .unwrap()
            .unwrap()
            .secondary
            .is_none());
        assert_eq!(
            get_zone(&conn, "old.test").unwrap().unwrap().record_policy,
            None
        );
        let z = get_zone(&conn, "old.test").unwrap().unwrap();
        assert!(z.dnssec);
        assert_eq!(z.signed_at, None);
        assert_eq!(z.signing_epoch(), "2026-09-20T10:00:00.000Z");
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

const DNSSEC_KEY_COLS: &str =
    "zone_id, zone, algorithm, flags, key_tag, public_key, private_key, created_at, rollover";

fn row_to_dnssec_key(r: &Row<'_>) -> rusqlite::Result<crate::replication::types::ReplDnssecKey> {
    Ok(crate::replication::types::ReplDnssecKey {
        zone_id: r.get(0)?,
        zone: r.get(1)?,
        algorithm: r.get::<_, i64>(2)? as u8,
        flags: r.get::<_, i64>(3)? as u16,
        key_tag: r.get::<_, i64>(4)? as u16,
        public_key: r.get(5)?,
        private_key: crate::replication::types::Hidden(r.get(6)?),
        created_at: r.get(7)?,
        // An unreadable value is an error, never "no rollover".
        rollover: r
            .get::<_, Option<String>>(8)?
            .map(|j| {
                serde_json::from_str(&j).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()?,
    })
}

pub(crate) fn list_dnssec_keys(
    c: &Connection,
) -> Result<Vec<crate::replication::types::ReplDnssecKey>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {DNSSEC_KEY_COLS} FROM dnssec_keys ORDER BY zone_id"
    ))?;
    let rows = stmt.query_map([], row_to_dnssec_key)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub(crate) fn get_dnssec_key(
    c: &Connection,
    zone_id: i64,
) -> Result<Option<crate::replication::types::ReplDnssecKey>> {
    Ok(c.query_row(
        &format!("SELECT {DNSSEC_KEY_COLS} FROM dnssec_keys WHERE zone_id = ?1"),
        params![zone_id],
        row_to_dnssec_key,
    )
    .optional()?)
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
