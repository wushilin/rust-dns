//! The store: one writer connection guarded by a mutex, capture triggers on
//! every replicated table, the hash-chained change log, and the operations
//! on it (write, apply, snapshot, verify, rewind, promote, reset).
//!
//! Structural rules:
//! - Capture triggers call `_cdc_capture()`, registered only on the writer
//!   connection. Outside [`Store::write`] (leader) or the apply path
//!   (follower) it raises an error, so any other write to a replicated
//!   table fails: from a stray statement, from a follower, or from another
//!   connection (`no such function`).
//! - A transaction's change log rows are whatever the triggers captured,
//!   committed in the same SQLite transaction as the data.
//! - A follower applies a row generically, lets its own triggers capture
//!   the result, and requires the capture to equal the received row
//!   byte for byte (which checks `before` as well).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::functions::FunctionFlags;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde_json::{Value, json};

use crate::hash;
use crate::schema::{self, TableConfig, TableSpec};
use crate::wire::{self, ChainEntry, Position, Row, SnapLine, SnapshotHeader, Txn};

const MODE_NONE: u8 = 0;
const MODE_CAPTURE: u8 = 1;
const MODE_LOAD: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The rows the follower needs were pruned; the history is the same.
    Gap,
    /// The follower's position is not on this server's chain.
    Diverged,
    /// The follower claims a transaction this server does not have.
    Ahead,
    /// Different history id.
    History,
    NotReady,
    NotLeader,
    Halted,
    Schema,
    NeedsReset,
    Refused,
    /// The peer could not be reached (network, timeout).
    Unreachable,
    /// The leader's change log is incomplete (a capture failed in lenient
    /// mode). Followers wait; the leader must start a new history.
    Broken,
    /// The upstream runs another schema (an upgrade in progress). Nothing
    /// was applied, so nothing diverged: the follower waits, loudly.
    SchemaMismatch,
    Internal,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Gap => "gap",
            Kind::Diverged => "diverged",
            Kind::Ahead => "ahead",
            Kind::History => "history",
            Kind::NotReady => "not_ready",
            Kind::NotLeader => "not_leader",
            Kind::Halted => "halted",
            Kind::Schema => "schema",
            Kind::NeedsReset => "needs_reset",
            Kind::Refused => "refused",
            Kind::Unreachable => "unreachable",
            Kind::SchemaMismatch => "schema_mismatch",
            Kind::Broken => "broken",
            Kind::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Kind {
        match s {
            "gap" => Kind::Gap,
            "diverged" => Kind::Diverged,
            "ahead" => Kind::Ahead,
            "history" => Kind::History,
            "not_ready" => Kind::NotReady,
            "not_leader" => Kind::NotLeader,
            "halted" => Kind::Halted,
            "schema" => Kind::Schema,
            "needs_reset" => Kind::NeedsReset,
            "refused" => Kind::Refused,
            "unreachable" => Kind::Unreachable,
            "schema_mismatch" => Kind::SchemaMismatch,
            "broken" => Kind::Broken,
            _ => Kind::Internal,
        }
    }

    /// Divergence of some kind: a follower halts on these.
    pub fn is_divergence(self) -> bool {
        matches!(
            self,
            Kind::Diverged | Kind::Ahead | Kind::History | Kind::Schema
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{}: {detail}", kind.as_str())]
pub struct CdcError {
    pub kind: Kind,
    pub detail: String,
}

pub fn err(kind: Kind, detail: impl Into<String>) -> CdcError {
    CdcError {
        kind,
        detail: detail.into(),
    }
}

impl From<rusqlite::Error> for CdcError {
    fn from(e: rusqlite::Error) -> Self {
        err(Kind::Internal, e.to_string())
    }
}

impl From<anyhow::Error> for CdcError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<CdcError>() {
            Ok(c) => c,
            Err(e) => err(Kind::Internal, format!("{e:#}")),
        }
    }
}

impl From<serde_json::Error> for CdcError {
    fn from(e: serde_json::Error) -> Self {
        err(Kind::Internal, e.to_string())
    }
}

pub type Result<T, E = CdcError> = std::result::Result<T, E>;

/// What an operator can do about a halt. Divergence is never repaired in
/// place: the node is rebuilt from a snapshot, which takes about a second
/// per 100k rows.
pub const REBOOTSTRAP_HINT: &str = "rebootstrap: POST <api>/admin/rebootstrap (optional {\"upstream\": url}) discards this node's replicated data and loads a fresh snapshot from the upstream";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// No history yet: may load a snapshot.
    Fresh,
    Leader,
    Follower,
    /// A former leader that found another leader of its history: no writes.
    Fenced,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Fresh => "fresh",
            Role::Leader => "leader",
            Role::Follower => "follower",
            Role::Fenced => "fenced",
        }
    }
    fn parse(s: &str) -> Role {
        match s {
            "leader" => Role::Leader,
            "follower" => Role::Follower,
            "fenced" => Role::Fenced,
            _ => Role::Fresh,
        }
    }
}

#[derive(Debug, Clone)]
pub struct State {
    pub node_id: String,
    pub history: Option<String>,
    pub role: Role,
    pub last_txn: u64,
    pub last_seq: u64,
    pub last_hash: String,
    /// Lowest txn whose rows are still stored (`last_txn + 1` when none).
    pub oldest_full: u64,
    pub halted: Option<Value>,
    /// Set when this leader's log is incomplete (see [`Kind::Broken`]).
    pub broken: Option<Value>,
    pub upstream: Option<String>,
}

impl State {
    pub fn position(&self) -> Option<Position> {
        Some(Position {
            history: self.history.clone()?,
            txn_id: self.last_txn,
            hash: self.last_hash.clone(),
        })
    }
}

fn sget(c: &Connection, k: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT v FROM _cdc_state WHERE k = ?1", [k], |r| r.get(0))
        .optional()
}

fn sset(c: &Connection, k: &str, v: Option<&str>) -> rusqlite::Result<()> {
    match v {
        Some(v) => c.execute(
            "INSERT INTO _cdc_state(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?,
        None => c.execute("DELETE FROM _cdc_state WHERE k = ?1", [k])?,
    };
    Ok(())
}

fn read_state(c: &Connection) -> rusqlite::Result<State> {
    let num = |k: &str, d: u64| -> rusqlite::Result<u64> {
        Ok(sget(c, k)?.and_then(|v| v.parse().ok()).unwrap_or(d))
    };
    let history = sget(c, "history")?;
    let last_txn = num("last_txn", 0)?;
    Ok(State {
        node_id: sget(c, "node_id")?.unwrap_or_default(),
        role: Role::parse(&sget(c, "role")?.unwrap_or_default()),
        last_txn,
        last_seq: num("last_seq", 0)?,
        last_hash: sget(c, "last_hash")?
            .or_else(|| history.as_deref().map(hash::genesis))
            .unwrap_or_default(),
        oldest_full: num("oldest_full", last_txn + 1)?,
        halted: sget(c, "halted")?.and_then(|v| serde_json::from_str(&v).ok()),
        broken: sget(c, "broken")?.and_then(|v| serde_json::from_str(&v).ok()),
        upstream: sget(c, "upstream")?,
        history,
    })
}

fn write_pos(c: &Connection, s: &State) -> rusqlite::Result<()> {
    sset(c, "last_txn", Some(&s.last_txn.to_string()))?;
    sset(c, "last_seq", Some(&s.last_seq.to_string()))?;
    sset(c, "last_hash", Some(&s.last_hash))?;
    sset(c, "oldest_full", Some(&s.oldest_full.to_string()))?;
    Ok(())
}

const INTERNAL_DDL: &str = "
CREATE TABLE IF NOT EXISTS _cdc_state (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS _cdc_pending (
  id INTEGER PRIMARY KEY, op TEXT NOT NULL, tbl TEXT NOT NULL,
  pk TEXT NOT NULL, before TEXT, after TEXT);
CREATE TABLE IF NOT EXISTS _cdc (
  seq INTEGER PRIMARY KEY, txn_id INTEGER NOT NULL, op TEXT NOT NULL,
  tbl TEXT NOT NULL, pk TEXT NOT NULL, before TEXT, after TEXT);
CREATE INDEX IF NOT EXISTS _cdc_by_txn ON _cdc (txn_id);
CREATE INDEX IF NOT EXISTS _cdc_by_tbl ON _cdc (tbl, txn_id);
CREATE TABLE IF NOT EXISTS _cdc_txn (
  txn_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, meta TEXT NOT NULL,
  end_seq INTEGER NOT NULL, rows INTEGER NOT NULL, hash TEXT NOT NULL);
";

/// Foreign keys are enforced where data is written by the application
/// (the leader). A follower replays the leader's rows, cascades included,
/// so it must not cascade again.
fn set_fk(c: &Connection, role: Role) -> rusqlite::Result<()> {
    c.execute_batch(if role == Role::Leader {
        "PRAGMA foreign_keys = ON"
    } else {
        "PRAGMA foreign_keys = OFF"
    })
}

/// Foreign keys off for a replay (apply, snapshot load, rewind); returns
/// whether they were on (the caller turns them back on afterwards).
/// Replayed rows already contain the leader's cascades and must not
/// cascade again; `PRAGMA foreign_keys` cannot change inside a
/// transaction, so the switch wraps it.
fn fk_off(conn: &Connection) -> rusqlite::Result<bool> {
    let on: bool = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    if on {
        conn.execute_batch("PRAGMA foreign_keys = OFF")?;
    }
    Ok(on)
}

/// A capture scope of a host transaction (see [`Store::host_begin`]).
pub struct HostScope<'a>(#[allow(dead_code)] ModeGuard<'a>);

/// Sets the capture mode for its lifetime.
struct ModeGuard<'a>(&'a AtomicU8);

impl<'a> ModeGuard<'a> {
    fn set(m: &'a AtomicU8, v: u8) -> Self {
        m.store(v, Ordering::SeqCst);
        ModeGuard(m)
    }
}

impl Drop for ModeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(MODE_NONE, Ordering::SeqCst);
    }
}

/// What to capture and how strictly.
#[derive(Debug, Clone)]
pub struct Config {
    /// The tables CDC is enabled for (opt-in, per table).
    pub tables: Vec<TableConfig>,
    /// Strict: a write to a captured table outside a capture scope fails.
    /// Lenient (a shadow log next to another source of truth): it is
    /// counted, and the next transaction marks the log broken instead of
    /// failing the host's write.
    pub strict: bool,
    /// Switch `foreign_keys` with the role (on for a leader, off for a
    /// follower, which replays the leader's cascades as rows). Off when a
    /// host application owns the connection settings.
    pub manage_foreign_keys: bool,
    /// TEMP triggers, recreated on every attach and never stored in the
    /// database file: an older binary opening the file sees no triggers (a
    /// shadow log must never break a rollback). Writes through any other
    /// connection are then not captured at all.
    pub temp_triggers: bool,
}

impl Config {
    pub fn new(tables: Vec<TableConfig>) -> Config {
        Config {
            tables,
            strict: true,
            manage_foreign_keys: true,
            temp_triggers: false,
        }
    }
}

pub struct Store {
    path: PathBuf,
    tables: Vec<TableSpec>,
    by_name: HashMap<String, usize>,
    /// The writer connection, possibly shared with a host application.
    w: Arc<Mutex<Connection>>,
    mode: Arc<AtomicU8>,
    /// The role, cached for the capture function (0 = not a leader).
    leader: Arc<std::sync::atomic::AtomicBool>,
    /// Writes to captured tables outside a capture scope (lenient mode).
    uncaptured: Arc<std::sync::atomic::AtomicU64>,
    cfg: Config,
    committed: tokio::sync::watch::Sender<u64>,
    /// blake3 of the table specs: followers present it on every request.
    schema_fp: String,
    /// `PRAGMA schema_version` right after the triggers were generated. Any
    /// later schema change (ALTER, a dropped trigger, ...) makes the
    /// triggers suspect: writes and applies are refused until a restart
    /// regenerates them.
    schema_version: i64,
}

pub fn schema_fingerprint(tables: &[TableSpec]) -> String {
    blake3::hash(&serde_json::to_vec(tables).expect("serializable"))
        .to_hex()
        .to_string()
}

/// A readable difference between two schemas, for halt reports.
pub fn schema_diff(ours: &[TableSpec], theirs: &[TableSpec]) -> String {
    let mut out = Vec::new();
    for t in theirs {
        match ours.iter().find(|o| o.name == t.name) {
            None => out.push(format!("table {} missing here", t.name)),
            Some(o) if o != t => {
                let cols = |x: &TableSpec| {
                    x.columns
                        .iter()
                        .map(|c| c.name.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                out.push(format!(
                    "table {}: here ({}) pk ({}), there ({}) pk ({})",
                    t.name,
                    cols(o),
                    o.pk.join(","),
                    cols(t),
                    t.pk.join(",")
                ));
            }
            _ => {}
        }
    }
    for o in ours
        .iter()
        .filter(|o| !theirs.iter().any(|t| t.name == o.name))
    {
        out.push(format!("table {} only here", o.name));
    }
    out.join("; ")
}

/// Progress of a snapshot load, readable while it runs.
#[derive(Default)]
pub struct Progress {
    pub total_rows: std::sync::atomic::AtomicU64,
    pub loaded_rows: std::sync::atomic::AtomicU64,
}

fn now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:06}", d.as_secs(), d.subsec_micros())
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::Rng::fill(&mut rand::rng(), &mut b[..]);
    hex::encode(b)
}

/// Captured row before it has a sequence number.
#[derive(Debug, PartialEq, Eq)]
struct Captured {
    op: String,
    tbl: String,
    pk: String,
    before: Option<String>,
    after: Option<String>,
}

impl Captured {
    fn of(r: &Row) -> Captured {
        Captured {
            op: r.op.clone(),
            tbl: r.tbl.clone(),
            pk: r.pk.get().to_string(),
            before: r.before.as_ref().map(|b| b.get().to_string()),
            after: r.after.as_ref().map(|a| a.get().to_string()),
        }
    }
}

fn take_pending(tx: &Connection) -> rusqlite::Result<Vec<Captured>> {
    let rows = tx
        .prepare_cached("SELECT op, tbl, pk, before, after FROM _cdc_pending ORDER BY id")?
        .query_map([], |r| {
            Ok(Captured {
                op: r.get(0)?,
                tbl: r.get(1)?,
                pk: r.get(2)?,
                before: r.get(3)?,
                after: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    tx.execute("DELETE FROM _cdc_pending", [])?;
    Ok(rows)
}

/// Store a transaction verbatim and advance the position.
fn store_txn(tx: &Connection, st: &mut State, t: &Txn) -> rusqlite::Result<()> {
    let mut ins = tx.prepare_cached(
        "INSERT INTO _cdc (seq, txn_id, op, tbl, pk, before, after) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for r in &t.rows {
        ins.execute(params![
            r.seq,
            t.txn_id,
            r.op,
            r.tbl,
            r.pk.get(),
            r.before.as_ref().map(|b| b.get()),
            r.after.as_ref().map(|a| a.get()),
        ])?;
    }
    if let Some(last) = t.rows.last() {
        st.last_seq = last.seq;
    }
    tx.prepare_cached(
        "INSERT INTO _cdc_txn (txn_id, ts, meta, end_seq, rows, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        t.txn_id,
        t.ts,
        t.meta.get(),
        st.last_seq,
        t.rows.len() as u64,
        t.hash
    ])?;
    if st.oldest_full > st.last_txn {
        // Nothing was stored before: this one is the oldest full txn.
        st.oldest_full = t.txn_id;
    }
    st.last_txn = t.txn_id;
    st.last_hash = t.hash.clone();
    write_pos(tx, st)
}

impl Store {
    /// Open (or create) a store that owns its connection. `migrate` runs
    /// the application's DDL first.
    pub fn open(
        path: &Path,
        cfg: Config,
        migrate: impl FnOnce(&Connection) -> anyhow::Result<()>,
    ) -> Result<Store> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )?;
        migrate(&conn).map_err(CdcError::from)?;
        Self::attach(path, Arc::new(Mutex::new(conn)), cfg)
    }

    /// Attach to a host application's writer connection (already migrated).
    /// The host keeps using it under the same mutex; its writes to captured
    /// tables must run inside [`Store::host_begin`] / [`Store::host_finish`].
    /// Installs the internal tables, the value functions and the capture
    /// triggers (regenerated on every attach: stale ones are dropped).
    pub fn attach(path: &Path, writer: Arc<Mutex<Connection>>, cfg: Config) -> Result<Store> {
        let mode = Arc::new(AtomicU8::new(MODE_NONE));
        let leader = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let uncaptured = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (tables, st, schema_version) = {
            let conn = writer.lock().unwrap_or_else(|p| p.into_inner());
            register_value_functions(&conn)?;
            let (m, l, u, strict) = (mode.clone(), leader.clone(), uncaptured.clone(), cfg.strict);
            conn.create_scalar_function(
                "_cdc_capture",
                0,
                FunctionFlags::SQLITE_UTF8,
                move |_| match m.load(Ordering::SeqCst) {
                    MODE_CAPTURE => Ok(1i64),
                    MODE_LOAD => Ok(0i64),
                    _ if strict => Err(rusqlite::Error::UserFunctionError(
                        "cdc: write to a captured table outside a capture scope".into(),
                    )),
                    _ => {
                        if l.load(Ordering::SeqCst) {
                            u.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(0i64)
                    }
                },
            )?;
            conn.execute_batch(INTERNAL_DDL)?;
            let tables = schema::introspect(&conn, &cfg.tables)?;
            let stale: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE '\\_cdc\\_%' ESCAPE '\\'")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut ddl: String = stale
                .iter()
                .map(|t| format!("DROP TRIGGER main.\"{t}\";\n"))
                .collect();
            ddl.extend(tables.iter().map(|t| t.trigger_sql(cfg.temp_triggers)));
            conn.execute_batch(&format!("BEGIN; {ddl} COMMIT;"))?;
            if sget(&conn, "node_id")?.is_none() {
                sset(&conn, "node_id", Some(&random_hex(6)))?;
            }
            let st = read_state(&conn)?;
            if cfg.manage_foreign_keys {
                set_fk(&conn, st.role)?;
            }
            let schema_version: i64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
            let problems = trigger_problems(&conn, &tables, &cfg)?;
            if !problems.is_empty() {
                return Err(err(Kind::Schema, problems.join("; ")));
            }
            (tables, st, schema_version)
        };
        leader.store(st.role == Role::Leader, Ordering::SeqCst);
        let by_name = tables
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i))
            .collect();
        Ok(Store {
            path: path.to_path_buf(),
            by_name,
            w: writer,
            mode,
            leader,
            uncaptured,
            cfg,
            committed: tokio::sync::watch::channel(st.last_txn).0,
            schema_fp: schema_fingerprint(&tables),
            schema_version,
            tables,
        })
    }

    // ---- host integration -------------------------------------------

    /// Start capturing a host transaction. Call with the writer lock held,
    /// after `BEGIN`. On a leader rows are captured; otherwise (a node that
    /// is not this log's leader) the triggers stay quiet. Ends on drop.
    pub fn host_begin(&self) -> HostScope<'_> {
        let m = if self.leader.load(Ordering::SeqCst) {
            MODE_CAPTURE
        } else {
            MODE_LOAD
        };
        HostScope(ModeGuard::set(&self.mode, m))
    }

    /// Turn what the host transaction captured into one change log
    /// transaction, inside that transaction (before its commit). After the
    /// commit, call [`Store::host_committed`] with the returned id.
    pub fn host_finish(
        &self,
        _scope: &HostScope<'_>,
        tx: &Connection,
        meta: Value,
    ) -> Result<Option<u64>> {
        if self.mode.load(Ordering::SeqCst) != MODE_CAPTURE {
            tx.execute("DELETE FROM _cdc_pending", [])?;
            return Ok(None);
        }
        let res = (|| {
            let n = self.uncaptured.swap(0, Ordering::SeqCst);
            if n > 0 {
                return Err(err(
                    Kind::Broken,
                    format!("{n} write(s) to captured tables happened outside a capture scope"),
                ));
            }
            self.check_schema_after(tx)?;
            let mut st = read_state(tx)?;
            if st.broken.is_some() {
                return Ok(None);
            }
            let captured = take_pending(tx)?;
            if captured.is_empty() {
                return Ok(None);
            }
            Ok(Some(commit_captured(tx, &mut st, meta, captured)?))
        })();
        if res.is_err() {
            let _ = tx.execute("DELETE FROM _cdc_pending", []);
        }
        res
    }

    /// Publish a committed change log transaction to waiting readers.
    pub fn host_committed(&self, id: Option<u64>) {
        if let Some(id) = id {
            self.committed.send_replace(id);
        }
    }

    /// Mark this leader's log incomplete (lenient mode: a capture failed
    /// but the host's write went on). Readers get `broken` until the leader
    /// starts a new history ([`Store::restart_history`]); followers must
    /// rebootstrap then.
    pub fn mark_broken(&self, reason: &str) -> Result<()> {
        let w = self.lock();
        let v = json!({"reason": reason, "at": now()});
        sset(&w, "broken", Some(&v.to_string()))?;
        tracing::error!(reason, "change log marked broken");
        Ok(())
    }

    /// Drop this node's change log and history, keeping the data: the
    /// node becomes fresh (a host that stops being the leader).
    pub fn forget_history(&self) -> Result<()> {
        let mut w = self.lock();
        let tx = w.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("DELETE FROM _cdc; DELETE FROM _cdc_txn; DELETE FROM _cdc_pending;")?;
        for k in [
            "history",
            "role",
            "last_txn",
            "last_seq",
            "last_hash",
            "oldest_full",
            "halted",
            "broken",
            "upstream",
        ] {
            sset(&tx, k, None)?;
        }
        tx.commit()?;
        self.leader.store(false, Ordering::SeqCst);
        self.committed.send_replace(0);
        Ok(())
    }

    /// A leader whose log broke starts a new history over its current
    /// data. Followers see another history and must rebootstrap.
    pub fn restart_history(&self) -> Result<State> {
        self.forget_history()?;
        self.init_leader()
    }

    pub fn schema_fp(&self) -> &str {
        &self.schema_fp
    }

    /// Refuse to write or apply on a schema that changed after the
    /// triggers were generated: they may no longer capture every column.
    fn check_schema(&self, c: &Connection) -> Result<()> {
        let v: i64 = c.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        if v != self.schema_version {
            let mut detail = format!(
                "the database schema changed while running (schema_version {} -> {v})",
                self.schema_version
            );
            let p = trigger_problems(c, &self.tables, &self.cfg)?;
            if !p.is_empty() {
                detail.push_str(&format!(": {}", p.join("; ")));
            }
            detail.push_str("; capture triggers may be stale, restart the node to regenerate them");
            return Err(err(Kind::Schema, detail));
        }
        let pending: i64 = c.query_row("SELECT count(*) FROM _cdc_pending", [], |r| r.get(0))?;
        if pending != 0 {
            return Err(err(
                Kind::Internal,
                format!("{pending} captured rows left over from an earlier transaction"),
            ));
        }
        Ok(())
    }

    /// Problems a self-check finds right now (empty when healthy).
    pub fn health(&self) -> Result<Vec<String>> {
        // On the writer (TEMP triggers exist only there), but only when it
        // is free: never wait for a long write from a status request.
        let c = match self.w.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Ok(Vec::new());
            }
        };
        let mut p = trigger_problems(&c, &self.tables, &self.cfg)?;
        let v: i64 = c.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        if v != self.schema_version {
            p.push(format!(
                "schema_version changed while running ({} -> {v}); restart to regenerate triggers",
                self.schema_version
            ));
        }
        Ok(p)
    }

    /// Test helper: change data behind the change log's back (simulated
    /// corruption), without touching the schema.
    #[doc(hidden)]
    pub fn corrupt_for_test(&self, sql: &str) -> Result<()> {
        let w = self.lock();
        let _g = ModeGuard::set(&self.mode, MODE_LOAD);
        w.execute_batch(sql)?;
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.w.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_fk(&self, c: &Connection, role: Role) -> rusqlite::Result<()> {
        self.leader.store(role == Role::Leader, Ordering::SeqCst);
        if self.cfg.manage_foreign_keys {
            set_fk(c, role)?;
        }
        Ok(())
    }

    pub fn tables(&self) -> &[TableSpec] {
        &self.tables
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.committed.subscribe()
    }

    /// A read-only connection. Writes through it fail.
    pub fn reader(&self) -> Result<Connection> {
        let c = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        register_value_functions(&c)?;
        Ok(c)
    }

    /// The committed state, read through a read-only connection: never
    /// waits for the writer (which a snapshot load holds for a long time;
    /// waiting for it from async code can starve the very task that feeds
    /// the load).
    pub fn state(&self) -> Result<State> {
        Ok(read_state(&self.reader()?)?)
    }

    fn spec(&self, name: &str) -> Result<&TableSpec> {
        self.by_name
            .get(name)
            .map(|&i| &self.tables[i])
            .ok_or_else(|| err(Kind::Schema, format!("unknown table {name}")))
    }

    // ---- leader -------------------------------------------------------

    /// Make a fresh store the leader of a new history.
    pub fn init_leader(&self) -> Result<State> {
        let w = self.lock();
        let st = read_state(&w)?;
        if st.role != Role::Fresh {
            return Ok(st);
        }
        let history = random_hex(16);
        sset(&w, "history", Some(&history))?;
        sset(&w, "role", Some("leader"))?;
        sset(&w, "last_hash", Some(&hash::genesis(&history)))?;
        self.set_fk(&w, Role::Leader)?;
        Ok(read_state(&w)?)
    }

    /// Run `f` in one transaction on the leader. Every row it changes in a
    /// replicated table is captured into one change log transaction. A
    /// transaction that changed nothing writes no change log entry.
    pub fn write<T>(
        &self,
        meta: Value,
        f: impl FnOnce(&Transaction) -> anyhow::Result<T>,
    ) -> Result<(T, Option<u64>)> {
        let mut w = self.lock();
        let (conn, mode) = (&mut *w, &*self.mode);
        let mut st = read_state(conn)?;
        if st.role != Role::Leader {
            return Err(err(
                Kind::NotLeader,
                format!("role is {}", st.role.as_str()),
            ));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.check_schema(&tx)?;
        let out = {
            let _g = ModeGuard::set(mode, MODE_CAPTURE);
            f(&tx)?
        };
        self.check_schema_after(&tx)?;
        let captured = take_pending(&tx)?;
        if captured.is_empty() {
            tx.commit()?;
            return Ok((out, None));
        }
        let id = commit_captured(&tx, &mut st, meta, captured)?;
        tx.commit()?;
        drop(w);
        self.committed.send_replace(id);
        Ok((out, Some(id)))
    }

    // ---- follower -----------------------------------------------------

    /// Apply a batch of transactions in one SQLite transaction, together
    /// with the new position. Any mismatch fails the whole batch with a
    /// divergence error; nothing is applied.
    pub fn apply(&self, txns: &[Txn]) -> Result<u64> {
        let mut w = self.lock();
        let fk = fk_off(&w)?;
        let res = self.apply_locked(&mut w, txns);
        if fk {
            let _ = w.execute_batch("PRAGMA foreign_keys = ON");
        }
        res
    }

    fn apply_locked(&self, w: &mut MutexGuard<'_, Connection>, txns: &[Txn]) -> Result<u64> {
        if txns.is_empty() {
            return Ok(read_state(w)?.last_txn);
        }
        let (conn, mode) = (&mut **w, &*self.mode);
        let mut st = read_state(conn)?;
        if st.role != Role::Follower {
            return Err(err(
                Kind::Refused,
                format!("apply on a {}", st.role.as_str()),
            ));
        }
        if let Some(h) = &st.halted {
            return Err(err(Kind::Halted, h.to_string()));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.check_schema(&tx)?;
        for t in txns {
            if t.txn_id != st.last_txn + 1 {
                return Err(err(
                    Kind::Diverged,
                    format!("expected txn {}, got {}", st.last_txn + 1, t.txn_id),
                ));
            }
            let h = hash::txn_hash(&st.last_hash, t.txn_id, &t.ts, t.meta.get(), &t.rows);
            if h != t.hash {
                return Err(err(
                    Kind::Diverged,
                    format!(
                        "txn {}: chain hash mismatch (computed {h}, received {})",
                        t.txn_id, t.hash
                    ),
                ));
            }
            for (i, r) in t.rows.iter().enumerate() {
                if r.seq != st.last_seq + 1 + i as u64 {
                    return Err(err(
                        Kind::Diverged,
                        format!("txn {}: seq gap at {}", t.txn_id, r.seq),
                    ));
                }
            }
            {
                let _g = ModeGuard::set(mode, MODE_CAPTURE);
                for r in &t.rows {
                    self.apply_row(
                        &tx,
                        &r.op,
                        &r.tbl,
                        r.pk.get(),
                        r.after.as_ref().map(|a| a.get()),
                    )
                    .map_err(|e| {
                        err(
                            Kind::Diverged,
                            format!(
                                "txn {} seq {} ({} {} {}): {}",
                                t.txn_id,
                                r.seq,
                                r.op,
                                r.tbl,
                                r.pk.get(),
                                e.detail
                            ),
                        )
                    })?;
                }
            }
            let captured = take_pending(&tx)?;
            let expected: Vec<Captured> = t.rows.iter().map(Captured::of).collect();
            if captured != expected {
                return Err(err(
                    Kind::Diverged,
                    format!(
                        "txn {}: {}",
                        t.txn_id,
                        first_difference(&expected, &captured)
                    ),
                ));
            }
            store_txn(&tx, &mut st, t)?;
        }
        tx.commit()?;
        self.committed.send_replace(st.last_txn);
        Ok(st.last_txn)
    }

    fn apply_row(
        &self,
        tx: &Transaction,
        op: &str,
        tbl: &str,
        pk: &str,
        after: Option<&str>,
    ) -> Result<()> {
        let spec = self.spec(tbl)?;
        let need = || err(Kind::Diverged, "row image missing");
        let n = match op {
            "I" => tx
                .prepare_cached(&spec.insert_sql())?
                .execute([after.ok_or_else(need)?])?,
            "U" => tx
                .prepare_cached(&spec.update_sql())?
                .execute([after.ok_or_else(need)?, pk])?,
            "D" => tx.prepare_cached(&spec.delete_sql())?.execute([pk])?,
            o => return Err(err(Kind::Diverged, format!("unknown op {o}"))),
        };
        if n != 1 {
            return Err(err(
                Kind::Diverged,
                format!("{n} rows affected, expected 1 (row missing)"),
            ));
        }
        Ok(())
    }

    /// After the application's code ran: no schema change inside the
    /// transaction (the triggers that captured it would be stale).
    fn check_schema_after(&self, c: &Connection) -> Result<()> {
        let v: i64 = c.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        if v != self.schema_version {
            return Err(err(
                Kind::Schema,
                "the transaction changed the schema; schema changes are not replicated, run them as migrations at startup",
            ));
        }
        Ok(())
    }

    /// Persist a halt. The node keeps serving reads and stops following
    /// until an operator resets it.
    pub fn halt(&self, kind: Kind, detail: &str) -> Result<()> {
        let w = self.lock();
        let v = json!({
            "kind": kind.as_str(),
            "detail": detail,
            "at": now(),
            "options": [REBOOTSTRAP_HINT],
        });
        sset(&w, "halted", Some(&v.to_string()))?;
        tracing::error!(kind = kind.as_str(), detail, "halted");
        Ok(())
    }

    pub fn set_upstream(&self, upstream: Option<&str>) -> Result<()> {
        sset(&self.lock(), "upstream", upstream)?;
        Ok(())
    }

    /// Wipe every replicated table and the change log: the node becomes
    /// fresh and may load a snapshot. An explicit operator action.
    pub fn reset(&self) -> Result<()> {
        let mut w = self.lock();
        let (conn, mode) = (&mut *w, &*self.mode);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let _g = ModeGuard::set(mode, MODE_LOAD);
            self.clear_all(&tx)?;
        }
        for k in [
            "history",
            "role",
            "last_txn",
            "last_seq",
            "last_hash",
            "oldest_full",
            "halted",
        ] {
            sset(&tx, k, None)?;
        }
        tx.commit()?;
        self.set_fk(conn, Role::Fresh)?;
        drop(w);
        self.committed.send_replace(0);
        Ok(())
    }

    fn clear_all(&self, tx: &Transaction) -> Result<()> {
        for t in &self.tables {
            tx.execute(&format!("DELETE FROM \"{}\"", t.name), [])?;
        }
        tx.execute_batch("DELETE FROM _cdc; DELETE FROM _cdc_txn; DELETE FROM _cdc_pending;")?;
        Ok(())
    }

    /// Turn a follower (or a fenced node) into the leader: the first
    /// transaction is an epoch marker with a random nonce, so this node's
    /// chain differs from anything another node writes after the split.
    pub fn promote(&self, force: bool) -> Result<u64> {
        let mut w = self.lock();
        let conn = &mut *w;
        let mut st = read_state(conn)?;
        match st.role {
            Role::Follower | Role::Fenced => {}
            r => {
                return Err(err(
                    Kind::Refused,
                    format!("cannot promote a {}", r.as_str()),
                ));
            }
        }
        if st.halted.is_some() && !force {
            return Err(err(
                Kind::Refused,
                "node is halted; its data may be wrong (force to override)",
            ));
        }
        self.set_fk(conn, Role::Leader)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        sset(&tx, "role", Some("leader"))?;
        sset(&tx, "upstream", None)?;
        sset(&tx, "halted", None)?;
        let meta = json!({"cdc": "epoch", "nonce": random_hex(16), "node": st.node_id, "from_txn": st.last_txn});
        let id = commit_captured(&tx, &mut st, meta, Vec::new())?;
        tx.commit()?;
        drop(w);
        self.committed.send_replace(id);
        Ok(id)
    }

    /// A leader asked to follow (its host became a standby): it may hold
    /// transactions the new upstream lacks, so it never follows silently.
    /// It becomes a halted follower; an operator rebootstraps it (which
    /// replaces its data) to continue. Its data and log stay as they are.
    pub fn demote_halted(&self, detail: &str) -> Result<()> {
        let w = self.lock();
        let st = read_state(&w)?;
        if st.role != Role::Leader {
            return Ok(());
        }
        sset(&w, "role", Some("follower"))?;
        let v = json!({
            "kind": "former_leader",
            "detail": format!("this database led history {} up to txn {}: it may hold changes the new primary does not have ({detail})", st.history.as_deref().unwrap_or("?"), st.last_txn),
            "at": now(),
            "options": [REBOOTSTRAP_HINT],
        });
        sset(&w, "halted", Some(&v.to_string()))?;
        self.set_fk(&w, Role::Follower)?;
        tracing::error!(history = ?st.history, txn = st.last_txn, "a former leader is now a follower: halted until an operator rebootstraps it");
        Ok(())
    }

    /// Stop accepting writes: another leader of this history exists.
    pub fn fence(&self) -> Result<()> {
        let w = self.lock();
        sset(&w, "role", Some("fenced"))?;
        self.set_fk(&w, Role::Fenced)?;
        Ok(())
    }

    /// Undo every transaction after `fork` (newest first) using the stored
    /// row images, then become a follower at `fork`. Each undo is checked
    /// like an apply: the row must still be exactly the `after` image.
    /// Returns the discarded transactions.
    pub fn rewind_to(&self, fork: u64) -> Result<Vec<Txn>> {
        let mut w = self.lock();
        let fk = fk_off(&w)?;
        let res = self.rewind_to_locked(&mut w, fork);
        if fk {
            let _ = w.execute_batch("PRAGMA foreign_keys = ON");
        }
        res
    }

    fn rewind_to_locked(&self, w: &mut MutexGuard<'_, Connection>, fork: u64) -> Result<Vec<Txn>> {
        let (conn, mode) = (&mut **w, &*self.mode);
        let mut st = read_state(conn)?;
        if fork > st.last_txn {
            return Err(err(
                Kind::Refused,
                format!("fork {fork} is after last txn {}", st.last_txn),
            ));
        }
        if fork + 1 < st.oldest_full && fork < st.last_txn {
            return Err(err(
                Kind::NeedsReset,
                format!(
                    "rows of txns {}..{} were pruned; cannot rewind, reset instead",
                    fork + 1,
                    st.oldest_full
                ),
            ));
        }
        self.set_fk(conn, Role::Follower)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let discarded = read_txns(&tx, fork, usize::MAX, usize::MAX)?;
        {
            let _g = ModeGuard::set(mode, MODE_CAPTURE);
            for t in discarded.iter().rev() {
                for r in t.rows.iter().rev() {
                    let (op, before, after) = match r.op.as_str() {
                        "I" => ("D", r.after.as_ref(), None),
                        "D" => ("I", None, r.before.as_ref()),
                        _ => ("U", r.after.as_ref(), r.before.as_ref()),
                    };
                    self.apply_row(&tx, op, &r.tbl, r.pk.get(), after.map(|a| a.get()))
                        .map_err(|e| {
                            err(
                                Kind::Diverged,
                                format!("undo txn {} seq {}: {}", t.txn_id, r.seq, e.detail),
                            )
                        })?;
                    let got = take_pending(&tx)?;
                    let want = vec![Captured {
                        op: op.into(),
                        tbl: r.tbl.clone(),
                        pk: r.pk.get().into(),
                        before: before.map(|b| b.get().into()),
                        after: after.map(|a| a.get().into()),
                    }];
                    if got != want {
                        return Err(err(
                            Kind::Diverged,
                            format!(
                                "undo txn {} seq {}: {}",
                                t.txn_id,
                                r.seq,
                                first_difference(&want, &got)
                            ),
                        ));
                    }
                }
            }
        }
        tx.execute("DELETE FROM _cdc WHERE txn_id > ?1", [fork])?;
        tx.execute("DELETE FROM _cdc_txn WHERE txn_id > ?1", [fork])?;
        let (end_seq, hash): (u64, String) = if fork == 0 {
            (0, hash::genesis(st.history.as_deref().unwrap_or_default()))
        } else {
            tx.query_row(
                "SELECT end_seq, hash FROM _cdc_txn WHERE txn_id = ?1",
                [fork],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
        };
        st.last_txn = fork;
        st.last_seq = end_seq;
        st.last_hash = hash;
        st.oldest_full = st.oldest_full.min(fork + 1);
        write_pos(&tx, &st)?;
        sset(&tx, "role", Some("follower"))?;
        sset(&tx, "halted", None)?;
        tx.commit()?;
        self.committed.send_replace(fork);
        Ok(discarded)
    }

    /// Drop row images of all but the newest `keep` transactions. The
    /// chain entries (hashes) are kept, so positions stay verifiable.
    pub fn prune(&self, keep: u64) -> Result<u64> {
        let w = self.lock();
        let mut st = read_state(&w)?;
        let cutoff = st.last_txn.saturating_sub(keep) + 1;
        if cutoff <= st.oldest_full {
            return Ok(0);
        }
        let n = w.execute("DELETE FROM _cdc WHERE txn_id < ?1", [cutoff])?;
        st.oldest_full = cutoff;
        sset(&w, "oldest_full", Some(&cutoff.to_string()))?;
        Ok(n as u64)
    }

    // ---- reads (any node) --------------------------------------------

    /// Check a follower's position against this node's chain.
    pub fn check_position(c: &Connection, pos: &Position) -> Result<State> {
        let st = read_state(c)?;
        let Some(history) = &st.history else {
            return Err(err(Kind::NotReady, "this node has no history yet"));
        };
        if *history != pos.history {
            return Err(err(
                Kind::History,
                format!("server history {history}, follower {}", pos.history),
            ));
        }
        if pos.txn_id > st.last_txn {
            return Err(err(
                Kind::Ahead,
                format!(
                    "follower at txn {}, server only at {}",
                    pos.txn_id, st.last_txn
                ),
            ));
        }
        let ours: Option<String> = if pos.txn_id == 0 {
            Some(hash::genesis(history))
        } else {
            c.query_row(
                "SELECT hash FROM _cdc_txn WHERE txn_id = ?1",
                [pos.txn_id],
                |r| r.get(0),
            )
            .optional()?
        };
        match ours {
            Some(h) if h == pos.hash => {}
            Some(h) => {
                return Err(err(
                    Kind::Diverged,
                    format!(
                        "txn {}: server hash {h}, follower hash {}",
                        pos.txn_id, pos.hash
                    ),
                ));
            }
            None => {
                return Err(err(
                    Kind::Diverged,
                    format!("txn {} unknown here", pos.txn_id),
                ));
            }
        }
        if pos.txn_id < st.last_txn && pos.txn_id + 1 < st.oldest_full {
            return Err(err(
                Kind::Gap,
                format!(
                    "rows after txn {} were pruned (oldest kept {})",
                    pos.txn_id, st.oldest_full
                ),
            ));
        }
        Ok(st)
    }

    /// Transactions after `pos`, up to `max_bytes` (at least one).
    pub fn changes(
        &self,
        pos: &Position,
        max_bytes: usize,
        max_txns: usize,
    ) -> Result<(Vec<Txn>, u64)> {
        let mut c = self.reader()?;
        let tx = c.transaction()?;
        let st = Self::check_position(&tx, pos)?;
        let txns = read_txns(&tx, pos.txn_id, max_bytes, max_txns)?;
        Ok((txns, st.last_txn))
    }

    /// `(txn_id, hash)` of the chain in `[from, to]`.
    pub fn hashes(&self, from: u64, to: u64) -> Result<Vec<(u64, String)>> {
        let c = self.reader()?;
        let v = c
            .prepare(
                "SELECT txn_id, hash FROM _cdc_txn WHERE txn_id BETWEEN ?1 AND ?2 ORDER BY txn_id",
            )?
            .query_map([from, to], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// A consistent snapshot as NDJSON lines, handed to `emit` one by one.
    pub fn snapshot(
        &self,
        mut emit: impl FnMut(Vec<u8>) -> anyhow::Result<()>,
    ) -> Result<SnapshotHeader> {
        let mut c = self.reader()?;
        let tx = c.transaction()?;
        let st = read_state(&tx)?;
        let Some(history) = st.history.clone() else {
            return Err(err(Kind::NotReady, "no history"));
        };
        if st.halted.is_some() {
            return Err(err(Kind::Halted, "a halted node does not serve snapshots"));
        }
        let mut counts = Vec::new();
        for t in &self.tables {
            counts.push(tx.query_row(
                &format!("SELECT count(*) FROM \"{}\"", t.name),
                [],
                |r| r.get(0),
            )?);
        }
        let chain_entries: u64 = tx.query_row("SELECT count(*) FROM _cdc_txn", [], |r| r.get(0))?;
        let header = SnapshotHeader {
            history,
            txn_id: st.last_txn,
            end_seq: st.last_seq,
            hash: st.last_hash.clone(),
            tables: self.tables.clone(),
            row_counts: counts,
            chain_entries,
        };
        let mut digest = blake3::Hasher::new();
        let mut lines = 0u64;
        let mut send = |line: &SnapLine, digest: &mut blake3::Hasher| -> Result<()> {
            let mut b = serde_json::to_vec(line)?;
            b.push(b'\n');
            digest.update(&b);
            lines += 1;
            emit(b).map_err(CdcError::from)
        };
        send(&SnapLine::Header(header.clone()), &mut digest)?;
        for t in &self.tables {
            let mut s = tx.prepare(&t.scan_sql())?;
            let mut rows = s.query([])?;
            while let Some(r) = rows.next()? {
                let row: String = r.get(1)?;
                send(
                    &SnapLine::Row {
                        t: t.name.clone(),
                        r: wire::raw(row),
                    },
                    &mut digest,
                )?;
            }
        }
        {
            let mut s = tx.prepare(
                "SELECT txn_id, ts, meta, end_seq, rows, hash FROM _cdc_txn ORDER BY txn_id",
            )?;
            let mut rows = s.query([])?;
            while let Some(r) = rows.next()? {
                let e = ChainEntry {
                    txn_id: r.get(0)?,
                    ts: r.get(1)?,
                    meta: wire::raw(r.get(2)?),
                    end_seq: r.get(3)?,
                    rows: r.get(4)?,
                    hash: r.get(5)?,
                };
                send(&SnapLine::Chain(e), &mut digest)?;
            }
        }
        let footer = SnapLine::Footer {
            digest: digest.finalize().to_hex().to_string(),
            lines,
        };
        let mut b = serde_json::to_vec(&footer)?;
        b.push(b'\n');
        emit(b)?;
        Ok(header)
    }

    /// Load a snapshot stream into this node, in one transaction. Allowed on
    /// a fresh node, or (`same_history`) to replace a node's data after a
    /// gap in the same history.
    pub fn load_snapshot(
        &self,
        lines: impl Iterator<Item = anyhow::Result<Vec<u8>>>,
        same_history: Option<&str>,
        progress: &Progress,
    ) -> Result<Position> {
        let mut w = self.lock();
        let fk = fk_off(&w)?;
        let res = self.load_snapshot_locked(&mut w, lines, same_history, progress);
        if fk {
            let _ = w.execute_batch("PRAGMA foreign_keys = ON");
        }
        res
    }

    fn load_snapshot_locked(
        &self,
        w: &mut MutexGuard<'_, Connection>,
        lines: impl Iterator<Item = anyhow::Result<Vec<u8>>>,
        same_history: Option<&str>,
        progress: &Progress,
    ) -> Result<Position> {
        let (conn, mode) = (&mut **w, &*self.mode);
        let st = read_state(conn)?;
        match (st.role, same_history) {
            (Role::Fresh, _) => {}
            (Role::Follower, Some(h)) if st.history.as_deref() == Some(h) => {}
            _ => {
                return Err(err(
                    Kind::Refused,
                    format!(
                        "a {} node with history {:?} does not load snapshots; reset it first",
                        st.role.as_str(),
                        st.history
                    ),
                ));
            }
        }
        self.set_fk(conn, Role::Follower)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _g = ModeGuard::set(mode, MODE_LOAD);
        self.clear_all(&tx)?;
        let mut digest = blake3::Hasher::new();
        let mut header: Option<SnapshotHeader> = None;
        let mut count = 0u64;
        let mut done = false;
        #[allow(clippy::explicit_counter_loop)] // `count` stops at the footer
        for line in lines {
            let line = line.map_err(CdcError::from)?;
            let parsed: SnapLine = serde_json::from_slice(&line)?;
            match parsed {
                SnapLine::Footer { digest: d, lines } => {
                    let ours = digest.finalize().to_hex().to_string();
                    if d != ours || lines != count {
                        return Err(err(Kind::Internal, "snapshot digest mismatch"));
                    }
                    done = true;
                    break;
                }
                SnapLine::Header(h) => {
                    if h.tables != self.tables {
                        return Err(err(
                            Kind::Schema,
                            format!(
                                "snapshot tables differ from this node's: {:?}",
                                h.tables.iter().map(|t| &t.name).collect::<Vec<_>>()
                            ),
                        ));
                    }
                    if let Some(want) = same_history
                        && h.history != want
                    {
                        return Err(err(Kind::History, "snapshot is of another history"));
                    }
                    progress
                        .total_rows
                        .store(h.row_counts.iter().sum(), Ordering::Relaxed);
                    progress.loaded_rows.store(0, Ordering::Relaxed);
                    header = Some(h);
                }
                SnapLine::Row { t, r } => {
                    let spec = self.spec(&t)?;
                    tx.prepare_cached(&spec.insert_sql())?.execute([r.get()])?;
                    progress.loaded_rows.fetch_add(1, Ordering::Relaxed);
                }
                SnapLine::Chain(e) => {
                    tx.prepare_cached(
                        "INSERT INTO _cdc_txn (txn_id, ts, meta, end_seq, rows, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?
                    .execute(params![e.txn_id, e.ts, e.meta.get(), e.end_seq, e.rows, e.hash])?;
                }
            }
            digest.update(&line);
            digest.update(b"\n");
            count += 1;
        }
        let Some(h) = header.filter(|_| done) else {
            return Err(err(Kind::Internal, "snapshot stream ended early"));
        };
        drop(_g);
        let st = State {
            node_id: st.node_id,
            history: Some(h.history.clone()),
            role: Role::Follower,
            last_txn: h.txn_id,
            last_seq: h.end_seq,
            last_hash: h.hash.clone(),
            oldest_full: h.txn_id + 1,
            halted: None,
            broken: None,
            upstream: st.upstream,
        };
        sset(&tx, "history", Some(&h.history))?;
        sset(&tx, "role", Some("follower"))?;
        sset(&tx, "halted", None)?;
        write_pos(&tx, &st)?;
        tx.commit()?;
        self.committed.send_replace(h.txn_id);
        Ok(st.position().expect("history set"))
    }

    /// Does the log agree with the data? For every row the log still holds
    /// changes of, its newest image must equal the live row (or the row
    /// must be gone after a delete). A write that escaped the capture, or a
    /// row changed behind the log's back, shows up here with its key.
    pub fn self_check(&self) -> Result<Value> {
        let mut c = self.reader()?;
        let tx = c.transaction()?;
        let st = read_state(&tx)?;
        let mut tables = Vec::new();
        let mut problems = Vec::new();
        for spec in &self.tables {
            let live: HashMap<String, String> = tx
                .prepare(&spec.scan_sql())?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let newest: Vec<(String, String, Option<String>, u64)> = tx
                .prepare(
                    "SELECT c.pk, c.op, c.after, c.seq FROM _cdc c
                     JOIN (SELECT pk, max(seq) AS seq FROM _cdc WHERE tbl = ?1 GROUP BY pk) m
                       ON c.seq = m.seq",
                )?
                .query_map([&spec.name], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut bad = 0;
            for (pk, op, after, seq) in &newest {
                let ok = match (op.as_str(), live.get(pk)) {
                    ("D", None) => true,
                    ("D", Some(_)) => false,
                    (_, Some(row)) => after.as_deref() == Some(row.as_str()),
                    (_, None) => false,
                };
                if !ok {
                    bad += 1;
                    if problems.len() < 50 {
                        problems.push(json!({"table": spec.name, "pk": pk, "seq": seq, "op": op,
                            "logged": after, "live": live.get(pk)}));
                    }
                }
            }
            tables.push(json!({"table": spec.name, "rows": live.len(), "rows_in_log": newest.len(), "mismatches": bad}));
        }
        Ok(json!({
            "ok": problems.is_empty() && st.broken.is_none(),
            "last_txn": st.last_txn,
            "broken": st.broken,
            "tables": tables,
            "problems": problems,
        }))
    }

    /// Per-bucket `(count, sum)` of `table` as of transaction `at`: the
    /// current rows, with every later change undone in memory from the
    /// stored row images.
    pub fn bucket_hashes(&self, table: &str, at: u64, buckets: u64) -> Result<wire::BucketReport> {
        let spec = self.spec(table)?;
        let mut c = self.reader()?;
        let tx = c.transaction()?;
        let rows = self.rows_at(&tx, spec, at)?;
        let mut acc = vec![(0u64, 0u128); buckets as usize];
        for (pk, row) in &rows {
            let (b, v) = hash::row_hash(table, pk, row, buckets);
            acc[b].0 += 1;
            acc[b].1 = acc[b].1.wrapping_add(v);
        }
        Ok(wire::BucketReport {
            table: table.into(),
            at,
            buckets: acc
                .into_iter()
                .map(|(n, s)| (n, format!("{s:032x}")))
                .collect(),
        })
    }

    /// The rows of one bucket as of `at`: `(pk, row hash)`, sorted by pk.
    pub fn bucket_rows(
        &self,
        table: &str,
        at: u64,
        buckets: u64,
        bucket: usize,
    ) -> Result<Vec<wire::RowHash>> {
        let spec = self.spec(table)?;
        let mut c = self.reader()?;
        let tx = c.transaction()?;
        let rows = self.rows_at(&tx, spec, at)?;
        let mut out: Vec<wire::RowHash> = rows
            .iter()
            .filter_map(|(pk, row)| {
                let (b, v) = hash::row_hash(table, pk, row, buckets);
                (b == bucket).then(|| wire::RowHash {
                    pk: pk.clone(),
                    hash: format!("{v:032x}"),
                })
            })
            .collect();
        out.sort_by(|a, b| a.pk.cmp(&b.pk));
        Ok(out)
    }

    fn rows_at(
        &self,
        tx: &Transaction,
        spec: &TableSpec,
        at: u64,
    ) -> Result<HashMap<String, String>> {
        let st = read_state(tx)?;
        if at > st.last_txn {
            return Err(err(
                Kind::NotReady,
                format!("asked for txn {at}, this node is at {}", st.last_txn),
            ));
        }
        if at < st.last_txn && at + 1 < st.oldest_full {
            return Err(err(Kind::Gap, format!("rows after txn {at} were pruned")));
        }
        let mut rows: HashMap<String, String> = tx
            .prepare(&spec.scan_sql())?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut s = tx.prepare(
            "SELECT op, pk, before FROM _cdc WHERE tbl = ?1 AND txn_id > ?2 ORDER BY seq DESC",
        )?;
        let mut q = s.query(params![spec.name, at])?;
        while let Some(r) = q.next()? {
            let op: String = r.get(0)?;
            let pk: String = r.get(1)?;
            let before: Option<String> = r.get(2)?;
            match (op.as_str(), before) {
                ("I", _) => {
                    rows.remove(&pk);
                }
                (_, Some(b)) => {
                    rows.insert(pk, b);
                }
                _ => return Err(err(Kind::Internal, "change without before image")),
            }
        }
        Ok(rows)
    }
}

/// `_cdc_real(x)`: the shortest decimal that parses back to exactly `x`.
/// `_cdc_num(v)`: such a decimal string back to its REAL; anything else
/// unchanged (a numeric-affinity column cannot hold numeric-looking text,
/// SQLite converts it on insert).
fn register_value_functions(c: &Connection) -> rusqlite::Result<()> {
    use rusqlite::types::{Value as V, ValueRef};
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    c.create_scalar_function("_cdc_real", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Real(f) => V::Text(format!("{f:?}")),
            other => V::from(other),
        })
    })?;
    c.create_scalar_function("_cdc_num", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Text(t) => {
                let s = std::str::from_utf8(t).unwrap_or_default();
                let numeric = !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b));
                match s.parse::<f64>() {
                    Ok(f) if numeric => V::Real(f),
                    _ => V::Text(s.to_string()),
                }
            }
            other => V::from(other),
        })
    })
}

/// Transactions after `after`, stopping once `max_bytes` is reached (always
/// at least one) or after `max_txns`.
fn read_txns(c: &Connection, after: u64, max_bytes: usize, max_txns: usize) -> Result<Vec<Txn>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    let mut ts = c.prepare_cached(
        "SELECT txn_id, ts, meta, hash FROM _cdc_txn WHERE txn_id > ?1 ORDER BY txn_id LIMIT ?2",
    )?;
    let mut rs = c.prepare_cached(
        "SELECT seq, op, tbl, pk, before, after FROM _cdc WHERE txn_id = ?1 ORDER BY seq",
    )?;
    let limit = max_txns.min(i64::MAX as usize) as i64;
    let heads: Vec<(u64, String, String, String)> = ts
        .query_map(params![after, limit], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (txn_id, ts, meta, hash) in heads {
        let rows: Vec<Row> = rs
            .query_map([txn_id], |r| {
                Ok(Row {
                    seq: r.get(0)?,
                    op: r.get(1)?,
                    tbl: r.get(2)?,
                    pk: wire::raw(r.get(3)?),
                    before: r.get::<_, Option<String>>(4)?.map(wire::raw),
                    after: r.get::<_, Option<String>>(5)?.map(wire::raw),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let t = Txn {
            txn_id,
            ts,
            meta: wire::raw(meta),
            hash,
            rows,
        };
        bytes += t.bytes();
        out.push(t);
        if bytes >= max_bytes {
            break;
        }
    }
    Ok(out)
}

fn first_difference(want: &[Captured], got: &[Captured]) -> String {
    for i in 0..want.len().max(got.len()) {
        match (want.get(i), got.get(i)) {
            (Some(w), Some(g)) if w == g => continue,
            (Some(w), Some(g)) => {
                return format!("row {i}: expected {w:?}, this node produced {g:?}");
            }
            (Some(w), None) => {
                return format!("row {i}: expected {w:?}, this node changed nothing");
            }
            (None, Some(g)) => return format!("row {i}: unexpected extra change {g:?}"),
            (None, None) => unreachable!(),
        }
    }
    "no difference".into()
}

/// Every replicated table has exactly its three generated triggers, the
/// columns are the ones the triggers were generated from, and no other
/// table carries capture triggers.
fn trigger_problems(c: &Connection, tables: &[TableSpec], cfg: &Config) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let master = if cfg.temp_triggers {
        "sqlite_temp_master"
    } else {
        "sqlite_master"
    };
    let have: HashMap<String, (String, String)> = c
        .prepare(&format!("SELECT name, tbl_name, sql FROM {master} WHERE type = 'trigger' AND name LIKE '\\_cdc\\_%' ESCAPE '\\'"))?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))))?
        .collect::<rusqlite::Result<_>>()?;
    let mut expected = std::collections::HashSet::new();
    for t in tables {
        let gen_sql = t.trigger_sql(cfg.temp_triggers);
        // Compare the trigger bodies; the stored text may spell the head
        // differently (TEMP).
        let norm = |x: &str| {
            x.replace("CREATE TEMP TRIGGER", "CREATE TRIGGER")
                .trim_end_matches(['\n', ';'])
                .to_string()
        };
        for (kind, name) in ["i", "u", "d"]
            .iter()
            .map(|k| (k, format!("_cdc_{k}_{}", t.name)))
        {
            expected.insert(name.clone());
            let want = gen_sql
                .split(if cfg.temp_triggers {
                    ";\nCREATE TEMP TRIGGER "
                } else {
                    ";\nCREATE TRIGGER "
                })
                .find(|part| part.starts_with(&format!("\"_cdc_{kind}_")))
                .map(|part| format!("CREATE TRIGGER {part};"))
                .unwrap_or_default();
            match have.get(&name) {
                None => problems.push(format!(
                    "table {}: capture trigger {name} is missing",
                    t.name
                )),
                Some((_, sql)) if norm(&want) != norm(sql) => problems.push(format!(
                    "table {}: capture trigger {name} differs from the generated one",
                    t.name
                )),
                _ => {}
            }
        }
    }
    for (name, (tbl, _)) in &have {
        if !expected.contains(name) {
            problems.push(format!("unexpected capture trigger {name} on {tbl}"));
        }
    }
    // A table altered since: compare the live columns.
    let live = schema::introspect(c, &cfg.tables)?;
    for t in tables {
        match live.iter().find(|l| l.name == t.name) {
            None => problems.push(format!("table {} was dropped", t.name)),
            Some(l) if l != t => problems.push(format!(
                "table {} columns changed: {}",
                t.name,
                schema_diff(std::slice::from_ref(t), std::slice::from_ref(l))
            )),
            _ => {}
        }
    }
    Ok(problems)
}

fn commit_captured(
    tx: &Connection,
    st: &mut State,
    meta: Value,
    captured: Vec<Captured>,
) -> Result<u64> {
    let mut seq = st.last_seq;
    let rows: Vec<Row> = captured
        .into_iter()
        .map(|c| {
            seq += 1;
            Row {
                seq,
                op: c.op,
                tbl: c.tbl,
                pk: wire::raw(c.pk),
                before: c.before.map(wire::raw),
                after: c.after.map(wire::raw),
            }
        })
        .collect();
    let txn_id = st.last_txn + 1;
    let ts = now();
    let meta = serde_json::to_string(&meta)?;
    let hash = hash::txn_hash(&st.last_hash, txn_id, &ts, &meta, &rows);
    let t = Txn {
        txn_id,
        ts,
        meta: wire::raw(meta),
        hash,
        rows,
    };
    store_txn(tx, st, &t)?;
    Ok(txn_id)
}
