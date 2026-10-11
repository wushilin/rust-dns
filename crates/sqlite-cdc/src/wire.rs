//! JSON types of the replication protocol. Row images travel as raw JSON
//! (`RawValue`), byte for byte as SQLite produced them, because the chain
//! hash covers those exact bytes.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::schema::TableSpec;

pub type Raw = Box<RawValue>;

pub fn raw(s: String) -> Raw {
    RawValue::from_string(s).expect("SQLite json_object output is valid JSON")
}

/// One captured row change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub seq: u64,
    /// `I`, `U` or `D`.
    pub op: String,
    pub tbl: String,
    pub pk: Raw,
    pub before: Option<Raw>,
    pub after: Option<Raw>,
}

/// One committed transaction: the unit of apply, never split.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Txn {
    pub txn_id: u64,
    pub ts: String,
    /// Application metadata (actor, command) or an epoch marker.
    pub meta: Raw,
    /// `blake3(prev_hash ‖ this txn)`, hex.
    pub hash: String,
    pub rows: Vec<Row>,
}

impl Txn {
    pub fn bytes(&self) -> usize {
        self.meta.get().len()
            + self
                .rows
                .iter()
                .map(|r| {
                    r.pk.get().len()
                        + r.before.as_ref().map_or(0, |b| b.get().len())
                        + r.after.as_ref().map_or(0, |a| a.get().len())
                        + 24
                })
                .sum::<usize>()
    }
}

/// A position in a history: the follower presents it on every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub history: String,
    pub txn_id: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub txns: Vec<Txn>,
    /// The server's last committed transaction (for lag).
    pub last_txn: u64,
    /// The server's view of this follower (position = `after`).
    #[serde(default)]
    pub client: Option<ClientView>,
}

/// The kept-forever chain entry (rows may be pruned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub txn_id: u64,
    pub ts: String,
    pub meta: Raw,
    pub end_seq: u64,
    pub rows: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub history: String,
    pub txn_id: u64,
    pub end_seq: u64,
    pub hash: String,
    pub tables: Vec<TableSpec>,
    /// Rows per table, for progress.
    pub row_counts: Vec<u64>,
    pub chain_entries: u64,
}

/// One NDJSON line of a snapshot stream.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapLine {
    Header(SnapshotHeader),
    Row {
        t: String,
        r: Raw,
    },
    Chain(ChainEntry),
    /// blake3 over every previous line (bytes plus `\n`), hex.
    Footer {
        digest: String,
        lines: u64,
    },
}

/// One NDJSON line of a change stream.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamLine {
    Txn(Txn),
    Heartbeat { last_txn: u64 },
    Error(ErrorBody),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// `gap`, `diverged`, `ahead`, `history`, `not_ready`, `halted`, ...
    pub error: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub node_id: String,
    pub role: String,
    pub history: Option<String>,
    pub last_txn: u64,
    pub last_hash: String,
    pub oldest_full: u64,
    pub halted: Option<serde_json::Value>,
    pub upstream: Option<String>,
    pub follow: Option<serde_json::Value>,
    /// Schema fingerprint (followers must match it).
    pub schema: String,
    /// Self-check problems; empty when healthy.
    pub health: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketReport {
    pub table: String,
    pub at: u64,
    /// `(count, sum)` per bucket; `sum` is a wrapping u128 of row hashes, hex.
    pub buckets: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowHash {
    pub pk: String,
    pub hash: String,
}

/// A follower as the server sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Stable id the follower sends (`x-cdc-client-id`), else its address.
    pub id: String,
    pub name: String,
    /// Who the authorizer said it is.
    pub principal: Option<String>,
    pub addr: Option<String>,
    /// `poll`, `stream` or `snapshot`: its last kind of request.
    pub mode: String,
    /// The last transaction it has applied, as it last reported.
    pub position: u64,
    /// A stream is open right now.
    pub connected: bool,
    pub first_seen: f64,
    pub last_seen: f64,
    pub requests: u64,
    pub txns_sent: u64,
    /// The server's last transaction minus `position`.
    pub lag_txns: u64,
    /// Caught up, and heard from within the last minute (or streaming).
    pub up_to_date: bool,
}

/// What the server thinks of the asking follower: returned to it, so both
/// sides agree on whether it is up to date.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientView {
    pub server_last_txn: u64,
    pub position: u64,
    pub lag_txns: u64,
    pub up_to_date: bool,
}
