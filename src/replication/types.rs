//! Wire types of the replication API (primary side) and their client
//! (standby side). Snapshots carry secrets (password hashes, TOTP secrets,
//! token hashes, TSIG secrets): `Debug` is implemented by hand where a
//! secret could otherwise end up in a log line.

use crate::model::{ChangeEvent, RecordType};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Version of the replication wire format. 2: account, settings and TSIG
/// changes travel in the changelog (1 = rust-dns b17f229, which synced them
/// as snapshots). A standby refuses a primary with another version.
pub const REPLICATION_PROTOCOL: u32 = 2;

fn protocol_1() -> u32 {
    1
}

/// A value that is serialized as-is but never printed by `Debug` (hashes of
/// recovery codes in change payloads, and similar).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hidden<T>(pub T);

impl<T> std::fmt::Debug for Hidden<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<hidden>")
    }
}

/// Where a database's data comes from. A primary gets a random
/// `history_id` on first start; a standby adopts its primary's lineage at
/// bootstrap; a promotion starts a new history whose parent is the old one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "history_id": "q3V9xY2mWk8pTf1a", "parent_history_id": "Hk2mP9sLq0ZwX4bN", "fork_offset": 1834, "promoted_at": "2026-01-15T09:30:00.000Z", "promoted_from": "https://dns1.example.net:8053" }))]
pub struct History {
    pub history_id: String,
    /// The history this one was promoted from; `null` for an original primary.
    #[schema(required = true)]
    pub parent_history_id: Option<String>,
    /// Changelog offset at which the promotion forked from the parent.
    #[schema(required = true)]
    pub fork_offset: Option<i64>,
    #[schema(required = true, format = DateTime)]
    pub promoted_at: Option<String>,
    /// The primary the promoted standby had been following.
    #[schema(required = true)]
    pub promoted_from: Option<String>,
}

/// A record with its expiry bookkeeping (`expired_noted`: the expiry has
/// been processed and changelogged).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplRecord {
    pub id: i64,
    pub zone_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: RecordType,
    pub value: String,
    #[schema(required = true)]
    pub ttl: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
    #[schema(required = true)]
    pub expires_at: Option<String>,
    pub expired_noted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplMember {
    pub zone_id: i64,
    pub user_id: i64,
    pub role: String,
    pub created_at: String,
}

/// A user with every stored column, secrets included.
#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub display_name: String,
    pub is_admin: bool,
    pub is_root: bool,
    pub mfa_required: bool,
    #[schema(required = true)]
    pub totp_secret: Option<String>,
    #[schema(required = true)]
    pub totp_enrolled_at: Option<String>,
    /// Last accepted TOTP time step (replay protection).
    #[schema(required = true)]
    pub totp_last_step: Option<i64>,
    #[schema(required = true)]
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl std::fmt::Debug for ReplUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplUser")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("is_admin", &self.is_admin)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplRecoveryCode {
    pub user_id: i64,
    pub code_hash: String,
    #[schema(required = true)]
    pub used_at: Option<String>,
}

impl std::fmt::Debug for ReplRecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplRecoveryCode")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// An API token as stored (hash only; `last_used_*` is local bookkeeping
/// and not replicated).
#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub token_hash: String,
    pub created_at: String,
    #[schema(required = true)]
    pub revoked_at: Option<String>,
    pub tags: Vec<String>,
}

impl std::fmt::Debug for ReplToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplToken")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A console/API setting (e.g. the forwarding override).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplSetting {
    pub key: String,
    pub value: String,
    pub updated_by: String,
    pub updated_at: String,
}

/// A TSIG key; `secret` is base64.
#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ReplTsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
    pub zones: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

impl std::fmt::Debug for ReplTsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplTsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A zone's DNSSEC signing key; `private_key` is base64 PKCS#8 (a secret:
/// hidden from `Debug`, travels only in account-class changes and snapshots).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplDnssecKey {
    pub zone_id: i64,
    pub zone: String,
    pub algorithm: u8,
    pub flags: u16,
    pub key_tag: u16,
    /// base64, 64 bytes (x || y).
    pub public_key: String,
    pub private_key: Hidden<String>,
    pub created_at: String,
}

/// A consistent copy of everything replicated, read in one transaction,
/// as logical entities: the same facts as changelog changes (`user_created`,
/// `token_created`, `recovery_codes_replaced`, `tsig_key_set`,
/// `setting_set`, `zone_created`, `record_created`, `record_expired`,
/// `member_set`, ...). A standby loads it through the same replay code as
/// the changelog, so the format does not depend on the storage engine.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Snapshot {
    /// Replication protocol version (2).
    pub format: u32,
    pub history: History,
    /// The changelog offset this snapshot corresponds to: tail from here.
    pub offset: i64,
    #[schema(format = DateTime)]
    pub taken_at: String,
    /// Users first, then their credentials and tokens, settings, TSIG keys,
    /// zones, records and memberships (references come after their targets).
    #[schema(value_type = Vec<Object>)]
    pub entities: Vec<crate::mutation::Change>,
}

/// One long-poll answer: committed changes after the cursor (whole
/// transactions only), DNS and account changes in one sequence.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChangesResponse {
    /// Replication protocol version (2).
    pub protocol: u32,
    pub history_id: String,
    /// Latest assigned offset.
    pub head: i64,
    #[schema(required = true)]
    pub oldest_offset: Option<i64>,
    /// The cursor fell behind retention (changelog pruned, or account
    /// changes scrubbed after `[changelog].account_retention_days`): fetch a
    /// snapshot.
    pub gap: bool,
    pub events: Vec<ChangeEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ZoneChecksum {
    pub name: String,
    #[schema(format = Int64, maximum = 4294967295_u64)]
    pub serial: u32,
    /// SHA-256 over the zone row, its records (with expiry state) and members.
    pub checksum: String,
}

/// Checksum of one replicated table (local columns and the standby's own
/// root account left out).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TableChecksum {
    pub table: String,
    pub rows: i64,
    pub checksum: String,
}

/// Checksums of every replicated table, and per zone, at one offset.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Checksums {
    pub history_id: String,
    pub offset: i64,
    pub tables: Vec<TableChecksum>,
    pub zones: Vec<ZoneChecksum>,
}

/// This node's replication role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Accepts writes; never promoted.
    Primary,
    /// Accepts writes; became primary by promoting a standby.
    Promoted,
    /// Read-only mirror of the `[follow]` primary.
    Standby,
    /// Read-only: an old primary whose `[peer]` was promoted from its history.
    Fenced,
}

/// Public identity (no authentication): lets a returning old primary find
/// out whether its peer was promoted away from its history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "protocol": 2, "role": "promoted", "writable": true, "history": { "history_id": "q3V9xY2mWk8pTf1a", "parent_history_id": "Hk2mP9sLq0ZwX4bN", "fork_offset": 1834, "promoted_at": "2026-01-15T09:30:00.000Z", "promoted_from": "https://dns1.example.net:8053" } }))]
pub struct Identity {
    /// Replication protocol version (absent before version 2).
    #[serde(default = "protocol_1")]
    pub protocol: u32,
    pub role: Role,
    pub writable: bool,
    pub history: History,
}

/// A standby stopped following because its data diverged from the primary
/// (a bug: a standby never changes replicated data by itself). Kept until
/// the operator rebuilds it with `rust-dns --prepare-standby --yes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HaltInfo {
    /// `diverged` (reconcile mismatch), `apply_failed`, `txn_mismatch`,
    /// `ahead_of_primary`.
    pub reason: String,
    /// What exactly differed (tables, zones, checksums, offsets).
    pub detail: String,
    #[schema(format = DateTime)]
    pub at: String,
    /// This standby's changelog offset when it halted.
    pub offset: i64,
    /// The divergence report written next to the database.
    #[schema(required = true)]
    pub report_file: Option<String>,
}

/// Standby side of `GET /replication/status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct FollowStatus {
    /// The `[follow]` primary URL.
    pub primary: String,
    /// This standby's `[follow].instance_id` (its name on the primary).
    pub instance_id: String,
    /// connecting | bootstrapping | following | error | refused | halted | stopped
    pub state: String,
    /// The last request to the primary succeeded.
    pub connected: bool,
    pub last_applied_offset: i64,
    /// The primary's latest offset at the last contact.
    #[schema(required = true)]
    pub primary_head: Option<i64>,
    /// Changes behind the primary (as of the last contact).
    #[schema(required = true)]
    pub lag_changes: Option<i64>,
    #[schema(required = true, format = DateTime)]
    pub last_applied_at: Option<String>,
    #[schema(required = true)]
    pub seconds_since_last_applied: Option<i64>,
    #[schema(required = true, format = DateTime)]
    pub last_contact_at: Option<String>,
    /// Unreachable or refused since (null while connected).
    #[schema(required = true, format = DateTime)]
    pub disconnected_since: Option<String>,
    #[schema(required = true)]
    pub last_error: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub last_snapshot_at: Option<String>,
    #[schema(required = true)]
    pub last_snapshot_result: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub last_reconcile_at: Option<String>,
    #[schema(required = true)]
    pub last_reconcile_result: Option<String>,
    pub reconnects: u64,
    pub rebootstraps: u64,
    /// Set when replication halted (terminal until `--prepare-standby`).
    #[schema(required = true)]
    pub halted: Option<HaltInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerStatus {
    pub url: String,
    #[schema(required = true, format = DateTime)]
    pub last_check_at: Option<String>,
    #[schema(required = true)]
    pub last_result: Option<String>,
}

/// `GET /replication/replicas`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReplicaList {
    pub replicas: Vec<super::replicas::ReplicaInfo>,
}

/// `GET /replication/status`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReplicationStatus {
    /// Replication protocol version (absent before version 2).
    #[serde(default = "protocol_1")]
    pub protocol: u32,
    pub role: Role,
    pub writable: bool,
    pub history: History,
    /// This node's latest changelog offset.
    pub head: i64,
    /// Why writes are refused (standby / fenced), else null.
    #[schema(required = true)]
    pub read_only_reason: Option<String>,
    /// Present on a standby (`[follow]`).
    #[schema(required = true)]
    pub follow: Option<FollowStatus>,
    /// Present when `[peer]` is configured.
    #[schema(required = true)]
    pub peer: Option<PeerStatus>,
    /// Primary side: the standbys that follow this server, by instance id.
    #[serde(default)]
    pub replicas: Vec<super::replicas::ReplicaInfo>,
    /// A warning to show prominently (e.g. `[follow]` left in the config after promotion).
    #[schema(required = true)]
    pub warning: Option<String>,
}

/// `POST /replication/promote`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[schema(example = json!({ "confirm": true, "force": false }))]
pub struct PromoteBody {
    /// Must be true.
    pub confirm: bool,
    /// Promote even though the primary is currently reachable (two
    /// writable servers until the old primary is stopped or fenced).
    #[serde(default)]
    pub force: bool,
}

/// Result of a promotion.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PromoteResult {
    pub history: History,
    /// Whether `[follow]` was removed from the config file.
    pub config_updated: bool,
    /// What to do next (config file, old primary).
    pub notes: Vec<String>,
}

/// Short replication summary in `GET /status` (every signed-in user).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReplicationSummary {
    pub role: Role,
    pub writable: bool,
    /// The primary (standby) or the peer that superseded this node (fenced).
    #[schema(required = true)]
    pub primary: Option<String>,
    pub connected: bool,
    #[schema(required = true)]
    pub lag_changes: Option<i64>,
    #[schema(required = true, format = DateTime)]
    pub disconnected_since: Option<String>,
    #[schema(required = true)]
    pub read_only_reason: Option<String>,
    /// Why a standby is not following (state `refused`: e.g. it has local
    /// data and must be prepared with `--prepare-standby`), else null.
    #[schema(required = true)]
    pub problem: Option<String>,
    /// Replication halted because the data diverged (see the status).
    #[serde(default)]
    pub halted: bool,
    /// The non-GET operations this server accepts while it is read-only
    /// (method, path template under `/api`, `{x}` = one segment); every
    /// other non-GET operation is refused with 409 `read_only_standby`.
    #[serde(default)]
    pub standby_writable: Vec<WritableRoute>,
}

/// One operation (method and path template under `/api`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "method": "POST", "path": "/users/{id}/sessions/revoke" }))]
pub struct WritableRoute {
    pub method: String,
    pub path: String,
}

/// `POST /replication/replicas/{id}/report`: a standby tells its primary
/// that it stopped (currently only `halted`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "state": "halted", "reason": "diverged", "detail": "table users: differs (3 rows here, 3 on the primary)" }))]
pub struct ReplicaReport {
    /// `halted`.
    pub state: String,
    pub reason: String,
    pub detail: String,
}
