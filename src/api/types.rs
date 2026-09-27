//! Typed response bodies of the REST API. Every handler returns one of these
//! (or a model type), so the OpenAPI schemas generated from them are exactly
//! what goes over the wire.
//!
//! Nullability conventions (checked by the contract tests):
//! * `Option<T>` that always serializes (as a value or `null`) carries
//!   `#[schema(required = true)]`: the property is required and nullable.
//! * `Option<T>` with `skip_serializing_if` carries `#[schema(nullable = false)]`:
//!   the property may be absent but is never `null`.

use crate::dns::DnsCounters;
use crate::model::{GlobalPerm, Member, Record, User, Zone, ZonePerm, ZoneRole};
use crate::storage::TokenInfo;
use serde::Serialize;
use utoipa::ToSchema;

// ---- shared status values ---------------------------------------------------

/// Always `ok`.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OkStatus {
    Ok,
}

/// Outcome of a simple action.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StatusValue {
    Ok,
    Revoked,
    Deleted,
}

/// Acknowledgement of an action without further data.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok" }))]
pub struct StatusResponse {
    pub status: StatusValue,
}

impl StatusResponse {
    pub fn ok() -> Self {
        StatusResponse {
            status: StatusValue::Ok,
        }
    }
    pub fn revoked() -> Self {
        StatusResponse {
            status: StatusValue::Revoked,
        }
    }
    pub fn deleted() -> Self {
        StatusResponse {
            status: StatusValue::Deleted,
        }
    }
}

/// How the caller authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthVia {
    /// Cookie session from `POST /auth/login`.
    Session,
    /// `Authorization: Bearer` API token.
    Token,
}

impl AuthVia {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthVia::Session => "session",
            AuthVia::Token => "token",
        }
    }
}

// ---- users and sessions -------------------------------------------------------

/// A user account as the API shows it (no secrets).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(example = json!({ "id": 2, "username": "alice", "display_name": "Alice Example", "is_admin": false, "is_root": false, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" }))]
#[schema(as = User)]
pub struct PublicUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub is_root: bool,
    /// The user must enroll a TOTP authenticator at the next sign-in.
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    #[schema(required = true, format = DateTime)]
    pub totp_enrolled_at: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub disabled_at: Option<String>,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
}

impl From<&User> for PublicUser {
    fn from(u: &User) -> Self {
        PublicUser {
            id: u.id,
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            is_admin: u.is_admin,
            is_root: u.is_root,
            mfa_required: u.mfa_required,
            mfa_enrolled: u.mfa_enrolled(),
            totp_enrolled_at: u.totp_enrolled_at.clone(),
            disabled_at: u.disabled_at.clone(),
            created_at: u.created_at.clone(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "users": [
    { "id": 1, "username": "root", "display_name": "", "is_admin": true, "is_root": true, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" },
    { "id": 2, "username": "alice", "display_name": "Alice Example", "is_admin": false, "is_root": false, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" }
] }))]
pub struct UserList {
    pub users: Vec<PublicUser>,
}

/// A user plus freshly generated recovery codes.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserWithRecoveryCodes {
    #[serde(flatten)]
    pub user: PublicUser,
    /// Shown once.
    pub recovery_codes: Vec<String>,
}

/// The caller.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "user": { "id": 1, "username": "root", "display_name": "", "is_admin": true, "is_root": true, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" }, "ip": "192.0.2.1", "via": "session" }))]
pub struct WhoAmI {
    pub user: PublicUser,
    /// Client IP as resolved by the server (proxy aware).
    #[schema(value_type = String)]
    pub ip: std::net::IpAddr,
    pub via: AuthVia,
}

/// TOTP enrollment data.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(example = json!({ "secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://totp/rust-dns:alice?secret=JBSWY3DPEHPK3PXP&issuer=rust-dns", "qr_svg": "<svg xmlns=\"http://www.w3.org/2000/svg\" ...></svg>" }))]
pub struct EnrollPayload {
    /// Base32 TOTP secret.
    pub secret: String,
    pub otpauth_uri: String,
    /// SVG QR code of `otpauth_uri` (null if it could not be rendered).
    #[schema(required = true)]
    pub qr_svg: Option<String>,
}

/// Next step after the password was accepted.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginStatus {
    /// Signed in.
    Ok,
    /// POST /auth/mfa next.
    MfaRequired,
    /// Scan `enroll` and POST /auth/enroll.
    EnrollRequired,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok", "user": { "id": 1, "username": "root", "display_name": "", "is_admin": true, "is_root": true, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" }, "enroll": null }))]
pub struct LoginResponse {
    /// `ok`: signed in. `mfa_required`: POST /auth/mfa next.
    /// `enroll_required`: scan `enroll` and POST /auth/enroll.
    pub status: LoginStatus,
    pub user: PublicUser,
    /// TOTP enrollment data; non-null only when `status` is `enroll_required`.
    #[schema(required = true)]
    pub enroll: Option<EnrollPayload>,
}

/// State of the cookie session.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Anonymous,
    Ok,
    MfaRequired,
    EnrollRequired,
}

/// `user` and `enroll` are absent when `status` is `anonymous`.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok", "user": { "id": 1, "username": "root", "display_name": "", "is_admin": true, "is_root": true, "mfa_required": false, "mfa_enrolled": false, "totp_enrolled_at": null, "disabled_at": null, "created_at": "2026-01-15T09:30:00.000Z" }, "enroll": null }))]
pub struct SessionInfo {
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub user: Option<PublicUser>,
    /// TOTP enrollment data; non-null only when `status` is `enroll_required`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<EnrollPayload>)]
    pub enroll: Option<Option<EnrollPayload>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MfaVerifyResponse {
    pub status: OkStatus,
    pub user: PublicUser,
    pub recovery_codes_left: i64,
    /// True when a one-time recovery code (not a TOTP code) was used.
    pub used_recovery_code: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollVerifyResponse {
    pub status: OkStatus,
    pub user: PublicUser,
    /// Shown once.
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "recovery_codes": ["abcd-efgh-ijkl", "mnop-qrst-uvwx"] }))]
pub struct RecoveryCodes {
    /// Shown once; the previous codes stop working.
    pub recovery_codes: Vec<String>,
}

/// A signed-in browser session.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "id": 3, "ip": "192.0.2.1", "user_agent": "Mozilla/5.0", "created_at": "2026-01-15T09:30:00.000Z", "last_seen_at": "2026-01-15T10:02:11.482Z", "expires_at": "2026-01-16T09:30:00.000Z", "current": true }))]
pub struct SessionEntry {
    pub id: i64,
    pub ip: String,
    pub user_agent: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub last_seen_at: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub expires_at: String,
    /// True for the session making this request (always false in the admin view).
    pub current: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionList {
    pub sessions: Vec<SessionEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok", "revoked": 2 }))]
pub struct RevokedCount {
    pub status: OkStatus,
    /// Number of sessions signed out.
    pub revoked: usize,
}

// ---- zones, records, members ------------------------------------------------------

/// A zone with the caller's view of it.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "id": 1, "name": "example.com", "serial": 2026011501, "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "refresh": 3600, "retry": 600, "expire": 1209600, "minimum": 300, "default_ttl": 3600, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "owner_id": 1, "fqdn": "example.com.", "owner": "root", "role": "owner", "record_count": 3 }))]
pub struct ZoneView {
    #[serde(flatten)]
    pub zone: Zone,
    #[schema(example = "example.com.")]
    pub fqdn: String,
    /// Owner username.
    #[schema(required = true)]
    pub owner: Option<String>,
    /// The caller's role on this zone.
    pub role: ZoneRole,
    pub record_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "zones": [{ "id": 1, "name": "example.com", "serial": 2026011501, "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "refresh": 3600, "retry": 600, "expire": 1209600, "minimum": 300, "default_ttl": 3600, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "owner_id": 1, "fqdn": "example.com.", "owner": "root", "role": "owner", "record_count": 3 }] }))]
pub struct ZoneList {
    pub zones: Vec<ZoneView>,
}

/// A zone with the first page of records and its members.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "id": 1, "name": "example.com", "serial": 2026011501, "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "refresh": 3600, "retry": 600, "expire": 1209600, "minimum": 300, "default_ttl": 3600, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "owner_id": 1, "fqdn": "example.com.", "owner": "root", "role": "owner", "record_count": 1,
    "records": [{ "id": 42, "zone_id": 1, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "expires_at": null }],
    "record_total": 1, "record_page": 500,
    "members": [{ "user_id": 2, "username": "alice", "role": "editor", "created_at": "2026-01-15T09:30:00.000Z" }] }))]
pub struct ZoneDetail {
    #[serde(flatten)]
    pub zone: ZoneView,
    /// First page of records (use /zones/{zone}/records to page or search).
    pub records: Vec<Record>,
    pub record_total: i64,
    #[schema(example = 500)]
    pub record_page: usize,
    /// Empty unless the caller may manage access (owner).
    pub members: Vec<Member>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "deleted", "zone": "example.com" }))]
pub struct ZoneDeleted {
    pub status: DeletedStatus,
    pub zone: String,
}

/// Always `deleted`.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletedStatus {
    Deleted,
}

/// A page of records.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "records": [{ "id": 42, "zone_id": 1, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "expires_at": null }], "total": 1, "offset": 0, "limit": 500 }))]
pub struct RecordPage {
    pub records: Vec<Record>,
    /// Matches before paging.
    pub total: i64,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "members": [{ "user_id": 2, "username": "alice", "role": "editor", "created_at": "2026-01-15T09:30:00.000Z" }] }))]
pub struct MemberList {
    pub members: Vec<Member>,
}

/// Import summary of a BIND zone file.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "zones_created": 0, "zones_updated": 1, "records_added": 3, "records_removed": 0, "records_skipped": 0, "skipped": [] }))]
pub struct BindImportSummary {
    #[serde(flatten)]
    pub summary: crate::mutation::ImportSummary,
    /// Zone-file entries that were not imported, with the reason.
    pub skipped: Vec<String>,
}

// ---- logs -------------------------------------------------------------------------

/// Change log entries plus retention bounds.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangelogPage {
    pub entries: Vec<crate::model::ChangeEvent>,
    #[schema(required = true)]
    pub oldest_offset: Option<i64>,
    #[schema(required = true)]
    pub latest_offset: Option<i64>,
    /// `after` fell behind retention; refetch full state.
    pub resync_required: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditPage {
    pub entries: Vec<crate::mutation::accounts::AuditRecord>,
}

// ---- rights -----------------------------------------------------------------------

/// Effective rights of a user (or of their API tokens).
#[derive(Debug, Serialize, ToSchema)]
pub struct Rights {
    pub user: PublicUser,
    pub via: AuthVia,
    pub active_tokens: usize,
    pub global: Vec<GlobalRight>,
    pub zones: Vec<ZoneRights>,
    /// Legend: every zone permission and the minimum role it needs.
    pub zone_permissions: Vec<ZonePermInfo>,
    pub notes: Vec<String>,
}

/// One account-level permission and whether the user holds it.
#[derive(Debug, Serialize, ToSchema)]
pub struct GlobalRight {
    pub perm: GlobalPerm,
    pub label: &'static str,
    pub allowed: bool,
    /// Why it is denied.
    #[schema(required = true)]
    pub reason: Option<String>,
    pub requires_admin: bool,
    pub requires_session: bool,
}

/// Where a zone role comes from.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoleSource {
    Administrator,
    Owner,
    Member,
}

/// The user's role on one zone and what it allows.
#[derive(Debug, Serialize, ToSchema)]
pub struct ZoneRights {
    pub zone: String,
    pub role: ZoneRole,
    pub source: RoleSource,
    pub permissions: Vec<ZonePerm>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ZonePermInfo {
    pub perm: ZonePerm,
    pub label: &'static str,
    pub min_role: ZoneRole,
}

// ---- tokens -------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListEntry {
    #[serde(flatten)]
    pub info: TokenInfo,
    /// Owner username.
    #[schema(required = true)]
    pub username: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "tokens": [{ "id": 7, "user_id": 1, "name": "ci-deploy", "tags": ["ci", "deploy"], "created_at": "2026-01-15T09:30:00.000Z", "last_used_at": "2026-01-16T08:00:00.000Z", "last_used_ip": "192.0.2.10", "revoked_at": null, "username": "root" }] }))]
pub struct TokenList {
    pub tokens: Vec<TokenListEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "token": "rdns_3q2+7w...", "info": { "id": 7, "user_id": 1, "name": "ci-deploy", "tags": ["ci", "deploy"], "created_at": "2026-01-15T09:30:00.000Z", "last_used_at": null, "last_used_ip": null, "revoked_at": null } }))]
pub struct TokenCreated {
    /// Plaintext `rdns_...` token; shown only once. Send as
    /// `Authorization: Bearer <token>`.
    pub token: String,
    pub info: TokenInfo,
}

// ---- server ---------------------------------------------------------------------------

/// `ok` or `error`.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OkOrError {
    Ok,
    Error,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok", "version": "0.1.0" }))]
pub struct Health {
    pub status: OkOrError,
    /// Present when ok.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub version: Option<&'static str>,
    /// `unavailable` on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub database: Option<&'static str>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok" }))]
pub struct IntegrityResult {
    pub status: OkOrError,
    /// What failed (only on error).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReloadResult {
    pub status: OkStatus,
    /// What changed / what needs a restart.
    pub notes: Vec<String>,
}

/// Server status, counters and runtime settings.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServerStatus {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub zones: i64,
    pub records: i64,
    /// Zones the caller can see.
    pub visible_zones: usize,
    pub changelog: ChangelogStatus,
    pub dns: DnsCounters,
    pub forward_cache: ForwardCacheStatus,
    pub rate_limit: RateLimitStatus,
    pub listeners: ListenerStatus,
    pub forwarding: ForwardingStatus,
    pub transfer: TransferStatus,
    pub auto_ptr: bool,
    /// Whether DNS cookies (RFC 7873) are enabled.
    pub cookies: bool,
    /// EDNS NSID reply; empty when off.
    pub nsid: String,
    /// When the in-memory zone catalog was last rebuilt.
    #[schema(format = DateTime)]
    pub catalog_built_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangelogStatus {
    #[schema(required = true)]
    pub oldest_offset: Option<i64>,
    #[schema(required = true)]
    pub latest_offset: Option<i64>,
    pub head: i64,
    pub retention_days: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardCacheStatus {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitStatus {
    pub tracked_addresses: usize,
    pub max_tracked_addresses: usize,
    pub max_resolutions_per_second_per_address: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListenerStatus {
    #[schema(value_type = Vec<String>)]
    pub bind: Vec<std::net::IpAddr>,
    pub port: u16,
    pub udp: bool,
    pub tcp: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardingStatus {
    #[schema(value_type = Vec<String>)]
    pub upstreams: Vec<std::net::SocketAddr>,
    pub allowed_clients: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransferStatus {
    pub allow: Vec<String>,
    #[schema(value_type = Vec<String>)]
    pub notify: Vec<std::net::SocketAddr>,
}
