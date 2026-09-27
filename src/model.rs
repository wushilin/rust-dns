//! Domain model: zones, records, validation and normalisation, and the
//! event types that flow over the bus.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn invalid<T>(msg: impl Into<String>) -> Result<T, Invalid> {
    Err(Invalid(msg.into()))
}

/// Record types the server stores and serves.
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, ToSchema,
)]
#[serde(rename_all = "UPPERCASE")]
#[schema(example = "A")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    DNAME,
    PTR,
    NS,
    MX,
    TXT,
    SRV,
    CAA,
    HTTPS,
    SVCB,
    TLSA,
    SSHFP,
    NAPTR,
    HINFO,
}

impl RecordType {
    pub const ALL: [RecordType; 16] = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::DNAME,
        RecordType::PTR,
        RecordType::NS,
        RecordType::MX,
        RecordType::TXT,
        RecordType::SRV,
        RecordType::CAA,
        RecordType::HTTPS,
        RecordType::SVCB,
        RecordType::TLSA,
        RecordType::SSHFP,
        RecordType::NAPTR,
        RecordType::HINFO,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::DNAME => "DNAME",
            RecordType::PTR => "PTR",
            RecordType::NS => "NS",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
            RecordType::HTTPS => "HTTPS",
            RecordType::SVCB => "SVCB",
            RecordType::TLSA => "TLSA",
            RecordType::SSHFP => "SSHFP",
            RecordType::NAPTR => "NAPTR",
            RecordType::HINFO => "HINFO",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        RecordType::ALL
            .iter()
            .copied()
            .find(|t| t.as_str().eq_ignore_ascii_case(s.trim()))
    }

    pub fn to_hickory(self) -> hickory_proto::rr::RecordType {
        use hickory_proto::rr::RecordType as H;
        match self {
            RecordType::A => H::A,
            RecordType::AAAA => H::AAAA,
            RecordType::CNAME => H::CNAME,
            RecordType::DNAME => H::Unknown(39),
            RecordType::PTR => H::PTR,
            RecordType::NS => H::NS,
            RecordType::MX => H::MX,
            RecordType::TXT => H::TXT,
            RecordType::SRV => H::SRV,
            RecordType::CAA => H::CAA,
            RecordType::HTTPS => H::HTTPS,
            RecordType::SVCB => H::SVCB,
            RecordType::TLSA => H::TLSA,
            RecordType::SSHFP => H::SSHFP,
            RecordType::NAPTR => H::NAPTR,
            RecordType::HINFO => H::HINFO,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A zone as stored. Names are stored lower-case without the trailing dot.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Zone {
    pub id: i64,
    /// Lower-case, no trailing dot (`.` for the root zone).
    #[schema(example = "example.com")]
    pub name: String,
    /// SOA serial (unsigned 32-bit, so it may exceed the int32 range).
    #[schema(format = Int64, maximum = 4294967295_u64)]
    pub serial: u32,
    #[schema(example = "ns1.example.com.")]
    pub soa_mname: String,
    #[schema(example = "hostmaster.example.com.")]
    pub soa_rname: String,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub default_ttl: u32,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub updated_at: String,
    #[schema(required = true)]
    pub owner_id: Option<i64>,
}

impl Zone {
    /// Fully qualified apex, e.g. `example.com.`
    pub fn fqdn(&self) -> String {
        zone_fqdn(&self.name)
    }
}

/// Input for creating or updating a zone. Create: `name` is required, other
/// fields fall back to server defaults. Update: omitted fields are left
/// unchanged (`name` is ignored).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ZoneInput {
    #[schema(example = "example.com")]
    pub name: Option<String>,
    #[schema(example = "ns1.example.com.")]
    pub soa_mname: Option<String>,
    /// `hostmaster.example.com.` or `hostmaster@example.com`
    #[schema(example = "hostmaster@example.com")]
    pub soa_rname: Option<String>,
    #[schema(example = 3600)]
    pub refresh: Option<u32>,
    #[schema(example = 600)]
    pub retry: Option<u32>,
    #[schema(example = 1209600)]
    pub expire: Option<u32>,
    #[schema(example = 300)]
    pub minimum: Option<u32>,
    #[schema(example = 3600)]
    pub default_ttl: Option<u32>,
    /// Owner username. Create: defaults to the caller. Update: administrators
    /// only; empty string clears the owner.
    pub owner: Option<String>,
}

// ---------------------------------------------------------------------------
// Users, sessions, membership
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub display_name: String,
    pub is_admin: bool,
    pub is_root: bool,
    pub mfa_required: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub totp_enrolled_at: Option<String>,
    pub disabled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    pub fn mfa_enrolled(&self) -> bool {
        self.totp_secret.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub display_name: String,
    pub is_admin: bool,
    pub mfa_required: bool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub token_hash: String,
    pub user_id: i64,
    /// active | mfa_pending | enroll_pending
    pub state: String,
    pub pending_secret: Option<String>,
    pub ip: String,
    pub user_agent: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_seen_at: String,
}

/// A user granted access to a zone that is not its owner.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(example = json!({ "user_id": 2, "username": "alice", "role": "editor", "created_at": "2026-01-15T09:30:00.000Z" }))]
pub struct Member {
    pub user_id: i64,
    pub username: String,
    /// editor | viewer
    #[schema(value_type = MemberRole)]
    pub role: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
}

/// Role of a zone member (the owner is not a member).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(example = "editor")]
pub enum MemberRole {
    Editor,
    Viewer,
}

/// What a caller may do with a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(example = "owner")]
pub enum ZoneRole {
    Viewer,
    Editor,
    Owner,
}

impl ZoneRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(ZoneRole::Viewer),
            "editor" => Some(ZoneRole::Editor),
            "owner" => Some(ZoneRole::Owner),
            _ => None,
        }
    }
}

impl ZoneRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ZoneRole::Viewer => "viewer",
            ZoneRole::Editor => "editor",
            ZoneRole::Owner => "owner",
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions: the single table that both the API checks and the "effective
// rights" view are generated from.
// ---------------------------------------------------------------------------

/// Something a caller may do inside one zone. Granted when the caller's role
/// on the zone is at least [`ZonePerm::min_role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ZonePerm {
    View,
    Export,
    EditRecords,
    EditSettings,
    ManageAccess,
    Import,
    DeleteZone,
    WatchQueries,
}

impl ZonePerm {
    pub const ALL: [ZonePerm; 8] = [
        ZonePerm::View,
        ZonePerm::Export,
        ZonePerm::EditRecords,
        ZonePerm::EditSettings,
        ZonePerm::ManageAccess,
        ZonePerm::Import,
        ZonePerm::DeleteZone,
        ZonePerm::WatchQueries,
    ];

    pub fn min_role(self) -> ZoneRole {
        match self {
            ZonePerm::View | ZonePerm::Export => ZoneRole::Viewer,
            ZonePerm::EditRecords => ZoneRole::Editor,
            ZonePerm::EditSettings
            | ZonePerm::ManageAccess
            | ZonePerm::Import
            | ZonePerm::DeleteZone
            | ZonePerm::WatchQueries => ZoneRole::Owner,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ZonePerm::View => "See records, SOA settings and the zone's change log",
            ZonePerm::Export => "Export the zone as JSON or a BIND zone file",
            ZonePerm::EditRecords => "Add, change and delete records",
            ZonePerm::EditSettings => "Change SOA settings (TTLs, timers, name servers)",
            ZonePerm::ManageAccess => "See and grant editor or viewer access to other users",
            ZonePerm::Import => "Import records (JSON or BIND), including replacing all records",
            ZonePerm::DeleteZone => "Delete the zone and all its records",
            ZonePerm::WatchQueries => "See live DNS queries for names in the zone",
        }
    }

    pub fn allowed(self, role: ZoneRole) -> bool {
        role >= self.min_role()
    }
}

/// Something a caller may do outside any one zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GlobalPerm {
    CreateZones,
    TransferOwnership,
    ManageUsers,
    ViewAudit,
    ServerAdmin,
    ManageOwnTokens,
    ChangeOwnPassword,
    ManageOwnMfa,
    ManageOwnSessions,
}

impl GlobalPerm {
    pub const ALL: [GlobalPerm; 9] = [
        GlobalPerm::CreateZones,
        GlobalPerm::TransferOwnership,
        GlobalPerm::ManageUsers,
        GlobalPerm::ViewAudit,
        GlobalPerm::ServerAdmin,
        GlobalPerm::ManageOwnTokens,
        GlobalPerm::ChangeOwnPassword,
        GlobalPerm::ManageOwnMfa,
        GlobalPerm::ManageOwnSessions,
    ];

    pub fn requires_admin(self) -> bool {
        matches!(
            self,
            GlobalPerm::CreateZones
                | GlobalPerm::TransferOwnership
                | GlobalPerm::ManageUsers
                | GlobalPerm::ViewAudit
                | GlobalPerm::ServerAdmin
        )
    }

    /// Only from a signed-in browser session, never with an API token.
    pub fn requires_session(self) -> bool {
        matches!(
            self,
            GlobalPerm::ChangeOwnPassword
                | GlobalPerm::ManageOwnMfa
                | GlobalPerm::ManageOwnSessions
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            GlobalPerm::CreateZones => "Create zones (including through import)",
            GlobalPerm::TransferOwnership => "Change the owner of any zone",
            GlobalPerm::ManageUsers => {
                "Create, change, disable and delete users; sign users out; see all API tokens"
            }
            GlobalPerm::ViewAudit => "Read the audit log",
            GlobalPerm::ServerAdmin => {
                "Reload the configuration and run the database integrity check"
            }
            GlobalPerm::ManageOwnTokens => "Create, list and revoke own API tokens",
            GlobalPerm::ChangeOwnPassword => "Change own password",
            GlobalPerm::ManageOwnMfa => "Enroll, disable or reset own MFA and recovery codes",
            GlobalPerm::ManageOwnSessions => "Sign out own sessions",
        }
    }

    /// Whether `user` holds this permission when authenticated `via`
    /// ("session" or "token"); `Err` carries the reason when not.
    pub fn check(self, user: &User, via: &str) -> Result<(), String> {
        if self.requires_admin() && !user.is_admin {
            return Err("administrators only".into());
        }
        if self.requires_session() && via != "session" {
            return Err("needs a signed-in browser session; API tokens cannot do this".into());
        }
        if self == GlobalPerm::ChangeOwnPassword && user.is_root {
            return Err("the root password is set in the configuration file".into());
        }
        Ok(())
    }
}

/// A record as stored. `name` is relative to the zone: `@` for the apex,
/// `www`, `*`, `_sip._tcp` and so on.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "id": 42, "zone_id": 1, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "expires_at": null }))]
pub struct Record {
    pub id: i64,
    pub zone_id: i64,
    /// Relative to the zone: `@` (apex), `www`, `*.apps`, `_sip._tcp`.
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: RecordType,
    /// Presentation format, e.g. `10 mail.example.com.` for MX.
    pub value: String,
    /// The record's TTL; `null` means the zone default TTL applies.
    #[schema(required = true)]
    pub ttl: Option<u32>,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub created_at: String,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub updated_at: String,
    /// When the record stops being served (RFC 3339, UTC); `null` = never.
    /// Expired records stay visible in the console and are deleted after
    /// `[expiry].retention_days` (default 30).
    #[serde(default)]
    #[schema(required = true, format = DateTime, example = "2026-10-01T00:00:00.000Z")]
    pub expires_at: Option<String>,
}

impl Record {
    /// True when the record has an expiry at or before `now` (RFC 3339 UTC strings compare in order).
    pub fn is_expired_at(&self, now: &str) -> bool {
        self.expires_at.as_deref().is_some_and(|e| e <= now)
    }

    /// Owner name as a fully qualified, lower-case name with trailing dot.
    pub fn owner(&self, zone: &Zone) -> String {
        owner_fqdn(&zone.name, &self.name)
    }
}

/// Input for creating or updating a record. Create: `type` is required,
/// `name` defaults to `@`. Update: omitted fields keep their current values,
/// including `ttl`; `"ttl": null` switches to the zone default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300 }))]
pub struct RecordInput {
    #[schema(example = "www")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub rtype: Option<RecordType>,
    #[schema(example = "192.0.2.10")]
    pub value: Option<String>,
    /// Omitted: keep the current TTL (update) or use the zone default (create).
    /// `null`: zone default. A number: that TTL.
    #[serde(
        default,
        deserialize_with = "present_or_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<u32>, example = 300)]
    pub ttl: Option<Option<u32>>,
    /// When the record stops being served, RFC 3339 (e.g. "2026-10-01T00:00:00Z").
    /// Absent: keep the current expiry (update) or never expire (create).
    /// `null`: never expire. Must be in the future. Do not combine with
    /// `expires_in`.
    #[serde(
        default,
        deserialize_with = "present_or_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, format = DateTime, example = "2026-10-01T00:00:00Z")]
    pub expires_at: Option<Option<String>>,
    /// Alternative to `expires_at`: seconds from now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, minimum = 1, example = 86400)]
    pub expires_in: Option<u64>,
}

/// Resolve the expiry fields of a record input against `now`.
/// `Ok(None)`: not specified. `Ok(Some(None))`: never expires. `Ok(Some(Some(t)))`: expires at `t`.
pub fn resolve_expiry(
    input: &RecordInput,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Option<String>>, Invalid> {
    let fmt =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    match (&input.expires_at, input.expires_in) {
        (Some(_), Some(_)) => invalid("send either expires_at or expires_in, not both"),
        (None, None) => Ok(None),
        (Some(None), None) => Ok(Some(None)),
        (None, Some(secs)) => {
            if secs == 0 || secs > 100 * 365 * 86_400 {
                return invalid("expires_in must be between 1 second and 100 years");
            }
            Ok(Some(Some(
                fmt(now + chrono::Duration::seconds(secs as i64)),
            )))
        }
        (Some(Some(t)), None) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(t.trim())
                .map_err(|_| {
                    Invalid(format!(
                        "expires_at '{t}' is not an RFC 3339 time, e.g. 2026-10-01T00:00:00Z"
                    ))
                })?
                .with_timezone(&chrono::Utc);
            if parsed <= now {
                return invalid("expires_at must be in the future");
            }
            Ok(Some(Some(fmt(parsed))))
        }
    }
}

/// Distinguishes an absent field (`None`) from an explicit `null` (`Some(None)`).
fn present_or_null<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

pub fn owner_fqdn(zone: &str, relative: &str) -> String {
    let apex = zone_fqdn(zone);
    if relative == "@" || relative.is_empty() {
        apex
    } else if zone == "." {
        format!("{relative}.")
    } else {
        format!("{relative}.{apex}")
    }
}

/// Fully qualified apex for a stored zone name (`example.com` -> `example.com.`, `.` -> `.`).
pub fn zone_fqdn(zone: &str) -> String {
    if zone == "." {
        ".".to_string()
    } else {
        format!("{zone}.")
    }
}

// ---------------------------------------------------------------------------
// Validation and normalisation
// ---------------------------------------------------------------------------

fn validate_label(
    label: &str,
    allow_underscore: bool,
    allow_wildcard: bool,
) -> Result<(), Invalid> {
    if label.is_empty() {
        return invalid("empty label");
    }
    if label.len() > 63 {
        return invalid(format!("label '{label}' is longer than 63 bytes"));
    }
    if label == "*" {
        if allow_wildcard {
            return Ok(());
        }
        return invalid("wildcard label not allowed here");
    }
    for (i, c) in label.chars().enumerate() {
        let ok = c.is_ascii_alphanumeric()
            || c == '-'
            || (allow_underscore && c == '_')
            || (i == 0 && c == '*' && allow_wildcard && false);
        if !ok {
            return invalid(format!("label '{label}' contains invalid character '{c}'"));
        }
    }
    if label.starts_with('-') || label.ends_with('-') {
        return invalid(format!("label '{label}' must not start or end with '-'"));
    }
    Ok(())
}

/// Normalise a domain name: lower-case, no trailing dot, validated labels.
pub fn normalize_domain(name: &str, allow_underscore: bool) -> Result<String, Invalid> {
    let trimmed = name.trim();
    let ascii;
    let name = if trimmed.is_ascii() {
        trimmed
    } else {
        // Internationalised names are stored in their punycode (A-label) form.
        ascii = idna::domain_to_ascii(trimmed)
            .map_err(|_| Invalid(format!("'{trimmed}' is not a valid internationalised name")))?;
        ascii.as_str()
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return invalid("name must not be empty");
    }
    if name.len() > 253 {
        return invalid("name is longer than 253 bytes");
    }
    for label in name.split('.') {
        validate_label(label, allow_underscore, false)?;
    }
    Ok(name)
}

/// Zone names: standard host-name labels, underscores allowed for things
/// like `_acme-challenge` delegations.
pub fn normalize_username(name: &str) -> Result<String, Invalid> {
    let n = name.trim().to_ascii_lowercase();
    if n.len() < 2 || n.len() > 64 {
        return invalid("username must be 2-64 characters");
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '@')
    {
        return invalid("username may contain letters, digits, '.', '_', '-' and '@'");
    }
    Ok(n)
}

pub fn normalize_zone_name(name: &str) -> Result<String, Invalid> {
    if name.trim() == "." {
        return Ok(".".to_string());
    }
    normalize_domain(name, true)
}

/// Normalise a record name relative to its zone. Accepts `@`, empty,
/// relative (`www`), or absolute (`www.example.com` / `www.example.com.`)
/// forms; wildcards (`*`, `*.sub`) allowed on the leftmost label.
pub fn normalize_record_name(name: &str, zone: &str) -> Result<String, Invalid> {
    let ascii;
    let name = if name.trim().is_ascii() {
        name.trim()
    } else {
        ascii = idna::domain_to_ascii(name.trim())
            .map_err(|_| Invalid(format!("'{name}' is not a valid internationalised name")))?;
        ascii.as_str()
    };
    let raw = name.to_ascii_lowercase();
    if raw.is_empty() || raw == "@" {
        return Ok("@".to_string());
    }
    let stripped = raw.trim_end_matches('.');
    let suffix = if zone == "." {
        String::new()
    } else {
        format!(".{zone}")
    };
    let rel = if zone == "." {
        stripped
    } else if stripped == zone {
        return Ok("@".to_string());
    } else if let Some(r) = stripped.strip_suffix(&suffix) {
        r
    } else if raw.ends_with('.') {
        return invalid(format!("'{name}' is not inside zone '{zone}'"));
    } else {
        stripped
    };
    if rel.is_empty() {
        return Ok("@".to_string());
    }
    let full_len = rel.len() + 1 + if zone == "." { 0 } else { zone.len() };
    if full_len > 253 {
        return invalid("name is longer than 253 bytes");
    }
    for (i, label) in rel.split('.').enumerate() {
        validate_label(label, true, i == 0)?;
    }
    Ok(rel.to_string())
}

/// Validate and canonicalise a record value for its type. Names inside
/// values are always absolute and are returned with a trailing dot.
pub fn normalize_value(rtype: RecordType, value: &str) -> Result<String, Invalid> {
    let v = value.trim();
    if v.is_empty() {
        return invalid("value must not be empty");
    }
    match rtype {
        RecordType::A => {
            let ip: Ipv4Addr = v
                .parse()
                .map_err(|_| Invalid(format!("'{v}' is not a valid IPv4 address")))?;
            Ok(ip.to_string())
        }
        RecordType::AAAA => {
            let ip: Ipv6Addr = v
                .parse()
                .map_err(|_| Invalid(format!("'{v}' is not a valid IPv6 address")))?;
            Ok(ip.to_string())
        }
        RecordType::CNAME | RecordType::PTR | RecordType::NS => {
            let n = normalize_domain(v, true)?;
            Ok(format!("{n}."))
        }
        RecordType::MX => {
            let mut parts = v.split_whitespace();
            let pref: u16 = parts
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| Invalid("MX value must be '<preference> <host>'".into()))?;
            let host = parts
                .next()
                .ok_or_else(|| Invalid("MX value must be '<preference> <host>'".into()))?;
            if parts.next().is_some() {
                return invalid("MX value must be '<preference> <host>'");
            }
            let host = normalize_domain(host, true)?;
            Ok(format!("{pref} {host}."))
        }
        RecordType::SRV => {
            let parts: Vec<&str> = v.split_whitespace().collect();
            if parts.len() != 4 {
                return invalid("SRV value must be '<priority> <weight> <port> <target>'");
            }
            let nums: Result<Vec<u16>, _> = parts[..3].iter().map(|p| p.parse::<u16>()).collect();
            let nums =
                nums.map_err(|_| Invalid("SRV priority, weight and port must be 0-65535".into()))?;
            let target = normalize_domain(parts[3], true)?;
            Ok(format!("{} {} {} {}.", nums[0], nums[1], nums[2], target))
        }
        RecordType::DNAME => {
            let n = normalize_domain(v, true)?;
            Ok(format!("{n}."))
        }
        RecordType::TXT => {
            if v.len() > 4096 {
                return invalid("TXT value is longer than 4096 bytes");
            }
            // Accept quoted BIND-style input and store the raw text.
            let unq = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                v[1..v.len() - 1].replace("\\\"", "\"")
            } else {
                v.to_string()
            };
            Ok(unq)
        }
        RecordType::CAA
        | RecordType::HTTPS
        | RecordType::SVCB
        | RecordType::TLSA
        | RecordType::SSHFP
        | RecordType::NAPTR
        | RecordType::HINFO => {
            // Validate with hickory's presentation-format parser and store the canonical text.
            use hickory_proto::serialize::txt::RDataParser;
            hickory_proto::rr::RData::try_from_str(rtype.to_hickory(), v).map_err(|e| {
                Invalid(format!(
                    "{rtype} value: {e} (example: {})",
                    value_hint(rtype)
                ))
            })?;
            if v.len() > 8192 {
                return invalid("value is too long");
            }
            // Keep the validated presentation text as typed: hickory's Display form
            // is not always re-parseable (e.g. SVCB parameter lists).
            Ok(v.split_whitespace().collect::<Vec<_>>().join(" "))
        }
    }
}

/// Human hints for the presentation format of each type (used by the console and errors).
pub fn value_hint(rtype: RecordType) -> &'static str {
    match rtype {
        RecordType::A => "10.0.0.1",
        RecordType::AAAA => "2001:db8::1",
        RecordType::CNAME => "target.example.com",
        RecordType::DNAME => "other.example.com",
        RecordType::PTR => "host.example.com",
        RecordType::NS => "ns1.example.com",
        RecordType::MX => "10 mail.example.com",
        RecordType::TXT => "v=spf1 -all",
        RecordType::SRV => "10 20 5060 sip.example.com",
        RecordType::CAA => "0 issue \"letsencrypt.org\"",
        RecordType::HTTPS => "1 . alpn=h2,h3",
        RecordType::SVCB => "1 svc.example.com. port=8443",
        RecordType::TLSA => "3 1 1 <sha256-hex>",
        RecordType::SSHFP => "4 2 <sha256-hex>",
        RecordType::NAPTR => "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com.",
        RecordType::HINFO => "\"x86_64\" \"Linux\"",
    }
}

/// Split a TXT value into RFC 1035 character-strings of at most 255 bytes.
pub fn txt_chunks(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let mut end = (start + 255).min(bytes.len());
        // Do not split inside a UTF-8 sequence.
        while end < bytes.len() && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
            end -= 1;
        }
        out.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        start = end;
    }
    out
}

/// Build the reverse-lookup owner (`4.3.2.1.in-addr.arpa.` or the ip6.arpa
/// nibble form) for an address.
pub fn reverse_name(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let mut s = String::with_capacity(80);
            for b in v6.octets().iter().rev() {
                s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
                s.push('.');
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push('.');
            }
            s.push_str("ip6.arpa.");
            s
        }
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// One changelog entry; also the event broadcast after every mutation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "offset": 17, "ts": "2026-01-15T10:02:11.482Z", "actor": "root", "actor_ip": "192.0.2.1",
    "action": "create", "entity": "record", "zone": "example.com", "entity_id": 42,
    "payload": { "kind": "record_created", "record": { "id": 42, "zone_id": 1, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "expires_at": null } },
    "txn": "01J0Z8X4K5T3", "command": "create_record"
}))]
pub struct ChangeEvent {
    /// Monotonic, never reused (WAL-style cursor).
    pub offset: i64,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub ts: String,
    pub actor: String,
    pub actor_ip: String,
    /// create | update | delete | import
    pub action: String,
    /// zone | record | member | ...
    pub entity: String,
    pub zone: String,
    #[schema(required = true)]
    pub entity_id: Option<i64>,
    /// The exact committed fact, tagged by `kind`: zone_created, zone_updated,
    /// zone_deleted, record_created, record_updated, record_deleted,
    /// serial_bumped, member_set, member_removed.
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
    /// Shared by every row committed in the same transaction.
    #[serde(default)]
    #[schema(required = true)]
    pub txn: String,
    /// Operation that produced the change (create_record, import, ...).
    #[serde(default)]
    #[schema(required = true)]
    pub command: String,
}

/// Emitted for every DNS query the server answers (streamed over `/ws`).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QueryEvent {
    #[schema(format = DateTime)]
    pub ts: String,
    pub client: String,
    pub proto: &'static str,
    pub name: String,
    pub qtype: String,
    pub rcode: String,
    pub answers: usize,
    /// What was returned, one entry per answer record in presentation form
    /// ("A 192.0.2.10", "CNAME www.example.com."), plus notes for referrals
    /// and truncation. Capped in length; empty for negative answers.
    pub result: Vec<String>,
    /// auth | forward | refused | error
    pub source: &'static str,
    pub duration_us: u64,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub name: String,
    pub ip: String,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_names() {
        assert_eq!(normalize_zone_name("Example.COM.").unwrap(), "example.com");
        assert!(normalize_zone_name("").is_err());
        assert!(normalize_zone_name("bad..name").is_err());
        assert!(normalize_zone_name("-bad.com").is_err());
        assert_eq!(
            normalize_zone_name("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_record_name("münchen", "example.com").unwrap(),
            "xn--mnchen-3ya"
        );
    }

    #[test]
    fn record_names() {
        assert_eq!(normalize_record_name("@", "example.com").unwrap(), "@");
        assert_eq!(normalize_record_name("", "example.com").unwrap(), "@");
        assert_eq!(normalize_record_name("WWW", "example.com").unwrap(), "www");
        assert_eq!(
            normalize_record_name("www.example.com.", "example.com").unwrap(),
            "www"
        );
        assert_eq!(
            normalize_record_name("example.com", "example.com").unwrap(),
            "@"
        );
        assert_eq!(
            normalize_record_name("*.apps", "example.com").unwrap(),
            "*.apps"
        );
        assert_eq!(
            normalize_record_name("_sip._tcp", "example.com").unwrap(),
            "_sip._tcp"
        );
        assert!(normalize_record_name("www.other.com.", "example.com").is_err());
        assert!(normalize_record_name("a.*", "example.com").is_err());
        assert_eq!(normalize_zone_name(".").unwrap(), ".");
        assert_eq!(normalize_record_name("com", ".").unwrap(), "com");
        assert_eq!(owner_fqdn(".", "com"), "com.");
        assert_eq!(owner_fqdn(".", "@"), ".");
        assert_eq!(owner_fqdn("example.com", "www"), "www.example.com.");
    }

    #[test]
    fn values() {
        assert_eq!(
            normalize_value(RecordType::A, " 10.0.0.1 ").unwrap(),
            "10.0.0.1"
        );
        assert!(normalize_value(RecordType::A, "::1").is_err());
        assert_eq!(
            normalize_value(RecordType::AAAA, "2001:DB8::1").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            normalize_value(RecordType::CNAME, "Host.Example.com").unwrap(),
            "host.example.com."
        );
        assert_eq!(
            normalize_value(RecordType::MX, "10 mail.example.com.").unwrap(),
            "10 mail.example.com."
        );
        assert_eq!(
            normalize_value(RecordType::SRV, "1 2 5060 sip.example.com").unwrap(),
            "1 2 5060 sip.example.com."
        );
        assert_eq!(
            normalize_value(RecordType::TXT, "\"v=spf1 -all\"").unwrap(),
            "v=spf1 -all"
        );
        assert!(normalize_value(RecordType::SRV, "1 2 sip.example.com").is_err());
        assert_eq!(
            normalize_value(RecordType::CAA, "0 issue \"letsencrypt.org\"").unwrap(),
            "0 issue \"letsencrypt.org\""
        );
        assert!(normalize_value(RecordType::CAA, "0 bogus").is_err());
        let https =
            normalize_value(RecordType::HTTPS, "1 .  alpn=h2,h3 ipv4hint=10.0.0.1").unwrap();
        assert_eq!(https, "1 . alpn=h2,h3 ipv4hint=10.0.0.1");
        assert_eq!(
            normalize_value(RecordType::HTTPS, &https).unwrap(),
            https,
            "stored form re-parses"
        );
        assert!(normalize_value(RecordType::TLSA, "3 1 1 abcd").is_ok());
        assert!(normalize_value(RecordType::TLSA, "9 1 1 zz").is_err());
        assert!(normalize_value(RecordType::SSHFP, "4 2 0123456789abcdef").is_ok());
        assert!(normalize_value(RecordType::HINFO, "\"x86\" \"Linux\"").is_ok());
        assert_eq!(
            normalize_value(RecordType::DNAME, "Other.Example.com").unwrap(),
            "other.example.com."
        );
        assert!(normalize_value(
            RecordType::NAPTR,
            "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."
        )
        .is_ok());
    }

    #[test]
    fn reverse() {
        assert_eq!(
            reverse_name(&"192.168.1.10".parse().unwrap()),
            "10.1.168.192.in-addr.arpa."
        );
        assert_eq!(
            reverse_name(&"2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn txt_split() {
        let long = "a".repeat(600);
        let chunks = txt_chunks(&long);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 255);
        assert_eq!(chunks[2].len(), 90);
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;

    /// Guards the permission table: changing who may do what must be a
    /// deliberate edit of this test as well.
    #[test]
    fn zone_permission_table() {
        let by_role = |r: ZoneRole| {
            ZonePerm::ALL
                .iter()
                .filter(|p| p.allowed(r))
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            by_role(ZoneRole::Viewer),
            vec![ZonePerm::View, ZonePerm::Export]
        );
        assert_eq!(
            by_role(ZoneRole::Editor),
            vec![ZonePerm::View, ZonePerm::Export, ZonePerm::EditRecords]
        );
        assert_eq!(by_role(ZoneRole::Owner), ZonePerm::ALL.to_vec());
    }

    #[test]
    fn global_permission_table() {
        let user = |admin: bool, root: bool| User {
            id: 1,
            username: "u".into(),
            password_hash: String::new(),
            display_name: String::new(),
            is_admin: admin,
            is_root: root,
            mfa_required: false,
            totp_secret: None,
            totp_enrolled_at: None,
            disabled_at: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let allowed = |u: &User, via: &str| {
            GlobalPerm::ALL
                .iter()
                .filter(|p| p.check(u, via).is_ok())
                .copied()
                .collect::<Vec<_>>()
        };
        use GlobalPerm::*;
        assert_eq!(
            allowed(&user(false, false), "session"),
            vec![
                ManageOwnTokens,
                ChangeOwnPassword,
                ManageOwnMfa,
                ManageOwnSessions
            ]
        );
        assert_eq!(allowed(&user(false, false), "token"), vec![ManageOwnTokens]);
        assert_eq!(
            allowed(&user(true, false), "token"),
            vec![
                CreateZones,
                TransferOwnership,
                ManageUsers,
                ViewAudit,
                ServerAdmin,
                ManageOwnTokens
            ]
        );
        assert!(
            !allowed(&user(true, true), "session").contains(&ChangeOwnPassword),
            "root password lives in the config file"
        );
    }
}
