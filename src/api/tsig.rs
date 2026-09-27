//! TSIG keys (RFC 8945) for authenticated zone transfers and NOTIFY, and a
//! read-only view of the transfer policy from `[transfer]` in the config
//! file. Administrators only (`server_admin`). Every change, and every
//! display of a secret after creation, is written to the audit log in the
//! same transaction; the secret itself is never logged or audited.

use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, Conflict, Forbidden, InvalidRequest, NotFound, Unauthorized};
use super::session::Caller;
use super::types::StatusResponse;
use super::AppState;
use crate::dns::tsig::Algorithm;
use crate::model::GlobalPerm;
use crate::mutation::tsig::{self as keys, NewTsigKey};
use crate::storage::StoredTsigKey;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

type St = State<Arc<AppState>>;

/// HMAC algorithm of a TSIG key. `hmac-sha1` is legacy: only for secondaries
/// that support nothing better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha1,
}

impl From<TsigAlgorithm> for Algorithm {
    fn from(a: TsigAlgorithm) -> Self {
        match a {
            TsigAlgorithm::HmacSha256 => Algorithm::HmacSha256,
            TsigAlgorithm::HmacSha384 => Algorithm::HmacSha384,
            TsigAlgorithm::HmacSha512 => Algorithm::HmacSha512,
            TsigAlgorithm::HmacSha1 => Algorithm::HmacSha1,
        }
    }
}

impl From<Algorithm> for TsigAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
            Algorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
            Algorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
            Algorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
        }
    }
}

/// A TSIG key (without its secret).
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "name": "hn-secondary.", "algorithm": "hmac-sha256", "zones": ["example.com"], "created_by": "root", "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z" }))]
pub struct TsigKeyInfo {
    /// Key name: a DNS name, lowercase with a trailing dot. Secondaries must
    /// use exactly this name.
    pub name: String,
    pub algorithm: TsigAlgorithm,
    /// Zones this key may transfer. Empty: every zone.
    pub zones: Vec<String>,
    pub created_by: String,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TsigKeyList {
    pub keys: Vec<TsigKeyInfo>,
}

/// A new TSIG key. Without `secret` a random one is generated (as long as
/// the hash: 32 bytes for hmac-sha256); with `secret` the base64 value your
/// secondary provider gave you is imported.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TsigKeyInput {
    /// A DNS name such as `hn-secondary.` (a trailing dot is added; stored lowercase).
    pub name: String,
    /// Default `hmac-sha256`.
    #[schema(nullable = false)]
    pub algorithm: Option<TsigAlgorithm>,
    /// Base64 secret to import (16 to 512 bytes). Omit to generate one.
    #[schema(nullable = false)]
    pub secret: Option<String>,
    /// Zones this key may transfer. Omitted or empty: every zone.
    #[schema(nullable = false)]
    pub zones: Option<Vec<String>>,
}

/// The created key and its secret. The secret is shown only here; later use
/// `POST /tsig/keys/{name}/reveal` (audited).
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "name": "hn-secondary.", "algorithm": "hmac-sha256", "zones": ["example.com"], "created_by": "root", "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "secret": "dGhpcyBpcyBub3QgYSByZWFsIHNlY3JldCBhdCBhbGw=" }))]
pub struct TsigKeyCreated {
    pub name: String,
    pub algorithm: TsigAlgorithm,
    pub zones: Vec<String>,
    pub created_by: String,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
    /// Base64 secret, for the secondary's configuration.
    pub secret: String,
}

/// A key's secret.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "name": "hn-secondary.", "algorithm": "hmac-sha256", "secret": "dGhpcyBpcyBub3QgYSByZWFsIHNlY3JldCBhdCBhbGw=" }))]
pub struct TsigKeySecret {
    pub name: String,
    pub algorithm: TsigAlgorithm,
    /// Base64.
    pub secret: String,
}

/// New zone scope of a key.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TsigKeyZones {
    /// Zones this key may transfer. Empty: every zone.
    pub zones: Vec<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct TsigKeyPath {
    /// Key name, with or without the trailing dot (`hn-secondary.`).
    pub name: String,
}

/// One NOTIFY target from the config file.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotifyTargetView {
    /// `ip:port`.
    #[schema(example = "203.0.113.5:53")]
    pub address: String,
    /// Key that signs NOTIFY to this target; `null`: unsigned.
    #[schema(required = true, example = "hn-secondary.")]
    pub key: Option<String>,
    /// False when `key` names a key that does not exist (then no NOTIFY is sent).
    pub key_exists: bool,
}

/// The zone transfer policy in effect (`[transfer]` in the config file;
/// change it there and reload).
#[derive(Debug, Serialize, ToSchema)]
pub struct TransferSettingsView {
    /// Client networks allowed to request transfers. Empty: transfers disabled.
    #[schema(example = json!(["203.0.113.5/32"]))]
    pub allow: Vec<String>,
    /// Transfers also need a valid TSIG signature.
    pub require_tsig: bool,
    /// Default key for NOTIFY (`[transfer].notify_key`); `null`: unsigned.
    #[schema(required = true, example = "hn-secondary.")]
    pub notify_key: Option<String>,
    pub notify: Vec<NotifyTargetView>,
    /// DNS port this server listens on (for secondary configuration snippets).
    pub port: u16,
    /// DNS listen addresses.
    #[schema(value_type = Vec<String>, example = json!(["::"]))]
    pub bind: Vec<std::net::IpAddr>,
    /// Problems with the settings in effect, e.g. a NOTIFY key that does not exist.
    pub warnings: Vec<String>,
}

fn algorithm_of(k: &StoredTsigKey) -> ApiResult<Algorithm> {
    Algorithm::from_name(&k.algorithm).ok_or_else(|| {
        ApiError::internal(format!("TSIG key {} has an unsupported algorithm", k.name))
    })
}

fn info(k: &StoredTsigKey) -> ApiResult<TsigKeyInfo> {
    Ok(TsigKeyInfo {
        name: k.name.clone(),
        algorithm: algorithm_of(k)?.into(),
        zones: k.zones.clone(),
        created_by: k.created_by.clone(),
        created_at: k.created_at.clone(),
        updated_at: k.updated_at.clone(),
    })
}

fn find_key(s: &AppState, raw: &str) -> ApiResult<StoredTsigKey> {
    let name = keys::normalize_key_name(raw)?;
    s.storage
        .get_tsig_key(&name)?
        .ok_or_else(|| ApiError::not_found(format!("TSIG key '{name}' not found")))
}

/// Swap the DNS keyring after a change.
fn apply(s: &AppState) -> ApiResult<()> {
    s.dns.reload_tsig_keys(&s.storage)?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/tsig/keys",
    tag = "TSIG",
    operation_id = "list_tsig_keys",
    summary = "List TSIG keys (admin)",
    description = "Names, algorithms and zone scopes. Secrets are never listed. Needs `server_admin`.",
    responses(
        (status = 200, description = "Keys, sorted by name.", body = TsigKeyList),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn list_tsig_keys(State(s): St, caller: Caller) -> ApiResult<Json<TsigKeyList>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let keys = s
        .storage
        .list_tsig_keys()?
        .iter()
        .map(info)
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(TsigKeyList { keys }))
}

#[utoipa::path(
    post,
    path = "/tsig/keys",
    tag = "TSIG",
    operation_id = "create_tsig_key",
    summary = "Create a TSIG key (admin)",
    description = "Generates a random secret, or imports `secret` (base64) when the secondary provider generated the key. The secret is returned only in this response (later: `POST /tsig/keys/{name}/reveal`, audited). Recorded in the audit log as `tsig.create` without the secret. Takes effect at once. Needs `server_admin`.",
    request_body(content = TsigKeyInput, examples(
        ("generate" = (summary = "Generate a secret, key limited to one zone", value = json!({ "name": "hn-secondary.", "algorithm": "hmac-sha256", "zones": ["example.com"] }))),
        ("import" = (summary = "Import a secret from the secondary provider, all zones", value = json!({ "name": "he-import.", "algorithm": "hmac-sha512", "secret": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+7w==" }))),
    )),
    responses(
        (status = 201, description = "Created. The secret is shown only here.", body = TsigKeyCreated),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn create_tsig_key(
    State(s): St,
    caller: Caller,
    Json(input): Json<TsigKeyInput>,
) -> ApiResult<(StatusCode, Json<TsigKeyCreated>)> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let name = keys::normalize_key_name(&input.name)?;
    let algorithm: Algorithm = input.algorithm.unwrap_or(TsigAlgorithm::HmacSha256).into();
    let zones = keys::normalize_zones(input.zones.as_deref().unwrap_or(&[]))?;
    let (secret, imported) = match input.secret.as_deref().map(str::trim) {
        Some(b64) if !b64.is_empty() => (keys::parse_secret(b64)?, true),
        _ => (keys::generate_secret(algorithm), false),
    };
    let actor = caller.actor();
    let new = NewTsigKey {
        name: name.clone(),
        algorithm,
        secret,
        zones,
        imported,
    };
    let created = s.accounts.run(&actor, "create_tsig_key", |t| {
        t.create_tsig_key(&actor.name, &new)
    })?;
    let Some(k) = created else {
        return Err(ApiError::conflict(format!(
            "TSIG key '{name}' already exists"
        )));
    };
    apply(&s)?;
    tracing::info!(actor = %actor.name, key = %k.name, algorithm = %k.algorithm, imported, "TSIG key created");
    let i = info(&k)?;
    Ok((
        StatusCode::CREATED,
        Json(TsigKeyCreated {
            name: i.name,
            algorithm: i.algorithm,
            zones: i.zones,
            created_by: i.created_by,
            created_at: i.created_at,
            updated_at: i.updated_at,
            secret: keys::encode_secret(&k.secret),
        }),
    ))
}

#[utoipa::path(
    put,
    path = "/tsig/keys/{name}",
    tag = "TSIG",
    operation_id = "update_tsig_key",
    summary = "Change the zones a TSIG key may transfer (admin)",
    description = "Replaces the zone scope; an empty list allows every zone. The secret and algorithm cannot be changed (create a new key and delete the old one). Recorded as `tsig.update`. Needs `server_admin`.",
    params(TsigKeyPath),
    request_body(content = TsigKeyZones, example = json!({ "zones": ["example.com", "example.org"] })),
    responses(
        (status = 200, description = "Updated key.", body = TsigKeyInfo),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn update_tsig_key(
    State(s): St,
    caller: Caller,
    Path(TsigKeyPath { name }): Path<TsigKeyPath>,
    Json(input): Json<TsigKeyZones>,
) -> ApiResult<Json<TsigKeyInfo>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let before = find_key(&s, &name)?;
    let zones = keys::normalize_zones(&input.zones)?;
    let after = s.accounts.run(&caller.actor(), "update_tsig_key", |t| {
        t.update_tsig_key_zones(&before, &zones)
    })?;
    apply(&s)?;
    Ok(Json(info(&after)?))
}

#[utoipa::path(
    delete,
    path = "/tsig/keys/{name}",
    tag = "TSIG",
    operation_id = "delete_tsig_key",
    summary = "Delete a TSIG key (admin)",
    description = "Secondaries using it can no longer transfer; NOTIFY configured with it is no longer sent. Recorded as `tsig.delete`. Needs `server_admin`.",
    params(TsigKeyPath),
    responses(
        (status = 200, description = "Deleted.", body = StatusResponse, example = json!({ "status": "deleted" })),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn delete_tsig_key(
    State(s): St,
    caller: Caller,
    Path(TsigKeyPath { name }): Path<TsigKeyPath>,
) -> ApiResult<Json<StatusResponse>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let k = find_key(&s, &name)?;
    s.accounts.run(&caller.actor(), "delete_tsig_key", |t| {
        t.delete_tsig_key(&k)
    })?;
    apply(&s)?;
    tracing::info!(actor = %caller.user.username, key = %k.name, "TSIG key deleted");
    Ok(Json(StatusResponse::deleted()))
}

#[utoipa::path(
    post,
    path = "/tsig/keys/{name}/reveal",
    tag = "TSIG",
    operation_id = "reveal_tsig_key",
    summary = "Show a TSIG key's secret (admin, audited)",
    description = "Returns the base64 secret, e.g. to configure another secondary. Every call is recorded in the audit log as `tsig.reveal` (without the secret). Needs `server_admin`.",
    params(TsigKeyPath),
    responses(
        (status = 200, description = "The secret.", body = TsigKeySecret),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn reveal_tsig_key(
    State(s): St,
    caller: Caller,
    Path(TsigKeyPath { name }): Path<TsigKeyPath>,
) -> ApiResult<Json<TsigKeySecret>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let k = find_key(&s, &name)?;
    s.accounts.run(&caller.actor(), "reveal_tsig_key", |t| {
        t.reveal_tsig_key(&k)
    })?;
    Ok(Json(TsigKeySecret {
        name: k.name.clone(),
        algorithm: algorithm_of(&k)?.into(),
        secret: keys::encode_secret(&k.secret),
    }))
}

#[utoipa::path(
    get,
    path = "/settings/transfer",
    tag = "TSIG",
    operation_id = "get_transfer_settings",
    summary = "Zone transfer policy in effect (admin)",
    description = "Allowed networks, whether TSIG is required, and NOTIFY targets with their keys, from `[transfer]` in the config file (edit the file and reload to change them). Needs `server_admin`.",
    responses(
        (status = 200, description = "Policy in effect.", body = TransferSettingsView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_transfer_settings(
    State(s): St,
    caller: Caller,
) -> ApiResult<Json<TransferSettingsView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let cfg = s.reloader.current.load();
    let rt = s.dns.runtime.load();
    let ring = s.dns.tsig_keys.load();
    let notify_key = keys::normalize_key_name(&cfg.transfer.notify_key).ok();
    Ok(Json(TransferSettingsView {
        allow: cfg.transfer.allow.clone(),
        require_tsig: rt.require_tsig,
        notify_key,
        notify: rt
            .notify
            .iter()
            .map(|(a, k)| NotifyTargetView {
                address: a.to_string(),
                key_exists: k.as_deref().is_none_or(|k| ring.get(k).is_some()),
                key: k.clone(),
            })
            .collect(),
        port: s.dns.listen.port,
        bind: s.dns.listen.bind.clone(),
        warnings: s.dns.transfer_warnings(),
    }))
}
