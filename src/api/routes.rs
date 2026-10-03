//! REST endpoints. Authorisation is enforced here; the mutator only writes.
//!
//! Every handler carries a `#[utoipa::path]` annotation and is mounted with
//! `routes!(...)` in `super::api_router`, so the route and its OpenAPI
//! operation are declared in one place. Request and response bodies are the
//! typed structs whose `ToSchema` derives produce the documented schemas.

use super::error::{ApiError, ApiResult, ErrorCode};
use super::openapi::{
    BadRequest, Conflict, Forbidden, InvalidRequest, NotFound, ServiceUnavailable, TooManyRequests,
    Unauthorized,
};
use super::session::{public_user, Caller};
use super::types::*;
use super::AppState;
use crate::auth;
use crate::model::*;
use crate::mutation::accounts::{normalize_tag, normalize_tags};
use crate::mutation::{ExportDoc, ImportMode, ImportSummary};
use crate::storage::TokenInfo;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

type St = State<Arc<AppState>>;

// ---- path parameters ---------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct ZonePath {
    /// Zone name, e.g. `example.com`.
    #[param(example = "example.com")]
    pub zone: String,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct ZoneRecordPath {
    /// Zone name, e.g. `example.com`.
    #[param(example = "example.com")]
    pub zone: String,
    /// Record id.
    #[param(example = 1)]
    pub id: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct ZoneMemberPath {
    /// Zone name, e.g. `example.com`.
    #[param(example = "example.com")]
    pub zone: String,
    /// Username of the member.
    #[param(example = "alice")]
    pub username: String,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct UserIdPath {
    /// User id.
    #[param(example = 1)]
    pub id: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct SessionIdPath {
    /// Session id.
    pub id: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct TokenIdPath {
    /// Token id.
    pub id: i64,
}

// ---- server --------------------------------------------------------------------

/// Unauthenticated liveness probe. Uses a cheap `SELECT 1` rather than an
/// integrity scan so load balancers cannot stall the shared DB connection,
/// and never exposes database error text.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Server",
    operation_id = "health",
    summary = "Liveness probe",
    description = "Cheap database ping (no integrity scan). No authentication.",
    responses(
        (status = 200, description = "Database reachable.", body = Health),
        (status = 503, description = "Database unavailable (details are only logged).", body = Health,
            example = json!({ "status": "error", "database": "unavailable" })),
    ),
    security(()),
)]
pub async fn health(State(s): St) -> (StatusCode, Json<Health>) {
    let storage = s.storage.clone();
    let res = tokio::task::spawn_blocking(move || storage.ping()).await;
    match res {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(Health {
                status: OkOrError::Ok,
                version: Some(env!("CARGO_PKG_VERSION")),
                database: None,
            }),
        ),
        Ok(Err(e)) => {
            tracing::error!(error = %format!("{e:#}"), "health check: database ping failed");
            health_unavailable()
        }
        Err(e) => {
            tracing::error!(error = %e, "health check: ping task failed");
            health_unavailable()
        }
    }
}

fn health_unavailable() -> (StatusCode, Json<Health>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Health {
            status: OkOrError::Error,
            version: None,
            database: Some("unavailable"),
        }),
    )
}

/// Admin-only full database integrity check (`PRAGMA quick_check`).
#[utoipa::path(
    get,
    path = "/admin/integrity",
    tag = "Server",
    operation_id = "integrity_check",
    summary = "Full database integrity check (admin)",
    description = "Runs `PRAGMA quick_check` over the whole database; may be slow on large databases. Needs `server_admin`.",
    responses(
        (status = 200, description = "Database is consistent.", body = IntegrityResult, example = json!({ "status": "ok" })),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 500, description = "Check could not run.", body = IntegrityResult),
        (status = 503, description = "Integrity check failed.", body = IntegrityResult),
    ),
)]
pub async fn integrity_check(
    State(s): St,
    caller: Caller,
) -> ApiResult<(StatusCode, Json<IntegrityResult>)> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let storage = s.storage.clone();
    let res = tokio::task::spawn_blocking(move || storage.check()).await;
    let error = |status, detail| {
        (
            status,
            Json(IntegrityResult {
                status: OkOrError::Error,
                detail: Some(detail),
            }),
        )
    };
    Ok(match res {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(IntegrityResult {
                status: OkOrError::Ok,
                detail: None,
            }),
        ),
        Ok(Err(e)) => {
            let detail = format!("{e:#}");
            tracing::error!(actor = %caller.user.username, error = %detail, "database integrity check failed");
            error(StatusCode::SERVICE_UNAVAILABLE, detail)
        }
        Err(e) => {
            tracing::error!(error = %e, "integrity check task failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("integrity check task failed: {e}"),
            )
        }
    })
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Server",
    operation_id = "get_status",
    summary = "Server status, counters and runtime settings",
    responses(
        (status = 200, description = "Status.", body = ServerStatus),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn status(State(s): St, caller: Caller) -> ApiResult<Json<ServerStatus>> {
    use std::sync::atomic::Ordering::Relaxed;
    let (zones, records) = s.storage.counts()?;
    let (oldest, latest) = s.storage.changelog_bounds()?;
    let visible = s.visible_zones(&caller.user)?.len();
    let rt = s.dns.runtime.load();
    let cfg = s.reloader.current.load();
    Ok(Json(ServerStatus {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: s.started.elapsed().as_secs(),
        zones,
        records,
        visible_zones: visible,
        changelog: ChangelogStatus {
            oldest_offset: oldest,
            latest_offset: latest,
            head: s.storage.changelog_head()?,
            retention_days: cfg.changelog.retention_days,
        },
        dns: s.dns.stats.snapshot(),
        pipeline: s.dns.pipeline_status(),
        forward_cache: ForwardCacheStatus {
            entries: s.dns.fwd_cache.len(),
            capacity: rt.forwarding.cache_entries,
            hits: s.dns.fwd_cache.hits.load(Relaxed),
            misses: s.dns.fwd_cache.misses.load(Relaxed),
        },
        rate_limit: RateLimitStatus {
            tracked_addresses: s.limiter.tracked(),
            max_tracked_addresses: s.limiter.max_tracked(),
            max_resolutions_per_second_per_address: s.limiter.limit(),
        },
        listeners: ListenerStatus {
            bind: s.dns.listen.bind.clone(),
            port: s.dns.listen.port,
            udp: s.dns.listen.udp,
            tcp: s.dns.listen.tcp,
            interfaces: s.dns.interfaces.status(),
        },
        forwarding: ForwardingStatus {
            upstreams: rt.forwarding.upstreams.clone(),
            allowed_clients: rt.forwarding.allowed_clients.clone(),
            open_resolver: rt.open_resolver(),
        },
        transfer: TransferStatus {
            allow: cfg.transfer.allow.clone(),
            require_tsig: rt.require_tsig,
            notify: rt.notify.iter().map(|(a, _)| *a).collect(),
        },
        auto_ptr: rt.auto_ptr,
        cookies: rt.cookies,
        nsid: rt.nsid.clone(),
        catalog_built_at: s.cache.load().built_at.clone(),
        replication: s.repl.summary(),
    }))
}

#[utoipa::path(
    post,
    path = "/admin/reload",
    tag = "Server",
    operation_id = "reload_config",
    summary = "Reload the config file (admin)",
    description = "Re-reads the configuration file and applies runtime settings. Needs `server_admin`.",
    responses(
        (status = 200, description = "Reloaded.", body = ReloadResult),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn reload_config(State(s): St, caller: Caller) -> ApiResult<Json<ReloadResult>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let notes = s
        .reloader
        .reload()
        .map_err(|e| ApiError::bad_request(format!("reload failed: {e:#}")))?;
    tracing::info!(actor = %caller.user.username, "configuration reloaded via API");
    Ok(Json(ReloadResult {
        status: OkStatus::Ok,
        notes,
    }))
}

/// Prometheus metrics, mounted at the server root (not under /api).
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "Server",
    operation_id = "get_metrics",
    summary = "Prometheus metrics",
    description = "Mounted at the server root (`/metrics`), not under `/api`. Requires authentication (a bearer API token for scrapers).",
    responses(
        (status = 200, description = "Prometheus text exposition format 0.0.4.", body = String, content_type = "text/plain",
            example = "# HELP rustdns_queries_total DNS queries received\n# TYPE rustdns_queries_total counter\nrustdns_queries_total 0\n"),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn metrics(State(s): St, _caller: Caller) -> ApiResult<Response> {
    use std::sync::atomic::Ordering::Relaxed;
    let d = &s.dns.stats;
    let (zones, records) = s.storage.counts()?;
    let mut out = String::new();
    let mut m = |name: &str, help: &str, v: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"
        ));
    };
    m(
        "rustdns_queries_total",
        "DNS queries received",
        d.queries.load(Relaxed),
    );
    m(
        "rustdns_queries_udp_total",
        "DNS queries over UDP",
        d.udp.load(Relaxed),
    );
    m(
        "rustdns_queries_tcp_total",
        "DNS queries over TCP",
        d.tcp.load(Relaxed),
    );
    m(
        "rustdns_answers_authoritative_total",
        "Authoritative answers",
        d.authoritative.load(Relaxed),
    );
    m(
        "rustdns_answers_forwarded_total",
        "Forwarded answers",
        d.forwarded.load(Relaxed),
    );
    m(
        "rustdns_answers_refused_total",
        "REFUSED answers",
        d.refused.load(Relaxed),
    );
    m(
        "rustdns_answers_nxdomain_total",
        "NXDOMAIN answers",
        d.nxdomain.load(Relaxed),
    );
    m(
        "rustdns_errors_total",
        "Malformed or failed queries",
        d.errors.load(Relaxed),
    );
    m(
        "rustdns_rate_limited_total",
        "Queries dropped by rate limiting",
        d.rate_limited.load(Relaxed),
    );
    m(
        "rustdns_bad_cookie_total",
        "DNS requests with invalid or malformed cookies",
        d.bad_cookie.load(Relaxed),
    );
    m(
        "rustdns_tsig_errors_total",
        "Signed DNS requests rejected (unknown key, bad signature, clock skew, truncated MAC)",
        d.tsig_errors.load(Relaxed),
    );
    m(
        "rustdns_truncated_total",
        "UDP responses truncated",
        d.truncated.load(Relaxed),
    );
    m(
        "rustdns_open_resolver_truncated_total",
        "Forwarded UDP answers truncated by the open resolver payload cap",
        d.open_resolver_truncated.load(Relaxed),
    );
    m(
        "rustdns_open_resolver_any_total",
        "ANY queries not forwarded in open resolver mode (minimal RFC 8482 answer)",
        d.open_resolver_any.load(Relaxed),
    );
    m(
        "rustdns_open_resolver_rate_limited_total",
        "Forwarded queries over the open resolver per-client limit",
        d.open_resolver_rate_limited.load(Relaxed),
    );
    m(
        "rustdns_dnssec_signatures_total",
        "DNSSEC signatures computed (signatures reused from the previous build of a zone are not counted)",
        s.mutator.signer().signatures_made(),
    );
    m(
        "rustdns_forward_overflow_total",
        "Queries not forwarded because [forwarding].max_inflight was reached",
        d.forward_overflow.load(Relaxed),
    );
    out.push_str(&format!(
        "# HELP rustdns_forward_inflight Forwarded queries waiting for an upstream\n# TYPE rustdns_forward_inflight gauge\nrustdns_forward_inflight {}\n",
        d.forward_inflight.load(Relaxed)
    ));
    out.push_str("# HELP rustdns_filter_queries_total Queries per filter of the query pipeline and outcome (answered, dropped, passed to the next filter, panicked)\n# TYPE rustdns_filter_queries_total counter\n");
    for (name, c) in s.dns.filter_stats.snapshot() {
        for (outcome, v) in [
            ("answered", c.answered),
            ("dropped", c.dropped),
            ("passed", c.passed),
            ("panicked", c.panicked),
        ] {
            out.push_str(&format!(
                "rustdns_filter_queries_total{{filter=\"{name}\",outcome=\"{outcome}\"}} {v}\n"
            ));
        }
    }
    out.push_str(&format!(
        "# HELP rustdns_open_resolver 1 while open resolver mode is in effect\n# TYPE rustdns_open_resolver gauge\nrustdns_open_resolver {}\n",
        u8::from(s.dns.runtime.load().open_resolver())
    ));
    out.push_str(&format!("# TYPE rustdns_zones gauge\nrustdns_zones {zones}\n# TYPE rustdns_records gauge\nrustdns_records {records}\n"));
    out.push_str(&format!("# TYPE rustdns_rate_limit_tracked_addresses gauge\nrustdns_rate_limit_tracked_addresses {}\n", s.limiter.tracked()));
    out.push_str(&format!(
        "# TYPE rustdns_uptime_seconds gauge\nrustdns_uptime_seconds {}\n",
        s.started.elapsed().as_secs()
    ));
    out.push_str(&s.repl.metrics_text());
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response())
}

/// This OpenAPI document, generated from the handlers' annotations and the
/// Rust types at startup (see `super::openapi`).
#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "Server",
    operation_id = "get_openapi",
    summary = "This OpenAPI document",
    description = "Generated from the server's route and type definitions, so it always matches the running server.",
    responses(
        (status = 200, description = "OpenAPI 3.1 JSON.", body = Object),
    ),
    security(()),
)]
pub async fn openapi() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        super::openapi::spec_json(),
    )
        .into_response()
}

// ---- account -----------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/me",
    tag = "Account",
    operation_id = "whoami",
    summary = "Current user, client IP and auth method",
    responses(
        (status = 200, description = "Caller, with the number of unused MFA recovery codes (shown on the account page).", body = WhoAmI),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn whoami(State(s): St, caller: Caller) -> ApiResult<Json<WhoAmI>> {
    let recovery_codes_left = if caller.user.mfa_enrolled() {
        s.storage.recovery_codes_left(caller.user.id)?
    } else {
        0
    };
    Ok(Json(WhoAmI {
        user: public_user(&caller.user),
        ip: caller.ip,
        via: caller.via,
        recovery_codes_left,
    }))
}

// ---- zones -----------------------------------------------------------------

fn zone_view(s: &AppState, z: &Zone, role: ZoneRole, record_count: usize) -> ZoneView {
    let owner = z
        .owner_id
        .and_then(|id| s.storage.get_user(id).ok().flatten())
        .map(|u| u.username);
    ZoneView {
        fqdn: z.fqdn(),
        zone: z.clone(),
        owner,
        role,
        record_count,
    }
}

#[utoipa::path(
    get,
    path = "/zones",
    tag = "Zones",
    operation_id = "list_zones",
    summary = "Zones visible to the caller",
    responses(
        (status = 200, description = "Zones with the caller's role.", body = ZoneList),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn list_zones(State(s): St, caller: Caller) -> ApiResult<Json<ZoneList>> {
    let catalog = s.cache.load();
    let zones = s
        .visible_zones(&caller.user)?
        .iter()
        .map(|(z, r)| {
            let count = catalog
                .zones
                .get(&z.fqdn())
                .map(|zd| zd.names.values().map(|v| v.len()).sum())
                .unwrap_or(0);
            zone_view(&s, z, *r, count)
        })
        .collect();
    Ok(Json(ZoneList { zones }))
}

#[utoipa::path(
    post,
    path = "/zones",
    tag = "Zones",
    operation_id = "create_zone",
    summary = "Create a zone",
    description = "Needs `create_zones`. The owner defaults to the caller.",
    request_body(content = ZoneInput, example = json!({ "name": "example.com", "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster@example.com", "default_ttl": 3600 })),
    responses(
        (status = 201, description = "Created.", body = ZoneView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn create_zone(
    State(s): St,
    caller: Caller,
    Json(input): Json<ZoneInput>,
) -> ApiResult<(StatusCode, Json<ZoneView>)> {
    s.require(&caller, GlobalPerm::CreateZones)?;
    let owner_id = match &input.owner {
        Some(name) if !name.is_empty() => Some(
            s.storage
                .get_user_by_name(name)?
                .ok_or_else(|| ApiError::bad_request(format!("owner '{name}' not found")))?
                .id,
        ),
        _ => Some(caller.user.id),
    };
    let z = s
        .mutator
        .create_zone(caller.actor(), input, owner_id)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(zone_view(&s, &z, ZoneRole::Owner, 0)),
    ))
}

#[utoipa::path(
    get,
    path = "/zones/{zone}",
    tag = "Zones",
    operation_id = "get_zone",
    summary = "Zone with the first page of records and its members",
    params(ZonePath),
    responses(
        (status = 200, description = "Zone.", body = ZoneDetail),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn get_zone(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<ZoneDetail>> {
    let (z, role) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    let (records, total) = s.storage.search_records(z.id, "", 0, RECORD_PAGE)?;
    let members = if ZonePerm::ManageAccess.allowed(role) {
        s.storage.list_members(z.id)?
    } else {
        vec![]
    };
    Ok(Json(ZoneDetail {
        zone: zone_view(&s, &z, role, total as usize),
        records,
        record_total: total,
        record_page: RECORD_PAGE,
        members,
    }))
}

#[utoipa::path(
    put,
    path = "/zones/{zone}",
    tag = "Zones",
    operation_id = "update_zone",
    summary = "Update SOA settings / owner",
    description = "Needs the owner role; changing `owner` needs `transfer_ownership` (administrators). Omitted fields are unchanged.",
    params(ZonePath),
    request_body(content = ZoneInput, example = json!({ "refresh": 7200, "retry": 900, "minimum": 300, "default_ttl": 3600 })),
    responses(
        (status = 200, description = "Updated zone.", body = ZoneView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn update_zone(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Json(input): Json<ZoneInput>,
) -> ApiResult<Json<ZoneView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    let new_owner = match &input.owner {
        Some(name) => {
            s.require(&caller, GlobalPerm::TransferOwnership)
                .map_err(|_| {
                    ApiError::forbidden("only administrators can change the zone owner")
                })?;
            if name.is_empty() {
                Some(None)
            } else {
                Some(Some(
                    s.storage
                        .get_user_by_name(name)?
                        .ok_or_else(|| ApiError::bad_request(format!("owner '{name}' not found")))?
                        .id,
                ))
            }
        }
        None => None,
    };
    let z2 = s
        .mutator
        .update_zone(caller.actor(), &z.name, input, new_owner)
        .await?;
    let count = s.storage.list_records(z2.id)?.len();
    Ok(Json(zone_view(&s, &z2, ZoneRole::Owner, count)))
}

#[utoipa::path(
    delete,
    path = "/zones/{zone}",
    tag = "Zones",
    operation_id = "delete_zone",
    summary = "Delete a zone and all its records",
    description = "Needs the owner role.",
    params(ZonePath),
    responses(
        (status = 200, description = "Deleted.", body = ZoneDeleted),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn delete_zone(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<ZoneDeleted>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::DeleteZone)?;
    s.mutator.delete_zone(caller.actor(), &z.name).await?;
    Ok(Json(ZoneDeleted {
        status: DeletedStatus::Deleted,
        zone: z.name,
    }))
}

// ---- records ---------------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecordsQuery {
    /// Search text matched against name, type and value.
    #[param(example = "www")]
    pub q: Option<String>,
    #[param(minimum = 0, default = 0)]
    pub offset: Option<usize>,
    /// Page size (clamped to 1-5000).
    #[param(minimum = 1, maximum = 5000, default = 500)]
    pub limit: Option<usize>,
}

pub const RECORD_PAGE: usize = 500;

#[utoipa::path(
    get,
    path = "/zones/{zone}/records",
    tag = "Records",
    operation_id = "list_records",
    summary = "Search / page records",
    params(ZonePath, RecordsQuery),
    responses(
        (status = 200, description = "A page of records.", body = RecordPage),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn list_records(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Query(q): Query<RecordsQuery>,
) -> ApiResult<Json<RecordPage>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    let limit = q.limit.unwrap_or(RECORD_PAGE).clamp(1, 5000);
    let offset = q.offset.unwrap_or(0);
    let (records, total) =
        s.storage
            .search_records(z.id, q.q.as_deref().unwrap_or("").trim(), offset, limit)?;
    Ok(Json(RecordPage {
        records,
        total,
        offset,
        limit,
    }))
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/records",
    tag = "Records",
    operation_id = "create_record",
    summary = "Create a record",
    description = "Needs the editor role. To register a name that disappears unless renewed, send `expires_in` (seconds) or `expires_at`; posting the identical record again with a new expiry renews it (200).",
    params(ZonePath),
    request_body(content = RecordInput, examples(
        ("A" = (summary = "A record", value = json!({ "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300 }))),
        ("AAAA" = (summary = "AAAA record", value = json!({ "name": "www", "type": "AAAA", "value": "2001:db8::10", "ttl": 300 }))),
        ("MX" = (summary = "MX record (zone default TTL)", value = json!({ "name": "@", "type": "MX", "value": "10 mail.example.com." }))),
        ("TXT" = (summary = "TXT record", value = json!({ "name": "@", "type": "TXT", "value": "v=spf1 -all" }))),
        ("CNAME" = (summary = "CNAME record", value = json!({ "name": "docs", "type": "CNAME", "value": "www.example.com." }))),
        ("expiring" = (summary = "Self-registration: A record that expires in 24 hours unless renewed", value = json!({ "name": "laptop-42", "type": "A", "value": "192.0.2.42", "expires_in": 86400 }))),
    )),
    responses(
        (status = 200, description = "Renewed: an identical record (same name, type and value) already existed and the request carried an expiry, or the existing one had expired. Its expiry was replaced.", body = Record),
        (status = 201, description = "Created.", body = Record),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = Conflict),
    ),
)]
pub async fn create_record(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Json(input): Json<RecordInput>,
) -> ApiResult<(StatusCode, Json<Record>)> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditRecords)?;
    let (record, renewed) = s
        .mutator
        .create_record(caller.actor(), &z.name, input)
        .await?;
    // 201 for a new record; 200 when an identical record was renewed (expiry replaced).
    Ok((
        if renewed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(record),
    ))
}

#[utoipa::path(
    put,
    path = "/zones/{zone}/records/{id}",
    tag = "Records",
    operation_id = "update_record",
    summary = "Update a record",
    description = "Needs the editor role. Send only the fields you change: omitted fields, including `ttl`, keep their current values. Send `\"ttl\": null` to switch to the zone default TTL.",
    params(ZoneRecordPath),
    request_body(content = RecordInput, example = json!({ "value": "192.0.2.20", "ttl": 600 })),
    responses(
        (status = 200, description = "Updated record.", body = Record),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = Conflict),
    ),
)]
pub async fn update_record(
    State(s): St,
    caller: Caller,
    Path(ZoneRecordPath { zone, id }): Path<ZoneRecordPath>,
    Json(input): Json<RecordInput>,
) -> ApiResult<Json<Record>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditRecords)?;
    Ok(Json(
        s.mutator
            .update_record(caller.actor(), &z.name, id, input)
            .await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/zones/{zone}/records/{id}",
    tag = "Records",
    operation_id = "delete_record",
    summary = "Delete a record",
    description = "Needs the editor role.",
    params(ZoneRecordPath),
    responses(
        (status = 200, description = "The deleted record.", body = Record),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn delete_record(
    State(s): St,
    caller: Caller,
    Path(ZoneRecordPath { zone, id }): Path<ZoneRecordPath>,
) -> ApiResult<Json<Record>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditRecords)?;
    Ok(Json(
        s.mutator.delete_record(caller.actor(), &z.name, id).await?,
    ))
}

// ---- members ---------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "role": "editor" }))]
pub struct MemberBody {
    /// `editor` or `viewer`.
    #[schema(value_type = MemberRole)]
    pub role: String,
}

#[utoipa::path(
    put,
    path = "/zones/{zone}/members/{username}",
    tag = "Access",
    operation_id = "set_member",
    summary = "Grant editor or viewer access",
    description = "Needs the owner role on the zone.",
    params(ZoneMemberPath),
    request_body(content = MemberBody, example = json!({ "role": "editor" })),
    responses(
        (status = 200, description = "Members after the change.", body = MemberList),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn set_member(
    State(s): St,
    caller: Caller,
    Path(ZoneMemberPath { zone, username }): Path<ZoneMemberPath>,
    Json(body): Json<MemberBody>,
) -> ApiResult<Json<MemberList>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::ManageAccess)?;
    let role = ZoneRole::parse(&body.role)
        .filter(|r| *r != ZoneRole::Owner)
        .ok_or_else(|| ApiError::bad_request("role must be 'editor' or 'viewer'"))?;
    let u = s
        .storage
        .get_user_by_name(&username.to_ascii_lowercase())?
        .ok_or_else(|| ApiError::not_found(format!("user '{username}' not found")))?;
    if z.owner_id == Some(u.id) {
        return Err(ApiError::bad_request("that user already owns the zone"));
    }
    s.mutator
        .set_member(caller.actor(), &z.name, u.id, role)
        .await?;
    Ok(Json(MemberList {
        members: s.storage.list_members(z.id)?,
    }))
}

#[utoipa::path(
    delete,
    path = "/zones/{zone}/members/{username}",
    tag = "Access",
    operation_id = "remove_member",
    summary = "Revoke access",
    description = "Needs the owner role on the zone.",
    params(ZoneMemberPath),
    responses(
        (status = 200, description = "Members after the change.", body = MemberList),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn remove_member(
    State(s): St,
    caller: Caller,
    Path(ZoneMemberPath { zone, username }): Path<ZoneMemberPath>,
) -> ApiResult<Json<MemberList>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::ManageAccess)?;
    let u = s
        .storage
        .get_user_by_name(&username.to_ascii_lowercase())?
        .ok_or_else(|| ApiError::not_found(format!("user '{username}' not found")))?;
    s.mutator
        .remove_member(caller.actor(), &z.name, u.id)
        .await?;
    Ok(Json(MemberList {
        members: s.storage.list_members(z.id)?,
    }))
}

// ---- export / import ---------------------------------------------------------

/// Export formats. Only `json` (BIND zone-file export was removed).
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)] // documents the accepted values of `ExportQuery::format`
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportQuery {
    /// Only `json` is supported.
    #[param(inline, value_type = ExportFormat, required = false, default = "json")]
    pub format: Option<String>,
}

#[utoipa::path(
    get,
    path = "/export",
    tag = "Import/Export",
    operation_id = "export_all",
    summary = "Export all visible zones as JSON",
    responses(
        (status = 200, description = "Export document (`Content-Disposition: attachment; filename=\"rust-dns-export.json\"`).", body = ExportDoc),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn export_all(State(s): St, caller: Caller) -> ApiResult<Response> {
    let names: Vec<String> = s
        .visible_zones(&caller.user)?
        .into_iter()
        .map(|(z, _)| z.name)
        .collect();
    let doc = s.mutator.export_all(Some(&names))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"rust-dns-export.json\"",
            ),
        ],
        Json(doc),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/export",
    tag = "Import/Export",
    operation_id = "export_zone",
    summary = "Export one zone",
    params(ZonePath, ExportQuery),
    responses(
        (status = 200, description = "Download (`Content-Disposition: attachment`): JSON export document.", body = ExportDoc),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn export_zone(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::Export)?;
    let catalog = s.cache.load();
    let zd = catalog
        .zones
        .get(&z.fqdn())
        .ok_or_else(|| ApiError::not_found("zone not in catalog"))?;
    let base = if z.name == "." {
        "root".to_string()
    } else {
        z.name.clone()
    };
    match q.format.as_deref().unwrap_or("json") {
        "json" => {
            let doc = ExportDoc {
                version: 1,
                exported_at: now_rfc3339(),
                zones: vec![crate::mutation::export_zone(zd)],
            };
            let disp = format!("attachment; filename=\"{base}.json\"");
            Ok((
                [
                    (header::CONTENT_TYPE, "application/json".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                Json(doc),
            )
                .into_response())
        }
        other => Err(ApiError::bad_request(format!(
            "unknown format '{other}'; only json is supported"
        ))),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ImportQuery {
    /// `merge` adds missing zones and records; `replace` replaces the records
    /// of each zone in the document.
    #[param(inline, value_type = ImportMode, required = false, default = "merge")]
    pub mode: Option<ImportMode>,
}

#[utoipa::path(
    post,
    path = "/import",
    tag = "Import/Export",
    operation_id = "import_json",
    summary = "Import a JSON export document",
    description = "Callers with `create_zones` may create zones; others can only import into zones where they are owner.",
    params(ImportQuery),
    request_body(content = ExportDoc, example = json!({
        "version": 1, "exported_at": "2026-01-15T09:30:00.000Z",
        "zones": [{
            "name": "example.com", "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "default_ttl": 3600,
            "records": [
                { "name": "@", "type": "NS", "value": "ns1.example.com." },
                { "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300 },
                { "name": "www", "type": "AAAA", "value": "2001:db8::10" },
                { "name": "@", "type": "MX", "value": "10 mail.example.com." }
            ]
        }]
    })),
    responses(
        (status = 200, description = "Summary.", body = ImportSummary),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn import(
    State(s): St,
    caller: Caller,
    Query(q): Query<ImportQuery>,
    Json(doc): Json<ExportDoc>,
) -> ApiResult<Json<ImportSummary>> {
    let allowed = if s.has(&caller, GlobalPerm::CreateZones) {
        None
    } else {
        Some(
            s.visible_zones(&caller.user)?
                .into_iter()
                .filter(|(_, r)| ZonePerm::Import.allowed(*r))
                .map(|(z, _)| z.name)
                .collect(),
        )
    };
    let summary = s
        .mutator
        .import(
            caller.actor(),
            doc,
            q.mode.unwrap_or(ImportMode::Merge),
            Some(caller.user.id),
            allowed,
        )
        .await?;
    Ok(Json(summary))
}

/// A hosts file to import into one zone.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "text": "192.168.1.10 nas.home.example nas\n192.168.1.11 printer\n", "mode": "merge", "preview": true }))]
pub struct HostsImportInput {
    /// `/etc/hosts` format: `address name [name...]`, `#` comments. Names
    /// without a dot are taken as relative to the zone.
    pub text: String,
    /// `merge` (default) adds missing records; `replace` replaces every
    /// record of the zone with the file's.
    #[serde(default)]
    #[schema(nullable = false)]
    pub mode: Option<ImportMode>,
    /// Only parse and list what would be imported; change nothing.
    #[serde(default)]
    pub preview: bool,
}

/// What a hosts file holds for the zone, and what importing it changed.
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct HostsImportResult {
    pub records: Vec<crate::mutation::HostsRecord>,
    /// Names not imported (outside the zone, loopback, unparseable).
    pub skipped: Vec<crate::mutation::HostsSkip>,
    /// `null` for a preview.
    #[schema(required = true)]
    pub summary: Option<ImportSummary>,
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/import/hosts",
    tag = "Import/Export",
    operation_id = "import_hosts",
    summary = "Import a hosts file into a zone",
    description = "Reads `/etc/hosts`-format text and adds its A / AAAA records to the zone in one transaction (same `merge` / `replace` modes as the JSON import). Names outside the zone are listed and skipped. `preview: true` changes nothing. Needs the zone's import permission (owner).",
    params(ZonePath),
    request_body(content = HostsImportInput, example = json!({ "text": "192.168.1.10 nas.home.example nas\n192.168.1.11 printer\n", "mode": "merge", "preview": false })),
    responses(
        (status = 200, description = "Parsed records, skipped names and (unless a preview) the import summary.", body = HostsImportResult),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = Conflict),
    ),
)]
pub async fn import_hosts(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Json(input): Json<HostsImportInput>,
) -> ApiResult<Json<HostsImportResult>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::Import)?;
    let parsed = crate::mutation::parse_hosts(&input.text, &z.name);
    let summary = if input.preview {
        None
    } else {
        Some(
            s.mutator
                .import_hosts(
                    caller.actor(),
                    &z.name,
                    &parsed.records,
                    input.mode.unwrap_or(ImportMode::Merge),
                    Some(vec![z.name.clone()]),
                )
                .await?,
        )
    };
    Ok(Json(HostsImportResult {
        records: parsed.records,
        skipped: parsed.skipped,
        summary,
    }))
}

// ---- sessions ------------------------------------------------------------------

fn session_entry(sess: &Session, current: Option<i64>) -> SessionEntry {
    SessionEntry {
        id: sess.id,
        ip: sess.ip.clone(),
        user_agent: sess.user_agent.clone(),
        created_at: sess.created_at.clone(),
        last_seen_at: sess.last_seen_at.clone(),
        expires_at: sess.expires_at.clone(),
        current: Some(sess.id) == current,
    }
}

#[utoipa::path(
    get,
    path = "/me/sessions",
    tag = "Account",
    operation_id = "list_my_sessions",
    summary = "List own sessions",
    responses(
        (status = 200, description = "Sessions.", body = SessionList),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn my_sessions(State(s): St, caller: Caller) -> ApiResult<Json<SessionList>> {
    let sessions = s
        .storage
        .list_sessions(caller.user.id)?
        .iter()
        .map(|x| session_entry(x, caller.session_id))
        .collect();
    Ok(Json(SessionList { sessions }))
}

#[utoipa::path(
    delete,
    path = "/me/sessions/{id}",
    tag = "Account",
    operation_id = "revoke_my_session",
    summary = "Revoke one of my sessions",
    description = "Needs an interactive (cookie) session.",
    params(SessionIdPath),
    responses(
        (status = 200, description = "Revoked.", body = StatusResponse, example = json!({ "status": "revoked" })),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn revoke_my_session(
    State(s): St,
    caller: Caller,
    Path(SessionIdPath { id }): Path<SessionIdPath>,
) -> ApiResult<Json<StatusResponse>> {
    s.require(&caller, GlobalPerm::ManageOwnSessions)?;
    let sess = s
        .storage
        .get_session_by_id(id)?
        .filter(|x| x.user_id == caller.user.id)
        .ok_or_else(|| ApiError::not_found("session not found"))?;
    s.accounts.run(&caller.actor(), "revoke_session", |t| {
        t.delete_session(&caller.user, &sess, "revoked by user")
    })?;
    Ok(Json(StatusResponse::revoked()))
}

#[utoipa::path(
    post,
    path = "/me/sessions/revoke-others",
    tag = "Account",
    operation_id = "revoke_other_sessions",
    summary = "Sign out everywhere else",
    description = "Needs an interactive (cookie) session; keeps the current one.",
    responses(
        (status = 200, description = "Other sessions revoked.", body = RevokedCount),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn revoke_other_sessions(State(s): St, caller: Caller) -> ApiResult<Json<RevokedCount>> {
    s.require(&caller, GlobalPerm::ManageOwnSessions)?;
    let keep = caller
        .session_id
        .ok_or_else(|| ApiError::forbidden("requires an interactive session"))?;
    let n = s
        .accounts
        .run(&caller.actor(), "revoke_other_sessions", |t| {
            t.delete_other_sessions(&caller.user, keep)
        })?;
    Ok(Json(RevokedCount {
        status: OkStatus::Ok,
        revoked: n,
    }))
}

#[utoipa::path(
    get,
    path = "/users/{id}/sessions",
    tag = "Users",
    operation_id = "list_user_sessions",
    summary = "List a user's sessions (admin)",
    params(UserIdPath),
    responses(
        (status = 200, description = "Sessions.", body = SessionList),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn user_sessions(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
) -> ApiResult<Json<SessionList>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let sessions = s
        .storage
        .list_sessions(id)?
        .iter()
        .map(|x| session_entry(x, None))
        .collect();
    Ok(Json(SessionList { sessions }))
}

#[utoipa::path(
    post,
    path = "/users/{id}/sessions/revoke",
    tag = "Users",
    operation_id = "revoke_user_sessions",
    summary = "Sign a user out everywhere (admin)",
    params(UserIdPath),
    responses(
        (status = 200, description = "Revoked.", body = RevokedCount),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn revoke_user_sessions(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
) -> ApiResult<Json<RevokedCount>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let target = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    let n = s
        .accounts
        .run(&caller.actor(), "revoke_user_sessions", |t| {
            t.delete_user_sessions(&target, "revoked by administrator")
        })?;
    Ok(Json(RevokedCount {
        status: OkStatus::Ok,
        revoked: n,
    }))
}

/// Regenerate recovery codes; requires a current TOTP code.
#[utoipa::path(
    post,
    path = "/me/mfa/recovery",
    tag = "Account",
    operation_id = "mfa_regenerate_recovery",
    summary = "Regenerate recovery codes",
    description = "Needs a current TOTP code; the previous recovery codes stop working.",
    request_body(content = super::session::CodeBody, example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "New recovery codes (old ones stop working).", body = RecoveryCodes),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 429, response = TooManyRequests),
    ),
)]
pub async fn mfa_recovery_regen(
    State(s): St,
    caller: Caller,
    Json(b): Json<super::session::CodeBody>,
) -> ApiResult<Json<RecoveryCodes>> {
    s.require(&caller, GlobalPerm::ManageOwnMfa)?;
    verify_current_totp(&s, &caller, &b.code)?;
    let (codes, hashes) = super::session::new_recovery_codes();
    s.accounts
        .run(&caller.actor(), "regenerate_recovery_codes", |t| {
            t.set_recovery_codes(&caller.user, &hashes)
        })?;
    Ok(Json(RecoveryCodes {
        recovery_codes: codes,
    }))
}

// ---- effective rights --------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RightsQuery {
    /// `token` shows what the user's API tokens may do.
    #[param(inline, value_type = AuthVia, required = false, default = "session")]
    pub via: Option<String>,
}

/// What a user (or an API token of that user) can actually do, generated from
/// the same permission table the API enforces. Admins may ask about anyone;
/// users about themselves.
#[utoipa::path(
    get,
    path = "/users/{id}/rights",
    tag = "Access",
    operation_id = "get_user_rights",
    summary = "Effective rights of a user or of their API tokens",
    description = "Administrators may read anyone's; users their own.",
    params(UserIdPath, RightsQuery),
    responses(
        (status = 200, description = "Rights generated from the same permission table the API enforces.", body = Rights),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn user_rights(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
    Query(q): Query<RightsQuery>,
) -> ApiResult<Json<Rights>> {
    if id != caller.user.id {
        s.require(&caller, GlobalPerm::ManageUsers)?;
    }
    let user = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    let via = if q.via.as_deref() == Some("token") {
        AuthVia::Token
    } else {
        AuthVia::Session
    };
    let global = GlobalPerm::ALL
        .iter()
        .map(|p| {
            let r = p.check(&user, via.as_str());
            GlobalRight {
                perm: *p,
                label: p.label(),
                allowed: r.is_ok(),
                reason: r.err(),
                requires_admin: p.requires_admin(),
                requires_session: p.requires_session(),
            }
        })
        .collect();
    let zones = s
        .visible_zones(&user)?
        .into_iter()
        .map(|(z, role)| {
            let source = if user.is_admin {
                RoleSource::Administrator
            } else if z.owner_id == Some(user.id) {
                RoleSource::Owner
            } else {
                RoleSource::Member
            };
            let permissions = ZonePerm::ALL
                .into_iter()
                .filter(|p| p.allowed(role))
                .collect();
            ZoneRights {
                zone: z.name,
                role,
                source,
                permissions,
            }
        })
        .collect();
    let legend = ZonePerm::ALL
        .iter()
        .map(|p| ZonePermInfo {
            perm: *p,
            label: p.label(),
            min_role: p.min_role(),
        })
        .collect();
    let mut notes = vec![
        "Rights come from the user's roles and are checked on every request, so changes apply immediately.".to_string(),
    ];
    if user.is_admin {
        notes.push(
            "Administrators act as owner of every zone, including zones created later.".into(),
        );
    }
    if via == AuthVia::Token {
        notes.push("An API token acts as its owner: it has exactly these rights, and stops working if the owner is disabled.".into());
        notes.push("Tokens do not expire and are not revoked by a password change; revoke them on the API tokens page.".into());
    }
    if user.disabled_at.is_some() {
        notes.insert(
            0,
            "This account is disabled: it cannot sign in and its API tokens are rejected.".into(),
        );
    }
    let tokens = s.storage.list_tokens(Some(user.id), None)?.len();
    Ok(Json(Rights {
        user: public_user(&user),
        via,
        active_tokens: tokens,
        global,
        zones,
        zone_permissions: legend,
        notes,
    }))
}

// ---- audit log / changelog ------------------------------------------------------

/// Paging of the change log and the audit log.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// Return entries after this offset/id (oldest first). Omit for the most
    /// recent entries.
    pub after: Option<i64>,
    /// Max entries (1-2000).
    #[param(minimum = 1, maximum = 2000, default = 200)]
    pub limit: Option<usize>,
}

#[utoipa::path(
    get,
    path = "/audit",
    tag = "Change log",
    operation_id = "get_audit",
    summary = "Account and security audit log (admin)",
    description = "Users, MFA, recovery codes, sessions, API tokens, root sync. Each entry was written in the same transaction as the change. Needs `view_audit`.",
    params(LogQuery),
    responses(
        (status = 200, description = "Entries.", body = AuditPage, example = json!({ "entries": [{
            "id": 5, "ts": "2026-01-15T10:02:11.482Z", "txn": "01J0Z8Y1QW2E", "operation": "create_user",
            "actor": "root", "actor_ip": "192.0.2.1", "action": "user_created", "target_user_id": 2,
            "target": "alice", "detail": { "username": "alice", "is_admin": false }
        }] })),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn audit(
    State(s): St,
    caller: Caller,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<AuditPage>> {
    s.require(&caller, GlobalPerm::ViewAudit)?;
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let entries = match q.after {
        Some(a) => s.storage.audit_after(a, limit)?,
        None => s.storage.audit_recent(limit)?,
    };
    Ok(Json(AuditPage { entries }))
}

#[utoipa::path(
    get,
    path = "/changelog",
    tag = "Change log",
    operation_id = "get_changelog",
    summary = "DNS change log (WAL-style offsets)",
    description = "One row per committed fact (zone, record, serial, member); rows from one transaction share `txn` and `command`. Rolled-back operations never appear. Non-admins see only their zones; membership rows and other users' `actor_ip` (empty string) only on zones they own.",
    params(LogQuery),
    responses(
        (status = 200, description = "Entries plus retention bounds.", body = ChangelogPage, example = json!({
            "entries": [{
                "offset": 17, "ts": "2026-01-15T10:02:11.482Z", "actor": "root", "actor_ip": "192.0.2.1",
                "action": "create", "entity": "record", "zone": "example.com", "entity_id": 42,
                "payload": { "kind": "record_created", "record": { "id": 42, "zone_id": 1, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300, "created_at": "2026-01-15T09:30:00.000Z", "updated_at": "2026-01-15T09:30:00.000Z", "expires_at": null } },
                "txn": "01J0Z8X4K5T3", "command": "create_record"
            }],
            "oldest_offset": 1, "latest_offset": 17, "resync_required": false
        })),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn changelog(
    State(s): St,
    caller: Caller,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<ChangelogPage>> {
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let (oldest, latest) = s.storage.changelog_bounds()?;
    let mut entries = match q.after {
        Some(a) => s.storage.changelog_after(a, limit)?,
        None => s.storage.changelog_recent(limit)?,
    };
    if !caller.user.is_admin {
        // Same rules as the websocket feed: own zones only; membership
        // changes and other users' IPs only for zone owners.
        let view = super::ws::View::build(&s, &caller.user)?;
        entries = entries.iter().filter_map(|e| view.change(e)).collect();
    }
    let stale = matches!((q.after, oldest), (Some(a), Some(o)) if a + 1 < o);
    Ok(Json(ChangelogPage {
        entries,
        oldest_offset: oldest,
        latest_offset: latest,
        resync_required: stale,
    }))
}

// ---- users (admin) -------------------------------------------------------------

/// Create: `username` and `password` (min. 8 characters) are required.
/// Update: every field is optional; setting `password` or `disabled: true`
/// signs the user out everywhere. The root account's password is managed in
/// the config file.
#[derive(Deserialize, ToSchema)]
pub struct UserBody {
    /// Create only; ignored on update.
    #[schema(example = "alice")]
    pub username: Option<String>,
    #[schema(format = Password, min_length = 8, example = "correct-horse-battery")]
    pub password: Option<String>,
    #[schema(max_length = 100, example = "Alice Example")]
    pub display_name: Option<String>,
    #[schema(example = false)]
    pub is_admin: Option<bool>,
    /// The user must enroll a TOTP authenticator at the next sign-in.
    #[schema(example = false)]
    pub mfa_required: Option<bool>,
    /// Update only.
    #[schema(example = false)]
    pub disabled: Option<bool>,
}

#[utoipa::path(
    get,
    path = "/users",
    tag = "Users",
    operation_id = "list_users",
    summary = "List users (admin)",
    responses(
        (status = 200, description = "Users.", body = UserList),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn list_users(State(s): St, caller: Caller) -> ApiResult<Json<UserList>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let users = s.storage.list_users()?.iter().map(public_user).collect();
    Ok(Json(UserList { users }))
}

#[utoipa::path(
    post,
    path = "/users",
    tag = "Users",
    operation_id = "create_user",
    summary = "Create a user (admin)",
    request_body(content = UserBody, example = json!({ "username": "alice", "password": "correct-horse-battery", "display_name": "Alice Example", "is_admin": false, "mfa_required": false })),
    responses(
        (status = 201, description = "Created.", body = PublicUser),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
        (status = 503, response = ServiceUnavailable),
    ),
)]
pub async fn create_user(
    State(s): St,
    caller: Caller,
    Json(b): Json<UserBody>,
) -> ApiResult<(StatusCode, Json<PublicUser>)> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let username = normalize_username(b.username.as_deref().unwrap_or(""))?;
    let password = b.password.as_deref().unwrap_or("");
    if password.len() < 8 {
        return Err(ApiError::bad_request(
            "password must be at least 8 characters",
        ));
    }
    if s.storage.get_user_by_name(&username)?.is_some() {
        return Err(ApiError::conflict(format!(
            "user '{username}' already exists"
        )));
    }
    let u = s.accounts.create_user(
        &caller.actor(),
        &NewUser {
            username: username.clone(),
            password_hash: auth::hash_password_async(password).await??,
            display_name: b
                .display_name
                .unwrap_or_default()
                .chars()
                .take(100)
                .collect(),
            is_admin: b.is_admin.unwrap_or(false),
            mfa_required: b.mfa_required.unwrap_or(false),
        },
    )?;
    Ok((StatusCode::CREATED, Json(public_user(&u))))
}

#[utoipa::path(
    put,
    path = "/users/{id}",
    tag = "Users",
    operation_id = "update_user",
    summary = "Update a user (admin)",
    description = "All fields optional. Changing the password or disabling the account signs the user out everywhere.",
    params(UserIdPath),
    request_body(content = UserBody, example = json!({ "display_name": "Alice Example", "mfa_required": true })),
    responses(
        (status = 200, description = "Updated user.", body = PublicUser),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 503, response = ServiceUnavailable),
    ),
)]
pub async fn update_user(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
    Json(b): Json<UserBody>,
) -> ApiResult<Json<PublicUser>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let before = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if before.is_root && !caller.user.is_root {
        return Err(ApiError::forbidden("only root may modify the root account"));
    }
    let mut ch = crate::mutation::accounts::UserChanges::default();
    let mut revoke_sessions = false;
    if let Some(p) = &b.password {
        if before.is_root {
            return Err(ApiError::bad_request(
                "the root password is managed in the configuration file",
            ));
        }
        if p.len() < 8 {
            return Err(ApiError::bad_request(
                "password must be at least 8 characters",
            ));
        }
        ch.password_hash = Some(auth::hash_password_async(p).await??);
        revoke_sessions = true;
    }
    if let Some(d) = b.display_name {
        ch.display_name = Some(d.chars().take(100).collect());
    }
    if let Some(a) = b.is_admin {
        if before.is_root && !a {
            return Err(ApiError::bad_request("root is always an administrator"));
        }
        ch.is_admin = Some(a);
    }
    if let Some(m) = b.mfa_required {
        ch.mfa_required = Some(m);
    }
    if let Some(d) = b.disabled {
        if before.is_root {
            return Err(ApiError::bad_request("root cannot be disabled"));
        }
        ch.disabled = Some(d);
        revoke_sessions |= d;
    }
    // Only the fields in the request are written (see AuditTx::change_user).
    let u = s.accounts.run(&caller.actor(), "update_user", |t| {
        let u = t.change_user(before.id, &ch)?;
        if revoke_sessions {
            t.delete_user_sessions(&u, "password changed or account disabled")?;
        }
        Ok(u)
    })?;
    Ok(Json(public_user(&u)))
}

#[utoipa::path(
    post,
    path = "/users/{id}/reset-mfa",
    tag = "Users",
    operation_id = "reset_user_mfa",
    summary = "Reset a user's MFA and sign them out (admin)",
    params(UserIdPath),
    responses(
        (status = 200, description = "Updated user.", body = PublicUser),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn reset_user_mfa(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
) -> ApiResult<Json<PublicUser>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let before = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if before.is_root && !caller.user.is_root {
        return Err(ApiError::forbidden("only root may modify the root account"));
    }
    let u = s.accounts.run(&caller.actor(), "reset_mfa", |t| {
        let u = t.set_mfa(before.id, None)?;
        t.set_recovery_codes(&u, &[])?;
        t.delete_user_sessions(&u, "MFA reset")?;
        Ok(u)
    })?;
    Ok(Json(public_user(&u)))
}

#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "Users",
    operation_id = "delete_user",
    summary = "Delete a user (admin)",
    params(UserIdPath),
    responses(
        (status = 200, description = "Deleted.", body = StatusResponse, example = json!({ "status": "deleted" })),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn delete_user(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
) -> ApiResult<Json<StatusResponse>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    if id == caller.user.id {
        return Err(ApiError::bad_request("you cannot delete yourself"));
    }
    let u = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if u.is_root {
        return Err(ApiError::bad_request("root cannot be deleted"));
    }
    // First its zones and memberships, as DNS changes (see
    // `Mutator::release_user`); then the account. Two transactions: if the
    // second fails, the user stays without zones, which deleting it meant.
    s.mutator.release_user(caller.actor(), u.id).await?;
    s.accounts
        .run(&caller.actor(), "delete_user", |t| t.delete_user(&u))?;
    Ok(Json(StatusResponse::deleted()))
}

// ---- self service ---------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "current_password": "rootpass123", "new_password": "a-new-long-password" }))]
pub struct PasswordBody {
    #[schema(format = Password, example = "rootpass123")]
    pub current_password: String,
    #[schema(format = Password, min_length = 8, example = "a-new-long-password")]
    pub new_password: String,
}

#[utoipa::path(
    put,
    path = "/me/password",
    tag = "Account",
    operation_id = "change_password",
    summary = "Change own password",
    description = "Needs an interactive (cookie) session. Not available to root, whose password is set in the configuration file. Every other session of the user is signed out; API tokens keep working (revoke them separately).",
    request_body(content = PasswordBody, example = json!({ "current_password": "rootpass123", "new_password": "a-new-long-password" })),
    responses(
        (status = 200, description = "Changed.", body = StatusResponse, example = json!({ "status": "ok" })),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 429, response = TooManyRequests),
        (status = 503, response = ServiceUnavailable),
    ),
)]
pub async fn change_password(
    State(s): St,
    caller: Caller,
    Json(b): Json<PasswordBody>,
) -> ApiResult<Json<StatusResponse>> {
    s.require(&caller, GlobalPerm::ChangeOwnPassword)?;
    super::session::account_wait(&s, &caller.user.username, caller.ip)?;
    if !auth::verify_password_async(&b.current_password, &caller.user.password_hash).await? {
        return Err(wrong_secret(&s, &caller, "current password is incorrect"));
    }
    if b.new_password.len() < 8 {
        return Err(ApiError::bad_request(
            "password must be at least 8 characters",
        ));
    }
    let hash = auth::hash_password_async(&b.new_password).await??;
    // Only the password column is written, and every other session of the
    // user is signed out in the same transaction (this one stays). API
    // tokens are not affected.
    let keep = caller.session_id;
    s.accounts.run(&caller.actor(), "change_password", |t| {
        let u = t.set_password(caller.user.id, &hash)?;
        if let Some(keep) = keep {
            t.delete_other_sessions(&u, keep)?;
        }
        Ok(())
    })?;
    Ok(Json(StatusResponse::ok()))
}

/// Voluntary enrollment: hand out a secret and keep it on the session until confirmed.
#[utoipa::path(
    post,
    path = "/me/mfa/start",
    tag = "Account",
    operation_id = "mfa_start",
    summary = "Start voluntary MFA enrollment",
    description = "Needs an interactive (cookie) session. Replacing an already enrolled authenticator also needs the current TOTP code or the password.",
    request_body(content = Option<ReauthBody>, description = "Only when MFA is already enrolled (replacing the authenticator): the current TOTP `code` or the account `password`. Otherwise send no body or `{}`.", example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "Secret, otpauth URI and QR SVG; confirm with /me/mfa/confirm.", body = EnrollPayload),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 429, response = TooManyRequests),
        (status = 503, response = ServiceUnavailable),
    ),
)]
pub async fn mfa_start(
    State(s): St,
    caller: Caller,
    body: axum::body::Bytes,
) -> ApiResult<Json<EnrollPayload>> {
    s.require(&caller, GlobalPerm::ManageOwnMfa)?;
    let sid = caller
        .session_id
        .ok_or_else(|| ApiError::forbidden("MFA enrollment requires an interactive session"))?;
    if caller.user.mfa_enrolled() {
        // Replacing an enrolled authenticator needs the current factor, so a
        // stolen session cookie cannot swap it for the attacker's.
        let b: ReauthBody = if body.iter().all(|c| c.is_ascii_whitespace()) {
            ReauthBody::default()
        } else {
            serde_json::from_slice(&body).map_err(|e| {
                ApiError::bad_request(format!("invalid body: {e}"))
                    .with_code(ErrorCode::InvalidRequest)
            })?
        };
        match (b.code.as_deref(), b.password.as_deref()) {
            (Some(code), _) => verify_current_totp(&s, &caller, code)?,
            (None, Some(pw)) => {
                super::session::account_wait(&s, &caller.user.username, caller.ip)?;
                if !auth::verify_password_async(pw, &caller.user.password_hash).await? {
                    return Err(wrong_secret(&s, &caller, "password is incorrect"));
                }
            }
            (None, None) => {
                return Err(ApiError::unauthorized(
                    "MFA is already enrolled: send the current TOTP `code` or your `password` to replace it",
                ))
            }
        }
    }
    let secret = auth::totp_new_secret();
    let sess = s
        .storage
        .get_session_by_id(sid)?
        .ok_or_else(|| ApiError::unauthorized("session gone"))?;
    // Keep the session active; only stash the secret until it is confirmed.
    s.accounts.run(&caller.actor(), "mfa_start", |t| {
        t.set_session_state(&caller.user, &sess, "active", Some(&secret))
    })?;
    Ok(Json(super::session::enroll_payload(&caller.user, &secret)))
}

#[utoipa::path(
    post,
    path = "/me/mfa/confirm",
    tag = "Account",
    operation_id = "mfa_confirm",
    summary = "Confirm MFA enrollment",
    description = "Confirms the secret from /me/mfa/start with a TOTP code.",
    request_body(content = super::session::CodeBody, example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "Enrolled; recovery codes shown once.", body = UserWithRecoveryCodes),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 429, response = TooManyRequests),
    ),
)]
pub async fn mfa_confirm(
    State(s): St,
    caller: Caller,
    Json(b): Json<super::session::CodeBody>,
) -> ApiResult<Json<UserWithRecoveryCodes>> {
    s.require(&caller, GlobalPerm::ManageOwnMfa)?;
    let sid = caller
        .session_id
        .ok_or_else(|| ApiError::forbidden("MFA enrollment requires an interactive session"))?;
    let sess = s
        .storage
        .get_session_by_id(sid)?
        .ok_or_else(|| ApiError::unauthorized("session gone"))?;
    let secret = sess
        .pending_secret
        .clone()
        .ok_or_else(|| ApiError::bad_request("start enrollment first"))?;
    super::session::account_wait(&s, &caller.user.username, caller.ip)?;
    let Some(step) = auth::totp_match(&secret, &b.code, &s.clock) else {
        return Err(super::session::code_failed(
            &s,
            &caller.user,
            &sess,
            caller.ip,
        ));
    };
    s.guard.code_success(sess.id);
    let (codes, hashes) = super::session::new_recovery_codes();
    let u = s.accounts.run(&caller.actor(), "mfa_enroll", |t| {
        let u = t.set_mfa(caller.user.id, Some(&secret))?;
        t.accept_totp_step(&u, step)?;
        t.set_recovery_codes(&u, &hashes)?;
        t.set_session_state(&u, &sess, "active", None)?;
        Ok(u)
    })?;
    Ok(Json(UserWithRecoveryCodes {
        user: public_user(&u),
        recovery_codes: codes,
    }))
}

#[utoipa::path(
    post,
    path = "/me/mfa/disable",
    tag = "Account",
    operation_id = "mfa_disable",
    summary = "Disable MFA",
    description = "Not allowed when MFA is required for the account. Needs a current TOTP code.",
    request_body(content = super::session::CodeBody, example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "MFA disabled.", body = PublicUser),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 429, response = TooManyRequests),
    ),
)]
pub async fn mfa_disable(
    State(s): St,
    caller: Caller,
    Json(b): Json<super::session::CodeBody>,
) -> ApiResult<Json<PublicUser>> {
    s.require(&caller, GlobalPerm::ManageOwnMfa)?;
    if caller.user.mfa_required {
        return Err(ApiError::forbidden("MFA is required for this account"));
    }
    verify_current_totp(&s, &caller, &b.code)?;
    let u = s.accounts.run(&caller.actor(), "mfa_disable", |t| {
        let u = t.set_mfa(caller.user.id, None)?;
        t.set_recovery_codes(&u, &[])?;
        Ok(u)
    })?;
    Ok(Json(public_user(&u)))
}

/// Body of `POST /me/mfa/start` when replacing an enrolled authenticator.
#[derive(Deserialize, ToSchema, Default)]
#[schema(example = json!({ "code": "123456" }))]
pub struct ReauthBody {
    /// A current TOTP code of the enrolled authenticator.
    #[schema(example = "123456")]
    pub code: Option<String>,
    /// Or the account password.
    #[schema(format = Password)]
    pub password: Option<String>,
}

/// The caller's session, needed to count wrong codes against it.
fn caller_session(s: &AppState, caller: &Caller) -> ApiResult<Session> {
    let sid = caller
        .session_id
        .ok_or_else(|| ApiError::forbidden("needs an interactive session"))?;
    s.storage
        .get_session_by_id(sid)?
        .ok_or_else(|| ApiError::unauthorized("session gone").with_code(ErrorCode::LoginRequired))
}

/// A wrong password or code from a signed-in session: account back-off
/// plus the session's attempt limit (the session is deleted after 5).
fn wrong_secret(s: &AppState, caller: &Caller, msg: &str) -> ApiError {
    match caller_session(s, caller) {
        Ok(sess) => match super::session::code_failed(s, &caller.user, &sess, caller.ip) {
            e if e.code == Some(ErrorCode::LoginRequired) => e,
            _ => ApiError::unauthorized(msg),
        },
        Err(e) => e,
    }
}

/// Check a current TOTP code of the caller's enrolled authenticator:
/// back-off first, replay-protected (the step is recorded), and wrong codes
/// count toward the session's attempt limit.
fn verify_current_totp(s: &AppState, caller: &Caller, code: &str) -> ApiResult<()> {
    let secret = caller
        .user
        .totp_secret
        .clone()
        .ok_or_else(|| ApiError::bad_request("MFA is not enrolled"))?;
    super::session::account_wait(s, &caller.user.username, caller.ip)?;
    let accepted = match auth::totp_match(&secret, code, &s.clock) {
        Some(step) => s.accounts.run(&caller.actor(), "totp_check", |t| {
            t.accept_totp_step(&caller.user, step)
        })?,
        None => false,
    };
    if !accepted {
        return Err(wrong_secret(s, caller, "invalid code"));
    }
    if let Some(sid) = caller.session_id {
        s.guard.code_success(sid);
    }
    Ok(())
}

// ---- API tokens ------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "name": "ci-deploy", "tags": ["ci", "deploy"] }))]
pub struct TokenBody {
    #[schema(max_length = 100, example = "ci-deploy")]
    pub name: String,
    /// Optional labels: at most 16, each 1-256 characters of `[A-Za-z0-9_-]`
    /// after trimming (case is kept); duplicates are dropped.
    #[serde(default)]
    #[schema(max_items = 16, example = json!(["ci", "deploy"]))]
    pub tags: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "tags": ["ci", "deploy", "prod"] }))]
pub struct TokenUpdateBody {
    /// The complete new tag list (replaces the old one; `[]` clears it).
    /// At most 16, each 1-256 characters of `[A-Za-z0-9_-]` after trimming
    /// (case is kept); duplicates are dropped.
    #[schema(max_items = 16, example = json!(["ci", "deploy", "prod"]))]
    pub tags: Vec<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TokenQuery {
    /// Administrators: list every user's tokens.
    #[param(default = false)]
    pub all: Option<bool>,
    /// Only tokens carrying exactly this tag (case-sensitive, surrounding spaces ignored).
    #[param(example = "ci")]
    pub tag: Option<String>,
}

/// Load a token the caller may manage: their own, or anyone's with
/// `manage_users`. Revoked tokens count as not found when `active_only`.
fn managed_token(
    s: &AppState,
    caller: &Caller,
    id: i64,
    active_only: bool,
) -> ApiResult<(TokenInfo, User)> {
    let t = s
        .storage
        .get_token(id)?
        .filter(|t| !active_only || t.revoked_at.is_none())
        .ok_or_else(|| ApiError::not_found("token not found"))?;
    if t.user_id != caller.user.id && !s.has(caller, GlobalPerm::ManageUsers) {
        return Err(ApiError::forbidden("not your token"));
    }
    let owner = s
        .storage
        .get_user(t.user_id)?
        .ok_or_else(|| ApiError::not_found("token owner not found"))?;
    Ok((t, owner))
}

#[utoipa::path(
    get,
    path = "/tokens",
    tag = "Tokens",
    operation_id = "list_tokens",
    summary = "List API tokens",
    description = "Active tokens with their tags, last use time and last client IP. Filter with `tag` (exact, case-sensitive match).",
    params(TokenQuery),
    responses(
        (status = 200, description = "Tokens (own, or everyone's with `all=true` for admins).", body = TokenList),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn list_tokens(
    State(s): St,
    caller: Caller,
    Query(q): Query<TokenQuery>,
) -> ApiResult<Json<TokenList>> {
    s.require(&caller, GlobalPerm::ManageOwnTokens)?;
    let scope = if q.all.unwrap_or(false) && s.has(&caller, GlobalPerm::ManageUsers) {
        None
    } else {
        Some(caller.user.id)
    };
    let tag = q.tag.as_deref().map(normalize_tag).transpose()?;
    let tokens = s.storage.list_tokens(scope, tag.as_deref())?;
    let users = s.storage.list_users()?;
    let tokens = tokens
        .into_iter()
        .map(|info: TokenInfo| TokenListEntry {
            username: users
                .iter()
                .find(|u| u.id == info.user_id)
                .map(|u| u.username.clone()),
            info,
        })
        .collect();
    Ok(Json(TokenList { tokens }))
}

#[utoipa::path(
    post,
    path = "/tokens",
    tag = "Tokens",
    operation_id = "create_token",
    summary = "Create an API token",
    description = "The token acts with exactly the caller's rights. Tokens do not expire; revoke them when no longer needed. Optional `tags` label the token (change them later with `PUT /tokens/{id}`).",
    request_body(content = TokenBody, example = json!({ "name": "ci-deploy", "tags": ["ci", "deploy"] })),
    responses(
        (status = 201, description = "Created. The plaintext token is returned only once.", body = TokenCreated),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn create_token(
    State(s): St,
    caller: Caller,
    Json(b): Json<TokenBody>,
) -> ApiResult<(StatusCode, Json<TokenCreated>)> {
    s.require(&caller, GlobalPerm::ManageOwnTokens)?;
    let name: String = b.name.trim().chars().take(100).collect();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    let tags = normalize_tags(&b.tags)?;
    let token = format!("rdns_{}", auth::random_token(32));
    let info = s.accounts.create_token(
        &caller.actor(),
        &caller.user,
        &name,
        &auth::sha256_hex(&token),
        &tags,
    )?;
    Ok((StatusCode::CREATED, Json(TokenCreated { token, info })))
}

#[utoipa::path(
    delete,
    path = "/tokens/{id}",
    tag = "Tokens",
    operation_id = "revoke_token",
    summary = "Revoke an API token",
    description = "Own tokens; administrators may revoke anyone's.",
    params(TokenIdPath),
    responses(
        (status = 200, description = "Revoked.", body = StatusResponse, example = json!({ "status": "revoked" })),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn revoke_token(
    State(s): St,
    caller: Caller,
    Path(TokenIdPath { id }): Path<TokenIdPath>,
) -> ApiResult<Json<StatusResponse>> {
    s.require(&caller, GlobalPerm::ManageOwnTokens)?;
    let (t, owner) = managed_token(&s, &caller, id, false)?;
    s.accounts.run(&caller.actor(), "revoke_token", |tx| {
        tx.revoke_token(&owner, &t)
    })?;
    Ok(Json(StatusResponse::revoked()))
}

#[utoipa::path(
    put,
    path = "/tokens/{id}",
    tag = "Tokens",
    operation_id = "update_token",
    summary = "Update an API token's tags",
    description = "Replaces the tag list. Own tokens; administrators (`manage_users`) may update anyone's. Revoked tokens cannot be changed (404). A change is recorded in the audit log as `token.update` with the tags before and after.",
    params(TokenIdPath),
    request_body(content = TokenUpdateBody, example = json!({ "tags": ["ci", "deploy", "prod"] })),
    responses(
        (status = 200, description = "Updated token.", body = TokenInfo),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn update_token(
    State(s): St,
    caller: Caller,
    Path(TokenIdPath { id }): Path<TokenIdPath>,
    Json(b): Json<TokenUpdateBody>,
) -> ApiResult<Json<TokenInfo>> {
    s.require(&caller, GlobalPerm::ManageOwnTokens)?;
    let (t, owner) = managed_token(&s, &caller, id, true)?;
    let tags = normalize_tags(&b.tags)?;
    let info = s.accounts.run(&caller.actor(), "update_token", |tx| {
        tx.update_token_tags(&owner, &t, &tags)
    })?;
    Ok(Json(info))
}
