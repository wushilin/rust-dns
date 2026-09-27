//! Server settings managed from the console/API. Today: forwarding (upstream
//! resolvers, allowed clients, timeout). Stored in SQLite as an override of the
//! config file, applied immediately, audited in the same transaction.

use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, Forbidden, Unauthorized};
use super::session::Caller;
use super::AppState;
use crate::config::ForwardingConfig;
use crate::dns::Proto;
use crate::model::GlobalPerm;
use crate::mutation::settings;
use axum::extract::State;
use axum::Json;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// Where the forwarding settings in effect come from.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SettingSource {
    /// `[forwarding]` in the config file.
    Config,
    /// Saved from the console/API; overrides the config file until reset.
    Console,
}

/// Forwarding values from the config file (shown next to an override).
#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardingFileValues {
    pub upstreams: Vec<String>,
    pub allowed_clients: Vec<String>,
    pub timeout_ms: u64,
    pub cache_max_ttl: u32,
    pub cache_negative_max_ttl: u32,
}

/// Forwarding cache size and counters since start.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "enabled": true, "entries": 42, "capacity": 10000, "hits": 900, "misses": 100, "hit_rate": 0.9 }))]
pub struct ForwardCacheInfo {
    /// False when `[forwarding].cache_entries = 0`.
    pub enabled: bool,
    pub entries: usize,
    /// `[forwarding].cache_entries` (fixed at startup).
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
    /// hits / (hits + misses); 0 when there were no lookups.
    pub hit_rate: f64,
}

/// Result of a cache flush.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "status": "ok", "dropped": 42 }))]
pub struct CacheFlushResult {
    pub status: crate::api::types::OkStatus,
    /// Entries removed.
    pub dropped: usize,
}

/// Forwarding settings in effect.
#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardingView {
    /// Upstream resolvers in effect, `ip:port`, tried in order. Empty: foreign names are refused.
    #[schema(example = json!(["192.168.44.99:53", "8.8.8.8:53"]))]
    pub upstreams: Vec<String>,
    /// Client networks allowed to use forwarding.
    #[schema(example = json!(["192.168.0.0/16"]))]
    pub allowed_clients: Vec<String>,
    /// Timeout per upstream, milliseconds.
    pub timeout_ms: u64,
    pub source: SettingSource,
    /// Who saved the override (`null` when the config file applies).
    #[schema(required = true)]
    pub updated_by: Option<String>,
    /// When the override was saved (`null` when the config file applies).
    #[schema(required = true, format = DateTime)]
    pub updated_at: Option<String>,
    /// Longest a positive answer is cached, seconds (in effect).
    #[schema(example = 86400)]
    pub cache_max_ttl: u32,
    /// Longest a negative answer is cached, seconds (in effect).
    #[schema(example = 3600)]
    pub cache_negative_max_ttl: u32,
    /// The config file's values, for comparison and reset.
    pub config: ForwardingFileValues,
    pub cache: ForwardCacheInfo,
}

/// New forwarding settings. Upstreams are IP addresses with an optional port
/// (53 when omitted): `1.1.1.1`, `8.8.8.8:53`, `2606:4700:4700::1111`,
/// `[2001:4860:4860::8888]:53`. Host names are not accepted.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "upstreams": ["1.1.1.1", "[2606:4700:4700::1111]:53"], "allowed_clients": ["192.168.0.0/16", "fd00::/8"], "timeout_ms": 2000 }))]
pub struct ForwardingInput {
    /// At most 8, tried in order. An empty list turns forwarding off.
    pub upstreams: Vec<String>,
    /// CIDR networks or single addresses. Anything that would make this an
    /// open resolver is refused: an entry shorter than /8 (IPv4) or /16
    /// (global IPv6), or entries covering over 1/16 of IPv4 together.
    pub allowed_clients: Vec<String>,
    /// 100 to 30000.
    pub timeout_ms: u64,
    /// Cap on how long positive answers are cached, 1 to 604800 seconds.
    /// Omitted: the config file's `cache_max_ttl`.
    #[serde(default)]
    #[schema(nullable = false, example = 86400)]
    pub cache_max_ttl: Option<u32>,
    /// Cap on how long negative answers are cached, 1 to 604800 seconds and
    /// not above the positive cap. Omitted: the config file's value.
    #[serde(default)]
    #[schema(nullable = false, example = 3600)]
    pub cache_negative_max_ttl: Option<u32>,
}

/// Upstreams to probe before saving.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "upstreams": ["1.1.1.1", "8.8.8.8:53"], "timeout_ms": 1500 }))]
pub struct UpstreamTestInput {
    pub upstreams: Vec<String>,
    /// Per-upstream timeout, milliseconds (default 2000, 100 to 30000).
    #[schema(nullable = false)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamTestResult {
    /// As entered.
    pub upstream: String,
    /// True when the upstream answered a recursive query for `. NS`.
    pub ok: bool,
    /// Round-trip time in milliseconds when it answered.
    #[schema(required = true)]
    pub ms: Option<u64>,
    /// Response code when it answered, e.g. "No Error".
    #[schema(required = true)]
    pub rcode: Option<String>,
    /// Why it failed.
    #[schema(required = true)]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamTestReport {
    pub results: Vec<UpstreamTestResult>,
}

fn view(s: &AppState) -> ApiResult<ForwardingView> {
    let rt = s.dns.runtime.load();
    let cfg = s.reloader.current.load();
    let stored = settings::load_forwarding(&s.storage)?;
    let (source, updated_by, updated_at) = match &stored {
        Some((_, by, at)) => (SettingSource::Console, Some(by.clone()), Some(at.clone())),
        None => (SettingSource::Config, None, None),
    };
    Ok(ForwardingView {
        upstreams: rt
            .forwarding
            .upstreams
            .iter()
            .map(|u| u.to_string())
            .collect(),
        allowed_clients: rt.forwarding.allowed_clients.clone(),
        timeout_ms: rt.forwarding.timeout_ms,
        cache_max_ttl: rt.forwarding.cache_max_ttl,
        cache_negative_max_ttl: rt.forwarding.cache_negative_max_ttl,
        cache: cache_info(s),
        source,
        updated_by,
        updated_at,
        config: ForwardingFileValues {
            upstreams: cfg
                .forwarding
                .upstreams
                .iter()
                .map(|u| u.to_string())
                .collect(),
            allowed_clients: cfg.forwarding.allowed_clients.clone(),
            timeout_ms: cfg.forwarding.timeout_ms,
            cache_max_ttl: cfg.forwarding.cache_max_ttl,
            cache_negative_max_ttl: cfg.forwarding.cache_negative_max_ttl,
        },
    })
}

fn cache_info(s: &AppState) -> ForwardCacheInfo {
    let st = s.dns.fwd_cache.stats();
    let lookups = st.hits + st.misses;
    ForwardCacheInfo {
        enabled: s.dns.runtime.load().forwarding.cache_entries > 0,
        entries: st.entries,
        capacity: st.capacity,
        hits: st.hits,
        misses: st.misses,
        hit_rate: if lookups == 0 {
            0.0
        } else {
            st.hits as f64 / lookups as f64
        },
    }
}

#[utoipa::path(
    post,
    path = "/settings/forwarding/cache/flush",
    tag = "Server",
    operation_id = "flush_forward_cache",
    summary = "Empty the forwarding cache (admin)",
    description = "Drops every cached forwarded answer; the next queries go to the upstreams. Audited as `settings.forwarding.cache_flush`. Needs `server_admin`.",
    responses(
        (status = 200, description = "Flushed.", body = CacheFlushResult),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn flush_forward_cache(
    State(s): St,
    caller: Caller,
) -> ApiResult<Json<CacheFlushResult>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let actor = caller.actor();
    let dropped = s.accounts.run(&actor, "flush_forward_cache", |t| {
        let n = s.dns.fwd_cache.clear();
        t.note_cache_flush(n);
        Ok(n)
    })?;
    tracing::info!(actor = %actor.name, dropped, "forwarding cache flushed");
    Ok(Json(CacheFlushResult {
        status: crate::api::types::OkStatus::Ok,
        dropped,
    }))
}

#[utoipa::path(
    get,
    path = "/settings/forwarding",
    tag = "Server",
    operation_id = "get_forwarding_settings",
    summary = "Forwarding settings in effect (admin)",
    description = "Upstream resolvers, allowed client networks and timeout currently in effect, whether they come from the config file or were saved from the console, and the config file's own values. Needs `server_admin`.",
    responses(
        (status = 200, description = "Settings in effect.", body = ForwardingView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_forwarding(State(s): St, caller: Caller) -> ApiResult<Json<ForwardingView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    Ok(Json(view(&s)?))
}

#[utoipa::path(
    put,
    path = "/settings/forwarding",
    tag = "Server",
    operation_id = "update_forwarding_settings",
    summary = "Change upstream resolvers (admin)",
    description = "Saves forwarding settings that override `[forwarding]` in the config file and applies them at once (no restart). The change and its audit entry are one transaction. Needs `server_admin`.",
    request_body(content = ForwardingInput, example = json!({ "upstreams": ["1.1.1.1", "[2606:4700:4700::1111]:53"], "allowed_clients": ["192.168.0.0/16", "fd00::/8"], "timeout_ms": 2000, "cache_max_ttl": 86400, "cache_negative_max_ttl": 3600 })),
    responses(
        (status = 200, description = "Saved and applied.", body = ForwardingView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn update_forwarding(
    State(s): St,
    caller: Caller,
    Json(input): Json<ForwardingInput>,
) -> ApiResult<Json<ForwardingView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let file = s.reloader.current.load().forwarding.clone();
    let next = settings::validate(
        &input.upstreams,
        &input.allowed_clients,
        input.timeout_ms,
        (input.cache_max_ttl, input.cache_negative_max_ttl),
        &file,
    )
    .map_err(|errs| ApiError::bad_request(errs.join("; ")))?;
    let before = settings::load_forwarding(&s.storage)?.map(|(f, _, _)| f);
    let actor = caller.actor();
    s.accounts.run(&actor, "update_forwarding", |t| {
        t.set_forwarding(&actor.name, before.as_ref(), &next)
    })?;
    s.dns
        .set_forwarding_override(Some(next.clone()), &s.reloader.current.load());
    tracing::info!(actor = %actor.name, upstreams = ?next.upstreams, "forwarding settings updated from the console");
    Ok(Json(view(&s)?))
}

#[utoipa::path(
    delete,
    path = "/settings/forwarding",
    tag = "Server",
    operation_id = "reset_forwarding_settings",
    summary = "Use the config file's forwarding settings again (admin)",
    description = "Removes the console override; `[forwarding]` from the config file applies at once. No-op when there is no override. Needs `server_admin`.",
    responses(
        (status = 200, description = "Config file values in effect.", body = ForwardingView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn reset_forwarding(State(s): St, caller: Caller) -> ApiResult<Json<ForwardingView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    if let Some((before, _, _)) = settings::load_forwarding(&s.storage)? {
        let actor = caller.actor();
        s.accounts
            .run(&actor, "reset_forwarding", |t| t.clear_forwarding(&before))?;
        tracing::info!(actor = %actor.name, "forwarding settings reset to the config file");
    }
    s.dns
        .set_forwarding_override(None, &s.reloader.current.load());
    Ok(Json(view(&s)?))
}

#[utoipa::path(
    post,
    path = "/settings/forwarding/test",
    tag = "Server",
    operation_id = "test_upstreams",
    summary = "Probe upstream resolvers (admin)",
    description = "Sends a recursive `. NS` query to each upstream over UDP and reports whether and how fast it answered. Nothing is saved. Needs `server_admin`.",
    request_body(content = UpstreamTestInput, example = json!({ "upstreams": ["1.1.1.1", "8.8.8.8:53"], "timeout_ms": 1000 })),
    responses(
        (status = 200, description = "One result per upstream, in order.", body = UpstreamTestReport),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn test_upstreams(
    State(s): St,
    caller: Caller,
    Json(input): Json<UpstreamTestInput>,
) -> ApiResult<Json<UpstreamTestReport>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let timeout_ms = input.timeout_ms.unwrap_or(2000);
    if !(100..=30_000).contains(&timeout_ms) {
        return Err(ApiError::bad_request(
            "timeout_ms must be between 100 and 30000",
        ));
    }
    let entries: Vec<&str> = input
        .upstreams
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .collect();
    if entries.len() > settings::MAX_UPSTREAMS {
        return Err(ApiError::bad_request(format!(
            "at most {} upstreams",
            settings::MAX_UPSTREAMS
        )));
    }
    // Probe all upstreams concurrently.
    let probes = entries.iter().map(|raw| {
        let raw = raw.to_string();
        async move {
            let addr = match settings::parse_upstream(&raw) {
                Ok(a) => a,
                Err(e) => {
                    return UpstreamTestResult {
                        upstream: raw,
                        ok: false,
                        ms: None,
                        rcode: None,
                        error: Some(e),
                    }
                }
            };
            probe(raw, addr, timeout_ms).await
        }
    });
    let results = futures::future::join_all(probes).await;
    Ok(Json(UpstreamTestReport { results }))
}

async fn probe(raw: String, addr: std::net::SocketAddr, timeout_ms: u64) -> UpstreamTestResult {
    let mut m = Message::new(rand::random::<u16>(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::root(), RecordType::NS));
    let req = match m.to_vec() {
        Ok(b) => b,
        Err(e) => {
            return UpstreamTestResult {
                upstream: raw,
                ok: false,
                ms: None,
                rcode: None,
                error: Some(e.to_string()),
            }
        }
    };
    let cfg = ForwardingConfig {
        upstreams: vec![addr],
        timeout_ms,
        ..ForwardingConfig::default()
    };
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_millis(timeout_ms + 500),
        crate::dns::forward::forward(&cfg, &req, Proto::Udp),
    )
    .await;
    let ms = started.elapsed().as_millis() as u64;
    match res {
        Ok(Ok(bytes)) => match Message::from_bytes(&bytes) {
            Ok(reply) => {
                let rcode = reply.metadata.response_code;
                let ok = matches!(rcode, hickory_proto::op::ResponseCode::NoError);
                UpstreamTestResult {
                    upstream: raw,
                    ok,
                    ms: Some(ms),
                    rcode: Some(rcode.to_string()),
                    error: (!ok).then(|| {
                        format!("answered with {rcode}; it may not allow recursion for this server")
                    }),
                }
            }
            Err(e) => UpstreamTestResult {
                upstream: raw,
                ok: false,
                ms: Some(ms),
                rcode: None,
                error: Some(format!("unparseable reply: {e}")),
            },
        },
        Ok(Err(e)) => UpstreamTestResult {
            upstream: raw,
            ok: false,
            ms: None,
            rcode: None,
            error: Some(e.to_string()),
        },
        Err(_) => UpstreamTestResult {
            upstream: raw,
            ok: false,
            ms: None,
            rcode: None,
            error: Some(format!("no answer within {timeout_ms} ms")),
        },
    }
}
