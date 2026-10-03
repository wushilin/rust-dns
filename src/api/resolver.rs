//! Resolver settings (I2-I6, I9, I10) and blocklists (I7), managed from the
//! console. Both are console settings (`resolver`, `blocklists`): stored as
//! typed `setting_set` changes with their audit entry in one transaction,
//! replicated to standbys, applied at once. Upstream health, the rebinding
//! log and blocklist downloads are per server.

use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, Forbidden, Unauthorized};
use super::session::Caller;
use super::settings::SettingSource;
use super::AppState;
use crate::blocklist::{BlockTest, BlocklistSettings, ListStatus};
use crate::dns::filters::RebindEntry;
use crate::dns::forward::UpstreamHealth;
use crate::model::GlobalPerm;
use crate::mutation::settings::{self, ResolverSettings, RESOLVER_KEY};
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// Health of the upstreams of one override zone.
#[derive(Debug, Serialize, ToSchema)]
pub struct ZoneUpstreams {
    /// The override zone.
    #[schema(example = "corp.example")]
    pub zone: String,
    pub upstreams: Vec<UpstreamHealth>,
}

/// Resolver settings in effect, with what this server observed.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResolverView {
    pub settings: ResolverSettings,
    /// `config`: the defaults (nothing saved); `console`: saved settings.
    pub source: SettingSource,
    #[schema(required = true)]
    pub updated_by: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub updated_at: Option<String>,
    /// Health of the forwarding upstreams on this server, in order.
    pub upstream_health: Vec<UpstreamHealth>,
    /// Health of the upstreams of each override zone with its own.
    pub zone_upstreams: Vec<ZoneUpstreams>,
    /// Names refused by rebinding protection on this server, most recent
    /// first (at most 100).
    pub rebind_blocked: Vec<RebindEntry>,
    /// Answers refused by rebinding protection since start.
    pub rebind_blocked_total: u64,
    /// Queries answered NXDOMAIN by `domain_needed` since start.
    pub domain_needed_answered: u64,
    /// Queries answered NXDOMAIN by `bogus_priv` since start.
    pub bogus_priv_answered: u64,
    /// Queries answered NODATA by `filter_types` since start.
    pub filtered_answered: u64,
    /// Stale answers served since start.
    pub stale_answers: u64,
}

fn filter_answered(s: &AppState, name: &str) -> u64 {
    s.dns
        .filter_stats
        .snapshot()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| c.answered)
        .unwrap_or(0)
}

fn resolver_view(s: &AppState) -> ApiResult<ResolverView> {
    let stored = settings::load_resolver(&s.storage)?;
    let (source, updated_by, updated_at) = match &stored {
        Some((_, by, at)) => (SettingSource::Console, Some(by.clone()), Some(at.clone())),
        None => (SettingSource::Config, None, None),
    };
    let rt = s.dns.runtime.load();
    let catalog = s.cache.load();
    let zone_upstreams = catalog
        .zones
        .values()
        .filter_map(|z| {
            let o = z.zone.overrides.as_ref()?;
            (!o.upstreams.is_empty()).then(|| ZoneUpstreams {
                zone: z.zone.name.clone(),
                upstreams: s.dns.upstream_health.report(&o.upstreams),
            })
        })
        .collect();
    Ok(ResolverView {
        settings: s.dns.resolver(),
        source,
        updated_by,
        updated_at,
        upstream_health: s.dns.upstream_health.report(&rt.forwarding.upstreams),
        zone_upstreams,
        rebind_blocked: s.dns.rebind_log.recent(),
        rebind_blocked_total: s
            .dns
            .rebind_log
            .total
            .load(std::sync::atomic::Ordering::Relaxed),
        domain_needed_answered: filter_answered(s, "domain_needed"),
        bogus_priv_answered: filter_answered(s, "bogus_priv"),
        filtered_answered: filter_answered(s, "filter_types"),
        stale_answers: s
            .dns
            .stats
            .stale_answers
            .load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[utoipa::path(
    get,
    path = "/settings/resolver",
    tag = "Server",
    operation_id = "get_resolver_settings",
    summary = "Resolver settings and upstream health (admin)",
    description = "Settings for forwarded queries (domain-needed, bogus-priv, rebinding protection, serve stale, upstream strategy, filtered types, EDNS Client Subnet), whether they were saved from the console, and what this server observed: upstream health, names refused by rebinding protection, counters. Needs `server_admin`.",
    responses(
        (status = 200, description = "Settings in effect.", body = ResolverView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_resolver(State(s): St, caller: Caller) -> ApiResult<Json<ResolverView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    Ok(Json(resolver_view(&s)?))
}

#[utoipa::path(
    put,
    path = "/settings/resolver",
    tag = "Server",
    operation_id = "update_resolver_settings",
    summary = "Change resolver settings (admin)",
    description = "Saves the resolver settings and applies them at once (no restart); replicated to standbys. Omitted fields take their defaults. The change and its audit entry (`settings.resolver.update`) are one transaction. Needs `server_admin`.",
    request_body(content = ResolverSettings, example = json!({ "domain_needed": true, "bogus_priv": true, "rebind_protection": true, "rebind_allow": ["internal"], "serve_stale": true, "max_stale_age_secs": 86400, "strategy": "fastest", "filter_types": ["AAAA"], "ecs": false, "ecs_ipv4_prefix": 24, "ecs_ipv6_prefix": 56, "ecs_private_clients": false })),
    responses(
        (status = 200, description = "Saved and applied.", body = ResolverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn update_resolver(
    State(s): St,
    caller: Caller,
    Json(input): Json<ResolverSettings>,
) -> ApiResult<Json<ResolverView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let next = input
        .validate()
        .map_err(|errs| ApiError::bad_request(errs.join("; ")))?;
    let before = settings::load_resolver(&s.storage)?.map(|(r, _, _)| r);
    let actor = caller.actor();
    s.accounts.run(&actor, "update_resolver", |t| {
        t.set_setting(
            RESOLVER_KEY,
            "settings.resolver.update",
            &actor.name,
            before.as_ref(),
            &next,
        )
    })?;
    s.dns
        .set_resolver(Some(next.clone()), &s.reloader.current.load());
    tracing::info!(actor = %actor.name, settings = ?next, "resolver settings updated from the console");
    Ok(Json(resolver_view(&s)?))
}

#[utoipa::path(
    delete,
    path = "/settings/resolver",
    tag = "Server",
    operation_id = "reset_resolver_settings",
    summary = "Use the default resolver settings again (admin)",
    description = "Removes the saved resolver settings; the defaults apply at once (domain-needed and bogus-priv on, everything else off, upstreams in order). Audited as `settings.resolver.reset`. No-op when nothing is saved. Needs `server_admin`.",
    responses(
        (status = 200, description = "Defaults in effect.", body = ResolverView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn reset_resolver(State(s): St, caller: Caller) -> ApiResult<Json<ResolverView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    if let Some((before, _, _)) = settings::load_resolver(&s.storage)? {
        let actor = caller.actor();
        s.accounts.run(&actor, "reset_resolver", |t| {
            t.clear_setting(RESOLVER_KEY, "settings.resolver.reset", &before)
        })?;
    }
    s.dns.set_resolver(None, &s.reloader.current.load());
    Ok(Json(resolver_view(&s)?))
}

/// Blocklist configuration and this server's download state.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlocklistView {
    pub settings: BlocklistSettings,
    #[schema(required = true)]
    pub updated_by: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub updated_at: Option<String>,
    /// Per list: entries in use, last download, errors, blocked queries
    /// (this server).
    pub lists: Vec<ListStatus>,
    /// Domains in use over all enabled lists (before de-duplication across
    /// lists).
    pub entries: usize,
    /// Memory held by the lists in use, bytes.
    pub memory_bytes: usize,
    /// Forwarded queries blocked since start (this server).
    pub blocked: u64,
}

fn blocklist_view(s: &AppState) -> ApiResult<BlocklistView> {
    let stored = settings::load_blocklists(&s.storage)?;
    let compiled = s.dns.blocklists.compiled();
    Ok(BlocklistView {
        settings: s.dns.blocklists.settings(),
        updated_by: stored.as_ref().map(|(_, by, _)| by.clone()),
        updated_at: stored.as_ref().map(|(_, _, at)| at.clone()),
        lists: s.dns.blocklists.status(),
        entries: compiled.lists.iter().map(|l| l.set.len()).sum(),
        memory_bytes: compiled.lists.iter().map(|l| l.set.heap_bytes()).sum(),
        blocked: s
            .dns
            .blocklists
            .blocked
            .load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[utoipa::path(
    get,
    path = "/blocklists",
    tag = "Server",
    operation_id = "get_blocklists",
    summary = "Blocklists and their download state (admin)",
    description = "The blocklist configuration (replicated) and, per list, this server's last download, entries in use, errors and blocked queries. Blocklists apply to forwarded queries only. Needs `server_admin`.",
    responses(
        (status = 200, description = "Blocklists.", body = BlocklistView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_blocklists(State(s): St, caller: Caller) -> ApiResult<Json<BlocklistView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    Ok(Json(blocklist_view(&s)?))
}

#[utoipa::path(
    put,
    path = "/blocklists",
    tag = "Server",
    operation_id = "update_blocklists",
    summary = "Change the blocklists (admin)",
    description = "Saves the list URLs, allowlist, block action and refresh interval; replicated to standbys, each server downloads the lists itself (new lists at once). Audited as `settings.blocklists.update`. Needs `server_admin`.",
    request_body(content = BlocklistSettings, example = json!({ "lists": [{ "name": "StevenBlack", "url": "https://blocklists.example/hosts.txt", "enabled": true }], "allow": ["example.com"], "action": "nxdomain", "refresh_hours": 24 })),
    responses(
        (status = 200, description = "Saved and applied.", body = BlocklistView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn update_blocklists(
    State(s): St,
    caller: Caller,
    Json(input): Json<BlocklistSettings>,
) -> ApiResult<Json<BlocklistView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let next = input
        .validate()
        .map_err(|errs| ApiError::bad_request(errs.join("; ")))?;
    let before = settings::load_blocklists(&s.storage)?.map(|(b, _, _)| b);
    let actor = caller.actor();
    s.accounts.run(&actor, "update_blocklists", |t| {
        t.set_setting(
            crate::blocklist::SETTINGS_KEY,
            "settings.blocklists.update",
            &actor.name,
            before.as_ref(),
            &next,
        )
    })?;
    s.dns.set_blocklists(Some(next), &s.reloader.current.load());
    tracing::info!(actor = %actor.name, "blocklists updated from the console");
    Ok(Json(blocklist_view(&s)?))
}

#[utoipa::path(
    post,
    path = "/blocklists/refresh",
    tag = "Server",
    operation_id = "refresh_blocklists",
    summary = "Download every enabled blocklist now (admin)",
    description = "Starts a download of every enabled list on this server (not replicated); the result shows in `GET /blocklists` when it finishes. Needs `server_admin`.",
    responses(
        (status = 200, description = "Started.", body = BlocklistView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn refresh_blocklists(State(s): St, caller: Caller) -> ApiResult<Json<BlocklistView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    s.dns.blocklists.refresh_now();
    Ok(Json(blocklist_view(&s)?))
}

/// A name to test against the blocklists.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "name": "ads.example.com" }))]
pub struct BlockTestInput {
    pub name: String,
}

#[utoipa::path(
    post,
    path = "/blocklists/test",
    tag = "Server",
    operation_id = "test_blocklists",
    summary = "Would a name be blocked? (admin)",
    description = "Checks a name against the allowlist and every list in use on this server. Own and override zones are answered before blocklists, so a name they hold is never blocked whatever this says. Needs `server_admin`.",
    request_body(content = BlockTestInput, example = json!({ "name": "ads.example.com" })),
    responses(
        (status = 200, description = "Outcome.", body = BlockTest),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn test_blocklists(
    State(s): St,
    caller: Caller,
    Json(input): Json<BlockTestInput>,
) -> ApiResult<Json<BlockTest>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 253 {
        return Err(ApiError::bad_request("name must be a domain name"));
    }
    Ok(Json(s.dns.blocklists.compiled().test(name)))
}
