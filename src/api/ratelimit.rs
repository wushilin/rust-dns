//! O15: DNS rate limiting set from the console (setting `rate_limit`):
//! the per-client limit, the slip ratio and the exemption of clients that
//! present a valid server cookie. Replicated like every console setting;
//! each server applies it to its own limiter.

use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, Forbidden, Unauthorized};
use super::session::Caller;
use super::settings::SettingSource;
use super::AppState;
use crate::model::GlobalPerm;
use crate::mutation::settings::{self, RateLimitSettings, RATE_LIMIT_KEY};
use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// The limits in effect on this server.
#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitInEffect {
    /// Queries per second per client (0: no limit).
    pub max_resolutions_per_second_per_address: u32,
    /// Every Nth over-limit UDP query gets a TC=1 answer (0: all dropped).
    pub slip: u32,
    /// Over-limit UDP queries with a valid server cookie are answered
    /// (in effect: only while `cookies` is on).
    pub exempt_valid_cookies: bool,
    /// `[server].cookies`: without it no client holds a server cookie and
    /// the exemption has no effect.
    pub cookies: bool,
    /// `[rate_limit].max_tracked_addresses` (file only).
    pub max_tracked_addresses: usize,
}

/// Rate limiting: the saved settings, the file's and what is in effect.
#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitView {
    /// Saved settings (`null` fields: the file's value).
    pub settings: RateLimitSettings,
    pub in_effect: RateLimitInEffect,
    /// `[rate_limit]` in the config file.
    pub file: RateLimitInEffect,
    /// `config`: nothing saved; `console`: saved settings.
    pub source: SettingSource,
    #[schema(required = true)]
    pub updated_by: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub updated_at: Option<String>,
    /// Over-limit UDP queries dropped (or slipped) since start.
    pub rate_limited: u64,
    /// Over-limit UDP queries answered because of a valid server cookie.
    pub cookie_exempt: u64,
}

fn view(s: &AppState) -> ApiResult<RateLimitView> {
    let cfg = s.reloader.current.load_full();
    let shown = |r: &crate::config::RateLimitConfig| RateLimitInEffect {
        max_resolutions_per_second_per_address: r.max_resolutions_per_second_per_address,
        slip: r.slip,
        exempt_valid_cookies: r.exempt_valid_cookies,
        cookies: cfg.server.cookies,
        max_tracked_addresses: r.max_tracked_addresses,
    };
    let stored = settings::load_rate_limit(&s.storage)?;
    let counters = s.dns.stats.snapshot();
    let (settings, source, by, at) = match stored {
        Some((v, by, at)) => (v, SettingSource::Console, Some(by), Some(at)),
        None => (
            RateLimitSettings::default(),
            SettingSource::Config,
            None,
            None,
        ),
    };
    // What this server's limiter actually runs with (a standby applies
    // replicated settings as they arrive).
    let live = RateLimitInEffect {
        max_resolutions_per_second_per_address: s.dns.limiter.limit(),
        slip: s.dns.limiter.slip(),
        exempt_valid_cookies: s
            .dns
            .cookie_exempt
            .load(std::sync::atomic::Ordering::Relaxed),
        cookies: cfg.server.cookies,
        max_tracked_addresses: s.dns.limiter.max_tracked(),
    };
    Ok(RateLimitView {
        in_effect: live,
        file: shown(&cfg.rate_limit),
        settings,
        source,
        updated_by: by,
        updated_at: at,
        rate_limited: counters.rate_limited,
        cookie_exempt: counters.rate_limit_cookie_exempt,
    })
}

#[utoipa::path(
    get,
    path = "/settings/rate-limit",
    tag = "Server",
    operation_id = "get_rate_limit",
    summary = "DNS rate limiting (admin)",
    description = "The per-client query limit, the slip ratio and the server-cookie exemption: saved values, the config file's and what is in effect on this server, with counters. Needs `server_admin`.",
    responses(
        (status = 200, description = "Rate limiting.", body = RateLimitView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_rate_limit(State(s): St, caller: Caller) -> ApiResult<Json<RateLimitView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    Ok(Json(view(&s)?))
}

#[utoipa::path(
    put,
    path = "/settings/rate-limit",
    tag = "Server",
    operation_id = "update_rate_limit",
    summary = "Change DNS rate limiting (admin)",
    description = "Saves the settings; they apply at once on this server and replicate to standbys, which apply them too. A field left out or `null` keeps the config file's value. `exempt_valid_cookies`: UDP queries that carry a valid server cookie (RFC 7873; the client proved its address earlier, so it is not spoofed) are answered even over the limit. Audited as `settings.rate_limit.update`. Needs `server_admin`.",
    request_body(content = RateLimitSettings, example = json!({ "max_resolutions_per_second_per_address": 200, "slip": 2, "exempt_valid_cookies": true })),
    responses(
        (status = 200, description = "Saved.", body = RateLimitView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn update_rate_limit(
    State(s): St,
    caller: Caller,
    Json(input): Json<RateLimitSettings>,
) -> ApiResult<Json<RateLimitView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    let next = input
        .validate()
        .map_err(|errs| ApiError::bad_request(errs.join("; ")))?;
    let before = settings::load_rate_limit(&s.storage)?.map(|(v, _, _)| v);
    let actor = caller.actor();
    s.accounts.run(&actor, "update_rate_limit", |t| {
        t.set_setting(
            RATE_LIMIT_KEY,
            "settings.rate_limit.update",
            &actor.name,
            before.as_ref(),
            &next,
        )
    })?;
    s.dns.set_rate_limit(Some(next), &s.reloader.current.load());
    Ok(Json(view(&s)?))
}

#[utoipa::path(
    delete,
    path = "/settings/rate-limit",
    tag = "Server",
    operation_id = "reset_rate_limit",
    summary = "Use the config file's rate limiting again (admin)",
    description = "Removes the saved settings; `[rate_limit]` of the config file applies again (here and on standbys). Audited as `settings.rate_limit.reset`; no-op when nothing is saved. Needs `server_admin`.",
    responses(
        (status = 200, description = "File values in effect.", body = RateLimitView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn reset_rate_limit(State(s): St, caller: Caller) -> ApiResult<Json<RateLimitView>> {
    s.require(&caller, GlobalPerm::ServerAdmin)?;
    if let Some((before, _, _)) = settings::load_rate_limit(&s.storage)? {
        let actor = caller.actor();
        s.accounts.run(&actor, "reset_rate_limit", |t| {
            t.clear_setting(RATE_LIMIT_KEY, "settings.rate_limit.reset", &before)
        })?;
    }
    s.dns.set_rate_limit(None, &s.reloader.current.load());
    Ok(Json(view(&s)?))
}
