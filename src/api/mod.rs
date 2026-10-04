//! HTTP server: REST API, websocket, embedded UI. Connections are accepted
//! by hand so PROXY protocol headers can be read before HTTP starts.

pub mod client_ip;
pub mod dnssec;
pub mod error;
pub mod guard;
pub mod openapi;
pub mod proxy;
pub mod ratelimit;
pub mod replication;
pub mod resolver;
pub mod rollover;
pub mod routes;
pub mod security;
pub mod session;
pub mod settings;
#[cfg(test)]
mod tests;
pub mod tsig;
pub mod types;
#[cfg(test)]
mod ui_tests;
pub mod ws;

use crate::cache::Cache;
use crate::config::{Cidr, Config};
use crate::dns::DnsServer;
use crate::events::Bus;
use crate::mutation::Mutator;
use crate::ratelimit::RateLimiter;
use crate::storage::Storage;
use axum::extract::Request;
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use client_ip::{ClientIp, ConnInfo};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::Service;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub storage: Arc<Storage>,
    pub cache: Arc<Cache>,
    pub mutator: Arc<Mutator>,
    pub accounts: Arc<crate::mutation::accounts::Accounts>,
    pub bus: Arc<Bus>,
    pub dns: Arc<DnsServer>,
    pub reloader: Arc<crate::reload::Reloader>,
    pub limiter: Arc<RateLimiter>,
    pub login_limiter: RateLimiter,
    /// Failed sign-in / code bookkeeping (per account, network, session).
    pub guard: guard::AttemptGuard,
    /// Time source for TOTP checks (the system clock; pinned in tests).
    pub clock: crate::auth::Clock,
    pub trusted: Vec<Cidr>,
    pub started: Instant,
    /// Replication role and standby/primary state.
    pub repl: Arc<crate::replication::Replication>,
}

/// Non-GET operations that still work on a read-only standby (method, path
/// under `/api`): signing in and out, local sessions, reloading the local
/// config, forwarding tests and cache flushes, TSIG reveals (a read with a
/// local audit row), blocklist downloads and name tests (this server's
/// in-memory lists only) and promotion. Every other non-GET operation is refused
/// with 409 `read_only_standby` by [`read_only_guard`] and documented so by
/// `openapi::finish` — a new route is read-only by default.
pub const STANDBY_WRITABLE: &[(&str, &str)] = &[
    ("POST", "/auth/login"),
    ("POST", "/auth/mfa"),
    ("POST", "/auth/enroll"),
    ("POST", "/auth/logout"),
    ("DELETE", "/me/sessions/{id}"),
    ("POST", "/me/sessions/revoke-others"),
    ("POST", "/users/{id}/sessions/revoke"),
    ("POST", "/admin/reload"),
    ("POST", "/settings/forwarding/test"),
    ("POST", "/settings/forwarding/cache/flush"),
    ("POST", "/blocklists/refresh"),
    ("POST", "/blocklists/test"),
    ("POST", "/tsig/keys/{name}/reveal"),
    ("POST", "/replication/promote"),
    // O21: standbys that follow this standby report a halt to it (local
    // replica list, not replicated).
    ("POST", "/replication/replicas/{id}/report"),
];

/// [`STANDBY_WRITABLE`] as published in `GET /status` (`replication.standby_writable`),
/// so the console refuses other writes on a standby before sending them.
pub fn standby_writable() -> Vec<crate::replication::types::WritableRoute> {
    STANDBY_WRITABLE
        .iter()
        .map(|(m, p)| crate::replication::types::WritableRoute {
            method: (*m).to_string(),
            path: (*p).to_string(),
        })
        .collect()
}

/// Whether `path` (concrete, under `/api`) matches `template` (`{x}` = one segment).
pub fn path_matches(template: &str, path: &str) -> bool {
    let t: Vec<&str> = template.trim_end_matches('/').split('/').collect();
    let p: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(a, b)| (a.starts_with('{') && a.ends_with('}') && !b.is_empty()) || a == b)
}

/// Is this API request allowed while the server is read-only?
pub fn allowed_when_read_only(method: &str, path: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
        || STANDBY_WRITABLE
            .iter()
            .any(|(m, t)| *m == method && path_matches(t, path))
}

/// Refuse mutations on a standby / fenced server before any handler runs.
async fn read_only_guard(
    axum::extract::State(s): axum::extract::State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(why) = s.repl.read_only_reason() {
        if !allowed_when_read_only(req.method().as_str(), req.uri().path()) {
            return error::ApiError::read_only(why).into_response();
        }
    }
    next.run(req).await
}

/// Whether the client reached us over HTTPS, as reported by a trusted
/// proxy (`X-Forwarded-Proto: https`). rust-dns itself serves plain HTTP.
#[derive(Clone, Copy, Debug)]
pub struct Https(pub bool);

async fn client_ip_layer(
    axum::extract::State(s): axum::extract::State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let (ip, https) = match req.extensions().get::<ConnInfo>() {
        Some(ci) => (
            client_ip::resolve(ci, req.headers(), &s.trusted),
            client_ip::forwarded_https(ci, req.headers(), &s.trusted),
        ),
        None => (std::net::IpAddr::from([0, 0, 0, 0]), false),
    };
    req.extensions_mut().insert(ClientIp(ip));
    req.extensions_mut().insert(Https(https));
    let page = match req.uri().path() {
        "/" | "/index.html" => Some(crate::ui::Page::Console),
        "/docs" => Some(crate::ui::Page::Docs),
        _ => None,
    };
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    // The console embeds its own API explorer (/docs) in a frame; other sites may not.
    h.insert("x-frame-options", "SAMEORIGIN".parse().unwrap());
    let csp = match page {
        Some(p) => crate::ui::content_security_policy(p, host.as_deref()),
        // API responses and static assets are never rendered as documents.
        None => "default-src 'none'; frame-ancestors 'self'".to_string(),
    };
    if let Ok(v) = csp.parse() {
        h.insert("content-security-policy", v);
    }
    h.insert("referrer-policy", "same-origin".parse().unwrap());
    h.insert(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
            .parse()
            .unwrap(),
    );
    h.insert("cross-origin-opener-policy", "same-origin".parse().unwrap());
    if https {
        // Only meaningful over HTTPS; browsers ignore it on plain HTTP.
        h.insert(
            "strict-transport-security",
            "max-age=15552000".parse().unwrap(),
        );
    }
    resp
}

/// Requests rejected by the framework before a handler runs (malformed JSON,
/// wrong field types, unknown enum values, unparsable path or query parameters,
/// a missing JSON content type) come back as plain text with 400, 415 or 422.
/// Turn them into the documented JSON error so every API error has one shape.
/// Largest request body accepted (imports are the large ones).
const MAX_BODY: usize = 16 * 1024 * 1024;

/// Read the whole request body before anything answers. A response sent
/// while part of the body is still unread (an early 401, 403 or the
/// standby's 409) makes hyper close the connection, and body bytes that
/// arrive after that get a TCP reset from the kernel: the client may then
/// lose the response itself (seen on macOS as `EINVAL` while reading its
/// headers; G2 in plan.md). The handlers buffer every body anyway, under
/// the same limit (an unauthenticated route like login reads its body
/// too), so reading it first costs nothing new.
async fn read_body_first(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Err(e) => (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            axum::Json(error::ErrorBody {
                error: format!("request body not accepted: {e}"),
                code: Some(error::ErrorCode::InvalidRequest),
            }),
        )
            .into_response(),
    }
}

async fn json_errors(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let plain_text = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain"));
    if !(resp.status().is_client_error() && plain_text) {
        return resp;
    }
    let status = match resp.status().as_u16() {
        415 | 422 => axum::http::StatusCode::BAD_REQUEST,
        _ => resp.status(),
    };
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let message = String::from_utf8_lossy(&bytes).trim().to_string();
    let message = if message.is_empty() {
        "invalid request".to_string()
    } else {
        message
    };
    (
        status,
        axum::Json(error::ErrorBody {
            error: message,
            code: Some(error::ErrorCode::InvalidRequest),
        }),
    )
        .into_response()
}

async fn ui_docs() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        crate::ui::DOCS_HTML,
    )
        .into_response()
}

/// Serve a vendored static asset, gzip-compressed when the client accepts it.
fn static_asset(
    headers: &axum::http::HeaderMap,
    content_type: &'static str,
    gz: &'static [u8],
    raw: &'static std::sync::OnceLock<Vec<u8>>,
) -> Response {
    let accepts_gzip = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim().starts_with("gzip")));
    let etag = format!("\"swagger-{}\"", crate::ui::SWAGGER_VERSION.trim());
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return (axum::http::StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    let base = [
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
        (header::VARY, "Accept-Encoding".to_string()),
        (header::ETAG, etag),
    ];
    if accepts_gzip {
        let mut r = (base, gz).into_response();
        r.headers_mut()
            .insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        r
    } else {
        (base, crate::ui::gunzipped(raw, gz)).into_response()
    }
}

async fn swagger_js(headers: axum::http::HeaderMap) -> Response {
    static RAW: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    static_asset(
        &headers,
        "application/javascript; charset=utf-8",
        crate::ui::SWAGGER_JS_GZ,
        &RAW,
    )
}

async fn swagger_css(headers: axum::http::HeaderMap) -> Response {
    static RAW: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    static_asset(
        &headers,
        "text/css; charset=utf-8",
        crate::ui::SWAGGER_CSS_GZ,
        &RAW,
    )
}

async fn ui_index() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        crate::ui::INDEX_HTML,
    )
        .into_response()
}

/// Every API route, mounted under `/api`. Each `routes!` entry both mounts
/// the handler and adds its `#[utoipa::path]` operation to the OpenAPI
/// document, so routes and documentation cannot drift apart. Handlers that
/// share a path go into one `routes!` call.
fn api_router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .routes(routes!(session::login))
        .routes(routes!(session::mfa_verify))
        .routes(routes!(session::enroll_verify))
        .routes(routes!(session::session_info))
        .routes(routes!(session::logout))
        .routes(routes!(routes::whoami))
        .routes(routes!(routes::change_password))
        .routes(routes!(routes::mfa_start))
        .routes(routes!(routes::mfa_confirm))
        .routes(routes!(routes::mfa_disable))
        .routes(routes!(routes::mfa_recovery_regen))
        .routes(routes!(routes::my_sessions))
        .routes(routes!(routes::revoke_my_session))
        .routes(routes!(routes::revoke_other_sessions))
        .routes(routes!(routes::list_zones, routes::create_zone))
        .routes(routes!(
            routes::get_zone,
            routes::update_zone,
            routes::delete_zone
        ))
        .routes(routes!(routes::list_records, routes::create_record))
        .routes(routes!(routes::update_record, routes::delete_record))
        .routes(routes!(routes::search))
        .routes(routes!(routes::rename_zone))
        .routes(routes!(routes::set_zone_settings))
        .routes(routes!(routes::get_secondary_status))
        .routes(routes!(routes::clone_zone))
        .routes(routes!(routes::bulk_records))
        .routes(routes!(routes::set_member, routes::remove_member))
        .routes(routes!(routes::user_rights))
        .routes(routes!(dnssec::get_dnssec, dnssec::set_dnssec))
        .routes(routes!(dnssec::get_ds))
        .routes(routes!(dnssec::check_dnssec))
        .routes(routes!(dnssec::get_parent_ds))
        .routes(routes!(rollover::get_rollover, rollover::start_rollover))
        .routes(routes!(rollover::rollover_ds_added))
        .routes(routes!(rollover::cancel_rollover))
        .routes(routes!(rollover::check_rollover))
        .routes(routes!(routes::export_zone))
        .routes(routes!(routes::export_all))
        .routes(routes!(routes::import))
        .routes(routes!(routes::import_hosts))
        .routes(routes!(routes::changelog))
        .routes(routes!(routes::audit))
        .routes(routes!(routes::sign_ins))
        .routes(routes!(ws::ws))
        .routes(routes!(routes::list_users, routes::create_user))
        .routes(routes!(routes::update_user, routes::delete_user))
        .routes(routes!(routes::reset_user_mfa))
        .routes(routes!(security::admin_enroll))
        .routes(routes!(
            security::get_security,
            security::update_security,
            security::reset_security
        ))
        .routes(routes!(routes::user_sessions))
        .routes(routes!(routes::revoke_user_sessions))
        .routes(routes!(routes::list_tokens, routes::create_token))
        .routes(routes!(routes::update_token, routes::revoke_token))
        .routes(routes!(routes::health))
        .routes(routes!(routes::openapi))
        .routes(routes!(routes::status))
        .routes(routes!(routes::reload_config))
        .routes(routes!(routes::integrity_check))
        .routes(routes!(
            settings::get_forwarding,
            settings::update_forwarding,
            settings::reset_forwarding
        ))
        .routes(routes!(settings::test_upstreams))
        .routes(routes!(settings::flush_forward_cache))
        .routes(routes!(
            resolver::get_resolver,
            resolver::update_resolver,
            resolver::reset_resolver
        ))
        .routes(routes!(
            resolver::get_blocklists,
            resolver::update_blocklists
        ))
        .routes(routes!(
            ratelimit::get_rate_limit,
            ratelimit::update_rate_limit,
            ratelimit::reset_rate_limit
        ))
        .routes(routes!(resolver::refresh_blocklists))
        .routes(routes!(resolver::test_blocklists))
        .routes(routes!(tsig::list_tsig_keys, tsig::create_tsig_key))
        .routes(routes!(tsig::update_tsig_key, tsig::delete_tsig_key))
        .routes(routes!(tsig::reveal_tsig_key))
        .routes(routes!(tsig::get_transfer_settings))
        .routes(routes!(replication::identity))
        .routes(routes!(replication::status))
        .routes(routes!(replication::snapshot))
        .routes(routes!(replication::changes))
        .routes(routes!(replication::checksum))
        .routes(routes!(replication::promote))
        .routes(routes!(replication::list_replicas))
        .routes(routes!(replication::forget_replica))
        .routes(routes!(replication::report_replica))
}

/// Documented routes mounted at the server root rather than under `/api`.
fn root_router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(routes::metrics))
}

/// The OpenAPI document generated from the routers above.
pub fn openapi_doc() -> utoipa::openapi::OpenApi {
    let (_, api) = api_router().split_for_parts();
    let (_, root) = root_router().split_for_parts();
    openapi::finish(api, root)
}

pub fn router(state: Arc<AppState>) -> Router {
    let (api, _) = api_router().split_for_parts();
    let (root, _) = root_router().split_for_parts();
    // Serialize the document once, now, so /api/openapi.json only copies bytes.
    openapi::spec_json();
    // Console pages are not part of the API document.
    let mut app = Router::new()
        .nest(
            "/api",
            api.layer(middleware::from_fn(json_errors))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    read_only_guard,
                )),
        )
        .merge(root);
    if state.cfg.web_console.enabled {
        app = app
            .route("/", get(ui_index))
            .route("/index.html", get(ui_index))
            .route("/docs", get(ui_docs))
            .route("/docs/swagger-ui-bundle.js", get(swagger_js))
            .route("/docs/swagger-ui.css", get(swagger_css));
    }
    // `read_body_first` wraps everything, the fallback (404) and the 405 of
    // root and console routes included: an early answer anywhere resets
    // the connection under load (O0b).
    app.layer(middleware::from_fn_with_state(
        state.clone(),
        client_ip_layer,
    ))
    .layer(middleware::from_fn(read_body_first))
    .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
    .with_state(state)
}

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = state.cfg.web_console.bind;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("cannot bind web listener {addr}: {e}"))?;
    tracing::info!(%addr, proxy_on = state.cfg.web_console.proxy.proxy_on, "web console and API listening");
    let app = router(state.clone());
    let slots = Arc::new(tokio::sync::Semaphore::new(
        state.cfg.web_console.max_connections.max(1),
    ));
    let header_timeout =
        Duration::from_secs(state.cfg.web_console.request_header_timeout_secs.max(1));
    loop {
        let (mut stream, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "web accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::debug!(%remote, "web connection limit reached; closing");
            drop(stream);
            continue;
        };
        let app = app.clone();
        let proxy_cfg = state.cfg.web_console.proxy.clone();
        let trusted = state.trusted.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let proxy_src = if proxy_cfg.proxy_on && trusted.iter().any(|c| c.contains(remote.ip()))
            {
                match proxy::read_proxy_header(&mut stream, proxy_cfg.proxy_version).await {
                    proxy::ProxyHeader::Source(src) => Some(src),
                    proxy::ProxyHeader::Absent => None,
                    proxy::ProxyHeader::Rejected(why) => {
                        tracing::warn!(%remote, why, "rejecting web connection");
                        return;
                    }
                }
            } else {
                None
            };
            let info = ConnInfo { remote, proxy_src };
            let svc = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(info);
                let mut app = app.clone();
                async move { app.call(req).await }
            });
            let io = TokioIo::new(stream);
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            // Slow or idle clients are cut off: headers (including the wait
            // for the next request on a keep-alive connection) must arrive
            // within `request_header_timeout_secs`.
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(true);
            if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
                tracing::debug!(%remote, error = %e, "connection ended with error");
            }
        });
    }
}
