//! Authentication (cookie sessions and bearer API tokens) and authorisation
//! helpers, plus the login / MFA / enrollment endpoints.

use super::client_ip::ClientIp;
use super::error::{ApiError, ApiResult, ErrorCode};
use super::openapi::{BadRequest, TooManyRequests, Unauthorized};
use super::types::*;
use super::AppState;
use crate::auth;
use crate::model::*;
use axum::extract::{FromRequestParts, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;

pub const COOKIE: &str = "rdns_session";

/// An authenticated principal on a request.
#[derive(Clone, Debug)]
pub struct Caller {
    pub user: User,
    pub ip: IpAddr,
    pub session_id: Option<i64>,
    pub via: AuthVia,
}

impl Caller {
    pub fn actor(&self) -> Actor {
        Actor {
            name: self.user.username.clone(),
            ip: self.ip.to_string(),
        }
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        if let Ok(s) = v.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(|s| s.trim().to_string())
}

fn set_cookie(state: &AppState, token: &str, max_age: i64) -> HeaderValue {
    let secure = if state.cfg.web_console.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .unwrap()
}

/// Load the session (any state) behind the cookie, if valid and unexpired.
pub fn load_session(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<(Session, User)>> {
    let Some(tok) = cookie_value(headers, COOKIE) else {
        return Ok(None);
    };
    let Some(sess) = state.storage.get_session(&auth::sha256_hex(&tok))? else {
        return Ok(None);
    };
    if sess.expires_at < now_rfc3339() {
        return Ok(None); // removed by the periodic prune_sessions task
    }
    let Some(user) = state.storage.get_user(sess.user_id)? else {
        return Ok(None);
    };
    if user.disabled_at.is_some() {
        return Ok(None);
    }
    Ok(Some((sess, user)))
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ClientIp>()
            .map(|c| c.0)
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        // API token first.
        let bearer_tok = bearer(&parts.headers).or_else(|| {
            // Websocket clients cannot set headers: allow ?token= on that path only.
            // The API router is nested under /api, which strips the prefix here.
            if matches!(parts.uri.path(), "/ws" | "/api/ws") {
                parts.uri.query().and_then(|q| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix("token=").map(|v| v.to_string()))
                })
            } else {
                None
            }
        });
        if let Some(tok) = bearer_tok {
            let Some(info) = state
                .storage
                .authenticate_token(&auth::sha256_hex(&tok), ip)?
            else {
                tracing::warn!(%ip, "rejected API token");
                return Err(ApiError::unauthorized("invalid API token"));
            };
            let Some(user) = state.storage.get_user(info.user_id)? else {
                return Err(ApiError::unauthorized("token owner no longer exists"));
            };
            if user.disabled_at.is_some() {
                return Err(ApiError::unauthorized("account disabled"));
            }
            return Ok(Caller {
                user,
                ip,
                session_id: None,
                via: AuthVia::Token,
            });
        }
        match load_session(state, &parts.headers)? {
            Some((sess, user)) if sess.state == "active" => {
                // CSRF guard for cookie-authenticated writes: browsers cannot add this header cross-site.
                let mutating = !matches!(parts.method.as_str(), "GET" | "HEAD" | "OPTIONS");
                if mutating
                    && parts
                        .headers
                        .get("x-requested-with")
                        .and_then(|v| v.to_str().ok())
                        != Some("rust-dns")
                {
                    return Err(
                        ApiError::forbidden("missing X-Requested-With: rust-dns header")
                            .with_code(ErrorCode::Csrf),
                    );
                }
                let _ = state.storage.touch_session(sess.id);
                Ok(Caller {
                    user,
                    ip,
                    session_id: Some(sess.id),
                    via: AuthVia::Session,
                })
            }
            Some((sess, _)) => Err(ApiError::unauthorized("additional authentication required")
                .with_code(match sess.state.as_str() {
                    "mfa_pending" => ErrorCode::MfaRequired,
                    _ => ErrorCode::EnrollRequired,
                })),
            None => {
                Err(ApiError::unauthorized("not signed in").with_code(ErrorCode::LoginRequired))
            }
        }
    }
}

// ---- authorisation --------------------------------------------------------

impl AppState {
    /// The caller's role on a zone, if any.
    pub fn zone_role(&self, user: &User, zone: &Zone) -> ApiResult<Option<ZoneRole>> {
        if user.is_admin {
            return Ok(Some(ZoneRole::Owner));
        }
        if zone.owner_id == Some(user.id) {
            return Ok(Some(ZoneRole::Owner));
        }
        let m = self.storage.memberships_for_user(user.id)?;
        Ok(m.into_iter()
            .find(|(zid, _)| *zid == zone.id)
            .and_then(|(_, r)| ZoneRole::parse(&r)))
    }

    /// Fetch a zone and check the caller holds at least `min`.
    pub fn require_zone(
        &self,
        caller: &Caller,
        name: &str,
        perm: ZonePerm,
    ) -> ApiResult<(Zone, ZoneRole)> {
        let name = normalize_zone_name(name)?;
        let zone = self
            .storage
            .get_zone(&name)?
            .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;
        match self.zone_role(&caller.user, &zone)? {
            Some(r) if perm.allowed(r) => Ok((zone, r)),
            Some(r) => Err(ApiError::forbidden(format!(
                "not allowed: {} needs the {} role on this zone; you are {}",
                perm.label(),
                perm.min_role().as_str(),
                r.as_str()
            ))),
            None => Err(ApiError::not_found(format!("zone '{name}' not found"))),
        }
    }

    /// Zones visible to the caller with their role.
    pub fn visible_zones(&self, user: &User) -> ApiResult<Vec<(Zone, ZoneRole)>> {
        let zones = self.storage.list_zones()?;
        if user.is_admin {
            return Ok(zones.into_iter().map(|z| (z, ZoneRole::Owner)).collect());
        }
        let m = self.storage.memberships_for_user(user.id)?;
        Ok(zones
            .into_iter()
            .filter_map(|z| {
                if z.owner_id == Some(user.id) {
                    return Some((z, ZoneRole::Owner));
                }
                m.iter()
                    .find(|(zid, _)| *zid == z.id)
                    .and_then(|(_, r)| ZoneRole::parse(r))
                    .map(|r| (z, r))
            })
            .collect())
    }

    /// Check an account-level permission from the permission table.
    pub fn require(&self, caller: &Caller, perm: GlobalPerm) -> ApiResult<()> {
        perm.check(&caller.user, caller.via.as_str())
            .map_err(|why| ApiError::forbidden(format!("not allowed: {} ({why})", perm.label())))
    }

    pub fn has(&self, caller: &Caller, perm: GlobalPerm) -> bool {
        perm.check(&caller.user, caller.via.as_str()).is_ok()
    }
}

// ---- login flow -----------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "username": "root", "password": "rootpass123" }))]
pub struct LoginBody {
    #[schema(example = "root")]
    pub username: String,
    #[schema(format = Password, example = "rootpass123")]
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
#[schema(example = json!({ "code": "123456" }))]
pub struct CodeBody {
    /// 6-digit TOTP code (or, for /auth/mfa, a recovery code).
    #[schema(example = "123456")]
    pub code: String,
}

fn new_session(
    state: &AppState,
    user: &User,
    ip: IpAddr,
    headers: &HeaderMap,
    sstate: &str,
    pending_secret: Option<String>,
) -> ApiResult<(String, Session)> {
    let token = auth::random_token(32);
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(state.cfg.web_console.session_ttl_hours.max(1) as i64);
    let sess = Session {
        id: 0,
        token_hash: auth::sha256_hex(&token),
        user_id: user.id,
        state: sstate.to_string(),
        pending_secret,
        ip: ip.to_string(),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect(),
        created_at: now_rfc3339(),
        expires_at: exp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        last_seen_at: now_rfc3339(),
    };
    let actor = Actor {
        name: user.username.clone(),
        ip: ip.to_string(),
    };
    state
        .accounts
        .run(&actor, "login", |t| t.create_session(user, &sess))?;
    Ok((token, sess))
}

pub fn enroll_payload(user: &User, secret: &str) -> EnrollPayload {
    let uri = auth::totp_uri("rust-dns", &user.username, secret);
    EnrollPayload {
        secret: secret.to_string(),
        qr_svg: auth::qr_svg(&uri),
        otpauth_uri: uri,
    }
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Auth",
    operation_id = "login",
    summary = "Sign in (step 1)",
    description = "Checks username and password and starts a cookie session. Depending on the account the session is active at once or still needs a TOTP code (`/auth/mfa`) or forced MFA enrollment (`/auth/enroll`).",
    request_body(content = LoginBody, example = json!({ "username": "root", "password": "rootpass123" })),
    responses(
        (status = 200, description = "Credentials accepted. Sets the `rdns_session` cookie; check `status` for the next step.", body = LoginResponse,
            headers(("Set-Cookie" = String, description = "`rdns_session=...; Path=/; HttpOnly; SameSite=Lax`"))),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 429, response = TooManyRequests),
    ),
    security(()),
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    ip: axum::Extension<ClientIp>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> ApiResult<Response> {
    let ip = ip.0 .0;
    if !matches!(
        state.login_limiter.check(ip),
        crate::ratelimit::Decision::Allow
    ) {
        tracing::warn!(%ip, "login rate limit exceeded");
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts; try again in a minute",
        ));
    }
    let username = body.username.trim().to_ascii_lowercase();
    let user = state.storage.get_user_by_name(&username)?;
    let ok = match &user {
        Some(u) => {
            auth::verify_password(&body.password, &u.password_hash) && u.disabled_at.is_none()
        }
        None => {
            // Burn similar time as a real verification to avoid user enumeration.
            let _ = auth::verify_password(&body.password, "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$k5T7bV4v2QG2kFQ0yYvL0qz5Hn4tq8mXwq5F3yqFq1o");
            false
        }
    };
    if !ok {
        tracing::warn!(%ip, user = %username, "failed login");
        return Err(ApiError::unauthorized("invalid username or password"));
    }
    let user = user.unwrap();
    let max_age = (state.cfg.web_console.session_ttl_hours.max(1) * 3600) as i64;
    let (status, sstate, secret, enroll) = if user.mfa_enrolled() {
        (LoginStatus::MfaRequired, "mfa_pending", None, None)
    } else if user.mfa_required {
        let secret = auth::totp_new_secret();
        let enroll = enroll_payload(&user, &secret);
        (
            LoginStatus::EnrollRequired,
            "enroll_pending",
            Some(secret),
            Some(enroll),
        )
    } else {
        (LoginStatus::Ok, "active", None, None)
    };
    let (token, _) = new_session(&state, &user, ip, &headers, sstate, secret)?;
    tracing::info!(%ip, user = %user.username, status = ?status, "login");
    let body = LoginResponse {
        status,
        user: public_user(&user),
        enroll,
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&state, &token, max_age));
    Ok(resp)
}

/// Second step: verify a TOTP code for a session in `mfa_pending`.
#[utoipa::path(
    post,
    path = "/auth/mfa",
    tag = "Auth",
    operation_id = "login_mfa",
    summary = "Sign in (step 2): TOTP or recovery code",
    description = "For a session in `mfa_required` state (cookie from /auth/login). Accepts a 6-digit TOTP code or a one-time recovery code.",
    request_body(content = CodeBody, example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "Session is now active.", body = MfaVerifyResponse),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 429, response = TooManyRequests),
    ),
    security(("cookie" = [])),
)]
pub async fn mfa_verify(
    State(state): State<Arc<AppState>>,
    ip: axum::Extension<ClientIp>,
    headers: HeaderMap,
    Json(body): Json<CodeBody>,
) -> ApiResult<Json<MfaVerifyResponse>> {
    let ip = ip.0 .0;
    if !matches!(
        state.login_limiter.check(ip),
        crate::ratelimit::Decision::Allow
    ) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts",
        ));
    }
    let Some((sess, user)) = load_session(&state, &headers)? else {
        return Err(ApiError::unauthorized("not signed in").with_code(ErrorCode::LoginRequired));
    };
    if sess.state != "mfa_pending" {
        return Err(ApiError::bad_request("session is not awaiting a code"));
    }
    let secret = user
        .totp_secret
        .clone()
        .ok_or_else(|| ApiError::bad_request("MFA is not enrolled"))?;
    let code = body.code.trim();
    let is_totp = code.len() == 6 && code.chars().all(|c| c.is_ascii_digit());
    let totp_ok = is_totp && auth::totp_verify(&secret, code);
    let recovery_hash = auth::sha256_hex(&auth::normalize_recovery_code(code));
    let actor = Actor {
        name: user.username.clone(),
        ip: ip.to_string(),
    };
    // One transaction: a recovery code is consumed only if the session is activated.
    let ok = state.accounts.run(&actor, "mfa_verify", |t| {
        let ok = if is_totp {
            totp_ok
        } else {
            t.use_recovery_code(&user, &recovery_hash)?
        };
        if ok {
            t.set_session_state(&user, &sess, "active", None)?;
        }
        Ok(ok)
    })?;
    if !ok {
        tracing::warn!(%ip, user = %user.username, "bad TOTP or recovery code");
        return Err(ApiError::unauthorized("invalid code"));
    }
    let left = state.storage.recovery_codes_left(user.id)?;
    tracing::info!(%ip, user = %user.username, method = if is_totp { "totp" } else { "recovery" }, recovery_codes_left = left, "mfa verified");
    Ok(Json(MfaVerifyResponse {
        status: OkStatus::Ok,
        user: public_user(&user),
        recovery_codes_left: left,
        used_recovery_code: !is_totp,
    }))
}

/// Complete forced enrollment for a session in `enroll_pending`.
#[utoipa::path(
    post,
    path = "/auth/enroll",
    tag = "Auth",
    operation_id = "login_enroll",
    summary = "Complete forced MFA enrollment",
    description = "For a session in `enroll_required` state: confirm the secret from the login response with a TOTP code.",
    request_body(content = CodeBody, example = json!({ "code": "123456" })),
    responses(
        (status = 200, description = "Enrolled; session active. Recovery codes are shown once.", body = EnrollVerifyResponse),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 429, response = TooManyRequests),
    ),
    security(("cookie" = [])),
)]
pub async fn enroll_verify(
    State(state): State<Arc<AppState>>,
    ip: axum::Extension<ClientIp>,
    headers: HeaderMap,
    Json(body): Json<CodeBody>,
) -> ApiResult<Json<EnrollVerifyResponse>> {
    let ip = ip.0 .0;
    if !matches!(
        state.login_limiter.check(ip),
        crate::ratelimit::Decision::Allow
    ) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts",
        ));
    }
    let Some((sess, mut user)) = load_session(&state, &headers)? else {
        return Err(ApiError::unauthorized("not signed in").with_code(ErrorCode::LoginRequired));
    };
    if sess.state != "enroll_pending" {
        return Err(ApiError::bad_request("session is not enrolling"));
    }
    let secret = sess
        .pending_secret
        .clone()
        .ok_or_else(|| ApiError::internal("missing pending secret"))?;
    if !auth::totp_verify(&secret, &body.code) {
        return Err(ApiError::unauthorized(
            "invalid code; check the time on your device",
        ));
    }
    let before = user.clone();
    user.totp_secret = Some(secret);
    user.totp_enrolled_at = Some(now_rfc3339());
    let (codes, hashes) = new_recovery_codes();
    let actor = Actor {
        name: user.username.clone(),
        ip: ip.to_string(),
    };
    let user = state.accounts.run(&actor, "mfa_enroll", |t| {
        let user = t.update_user(&before, &user)?;
        t.set_recovery_codes(&user, &hashes)?;
        t.set_session_state(&user, &sess, "active", None)?;
        Ok(user)
    })?;
    tracing::info!(%ip, user = %user.username, "mfa enrolled");
    Ok(Json(EnrollVerifyResponse {
        status: OkStatus::Ok,
        user: public_user(&user),
        recovery_codes: codes,
    }))
}

/// Describe the current cookie session so the UI can resume the right step.
#[utoipa::path(
    get,
    path = "/auth/session",
    tag = "Auth",
    operation_id = "get_session",
    summary = "State of the current cookie session",
    description = "Lets a client resume the right sign-in step. Never fails for a missing or expired cookie: that is `anonymous`.",
    responses(
        (status = 200, description = "Session state (`anonymous` without a valid cookie).", body = SessionInfo),
    ),
    security(()),
)]
pub async fn session_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<SessionInfo>> {
    match load_session(&state, &headers)? {
        None => Ok(Json(SessionInfo {
            status: SessionStatus::Anonymous,
            user: None,
            enroll: None,
        })),
        Some((sess, user)) => {
            let status = match sess.state.as_str() {
                "active" => SessionStatus::Ok,
                "mfa_pending" => SessionStatus::MfaRequired,
                _ => SessionStatus::EnrollRequired,
            };
            let enroll = if sess.state == "enroll_pending" {
                sess.pending_secret
                    .as_deref()
                    .map(|s| enroll_payload(&user, s))
            } else {
                None
            };
            Ok(Json(SessionInfo {
                status,
                user: Some(public_user(&user)),
                enroll: Some(enroll),
            }))
        }
    }
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Auth",
    operation_id = "logout",
    summary = "Sign out",
    description = "Deletes the cookie session if there is one. Always succeeds.",
    responses(
        (status = 200, description = "Signed out; the cookie is cleared.", body = StatusResponse, example = json!({ "status": "ok" })),
    ),
    security(("cookie" = []), ()),
)]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    ip: axum::Extension<ClientIp>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if let Some((sess, user)) = load_session(&state, &headers)? {
        let actor = Actor {
            name: user.username.clone(),
            ip: ip.0 .0.to_string(),
        };
        state.accounts.run(&actor, "logout", |t| {
            t.delete_session(&user, &sess, "logout")
        })?;
    }
    let mut resp = Json(StatusResponse::ok()).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&state, "", 0));
    Ok(resp)
}

/// A fresh set of recovery codes: (plaintext shown once, hashes to store).
pub fn new_recovery_codes() -> (Vec<String>, Vec<String>) {
    let codes = auth::recovery_codes();
    let hashes = codes
        .iter()
        .map(|c| auth::sha256_hex(&auth::normalize_recovery_code(c)))
        .collect();
    (codes, hashes)
}

pub fn public_user(u: &User) -> PublicUser {
    PublicUser::from(u)
}
