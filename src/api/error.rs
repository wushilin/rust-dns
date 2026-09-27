use crate::mutation::MutationError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// Machine-readable reason carried by some errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 401: not signed in (no or expired session, no token).
    LoginRequired,
    /// 401: the session still needs a TOTP or recovery code (`POST /auth/mfa`).
    MfaRequired,
    /// 401: the session still needs forced MFA enrollment (`POST /auth/enroll`).
    EnrollRequired,
    /// 403: cookie-authenticated write without `X-Requested-With: rust-dns`.
    Csrf,
    /// 400: the request could not be parsed (malformed JSON, wrong field type
    /// or value, unparsable path or query parameter, missing JSON content type).
    InvalidRequest,
    /// 409: this server is a read-only standby (or an old primary fenced
    /// after a failover); the message names the primary to use.
    ReadOnlyStandby,
}

/// Every non-2xx JSON error has this shape.
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Error, example = json!({ "error": "zone 'example.org' not found", "code": null }))]
pub struct ErrorBody {
    /// Human-readable message.
    pub error: String,
    /// Machine-readable reason when one applies: `login_required`,
    /// `mfa_required`, `enroll_required` (401) or `csrf` (403, cookie write
    /// without `X-Requested-With: rust-dns`). `invalid_request`: the request
    /// could not be parsed (malformed JSON, wrong field type or value,
    /// unparsable path or query parameter, missing JSON content type).
    /// `read_only_standby` (409): this server is a read-only standby; write
    /// to the primary named in the message.
    #[schema(required = true)]
    pub code: Option<ErrorCode>,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub code: Option<ErrorCode>,
    /// Sent as `Retry-After` (seconds) when set.
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            code: None,
            retry_after: None,
        }
    }
    pub fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }
    pub fn too_many(m: impl Into<String>, retry_after: u64) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, m).retry_after(retry_after.max(1))
    }
    pub fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = Some(code);
        self
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
    /// 409 `read_only_standby`.
    pub fn read_only(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m).with_code(ErrorCode::ReadOnlyStandby)
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.message,
            code: self.code,
        };
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(s) = self.retry_after {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, s.into());
        }
        resp
    }
}

impl From<crate::auth::KdfBusy> for ApiError {
    fn from(_: crate::auth::KdfBusy) -> Self {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many sign-ins or password changes in progress; retry in a moment",
        )
        .retry_after(1)
    }
}

impl From<MutationError> for ApiError {
    fn from(e: MutationError) -> Self {
        match e {
            MutationError::ReadOnly(m) => ApiError::read_only(m),
            MutationError::Invalid(m) => ApiError::bad_request(m),
            MutationError::NotFound(m) => ApiError::not_found(m),
            MutationError::Conflict(m) => ApiError::conflict(m),
            MutationError::Internal(e) => ApiError::internal(e),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::internal(e)
    }
}

impl From<crate::model::Invalid> for ApiError {
    fn from(e: crate::model::Invalid) -> Self {
        ApiError::bad_request(e.0)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
