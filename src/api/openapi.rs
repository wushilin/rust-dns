//! The OpenAPI document, generated from the code.
//!
//! Routes are declared once, in `super::api_router` / `super::root_router`,
//! with `utoipa_axum::routes!(handler, ...)`: that single declaration mounts
//! the handler on the axum router and adds its `#[utoipa::path]` operation to
//! the document. Schemas come from `#[derive(ToSchema)]` on the request and
//! response types the handlers actually use. This module adds what is not
//! tied to one handler: info, servers, tags, security schemes and the shared
//! error responses.
//!
//! A snapshot of the generated document is committed at `docs/openapi.json`
//! so API changes show up in code review; the `snapshot_is_up_to_date` test
//! fails when it is stale. Refresh it with
//! `UPDATE_OPENAPI=1 cargo test --bin rust-dns openapi`.

use super::error::ErrorBody;
use std::sync::OnceLock;
use utoipa::openapi::path::PathItem;
use utoipa::openapi::response::{Response, ResponseBuilder};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::server::ServerBuilder;
use utoipa::openapi::{ContentBuilder, OpenApi as OpenApiDoc, Ref, RefOr, Schema};
use utoipa::{Modify, OpenApi, ToSchema};

/// Top-level description shown by Swagger UI.
const DESCRIPTION: &str = "Management API of the rust-dns authoritative DNS server.

**Authentication.** Either
* a cookie session: `POST /auth/login` (then `/auth/mfa` if MFA is enabled) sets the `rdns_session` cookie, which the browser sends automatically; or
* an API token: `Authorization: Bearer rdns_...` (create one under *Tokens*; use the **Authorize** button).

**CSRF guard.** Cookie-authenticated writes (POST/PUT/DELETE) must send the header `X-Requested-With: rust-dns`, otherwise they fail with 403 `code: csrf`. The Swagger UI in the web console adds this header automatically. Bearer-token requests do not need it.

**Live server.** \"Try it out\" sends real requests to this server with the caller's permissions: changes are committed, logged and served over DNS immediately.

Errors are JSON `{\"error\": \"...\", \"code\": null|\"...\"}`. Zones the caller cannot see return 404.

This document is generated from the server's code, so it always matches the running version.";

#[derive(OpenApi)]
#[openapi(
    info(title = "rust-dns API"),
    servers((url = "/api", description = "This server")),
    tags(
        (name = "Auth", description = "Sign in and out. Sign in here first (cookie session), or authorize with an API token."),
        (name = "Account", description = "The caller's own profile, password, MFA and sessions."),
        (name = "Zones", description = "Create, inspect, update and delete zones."),
        (name = "Records", description = "Search and edit resource records inside a zone."),
        (name = "Access", description = "Zone membership (editor/viewer) and effective rights."),
        (name = "Import/Export", description = "JSON export documents and BIND zone files."),
        (name = "Change log", description = "DNS change log, account audit log and the realtime WebSocket."),
        (name = "Users", description = "User administration (administrators)."),
        (name = "Tokens", description = "API tokens for scripts and automation."),
        (name = "Server", description = "Health, status, metrics and server administration."),
    ),
    security(("bearer" = []), ("cookie" = [])),
    components(
        schemas(ErrorBody, crate::model::QueryEvent),
        responses(BadRequest, InvalidRequest, Unauthorized, Forbidden, NotFound, Conflict, TooManyRequests),
    ),
    modifiers(&Security),
)]
pub struct ApiDoc;

struct Security;

impl Modify for Security {
    fn modify(&self, doc: &mut OpenApiDoc) {
        let components = doc.components.get_or_insert_with(Default::default);
        let mut bearer = HttpBuilder::new()
            .scheme(HttpAuthScheme::Bearer)
            .bearer_format("rdns_...")
            .build();
        bearer.description = Some("API token from POST /tokens.".into());
        components.add_security_scheme("bearer", SecurityScheme::Http(bearer));
        components.add_security_scheme(
            "cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                super::session::COOKIE,
                "Session cookie set by POST /auth/login. Cookie writes also need `X-Requested-With: rust-dns`.",
            ))),
        );
    }
}

/// Declares a reusable error response (`#/components/responses/<Name>`)
/// whose body is the `Error` schema. Use it in `#[utoipa::path]` as
/// `(status = 404, response = NotFound)`.
macro_rules! error_response {
    ($name:ident, $description:expr) => {
        error_response!($name, $description, None);
    };
    ($name:ident, $description:expr, $example:expr) => {
        pub struct $name;

        impl<'s> utoipa::ToResponse<'s> for $name {
            fn response() -> (&'s str, RefOr<Response>) {
                let content = ContentBuilder::new()
                    .schema(Some(Ref::from_schema_name(ErrorBody::name())))
                    .example($example)
                    .build();
                (
                    stringify!($name),
                    ResponseBuilder::new()
                        .description($description)
                        .content("application/json", content)
                        .build()
                        .into(),
                )
            }
        }
    };
}

error_response!(
    BadRequest,
    "Invalid input: rejected by validation, or the request could not be parsed (`code: invalid_request`)."
);
error_response!(
    InvalidRequest,
    "Invalid request: malformed JSON, wrong field type or value, or an unparsable path or query parameter (`code: invalid_request`)."
);
error_response!(
    Unauthorized,
    "Not signed in / invalid token (`code`: login_required, mfa_required, enroll_required).",
    Some(serde_json::json!({ "error": "not signed in", "code": "login_required" }))
);
error_response!(
    Forbidden,
    "Not allowed, or cookie write without `X-Requested-With: rust-dns` (`code`: csrf).",
    Some(
        serde_json::json!({ "error": "missing X-Requested-With: rust-dns header", "code": "csrf" })
    )
);
error_response!(
    NotFound,
    "Not found (zones the caller cannot see also return 404)."
);
error_response!(Conflict, "Conflicts with existing data.");
error_response!(TooManyRequests, "Login rate limit exceeded.");

/// Assemble the final document from the operations collected by the API
/// router (paths relative to `/api`) and the root router (`/metrics`).
pub fn finish(mut api: OpenApiDoc, root: OpenApiDoc) -> OpenApiDoc {
    api.info.description = Some(DESCRIPTION.into());
    // Root-mounted paths keep the /api server list from being applied to them.
    let root_server = ServerBuilder::new()
        .url("/")
        .description(Some("Server root (not under /api)"))
        .build();
    for (path, mut item) in root.paths.paths {
        item.servers = Some(vec![root_server.clone()]);
        api.paths.paths.insert(path, item);
    }
    for item in api.paths.paths.values_mut() {
        for op in operations_mut(item) {
            // `security(())` renders as `[{}]`; the canonical "no authentication" is `[]`.
            if let Some(sec) = &op.security {
                if sec.len() == 1
                    && serde_json::to_value(&sec[0]).ok() == Some(serde_json::json!({}))
                {
                    op.security = Some(vec![]);
                }
            }
            // An inline enum parameter with a default renders as a one-item
            // `oneOf`; unwrap it so clients (and Swagger UI) see a plain enum.
            for param in op.parameters.iter_mut().flatten() {
                if let Some(RefOr::T(Schema::OneOf(one))) = &param.schema {
                    if let [RefOr::T(Schema::Object(obj))] = one.items.as_slice() {
                        let mut obj = obj.clone();
                        obj.default = one.default.clone().or(obj.default);
                        obj.description = None;
                        param.schema = Some(RefOr::T(Schema::Object(obj)));
                    }
                }
            }
        }
    }
    api
}

fn operations_mut(
    item: &mut PathItem,
) -> impl Iterator<Item = &mut utoipa::openapi::path::Operation> {
    [
        item.get.as_mut(),
        item.put.as_mut(),
        item.post.as_mut(),
        item.delete.as_mut(),
        item.options.as_mut(),
        item.head.as_mut(),
        item.patch.as_mut(),
        item.trace.as_mut(),
    ]
    .into_iter()
    .flatten()
}

/// The generated document as pretty JSON, built once and cached.
pub fn spec_json() -> &'static str {
    static JSON: OnceLock<String> = OnceLock::new();
    JSON.get_or_init(|| {
        let mut s = super::openapi_doc()
            .to_pretty_json()
            .expect("OpenAPI document serializes");
        s.push('\n');
        s
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn snapshot_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/openapi.json")
    }

    /// The committed snapshot must equal the document generated from the code.
    #[test]
    fn snapshot_is_up_to_date() {
        let generated = super::spec_json();
        let path = snapshot_path();
        let update = std::env::var("UPDATE_OPENAPI").is_ok_and(|v| !v.is_empty() && v != "0");
        if update {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, generated).unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        if committed != generated {
            let first_diff = committed
                .lines()
                .zip(generated.lines())
                .position(|(a, b)| a != b)
                .map(|i| i + 1)
                .unwrap_or(committed.lines().count().min(generated.lines().count()) + 1);
            panic!(
                "docs/openapi.json is out of date with the API code (first difference at line {first_diff}).\n\
                 The API changed: review the change, then refresh the snapshot with\n\n    \
                 UPDATE_OPENAPI=1 cargo test --bin rust-dns openapi\n\n\
                 and commit docs/openapi.json together with the code change."
            );
        }
    }

    #[test]
    fn document_is_openapi_3_1_with_api_server() {
        let v: serde_json::Value = serde_json::from_str(super::spec_json()).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
        assert_eq!(v["servers"][0]["url"], "/api");
        assert_eq!(v["paths"]["/metrics"]["servers"][0]["url"], "/");
        assert_eq!(v["info"]["version"], env!("CARGO_PKG_VERSION"));
    }
}
