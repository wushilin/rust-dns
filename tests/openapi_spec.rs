//! Static checks on the generated OpenAPI document (docs/openapi.json).
//!
//! Routes and the document can no longer drift: every API route is mounted
//! with `utoipa_axum::routes!`, which also adds its operation to the
//! document, and the `snapshot_is_up_to_date` unit test (src/api/openapi.rs)
//! keeps the committed snapshot equal to what the code generates. What is
//! left to check here is what the generator does not enforce: completeness
//! and consistency of the hand-written parts of each `#[utoipa::path]`
//! annotation, and that nobody mounts an API route bypassing `routes!`.

use std::collections::BTreeSet;

const SPEC_SRC: &str = include_str!("../docs/openapi.json");
const ROUTER_SRC: &str = include_str!("../src/api/mod.rs");
const HANDLER_SRCS: [(&str, &str); 3] = [
    ("src/api/routes.rs", include_str!("../src/api/routes.rs")),
    ("src/api/session.rs", include_str!("../src/api/session.rs")),
    ("src/api/ws.rs", include_str!("../src/api/ws.rs")),
];

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn spec() -> serde_json::Value {
    serde_json::from_str(SPEC_SRC).expect("docs/openapi.json is valid JSON")
}

/// ((path, method), operation) for every operation.
fn ops(spec: &serde_json::Value) -> Vec<((String, String), serde_json::Value)> {
    let mut out = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("paths object") {
        for (k, v) in item.as_object().unwrap() {
            if METHODS.contains(&k.as_str()) {
                out.push(((path.clone(), k.clone()), v.clone()));
            }
        }
    }
    assert!(out.len() > 40, "too few operations ({})", out.len());
    out
}

/// Return the text between the `(` at `open` and its matching `)`.
fn balanced(src: &str, open: usize) -> &str {
    let bytes = src.as_bytes();
    assert_eq!(bytes[open], b'(');
    let mut depth = 0usize;
    let mut in_str = false;
    let mut i = open;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &src[open + 1..i];
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    panic!("unbalanced parentheses");
}

/// One annotated handler: (file, fn name, method, path, fn parameter list).
struct Handler {
    file: &'static str,
    name: String,
    method: String,
    path: String,
    params: &'static str,
}

/// Every `#[utoipa::path(...)]` annotation and the handler it documents.
fn handlers() -> Vec<Handler> {
    let mut out = Vec::new();
    for (file, src) in HANDLER_SRCS {
        let mut from = 0;
        while let Some(off) = src[from..].find("#[utoipa::path(") {
            let open = from + off + "#[utoipa::path".len();
            let attr = balanced(src, open);
            let method = attr.split(',').next().unwrap().trim().to_string();
            let p = attr.find("path = \"").expect("path in #[utoipa::path]") + 8;
            let path = attr[p..p + attr[p..].find('"').unwrap()].to_string();
            let after = open + attr.len();
            let f = after + src[after..].find("pub async fn ").expect("handler fn") + 13;
            let name_end = f + src[f..].find('(').unwrap();
            let name = src[f..name_end].to_string();
            let params = balanced(src, name_end);
            out.push(Handler {
                file,
                name,
                method,
                path,
                params,
            });
            from = after;
        }
    }
    assert!(out.len() > 40, "annotation scan found too few handlers");
    out
}

#[test]
fn every_operation_has_id_tag_summary_and_responses() {
    let spec = spec();
    let tag_names: BTreeSet<String> = spec["tags"]
        .as_array()
        .expect("top-level tags")
        .iter()
        .map(|t| {
            assert!(
                t["description"].as_str().is_some_and(|d| !d.is_empty()),
                "tag {} has no description",
                t["name"]
            );
            t["name"].as_str().unwrap().to_string()
        })
        .collect();
    let mut ids = BTreeSet::new();
    let mut used_tags = BTreeSet::new();
    for ((path, method), op) in ops(&spec) {
        let id = op["operationId"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} {path}: missing operation_id"));
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{method} {path}: operationId '{id}' is not snake_case"
        );
        assert!(ids.insert(id.to_string()), "duplicate operationId '{id}'");
        assert!(
            op["summary"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "{method} {path}: missing summary"
        );
        let tags = op["tags"]
            .as_array()
            .unwrap_or_else(|| panic!("{method} {path}: missing tag"));
        assert_eq!(tags.len(), 1, "{method} {path}: expected exactly one tag");
        for t in tags {
            let t = t.as_str().unwrap();
            assert!(
                tag_names.contains(t),
                "{method} {path}: tag '{t}' is not declared in ApiDoc (src/api/openapi.rs)"
            );
            used_tags.insert(t.to_string());
        }
        let responses = op["responses"].as_object().expect("responses");
        assert!(
            responses
                .keys()
                .any(|s| s.starts_with('1') || s.starts_with('2')),
            "{method} {path}: no success response"
        );
        for (status, r) in responses {
            let r = match r["$ref"].as_str() {
                Some(name) => &spec["components"]["responses"][name.rsplit('/').next().unwrap()],
                None => r,
            };
            assert!(
                r["description"].as_str().is_some_and(|d| !d.is_empty()),
                "{method} {path}: response {status} has no description"
            );
        }
        // Every {param} in the path must be declared.
        let declared: BTreeSet<&str> = op["parameters"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|p| p["in"] == "path")
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        let in_path: BTreeSet<&str> = path
            .split('/')
            .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .collect();
        assert_eq!(
            declared, in_path,
            "{method} {path}: path parameters in params(...) do not match the path"
        );
    }
    assert_eq!(used_tags, tag_names, "declared tags without operations");
}

/// Anything that takes input (a body, a path or a query parameter) can be
/// rejected before the handler runs, with 400 `invalid_request`.
#[test]
fn operations_taking_input_document_400() {
    let spec = spec();
    for ((path, method), op) in ops(&spec) {
        let takes_input = op.get("requestBody").is_some()
            || op["parameters"].as_array().is_some_and(|p| !p.is_empty());
        if takes_input {
            assert!(
                op["responses"].get("400").is_some(),
                "{method} {path} takes input but does not document 400 (use `response = InvalidRequest` or `BadRequest`)"
            );
        }
    }
}

/// Operations that need authentication document 401.
#[test]
fn authenticated_operations_document_401() {
    let spec = spec();
    let global = spec["security"].as_array().expect("top-level security");
    assert!(!global.is_empty());
    for ((path, method), op) in ops(&spec) {
        let security = op
            .get("security")
            .and_then(|s| s.as_array())
            .unwrap_or(global);
        // `[]` or an alternative `{}` means anonymous access is allowed.
        let anonymous_ok = security.is_empty()
            || security
                .iter()
                .any(|s| s.as_object().is_some_and(|o| o.is_empty()));
        if !anonymous_ok {
            assert!(
                op["responses"].get("401").is_some(),
                "{method} {path} requires authentication but does not document 401"
            );
        }
    }
    // The endpoints that must work without credentials.
    for (path, method) in [
        ("/health", "get"),
        ("/auth/login", "post"),
        ("/auth/session", "get"),
        ("/openapi.json", "get"),
    ] {
        assert_eq!(
            spec["paths"][path][method]["security"],
            serde_json::json!([]),
            "{method} {path} must be documented as unauthenticated"
        );
    }
}

/// A request body is declared by hand in `request_body(...)`; check it
/// against the handler's extractors.
#[test]
fn body_taking_handlers_document_a_request_body() {
    let spec = spec();
    for h in handlers() {
        let op = &spec["paths"][&h.path][&h.method];
        assert!(
            op.is_object(),
            "{} ({}) is annotated for {} {} but that operation is not in docs/openapi.json: mount it with .routes(routes!(...)) and refresh the snapshot (UPDATE_OPENAPI=1 cargo test --bin rust-dns openapi)",
            h.name,
            h.file,
            h.method,
            h.path
        );
        // `Json(..)`, or raw `Bytes` parsed as optional JSON by the handler.
        let wants_json = h.params.contains("Json(") || h.params.contains("body::Bytes");
        // A bare `String` extractor (not inside Path/Query) is the raw request body.
        let wants_text = h.params.contains("body: String");
        let content = &op["requestBody"]["content"];
        if wants_json {
            assert!(
                content["application/json"]["schema"].is_object(),
                "{} {} ({}) takes a JSON body but has no application/json request_body",
                h.method,
                h.path,
                h.name
            );
        } else if wants_text {
            assert!(
                content["text/plain"]["schema"].is_object(),
                "{} {} ({}) takes a text body but has no text/plain request_body",
                h.method,
                h.path,
                h.name
            );
        } else {
            assert!(
                op.get("requestBody").is_none(),
                "{} {} ({}) takes no body but documents one",
                h.method,
                h.path,
                h.name
            );
        }
        if op.get("requestBody").is_some() {
            let c = content.as_object().unwrap().values().next().unwrap();
            assert!(
                c.get("example").is_some() || c.get("examples").is_some(),
                "{} {} ({}): add a request_body example so Swagger UI and the contract test can send it",
                h.method,
                h.path,
                h.name
            );
        }
    }
}

/// API routes must go through `routes!` (which documents them); plain
/// `.route(...)` is only for the console pages (and the redirects of `/`
/// and `/rust-dns` to the console), which stay out of the spec.
#[test]
fn only_console_routes_bypass_the_openapi_router() {
    let mut from = 0;
    let mut n = 0;
    while let Some(off) = ROUTER_SRC[from..].find(".route(") {
        let open = from + off + ".route".len();
        let args = balanced(ROUTER_SRC, open);
        let q1 = args.find('"').expect("route path literal");
        let path = &args[q1 + 1..q1 + 1 + args[q1 + 1..].find('"').unwrap()];
        assert!(
            path == "/"
                || path == "/rust-dns"
                || path == "/index.html"
                || path == "/docs"
                || path.starts_with("/docs/"),
            "src/api/mod.rs mounts {path} with .route(); API routes must use .routes(routes!(handler)) so they are documented"
        );
        n += 1;
        from = open + args.len();
    }
    assert!(n >= 3, "console routes not found");
    let spec = spec();
    for path in spec["paths"].as_object().unwrap().keys() {
        assert!(
            !(path == "/" || path == "/index.html" || path.starts_with("/docs")),
            "console route {path} must not be in the API document"
        );
    }
}

#[test]
fn servers_and_root_mounted_metrics() {
    let spec = spec();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["servers"][0]["url"], "/rust-dns/api");
    assert_eq!(
        spec["paths"]["/metrics"]["servers"][0]["url"], "/rust-dns",
        "/metrics needs a path-level servers override to /rust-dns (it is not under /rust-dns/api)"
    );
    assert!(spec["paths"]["/metrics"]["get"].is_object());
    for scheme in ["bearer", "cookie"] {
        assert!(
            spec["components"]["securitySchemes"][scheme].is_object(),
            "security scheme {scheme} missing"
        );
    }
    let codes = &spec["components"]["schemas"]["ErrorCode"]["enum"];
    for c in [
        "login_required",
        "mfa_required",
        "enroll_required",
        "csrf",
        "invalid_request",
    ] {
        assert!(
            codes.as_array().unwrap().iter().any(|v| v == c),
            "error code {c} not documented"
        );
    }
}

/// API token tags, last use and the tag update/filter operations are documented.
#[test]
fn token_tags_and_last_use_are_documented() {
    let spec = spec();
    let schemas = &spec["components"]["schemas"];
    let info = &schemas["TokenInfo"];
    for f in ["tags", "last_used_at", "last_used_ip"] {
        assert!(info["properties"][f].is_object(), "TokenInfo.{f} missing");
        assert!(
            info["required"].as_array().unwrap().iter().any(|r| r == f),
            "TokenInfo.{f} must be required (always present, possibly null)"
        );
    }
    assert_eq!(info["properties"]["tags"]["maxItems"], 16);
    assert!(
        !schemas["TokenBody"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "tags"),
        "tags are optional when creating a token"
    );
    // M1: tags and scope are each optional on update (absent = unchanged).
    assert!(
        schemas["TokenUpdateBody"]["required"]
            .as_array()
            .is_none_or(|r| r.is_empty()),
        "{}",
        schemas["TokenUpdateBody"]
    );
    for body in ["TokenBody", "TokenUpdateBody"] {
        assert!(
            schemas[body]["properties"]["scope"].is_object(),
            "{body}.scope missing"
        );
    }
    let scope = &schemas["TokenScope"]["properties"];
    for f in ["zones", "max_role", "expires_at"] {
        assert!(scope[f].is_object(), "TokenScope.{f} missing");
    }
    assert!(info["properties"]["scope"].is_object(), "TokenInfo.scope");

    let put = &spec["paths"]["/tokens/{id}"]["put"];
    assert_eq!(put["operationId"], "update_token");
    for status in ["200", "400", "401", "403", "404"] {
        assert!(
            put["responses"][status].is_object(),
            "PUT /tokens/{{id}} does not document {status}"
        );
    }
    let ex = &put["requestBody"]["content"]["application/json"]["example"];
    assert!(ex["tags"].as_array().is_some_and(|t| !t.is_empty()), "{ex}");

    let create_ex =
        &spec["paths"]["/tokens"]["post"]["requestBody"]["content"]["application/json"]["example"];
    assert!(
        create_ex["tags"].is_array(),
        "create example shows tags: {create_ex}"
    );
    let list = &spec["paths"]["/tokens"]["get"];
    assert!(
        list["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "tag" && p["in"] == "query"),
        "GET /tokens documents the tag filter"
    );
}

/// Every `$ref` points at an existing component.
#[test]
fn no_dangling_refs() {
    fn walk(spec: &serde_json::Value, v: &serde_json::Value, at: &str) {
        match v {
            serde_json::Value::Object(o) => {
                if let Some(r) = o.get("$ref").and_then(|r| r.as_str()) {
                    let parts: Vec<&str> = r.trim_start_matches("#/").split('/').collect();
                    let target = parts.iter().fold(spec, |acc, p| &acc[*p]);
                    assert!(target.is_object(), "dangling $ref {r} at {at}");
                }
                for (k, x) in o {
                    walk(spec, x, &format!("{at}/{k}"));
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(spec, x, &format!("{at}/{i}"));
                }
            }
            _ => {}
        }
    }
    let spec = spec();
    walk(&spec, &spec, "");
}
