//! Contract tests: the OpenAPI document generated from the code (served at
//! /api/openapi.json, snapshot committed at docs/openapi.json) must describe
//! what the running server actually does.
//!
//! The document is generated from `#[utoipa::path]` annotations and
//! `ToSchema` types, so schemas follow the Rust types automatically; what
//! these tests still catch is everything the generator cannot know: status
//! codes a handler returns but its annotation does not list, `required` /
//! nullability attributes that disagree with serde, and examples the server
//! rejects.
//!
//! * `live_api_matches_spec` spawns the real binary, fetches the document it
//!   serves and calls every operation in it (iterating paths x methods),
//!   sending every request example the spec carries. Each response must have
//!   a documented status and a body that validates against the documented
//!   schema, checked STRICTLY: OpenAPI schemas are converted to JSON Schema
//!   with `$ref`/`allOf` inlined and `additionalProperties: false` on every
//!   object that lists `properties` (unless the spec explicitly allows
//!   extras). An undocumented field, a missing `required` field, a wrong type
//!   or an undocumented status all fail, with a hint naming what to change.
//! * `request_examples_match_request_schemas` / `response_examples_match_schemas`
//!   check the spec's own examples (from the committed snapshot) against its
//!   schemas (same strict rules), so an example with a misspelt field fails
//!   even if the server ignores it. The snapshot itself is kept equal to the
//!   code by the `snapshot_is_up_to_date` unit test in src/api/openapi.rs.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SPEC_SRC: &str = include_str!("../docs/openapi.json");
/// Where a spec-side fix goes: the annotation or type the document is generated from.
const SPEC_FILE: &str =
    "the API code (the handler's #[utoipa::path] annotation or the ToSchema type; docs/openapi.json is regenerated from them)";
const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

/// Request examples that are *expected* to be rejected, with the reason.
/// Every other example must get a 2xx at least once.
const EXPECTED_EXAMPLE_REJECTIONS: &[(&str, &str, &str)] = &[
    // (path, method, why)
    (
        "/auth/mfa",
        "post",
        "placeholder TOTP code 123456 -> 401 invalid code",
    ),
    (
        "/auth/enroll",
        "post",
        "placeholder TOTP code 123456 -> 401 invalid code",
    ),
    (
        "/me/mfa/confirm",
        "post",
        "placeholder TOTP code 123456 -> 401 invalid code",
    ),
    (
        "/me/mfa/disable",
        "post",
        "placeholder TOTP code 123456 -> 401 invalid code",
    ),
    (
        "/me/mfa/recovery",
        "post",
        "placeholder TOTP code 123456 -> 401 invalid code",
    ),
    (
        "/me/mfa/start",
        "post",
        "re-enrollment with the placeholder TOTP code 123456 -> 401 invalid code",
    ),
];

/// Operations that cannot be exercised over plain HTTP. Currently empty:
/// `/ws` is covered by a raw websocket handshake (101) plus an
/// unauthenticated call (401). Add `(path, method, reason)` entries only
/// with a written reason.
const COVERAGE_SKIPS: &[(&str, &str, &str)] = &[];

/// Operations driven by dedicated flows below because they change who is
/// signed in (login, MFA, sessions) or need a non-HTTP client (websocket).
/// Every other operation in the spec is exercised by the generic driver.
const DEDICATED: &[&str] = &[
    "login",
    "logout",
    "login_mfa",
    "login_enroll",
    "change_password",
    "mfa_start",
    "mfa_confirm",
    "mfa_disable",
    "mfa_regenerate_recovery",
    "revoke_my_session",
    "revoke_other_sessions",
    "websocket",
    // Needs a second server following this one (see the promotion flow).
    "promote_standby",
];

// ---------------------------------------------------------------------------
// OpenAPI -> strict JSON Schema
// ---------------------------------------------------------------------------

/// The committed snapshot (static checks).
fn spec() -> Value {
    serde_json::from_str(SPEC_SRC).expect("docs/openapi.json is valid JSON")
}

/// The document the running server serves (live checks).
fn served_spec(web: &str) -> Value {
    let r = ureq::get(&format!("http://{web}/api/openapi.json"))
        .call()
        .expect("GET /api/openapi.json");
    assert_eq!(r.content_type(), "application/json");
    serde_json::from_str(&r.into_string().unwrap()).expect("served spec is JSON")
}

fn ref_name<'a>(r: &'a str, section: &str) -> &'a str {
    r.strip_prefix(&format!("#/components/{section}/"))
        .unwrap_or_else(|| panic!("unsupported $ref '{r}' (expected #/components/{section}/...)"))
}

/// Follow a `$ref` to components/schemas, returning (name, raw schema).
fn deref_schema<'a>(spec: &'a Value, s: &'a Value) -> (Option<String>, &'a Value) {
    match s.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = ref_name(r, "schemas");
            let target = &spec["components"]["schemas"][name];
            assert!(target.is_object(), "dangling $ref {r}");
            let (inner, t) = deref_schema(spec, target);
            (Some(inner.unwrap_or_else(|| name.to_string())), t)
        }
        None => (None, s),
    }
}

/// Merge the parts of an `allOf` into one raw OpenAPI object schema.
fn merge_all_of(spec: &Value, parts: &[Value]) -> Map<String, Value> {
    let mut props = Map::new();
    let mut required: Vec<Value> = Vec::new();
    let mut extra: Option<Value> = None;
    for p in parts {
        let (_, raw) = deref_schema(spec, p);
        let raw = match raw.get("allOf").and_then(Value::as_array) {
            Some(inner) => Value::Object(merge_all_of(spec, inner)),
            None => raw.clone(),
        };
        if let Some(ps) = raw.get("properties").and_then(Value::as_object) {
            for (k, v) in ps {
                props.insert(k.clone(), v.clone());
            }
        }
        for r in raw
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !required.contains(r) {
                required.push(r.clone());
            }
        }
        if let Some(a) = raw.get("additionalProperties") {
            extra = Some(a.clone());
        }
    }
    let mut out = Map::new();
    out.insert("type".into(), json!("object"));
    out.insert("properties".into(), Value::Object(props));
    if !required.is_empty() {
        out.insert("required".into(), Value::Array(required));
    }
    if let Some(a) = extra {
        out.insert("additionalProperties".into(), a);
    }
    out
}

/// Convert an OpenAPI schema to a self-contained, strict JSON Schema. OpenAPI
/// 3.1 schemas are JSON Schema already (nullable values are `type` unions or
/// `oneOf` with `{"type": "null"}`); 3.0 `nullable` is still understood.
/// Named component schemas are tagged with `x-schema` so failures can say
/// which schema to edit.
fn convert(spec: &Value, s: &Value, stack: &mut Vec<String>) -> Value {
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let name = ref_name(r, "schemas").to_string();
        assert!(
            !stack.contains(&name),
            "recursive schema {name} is not supported"
        );
        stack.push(name.clone());
        let mut out = convert(spec, &spec["components"]["schemas"][&name], stack);
        stack.pop();
        if let Some(o) = out.as_object_mut() {
            o.entry("x-schema").or_insert(json!(name));
        }
        return out;
    }
    let Some(m) = s.as_object() else {
        return s.clone();
    };
    if let Some(all) = m.get("allOf").and_then(Value::as_array) {
        let mut merged = merge_all_of(spec, all);
        for (k, v) in m {
            if k != "allOf" {
                merged.insert(k.clone(), v.clone());
            }
        }
        return convert(spec, &Value::Object(merged), stack);
    }
    let mut out = Map::new();
    for (k, v) in m {
        match k.as_str() {
            // OpenAPI-only annotations.
            "example" | "nullable" | "discriminator" | "xml" | "externalDocs" | "readOnly"
            | "writeOnly" | "deprecated" => {}
            "properties" => {
                let props: Map<String, Value> = v
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(pk, pv)| (pk.clone(), convert(spec, pv, stack)))
                    .collect();
                out.insert(k.clone(), Value::Object(props));
            }
            "items" | "not" => {
                out.insert(k.clone(), convert(spec, v, stack));
            }
            "additionalProperties" if v.is_object() => {
                out.insert(k.clone(), convert(spec, v, stack));
            }
            "anyOf" | "oneOf" => {
                let parts: Vec<Value> = v
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| convert(spec, p, stack))
                    .collect();
                out.insert(k.clone(), Value::Array(parts));
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    if m.get("nullable") == Some(&Value::Bool(true)) {
        if let Some(t) = m.get("type").and_then(Value::as_str) {
            out.insert("type".into(), json!([t, "null"]));
        }
        if let Some(Value::Array(e)) = out.get_mut("enum") {
            if !e.contains(&Value::Null) {
                e.push(Value::Null);
            }
        }
    }
    if m.contains_key("properties") && !m.contains_key("additionalProperties") {
        out.insert("additionalProperties".into(), json!(false));
    }
    Value::Object(out)
}

fn strict_schema(spec: &Value, openapi_schema: &Value) -> Value {
    convert(spec, openapi_schema, &mut Vec::new())
}

/// Walk a schema along a JSON pointer, returning the nearest named schema
/// and the pointer relative to it.
fn locate(schema: &Value, pointer: &str) -> (Option<String>, String) {
    let mut name = schema
        .get("x-schema")
        .and_then(Value::as_str)
        .map(String::from);
    let mut rel = String::new();
    let mut cur = schema;
    for seg in pointer.split('/').filter(|s| !s.is_empty()) {
        let seg = seg.replace("~1", "/").replace("~0", "~");
        let next = match cur {
            Value::Object(o) => o.get(&seg),
            Value::Array(a) => seg.parse::<usize>().ok().and_then(|i| a.get(i)),
            _ => None,
        };
        let Some(next) = next else { break };
        cur = next;
        if let Some(n) = cur.get("x-schema").and_then(Value::as_str) {
            name = Some(n.to_string());
            rel.clear();
        } else {
            rel.push('/');
            rel.push_str(&seg);
        }
    }
    (name, rel)
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 300 {
        format!("{}...", &s[..300])
    } else {
        s
    }
}

/// Validate `instance` against a strict schema; return actionable messages.
fn validate(schema: &Value, instance: &Value, where_: &str) -> Vec<String> {
    let validator = match jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .should_validate_formats(true)
        .build(schema)
    {
        Ok(v) => v,
        Err(e) => return vec![format!("{where_}: schema does not compile: {e}")],
    };
    let mut out = Vec::new();
    for err in validator.iter_errors(instance) {
        let ptr = err.instance_path().as_str().to_string();
        let ptr = if ptr.is_empty() { "/".to_string() } else { ptr };
        let schema_ptr = err.schema_path().as_str().to_string();
        // The keyword itself is the last segment; locate its owning schema.
        let owner_ptr = schema_ptr.rsplit_once('/').map(|x| x.0).unwrap_or("");
        let (name, rel) = locate(schema, owner_ptr);
        let loc = match (&name, rel.is_empty()) {
            (Some(n), true) => format!("components.schemas.{n}"),
            (Some(n), false) => format!("components.schemas.{n} (at schema path {rel})"),
            (None, _) => format!(
                "the inline schema at {}",
                if rel.is_empty() { "/" } else { &rel }
            ),
        };
        use jsonschema::error::ValidationErrorKind as K;
        let hint = match err.kind() {
            K::AdditionalProperties { unexpected } => format!(
                "add propert{} {} to {loc} in {SPEC_FILE} (returned/sent but not documented)",
                if unexpected.len() == 1 { "y" } else { "ies" },
                unexpected.iter().map(|u| format!("'{u}'")).collect::<Vec<_>>().join(", ")
            ),
            K::Required { property } => format!(
                "required property {property} of {loc} is missing: if the field is genuinely optional (`skip_serializing_if`), give it `#[schema(nullable = false)]` instead of `required = true` in {SPEC_FILE}, otherwise the code is wrong"
            ),
            K::Type { .. } => format!(
                "type mismatch against {loc}: fix the field type or `value_type` in {SPEC_FILE} (null needs an Option<T>; `required = true` if it is always serialized) or fix the code"
            ),
            K::Enum { options } => format!(
                "value not in enum {options} of {loc}: add the variant to the Rust enum (or `value_type` enum) in {SPEC_FILE} or fix the code"
            ),
            K::Format { format } => format!(
                "value is not a valid '{format}' as declared by {loc}"
            ),
            _ => format!("constraint of {loc} violated"),
        };
        out.push(format!(
            "{where_}\n      at JSON pointer {ptr}: {err}\n      offending value: {}\n      hint: {hint}",
            short(err.instance().as_ref())
        ));
    }
    out
}

type Presence = BTreeMap<String, (usize, BTreeMap<String, usize>, BTreeSet<String>)>;

/// Record which documented properties appear in a response object.
fn observe(schema: &Value, inst: &Value, key: &str, stats: &mut Presence) {
    let key = match schema.get("x-schema").and_then(Value::as_str) {
        Some(n) => n.to_string(),
        None => key.to_string(),
    };
    match inst {
        Value::Object(o) => {
            let Some(props) = schema.get("properties").and_then(Value::as_object) else {
                return;
            };
            let e = stats.entry(key.clone()).or_default();
            e.0 += 1;
            for r in schema["required"].as_array().into_iter().flatten() {
                e.2.insert(r.as_str().unwrap_or_default().to_string());
            }
            for p in props.keys() {
                *e.1.entry(p.clone()).or_default() += usize::from(o.contains_key(p));
            }
            for (p, ps) in props {
                if let Some(v) = o.get(p) {
                    observe(ps, v, &format!("{key}.{p}"), stats);
                }
            }
        }
        Value::Array(a) => {
            if let Some(items) = schema.get("items") {
                for v in a {
                    observe(items, v, &format!("{key}[]"), stats);
                }
            }
        }
        _ => {}
    }
}

/// Properties that were present every time but are not `required`.
/// Names of component schemas reachable from any request body. Those also
/// describe input, where optional fields are genuinely optional.
fn request_schema_names(spec: &Value) -> BTreeSet<String> {
    fn walk(spec: &Value, v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(o) => {
                if let Some(r) = o.get("$ref").and_then(Value::as_str) {
                    if let Some(n) = r.strip_prefix("#/components/schemas/") {
                        if out.insert(n.to_string()) {
                            walk(spec, &spec["components"]["schemas"][n], out);
                        }
                    }
                }
                o.values().for_each(|x| walk(spec, x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(spec, x, out)),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    for (path, method) in spec_ops(spec) {
        if let Some(rb) = spec["paths"][&path][&method].get("requestBody") {
            walk(spec, &rb["content"], &mut out);
        }
    }
    out
}

fn always_present_optional(spec: &Value, stats: &Presence) -> Vec<String> {
    let shared = request_schema_names(spec);
    let mut out = Vec::new();
    for (key, (seen, props, required)) in stats {
        if shared.contains(key.split(['.', '[']).next().unwrap_or("")) {
            continue;
        }
        for (p, n) in props {
            if n == seen && !required.contains(p) {
                out.push(format!("{key}.{p} (present in {n}/{seen})"));
            }
        }
    }
    out
}

fn spec_ops(spec: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("paths") {
        for m in METHODS {
            if item.get(m).is_some() {
                out.push((path.clone(), m.to_string()));
            }
        }
    }
    out
}

fn resolve<'a>(spec: &'a Value, v: &'a Value, section: &str) -> &'a Value {
    match v.get("$ref").and_then(Value::as_str) {
        Some(r) => &spec["components"][section][ref_name(r, section)],
        None => v,
    }
}

/// (name, media type, value) for every request-body example of an operation.
fn request_examples(spec: &Value, op: &Value) -> Vec<(String, String, Value)> {
    let mut out = Vec::new();
    let Some(rb) = op.get("requestBody") else {
        return out;
    };
    let rb = resolve(spec, rb, "requestBodies");
    for (media, c) in rb["content"].as_object().into_iter().flatten() {
        if let Some(e) = c.get("example") {
            out.push(("example".to_string(), media.clone(), e.clone()));
        }
        for (name, e) in c
            .get("examples")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let e = resolve(spec, e, "examples");
            out.push((name.clone(), media.clone(), e["value"].clone()));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Static checks on the spec's own examples
// ---------------------------------------------------------------------------

#[test]
fn request_examples_match_request_schemas() {
    let spec = spec();
    let mut failures = Vec::new();
    let mut n = 0;
    for (path, method) in spec_ops(&spec) {
        let op = &spec["paths"][&path][&method];
        let Some(rb) = op.get("requestBody") else {
            continue;
        };
        let rb = resolve(&spec, rb, "requestBodies");
        for (name, media, value) in request_examples(&spec, op) {
            n += 1;
            let schema = strict_schema(&spec, &rb["content"][&media]["schema"]);
            failures.extend(validate(
                &schema,
                &value,
                &format!(
                    "request example '{name}' of {} {path} ({media})",
                    method.to_uppercase()
                ),
            ));
        }
        // Schema-level examples of request schemas, too.
        for (media, c) in rb["content"].as_object().into_iter().flatten() {
            let (sname, raw) = deref_schema(&spec, &c["schema"]);
            if let Some(ex) = raw.get("example") {
                n += 1;
                let schema = strict_schema(&spec, &c["schema"]);
                failures.extend(validate(
                    &schema,
                    ex,
                    &format!(
                        "schema example of {} (request of {} {path}, {media})",
                        sname.unwrap_or_default(),
                        method.to_uppercase()
                    ),
                ));
            }
        }
    }
    assert!(n > 10, "too few request examples found ({n})");
    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

#[test]
fn response_examples_match_schemas() {
    let spec = spec();
    let mut failures = Vec::new();
    // Examples on component schemas.
    for (name, raw) in spec["components"]["schemas"].as_object().unwrap() {
        if let Some(ex) = raw.get("example") {
            let schema = strict_schema(
                &spec,
                &json!({ "$ref": format!("#/components/schemas/{name}") }),
            );
            failures.extend(validate(
                &schema,
                ex,
                &format!("example of components.schemas.{name}"),
            ));
        }
    }
    // Examples on response media types.
    for (path, method) in spec_ops(&spec) {
        let op = &spec["paths"][&path][&method];
        for (status, r) in op["responses"].as_object().unwrap() {
            let r = resolve(&spec, r, "responses");
            for (media, c) in r
                .get("content")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                if let Some(ex) = c.get("example") {
                    let schema = strict_schema(&spec, &c["schema"]);
                    failures.extend(validate(
                        &schema,
                        ex,
                        &format!(
                            "response example of {} {path} -> {status} ({media})",
                            method.to_uppercase()
                        ),
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

#[test]
fn strict_conversion_rejects_undocumented_fields() {
    let spec = spec();
    let schema = strict_schema(&spec, &json!({ "$ref": "#/components/schemas/Error" }));
    assert!(validate(&schema, &json!({ "error": "x", "code": null }), "ok").is_empty());
    let errs = validate(
        &schema,
        &json!({ "error": "x", "code": null, "extra": 1 }),
        "extra",
    );
    assert!(
        errs.len() == 1 && errs[0].contains("add property 'extra' to components.schemas.Error"),
        "{errs:?}"
    );
    let errs = validate(&schema, &json!({ "error": "x" }), "missing");
    assert!(errs.len() == 1 && errs[0].contains("\"code\""), "{errs:?}");
    // allOf is merged, not intersected: fields of both parts are allowed, others are not.
    let schema = strict_schema(
        &spec,
        &json!({ "allOf": [
            { "$ref": "#/components/schemas/ImportSummary" },
            { "type": "object", "required": ["skipped"], "properties": { "skipped": { "type": "array", "items": { "type": "string" } } } }
        ] }),
    );
    let ok = json!({ "zones_created": 0, "zones_updated": 1, "records_added": 0, "records_removed": 0, "records_skipped": 0, "skipped": [] });
    assert!(validate(&schema, &ok, "allOf").is_empty());
    let mut bad = ok.clone();
    bad["surprise"] = json!(true);
    assert_eq!(validate(&schema, &bad, "allOf").len(), 1);
    // nullable becomes a type union; formats are checked.
    let schema = strict_schema(&spec, &json!({ "$ref": "#/components/schemas/TokenInfo" }));
    let tok = json!({ "id": 1, "user_id": 1, "name": "t", "tags": [], "created_at": "2026-01-15T09:30:00.000Z", "last_used_at": null, "last_used_ip": null, "revoked_at": null });
    assert!(validate(&schema, &tok, "nullable").is_empty());
    let mut bad = tok.clone();
    bad["created_at"] = json!("yesterday");
    assert_eq!(validate(&schema, &bad, "format").len(), 1);
    bad["created_at"] = json!(null);
    assert_eq!(validate(&schema, &bad, "not nullable").len(), 1);
}

// ---------------------------------------------------------------------------
// Live server
// ---------------------------------------------------------------------------

struct Server {
    child: Child,
    web: String,
    dir: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn start() -> Server {
    start_with("")
}

/// A server whose config has `extra` appended (e.g. a `[follow]` section).
fn start_with(extra: &str) -> Server {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("rust-dns-contract-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dns_port = free_port();
    let web_port = free_port();
    let cfg = format!(
        r#"
[server]
bind = ["127.0.0.1"]
port = {dns_port}
[rate_limit]
max_resolutions_per_second_per_address = 0
[transfer]
allow = ["127.0.0.0/8"]
[database]
path = "{db}"
[web_console]
bind = "127.0.0.1:{web_port}"
login_attempts_per_minute = 10000
# The flow sends many deliberately wrong passwords and codes.
login_backoff_after = 100000
# totp() may idle up to 30 s waiting for a fresh time step; keep pooled
# keep-alive connections open across that wait.
request_header_timeout_secs = 300
[root]
username = "root"
password = "rootpass123"
[logging]
level = "warn"
[backup]
dir = ""
{extra}
"#,
        db = dir.join("test.db").display()
    );
    let cfg_path = dir.join("test.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn rust-dns");
    let web = format!("127.0.0.1:{web_port}");
    let srv = Server { child, web, dir };
    let deadline = Instant::now() + Duration::from_secs(15);
    while ureq::get(&format!("http://{}/api/health", srv.web))
        .timeout(Duration::from_millis(500))
        .call()
        .is_err()
    {
        assert!(Instant::now() < deadline, "server did not come up");
        std::thread::sleep(Duration::from_millis(100));
    }
    srv
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build()
}

/// Minimal RFC 6238 TOTP (SHA-1, 30 s, 6 digits). The server refuses a
/// code whose time step is not later than the last one it accepted
/// (replay protection), so each call gets the next unused step of the
/// three the server accepts (previous, current, next), waiting for the
/// next 30-second window when all three are used.
fn totp(secret_b32: &str) -> String {
    use hmac::{Hmac, Mac};
    static LAST: std::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
        std::sync::Mutex::new(None);
    let key = data_encoding::BASE32_NOPAD
        .decode(secret_b32.trim_end_matches('=').as_bytes())
        .unwrap();
    let step = loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let cur = now.as_secs() / 30;
        let mut g = LAST.lock().unwrap();
        let last = g
            .get_or_insert_with(Default::default)
            .get(secret_b32)
            .copied();
        let next = match last {
            None => cur - 1,
            Some(l) => (l + 1).max(cur - 1),
        };
        if next <= cur + 1 {
            g.as_mut().unwrap().insert(secret_b32.to_string(), next);
            break next;
        }
        drop(g);
        let wait = 30 - now.as_secs() % 30;
        std::thread::sleep(Duration::from_millis(wait * 1000 + 200));
    };
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0xf) as usize;
    let bin = ((h[o] as u32 & 0x7f) << 24)
        | ((h[o + 1] as u32) << 16)
        | ((h[o + 2] as u32) << 8)
        | h[o + 3] as u32;
    format!("{:06}", bin % 1_000_000)
}

#[derive(Clone, Copy)]
enum Auth<'a> {
    /// Cookie session, with the CSRF header on writes.
    Session(&'a ureq::Agent),
    /// Cookie session without the CSRF header.
    NoCsrf(&'a ureq::Agent),
    Bearer(&'a str),
    Anon,
}

enum Body<'a> {
    None,
    Json(&'a Value),
    Text(&'a str),
}

struct Resp {
    status: u16,
    ctype: String,
    text: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
}

struct Contract {
    spec: Value,
    web: String,
    /// Path params by key: "zone", "username", "<collection>.id".
    ctx: HashMap<String, String>,
    /// (path, method) -> statuses seen that were documented.
    hits: BTreeMap<(String, String), BTreeSet<u16>>,
    /// (path, method, media, example name) -> statuses.
    examples: BTreeMap<(String, String, String, String), Vec<u16>>,
    failures: Vec<String>,
    calls: usize,
    /// schema key -> (objects seen, property -> times present). Used to spot
    /// properties the code always returns but the spec leaves optional.
    presence: Presence,
}

impl Contract {
    fn op(&self, path: &str, method: &str) -> &Value {
        let op = &self.spec["paths"][path][method];
        assert!(
            op.is_object(),
            "{} {path} is not in the spec",
            method.to_uppercase()
        );
        op
    }

    fn op_id(&self, path: &str, method: &str) -> String {
        self.op(path, method)["operationId"]
            .as_str()
            .unwrap_or("?")
            .to_string()
    }

    fn base(&self, path: &str, method: &str) -> String {
        let item = &self.spec["paths"][path];
        let servers = [
            &item[method]["servers"],
            &item["servers"],
            &self.spec["servers"],
        ]
        .into_iter()
        .find(|s| s.as_array().is_some_and(|a| !a.is_empty()))
        .cloned()
        .unwrap_or(json!([{ "url": "/" }]));
        let url = servers[0]["url"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
            .to_string();
        format!("http://{}{url}", self.web)
    }

    fn param_key(path: &str, name: &str) -> String {
        if name != "id" {
            return name.to_string();
        }
        let segs: Vec<&str> = path.split('/').collect();
        let i = segs.iter().position(|s| *s == "{id}").unwrap();
        format!("{}.id", segs[i - 1])
    }

    /// Substitute path params from `overrides`, falling back to the context.
    fn fill(&mut self, path: &str, overrides: &[(&str, String)]) -> Option<String> {
        let mut out = String::new();
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            out.push('/');
            match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => {
                    let v = overrides
                        .iter()
                        .find(|(k, _)| *k == name)
                        .map(|(_, v)| v.clone())
                        .or_else(|| self.ctx.get(&Self::param_key(path, name)).cloned());
                    match v {
                        Some(v) => out.push_str(&v),
                        None => {
                            self.failures.push(format!(
                                "{path}: api_contract does not know how to fill path parameter {{{name}}} (context key '{}'); create the object first or teach Contract::capture about it",
                                Self::param_key(path, name)
                            ));
                            return None;
                        }
                    }
                }
                None => out.push_str(seg),
            }
        }
        Some(out)
    }

    /// Perform one call and check it against the spec.
    fn call(
        &mut self,
        auth: Auth,
        method: &str,
        path: &str,
        params: &[(&str, String)],
        query: &str,
        body: Body,
    ) -> Resp {
        let Some(concrete) = self.fill(path, params) else {
            return Resp {
                status: 0,
                ctype: String::new(),
                text: String::new(),
            };
        };
        let mut url = format!("{}{concrete}", self.base(path, method));
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let anon = agent();
        let (a, csrf, bearer) = match auth {
            Auth::Session(a) => (a, true, None),
            Auth::NoCsrf(a) => (a, false, None),
            Auth::Bearer(t) => (&anon, false, Some(t)),
            Auth::Anon => (&anon, false, None),
        };
        let mut req = a.request(&method.to_uppercase(), &url);
        // Documented header parameters get their example value.
        let op = self.op(path, method).clone();
        for p in op["parameters"].as_array().into_iter().flatten() {
            let p = resolve(&self.spec, p, "parameters");
            if p["in"] == "header" {
                if let Some(ex) = p["example"].as_str().or(p["schema"]["example"].as_str()) {
                    req = req.set(p["name"].as_str().unwrap(), ex);
                }
            }
        }
        if csrf {
            req = req.set("X-Requested-With", "rust-dns");
        }
        if let Some(t) = bearer {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let res = match body {
            Body::None => req.call(),
            Body::Json(v) => req
                .set("Content-Type", "application/json")
                .send_string(&v.to_string()),
            Body::Text(t) => req.set("Content-Type", "text/plain").send_string(t),
        };
        let r = match res {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{} {url}: transport error {e}", method.to_uppercase()),
        };
        let resp = Resp {
            status: r.status(),
            ctype: r.header("content-type").unwrap_or("").to_string(),
            text: r.into_string().unwrap_or_default(),
        };
        self.calls += 1;
        self.check(method, path, &resp);
        resp
    }

    fn check(&mut self, method: &str, path: &str, resp: &Resp) {
        let op = self.op(path, method).clone();
        let label = format!(
            "[{}] {} {path} -> {}",
            self.op_id(path, method),
            method.to_uppercase(),
            resp.status
        );
        let responses = &op["responses"];
        let key = resp.status.to_string();
        let r = match responses.get(&key).or_else(|| responses.get("default")) {
            Some(r) => r,
            None => {
                self.failures.push(format!(
                    "{label}: code returned undocumented status {}\n      body: {}\n      hint: add response '{key}' to paths.\"{path}\".{method}.responses in {SPEC_FILE} (documented: {:?}), or fix the code",
                    resp.status,
                    short(&Value::String(resp.text.clone())),
                    responses.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()
                ));
                return;
            }
        };
        self.hits
            .entry((path.to_string(), method.to_string()))
            .or_default()
            .insert(resp.status);
        let r = resolve(&self.spec, r, "responses").clone();
        let Some(content) = r.get("content").and_then(Value::as_object) else {
            return;
        };
        let media = resp
            .ctype
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let Some(c) = content.get(&media) else {
            self.failures.push(format!(
                "{label}: response Content-Type '{}' is not documented (spec has {:?})\n      hint: add '{media}' under paths.\"{path}\".{method}.responses.{key}.content in {SPEC_FILE}, or fix the code",
                resp.ctype,
                content.keys().collect::<Vec<_>>()
            ));
            return;
        };
        let schema = strict_schema(&self.spec, &c["schema"]);
        let instance = if media == "application/json" {
            match serde_json::from_str::<Value>(&resp.text) {
                Ok(v) => v,
                Err(e) => {
                    self.failures.push(format!(
                        "{label}: body is not JSON ({e}): {}",
                        short(&Value::String(resp.text.clone()))
                    ));
                    return;
                }
            }
        } else {
            Value::String(resp.text.clone())
        };
        let errs = validate(
            &schema,
            &instance,
            &format!("{label}: response body does not match the documented schema"),
        );
        self.failures.extend(errs);
        observe(&schema, &instance, &label, &mut self.presence);
    }

    /// Send one named request example.
    fn send_example(
        &mut self,
        auth: Auth,
        method: &str,
        path: &str,
        params: &[(&str, String)],
        query: &str,
        (name, media, value): &(String, String, Value),
    ) -> Resp {
        let resp = if media == "application/json" {
            self.call(auth, method, path, params, query, Body::Json(value))
        } else {
            let text = value
                .as_str()
                .expect("non-JSON example must be a string")
                .to_string();
            self.call(auth, method, path, params, query, Body::Text(&text))
        };
        if resp.status != 0 {
            self.examples
                .entry((
                    path.to_string(),
                    method.to_string(),
                    media.clone(),
                    name.clone(),
                ))
                .or_default()
                .push(resp.status);
        }
        resp
    }

    /// The single example of an operation (panics if there is not exactly one).
    fn example(&self, path: &str, method: &str) -> (String, String, Value) {
        let mut ex = request_examples(&self.spec, self.op(path, method));
        assert_eq!(
            ex.len(),
            1,
            "{method} {path}: expected exactly one request example"
        );
        ex.remove(0)
    }

    /// Remember ids of created objects so later calls can use them.
    fn capture(&mut self, path: &str, resp: &Resp) {
        if !(200..300).contains(&resp.status) {
            return;
        }
        let v = resp.json();
        let item = self.spec["paths"]
            .as_object()
            .unwrap()
            .keys()
            .find(|p| {
                p.starts_with(&format!("{path}/{{")) && p[path.len() + 1..].find('/').is_none()
            })
            .cloned();
        let Some(item) = item else { return };
        let param = &item[path.len() + 2..item.len() - 1];
        let key = Self::param_key(&item, param);
        if self.ctx.contains_key(&key) {
            return; // keep the first object created
        }
        let value = match param {
            "id" => v["id"]
                .as_i64()
                .or_else(|| v["info"]["id"].as_i64())
                .map(|i| i.to_string()),
            other => v
                .get(other)
                .or_else(|| v.get("name"))
                .and_then(Value::as_str)
                .map(String::from),
        };
        if let Some(value) = value {
            self.ctx.insert(key, value);
        }
        if path == "/users" {
            if let Some(u) = v["username"].as_str() {
                self.ctx.insert("username".into(), u.to_string());
            }
        }
        if path == "/tokens" {
            if let Some(t) = v["token"].as_str() {
                self.ctx.insert("token".into(), t.to_string());
            }
        }
    }

    fn login(&mut self, a: &ureq::Agent, user: &str, pass: &str) -> Value {
        let r = self.call(
            Auth::Session(a),
            "post",
            "/auth/login",
            &[],
            "",
            Body::Json(&json!({ "username": user, "password": pass })),
        );
        self.expect(&format!("login as {user}"), &r, 200);
        r.json()
    }

    fn expect(&mut self, what: &str, resp: &Resp, want: u16) {
        if resp.status != want {
            self.failures.push(format!(
                "{what}: expected status {want}, got {} (body {})",
                resp.status,
                short(&Value::String(resp.text.clone()))
            ));
        }
    }
}

/// Order for the generic driver: creates first, then reads, updates, other
/// actions, and deletes last (deepest paths first).
/// A POST to a collection that has an item path (`/x` with `/x/{id}`) creates.
fn rank(spec: &Value, path: &str, method: &str) -> (u8, i64, String) {
    let depth = path.split('/').filter(|s| !s.is_empty()).count() as i64;
    let creates = spec["paths"]
        .as_object()
        .unwrap()
        .keys()
        .any(|p| p.starts_with(&format!("{path}/{{")));
    let r = match method {
        "post" if creates => 0,
        "get" => 1,
        "put" | "patch" => 2,
        "delete" => 4,
        _ => 3,
    };
    (r, if r == 4 { -depth } else { depth }, path.to_string())
}

/// For GETs: one query string per value of each enum/boolean query parameter.
fn query_variants(spec: &Value, path: &str, method: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let item = &spec["paths"][path];
    let params = [&item["parameters"], &item[method]["parameters"]];
    for p in params.iter().filter_map(|p| p.as_array()).flatten() {
        let p = resolve(spec, p, "parameters");
        if p["in"] != "query" {
            continue;
        }
        let name = p["name"].as_str().unwrap();
        let values: Vec<String> = match (&p["schema"]["enum"], p["schema"]["type"].as_str()) {
            (Value::Array(e), _) => e
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            (_, Some("boolean")) => vec!["true".into(), "false".into()],
            _ => vec![],
        };
        out.extend(values.into_iter().map(|v| format!("{name}={v}")));
    }
    out
}

/// Websocket handshake by hand (ureq cannot upgrade); returns the HTTP status.
fn ws_handshake(web: &str, path_and_query: &str) -> u16 {
    let mut s = std::net::TcpStream::connect(web).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path_and_query} HTTP/1.1\r\nHost: {web}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

#[test]
fn live_api_matches_spec() {
    let srv = start();
    let mut c = Contract {
        spec: served_spec(&srv.web),
        web: srv.web.clone(),
        ctx: HashMap::new(),
        hits: BTreeMap::new(),
        examples: BTreeMap::new(),
        failures: Vec::new(),
        calls: 0,
        presence: BTreeMap::new(),
    };
    let root = agent();

    // ---- sign in as root with the spec's own login example ------------------
    let ex = c.example("/auth/login", "post");
    let r = c.send_example(Auth::Session(&root), "post", "/auth/login", &[], "", &ex);
    assert_eq!(
        r.status, 200,
        "root login with the spec example failed: {}",
        r.text
    );
    assert_eq!(r.json()["status"], "ok");
    let me = c
        .call(Auth::Session(&root), "get", "/me", &[], "", Body::None)
        .json();
    let root_id = me["user"]["id"].as_i64().unwrap().to_string();
    // Replication requests carry the documented example instance id
    // (header parameter examples), so that replica exists.
    c.ctx.insert("replicas.id".into(), "dns2".into());

    // ---- generic driver: every non-dedicated operation, except deletes -------
    let mut ops: Vec<(String, String)> = spec_ops(&c.spec)
        .into_iter()
        .filter(|(p, m)| !DEDICATED.contains(&c.op_id(p, m).as_str()))
        .collect();
    ops.sort_by_key(|(p, m)| rank(&c.spec, p, m));
    let (deletes, others): (Vec<_>, Vec<_>) = ops
        .into_iter()
        .partition(|(p, m)| rank(&c.spec, p, m).0 == 4);
    let run_generic = |c: &mut Contract, path: &str, method: &str| {
        let op = c.op(path, method).clone();
        let examples = request_examples(&c.spec, &op);
        if !examples.is_empty() {
            for ex in &examples {
                let r = c.send_example(Auth::Session(&root), method, path, &[], "", ex);
                c.capture(path, &r);
            }
        } else if op.get("requestBody").is_some() {
            c.failures.push(format!(
                "{} {path}: has a requestBody but no example; add one so the contract test can send it",
                method.to_uppercase()
            ));
        } else {
            let variants = if method == "get" {
                query_variants(&c.spec, path, method)
            } else {
                vec![String::new()]
            };
            for q in variants {
                let r = c.call(Auth::Session(&root), method, path, &[], &q, Body::None);
                c.capture(path, &r);
            }
        }
    };
    for (path, method) in &others {
        run_generic(&mut c, path, method);
    }

    // ---- records: renewal (200) and duplicate (409) ---------------------------
    let rec_examples = request_examples(&c.spec, c.op("/zones/{zone}/records", "post"));
    if let Some(expiring) = rec_examples
        .iter()
        .find(|(_, _, v)| v.get("expires_in").is_some() || v.get("expires_at").is_some())
    {
        let r = c.send_example(
            Auth::Session(&root),
            "post",
            "/zones/{zone}/records",
            &[],
            "",
            expiring,
        );
        c.expect("re-sending an expiring record renews it", &r, 200);
    } else {
        c.failures.push("POST /zones/{zone}/records: no example with expires_in/expires_at (needed to exercise the 200 renewal)".into());
    }
    if let Some(plain) = rec_examples
        .iter()
        .find(|(_, _, v)| v.get("expires_in").is_none() && v.get("expires_at").is_none())
    {
        let r = c.send_example(
            Auth::Session(&root),
            "post",
            "/zones/{zone}/records",
            &[],
            "",
            plain,
        );
        c.expect("duplicate record", &r, 409);
    }

    // ---- DNSSEC: the PUT example turned signing on; the self-check now
    // succeeds. Turning it off is refused while the parent's DS cannot be
    // ruled out (no forwarding upstream here) and allowed with force.
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/zones/{zone}/dnssec/check",
        &[],
        "",
        Body::None,
    );
    c.expect("DNSSEC self-check once signing is on", &r, 200);
    if r.status == 200 && r.json()["ok"] != true {
        c.failures
            .push(format!("DNSSEC self-check did not pass: {}", r.text));
    }
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/zones/{zone}/dnssec",
        &[],
        "",
        Body::Json(&json!({ "enabled": false })),
    );
    c.expect(
        "turning DNSSEC off without a confirmed-absent parent DS",
        &r,
        409,
    );
    if r.status == 409 && r.json()["code"] != "ds_published" {
        c.failures
            .push(format!("expected code ds_published: {}", r.text));
    }
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/zones/{zone}/dnssec",
        &[],
        "",
        Body::Json(&json!({ "enabled": false, "force": true })),
    );
    c.expect("turning DNSSEC off with force", &r, 200);
    if r.status == 200 && (r.json()["enabled"] != false || r.json()["state"] != "off") {
        c.failures.push(format!("DNSSEC should be off: {}", r.text));
    }

    // ---- API token (bearer) --------------------------------------------------
    let token = c
        .ctx
        .get("token")
        .cloned()
        .expect("POST /tokens example created a token");
    let r = c.call(Auth::Bearer(&token), "get", "/me", &[], "", Body::None);
    c.expect("GET /me with a bearer token", &r, 200);
    if r.json()["via"] != "token" {
        c.failures.push(format!(
            "GET /me with a bearer token: via should be 'token': {}",
            r.text
        ));
    }
    let r = c.call(
        Auth::Bearer(&token),
        "post",
        "/me/mfa/start",
        &[],
        "",
        Body::None,
    );
    c.expect("MFA enrollment needs a session, not a token", &r, 403);
    let r = c.call(Auth::Anon, "get", "/auth/session", &[], "", Body::None);
    c.expect("anonymous session info", &r, 200);

    // ---- websocket -----------------------------------------------------------
    let r = c.call(Auth::Anon, "get", "/ws", &[], "", Body::None);
    c.expect("websocket without credentials", &r, 401);
    let ws_path = format!(
        "{}/ws?token={token}",
        c.base("/ws", "get")
            .trim_start_matches(&format!("http://{}", srv.web))
    );
    let status = ws_handshake(&srv.web, &ws_path);
    let fake = Resp {
        status,
        ctype: String::new(),
        text: String::new(),
    };
    c.check("get", "/ws", &fake);
    c.expect("websocket upgrade with ?token=", &fake, 101);

    // ---- password change: a non-root user whose password is the example's ---
    let ex = c.example("/me/password", "put");
    let current = ex.2["current_password"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/users",
        &[],
        "",
        Body::Json(&json!({ "username": "pwuser", "password": current })),
    );
    c.expect("create pwuser", &r, 201);
    let pw = agent();
    c.login(&pw, "pwuser", &current);
    let r = c.send_example(Auth::Session(&pw), "put", "/me/password", &[], "", &ex);
    c.expect("PUT /me/password with the spec example", &r, 200);
    let r = c.send_example(Auth::Session(&root), "put", "/me/password", &[], "", &ex);
    c.expect("root cannot change its password via the API", &r, 403);

    // ---- forced enrollment: the user from the POST /users example ------------
    // (the PUT /users/{id} example sets mfa_required).
    let user_ex = c.example("/users", "post").2;
    let (uname, upass) = (
        user_ex["username"].as_str().unwrap_or_default().to_string(),
        user_ex["password"].as_str().unwrap_or_default().to_string(),
    );
    let user_agent = agent();
    let lr = c.login(&user_agent, &uname, &upass);
    let secret = lr["enroll"]["secret"].as_str().map(String::from);
    if lr["status"] != "enroll_required" || secret.is_none() {
        c.failures.push(format!(
            "expected enroll_required for {uname} (PUT /users/{{id}} example should set mfa_required): {lr}"
        ));
    }
    let r = c.call(
        Auth::Session(&user_agent),
        "get",
        "/auth/session",
        &[],
        "",
        Body::None,
    );
    c.expect("session info while enrolling", &r, 200);
    let r = c.call(
        Auth::Session(&user_agent),
        "get",
        "/me",
        &[],
        "",
        Body::None,
    );
    c.expect("API use before enrollment", &r, 401);
    let ex = c.example("/auth/enroll", "post");
    c.send_example(
        Auth::Session(&user_agent),
        "post",
        "/auth/enroll",
        &[],
        "",
        &ex,
    );
    if let Some(secret) = &secret {
        let r = c.call(
            Auth::Session(&user_agent),
            "post",
            "/auth/enroll",
            &[],
            "",
            Body::Json(&json!({ "code": totp(secret) })),
        );
        c.expect("enroll with a valid TOTP", &r, 200);
    }

    // ---- voluntary MFA for root: start, confirm, recovery, login, disable -----
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/start",
        &[],
        "",
        Body::None,
    );
    c.expect("mfa start", &r, 200);
    let root_secret = r.json()["secret"].as_str().unwrap_or("").to_string();
    for p in ["/me/mfa/confirm", "/me/mfa/recovery"] {
        let ex = c.example(p, "post");
        c.send_example(Auth::Session(&root), "post", p, &[], "", &ex);
        let r = c.call(
            Auth::Session(&root),
            "post",
            p,
            &[],
            "",
            Body::Json(&json!({ "code": totp(&root_secret) })),
        );
        c.expect(&format!("POST {p} with a valid TOTP"), &r, 200);
    }
    // Replacing an enrolled authenticator needs the current factor (M6).
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/start",
        &[],
        "",
        Body::None,
    );
    c.expect("re-enrollment without the current factor", &r, 401);
    let ex = c.example("/me/mfa/start", "post");
    c.send_example(Auth::Session(&root), "post", "/me/mfa/start", &[], "", &ex);
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/start",
        &[],
        "",
        Body::Json(&json!({ "code": totp(&root_secret) })),
    );
    c.expect("re-enrollment with the current TOTP", &r, 200);
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/recovery",
        &[],
        "",
        Body::Json(&json!({ "code": totp(&root_secret) })),
    );
    let recovery = r.json()["recovery_codes"][0]
        .as_str()
        .unwrap_or("")
        .to_string();
    // Second step of login: example (rejected), TOTP, then a recovery code.
    let mfa = agent();
    let ex = c.example("/auth/login", "post");
    let lr = c.send_example(Auth::Session(&mfa), "post", "/auth/login", &[], "", &ex);
    if lr.json()["status"] != "mfa_required" {
        c.failures.push(format!(
            "root login after enrolling should be mfa_required: {}",
            lr.text
        ));
    }
    let r = c.call(
        Auth::Session(&mfa),
        "get",
        "/auth/session",
        &[],
        "",
        Body::None,
    );
    c.expect("session info while mfa pending", &r, 200);
    let ex = c.example("/auth/mfa", "post");
    c.send_example(Auth::Session(&mfa), "post", "/auth/mfa", &[], "", &ex);
    let r = c.call(
        Auth::Session(&mfa),
        "post",
        "/auth/mfa",
        &[],
        "",
        Body::Json(&json!({ "code": totp(&root_secret) })),
    );
    c.expect("mfa with TOTP", &r, 200);
    let r = c.call(
        Auth::Session(&mfa),
        "post",
        "/auth/mfa",
        &[],
        "",
        Body::Json(&json!({ "code": totp(&root_secret) })),
    );
    c.expect("mfa on an already active session", &r, 400);
    let mfa2 = agent();
    c.call(
        Auth::Session(&mfa2),
        "post",
        "/auth/login",
        &[],
        "",
        Body::Json(&ex_login(&c)),
    );
    let r = c.call(
        Auth::Session(&mfa2),
        "post",
        "/auth/mfa",
        &[],
        "",
        Body::Json(&json!({ "code": recovery })),
    );
    c.expect("mfa with a recovery code", &r, 200);
    let ex = c.example("/me/mfa/disable", "post");
    c.send_example(
        Auth::Session(&root),
        "post",
        "/me/mfa/disable",
        &[],
        "",
        &ex,
    );
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/disable",
        &[],
        "",
        Body::Json(&json!({ "code": totp(&root_secret) })),
    );
    c.expect("mfa disable with TOTP", &r, 200);
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/mfa/disable",
        &[],
        "",
        Body::Json(&json!({ "code": "000000" })),
    );
    c.expect("mfa disable when not enrolled", &r, 400);

    // ---- own sessions --------------------------------------------------------
    let other = agent();
    c.login(&other, "root", "rootpass123");
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/me/sessions",
        &[],
        "",
        Body::None,
    );
    let victim = r.json()["sessions"].as_array().and_then(|a| {
        a.iter()
            .find(|s| s["current"] == false)
            .map(|s| s["id"].to_string())
    });
    match victim {
        Some(id) => {
            let r = c.call(
                Auth::Session(&root),
                "delete",
                "/me/sessions/{id}",
                &[("id", id.clone())],
                "",
                Body::None,
            );
            c.expect("revoke one of my sessions", &r, 200);
            let r = c.call(
                Auth::Session(&root),
                "delete",
                "/me/sessions/{id}",
                &[("id", id)],
                "",
                Body::None,
            );
            c.expect("revoke it again", &r, 404);
        }
        None => c.failures.push("no other root session to revoke".into()),
    }
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/me/sessions/revoke-others",
        &[],
        "",
        Body::None,
    );
    c.expect("revoke other sessions", &r, 200);
    let r = c.call(Auth::Session(&other), "get", "/me", &[], "", Body::None);
    c.expect("a revoked session is signed out", &r, 401);

    // ---- documented error paths, at least one per tag ------------------------
    let na = [("zone", "no-such-zone.test".to_string())];
    // Auth
    let r = c.call(
        Auth::Anon,
        "post",
        "/auth/login",
        &[],
        "",
        Body::Json(&json!({ "username": "root", "password": "wrong-password" })),
    );
    c.expect("login with a wrong password", &r, 401);
    // Zones
    let r = c.call(Auth::Anon, "get", "/zones", &[], "", Body::None);
    c.expect("unauthenticated", &r, 401);
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/zones/{zone}",
        &na,
        "",
        Body::None,
    );
    c.expect("unknown zone", &r, 404);
    let ex = c.example("/zones", "post");
    let r = c.send_example(Auth::Session(&root), "post", "/zones", &[], "", &ex);
    c.expect("duplicate zone", &r, 409);
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/zones",
        &[],
        "",
        Body::Json(&json!({ "name": "bad..name" })),
    );
    c.expect("invalid zone name", &r, 400);
    let r = c.call(
        Auth::NoCsrf(&root),
        "post",
        "/zones",
        &[],
        "",
        Body::Json(&json!({ "name": "csrf.test" })),
    );
    c.expect("cookie write without X-Requested-With", &r, 403);
    if r.json()["code"] != "csrf" {
        c.failures.push(format!(
            "CSRF rejection should carry code 'csrf': {}",
            r.text
        ));
    }
    let r = c.call(
        Auth::Session(&user_agent),
        "put",
        "/zones/{zone}",
        &[],
        "",
        Body::Json(&json!({ "refresh": 7200 })),
    );
    c.expect("editor cannot change zone settings", &r, 403);
    // Records
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/zones/{zone}/records",
        &[],
        "",
        Body::Json(&json!({ "name": "bad", "type": "A", "value": "not-an-ip" })),
    );
    c.expect("invalid A record", &r, 400);
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/zones/{zone}/records",
        &na,
        "",
        Body::Json(&json!({ "type": "A", "value": "192.0.2.1" })),
    );
    c.expect("record in unknown zone", &r, 404);
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/zones/{zone}/records/{id}",
        &[("id", "999999".into())],
        "",
        Body::Json(&json!({ "value": "192.0.2.1" })),
    );
    c.expect("unknown record", &r, 404);
    // Access
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/zones/{zone}/members/{username}",
        &[],
        "",
        Body::Json(&json!({ "role": "owner" })),
    );
    c.expect("member role owner", &r, 400);
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/zones/{zone}/members/{username}",
        &[("username", "nobody".into())],
        "",
        Body::Json(&json!({ "role": "viewer" })),
    );
    c.expect("member unknown user", &r, 404);
    let r = c.call(
        Auth::Session(&user_agent),
        "get",
        "/users/{id}/rights",
        &[("id", root_id.clone())],
        "",
        Body::None,
    );
    c.expect("non-admin reading someone else's rights", &r, 403);
    // Import/Export
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/zones/{zone}/export",
        &[],
        "format=xml",
        Body::None,
    );
    c.expect("unknown export format", &r, 400);
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/zones/{zone}/export",
        &na,
        "",
        Body::None,
    );
    c.expect("export unknown zone", &r, 404);
    // Change log
    let r = c.call(
        Auth::Session(&user_agent),
        "get",
        "/audit",
        &[],
        "",
        Body::None,
    );
    c.expect("non-admin audit", &r, 403);
    let r = c.call(Auth::Anon, "get", "/changelog", &[], "", Body::None);
    c.expect("unauthenticated changelog", &r, 401);
    // Users
    let r = c.call(
        Auth::Session(&user_agent),
        "get",
        "/users",
        &[],
        "",
        Body::None,
    );
    c.expect("non-admin list users", &r, 403);
    let ex = c.example("/users", "post");
    let r = c.send_example(Auth::Session(&root), "post", "/users", &[], "", &ex);
    c.expect("duplicate user", &r, 409);
    let r = c.call(
        Auth::Session(&root),
        "delete",
        "/users/{id}",
        &[("id", root_id.clone())],
        "",
        Body::None,
    );
    c.expect("delete yourself", &r, 400);
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/users/{id}",
        &[("id", "999999".into())],
        "",
        Body::Json(&json!({ "display_name": "x" })),
    );
    c.expect("update unknown user", &r, 404);
    // Tokens
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/tokens",
        &[],
        "",
        Body::Json(&json!({ "name": "  " })),
    );
    c.expect("empty token name", &r, 400);
    let r = c.call(
        Auth::Session(&root),
        "delete",
        "/tokens/{id}",
        &[("id", "999999".into())],
        "",
        Body::None,
    );
    c.expect("unknown token", &r, 404);
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/tokens/{id}",
        &[("id", "999999".into())],
        "",
        Body::Json(&json!({ "tags": ["ci"] })),
    );
    c.expect("update unknown token", &r, 404);
    let r = c.call(
        Auth::Session(&root),
        "put",
        "/tokens/{id}",
        &[],
        "",
        Body::Json(&json!({ "tags": ["not valid!"] })),
    );
    c.expect("invalid token tag", &r, 400);
    // The tag filter finds the token created (and re-tagged) by the examples.
    let tagged = c.example("/tokens/{id}", "put").2["tags"][0]
        .as_str()
        .unwrap()
        .to_string();
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/tokens",
        &[],
        &format!("tag={tagged}"),
        Body::None,
    );
    c.expect("list tokens by tag", &r, 200);
    let token_id = c.ctx.get("tokens.id").cloned().unwrap_or_default();
    let listed = r.json()["tokens"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["id"].as_i64().is_some_and(|i| i.to_string() == token_id))
        .cloned();
    match listed {
        None => c.failures.push(format!(
            "GET /tokens?tag={tagged}: expected token {token_id} (tagged by the PUT /tokens/{{id}} example): {}",
            r.text
        )),
        // It was used as a bearer token above, from loopback.
        Some(t) if t["last_used_ip"] != "127.0.0.1" || !t["last_used_at"].is_string() => {
            c.failures.push(format!(
                "token {token_id}: last_used_at/last_used_ip not recorded after bearer use: {t}"
            ))
        }
        _ => {}
    }
    let r = c.call(
        Auth::Session(&root),
        "get",
        "/tokens",
        &[],
        "tag=no-such-tag",
        Body::None,
    );
    c.expect("list tokens by unused tag", &r, 200);
    if r.json()["tokens"].as_array().is_none_or(|t| !t.is_empty()) {
        c.failures.push(format!(
            "GET /tokens?tag=no-such-tag should be empty: {}",
            r.text
        ));
    }
    // Server
    let r = c.call(
        Auth::Session(&user_agent),
        "post",
        "/admin/reload",
        &[],
        "",
        Body::None,
    );
    c.expect("non-admin reload", &r, 403);
    let r = c.call(Auth::Anon, "get", "/status", &[], "", Body::None);
    c.expect("unauthenticated status", &r, 401);
    let r = c.call(Auth::Anon, "get", "/metrics", &[], "", Body::None);
    c.expect("unauthenticated metrics", &r, 401);

    // ---- deletes, deepest first ----------------------------------------------
    for (path, method) in &deletes {
        run_generic(&mut c, path, method);
    }

    // ---- logout --------------------------------------------------------------
    let r = c.call(
        Auth::Session(&root),
        "post",
        "/auth/logout",
        &[],
        "",
        Body::None,
    );
    c.expect("logout", &r, 200);
    let r = c.call(Auth::Session(&root), "get", "/me", &[], "", Body::None);
    c.expect("signed out after logout", &r, 401);
    let r = c.call(Auth::Anon, "post", "/auth/logout", &[], "", Body::None);
    c.expect("anonymous logout", &r, 200);

    // ---- standby promotion: a second server follows this one ------------------
    let admin = agent();
    let r = c.call(
        Auth::Session(&admin),
        "post",
        "/auth/login",
        &[],
        "",
        Body::Json(&serde_json::json!({ "username": "root", "password": "rootpass123" })),
    );
    c.expect("root login for the standby flow", &r, 200);
    let r = c.call(
        Auth::Session(&admin),
        "post",
        "/tokens",
        &[],
        "",
        Body::Json(&serde_json::json!({ "name": "standby" })),
    );
    c.expect("replication token", &r, 201);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let standby = start_with(&format!(
        "[follow]\nprimary = \"http://{}\"\ninstance_id = \"contract-standby\"\ntoken = \"{token}\"\n",
        srv.web
    ));
    let status_of = |web: &str| -> Value {
        ureq::get(&format!("http://{web}/api/replication/status"))
            .set("Authorization", &format!("Bearer {token}"))
            .timeout(Duration::from_secs(5))
            .call()
            .ok()
            .and_then(|r| r.into_json().ok())
            .unwrap_or(Value::Null)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while status_of(&standby.web)["follow"]["state"] != "following" {
        assert!(Instant::now() < deadline, "standby did not start following");
        std::thread::sleep(Duration::from_millis(200));
    }
    // The primary goes away; then the standby is promoted with the spec's example.
    let mut srv = srv;
    let _ = srv.child.kill();
    let _ = srv.child.wait();
    let deadline = Instant::now() + Duration::from_secs(20);
    while status_of(&standby.web)["follow"]["connected"] != false {
        assert!(
            Instant::now() < deadline,
            "standby did not notice the primary is gone"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    c.web = standby.web.clone();
    let sroot = agent();
    let r = c.call(
        Auth::Session(&sroot),
        "post",
        "/auth/login",
        &[],
        "",
        Body::Json(&serde_json::json!({ "username": "root", "password": "rootpass123" })),
    );
    c.expect("standby root login", &r, 200);
    let ex = c.example("/replication/promote", "post");
    let r = c.send_example(
        Auth::Session(&sroot),
        "post",
        "/replication/promote",
        &[],
        "",
        &ex,
    );
    c.expect("promote the standby", &r, 200);
    c.capture("/replication/promote", &r);
    let r = c.call(
        Auth::Session(&sroot),
        "get",
        "/replication/status",
        &[],
        "",
        Body::None,
    );
    c.expect("status after promotion", &r, 200);
    if r.json()["role"] != "promoted" {
        c.failures
            .push(format!("promoted standby reports {}", r.text));
    }
    drop(standby);

    // ---- coverage ------------------------------------------------------------
    let all = spec_ops(&c.spec);
    let mut missing = Vec::new();
    let mut no_success = Vec::new();
    for (p, m) in &all {
        if COVERAGE_SKIPS.iter().any(|(sp, sm, _)| sp == p && sm == m) {
            continue;
        }
        match c.hits.get(&(p.clone(), m.clone())) {
            None => missing.push(format!("{} {p} ({})", m.to_uppercase(), c.op_id(p, m))),
            Some(s) if !s.iter().any(|s| (100..300).contains(s)) => {
                no_success.push(format!("{} {p} (only {s:?})", m.to_uppercase()))
            }
            _ => {}
        }
    }
    for p in &missing {
        c.failures.push(format!(
            "coverage: {p} was never called with a documented status; if it is new, make sure the generic driver can fill its parameters or add it to a dedicated flow in tests/api_contract.rs"
        ));
    }
    for p in &no_success {
        c.failures.push(format!(
            "coverage: {p} never succeeded, so its success schema was never checked"
        ));
    }
    // Every request example was sent, and got a 2xx unless expected otherwise.
    for (path, method) in &all {
        for (name, media, _) in request_examples(&c.spec, c.op(path, method)) {
            let key = (path.clone(), method.clone(), media.clone(), name.clone());
            let expected_reject = EXPECTED_EXAMPLE_REJECTIONS
                .iter()
                .any(|(p, m, _)| p == path && m == method);
            match c.examples.get(&key) {
                None => c.failures.push(format!(
                    "request example '{name}' of {} {path} ({media}) was never sent",
                    method.to_uppercase()
                )),
                Some(st) if !expected_reject && !st.iter().any(|s| (200..300).contains(s)) => {
                    c.failures.push(format!(
                        "request example '{name}' of {} {path} was rejected ({st:?}): the example does not match what the code accepts; fix the example in {SPEC_FILE}",
                        method.to_uppercase()
                    ))
                }
                Some(st) if expected_reject && !st.iter().any(|s| (400..500).contains(s)) => {
                    c.failures.push(format!(
                        "request example '{name}' of {} {path} was expected to be rejected but got {st:?}",
                        method.to_uppercase()
                    ))
                }
                _ => {}
            }
        }
    }
    let covered = all.len() - missing.len();
    let n_examples: usize = all
        .iter()
        .map(|(p, m)| request_examples(&c.spec, c.op(p, m)).len())
        .sum();
    let loose = always_present_optional(&c.spec, &c.presence);
    if !loose.is_empty() {
        eprintln!(
            "api_contract: note: always returned but not `required` (consider tightening the spec):\n  {}",
            loose.join("\n  ")
        );
    }
    eprintln!(
        "api_contract: {} HTTP calls; operations exercised {covered}/{} (skipped {}); request examples sent {}/{}",
        c.calls,
        all.len(),
        COVERAGE_SKIPS.len(),
        c.examples.len(),
        n_examples
    );
    report(c.failures);
}

/// Fail with de-duplicated messages, direct spec/code mismatches first
/// (coverage gaps are usually knock-on effects of those).
fn report(failures: Vec<String>) {
    let mut seen = BTreeSet::new();
    let mut uniq: Vec<String> = failures
        .into_iter()
        .filter(|f| seen.insert(f.clone()))
        .collect();
    uniq.sort_by_key(|f| {
        if f.contains("undocumented status")
            || f.contains("documented schema")
            || f.contains("Content-Type")
            || f.contains("was rejected")
        {
            0
        } else if f.starts_with("coverage")
            || f.starts_with("request example")
            || f.contains("does not know how to fill")
        {
            2
        } else {
            1
        }
    });
    assert!(
        uniq.is_empty(),
        "\n{} contract violation(s) between the generated OpenAPI document and the server:\n\n{}\n",
        uniq.len(),
        uniq.join("\n\n")
    );
}

fn ex_login(c: &Contract) -> Value {
    c.example("/auth/login", "post").2
}

/// Requests the server cannot parse must still get a documented JSON Error.
/// Known divergence: axum's extractor rejections (bad JSON, wrong field
/// types, unknown enum values, missing Content-Type, unparsable path/query
/// params) answer 400/415/422 with a text/plain body, while the spec promises
/// that "every non-2xx JSON error has this shape" and documents neither 415
/// nor 422. Fixed by the `json_errors` middleware in src/api/mod.rs.
#[test]
fn malformed_requests_get_documented_json_errors() {
    let srv = start();
    let mut c = Contract {
        spec: served_spec(&srv.web),
        web: srv.web.clone(),
        ctx: HashMap::new(),
        hits: BTreeMap::new(),
        examples: BTreeMap::new(),
        failures: Vec::new(),
        calls: 0,
        presence: BTreeMap::new(),
    };
    let root = agent();
    c.login(&root, "root", "rootpass123");
    c.call(
        Auth::Session(&root),
        "post",
        "/zones",
        &[],
        "",
        Body::Json(&json!({ "name": 5 })),
    );
    c.call(
        Auth::Session(&root),
        "post",
        "/zones",
        &[],
        "",
        Body::Text("{\"name\":\"x.test\"}"),
    );
    c.call(
        Auth::Session(&root),
        "post",
        "/zones",
        &[],
        "",
        Body::Json(&json!({ "name": "z.test" })),
    );
    c.call(
        Auth::Session(&root),
        "post",
        "/zones/{zone}/records",
        &[("zone", "z.test".into())],
        "",
        Body::Json(&json!({ "type": "XYZ", "value": "1" })),
    );
    c.call(
        Auth::Session(&root),
        "get",
        "/users/{id}/rights",
        &[("id", "abc".into())],
        "",
        Body::None,
    );
    c.call(
        Auth::Session(&root),
        "get",
        "/changelog",
        &[],
        "limit=abc",
        Body::None,
    );
    report(c.failures);
}
