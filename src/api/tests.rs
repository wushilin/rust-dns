//! In-process tests of the sign-in flow: the real router and handlers over
//! an in-memory database, with the TOTP clock pinned so time steps are
//! deterministic (no sleeping for the next 30-second window).

use super::*;
use crate::model::NewUser;
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

/// A pinned time (seconds); TOTP step = t / 30.
const T0: u64 = 1_800_000_000;

struct Harness {
    app: Router,
    state: Arc<AppState>,
    now: Arc<AtomicU64>,
}

struct Resp {
    status: StatusCode,
    json: serde_json::Value,
    cookie: Option<String>,
    retry_after: Option<String>,
}

impl Harness {
    fn new() -> Harness {
        Self::with_backoff(1000)
    }

    fn with_backoff(login_backoff_after: u32) -> Harness {
        Self::with_config(login_backoff_after, "")
    }

    /// `web_extra`: more `[web_console]` lines.
    fn with_config(login_backoff_after: u32, web_extra: &str) -> Harness {
        let cfg: Config = toml::from_str(&format!(
            "[web_console]\nlogin_attempts_per_minute = 1000\n{web_extra}\n[root]\npassword = \"x\"\n[backup]\ndir = \"\"",
        ))
        .unwrap();
        let cfg = Arc::new(cfg);
        let storage = Arc::new(Storage::open_memory().unwrap());
        let cache = Arc::new(Cache::new(crate::cache::Catalog::empty()));
        let bus = Arc::new(Bus::new(64, 64));
        let mutator = Arc::new(Mutator::new(
            storage.clone(),
            cache.clone(),
            bus.clone(),
            "",
            "",
        ));
        let accounts = Arc::new(crate::mutation::accounts::Accounts::new(storage.clone()));
        accounts.set_bus(bus.clone());
        let limiter = Arc::new(RateLimiter::new(0, Duration::from_secs(1), 10));
        let dns = Arc::new(DnsServer::new(
            cache.clone(),
            bus.clone(),
            limiter.clone(),
            &cfg,
        ));
        let reloader = Arc::new(crate::reload::Reloader {
            path: "unused.toml".into(),
            current: arc_swap::ArcSwap::from(cfg.clone()),
            dns: dns.clone(),
            mutator: mutator.clone(),
            accounts: accounts.clone(),
        });
        let now = Arc::new(AtomicU64::new(T0));
        let clock_now = now.clone();
        let repl = crate::replication::Replication::new(
            storage.clone(),
            mutator.clone(),
            dns.clone(),
            reloader.clone(),
            "unused.toml".into(),
        );
        let state = Arc::new(AppState {
            cfg: cfg.clone(),
            storage,
            cache,
            mutator,
            accounts,
            bus,
            dns,
            reloader,
            limiter,
            login_limiter: RateLimiter::new(1000, Duration::from_secs(60), 100),
            guard: guard::AttemptGuard::new(login_backoff_after),
            clock: Arc::new(move || clock_now.load(Ordering::SeqCst)),
            trusted: vec![],
            started: Instant::now(),
            repl,
        });
        Harness {
            app: router(state.clone()),
            state,
            now,
        }
    }

    fn step(&self) -> u64 {
        self.now.load(Ordering::SeqCst) / 30
    }

    fn advance_steps(&self, n: u64) {
        self.now.fetch_add(30 * n, Ordering::SeqCst);
    }

    /// A user with a password and, optionally, an enrolled TOTP secret.
    fn user(&self, name: &str, password: &str, totp_secret: Option<&str>) -> crate::model::User {
        let actor = crate::model::Actor {
            name: "test".into(),
            ip: "127.0.0.1".into(),
        };
        let u = self
            .state
            .accounts
            .create_user(
                &actor,
                &NewUser {
                    username: name.into(),
                    password_hash: crate::auth::hash_password(password).unwrap(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        match totp_secret {
            Some(s) => self
                .state
                .accounts
                .run(&actor, "mfa_enroll", |t| {
                    let u = t.set_mfa(u.id, Some(s))?;
                    t.set_recovery_codes(&u, &[crate::auth::sha256_hex("abcde12345")])?;
                    Ok(u)
                })
                .unwrap(),
            None => u,
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Resp {
        let mut b = HttpRequest::builder()
            .method(method)
            .uri(format!("/api{path}"))
            .header("x-requested-with", "rust-dns");
        match cookie {
            // An API token instead of a session cookie.
            Some(c) if c.starts_with("Bearer ") => b = b.header("authorization", c),
            Some(c) => b = b.header("cookie", c),
            None => {}
        }
        let req = match body {
            Some(j) => b
                .header("content-type", "application/json")
                .body(Body::from(j.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| !v.contains("Max-Age=0"))
            .and_then(|v| v.split(';').next())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        Resp {
            status,
            json,
            cookie,
            retry_after,
        }
    }

    async fn login(&self, user: &str, pw: &str) -> Resp {
        self.call(
            "POST",
            "/auth/login",
            None,
            Some(serde_json::json!({ "username": user, "password": pw })),
        )
        .await
    }

    async fn mfa(&self, cookie: &str, code: &str) -> Resp {
        self.call(
            "POST",
            "/auth/mfa",
            Some(cookie),
            Some(serde_json::json!({ "code": code })),
        )
        .await
    }
}

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn code(step: u64) -> String {
    crate::auth::totp_code_for(SECRET, step)
}

/// Owner test 1a: with MFA enrolled, the password alone yields a session
/// that is still waiting for a code; protected endpoints refuse it until a
/// valid TOTP (or recovery code) is given.
#[tokio::test]
async fn login_requires_mfa_when_enabled() {
    let h = Harness::new();
    h.user("mia", "mia-password-1", Some(SECRET));
    let r = h.login("mia", "mia-password-1").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["status"], "mfa_required", "{}", r.json);
    let cookie = r.cookie.expect("pending session cookie");
    let me = h.call("GET", "/me", Some(&cookie), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.json["code"], "mfa_required");
    // A wrong code does not activate it.
    let bad = h.mfa(&cookie, "000000").await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.call("GET", "/me", Some(&cookie), None).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A valid TOTP does.
    let ok = h.mfa(&cookie, &code(h.step())).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.json);
    let me = h.call("GET", "/me", Some(&cookie), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json["user"]["username"], "mia");

    // So does a recovery code, on another pending session.
    let r = h.login("mia", "mia-password-1").await;
    let cookie = r.cookie.unwrap();
    assert_eq!(
        h.call("GET", "/me", Some(&cookie), None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let ok = h.mfa(&cookie, "ABCDE-12345").await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.json);
    assert_eq!(ok.json["used_recovery_code"], true);
    assert_eq!(
        h.call("GET", "/me", Some(&cookie), None).await.status,
        StatusCode::OK
    );
}

/// Owner test 1b: without MFA the password gives an active session at once;
/// there is no code step to take.
#[tokio::test]
async fn login_without_mfa_is_direct() {
    let h = Harness::new();
    h.user("nora", "nora-password-1", None);
    let r = h.login("nora", "nora-password-1").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["status"], "ok", "{}", r.json);
    let cookie = r.cookie.expect("session cookie");
    let me = h.call("GET", "/me", Some(&cookie), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json["user"]["username"], "nora");
    // A TOTP is not a step for this session.
    let r = h.mfa(&cookie, &code(h.step())).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.json);
}

/// Owner test 1c: a wrong password never yields a session or reaches the
/// code step, with or without MFA.
#[tokio::test]
async fn wrong_password_never_reaches_mfa() {
    let h = Harness::new();
    h.user("mia", "mia-password-1", Some(SECRET));
    h.user("nora", "nora-password-1", None);
    for user in ["mia", "nora", "nobody"] {
        let r = h.login(user, "wrong-password").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{user}");
        assert!(r.cookie.is_none(), "{user}: no session cookie");
        assert_ne!(r.json["status"], "mfa_required");
    }
    // Without a pending session the code step is unreachable.
    let r = h
        .call(
            "POST",
            "/auth/mfa",
            None,
            Some(serde_json::json!({ "code": code(h.step()) })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json["code"], "login_required");
    assert!(
        h.state.storage.list_sessions(1).unwrap().is_empty(),
        "no session was created"
    );
}

/// Owner test 2 (same process): an accepted code cannot be used again for
/// the same user, on a new sign-in or on other code-checking endpoints;
/// the next step's code is accepted.
#[tokio::test]
async fn totp_code_cannot_be_reused_same_process() {
    let h = Harness::new();
    h.user("mia", "mia-password-1", Some(SECRET));
    let x = code(h.step());
    let first = h.login("mia", "mia-password-1").await.cookie.unwrap();
    assert_eq!(h.mfa(&first, &x).await.status, StatusCode::OK);

    // Same code, new pending session: refused, and the session stays pending.
    let second = h.login("mia", "mia-password-1").await.cookie.unwrap();
    let r = h.mfa(&second, &x).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.json);
    assert_eq!(
        h.call("GET", "/me", Some(&second), None).await.status,
        StatusCode::UNAUTHORIZED
    );
    // An older step (still inside the skew window) is refused as well.
    let r = h.mfa(&second, &code(h.step() - 1)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Other endpoints that check a code refuse the replay too.
    for path in ["/me/mfa/recovery", "/me/mfa/disable"] {
        let r = h
            .call(
                "POST",
                path,
                Some(&first),
                Some(serde_json::json!({ "code": x })),
            )
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}: {}", r.json);
    }

    // The next time step's code is accepted (once).
    h.advance_steps(1);
    let y = code(h.step());
    assert_eq!(h.mfa(&second, &y).await.status, StatusCode::OK);
    let r = h
        .call(
            "POST",
            "/me/mfa/recovery",
            Some(&first),
            Some(serde_json::json!({ "code": y })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "y was just used");
    let r = h
        .call(
            "POST",
            "/me/mfa/recovery",
            Some(&first),
            Some(serde_json::json!({ "code": code(h.step() + 1) })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
}

/// M6/M2: each session gets five wrong codes; then it is deleted.
#[tokio::test]
async fn code_attempts_are_limited_per_session() {
    let h = Harness::new();
    h.user("mia", "mia-password-1", Some(SECRET));
    let cookie = h.login("mia", "mia-password-1").await.cookie.unwrap();
    for i in 0..4 {
        let r = h.mfa(&cookie, &format!("{:06}", 100000 + i)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_ne!(r.json["code"], "login_required", "attempt {i}");
    }
    let r = h.mfa(&cookie, "999999").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.json["code"], "login_required",
        "session deleted: {}",
        r.json
    );
    // Even the right code no longer helps on that session.
    let r = h.mfa(&cookie, &code(h.step())).await;
    assert_eq!(r.json["code"], "login_required");
}

/// M6: replacing an enrolled authenticator needs the current factor.
#[tokio::test]
async fn re_enrollment_needs_the_current_factor() {
    let h = Harness::new();
    h.user("mia", "mia-password-1", Some(SECRET));
    let cookie = h.login("mia", "mia-password-1").await.cookie.unwrap();
    assert_eq!(h.mfa(&cookie, &code(h.step())).await.status, StatusCode::OK);
    let r = h
        .call(
            "POST",
            "/me/mfa/start",
            Some(&cookie),
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.json);
    let r = h
        .call(
            "POST",
            "/me/mfa/start",
            Some(&cookie),
            Some(serde_json::json!({ "password": "wrong" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = h
        .call(
            "POST",
            "/me/mfa/start",
            Some(&cookie),
            Some(serde_json::json!({ "password": "mia-password-1" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    let r = h
        .call(
            "POST",
            "/me/mfa/start",
            Some(&cookie),
            Some(serde_json::json!({ "code": code(h.step() + 1) })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
}

/// M7: changing the own password signs out the user's other sessions (API
/// tokens are not affected); the current session stays.
#[tokio::test]
async fn password_change_revokes_other_sessions() {
    let h = Harness::new();
    h.user("nora", "nora-password-1", None);
    let a = h.login("nora", "nora-password-1").await.cookie.unwrap();
    let b = h.login("nora", "nora-password-1").await.cookie.unwrap();
    let r = h
        .call(
            "PUT",
            "/me/password",
            Some(&a),
            Some(serde_json::json!({ "current_password": "nora-password-1", "new_password": "nora-password-2" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(
        h.call("GET", "/me", Some(&a), None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.call("GET", "/me", Some(&b), None).await.status,
        StatusCode::UNAUTHORIZED,
        "the other session is signed out"
    );
    let log = h.state.storage.audit_after(0, 100).unwrap();
    assert!(log
        .iter()
        .any(|e| e.operation == "change_password" && e.action == "session.revoke_others"));
}

/// M2: failures for one account slow it down (429 with Retry-After) before
/// the password is even checked; other accounts are unaffected.
#[tokio::test]
async fn failed_logins_back_off_per_account() {
    let h = Harness::with_backoff(3);
    h.user("nora", "nora-password-1", None);
    h.user("olga", "olga-password-1", None);
    for i in 0..4 {
        let r = h.login("nora", "wrong-password").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    // Now waiting: even the right password is refused, without being checked.
    let r = h.login("nora", "nora-password-1").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.json);
    assert_eq!(r.retry_after.as_deref(), Some("1"));
    assert!(r.cookie.is_none());
    let r = h.login("olga", "olga-password-1").await;
    assert_eq!(r.status, StatusCode::OK, "another account is not affected");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = h.login("nora", "nora-password-1").await;
    assert_eq!(r.status, StatusCode::OK, "after the wait: {}", r.json);
}

/// Every mutating operation in the OpenAPI document (so every route: the
/// document is generated from the router) is refused on a read-only
/// standby, except the explicit allowlist, and documents the 409.
#[tokio::test]
async fn read_only_standby_refuses_every_mutating_operation() {
    let h = Harness::new();
    let doc = serde_json::to_value(openapi_doc()).unwrap();
    h.state
        .mutator
        .gate()
        .close("this server is a read-only standby of https://dns1.example.net:8053; make changes on the primary");
    let mut refused = 0;
    let mut allowed = 0;
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in ["put", "post", "delete", "patch"] {
            let Some(op) = item.get(method) else { continue };
            let upper = method.to_uppercase();
            let concrete = path
                .replace("{zone}", "a.test")
                .replace("{username}", "bob")
                .replace("{name}", "k1.")
                .replace("{id}", "1");
            assert!(
                !concrete.contains('{'),
                "unhandled path parameter in {path}"
            );
            let r = h
                .call(&upper, &concrete, None, Some(serde_json::json!({})))
                .await;
            let read_only =
                r.status == StatusCode::CONFLICT && r.json["code"] == "read_only_standby";
            if STANDBY_WRITABLE
                .iter()
                .any(|(m, t)| *m == upper && t == path)
            {
                assert!(!read_only, "{upper} {path} is allowed on a standby");
                allowed += 1;
            } else {
                assert!(
                    read_only,
                    "{upper} {path} must be refused on a standby, got {} {}",
                    r.status, r.json
                );
                assert!(r.json["error"]
                    .as_str()
                    .unwrap()
                    .contains("dns1.example.net"));
                let doc409 = op["responses"]["409"]["$ref"].as_str().unwrap_or("");
                assert!(
                    doc409.ends_with("/ReadOnly") || doc409.ends_with("/ConflictOrReadOnly"),
                    "{upper} {path} documents the read-only 409: {doc409}"
                );
                refused += 1;
            }
        }
    }
    assert_eq!(
        allowed,
        STANDBY_WRITABLE.len(),
        "every allowlist entry is a real route"
    );
    assert!(refused >= 25, "refused {refused}");
    // DNS writes are refused below the API too (background writers).
    let err = h
        .state
        .mutator
        .create_zone(
            crate::model::Actor {
                name: "system".into(),
                ip: "expiry".into(),
            },
            crate::model::ZoneInput {
                name: Some("x.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, crate::mutation::MutationError::ReadOnly(_)));
    // Reads and sign-in still work.
    let r = h.call("GET", "/health", None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    h.state.mutator.gate().open();
    let r = h
        .call("POST", "/zones", None, Some(serde_json::json!({})))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "writable again");
}

#[test]
fn path_templates_match_single_segments() {
    assert!(path_matches("/me/sessions/{id}", "/me/sessions/12"));
    assert!(!path_matches("/me/sessions/{id}", "/me/sessions/12/x"));
    assert!(!path_matches("/me/sessions/{id}", "/me/sessions/"));
    assert!(path_matches(
        "/tsig/keys/{name}/reveal",
        "/tsig/keys/k1./reveal"
    ));
    assert!(!path_matches(
        "/tsig/keys/{name}/reveal",
        "/tsig/keys/k1./delete"
    ));
    assert!(allowed_when_read_only("GET", "/zones"));
    assert!(!allowed_when_read_only("POST", "/zones"));
    assert!(allowed_when_read_only("POST", "/auth/login"));
}

/// K1: `GET /status` publishes exactly [`STANDBY_WRITABLE`] (the console's
/// client-side guard refuses every other write on a standby), on a primary
/// and on a read-only server alike.
#[tokio::test]
async fn status_publishes_the_standby_allowlist() {
    let h = Harness::new();
    h.user("nora", "nora-password-1", None);
    let cookie = h
        .login("nora", "nora-password-1")
        .await
        .cookie
        .expect("session");
    let want: Vec<serde_json::Value> = STANDBY_WRITABLE
        .iter()
        .map(|(m, p)| serde_json::json!({ "method": m, "path": p }))
        .collect();
    for closed in [false, true] {
        if closed {
            h.state
                .mutator
                .gate()
                .close("this server is a read-only standby of https://dns1.example.net:8053");
        }
        let r = h.call("GET", "/status", Some(&cookie), None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.json);
        assert_eq!(
            r.json["replication"]["standby_writable"],
            serde_json::Value::Array(want.clone()),
            "read-only: {closed}"
        );
    }
    for (m, p) in [
        ("POST", "/blocklists/refresh"),
        ("POST", "/blocklists/test"),
    ] {
        assert!(allowed_when_read_only(m, p), "{m} {p}");
    }
    assert!(!allowed_when_read_only("PUT", "/blocklists"));
}

/// B3: while a long write (a large import) holds the write connection, API
/// reads and DNS answers stay fast, also when more account writes than
/// runtime workers are waiting for it. Account writes are synchronous calls
/// from handlers: `Storage::write` hands the worker's other tasks to another
/// thread first (`storage::blocking`), and reads use the read connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_reads_and_dns_stay_fast_during_a_long_write() {
    use crate::mutation::{ExportDoc, ExportRecord, ExportZone, ImportMode};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    let h = Arc::new(Harness::new());
    let actor = crate::model::Actor {
        name: "test".into(),
        ip: "127.0.0.1".into(),
    };
    h.state.accounts.sync_root("root", "x", false).unwrap();
    let root = h.state.storage.get_user_by_name("root").unwrap().unwrap();
    let token = "rdns_latency_probe";
    h.state
        .accounts
        .create_token(&actor, &root, "probe", &crate::auth::sha256_hex(token), &[])
        .unwrap();
    h.state
        .mutator
        .create_zone(
            actor.clone(),
            crate::model::ZoneInput {
                name: Some("lat.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    h.state
        .mutator
        .create_record(
            actor.clone(),
            "lat.test",
            crate::model::RecordInput {
                name: Some("www".into()),
                rtype: Some(crate::model::RecordType::A),
                value: Some("192.0.2.1".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut q = Message::query();
    q.add_query(Query::query(
        Name::from_ascii("www.lat.test.").unwrap(),
        RecordType::A,
    ));
    let dns_req = q.to_vec().unwrap();
    let client: std::net::SocketAddr = "127.0.0.1:5300".parse().unwrap();

    let read = |h: Arc<Harness>| async move {
        let t = Instant::now();
        let req = HttpRequest::builder()
            .uri("/api/zones")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = h.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        t.elapsed()
    };
    let dns = |h: Arc<Harness>, req: Vec<u8>| async move {
        let t = Instant::now();
        match h
            .state
            .dns
            .handle(&req, client, crate::dns::Proto::Udp)
            .await
        {
            crate::dns::Reply::One(b) => {
                let m = Message::from_vec(&b).unwrap();
                assert_eq!(m.answers.len(), 1);
            }
            _ => panic!("no DNS answer"),
        }
        t.elapsed()
    };
    // Warm up (first use of the router and the caches).
    read(h.clone()).await;
    dns(h.clone(), dns_req.clone()).await;

    // The long write: one transaction importing many records (since H1
    // an import is linear: 15,000 records hold it about 1.5 s in a debug
    // build; 1,500 did before).
    let n = 15000;
    let doc = ExportDoc {
        version: 1,
        exported_at: String::new(),
        zones: vec![ExportZone {
            name: "big.test".into(),
            serial: None,
            soa_mname: None,
            soa_rname: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum: None,
            default_ttl: None,
            owner: None,
            overrides: None,
            record_policy: None,
            records: (0..n)
                .map(|i| ExportRecord {
                    name: format!("h{i}"),
                    rtype: crate::model::RecordType::A,
                    value: format!("198.51.{}.{}", i / 250, i % 250 + 1),
                    ttl: None,
                    expires_at: None,
                })
                .collect(),
        }],
    };
    let import_started = Instant::now();
    let m = h.state.mutator.clone();
    let a2 = actor.clone();
    let import = tokio::spawn(async move {
        m.import(a2, doc, ImportMode::Merge, None, None)
            .await
            .unwrap();
        import_started.elapsed()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // More account writes than workers, all waiting for the write connection.
    let mut writers = Vec::new();
    for _ in 0..6 {
        let h2 = h.clone();
        let a = actor.clone();
        writers.push(tokio::spawn(async move {
            h2.state.accounts.run(&a, "probe", |_t| Ok(())).unwrap();
            import_started.elapsed()
        }));
    }
    let (mut max_read, mut max_dns, mut probes) = (Duration::ZERO, Duration::ZERO, 0u32);
    while !import.is_finished() {
        let r = tokio::spawn(read(h.clone())).await.unwrap();
        let d = tokio::spawn(dns(h.clone(), dns_req.clone())).await.unwrap();
        max_read = max_read.max(r);
        max_dns = max_dns.max(d);
        probes += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let import_took = import.await.unwrap();
    let mut first_writer = Duration::MAX;
    for w in writers {
        first_writer = first_writer.min(w.await.unwrap());
    }
    eprintln!(
        "B3 latency: import of {n} records held the write connection {import_took:?}; {probes} probes; max API read {max_read:?}, max DNS answer {max_dns:?}; queued account writes finished after {first_writer:?}"
    );
    assert!(
        import_took > Duration::from_millis(400),
        "the import must be long enough to measure: {import_took:?}"
    );
    assert!(probes >= 10, "probes ran during the write: {probes}");
    assert!(
        // (The import's own time also covers the catalog build and the
        // events after its commit, which grow with its size.)
        first_writer >= import_took / 2,
        "the account writes waited for the import"
    );
    assert!(
        max_dns < Duration::from_millis(150),
        "DNS waited: {max_dns:?}"
    );
    assert!(
        max_read < Duration::from_millis(300),
        "API read waited: {max_read:?}"
    );
}

/// M1: a scoped token never has more than its owner (the permission table
/// narrowed by the scope, on every route), and the rights view, the zone
/// list and the changelog show exactly what it may do.
#[tokio::test]
async fn scoped_tokens_never_exceed_their_owner() {
    use serde_json::json;
    let h = Harness::new();
    h.state
        .accounts
        .sync_root(
            "root",
            &crate::auth::hash_password("root-password-1").unwrap(),
            false,
        )
        .unwrap();
    let alice = h.user("alice", "alice-password-1", None);
    let root_c = h
        .login("root", "root-password-1")
        .await
        .cookie
        .expect("root session");
    let alice_c = h
        .login("alice", "alice-password-1")
        .await
        .cookie
        .expect("alice session");
    for (z, owner) in [("a.test", "alice"), ("b.test", "alice"), ("c.test", "root")] {
        let r = h
            .call(
                "POST",
                "/zones",
                Some(&root_c),
                Some(json!({ "name": z, "owner": owner })),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
        let r = h
            .call(
                "POST",
                &format!("/zones/{z}/records"),
                Some(&root_c),
                Some(json!({ "name": "www", "type": "A", "value": "192.0.2.1" })),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    }
    let token = |c: String, body: serde_json::Value| {
        let h = &h;
        async move {
            let r = h.call("POST", "/tokens", Some(&c), Some(body)).await;
            assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
            (
                format!("Bearer {}", r.json["token"].as_str().unwrap()),
                r.json["info"]["id"].as_i64().unwrap(),
            )
        }
    };
    // Validation.
    for (scope, why) in [
        (json!({ "zones": [] }), "no zone"),
        (json!({ "zones": ["not a zone!"] }), "bad name"),
        (json!({ "expires_at": "2001-01-01T00:00:00Z" }), "past"),
        (json!({ "expires_at": "tomorrow" }), "not a time"),
        (json!({ "max_role": "admin" }), "no such role"),
    ] {
        let r = h
            .call(
                "POST",
                "/tokens",
                Some(&alice_c),
                Some(json!({ "name": "bad", "scope": scope })),
            )
            .await;
        assert!(r.status.is_client_error(), "{why}: {} {}", r.status, r.json);
    }

    // Alice: a.test only, viewer.
    let (t1, t1_id) = token(
        alice_c.clone(),
        json!({ "name": "ro", "scope": { "zones": ["A.test."], "max_role": "viewer" } }),
    )
    .await;
    let r = h.call("GET", "/zones", Some(&t1), None).await;
    let zones: Vec<(String, String)> = r.json["zones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| {
            (
                z["name"].as_str().unwrap().into(),
                z["role"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(zones, vec![("a.test".to_string(), "viewer".to_string())]);
    assert_eq!(
        h.call("GET", "/zones/a.test/records", Some(&t1), None)
            .await
            .status,
        StatusCode::OK
    );
    let rec = json!({ "name": "x", "type": "A", "value": "192.0.2.9" });
    let r = h
        .call(
            "POST",
            "/zones/a.test/records",
            Some(&t1),
            Some(rec.clone()),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.json);
    assert!(
        r.json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("scope")
            || r.json.to_string().contains("scope"),
        "{}",
        r.json
    );
    for path in ["/zones/b.test", "/zones/b.test/records", "/zones/c.test"] {
        assert_eq!(
            h.call("GET", path, Some(&t1), None).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // No token management with a scoped token (it could widen itself).
    let r = h
        .call(
            "POST",
            "/tokens",
            Some(&t1),
            Some(json!({ "name": "wider" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.json);
    let r = h
        .call(
            "PUT",
            &format!("/tokens/{t1_id}"),
            Some(&t1),
            Some(json!({ "scope": {} })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.json);
    assert_eq!(
        h.call("GET", "/tokens", Some(&t1), None).await.status,
        StatusCode::FORBIDDEN
    );
    // Its rights document: the scope applied.
    let r = h
        .call(
            "GET",
            &format!("/users/{}/rights", alice.id),
            Some(&t1),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(r.json["via"], "token");
    assert_eq!(r.json["token"]["id"], t1_id);
    assert_eq!(r.json["token"]["scope"]["zones"], json!(["a.test"]));
    let zr = r.json["zones"].as_array().unwrap();
    assert_eq!(zr.len(), 1, "{}", r.json);
    assert_eq!(zr[0]["zone"], "a.test");
    assert_eq!(zr[0]["role"], "viewer");
    assert_eq!(zr[0]["permissions"], json!(["view", "export"]));
    let own_tokens = r.json["global"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["perm"] == "manage_own_tokens")
        .unwrap()
        .clone();
    assert_eq!(own_tokens["allowed"], false, "{own_tokens}");
    // The same from alice's session with token_id; the session's own rights unchanged.
    let r = h
        .call(
            "GET",
            &format!("/users/{}/rights?token_id={t1_id}", alice.id),
            Some(&alice_c),
            None,
        )
        .await;
    assert_eq!(r.json["zones"].as_array().unwrap().len(), 1, "{}", r.json);
    let r = h
        .call(
            "GET",
            &format!("/users/{}/rights", alice.id),
            Some(&alice_c),
            None,
        )
        .await;
    assert_eq!(r.json["zones"].as_array().unwrap().len(), 2, "{}", r.json);
    assert!(r.json.get("token").is_none());
    // Another user's token id: not found.
    let r = h
        .call(
            "GET",
            &format!("/users/{}/rights?token_id={t1_id}", 1),
            Some(&root_c),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.json);
    // Changelog: only a.test.
    let r = h.call("GET", "/changelog", Some(&t1), None).await;
    let zs: std::collections::BTreeSet<String> = r.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["zone"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(zs.into_iter().collect::<Vec<_>>(), vec!["a.test"]);

    // Alice: every zone, at most editor: records yes, settings and deletion no.
    let (t2, _) = token(
        alice_c.clone(),
        json!({ "name": "ed", "scope": { "max_role": "editor" } }),
    )
    .await;
    let r = h
        .call(
            "POST",
            "/zones/b.test/records",
            Some(&t2),
            Some(rec.clone()),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    assert_eq!(
        h.call("DELETE", "/zones/b.test", Some(&t2), None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.call(
            "PUT",
            "/zones/b.test",
            Some(&t2),
            Some(json!({ "default_ttl": 600 }))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );

    // Root (admin) limited to c.test: no account-wide rights at all.
    let (t3, _) = token(
        root_c.clone(),
        json!({ "name": "c", "scope": { "zones": ["c.test"] } }),
    )
    .await;
    for (m, path) in [
        ("GET", "/users"),
        ("GET", "/audit"),
        ("GET", "/replication/snapshot"),
        ("GET", "/tsig/keys"),
    ] {
        let st = h.call(m, path, Some(&t3), None).await.status;
        assert_eq!(st, StatusCode::FORBIDDEN, "{m} {path}");
    }
    let r = h
        .call(
            "POST",
            "/zones",
            Some(&t3),
            Some(json!({ "name": "d.test" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.json);
    let r = h.call("GET", "/zones", Some(&t3), None).await;
    assert_eq!(r.json["zones"].as_array().unwrap().len(), 1, "{}", r.json);
    assert_eq!(
        r.json["zones"][0]["role"], "owner",
        "an admin's role on its zone"
    );
    let r = h.call("GET", "/changelog", Some(&t3), None).await;
    assert!(r.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["zone"] == "c.test"));
    let r = h.call("GET", "/status", Some(&t3), None).await;
    assert_eq!(r.json["visible_zones"], 1);

    // Expiry: refused once the time has passed (set directly: the API
    // refuses a time in the past).
    let (t4, t4_id) = token(
        root_c.clone(),
        json!({ "name": "soon", "scope": { "expires_at": "2999-01-01T00:00:00Z" } }),
    )
    .await;
    let r = h.call("GET", "/users", Some(&t4), None).await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "an expiry alone keeps admin rights"
    );
    let actor = crate::model::Actor {
        name: "test".into(),
        ip: "127.0.0.1".into(),
    };
    let root = h.state.storage.get_user_by_name("root").unwrap().unwrap();
    let info = h.state.storage.get_token(t4_id).unwrap().unwrap();
    h.state
        .accounts
        .run(&actor, "update_token", |t| {
            t.update_token(
                &root,
                &info,
                None,
                Some(&crate::model::TokenScope {
                    expires_at: Some("2001-01-01T00:00:00.000Z".into()),
                    ..Default::default()
                }),
            )
        })
        .unwrap();
    let r = h.call("GET", "/zones", Some(&t4), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.json);

    // The owner widens the scope again from a session: the token then has
    // exactly the owner's rights.
    let r = h
        .call(
            "PUT",
            &format!("/tokens/{t1_id}"),
            Some(&alice_c),
            Some(json!({ "scope": {} })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert!(r.json.get("scope").is_none(), "{}", r.json);
    let r = h.call("GET", "/zones", Some(&t1), None).await;
    assert_eq!(r.json["zones"].as_array().unwrap().len(), 2, "{}", r.json);
    // Listed with its scope.
    let r = h.call("GET", "/tokens", Some(&alice_c), None).await;
    let ed = r.json["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "ed")
        .unwrap()
        .clone();
    assert_eq!(ed["scope"], json!({ "max_role": "editor" }));
    // Audited with before/after.
    let r = h.call("GET", "/audit", Some(&root_c), None).await;
    assert!(r.json.to_string().contains("\"scope\""), "{}", r.json);
}

/// M2: the record expiry policy through the API: set by zone owners only
/// (EditSettings), shown on the zone, a too-long expiry is a 400 naming the
/// limit, a record without one gets the default.
#[tokio::test]
async fn zone_record_policy_through_the_api() {
    use serde_json::json;
    let h = Harness::new();
    h.state
        .accounts
        .sync_root(
            "root",
            &crate::auth::hash_password("root-password-1").unwrap(),
            false,
        )
        .unwrap();
    h.user("ed", "ed-password-11", None);
    let root = h
        .login("root", "root-password-1")
        .await
        .cookie
        .expect("root");
    let ed = h.login("ed", "ed-password-11").await.cookie.expect("ed");
    let r = h
        .call(
            "POST",
            "/zones",
            Some(&root),
            Some(json!({ "name": "dyn.test" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = h
        .call(
            "PUT",
            "/zones/dyn.test/members/ed",
            Some(&root),
            Some(json!({ "role": "editor" })),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.json);
    let policy =
        json!({ "record_policy": { "default_expiry_secs": 3600, "max_expiry_secs": 86400 } });
    let r = h
        .call("PUT", "/zones/dyn.test", Some(&ed), Some(policy.clone()))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "an editor cannot set it");
    let r = h
        .call(
            "PUT",
            "/zones/dyn.test",
            Some(&root),
            Some(json!({ "record_policy": { "default_expiry_secs": 9, "max_expiry_secs": 8 } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.json);
    let r = h
        .call("PUT", "/zones/dyn.test", Some(&root), Some(policy))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(r.json["record_policy"]["max_expiry_secs"], 86400);
    let r = h.call("GET", "/zones/dyn.test", Some(&ed), None).await;
    assert_eq!(r.json["record_policy"]["default_expiry_secs"], 3600);
    let r = h
        .call(
            "POST",
            "/zones/dyn.test/records",
            Some(&ed),
            Some(json!({ "name": "pc", "type": "A", "value": "192.0.2.1", "expires_in": 172800 })),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.json);
    assert!(r.json.to_string().contains("86400"), "{}", r.json);
    let r = h
        .call(
            "POST",
            "/zones/dyn.test/records",
            Some(&ed),
            Some(json!({ "name": "pc", "type": "A", "value": "192.0.2.1" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    assert!(r.json["expires_at"].is_string(), "{}", r.json);
    let r = h
        .call(
            "PUT",
            "/zones/dyn.test",
            Some(&root),
            Some(json!({ "record_policy": null })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert!(r.json.get("record_policy").is_none(), "{}", r.json);
}

/// Root with a known password, signed in: its session cookie.
async fn root_session(h: &Harness) -> String {
    h.state
        .accounts
        .sync_root(
            "root",
            &crate::auth::hash_password("root-password-1").unwrap(),
            false,
        )
        .unwrap();
    h.login("root", "root-password-1")
        .await
        .cookie
        .expect("root session")
}

/// A new API token of the session's user: (`Bearer ...`, id).
async fn new_token(h: &Harness, cookie: &str, name: &str) -> (String, i64) {
    let r = h
        .call(
            "POST",
            "/tokens",
            Some(cookie),
            Some(serde_json::json!({ "name": name })),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    (
        format!("Bearer {}", r.json["token"].as_str().unwrap()),
        r.json["info"]["id"].as_i64().unwrap(),
    )
}

/// O1: a password change (own, or an administrator's reset) revokes the
/// user's API tokens only when asked; each revocation is a `token_revoked`
/// change with a `token.revoke` audit row.
#[tokio::test]
async fn password_change_can_revoke_api_tokens() {
    use serde_json::json;
    let h = Harness::new();
    let root_c = root_session(&h).await;
    let nora = h.user("nora", "nora-password-1", None);
    let c = h.login("nora", "nora-password-1").await.cookie.unwrap();
    let (t1, _) = new_token(&h, &c, "one").await;
    // Default: tokens keep working.
    let r = h
        .call(
            "PUT",
            "/me/password",
            Some(&c),
            Some(
                json!({ "current_password": "nora-password-1", "new_password": "nora-password-2" }),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(
        h.call("GET", "/me", Some(&t1), None).await.status,
        StatusCode::OK
    );
    let (t2, _) = new_token(&h, &c, "two").await;
    // Asked: every token of the user is revoked, in the same transaction.
    let r = h
        .call(
            "PUT",
            "/me/password",
            Some(&c),
            Some(json!({ "current_password": "nora-password-2", "new_password": "nora-password-3", "revoke_tokens": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    for t in [&t1, &t2] {
        assert_eq!(
            h.call("GET", "/me", Some(t), None).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        h.call("GET", "/me", Some(&c), None).await.status,
        StatusCode::OK
    );
    let log = h.state.storage.audit_after(0, 1000).unwrap();
    let revoked: Vec<_> = log
        .iter()
        .filter(|e| e.operation == "change_password" && e.action == "token.revoke")
        .collect();
    assert_eq!(revoked.len(), 2);
    assert_eq!(revoked[0].detail["reason"], "password changed");
    let kinds: Vec<String> = h
        .state
        .storage
        .read_tx(|c| {
            let mut st = c.prepare("SELECT payload FROM changelog ORDER BY offset")?;
            let rows = st.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap();
    assert_eq!(
        kinds
            .iter()
            .filter(|p| p.contains("\"token_revoked\""))
            .count(),
        2
    );
    // Administrator reset: same option; without a password it is refused.
    let (t3, _) = new_token(&h, &c, "three").await;
    let path = format!("/users/{}", nora.id);
    let r = h
        .call(
            "PUT",
            &path,
            Some(&root_c),
            Some(json!({ "revoke_tokens": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.json);
    let r = h
        .call(
            "PUT",
            &path,
            Some(&root_c),
            Some(json!({ "password": "nora-password-4" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(
        h.call("GET", "/me", Some(&t3), None).await.status,
        StatusCode::OK,
        "a reset without the option keeps tokens"
    );
    let r = h
        .call(
            "PUT",
            &path,
            Some(&root_c),
            Some(json!({ "password": "nora-password-5", "revoke_tokens": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    assert_eq!(
        h.call("GET", "/me", Some(&t3), None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

/// O1: `token_creation_requires_session` refuses token creation with a
/// token (default: allowed); a browser session still can.
#[tokio::test]
async fn token_creation_can_require_a_session() {
    let h = Harness::new();
    let c = root_session(&h).await;
    let (t, _) = new_token(&h, &c, "a").await;
    new_token(&h, &t, "made-with-a-token").await;

    let h = Harness::with_config(1000, "token_creation_requires_session = true");
    let c = root_session(&h).await;
    let (t, _) = new_token(&h, &c, "a").await;
    let r = h
        .call(
            "POST",
            "/tokens",
            Some(&t),
            Some(serde_json::json!({ "name": "b" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.json);
    assert!(r.json["error"]
        .as_str()
        .unwrap()
        .contains("token_creation_requires_session"));
}
