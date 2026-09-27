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
        let cfg: Config = toml::from_str(
            "[web_console]\nlogin_attempts_per_minute = 1000\n[root]\npassword = \"x\"\n[backup]\ndir = \"\"",
        )
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
        if let Some(c) = cookie {
            b = b.header("cookie", c);
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
