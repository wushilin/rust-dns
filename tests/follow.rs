//! Standby (follow) mode end to end: two real binaries on loopback (plain
//! http is allowed for loopback), a primary P and a standby S.
//!
//! Covers: token validation (non-admin refused), bootstrap, replication of
//! zones/records/members/TSIG keys/forwarding settings/users with MFA/
//! tagged tokens, matching DNS answers, record expiry replicated (not swept
//! on the standby), 409 on standby writes, the primary going away,
//! promotion, the returning old primary fenced by [peer], the old primary
//! rejoining as a standby (divergent tail saved, re-bootstrapped,
//! converged), TOTP replay protection and API tokens across the failover,
//! and a revoked replication token stopping the standby.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{json, Value};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    // Also free for UDP (DNS listens on both).
    if UdpSocket::bind(("127.0.0.1", p)).is_err() {
        return free_port();
    }
    p
}

struct Node {
    name: &'static str,
    dir: PathBuf,
    dns: u16,
    web: u16,
    password: &'static str,
    child: Option<Child>,
}

impl Node {
    fn new(root: &Path, name: &'static str, password: &'static str) -> Node {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Node {
            name,
            dir,
            dns: free_port(),
            web: free_port(),
            password,
            child: None,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.web)
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("rust-dns.toml")
    }

    /// Write the config; `extra` is appended ([follow] / [peer]).
    fn configure(&self, extra: &str) {
        let cfg = format!(
            r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{db}"
[web_console]
bind = "127.0.0.1:{web}"
login_attempts_per_minute = 10000
login_backoff_after = 100000
[root]
username = "root"
password = "{pw}"
[expiry]
sweep_interval_secs = 1
[logging]
level = "info"
file = "{log}"
[backup]
dir = ""
{extra}
"#,
            dns = self.dns,
            web = self.web,
            db = self.dir.join("data.db").display(),
            log = self.dir.join("server.log").display(),
            pw = self.password,
        );
        std::fs::write(self.config_path(), cfg).unwrap();
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        let child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(self.config_path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rust-dns");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while ureq::get(&format!("{}/api/health", self.url()))
            .timeout(Duration::from_millis(500))
            .call()
            .is_err()
        {
            assert!(
                Instant::now() < deadline,
                "{} did not come up; log:\n{}",
                self.name,
                self.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }

    fn login(&self, user: &str, pw: &str) -> ureq::Agent {
        let a = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let (s, v) = call(
            &Auth::Session(&a),
            "POST",
            &format!("{}/api/auth/login", self.url()),
            Some(json!({ "username": user, "password": pw })),
        );
        assert_eq!(s, 200, "{} login {user}: {v}", self.name);
        assert_eq!(v["status"], "ok", "{} login {user}: {v}", self.name);
        a
    }

    fn root(&self) -> ureq::Agent {
        self.login("root", self.password)
    }

    fn api(&self, path: &str) -> String {
        format!("{}/api{path}", self.url())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

enum Auth<'a> {
    Session(&'a ureq::Agent),
    Token(&'a str),
    None,
}

fn call(auth: &Auth, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
    let agent;
    let a = match auth {
        Auth::Session(a) => *a,
        _ => {
            agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build();
            &agent
        }
    };
    let mut req = a.request(method, url).set("X-Requested-With", "rust-dns");
    if let Auth::Token(t) = auth {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let r = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match r {
        Ok(r) => {
            let s = r.status();
            (s, r.into_json().unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(Value::Null)),
        Err(e) => (0, json!({ "transport": e.to_string() })),
    }
}

fn ok(r: (u16, Value), what: &str) -> Value {
    assert!((200..300).contains(&r.0), "{what}: {} {}", r.0, r.1);
    r.1
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn query(port: u16, name: &str, rtype: RecordType) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).expect("udp reply");
    Message::from_bytes(&buf[..n]).unwrap()
}

/// Sorted answer data for comparison.
fn answers(port: u16, name: &str, rtype: RecordType) -> (ResponseCode, Vec<String>) {
    let m = query(port, name, rtype);
    let mut v: Vec<String> = m
        .answers
        .iter()
        .map(|r| format!("{} {} {}", r.name, r.ttl, r.data))
        .collect();
    v.sort();
    (m.metadata.response_code, v)
}

fn soa_serial(port: u16, zone: &str) -> u32 {
    let m = query(port, zone, RecordType::SOA);
    match &m.answers.first().map(|r| r.data.clone()) {
        Some(RData::SOA(s)) => s.serial,
        other => panic!("no SOA for {zone}: {other:?}"),
    }
}

fn totp_at(secret_b32: &str, step: u64) -> String {
    use hmac::{Hmac, Mac};
    let key = data_encoding::BASE32_NOPAD
        .decode(secret_b32.trim_end_matches('=').as_bytes())
        .unwrap();
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

fn step_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30
}

fn status(node: &Node, a: &ureq::Agent) -> Value {
    ok(
        call(
            &Auth::Session(a),
            "GET",
            &node.api("/replication/status"),
            None,
        ),
        "replication status",
    )
}

fn follow_cfg(primary: &Node, token: &str) -> String {
    format!(
        "[follow]\nprimary = \"{}\"\ntoken = \"{token}\"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n",
        primary.url()
    )
}

fn record_names(node: &Node, a: &ureq::Agent, zone: &str) -> Vec<String> {
    let v = call(
        &Auth::Session(a),
        "GET",
        &node.api(&format!("/zones/{zone}/records")),
        None,
    );
    if v.0 != 200 {
        return vec![];
    }
    let mut n: Vec<String> = v.1["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["name"].as_str().unwrap(),
                r["type"].as_str().unwrap(),
                r["value"].as_str().unwrap()
            )
        })
        .collect();
    n.sort();
    n
}

#[test]
fn primary_standby_failover_and_rejoin() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir =
        std::env::temp_dir().join(format!("rust-dns-follow-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");

    // ---- primary with [peer] = the standby ------------------------------------
    p.configure(&format!(
        "[peer]\nurl = \"{}\"\ncheck_interval_secs = 1\n",
        s.url()
    ));
    p.start();
    let pr = p.root();
    let admin_token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "replication", "tags": ["replication"] })),
        ),
        "admin token",
    );
    let admin_token_id = admin_token["info"]["id"].as_i64().unwrap();
    let admin_token = admin_token["token"].as_str().unwrap().to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/users"),
            Some(json!({ "username": "bob", "password": "bob-password-1" })),
        ),
        "create bob",
    );
    let bob = p.login("bob", "bob-password-1");
    let bob_token = ok(
        call(
            &Auth::Session(&bob),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "bob" })),
        ),
        "bob token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();

    // ---- a non-admin token is refused ------------------------------------------
    s.configure(&follow_cfg(&p, &bob_token));
    s.start();
    let sr = s.root();
    wait_for("standby refuses a non-admin token", 15, || {
        let st = status(&s, &sr);
        st["follow"]["state"] == "refused"
            && st["follow"]["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("not an administrator")
    });
    let st = status(&s, &sr);
    assert_eq!(st["role"], "standby");
    assert_eq!(st["writable"], false);
    s.stop();

    // ---- bootstrap with an admin token -----------------------------------------
    // Data on the primary before the standby starts (goes via the snapshot).
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "z.test" })),
        ),
        "zone",
    );
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/z.test/records"),
            Some(json!({ "name": "www", "type": "A", "value": "192.0.2.10" })),
        ),
        "record",
    );
    s.configure(&follow_cfg(&p, &admin_token));
    s.start();
    let sr = s.root();
    wait_for("standby bootstrapped", 15, || {
        record_names(&s, &sr, "z.test") == vec!["www A 192.0.2.10".to_string()]
    });
    let st = status(&s, &sr);
    assert_eq!(st["follow"]["connected"], true, "{st}");
    assert!(st["follow"]["last_snapshot_result"]
        .as_str()
        .unwrap()
        .starts_with("ok"));
    // The primary sees its standby, and both share the history id.
    let pst = status(&p, &pr);
    assert_eq!(pst["role"], "primary");
    assert_eq!(pst["history"]["history_id"], st["history"]["history_id"]);
    assert!(!pst["standbys"].as_array().unwrap().is_empty(), "{pst}");
    // The primary's root password is not the standby's: the local root wins.
    let (code, _) = call(
        &Auth::None,
        "POST",
        &s.api("/auth/login"),
        Some(json!({ "username": "root", "password": "rootpass-primary" })),
    );
    assert_eq!(code, 401, "the standby's root keeps its own password");

    // ---- live replication of everything ----------------------------------------
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/z.test/records"),
            Some(json!({ "name": "@", "type": "TXT", "value": "hello standby" })),
        ),
        "txt",
    );
    ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/z.test/members/bob"),
            Some(json!({ "role": "editor" })),
        ),
        "member",
    );
    let tsig = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tsig/keys"),
            Some(json!({ "name": "sec1" })),
        ),
        "tsig",
    );
    let tsig_secret = tsig["secret"].as_str().unwrap().to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/settings/forwarding"),
            Some(
                json!({ "upstreams": ["192.0.2.53"], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 1500 }),
            ),
        ),
        "forwarding",
    );
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/users"),
            Some(
                json!({ "username": "carol", "password": "carol-password-1", "mfa_required": true }),
            ),
        ),
        "carol",
    );
    // Carol enrolls on the primary (step now-1) and gets a tagged token.
    let carol = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let login = ok(
        call(
            &Auth::Session(&carol),
            "POST",
            &p.api("/auth/login"),
            Some(json!({ "username": "carol", "password": "carol-password-1" })),
        ),
        "carol login",
    );
    assert_eq!(login["status"], "enroll_required");
    let secret = login["enroll"]["secret"].as_str().unwrap().to_string();
    let enroll_step = step_now() - 1;
    ok(
        call(
            &Auth::Session(&carol),
            "POST",
            &p.api("/auth/enroll"),
            Some(json!({ "code": totp_at(&secret, enroll_step) })),
        ),
        "carol enroll",
    );
    let carol_token = ok(
        call(
            &Auth::Session(&carol),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "carol-ci", "tags": ["ci", "deploy"] })),
        ),
        "carol token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    // An expiring record: the primary's sweeper expires it.
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/z.test/records"),
            Some(json!({ "name": "tmp", "type": "A", "value": "192.0.2.99", "expires_in": 3 })),
        ),
        "expiring record",
    );

    let missing = || -> Vec<&'static str> {
        let recs = record_names(&s, &sr, "z.test");
        let users = call(&Auth::Session(&sr), "GET", &s.api("/users"), None).1;
        let tokens = call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/tokens?all=true&tag=ci"),
            None,
        )
        .1;
        let keys = call(&Auth::Session(&sr), "GET", &s.api("/tsig/keys"), None).1;
        let fwd = call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/settings/forwarding"),
            None,
        )
        .1;
        let zone = call(&Auth::Session(&sr), "GET", &s.api("/zones/z.test"), None).1;
        let mut m = Vec::new();
        if !recs
            .iter()
            .any(|r| r.starts_with("@ TXT") && r.contains("hello standby"))
        {
            m.push("txt record");
        }
        if !recs.iter().any(|r| r.starts_with("tmp A")) {
            m.push("expiring record");
        }
        if !users["users"].as_array().is_some_and(|u| {
            u.iter()
                .any(|u| u["username"] == "carol" && u["mfa_enrolled"] == true)
        }) {
            m.push("carol with MFA");
        }
        if !tokens["tokens"].as_array().is_some_and(|t| {
            t.iter()
                .any(|t| t["name"] == "carol-ci" && t["tags"] == json!(["ci", "deploy"]))
        }) {
            m.push("tagged token");
        }
        if !keys["keys"]
            .as_array()
            .is_some_and(|k| k.iter().any(|k| k["name"] == "sec1."))
        {
            m.push("tsig key");
        }
        if !fwd["upstreams"].to_string().contains("192.0.2.53") {
            m.push("forwarding");
        }
        if !zone.to_string().contains("\"bob\"") {
            m.push("member");
        }
        m
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let m = missing();
        if m.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not replicated: {m:?}\n{}",
            s.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // DNS answers match.
    for (name, t) in [
        ("www.z.test.", RecordType::A),
        ("z.test.", RecordType::TXT),
        ("z.test.", RecordType::SOA),
        ("z.test.", RecordType::NS),
        ("nope.z.test.", RecordType::A),
    ] {
        assert_eq!(
            answers(s.dns, name, t),
            answers(p.dns, name, t),
            "{name} {t}"
        );
    }
    // The standby's TSIG keyring works: a signed transfer needs the key, so
    // just check the key material arrived (the secret revealed on S equals P's).
    let rev = ok(
        call(
            &Auth::Session(&sr),
            "POST",
            &s.api("/tsig/keys/sec1./reveal"),
            None,
        ),
        "reveal on standby",
    );
    assert_eq!(rev["secret"].as_str().unwrap(), tsig_secret);

    // Record expiry comes from the primary's changelog, same offsets and txn.
    wait_for("expiry replicated", 20, || {
        let cl = call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/changelog?after=0&limit=2000"),
            None,
        )
        .1;
        cl["entries"]
            .as_array()
            .is_some_and(|e| e.iter().any(|e| e["payload"]["kind"] == "record_expired"))
    });
    let pcl = ok(
        call(
            &Auth::Session(&pr),
            "GET",
            &p.api("/changelog?after=0&limit=2000"),
            None,
        ),
        "p changelog",
    );
    let scl = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/changelog?after=0&limit=2000"),
            None,
        ),
        "s changelog",
    );
    let key = |v: &Value| -> Vec<(i64, String, String)> {
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["offset"].as_i64().unwrap(),
                    e["txn"].as_str().unwrap().to_string(),
                    e["payload"]["kind"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    };
    let (pk, sk) = (key(&pcl), key(&scl));
    let exp = sk.iter().find(|e| e.2 == "record_expired").unwrap();
    assert!(
        pk.contains(exp),
        "the standby's expiry row is the primary's (same offset and txn)"
    );
    for e in &sk {
        assert!(
            pk.contains(e),
            "every standby changelog row exists on the primary: {e:?}"
        );
    }
    assert_eq!(
        answers(s.dns, "tmp.z.test.", RecordType::A).1,
        Vec::<String>::new()
    );
    assert_eq!(soa_serial(s.dns, "z.test."), soa_serial(p.dns, "z.test."));

    // ---- writes on the standby are refused ---------------------------------------
    for (m, path, body) in [
        ("POST", "/zones", Some(json!({ "name": "nope.test" }))),
        (
            "POST",
            "/zones/z.test/records",
            Some(json!({ "name": "x", "type": "A", "value": "192.0.2.1" })),
        ),
        (
            "POST",
            "/users",
            Some(json!({ "username": "dave", "password": "dave-password-1" })),
        ),
        ("POST", "/tokens", Some(json!({ "name": "x" }))),
        ("DELETE", "/tsig/keys/sec1.", None),
        (
            "PUT",
            "/settings/forwarding",
            Some(json!({ "upstreams": [], "allowed_clients": [], "timeout_ms": 1000 })),
        ),
    ] {
        let (code, v) = call(&Auth::Session(&sr), m, &s.api(path), body);
        assert_eq!(code, 409, "{m} {path}: {v}");
        assert_eq!(v["code"], "read_only_standby");
        assert!(
            v["error"].as_str().unwrap().contains(&p.url()),
            "names the primary: {v}"
        );
    }
    let metrics = ureq::get(&format!("{}/metrics", s.url()))
        .set("Authorization", &format!("Bearer {admin_token}"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(
        metrics.contains("rustdns_replication_connected 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("rustdns_replication_lag_changes 0"),
        "{metrics}"
    );

    // ---- carol signs in on the primary with TOTP (step X) ---------------------
    let x = step_now();
    let carol2 = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let l = ok(
        call(
            &Auth::Session(&carol2),
            "POST",
            &p.api("/auth/login"),
            Some(json!({ "username": "carol", "password": "carol-password-1" })),
        ),
        "carol login 2",
    );
    assert_eq!(l["status"], "mfa_required");
    ok(
        call(
            &Auth::Session(&carol2),
            "POST",
            &p.api("/auth/mfa"),
            Some(json!({ "code": totp_at(&secret, x) })),
        ),
        "carol mfa on primary",
    );
    // Let the used step reach the standby.
    std::thread::sleep(Duration::from_millis(1500));
    let head_before = status(&s, &sr)["head"].as_i64().unwrap();

    // ---- split: standby down, the primary writes, then the primary dies --------
    s.stop();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "diverged.test" })),
        ),
        "divergent write",
    );
    let pdiv_head = status(&p, &pr)["head"].as_i64().unwrap();
    assert!(pdiv_head > head_before);
    p.stop();

    // ---- standby alone: still answers, reports disconnected ---------------------
    s.start();
    let sr = s.root();
    assert_eq!(answers(s.dns, "www.z.test.", RecordType::A).1.len(), 1);
    wait_for("standby reports the primary unreachable", 15, || {
        let st = status(&s, &sr);
        st["follow"]["connected"] == false && !st["follow"]["disconnected_since"].is_null()
    });
    let (code, _) = call(
        &Auth::Session(&sr),
        "POST",
        &s.api("/zones"),
        Some(json!({ "name": "early.test" })),
    );
    assert_eq!(code, 409);

    // ---- promote ---------------------------------------------------------------------
    let old_history = status(&s, &sr)["history"]["history_id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = ok(
        call(
            &Auth::Session(&sr),
            "POST",
            &s.api("/replication/promote"),
            Some(json!({ "confirm": true })),
        ),
        "promote",
    );
    assert_eq!(r["history"]["parent_history_id"], old_history.as_str());
    assert_ne!(r["history"]["history_id"], old_history.as_str());
    assert_eq!(r["config_updated"], true);
    let cfg_text = std::fs::read_to_string(s.config_path()).unwrap();
    assert!(!cfg_text.contains("\n[follow]"), "{cfg_text}");
    assert!(
        !cfg_text.contains(&admin_token),
        "the token is not kept in a comment"
    );
    let st = status(&s, &sr);
    assert_eq!(st["role"], "promoted");
    assert_eq!(st["writable"], true);
    ok(
        call(
            &Auth::Session(&sr),
            "POST",
            &s.api("/zones/z.test/records"),
            Some(json!({ "name": "after", "type": "A", "value": "192.0.2.77" })),
        ),
        "write on the promoted standby",
    );
    assert_eq!(answers(s.dns, "after.z.test.", RecordType::A).1.len(), 1);

    // TOTP: the step used on the old primary is refused, a later one works.
    let c = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let l = ok(
        call(
            &Auth::Session(&c),
            "POST",
            &s.api("/auth/login"),
            Some(json!({ "username": "carol", "password": "carol-password-1" })),
        ),
        "carol login on promoted",
    );
    assert_eq!(l["status"], "mfa_required");
    let (code, _) = call(
        &Auth::Session(&c),
        "POST",
        &s.api("/auth/mfa"),
        Some(json!({ "code": totp_at(&secret, x) })),
    );
    assert_eq!(
        code, 401,
        "a TOTP code already used on the old primary is refused"
    );
    let l = ok(
        call(
            &Auth::Session(&c),
            "POST",
            &s.api("/auth/login"),
            Some(json!({ "username": "carol", "password": "carol-password-1" })),
        ),
        "carol login again",
    );
    assert_eq!(l["status"], "mfa_required");
    ok(
        call(
            &Auth::Session(&c),
            "POST",
            &s.api("/auth/mfa"),
            Some(json!({ "code": totp_at(&secret, x + 1) })),
        ),
        "carol with a fresh code",
    );
    // API tokens made on the old primary work here.
    let me = ok(
        call(&Auth::Token(&carol_token), "GET", &s.api("/me"), None),
        "carol token",
    );
    assert_eq!(me["user"]["username"], "carol");
    ok(
        call(
            &Auth::Token(&admin_token),
            "GET",
            &s.api("/replication/status"),
            None,
        ),
        "admin token",
    );

    // ---- the old primary comes back with [peer]: fenced ---------------------------
    p.start();
    let pr = p.root();
    let pst = status(&p, &pr);
    assert_eq!(pst["role"], "fenced", "{pst}");
    assert_eq!(pst["writable"], false);
    let (code, v) = call(
        &Auth::Session(&pr),
        "POST",
        &p.api("/zones"),
        Some(json!({ "name": "split.test" })),
    );
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(&s.url()), "{v}");

    // ---- the old primary rejoins as a standby of the promoted server ------------
    p.stop();
    p.configure(&follow_cfg(&s, &admin_token));
    p.start();
    let pr = p.root();
    wait_for(
        "old primary re-bootstrapped from the new primary",
        20,
        || {
            let recs = record_names(&p, &pr, "z.test");
            recs.contains(&"after A 192.0.2.77".to_string())
        },
    );
    let div: Vec<PathBuf> = std::fs::read_dir(&p.dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("divergent-")
        })
        .collect();
    assert_eq!(div.len(), 1, "one divergence file");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&div[0]).unwrap()).unwrap();
    assert!(
        doc["divergent_changes"]
            .to_string()
            .contains("diverged.test"),
        "the old primary's change after the fork is saved: {doc}"
    );
    assert!(
        !doc.to_string().contains("argon2"),
        "no password hashes in the divergence file"
    );
    assert!(p.log().contains("DIVERGED"), "logged");
    // The old primary's divergent zone is gone; data converged.
    let (code, _) = call(
        &Auth::Session(&pr),
        "GET",
        &p.api("/zones/diverged.test"),
        None,
    );
    assert_eq!(code, 404);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let st = status(&p, &pr);
        if st["follow"]["last_reconcile_result"]
            .as_str()
            .is_some_and(|r| r.starts_with("ok"))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "reconcile not ok on the rejoined server: {st}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    for (name, t) in [
        ("www.z.test.", RecordType::A),
        ("after.z.test.", RecordType::A),
        ("z.test.", RecordType::SOA),
    ] {
        assert_eq!(
            answers(p.dns, name, t),
            answers(s.dns, name, t),
            "{name} {t}"
        );
    }
    let sst = status(&s, &sr);
    let pst = status(&p, &pr);
    assert_eq!(pst["history"]["history_id"], sst["history"]["history_id"]);
    assert_eq!(pst["head"], sst["head"]);

    // ---- revoking the replication token stops the standby -------------------------
    ok(
        call(
            &Auth::Session(&sr),
            "DELETE",
            &s.api(&format!("/tokens/{admin_token_id}")),
            None,
        ),
        "revoke",
    );
    wait_for("standby refuses after the token is revoked", 20, || {
        let st = status(&p, &pr);
        st["follow"]["state"] == "refused"
            && st["follow"]["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("rejected the replication token")
    });
    let log = p.log() + &s.log();
    for secret_text in [
        admin_token.as_str(),
        carol_token.as_str(),
        secret.as_str(),
        tsig_secret.as_str(),
    ] {
        assert!(!log.contains(secret_text), "a secret leaked into a log");
    }
    drop(p);
    drop(s);
    let _ = std::fs::remove_dir_all(&root_dir);
}
