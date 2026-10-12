//! Standby (follow) mode end to end with changelog v2 (`crates/sqlite-cdc`):
//! real binaries on loopback (plain http is allowed for loopback).
//!
//! A standby (`[follow]`) streams `<primary>/rust-dns/changelog-api/v2`
//! with its `[follow].token`. A fresh one loads a snapshot, verifies every
//! table against the primary, then streams. It has the primary's accounts
//! only (its users table is an exact copy; its own `[root]` is not synced),
//! so every standby here is signed in to with the PRIMARY's root password.
//!
//! "Same data" ([`same_data`]) is checked through the v2 protocol itself:
//! the same position (history, transaction, chain hash) and, for every
//! captured table, the same bucketed row hashes at that transaction.
//!
//! Covered: bootstrap and live replication of zones, records (expiry
//! included), members, users with MFA, tokens, TSIG keys, settings,
//! DNSSEC, secondary-zone definitions; a read-only standby; a restart that
//! resumes without a snapshot; a standby's own audit events; divergence
//! (halt, keep serving, rebootstrap); failover with a fenced old primary
//! rebootstrapped onto the new one; rebootstrap repointing to another
//! primary.
//!
//! The mixed-version tests (`RUST_DNS_PREV_BIN`) are gone: every previous
//! release replicates with the v1 protocol, whose endpoints no longer
//! exist, so no previous release can follow this one nor be followed by
//! it. They return with the first release after changelog v2.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{json, Value};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// O7: the session's CSRF token (from its cookie), sent with cookie writes.
fn csrf_of(a: &ureq::Agent) -> String {
    a.cookie_store()
        .iter_unexpired()
        .find(|c| c.name() == "rdns_csrf" || c.name() == "__Host-rdns_csrf")
        .map(|c| c.value().to_string())
        .unwrap_or_default()
}

mod common;
use common::free_port;

struct Node {
    name: &'static str,
    dir: PathBuf,
    dns: u16,
    web: u16,
    /// The `[root]` password in this node's config.
    password: &'static str,
    /// The root password to sign in with: its own while it leads, its
    /// primary's while it follows (a standby has the primary's accounts).
    signin: &'static str,
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
            signin: password,
            child: None,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.web)
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("rust-dns.toml")
    }

    fn db_path(&self) -> PathBuf {
        self.dir.join("data.db")
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
            db = self.db_path().display(),
            log = self.dir.join("server.log").display(),
            pw = self.password,
        );
        std::fs::write(self.config_path(), cfg).unwrap();
    }

    /// Start the node; `self.dns` moves when its port was taken (O0a).
    fn start(&mut self) {
        assert!(self.child.is_none());
        for attempt in 0.. {
            assert!(
                attempt < 5,
                "{} never came up with all its listeners",
                self.name
            );
            let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
                .arg("--config")
                .arg(self.config_path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                // O0c: the server exits when this test process is gone.
                .env("RUST_DNS_EXIT_WITH_STDIN", "1")
                .stdin(Stdio::piped())
                .spawn()
                .expect("spawn rust-dns");
            let deadline = Instant::now() + Duration::from_secs(20);
            while ureq::get(&format!("{}/rust-dns/api/health", self.url()))
                .timeout(Duration::from_millis(500))
                .call()
                .is_err()
            {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{} did not come up; log:\n{}", self.name, self.log());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if common::came_up(&mut child, self.dns) {
                self.child = Some(child);
                return;
            }
            self.dns = common::move_dns_port(&self.config_path(), self.dns);
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

    fn try_login(&self, user: &str, pw: &str) -> (u16, Value, ureq::Agent) {
        let a = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let (s, v) = call(
            &Auth::Session(&a),
            "POST",
            &format!("{}/rust-dns/api/auth/login", self.url()),
            Some(json!({ "username": user, "password": pw })),
        );
        (s, v, a)
    }

    /// Sign in. A fresh standby has no accounts until its snapshot loaded
    /// (and a rebootstrapped one swaps them), so this retries for a while.
    fn login(&self, user: &str, pw: &str) -> ureq::Agent {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (s, v, a) = self.try_login(user, pw);
            if s == 200 && v["status"] == "ok" {
                return a;
            }
            assert!(
                Instant::now() < deadline,
                "{} login {user}: {s} {v}\n{}",
                self.name,
                self.log()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn root(&self) -> ureq::Agent {
        self.login("root", self.signin)
    }

    fn api(&self, path: &str) -> String {
        format!("{}/rust-dns/api{path}", self.url())
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
}

fn call(auth: &Auth, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
    let agent;
    let a = match auth {
        Auth::Session(a) => *a,
        Auth::Token(_) => {
            agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build();
            &agent
        }
    };
    let mut req = a
        .request(method, url)
        .set("X-Requested-With", "rust-dns")
        .set("X-CSRF-Token", &csrf_of(a));
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

/// A session call on `n`'s API.
fn api(n: &Node, a: &ureq::Agent, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    call(&Auth::Session(a), method, &n.api(path), body)
}

fn get(n: &Node, a: &ureq::Agent, path: &str) -> Value {
    ok(
        api(n, a, "GET", path, None),
        &format!("{} GET {path}", n.name),
    )
}

fn post(n: &Node, a: &ureq::Agent, path: &str, body: Value) -> Value {
    ok(
        api(n, a, "POST", path, Some(body)),
        &format!("{} POST {path}", n.name),
    )
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
    get(node, a, "/replication/status")
}

fn follow_state(n: &Node, a: &ureq::Agent) -> Value {
    status(n, a)["follow"].clone()
}

fn follow_cfg(primary: &Node, id: &str, token: &str) -> String {
    format!(
        "[follow]\nprimary = \"{}\"\ninstance_id = \"{id}\"\ntoken = \"{token}\"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n",
        primary.url()
    )
}

fn record_names(node: &Node, a: &ureq::Agent, zone: &str) -> Vec<String> {
    let v = api(node, a, "GET", &format!("/zones/{zone}/records"), None);
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

fn record_id(node: &Node, a: &ureq::Agent, zone: &str, name: &str) -> i64 {
    get(node, a, &format!("/zones/{zone}/records"))["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("no record {name} in {zone}"))["id"]
        .as_i64()
        .unwrap()
}

fn replica_of(n: &Node, a: &ureq::Agent, id: &str) -> Value {
    get(n, a, "/replication/replicas")["replicas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["instance"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

fn temp_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("rust-dns-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn add_record(n: &Node, a: &ureq::Agent, zone: &str, name: &str, value: &str) {
    post(
        n,
        a,
        &format!("/zones/{zone}/records"),
        json!({ "name": name, "type": "A", "value": value }),
    );
}

fn new_token(n: &Node, a: &ureq::Agent, name: &str) -> String {
    post(n, a, "/tokens", json!({ "name": name }))["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A GET on `n`'s changelog v2 protocol (needs `replicate`).
fn v2(n: &Node, a: &ureq::Agent, path: &str) -> Value {
    ok(
        call(
            &Auth::Session(a),
            "GET",
            &format!("{}/rust-dns/changelog-api/v2{path}", n.url()),
            None,
        ),
        &format!("{} v2 {path}", n.name),
    )
}

/// The standby `s` holds exactly the primary `p`'s replicated data: the
/// same v2 position (history, transaction, chain hash) and, for every
/// captured table, the same bucketed row hashes at that transaction.
/// Fails at once if `s` halted.
fn same_data(p: &Node, pa: &ureq::Agent, s: &Node, sa: &ureq::Agent, what: &str) {
    let mut at = 0;
    wait_for(
        &format!("{what}: {} at {}'s position", s.name, p.name),
        30,
        || {
            let (ps, ss) = (v2(p, pa, "/status"), v2(s, sa, "/status"));
            assert!(ss["halted"].is_null(), "{what}: {} halted: {ss}", s.name);
            at = ps["last_txn"].as_u64().unwrap();
            ps["history"] == ss["history"]
                && ps["last_txn"] == ss["last_txn"]
                && ps["last_hash"] == ss["last_hash"]
        },
    );
    let tables = v2(p, pa, "/schema");
    let tables = tables.as_array().unwrap();
    let names: Vec<&str> = tables.iter().filter_map(|t| t["name"].as_str()).collect();
    for t in ["zones", "records", "users", "api_tokens", "settings"] {
        assert!(names.contains(&t), "{t} is captured: {names:?}");
    }
    for t in tables {
        let t = t["name"].as_str().unwrap();
        let path = format!("/verify/{t}?at={at}&buckets=16");
        assert_eq!(
            v2(p, pa, &path)["buckets"],
            v2(s, sa, &path)["buckets"],
            "{what}: table {t} differs at txn {at}"
        );
    }
}

/// `s` follows, connected, with no lag and no halt.
fn wait_following(s: &Node, sa: &ureq::Agent, what: &str) {
    wait_for(&format!("{what}: {} following", s.name), 30, || {
        let f = follow_state(s, sa);
        assert!(f["halted"].is_null(), "{what}: halted: {f}");
        f["state"] == "following" && f["connected"] == true && f["lag_changes"] == 0
    });
}

/// A primary and a fresh standby following it (`dns2`), both up; the
/// standby signs in with the primary's root password.
fn pair(
    root: &Path,
    p_extra: &str,
    s_extra: &str,
) -> (Node, ureq::Agent, Node, ureq::Agent, String) {
    let mut p = Node::new(root, "primary", "rootpass-primary");
    let mut s = Node::new(root, "standby", "rootpass-standby");
    p.configure(p_extra);
    p.start();
    let pr = p.root();
    let token = new_token(&p, &pr, "repl");
    s.configure(&format!("{s_extra}{}", follow_cfg(&p, "dns2", &token)));
    s.signin = p.password;
    s.start();
    let sr = s.root();
    (p, pr, s, sr, token)
}

/// The writes a standby refuses (409 `read_only_standby`, naming the primary).
fn assert_read_only(s: &Node, sa: &ureq::Agent, primary: &str) {
    for (m, path, body) in [
        ("POST", "/zones", Some(json!({ "name": "nope.test" }))),
        (
            "POST",
            "/users",
            Some(json!({ "username": "dave", "password": "dave-password-1" })),
        ),
        ("POST", "/tokens", Some(json!({ "name": "x" }))),
        ("POST", "/tsig/keys", Some(json!({ "name": "x" }))),
        (
            "PUT",
            "/settings/forwarding",
            Some(json!({ "upstreams": [], "allowed_clients": [], "timeout_ms": 1000 })),
        ),
    ] {
        let (code, v) = api(s, sa, m, path, body);
        assert_eq!(code, 409, "{m} {path}: {v}");
        assert_eq!(v["code"], "read_only_standby", "{m} {path}: {v}");
        assert!(
            v["error"].as_str().unwrap().contains(primary),
            "names the primary: {v}"
        );
    }
}

/// 1-4, 8: a fresh standby bootstraps (snapshot + verify) and follows:
/// zones, records, members, users with MFA, tokens, TSIG keys, settings;
/// live changes (record create/update/delete and expiry, zone delete with
/// its cascades, user delete) arrive within seconds; it refuses writes and
/// reports following/connected/lag 0, the primary lists it up to date;
/// its own config root is not an account; a sign-in on it is audited
/// locally without disturbing replication; a restart resumes from its
/// position without a snapshot.
#[test]
fn a_fresh_standby_bootstraps_follows_and_resumes() {
    let root_dir = temp_root("follow-basic");
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let repl = new_token(&p, &pr, "repl");

    // ---- data before the standby exists (goes via the snapshot) ----------
    post(
        &p,
        &pr,
        "/users",
        json!({ "username": "bob", "password": "bob-password-1" }),
    );
    let bob = p.login("bob", "bob-password-1");
    let bob_token = new_token(&p, &bob, "bob");
    post(&p, &pr, "/zones", json!({ "name": "z.test" }));
    add_record(&p, &pr, "z.test", "www", "192.0.2.10");
    ok(
        api(
            &p,
            &pr,
            "PUT",
            "/zones/z.test/members/bob",
            Some(json!({ "role": "editor" })),
        ),
        "member",
    );
    let tsig_secret = post(&p, &pr, "/tsig/keys", json!({ "name": "sec1" }))["secret"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        api(
            &p,
            &pr,
            "PUT",
            "/settings/forwarding",
            Some(
                json!({ "upstreams": ["192.0.2.53"], "allowed_clients": ["0.0.0.0/0", "::/0"], "timeout_ms": 1500, "open_resolver": true }),
            ),
        ),
        "forwarding",
    );
    // Carol: MFA required, enrolled on the primary.
    post(
        &p,
        &pr,
        "/users",
        json!({ "username": "carol", "password": "carol-password-1", "mfa_required": true }),
    );
    let (_, login, carol) = p.try_login("carol", "carol-password-1");
    assert_eq!(login["status"], "enroll_required", "{login}");
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

    // ---- bootstrap -----------------------------------------------------------
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.signin = p.password;
    s.start();
    let sr = s.root();
    same_data(&p, &pr, &s, &sr, "bootstrap");
    wait_following(&s, &sr, "bootstrap");
    let st = status(&s, &sr);
    assert_eq!(st["role"], "standby", "{st}");
    assert_eq!(st["writable"], false, "{st}");
    assert_eq!(st["follow"]["instance_id"], "dns2", "{st}");
    assert_eq!(st["follow"]["rebootstraps"], 1, "one snapshot: {st}");
    assert!(
        st["follow"]["last_reconcile_result"]
            .as_str()
            .is_some_and(|r| r.ends_with(": ok")),
        "the snapshot was verified: {st}"
    );
    // The standby's own [root] password is not an account there.
    let (code, v, _) = s.try_login("root", s.password);
    assert_eq!(code, 401, "the standby's config root is not synced: {v}");
    // The primary lists it up to date.
    wait_for("the primary lists dns2 up to date", 20, || {
        let r = replica_of(&p, &pr, "dns2");
        r["state"] == "up_to_date" && r["lag_changes"] == 0
    });

    // What arrived, as the standby's API and DNS show it.
    assert_eq!(
        record_names(&s, &sr, "z.test"),
        record_names(&p, &pr, "z.test")
    );
    assert!(get(&s, &sr, "/zones/z.test")
        .to_string()
        .contains("\"bob\""));
    let me = ok(
        call(&Auth::Token(&bob_token), "GET", &s.api("/me"), None),
        "bob's token on the standby",
    );
    assert_eq!(me["user"]["username"], "bob");
    ok(
        call(
            &Auth::Token(&repl),
            "GET",
            &s.api("/replication/status"),
            None,
        ),
        "the replication token on the standby",
    );
    let rev = ok(
        api(&s, &sr, "POST", "/tsig/keys/sec1./reveal", None),
        "reveal on the standby",
    );
    assert_eq!(rev["secret"].as_str().unwrap(), tsig_secret);
    let fwd = get(&s, &sr, "/settings/forwarding");
    assert_eq!(fwd["upstreams"], json!(["192.0.2.53:53"]), "{fwd}");
    assert_eq!(fwd["open_resolver"], true, "{fwd}");
    // Carol signs in on the standby with her password and TOTP.
    let (_, l, c) = s.try_login("carol", "carol-password-1");
    assert_eq!(l["status"], "mfa_required", "{l}");
    ok(
        call(
            &Auth::Session(&c),
            "POST",
            &s.api("/auth/mfa"),
            Some(json!({ "code": totp_at(&secret, step_now() + 1) })),
        ),
        "carol's TOTP on the standby",
    );
    for (name, t) in [
        ("www.z.test.", RecordType::A),
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
    assert_read_only(&s, &sr, &p.url());
    let (code, v) = api(
        &s,
        &sr,
        "POST",
        "/zones/z.test/records",
        Some(json!({ "name": "x", "type": "A", "value": "192.0.2.1" })),
    );
    assert_eq!(
        (code, &v["code"]),
        (409, &json!("read_only_standby")),
        "{v}"
    );

    // ---- live changes ----------------------------------------------------------
    let t0 = Instant::now();
    add_record(&p, &pr, "z.test", "live", "192.0.2.20");
    let www = record_id(&p, &pr, "z.test", "www");
    ok(
        api(
            &p,
            &pr,
            "PUT",
            &format!("/zones/z.test/records/{www}"),
            Some(json!({ "value": "192.0.2.11" })),
        ),
        "update www",
    );
    let live = record_id(&p, &pr, "z.test", "live");
    post(
        &p,
        &pr,
        "/zones/z.test/records",
        json!({ "name": "tmp", "type": "A", "value": "192.0.2.99", "expires_in": 3 }),
    );
    wait_for("the live changes on the standby", 10, || {
        let r = record_names(&s, &sr, "z.test");
        r.contains(&"live A 192.0.2.20".to_string())
            && r.contains(&"www A 192.0.2.11".to_string())
            && r.contains(&"tmp A 192.0.2.99".to_string())
    });
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "replicated within seconds"
    );
    ok(
        api(
            &p,
            &pr,
            "DELETE",
            &format!("/zones/z.test/records/{live}"),
            None,
        ),
        "delete live",
    );
    wait_for("the delete on the standby", 10, || {
        !record_names(&s, &sr, "z.test").contains(&"live A 192.0.2.20".to_string())
    });
    // The primary's sweeper expires tmp; the standby stops serving it.
    wait_for("tmp expired on both", 20, || {
        answers(p.dns, "tmp.z.test.", RecordType::A).1.is_empty()
            && answers(s.dns, "tmp.z.test.", RecordType::A).1.is_empty()
    });
    assert_eq!(
        answers(s.dns, "www.z.test.", RecordType::A),
        answers(p.dns, "www.z.test.", RecordType::A)
    );
    // A zone with records and a member, deleted: the cascades replicate.
    post(&p, &pr, "/zones", json!({ "name": "gone.test" }));
    add_record(&p, &pr, "gone.test", "www", "192.0.2.30");
    ok(
        api(
            &p,
            &pr,
            "PUT",
            "/zones/gone.test/members/bob",
            Some(json!({ "role": "viewer" })),
        ),
        "member",
    );
    wait_for("gone.test on the standby", 10, || {
        answers(s.dns, "www.gone.test.", RecordType::A).1.len() == 1
    });
    ok(
        api(&p, &pr, "DELETE", "/zones/gone.test", None),
        "delete zone",
    );
    // A user deleted: their token stops working on the standby too.
    let bob_id = get(&p, &pr, "/users")["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "bob")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    ok(
        api(&p, &pr, "DELETE", &format!("/users/{bob_id}"), None),
        "delete bob",
    );
    wait_for("zone and user deletes on the standby", 10, || {
        api(&s, &sr, "GET", "/zones/gone.test", None).0 == 404
            && !get(&s, &sr, "/users").to_string().contains("\"bob\"")
    });
    assert_eq!(
        answers(s.dns, "www.gone.test.", RecordType::A),
        answers(p.dns, "www.gone.test.", RecordType::A)
    );
    let (code, _) = call(&Auth::Token(&bob_token), "GET", &s.api("/me"), None);
    assert_eq!(code, 401, "a deleted user's token is gone on the standby");
    same_data(&p, &pr, &s, &sr, "live changes");
    wait_following(&s, &sr, "live changes");
    wait_for("dns2 up to date after the changes", 20, || {
        replica_of(&p, &pr, "dns2")["state"] == "up_to_date"
    });

    // ---- 8: the standby's own audit events ----------------------------------
    // Sign-ins on the standby were audited there, locally (audit_local, ids
    // from 10^12), next to the primary's replicated audit log.
    let _again = s.root();
    let audit = get(&s, &sr, "/audit?limit=2000");
    let entries = audit["entries"].as_array().unwrap();
    let local: Vec<&Value> = entries
        .iter()
        .filter(|e| e["id"].as_i64().unwrap() >= 1_000_000_000_000)
        .collect();
    assert!(
        local
            .iter()
            .any(|e| e["action"] == "session.create" && e["target"] == "root"),
        "the standby's sign-in is in its audit list: {audit}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e["action"] == "user.delete" || e["action"] == "user.create"),
        "and the primary's replicated audit log: {audit}"
    );
    let paudit = get(&p, &pr, "/audit?limit=2000");
    assert!(
        paudit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["id"].as_i64().unwrap() < 1_000_000_000_000),
        "the standby's own events stay on the standby: {paudit}"
    );
    add_record(&p, &pr, "z.test", "after-audit", "192.0.2.21");
    same_data(&p, &pr, &s, &sr, "after sign-ins on the standby");

    // ---- 4: a restart resumes from its position, no snapshot ----------------
    s.stop();
    add_record(&p, &pr, "z.test", "while-down", "192.0.2.44");
    s.start();
    let sr = s.root();
    same_data(&p, &pr, &s, &sr, "after the restart");
    wait_following(&s, &sr, "after the restart");
    assert!(record_names(&s, &sr, "z.test").contains(&"while-down A 192.0.2.44".to_string()));
    let st = status(&s, &sr);
    assert_eq!(
        st["follow"]["rebootstraps"], 0,
        "resumed from its position, no snapshot: {st}"
    );
    drop((s, p));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// Tools for the DNSSEC checks (BIND; skipped when absent unless
/// REQUIRE_BIND_TOOLS is set).
fn bind_tool(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/opt/homebrew/opt/bind/bin",
        "/usr/local/opt/bind/bin",
        "/usr/local/bin",
        "/usr/bin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(p) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&p));
    }
    let t = dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file());
    if t.is_none() {
        assert!(
            std::env::var("REQUIRE_BIND_TOOLS").is_err(),
            "{name} not found"
        );
        eprintln!("follow: {name} not found; skipping that check");
    }
    t
}

fn dnssec_query(port: u16, name: &str, rtype: RecordType) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut m = Message::new(4343, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(4096).set_dnssec_ok(true);
    m.set_edns(e);
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 65535];
    let n = sock.recv(&mut buf).expect("udp reply");
    Message::from_bytes(&buf[..n]).unwrap()
}

/// 1 (DNSSEC): signing turned on at the primary; the standby has the same
/// key, DS and serial, signs its own answers with the replicated key (never
/// re-signs by itself), and its answers validate with `delv`; its zone
/// transfer passes `dnssec-verify`. Nothing halts, the data stays equal.
#[test]
fn dnssec_signing_on_the_primary_is_served_by_the_standby() {
    let root_dir = temp_root("follow-dnssec");
    let transfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    let (p, pr, s, sr, _) = pair(&root_dir, transfer, transfer);
    post(&p, &pr, "/zones", json!({ "name": "sec.test" }));
    for (n, t, v) in [
        ("@", "NS", "ns1.sec.test."),
        ("ns1", "A", "192.0.2.53"),
        ("www", "A", "192.0.2.1"),
        ("*.gate", "A", "192.0.2.2"),
        ("gate", "A", "192.0.2.3"),
        ("a.b.deep", "TXT", "hello"),
    ] {
        post(
            &p,
            &pr,
            "/zones/sec.test/records",
            json!({ "name": n, "type": t, "value": v }),
        );
    }
    wait_for("standby has the zone", 15, || {
        record_names(&s, &sr, "sec.test").len() == 6
    });

    let on = ok(
        api(
            &p,
            &pr,
            "PUT",
            "/zones/sec.test/dnssec",
            Some(json!({ "enabled": true })),
        ),
        "enable DNSSEC",
    );
    let key_tag = on["key"]["key_tag"].clone();
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    wait_for("the standby signs with the replicated key", 15, || {
        let st = get(&s, &sr, "/zones/sec.test/dnssec");
        st["state"] == "signing" && st["key"]["key_tag"] == key_tag
    });
    let sst = get(&s, &sr, "/zones/sec.test/dnssec");
    assert_eq!(sst["standby"], true);
    assert!(
        sst["signatures"]["next_resign"].is_null(),
        "a standby never re-signs"
    );
    assert_eq!(sst["key"]["dnskey"], on["key"]["dnskey"]);
    assert_eq!(sst["ds"], on["ds"], "same DS from both servers");
    assert_eq!(
        soa_serial(p.dns, "sec.test."),
        soa_serial(s.dns, "sec.test.")
    );
    assert_eq!(
        sst["signatures"]["inception"],
        on["signatures"]["inception"]
    );
    let dnskey_rdata = |m: &Message| {
        m.answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DNSKEY)
            .map(|r| r.data.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        dnskey_rdata(&dnssec_query(p.dns, "sec.test.", RecordType::DNSKEY)),
        dnskey_rdata(&dnssec_query(s.dns, "sec.test.", RecordType::DNSKEY))
    );
    let sw = dnssec_query(s.dns, "x.gate.sec.test.", RecordType::A);
    assert_eq!(sw.answers.len(), 2, "A + RRSIG");
    assert!(sw
        .authorities
        .iter()
        .any(|r| r.record_type() == RecordType::NSEC));
    let (code, v) = api(
        &s,
        &sr,
        "PUT",
        "/zones/sec.test/dnssec",
        Some(json!({ "enabled": false, "force": true })),
    );
    assert_eq!(code, 409, "{v}");
    assert_eq!(v["code"], "read_only_standby");

    // Independent validation of both servers' answers.
    if let Some(delv) = bind_tool("delv") {
        let f: Vec<&str> = dnskey.split_whitespace().collect();
        let anchor = root_dir.join("anchor.conf");
        std::fs::write(
            &anchor,
            format!(
                "trust-anchors {{ \"{}\" static-key {} {} {} \"{}\"; }};\n",
                f[0], f[4], f[5], f[6], f[7]
            ),
        )
        .unwrap();
        for port in [p.dns, s.dns] {
            for (name, t, want) in [
                ("sec.test", "SOA", "; fully validated"),
                ("sec.test", "DNSKEY", "; fully validated"),
                ("www.sec.test", "A", "; fully validated"),
                ("x.gate.sec.test", "A", "; fully validated"),
                ("nope.sec.test", "A", "; negative response, fully validated"),
                ("deep.sec.test", "A", "; negative response, fully validated"),
                (
                    "x.gate.sec.test",
                    "AAAA",
                    "; negative response, fully validated",
                ),
            ] {
                let out = Command::new(&delv)
                    .args([
                        "@127.0.0.1",
                        "-p",
                        &port.to_string(),
                        "-a",
                        anchor.to_str().unwrap(),
                        "+root=sec.test",
                        name,
                        t,
                    ])
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&out.stdout).to_string()
                    + &String::from_utf8_lossy(&out.stderr);
                assert!(
                    text.lines().any(|l| l.starts_with(want)),
                    "delv @{port} {name} {t}: {text}"
                );
            }
        }
    }
    if let (Some(dig), Some(verify)) = (bind_tool("dig"), bind_tool("dnssec-verify")) {
        let out = Command::new(&dig)
            .args([
                "@127.0.0.1",
                "-p",
                &s.dns.to_string(),
                "sec.test",
                "AXFR",
                "+nocmd",
                "+nocomments",
                "+nostats",
            ])
            .output()
            .unwrap();
        let zf = root_dir.join("standby-axfr.zone");
        std::fs::write(&zf, &out.stdout).unwrap();
        let v = Command::new(&verify)
            .args(["-z", "-o", "sec.test", zf.to_str().unwrap()])
            .output()
            .unwrap();
        let text =
            String::from_utf8_lossy(&v.stdout).to_string() + &String::from_utf8_lossy(&v.stderr);
        assert!(
            v.status.success() && text.contains("Zone fully signed"),
            "{text}"
        );
    }
    same_data(&p, &pr, &s, &sr, "signed zone");
    wait_following(&s, &sr, "signed zone");
    assert_eq!(
        soa_serial(p.dns, "sec.test."),
        soa_serial(s.dns, "sec.test.")
    );
    assert!(!s.log().contains("re-signed"), "the standby never re-signs");
    drop((s, p));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// 1 (secondary zones): a secondary zone's definition replicates; every
/// server transfers the zone from the upstream itself (the transferred
/// records are not replicated), and a NOTIFY refreshes both.
#[test]
fn secondary_zones_replicate_their_definition_and_every_server_transfers_itself() {
    let root_dir = temp_root("follow-secondary");
    let mut u = Node::new(&root_dir, "upstream", "rootpass-up");
    let xfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    // Ports first: the upstream notifies both servers.
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    u.configure(&format!(
        "[transfer]\nallow = [\"127.0.0.0/8\"]\nnotify = [\"127.0.0.1:{}\", \"127.0.0.1:{}\"]\n",
        p.dns, s.dns
    ));
    u.start();
    let ur = u.root();
    post(&u, &ur, "/zones", json!({ "name": "far.test" }));
    add_record(&u, &ur, "far.test", "www", "192.0.2.10");
    p.configure(xfer);
    p.start();
    let pr = p.root();
    let repl = new_token(&p, &pr, "repl");
    let head_before = status(&p, &pr)["head"].as_i64().unwrap();
    let z = post(
        &p,
        &pr,
        "/zones",
        json!({ "name": "far.test", "secondary": { "primaries": [format!("127.0.0.1:{}", u.dns)] } }),
    );
    assert_eq!(
        z["secondary"]["primaries"][0],
        format!("127.0.0.1:{}", u.dns)
    );
    s.configure(&format!("{xfer}{}", follow_cfg(&p, "dns2", &repl)));
    s.signin = p.password;
    s.start();
    let sr = s.root();
    same_data(&p, &pr, &s, &sr, "secondary zone definition");
    for (n, a) in [(&p, &pr), (&s, &sr)] {
        wait_for(&format!("{} transfers far.test", n.name), 20, || {
            answers(n.dns, "www.far.test.", RecordType::A).1.len() == 1
        });
        let st = get(n, a, "/zones/far.test/secondary");
        assert_eq!(st["state"], "ok", "{}: {st}", n.name);
        assert_eq!(st["source"], format!("127.0.0.1:{}", u.dns), "{st}");
    }
    assert_eq!(
        answers(p.dns, "www.far.test.", RecordType::A),
        answers(s.dns, "www.far.test.", RecordType::A)
    );
    let (st, v) = api(
        &p,
        &pr,
        "POST",
        "/zones/far.test/records",
        Some(json!({ "name": "x", "type": "A", "value": "192.0.2.1" })),
    );
    assert_eq!(st, 409, "a secondary zone is read-only: {v}");
    // The upstream changes: its NOTIFY reaches both, each transfers again.
    add_record(&u, &ur, "far.test", "new", "192.0.2.11");
    for n in [&p, &s] {
        wait_for(&format!("{} refreshed by NOTIFY", n.name), 15, || {
            answers(n.dns, "new.far.test.", RecordType::A).1.len() == 1
        });
    }
    assert!(
        get(&s, &sr, "/zones/far.test/secondary")["notifies"]
            .as_u64()
            .unwrap()
            >= 1
    );
    // Only the zone itself entered the primary's history, no transferred record.
    let ch = get(&p, &pr, &format!("/changelog?after={head_before}"));
    let kinds: Vec<String> = ch["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["zone"] == "far.test")
        .map(|c| format!("{} {}", c["entity"], c["action"]))
        .collect();
    assert!(
        !kinds.is_empty() && kinds.iter().all(|k| !k.contains("record")),
        "only the definition, no transferred record: {kinds:?}"
    );
    same_data(&p, &pr, &s, &sr, "after the refreshes");
    wait_following(&s, &sr, "after the refreshes");
    drop((s, p, u));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// 5: a replicated row changed behind the standby's back (directly in its
/// SQLite file, bypassing rust-dns), then changed on the primary: applying
/// the primary's row does not match the standby's before image, so the
/// standby halts (persistent, survives a restart), keeps serving DNS and
/// refuses writes. Rebootstrap replaces its data with the primary's and
/// clears the halt.
#[test]
fn a_diverged_standby_halts_and_rebootstrap_rebuilds_it() {
    let root_dir = temp_root("follow-halt");
    let (p, pr, mut s, sr, _) = pair(&root_dir, "", "");
    post(&p, &pr, "/zones", json!({ "name": "h.test" }));
    add_record(&p, &pr, "h.test", "www", "192.0.2.1");
    add_record(&p, &pr, "h.test", "other", "192.0.2.5");
    same_data(&p, &pr, &s, &sr, "before the corruption");
    let before = status(&s, &sr)["follow"]["rebootstraps"].as_i64().unwrap();
    drop(sr);

    // Corrupt a replicated row behind the standby's back (test only).
    s.stop();
    {
        let c = rusqlite::Connection::open(s.db_path()).unwrap();
        let n = c
            .execute(
                "UPDATE records SET value = '192.0.2.250' WHERE name = 'www'",
                [],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    s.start();
    let sr = s.root();
    wait_following(&s, &sr, "restarted with a corrupt row");
    // The primary changes that row: the standby's copy is not its before image.
    let www = record_id(&p, &pr, "h.test", "www");
    ok(
        api(
            &p,
            &pr,
            "PUT",
            &format!("/zones/h.test/records/{www}"),
            Some(json!({ "value": "192.0.2.2" })),
        ),
        "update www on the primary",
    );
    wait_for("the standby halts", 20, || {
        let f = follow_state(&s, &sr);
        f["state"] == "halted" && !f["halted"].is_null()
    });
    let st = status(&s, &sr);
    assert!(
        !st["follow"]["halted"]["reason"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "{st}"
    );
    let summary = get(&s, &sr, "/status");
    assert_eq!(summary["replication"]["halted"], true, "{summary}");
    // It keeps serving its last data and stays read-only.
    assert_eq!(
        answers(s.dns, "other.h.test.", RecordType::A),
        answers(p.dns, "other.h.test.", RecordType::A)
    );
    assert!(soa_serial(s.dns, "h.test.") > 0);
    assert_read_only(&s, &sr, &p.url());
    // Later changes do not arrive.
    add_record(&p, &pr, "h.test", "later", "192.0.2.6");
    std::thread::sleep(Duration::from_secs(2));
    assert!(answers(s.dns, "later.h.test.", RecordType::A).1.is_empty());
    // The halt is persistent: a restart does not resume following.
    s.stop();
    s.start();
    let sr = s.root();
    wait_for("still halted after a restart", 15, || {
        follow_state(&s, &sr)["state"] == "halted"
    });

    // ---- rebootstrap ------------------------------------------------------------
    let (code, v) = api(
        &s,
        &sr,
        "POST",
        "/replication/rebootstrap",
        Some(json!({ "confirm": false })),
    );
    assert_eq!(code, 400, "{v}");
    post(
        &s,
        &sr,
        "/replication/rebootstrap",
        json!({ "confirm": true }),
    );
    let sr = s.root();
    same_data(&p, &pr, &s, &sr, "after the rebootstrap");
    wait_following(&s, &sr, "after the rebootstrap");
    let st = status(&s, &sr);
    assert!(st["follow"]["halted"].is_null(), "{st}");
    assert!(
        st["follow"]["rebootstraps"].as_i64().unwrap() >= 1,
        "a snapshot was loaded: {st} (before: {before})"
    );
    for name in ["www.h.test.", "later.h.test.", "other.h.test."] {
        assert_eq!(
            answers(s.dns, name, RecordType::A),
            answers(p.dns, name, RecordType::A),
            "{name}"
        );
    }
    assert_eq!(
        record_names(&s, &sr, "h.test"),
        record_names(&p, &pr, "h.test")
    );
    // It follows again.
    add_record(&p, &pr, "h.test", "after", "192.0.2.7");
    same_data(&p, &pr, &s, &sr, "following after the rebootstrap");
    let audit = get(&s, &sr, "/audit?limit=2000").to_string();
    assert!(
        audit.contains("replication.rebootstrap"),
        "the rebootstrap is audited: {audit}"
    );
    drop((s, p));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// 6, first half: a primary (`[peer]` = the standby when `peer`) and its
/// standby `dns2`; the primary dies, the standby is promoted (refused while
/// the primary is reachable) and takes writes (`after.f.test`,
/// `new.test`). Returns with the old primary stopped.
fn failover(root_dir: &Path, peer: bool) -> (Node, Node, ureq::Agent, String) {
    let mut p = Node::new(root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(root_dir, "standby", "rootpass-standby");
    p.configure(&if peer {
        format!("[peer]\nurl = \"{}\"\ncheck_interval_secs = 1\n", s.url())
    } else {
        String::new()
    });
    p.start();
    let pr = p.root();
    let repl = new_token(&p, &pr, "repl");
    post(&p, &pr, "/zones", json!({ "name": "f.test" }));
    add_record(&p, &pr, "f.test", "www", "192.0.2.1");
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.signin = p.password;
    s.start();
    let sr = s.root();
    same_data(&p, &pr, &s, &sr, "before the failover");
    wait_following(&s, &sr, "before the failover");
    // A change streamed after the snapshot: the standby has heard from its
    // primary just now (a standby that has not received a stream line since
    // it connected treats its primary as unreachable; see the report).
    add_record(&p, &pr, "f.test", "streamed", "192.0.2.2");
    same_data(&p, &pr, &s, &sr, "streamed");

    // Promotion is refused while the primary is reachable.
    let (code, v) = api(
        &s,
        &sr,
        "POST",
        "/replication/promote",
        Some(json!({ "confirm": true })),
    );
    assert_eq!(code, 409, "{v}");
    assert_eq!(status(&s, &sr)["role"], "standby");

    // The primary dies; promote.
    p.stop();
    wait_for("the standby sees the primary gone", 30, || {
        follow_state(&s, &sr)["connected"] == false
    });
    assert_eq!(answers(s.dns, "www.f.test.", RecordType::A).1.len(), 1);
    let r = post(&s, &sr, "/replication/promote", json!({ "confirm": true }));
    assert_eq!(r["config_updated"], true, "{r}");
    let cfg_text = std::fs::read_to_string(s.config_path()).unwrap();
    assert!(!cfg_text.contains("\n[follow]"), "{cfg_text}");
    let st = status(&s, &sr);
    assert_eq!(st["role"], "promoted", "{st}");
    assert_eq!(st["writable"], true, "{st}");
    add_record(&s, &sr, "f.test", "after", "192.0.2.77");
    post(&s, &sr, "/zones", json!({ "name": "new.test" }));
    assert_eq!(answers(s.dns, "after.f.test.", RecordType::A).1.len(), 1);
    // The old primary's tokens and accounts work on the new one.
    ok(
        call(
            &Auth::Token(&repl),
            "GET",
            &s.api("/replication/status"),
            None,
        ),
        "the replication token on the new primary",
    );
    (p, s, sr, repl)
}

/// The old primary `p` follows the new primary `s` with `s`'s data.
fn old_primary_follows(p: &Node, s: &Node, sr: &ureq::Agent, what: &str) -> ureq::Agent {
    let pr = p.root();
    same_data(s, sr, p, &pr, what);
    wait_following(p, &pr, what);
    let pst = status(p, &pr);
    assert_eq!(pst["role"], "standby", "{pst}");
    assert_eq!(pst["writable"], false, "{pst}");
    assert_eq!(
        answers(p.dns, "after.f.test.", RecordType::A),
        answers(s.dns, "after.f.test.", RecordType::A)
    );
    assert_eq!(api(p, &pr, "GET", "/zones/new.test", None).0, 200);
    let cfg_text = std::fs::read_to_string(p.config_path()).unwrap();
    assert!(
        cfg_text.contains("[follow]") && cfg_text.contains(&format!("primary = \"{}\"", s.url())),
        "{cfg_text}"
    );
    wait_for("the new primary lists dns1 up to date", 20, || {
        replica_of(s, sr, "dns1")["state"] == "up_to_date"
    });
    pr
}

/// 6: failover. Promote is refused while the primary is reachable; after
/// it stops, the standby is promoted and takes writes. The old primary,
/// restarted as a standby of the new one, never follows silently: it led
/// the history and may hold changes the new primary lacks, so it halts
/// (`former_leader`) and keeps its data until an operator rebootstraps it;
/// then it has the new primary's data and follows.
#[test]
fn failover_promotes_the_standby_and_the_old_primary_follows_the_new_one() {
    let root_dir = temp_root("follow-failover");
    let (mut p, s, sr, repl) = failover(&root_dir, false);
    p.configure(&follow_cfg(&s, "dns1", &repl));
    p.start();
    let pr = p.root();
    wait_for("the old primary halts as a former leader", 20, || {
        status(&p, &pr)["follow"]["halted"]["reason"] == "former_leader"
    });
    assert_read_only(&p, &pr, &s.url());
    post(
        &p,
        &pr,
        "/replication/rebootstrap",
        json!({ "confirm": true }),
    );
    let pr = p.root();
    add_record(&s, &sr, "f.test", "later", "192.0.2.78");
    same_data(&s, &sr, &p, &pr, "rebootstrapped onto the new primary");
    wait_following(&p, &pr, "rebootstrapped onto the new primary");
    assert!(
        status(&p, &pr)["follow"]["rebootstraps"].as_i64().unwrap() >= 1,
        "a snapshot was loaded"
    );
    assert_read_only(&p, &pr, &s.url());
    drop((p, s));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// 6, with `[peer]`: the old primary returns, finds its standby promoted
/// and stays read-only (fenced); a rebootstrap onto the new primary (URL,
/// token, instance id) makes it a standby with the new primary's data.
#[test]
fn a_returning_old_primary_is_fenced_and_rebootstrap_makes_it_a_standby() {
    let root_dir = temp_root("follow-fenced");
    let (mut p, s, sr, repl) = failover(&root_dir, true);
    p.start();
    let pr = p.root();
    wait_for("the old primary is fenced", 20, || {
        status(&p, &pr)["role"] == "fenced"
    });
    assert_eq!(status(&p, &pr)["writable"], false);
    let (code, v) = api(
        &p,
        &pr,
        "POST",
        "/zones",
        Some(json!({ "name": "split.test" })),
    );
    assert_eq!(code, 409, "{v}");
    post(
        &p,
        &pr,
        "/replication/rebootstrap",
        json!({ "confirm": true, "primary": s.url(), "token": repl, "instance_id": "dns1" }),
    );
    old_primary_follows(&p, &s, &sr, "the fenced old primary rebootstrapped");
    drop((p, s));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// AGENT.md section 4: only a fresh database, or one already in this
/// primary's history, may start following; discarding data is an explicit
/// operator action. An old primary that wrote after the split and is then
/// configured to follow the new primary must not silently lose that write:
/// it does not follow (halted or refused) until the operator rebootstraps.
#[test]
fn an_old_primary_with_writes_after_the_split_does_not_silently_follow() {
    let root_dir = temp_root("follow-split");
    let (mut p, s, sr, repl) = failover(&root_dir, false);
    p.start();
    let pr = p.root();
    post(&p, &pr, "/zones", json!({ "name": "split.test" }));
    p.stop();
    p.configure(&follow_cfg(&s, "dns1", &repl));
    p.start();
    let pr = p.root();
    wait_for(
        "the old primary refuses to follow another history",
        20,
        || {
            let f = follow_state(&p, &pr);
            f["state"] == "halted" || f["state"] == "refused"
        },
    );
    assert_eq!(
        api(&p, &pr, "GET", "/zones/split.test", None).0,
        200,
        "the write after the split is kept until the operator decides"
    );
    post(
        &p,
        &pr,
        "/replication/rebootstrap",
        json!({ "confirm": true }),
    );
    old_primary_follows(&p, &s, &sr, "rebootstrapped by the operator");
    drop((p, s));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// 7: a rebootstrap with another primary, token and instance id repoints
/// the standby: its data (accounts included: it signs in with the new
/// primary's root password) becomes the other primary's, its config file's
/// `[follow]` is rewritten, and a restart keeps following the new primary.
#[test]
fn rebootstrap_repoints_a_standby_to_another_primary() {
    let root_dir = temp_root("follow-repoint");
    let (p1, p1r, mut s, sr, _) = pair(&root_dir, "", "");
    post(&p1, &p1r, "/zones", json!({ "name": "one.test" }));
    add_record(&p1, &p1r, "one.test", "www", "192.0.2.1");
    same_data(&p1, &p1r, &s, &sr, "following P1");

    let mut p2 = Node::new(&root_dir, "other", "rootpass-other");
    p2.configure("");
    p2.start();
    let p2r = p2.root();
    let token2 = new_token(&p2, &p2r, "repl2");
    post(&p2, &p2r, "/zones", json!({ "name": "two.test" }));
    add_record(&p2, &p2r, "two.test", "www", "192.0.2.2");
    post(
        &p2,
        &p2r,
        "/users",
        json!({ "username": "erin", "password": "erin-password-1" }),
    );

    post(
        &s,
        &sr,
        "/replication/rebootstrap",
        json!({ "confirm": true, "primary": p2.url(), "token": token2, "instance_id": "dns2b" }),
    );
    s.signin = p2.password;
    let sr = s.root();
    same_data(&p2, &p2r, &s, &sr, "repointed to P2");
    wait_following(&s, &sr, "repointed to P2");
    assert_eq!(api(&s, &sr, "GET", "/zones/one.test", None).0, 404);
    assert_eq!(
        record_names(&s, &sr, "two.test"),
        vec!["www A 192.0.2.2".to_string()]
    );
    assert!(answers(s.dns, "www.one.test.", RecordType::A).1.is_empty());
    assert_eq!(
        answers(s.dns, "www.two.test.", RecordType::A),
        answers(p2.dns, "www.two.test.", RecordType::A)
    );
    s.login("erin", "erin-password-1");
    let (code, _, _) = s.try_login("root", p1.password);
    assert_eq!(code, 401, "P1's accounts are gone");
    let cfg_text = std::fs::read_to_string(s.config_path()).unwrap();
    assert!(
        cfg_text.contains(&format!("primary = \"{}\"", p2.url()))
            && cfg_text.contains(&token2)
            && cfg_text.contains("instance_id = \"dns2b\"")
            && !cfg_text.contains(&p1.url()),
        "[follow] rewritten: {cfg_text}"
    );
    wait_for("P2 lists dns2b up to date", 20, || {
        replica_of(&p2, &p2r, "dns2b")["state"] == "up_to_date"
    });
    // P1's changes do not arrive any more; P2's do, across a restart.
    add_record(&p1, &p1r, "one.test", "late", "192.0.2.9");
    s.stop();
    add_record(&p2, &p2r, "two.test", "while-down", "192.0.2.3");
    s.start();
    let sr = s.root();
    same_data(&p2, &p2r, &s, &sr, "P2 after a restart");
    assert_eq!(status(&s, &sr)["follow"]["rebootstraps"], 0);
    assert!(answers(s.dns, "late.one.test.", RecordType::A).1.is_empty());
    drop((s, p1, p2));
    let _ = std::fs::remove_dir_all(&root_dir);
}

fn user_id(n: &Node, a: &ureq::Agent, name: &str) -> i64 {
    get(n, a, "/users")["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == name)
        .unwrap_or_else(|| panic!("user {name} on {}", n.name))["id"]
        .as_i64()
        .unwrap()
}

/// Sessions are local, so a sign-out on the primary (a new password, an
/// administrator's revoke) removes only the primary's; the standby sees it
/// in the replicated audit log and signs the same users out. And the
/// standby's catalog follows zone by zone: a zone deleted and created
/// again under the same name, records moved between rounds, answer as on
/// the primary.
#[test]
fn sign_outs_on_the_primary_end_sessions_on_the_standby() {
    let root_dir = temp_root("follow-signout");
    let (p, pr, s, sr, _) = pair(&root_dir, "", "");
    for u in ["dan", "eve", "fay"] {
        post(
            &p,
            &pr,
            "/users",
            json!({ "username": u, "password": format!("{u}-password-1") }),
        );
    }
    same_data(&p, &pr, &s, &sr, "users");
    let me = |a: &ureq::Agent| api(&s, a, "GET", "/me", None).0;
    let dan = s.login("dan", "dan-password-1");
    let eve = s.login("eve", "eve-password-1");
    let fay = s.login("fay", "fay-password-1");
    for a in [&dan, &eve, &fay] {
        assert_eq!(me(a), 200, "signed in on the standby");
    }

    let dan_id = user_id(&p, &pr, "dan");
    let eve_id = user_id(&p, &pr, "eve");
    ok(
        api(
            &p,
            &pr,
            "PUT",
            &format!("/users/{dan_id}"),
            Some(json!({ "password": "dan-password-2" })),
        ),
        "new password for dan",
    );
    post(
        &p,
        &pr,
        &format!("/users/{eve_id}/sessions/revoke"),
        json!({}),
    );
    wait_for("dan and eve signed out on the standby", 10, || {
        me(&dan) == 401 && me(&eve) == 401
    });
    assert_eq!(me(&fay), 200, "other users keep their sessions");
    assert_eq!(me(&sr), 200, "root keeps its session");
    let dan = s.login("dan", "dan-password-2");
    assert_eq!(me(&dan), 200, "the new password works on the standby");

    // Zone by zone: churn, then the same answers on both.
    post(&p, &pr, "/zones", json!({ "name": "re.test" }));
    add_record(&p, &pr, "re.test", "www", "192.0.2.21");
    post(&p, &pr, "/zones", json!({ "name": "keep.test" }));
    add_record(&p, &pr, "keep.test", "www", "192.0.2.31");
    ok(
        api(&p, &pr, "DELETE", "/zones/re.test", None),
        "delete re.test",
    );
    post(&p, &pr, "/zones", json!({ "name": "re.test" }));
    add_record(&p, &pr, "re.test", "www", "192.0.2.22");
    add_record(&p, &pr, "keep.test", "mail", "192.0.2.32");
    same_data(&p, &pr, &s, &sr, "zone churn");
    for name in ["www.re.test.", "www.keep.test.", "mail.keep.test."] {
        wait_for(&format!("{name} on the standby"), 10, || {
            answers(s.dns, name, RecordType::A) == answers(p.dns, name, RecordType::A)
        });
    }
    let www = answers(s.dns, "www.re.test.", RecordType::A).1;
    assert!(
        www.len() == 1 && www[0].ends_with("192.0.2.22"),
        "the recreated zone's record only: {www:?}"
    );
    assert_eq!(soa_serial(s.dns, "re.test."), soa_serial(p.dns, "re.test."));
    assert_eq!(
        soa_serial(s.dns, "keep.test."),
        soa_serial(p.dns, "keep.test.")
    );
    drop((s, p));
    let _ = std::fs::remove_dir_all(&root_dir);
}
