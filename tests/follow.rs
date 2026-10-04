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
    password: &'static str,
    child: Option<Child>,
    /// The binary this node runs (the one under test unless changed: the
    /// mixed-version test runs a node with the previous release).
    bin: PathBuf,
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
            bin: PathBuf::from(env!("CARGO_BIN_EXE_rust-dns")),
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

    /// Start the node; `self.dns` moves when its port was taken (O0a).
    fn start(&mut self) {
        assert!(self.child.is_none());
        for attempt in 0.. {
            assert!(
                attempt < 5,
                "{} never came up with all its listeners",
                self.name
            );
            let mut child = Command::new(&self.bin)
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
            while ureq::get(&format!("{}/api/health", self.url()))
                .timeout(Duration::from_millis(500))
                .call()
                .is_err()
            {
                if Instant::now() >= deadline {
                    // Not left running (an older binary has no stdin hook).
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

fn follow_cfg(primary: &Node, id: &str, token: &str) -> String {
    format!(
        "[follow]\nprimary = \"{}\"\ninstance_id = \"{id}\"\ntoken = \"{token}\"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n",
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
    let replication_cfg =
        "[replication]\nup_to_date_grace_secs = 1\nmax_lag_secs = 3\noffline_after_secs = 8\n";
    p.configure(&format!(
        "[peer]\nurl = \"{}\"\ncheck_interval_secs = 1\n{replication_cfg}",
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
    s.configure(&follow_cfg(&p, "dns2", &bob_token));
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
    s.configure(&follow_cfg(&p, "dns2", &admin_token));
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
    // ---- replica tracking on the primary ------------------------------------------
    let p_replicas = p.api("/replication/replicas");
    let replica = |pr: &ureq::Agent| -> Value {
        let l = ok(
            call(&Auth::Session(pr), "GET", &p_replicas, None),
            "replicas",
        );
        l["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["instance"] == "dns2")
            .cloned()
            .unwrap_or(Value::Null)
    };
    wait_for("the primary lists dns2 up to date", 15, || {
        replica(&pr)["state"] == "up_to_date"
    });
    let r = replica(&pr);
    assert_eq!(r["lag_changes"], 0);
    // The version with what the standby can follow (N1).
    assert_eq!(
        r["version"],
        format!(
            "{}+dnssec-rollover.zone-rename.zone-settings.nsec3",
            env!("CARGO_PKG_VERSION")
        )
    );
    assert_eq!(r["address"], "127.0.0.1");
    assert_eq!(r["conflict"], false);
    assert!(pst["replicas"].to_string().contains("dns2"), "{pst}");
    assert_eq!(
        st["follow"]["instance_id"], "dns2",
        "the standby shows its own id"
    );
    // Requests without an instance id are refused.
    let (code, v) = call(
        &Auth::Token(&admin_token),
        "GET",
        &p.api("/replication/changes?after=0"),
        None,
    );
    assert_eq!(code, 400, "{v}");
    assert!(v["error"].as_str().unwrap().contains("X-Rust-DNS-Instance"));
    // ... and so is a standby config without one.
    let bad = root_dir.join("no-instance.toml");
    std::fs::write(
        &bad,
        std::fs::read_to_string(s.config_path())
            .unwrap()
            .replace("instance_id = \"dns2\"\n", ""),
    )
    .unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--check", "--config"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("instance_id is required"));
    // A stalled standby falls behind while writes continue, then catches up.
    #[cfg(unix)]
    {
        let pid = s.child.as_ref().unwrap().id() as i32;
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/z.test/records"),
                Some(json!({ "name": "stall", "type": "A", "value": "192.0.2.66" })),
            ),
            "write while stalled",
        );
        wait_for("dns2 falling behind", 8, || {
            replica(&pr)["state"] == "falling_behind"
        });
        let r = replica(&pr);
        assert!(
            r["lag_changes"].as_i64().unwrap() >= 2 && r["lag_seconds"].as_i64().unwrap() >= 3,
            "{r}"
        );
        let metrics = ureq::get(&format!("{}/metrics", p.url()))
            .set("Authorization", &format!("Bearer {admin_token}"))
            .call()
            .unwrap()
            .into_string()
            .unwrap();
        assert!(
            metrics.contains(
                "rustdns_replication_replica_state{instance=\"dns2\",state=\"falling_behind\"} 1"
            ),
            "{metrics}"
        );
        assert!(metrics.contains("rustdns_replication_replica_lag_changes{instance=\"dns2\"}"));
        assert!(metrics.contains("rustdns_replication_replicas{state=\"falling_behind\"} 1"));
        unsafe { libc::kill(pid, libc::SIGCONT) };
        wait_for("dns2 caught up again", 15, || {
            replica(&pr)["state"] == "up_to_date"
        });
    }
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
                json!({ "upstreams": ["192.0.2.53"], "allowed_clients": ["0.0.0.0/0", "::/0"], "timeout_ms": 1500, "open_resolver": true }),
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
        // Open resolver mode is part of the replicated setting and applied.
        if fwd["open_resolver"] != true || fwd["allowed_clients"] != json!(["0.0.0.0/0", "::/0"]) {
            m.push("open resolver mode");
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

    // ---- a standby restart resumes without any command -------------------------
    s.stop();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/z.test/records"),
            Some(json!({ "name": "while-down", "type": "A", "value": "192.0.2.44" })),
        ),
        "write while the standby is down",
    );
    s.start();
    let sr = s.root();
    wait_for("restarted standby caught up", 15, || {
        record_names(&s, &sr, "z.test").contains(&"while-down A 192.0.2.44".to_string())
    });
    let st = status(&s, &sr);
    assert_eq!(
        st["follow"]["rebootstraps"], 0,
        "resumed from its offset, no snapshot: {st}"
    );
    assert_eq!(st["follow"]["state"], "following");

    // ---- carol signs in on the primary with TOTP (step X) ---------------------
    let account_rows = |node: &Node| -> Vec<(i64, String)> {
        let c = rusqlite::Connection::open_with_flags(
            node.dir.join("data.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut st = c
            .prepare("SELECT offset, json_extract(payload, '$.kind') FROM changelog WHERE class = 'account' ORDER BY offset")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    // A password change and a token revocation on the primary replicate.
    let bobtok = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "short-lived" })),
        ),
        "token to revoke",
    );
    let bobtok_secret = bobtok["token"].as_str().unwrap().to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "DELETE",
            &p.api(&format!("/tokens/{}", bobtok["info"]["id"])),
            None,
        ),
        "revoke",
    );
    let bob_id = ok(
        call(&Auth::Session(&pr), "GET", &p.api("/users"), None),
        "users",
    )["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "bob")
        .unwrap()["id"]
        .clone();
    ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api(&format!("/users/{bob_id}")),
            Some(json!({ "password": "bob-password-2" })),
        ),
        "bob password",
    );
    wait_for("password change replicated", 10, || {
        call(
            &Auth::None,
            "POST",
            &s.api("/auth/login"),
            Some(json!({ "username": "bob", "password": "bob-password-2" })),
        )
        .0 == 200
    });
    let (code, _) = call(&Auth::Token(&bobtok_secret), "GET", &s.api("/me"), None);
    assert_eq!(code, 401, "revoked on the standby too");
    let snapshots_before = status(&s, &sr)["follow"]["rebootstraps"].clone();
    let rows_before = account_rows(&s).len();
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
    // The used step reaches the standby as exactly one incremental change.
    wait_for("TOTP step replicated", 10, || {
        account_rows(&s).len() > rows_before
    });
    std::thread::sleep(Duration::from_millis(500));
    let new_rows: Vec<String> = account_rows(&s)[rows_before..]
        .iter()
        .map(|r| r.1.clone())
        .collect();
    assert_eq!(
        new_rows,
        vec!["totp_step_accepted".to_string()],
        "one change, no full sync"
    );
    let first = account_rows(&s)[0].0;
    let primary_rows: Vec<(i64, String)> = account_rows(&p)
        .into_iter()
        .filter(|r| r.0 >= first)
        .collect();
    assert_eq!(
        account_rows(&s),
        primary_rows,
        "same account rows, same offsets (since the snapshot)"
    );
    assert_eq!(
        status(&s, &sr)["follow"]["rebootstraps"],
        snapshots_before,
        "no snapshot was loaded"
    );
    // Account changes never appear in the user-facing changelog, not even for admins.
    for (node, agent) in [(&p, &pr), (&s, &sr)] {
        let cl = ok(
            call(
                &Auth::Session(agent),
                "GET",
                &node.api("/changelog?after=0&limit=2000"),
                None,
            ),
            "changelog",
        );
        let text = cl.to_string();
        for kind in [
            "user_created",
            "user_updated",
            "totp_step_accepted",
            "token_created",
            "tsig_key_set",
            "setting_set",
        ] {
            assert!(!text.contains(kind), "{kind} leaked into /api/changelog");
        }
        assert!(
            !text.contains("argon2"),
            "no password hashes in /api/changelog"
        );
    }
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
    wait_for("dns2 offline after it stopped", 15, || {
        replica(&pr)["state"] == "offline"
    });
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
    // The console's "Promoted" dialog lists these notes.
    let notes = r["notes"].as_array().expect("notes");
    assert!(
        !notes.is_empty()
            && notes
                .iter()
                .all(|n| n.as_str().is_some_and(|t| !t.is_empty())),
        "{r}"
    );
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
    let r = replica(&pr);
    assert_eq!(
        r["state"], "offline",
        "the replica list survived the restart: {r}"
    );
    // Forgetting is audited local bookkeeping.
    let (code, _) = call(
        &Auth::Session(&pr),
        "DELETE",
        &p.api("/replication/replicas/dns2"),
        None,
    );
    assert_eq!(code, 409, "a fenced server is read-only");
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

    // ---- the old primary is told to follow: refused, it has its own data -------
    p.stop();
    p.configure(&follow_cfg(&s, "dns1", &admin_token));
    p.start();
    let pr = p.root();
    wait_for(
        "the old primary refuses to follow while it has data",
        20,
        || {
            let st = status(&p, &pr);
            st["follow"]["state"] == "refused"
                && st["follow"]["last_error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("--prepare-standby")
        },
    );
    let st = status(&p, &pr);
    let err = st["follow"]["last_error"].as_str().unwrap();
    assert!(err.contains("zone"), "names the data: {err}");
    assert_eq!(st["writable"], false, "still read-only");
    let summary = ok(
        call(&Auth::Session(&pr), "GET", &p.api("/status"), None),
        "status",
    );
    assert!(summary["replication"]["problem"]
        .as_str()
        .is_some_and(|m| m.contains("--prepare-standby")));
    ok(
        call(
            &Auth::Session(&pr),
            "GET",
            &p.api("/zones/diverged.test"),
            None,
        ),
        "its own data is untouched",
    );
    let (code, _) = call(
        &Auth::Session(&pr),
        "POST",
        &p.api("/zones"),
        Some(json!({ "name": "x.test" })),
    );
    assert_eq!(code, 409);
    p.stop();
    let check = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--check", "--config"])
        .arg(p.config_path())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&check.stdout).contains("--prepare-standby"),
        "--check warns: {}",
        String::from_utf8_lossy(&check.stdout)
    );

    // ---- --prepare-standby: without --yes nothing changes ------------------------
    let files = |dir: &Path, prefix: &str| -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
            .collect()
    };
    let db_bytes = |p: &Node| {
        (
            std::fs::read(p.dir.join("data.db")).unwrap(),
            std::fs::read(p.dir.join("data.db-wal")).unwrap_or_default(),
        )
    };
    let before = db_bytes(&p);
    let dry = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--prepare-standby", "--config"])
        .arg(p.config_path())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&dry.stdout).to_string();
    assert!(
        !dry.status.success(),
        "without --yes it exits non-zero: {out}"
    );
    assert!(
        out.contains("would delete") && out.contains("zones"),
        "{out}"
    );
    assert!(
        files(&p.dir, "data.db.pre-standby-").is_empty(),
        "no backup written"
    );
    assert!(files(&p.dir, "divergent-").is_empty());
    assert!(db_bytes(&p) == before, "database untouched");

    // ---- with --yes: backup, divergence report, fresh database ------------------
    let run = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--prepare-standby", "--yes", "--config"])
        .arg(p.config_path())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&run.stdout).to_string();
    assert!(
        run.status.success(),
        "{out}{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let backups = files(&p.dir, "data.db.pre-standby-");
    assert_eq!(backups.len(), 1, "{out}");
    assert!(
        out.contains(&backups[0].display().to_string()),
        "prints the backup path"
    );
    let bk = rusqlite::Connection::open_with_flags(
        &backups[0],
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let zones: Vec<String> = bk
        .prepare("SELECT name FROM zones")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(
        zones.contains(&"diverged.test".to_string()),
        "the backup has the old data: {zones:?}"
    );
    let integrity: String = bk
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let div = files(&p.dir, "divergent-");
    assert_eq!(div.len(), 1, "one divergence file");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&div[0]).unwrap()).unwrap();
    assert!(
        doc["divergent_changes"]
            .to_string()
            .contains("diverged.test"),
        "the old primary's change after the fork is saved: {doc}"
    );
    assert!(
        doc["fork_offset"].is_i64(),
        "fork point known from the new primary: {doc}"
    );
    assert!(
        !doc.to_string().contains("argon2"),
        "no password hashes in the divergence file"
    );

    // ---- now it follows the new primary --------------------------------------------
    p.start();
    let pr = p.root();
    wait_for("old primary copied the new primary", 20, || {
        let recs = record_names(&p, &pr, "z.test");
        recs.contains(&"after A 192.0.2.77".to_string())
    });
    let audit = ok(
        call(
            &Auth::Session(&pr),
            "GET",
            &p.api("/audit?after=0&limit=1000"),
            None,
        ),
        "audit",
    );
    assert!(
        audit.to_string().contains("replication.prepare_standby"),
        "audited"
    );
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

/// Any divergence is a bug: the standby halts (terminal), reports it, keeps
/// answering DNS from its last state, stays halted across restarts, and
/// follows again only after `--prepare-standby --yes`.
#[test]
fn a_diverged_standby_halts_until_rebuilt() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir =
        std::env::temp_dir().join(format!("rust-dns-halt-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "h.test" })),
        ),
        "zone",
    );
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/h.test/records"),
            Some(json!({ "name": "www", "type": "A", "value": "192.0.2.1" })),
        ),
        "record",
    );
    s.configure(&follow_cfg(&p, "dns2", &token));
    s.start();
    let replica = |pr: &ureq::Agent| -> Value {
        ok(
            call(
                &Auth::Session(pr),
                "GET",
                &p.api("/replication/replicas"),
                None,
            ),
            "replicas",
        )["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["instance"] == "dns2")
            .cloned()
            .unwrap_or(Value::Null)
    };
    wait_for("dns2 up to date", 15, || {
        let r = replica(&pr);
        r["state"] == "up_to_date" && r["lag_changes"] == 0
    });
    let sr = s.root();
    wait_for("standby has the data", 15, || {
        record_names(&s, &sr, "h.test") == vec!["www A 192.0.2.1".to_string()]
    });

    // Corrupt a replicated row behind the standby's back (test only).
    s.stop();
    {
        let c = rusqlite::Connection::open(s.dir.join("data.db")).unwrap();
        c.execute(
            "UPDATE records SET value = '192.0.2.250' WHERE name = 'www'",
            [],
        )
        .unwrap();
    }
    s.start();
    let sr = s.root();
    wait_for("the standby halts at the next reconcile", 20, || {
        status(&s, &sr)["follow"]["state"] == "halted"
    });
    let st = status(&s, &sr);
    let h = &st["follow"]["halted"];
    assert_eq!(h["reason"], "diverged", "{st}");
    assert!(
        h["detail"].as_str().unwrap().contains("h.test"),
        "names the zone: {h}"
    );
    assert!(
        h["detail"].as_str().unwrap().contains("records"),
        "names the table: {h}"
    );
    let report = h["report_file"].as_str().unwrap().to_string();
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(doc["reason"], "diverged");
    assert!(
        doc["evidence"]["local"]["tables"].is_array()
            && doc["evidence"]["primary"]["tables"].is_array()
    );
    assert!(
        !doc.to_string().contains("argon2"),
        "no secrets in the report"
    );
    assert!(s.log().contains("REPLICATION HALTED"));
    let summary = ok(
        call(&Auth::Session(&sr), "GET", &s.api("/status"), None),
        "status",
    );
    assert_eq!(summary["replication"]["halted"], true);
    assert!(summary["replication"]["problem"]
        .as_str()
        .unwrap()
        .contains("Replication halted"));
    let metrics = ureq::get(&format!("{}/metrics", s.url()))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(
        metrics.contains("rustdns_replication_halted 1"),
        "{metrics}"
    );
    // It keeps answering DNS from its last (diverged) state, and stops polling.
    assert_eq!(answers(s.dns, "www.h.test.", RecordType::A).1.len(), 1);
    wait_for("the primary shows dns2 halted", 15, || {
        replica(&pr)["state"] == "halted"
    });
    assert!(replica(&pr)["halted_reason"]
        .as_str()
        .unwrap()
        .contains("diverged"));
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/h.test/records"),
            Some(json!({ "name": "new", "type": "A", "value": "192.0.2.2" })),
        ),
        "write on the primary",
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        answers(s.dns, "new.h.test.", RecordType::A).1.is_empty(),
        "a halted standby does not follow"
    );

    // Halted survives a restart (and is reported again).
    s.stop();
    let check = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--check", "--config"])
        .arg(s.config_path())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&check.stdout).contains("REPLICATION HALTED"),
        "--check says so"
    );
    s.start();
    let sr = s.root();
    wait_for("still halted after a restart", 10, || {
        status(&s, &sr)["follow"]["state"] == "halted"
    });
    assert_eq!(replica(&pr)["state"], "halted");

    // Rebuild: --prepare-standby --yes, then it follows again.
    s.stop();
    let run = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--prepare-standby", "--yes", "--config"])
        .arg(s.config_path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    s.start();
    let sr = s.root();
    wait_for("rebuilt standby follows", 20, || {
        record_names(&s, &sr, "h.test")
            == vec!["new A 192.0.2.2".to_string(), "www A 192.0.2.1".to_string()]
    });
    assert!(status(&s, &sr)["follow"]["halted"].is_null());
    wait_for("dns2 up to date again", 15, || {
        replica(&pr)["state"] == "up_to_date"
    });
    drop(p);
    drop(s);
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

#[test]
fn dnssec_signing_on_the_primary_is_served_by_the_standby() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-dnssec-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let transfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    p.configure(transfer);
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "sec.test" })),
        ),
        "zone",
    );
    for (n, t, v) in [
        ("@", "NS", "ns1.sec.test."),
        ("ns1", "A", "192.0.2.53"),
        ("www", "A", "192.0.2.1"),
        ("*.gate", "A", "192.0.2.2"),
        ("gate", "A", "192.0.2.3"),
        ("a.b.deep", "TXT", "hello"),
    ] {
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/sec.test/records"),
                Some(json!({ "name": n, "type": t, "value": v })),
            ),
            "record",
        );
    }
    s.configure(&format!("{transfer}{}", follow_cfg(&p, "dns2", &token)));
    s.start();
    let sr = s.root();
    wait_for("standby has the zone", 15, || {
        record_names(&s, &sr, "sec.test").len() == 6
    });

    // Turn signing on at the primary.
    let on = ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/sec.test/dnssec"),
            Some(json!({ "enabled": true })),
        ),
        "enable DNSSEC",
    );
    let key_tag = on["key"]["key_tag"].clone();
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    wait_for("the standby signs with the replicated key", 15, || {
        let st = call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/zones/sec.test/dnssec"),
            None,
        )
        .1;
        st["state"] == "signing" && st["key"]["key_tag"] == key_tag
    });
    let sst = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/zones/sec.test/dnssec"),
            None,
        ),
        "standby status",
    );
    assert_eq!(sst["standby"], true);
    assert!(
        sst["signatures"]["next_resign"].is_null(),
        "a standby never re-signs"
    );
    assert_eq!(sst["key"]["dnskey"], on["key"]["dnskey"]);
    assert_eq!(sst["ds"], on["ds"], "same DS from both servers");
    // Same data and serial; the same signature window (from the replicated
    // change time), but their own (randomised) ECDSA signatures.
    assert_eq!(
        soa_serial(p.dns, "sec.test."),
        soa_serial(s.dns, "sec.test.")
    );
    assert_eq!(
        sst["signatures"]["inception"],
        on["signatures"]["inception"]
    );
    let pk = dnssec_query(p.dns, "sec.test.", RecordType::DNSKEY);
    let sk = dnssec_query(s.dns, "sec.test.", RecordType::DNSKEY);
    let dnskey_rdata = |m: &Message| {
        m.answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DNSKEY)
            .map(|r| r.data.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(dnskey_rdata(&pk), dnskey_rdata(&sk));
    let pw = dnssec_query(p.dns, "x.gate.sec.test.", RecordType::A);
    let sw = dnssec_query(s.dns, "x.gate.sec.test.", RecordType::A);
    assert_eq!(pw.answers.len(), 2, "A + RRSIG");
    assert_eq!(sw.answers.len(), 2, "A + RRSIG");
    assert!(sw
        .authorities
        .iter()
        .any(|r| r.record_type() == RecordType::NSEC));
    // A write on the standby is refused.
    let (code, v) = call(
        &Auth::Session(&sr),
        "PUT",
        &s.api("/zones/sec.test/dnssec"),
        Some(json!({ "enabled": false, "force": true })),
    );
    assert_eq!(code, 409, "{v}");
    assert_eq!(v["code"], "read_only_standby");

    // Independent validation of the standby's answers.
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

    // Reconcile: every replicated table (the key included) and the zone
    // match; nothing halted; the standby wrote no serial bump of its own.
    let head = ok(
        call(
            &Auth::Session(&pr),
            "GET",
            &p.api("/replication/status"),
            None,
        ),
        "primary status",
    )["head"]
        .clone();
    wait_for("a reconcile at the primary's head reports ok", 20, || {
        let st = status(&s, &sr);
        st["head"] == head
            && st["follow"]["last_reconcile_result"]
                .as_str()
                .is_some_and(|r| r.starts_with("ok"))
    });
    let st = status(&s, &sr);
    assert!(st["follow"]["halted"].is_null(), "{st}");
    assert_eq!(st["follow"]["state"], "following");
    assert_eq!(
        soa_serial(p.dns, "sec.test."),
        soa_serial(s.dns, "sec.test.")
    );
    assert!(!s.log().contains("re-signed"), "the standby never re-signs");
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// The previous release's binary (`RUST_DNS_PREV_BIN`: built from the
/// commit that is deployed), for the mixed-version tests. Without it they
/// are skipped (loudly), unless `REQUIRE_PREV_BIN` is set.
fn prev_bin() -> Option<PathBuf> {
    match std::env::var_os("RUST_DNS_PREV_BIN").map(PathBuf::from) {
        Some(p) if p.is_file() => Some(p),
        _ => {
            assert!(
                std::env::var("REQUIRE_PREV_BIN").is_err(),
                "RUST_DNS_PREV_BIN is not set to the previous release's binary"
            );
            eprintln!("follow: RUST_DNS_PREV_BIN not set; skipping the mixed-version test");
            None
        }
    }
}

fn dnssec_status(n: &Node, a: &ureq::Agent, zone: &str) -> Value {
    ok(
        call(
            &Auth::Session(a),
            "GET",
            &n.api(&format!("/zones/{zone}/dnssec")),
            None,
        ),
        "dnssec status",
    )
}

/// AXFR from `port` and `dnssec-verify` it (skipped without BIND tools).
fn verify_zone(dir: &Path, port: u16, zone: &str, what: &str) {
    let (Some(dig), Some(verify)) = (bind_tool("dig"), bind_tool("dnssec-verify")) else {
        return;
    };
    let out = Command::new(&dig)
        .args([
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            zone,
            "AXFR",
            "+nocmd",
            "+nocomments",
            "+nostats",
        ])
        .output()
        .unwrap();
    let zf = dir.join(format!("{}-axfr.zone", what.replace(' ', "-")));
    std::fs::write(&zf, &out.stdout).unwrap();
    let v = Command::new(&verify)
        .args(["-z", "-o", zone, zf.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&v.stdout).to_string() + &String::from_utf8_lossy(&v.stderr);
    assert!(
        v.status.success() && text.contains("Zone fully signed"),
        "{what}: {text}"
    );
}

fn wait_reconciled(p: &Node, pr: &ureq::Agent, s: &Node, sr: &ureq::Agent, what: &str) {
    let head = status(p, pr)["head"].clone();
    wait_for(
        &format!("{what}: reconcile ok at the primary's head"),
        30,
        || {
            let st = status(s, sr);
            assert!(st["follow"]["halted"].is_null(), "{what}: halted: {st}");
            st["head"] == head
                && st["follow"]["last_reconcile_result"]
                    .as_str()
                    .is_some_and(|r| r.starts_with("ok") && r.ends_with(&format!("offset {head}")))
        },
    );
}

/// D1, mixed versions: a signed zone followed across an upgrade in either
/// order. Nothing halts, the signatures of both servers validate at every
/// step, the window served before the upgrade is the window served after
/// it, and once both run this version an ordinary change no longer moves
/// the window and the standby has the primary's signing epoch.
#[test]
fn a_signed_zone_survives_a_mixed_version_pair_and_the_upgrade() {
    let Some(prev) = prev_bin() else { return };
    for primary_first in [false, true] {
        let tag = if primary_first {
            "primary-first"
        } else {
            "standby-first"
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!(
            "rust-dns-follow-mixed-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root_dir).unwrap();
        let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
        let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
        let new_bin = p.bin.clone();
        // Both start on the previous release, as deployed.
        p.bin = prev.clone();
        s.bin = prev.clone();
        let transfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
        p.configure(transfer);
        p.start();
        let pr = p.root();
        let token = ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/tokens"),
                Some(json!({ "name": "repl" })),
            ),
            "token",
        )["token"]
            .as_str()
            .unwrap()
            .to_string();
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones"),
                Some(json!({ "name": "mix.test" })),
            ),
            "zone",
        );
        let add = |a: &ureq::Agent, n: &Node, name: &str, v: &str| {
            ok(
                call(
                    &Auth::Session(a),
                    "POST",
                    &n.api("/zones/mix.test/records"),
                    Some(json!({ "name": name, "type": "A", "value": v })),
                ),
                "record",
            );
        };
        add(&pr, &p, "www", "192.0.2.1");
        add(&pr, &p, "*.w", "192.0.2.2");
        ok(
            call(
                &Auth::Session(&pr),
                "PUT",
                &p.api("/zones/mix.test/dnssec"),
                Some(json!({ "enabled": true })),
            ),
            "enable DNSSEC",
        );
        s.configure(&format!("{transfer}{}", follow_cfg(&p, "dns2", &token)));
        s.start();
        let sr = s.root();
        wait_reconciled(&p, &pr, &s, &sr, &format!("{tag}: both previous"));
        // A previous release with D1 (d32d67f and later) keeps the window
        // itself; an older one (3884ba8) moves it with every change.
        let prev_keeps_window = ok(
            call(&Auth::Session(&pr), "GET", &p.api("/zones/mix.test"), None),
            "zone",
        )
        .get("signed_at")
        .is_some();
        eprintln!("{tag}: previous release keeps the signing window: {prev_keeps_window}");
        let inception0 = dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"].clone();
        assert!(inception0.is_string());
        assert_eq!(
            dnssec_status(&s, &sr, "mix.test")["signatures"]["inception"],
            inception0
        );

        // Upgrade one server in place (same database), then change data
        // while the pair is mixed.
        let (first, first_is_primary) = if primary_first {
            (&mut p, true)
        } else {
            (&mut s, false)
        };
        first.stop();
        first.bin = new_bin.clone();
        first.start();
        let (pr, sr) = (p.root(), s.root());
        assert_eq!(
            dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"],
            inception0,
            "{tag}: the window did not move at the upgrade (primary)"
        );
        assert_eq!(
            dnssec_status(&s, &sr, "mix.test")["signatures"]["inception"],
            inception0,
            "{tag}: the window did not move at the upgrade (standby)"
        );
        wait_reconciled(&p, &pr, &s, &sr, &format!("{tag}: mixed, before a change"));
        std::thread::sleep(Duration::from_millis(1100));
        add(&pr, &p, "mixed", "192.0.2.3");
        wait_for("the change reaches the standby", 20, || {
            soa_serial(s.dns, "mix.test.") == soa_serial(p.dns, "mix.test.")
        });
        wait_reconciled(&p, &pr, &s, &sr, &format!("{tag}: mixed, after a change"));
        let p_inc = dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"].clone();
        let s_inc = dnssec_status(&s, &sr, "mix.test")["signatures"]["inception"].clone();
        if prev_keeps_window {
            // Both versions keep the window and carry the epoch.
            assert_eq!(p_inc, inception0, "{tag}");
            assert_eq!(s_inc, inception0, "{tag}");
        } else if first_is_primary {
            // The upgraded primary keeps its window; the old standby signs
            // by the old rule (from the change time). Both validate.
            assert_eq!(p_inc, inception0, "{tag}");
            assert_ne!(s_inc, inception0, "{tag}");
        } else {
            // The old primary moves its window with every change, and the
            // upgraded standby follows it (no epoch from that primary).
            assert_ne!(p_inc, inception0, "{tag}");
            assert_eq!(s_inc, p_inc, "{tag}");
        }
        verify_zone(
            &root_dir,
            p.dns,
            "mix.test",
            &format!("{tag} mixed primary"),
        );
        verify_zone(
            &root_dir,
            s.dns,
            "mix.test",
            &format!("{tag} mixed standby"),
        );

        // Upgrade the other one too.
        let second = if primary_first { &mut s } else { &mut p };
        second.stop();
        second.bin = new_bin.clone();
        second.start();
        let (pr, sr) = (p.root(), s.root());
        wait_reconciled(&p, &pr, &s, &sr, &format!("{tag}: both upgraded"));
        assert_eq!(
            dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"],
            p_inc,
            "{tag}: the primary's window did not move at its upgrade"
        );
        // From now on a change keeps the window, and the standby has the
        // primary's signing epoch (carried by every serial bump).
        std::thread::sleep(Duration::from_millis(1100));
        add(&pr, &p, "after", "192.0.2.4");
        wait_for("the change reaches the standby", 20, || {
            soa_serial(s.dns, "mix.test.") == soa_serial(p.dns, "mix.test.")
        });
        wait_reconciled(
            &p,
            &pr,
            &s,
            &sr,
            &format!("{tag}: both upgraded, after a change"),
        );
        let zone_of = |n: &Node, a: &ureq::Agent| {
            ok(
                call(&Auth::Session(a), "GET", &n.api("/zones/mix.test"), None),
                "zone",
            )
        };
        let (pz, sz) = (zone_of(&p, &pr), zone_of(&s, &sr));
        assert!(pz["signed_at"].is_string(), "{tag}: {pz}");
        assert_eq!(pz["signed_at"], sz["signed_at"], "{tag}");
        let p2 = dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"].clone();
        assert_eq!(p2, p_inc, "{tag}: an ordinary change keeps the window");
        assert_eq!(
            dnssec_status(&s, &sr, "mix.test")["signatures"]["inception"],
            p2,
            "{tag}: same window on both"
        );
        std::thread::sleep(Duration::from_millis(1100));
        add(&pr, &p, "again", "192.0.2.5");
        wait_for("the change reaches the standby", 20, || {
            soa_serial(s.dns, "mix.test.") == soa_serial(p.dns, "mix.test.")
        });
        assert_eq!(
            dnssec_status(&p, &pr, "mix.test")["signatures"]["inception"],
            p2
        );
        verify_zone(
            &root_dir,
            p.dns,
            "mix.test",
            &format!("{tag} final primary"),
        );
        verify_zone(
            &root_dir,
            s.dns,
            "mix.test",
            &format!("{tag} final standby"),
        );
        wait_reconciled(&p, &pr, &s, &sr, &format!("{tag}: final"));
        let st = status(&s, &sr);
        assert_eq!(st["follow"]["state"], "following", "{tag}: {st}");
        drop(p);
        drop(s);
        let _ = std::fs::remove_dir_all(&root_dir);
    }
}

/// `delv` each (name, type, expected first-line prefix) against `port`,
/// trusting `dnskey` (skipped without BIND tools).
fn delv_all(dir: &Path, dnskey: &str, zone: &str, port: u16, cases: &[(&str, &str, &str)]) {
    let Some(delv) = bind_tool("delv") else {
        return;
    };
    let f: Vec<&str> = dnskey.split_whitespace().collect();
    let anchor = dir.join("delv-anchor.conf");
    std::fs::write(
        &anchor,
        format!(
            "trust-anchors {{ \"{}\" static-key {} {} {} \"{}\"; }};\n",
            f[0], f[4], f[5], f[6], f[7]
        ),
    )
    .unwrap();
    for (name, t, want) in cases {
        let out = Command::new(&delv)
            .args([
                "@127.0.0.1",
                "-p",
                &port.to_string(),
                "-a",
                anchor.to_str().unwrap(),
                &format!("+root={zone}"),
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

/// H3: a record stops being served at its expiry time on every node, by
/// the node's own clock, without any commit: here on a standby cut off
/// from its primary (which therefore never sends `record_expired`). The
/// standby writes nothing; its signed zone stays valid (NSEC chain and
/// signatures follow the served data).
#[test]
fn an_expired_record_stops_being_served_on_a_cut_off_standby() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-expiry-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let transfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    p.configure(transfer);
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "exp.test" })),
        ),
        "zone",
    );
    for (n, t, v) in [
        ("@", "NS", "ns1.exp.test."),
        ("ns1", "A", "192.0.2.53"),
        ("www", "A", "192.0.2.1"),
    ] {
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/exp.test/records"),
                Some(json!({ "name": n, "type": t, "value": v })),
            ),
            "record",
        );
    }
    let on = ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/exp.test/dnssec"),
            Some(json!({ "enabled": true })),
        ),
        "enable DNSSEC",
    );
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    s.configure(&format!("{transfer}{}", follow_cfg(&p, "dns2", &token)));
    s.start();
    let sr = s.root();
    wait_for("standby has the zone", 15, || {
        record_names(&s, &sr, "exp.test").len() == 3
    });
    // Two short-lived records: one alone at its name (the name goes), one
    // beside a permanent record (only that RRset goes).
    for (n, t, v) in [("tmp", "A", "192.0.2.9"), ("www", "TXT", "short-lived")] {
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/exp.test/records"),
                Some(json!({ "name": n, "type": t, "value": v, "expires_in": 6 })),
            ),
            "short-lived record",
        );
    }
    let expires = Instant::now() + Duration::from_secs(6);
    wait_for("standby serves the short-lived records", 5, || {
        answers(s.dns, "tmp.exp.test.", RecordType::A).1.len() == 1
            && answers(s.dns, "www.exp.test.", RecordType::TXT).1.len() == 1
    });
    let serial = soa_serial(s.dns, "exp.test.");
    let head = status(&s, &sr)["head"].clone();
    verify_zone(&root_dir, s.dns, "exp.test", "standby before expiry");
    // Cut off: the primary goes away before the expiry.
    p.stop();
    std::thread::sleep(expires.saturating_duration_since(Instant::now()));
    wait_for("the standby stops serving them by its own clock", 3, || {
        answers(s.dns, "tmp.exp.test.", RecordType::A).0 == ResponseCode::NXDomain
            && answers(s.dns, "www.exp.test.", RecordType::TXT)
                .1
                .is_empty()
    });
    assert_eq!(
        answers(s.dns, "www.exp.test.", RecordType::A).1.len(),
        1,
        "the permanent record at the same name stays"
    );
    assert_eq!(soa_serial(s.dns, "exp.test."), serial, "no serial bump");
    let st = status(&s, &sr);
    assert_eq!(st["head"], head, "the standby wrote nothing");
    assert_eq!(
        record_names(&s, &sr, "exp.test").len(),
        5,
        "still stored (the primary's record_expired has not arrived)"
    );
    verify_zone(&root_dir, s.dns, "exp.test", "cut-off standby after expiry");
    delv_all(
        &root_dir,
        &dnskey,
        "exp.test",
        s.dns,
        &[
            ("www.exp.test", "A", "; fully validated"),
            ("tmp.exp.test", "A", "; negative response, fully validated"),
            (
                "www.exp.test",
                "TXT",
                "; negative response, fully validated",
            ),
        ],
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// Phase I, mixed versions. A new primary with every new console setting
/// configured (resolver settings, blocklists, a forwarding override:
/// `setting_set` changes of keys an old version does not use) keeps a
/// standby on the previous release following, never halted, reconcile ok
/// at every step. After the standby is upgraded in place it applies them
/// (they replicated as rows) and an override zone created then reaches it
/// with its type. An override zone created while the standby is still on
/// the previous release cannot be represented there: see
/// `an_old_standby_cannot_represent_an_override_zone`.
#[test]
fn phase_i_settings_keep_an_old_standby_following() {
    let Some(prev) = prev_bin() else { return };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-phasei-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let new_bin = p.bin.clone();
    s.bin = prev.clone();
    let fwd = "[forwarding]\nallowed_clients = [\"127.0.0.0/8\"]\n";
    p.configure(fwd);
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    let put = |path: &str, body: Value| {
        ok(
            call(&Auth::Session(&pr), "PUT", &p.api(path), Some(body)),
            path,
        );
    };
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "mix.test" })),
        ),
        "zone",
    );
    let add = |name: &str, v: &str| {
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/mix.test/records"),
                Some(json!({ "name": name, "type": "A", "value": v })),
            ),
            "record",
        );
    };
    add("www", "192.0.2.1");
    put(
        "/settings/forwarding",
        json!({ "upstreams": ["192.0.2.53"], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 500 }),
    );
    put(
        "/settings/resolver",
        json!({ "domain_needed": false, "rebind_protection": true, "rebind_allow": ["internal"], "serve_stale": true, "strategy": "fastest", "filter_types": ["AAAA"], "ecs": true }),
    );
    put(
        "/blocklists",
        json!({ "lists": [{ "name": "none", "url": "http://127.0.0.1:9/never.txt" }], "allow": ["example.com"], "action": "null_address" }),
    );
    // O15: rate limiting set from the console (key `rate_limit`).
    put(
        "/settings/rate-limit",
        json!({ "max_resolutions_per_second_per_address": 300, "exempt_valid_cookies": true }),
    );
    // The previous release follows from a snapshot that has these rows.
    s.configure(&format!("{fwd}{}", follow_cfg(&p, "dns2", &token)));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "old standby, after the snapshot");
    // Changed again while following: replayed as `setting_set`.
    put(
        "/settings/resolver",
        json!({ "bogus_priv": false, "strategy": "parallel" }),
    );
    put(
        "/blocklists",
        json!({ "lists": [{ "name": "none", "url": "http://127.0.0.1:9/other.txt", "enabled": false }] }),
    );
    put(
        "/settings/rate-limit",
        json!({ "max_resolutions_per_second_per_address": 250, "slip": 3, "exempt_valid_cookies": true }),
    );
    std::thread::sleep(Duration::from_millis(1100));
    add("mixed", "192.0.2.2");
    wait_for("the change reaches the old standby", 20, || {
        soa_serial(s.dns, "mix.test.") == soa_serial(p.dns, "mix.test.")
    });
    wait_reconciled(&p, &pr, &s, &sr, "old standby, after changes");
    assert_eq!(status(&s, &sr)["follow"]["state"], "following");
    // The old standby keeps answering its zones as before.
    assert_eq!(
        answers(s.dns, "mixed.mix.test.", RecordType::A).1,
        vec!["mixed.mix.test. 300 192.0.2.2"]
    );

    // Upgrade the standby in place: it applies the replicated settings.
    s.stop();
    s.bin = new_bin.clone();
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "upgraded standby");
    let v = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/settings/resolver"),
            None,
        ),
        "standby resolver settings",
    );
    assert_eq!(v["source"], "console");
    assert_eq!(v["settings"]["strategy"], "parallel");
    assert_eq!(v["settings"]["bogus_priv"], false);
    let v = ok(
        call(&Auth::Session(&sr), "GET", &s.api("/blocklists"), None),
        "standby blocklists",
    );
    assert_eq!(
        v["settings"]["lists"][0]["url"],
        "http://127.0.0.1:9/other.txt"
    );
    // O15: the upgraded standby runs its limiter with the replicated rate
    // limiting, and applies a change that arrives while it follows.
    let rl = |what: &str| {
        ok(
            call(
                &Auth::Session(&sr),
                "GET",
                &s.api("/settings/rate-limit"),
                None,
            ),
            what,
        )
    };
    let v = rl("standby rate limit");
    assert_eq!(v["source"], "console", "{v}");
    assert_eq!(
        v["in_effect"]["max_resolutions_per_second_per_address"], 250,
        "{v}"
    );
    assert_eq!(v["in_effect"]["slip"], 3, "{v}");
    assert_eq!(v["in_effect"]["exempt_valid_cookies"], true, "{v}");
    put(
        "/settings/rate-limit",
        json!({ "max_resolutions_per_second_per_address": 40, "exempt_valid_cookies": false }),
    );
    wait_for("the standby applies the new limit", 20, || {
        rl("standby rate limit")["in_effect"]["max_resolutions_per_second_per_address"] == 40
    });
    assert_eq!(
        rl("standby rate limit")["in_effect"]["exempt_valid_cookies"],
        false
    );
    // A write on the standby is refused (its only writer is replication).
    assert_eq!(
        call(
            &Auth::Session(&sr),
            "PUT",
            &s.api("/settings/rate-limit"),
            Some(json!({ "slip": 0 })),
        )
        .0,
        409
    );
    // An override zone now replicates with its type.
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "corp.test", "override": { "mode": "static" } })),
        ),
        "override zone",
    );
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones/corp.test/records"),
            Some(json!({ "name": "gw", "type": "A", "value": "10.8.0.1" })),
        ),
        "override record",
    );
    wait_for("the override zone reaches the standby", 20, || {
        query(s.dns, "gw.corp.test.", RecordType::A)
            .answers
            .iter()
            .any(|r| r.data.to_string() == "10.8.0.1")
    });
    let m = query(s.dns, "gw.corp.test.", RecordType::A);
    assert!(
        !m.metadata.authoritative,
        "the standby serves it as an override zone"
    );
    assert_eq!(
        query(s.dns, "nope.corp.test.", RecordType::A)
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    wait_reconciled(&p, &pr, &s, &sr, "upgraded standby, override zone");
    drop(p);
    drop(s);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// What an old (previous release) standby does with an override zone
/// created on a new primary: it cannot store the type, so it applies the
/// zone as an ordinary authoritative zone, the per-zone checksum differs
/// and the standby HALTS (diverged), as for any divergence. Recorded in
/// plan.md (Rollout): upgrade the standby before creating override zones.
/// A previous release that has override zones (d32d67f, phase I) follows
/// one instead: reconcile ok, served non-authoritatively.
#[test]
fn an_old_standby_cannot_represent_an_override_zone() {
    let Some(prev) = prev_bin() else { return };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-ovold-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    s.bin = prev.clone();
    p.configure("");
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &token));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "old standby");
    // A previous release with phase I (d32d67f and later) has override
    // zones: it follows one like the current version.
    let prev_has_overrides = call(
        &Auth::Session(&sr),
        "GET",
        &s.api("/settings/resolver"),
        None,
    )
    .0 == 200;
    eprintln!("previous release has override zones: {prev_has_overrides}");
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "corp.test", "override": { "mode": "static" } })),
        ),
        "override zone",
    );
    if prev_has_overrides {
        ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/zones/corp.test/records"),
                Some(json!({ "name": "gw", "type": "A", "value": "10.8.0.1" })),
            ),
            "override record",
        );
        wait_reconciled(&p, &pr, &s, &sr, "old standby with phase I, override zone");
        let m = query(s.dns, "gw.corp.test.", RecordType::A);
        assert!(!m.metadata.authoritative, "served as an override zone");
        assert_eq!(m.answers.len(), 1);
        drop(p);
        drop(s);
        let _ = std::fs::remove_dir_all(&root_dir);
        return;
    }
    let head = status(&p, &pr)["head"].clone();
    let mut last = Value::Null;
    wait_for("the old standby reconciles at the new head", 30, || {
        last = status(&s, &sr);
        last["head"] == head
            && last["follow"]["last_reconcile_result"].is_string()
            && last["follow"]["last_reconcile_at"] != Value::Null
            && !last["follow"]["last_reconcile_result"]
                .as_str()
                .unwrap()
                .ends_with(&format!("offset {}", head.as_i64().unwrap() - 1))
    });
    eprintln!("old standby with an override zone: {last}");
    let r = last["follow"]["last_reconcile_result"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !r.starts_with("ok"),
        "an old standby cannot match an override zone: {r}"
    );
    assert_eq!(last["follow"]["halted"]["reason"], "diverged", "{last}");
    // It serves the zone authoritatively (it does not know the type).
    let m = query(s.dns, "x.corp.test.", RecordType::A);
    assert!(m.metadata.authoritative, "old standby: authoritative");
    drop(p);
    drop(s);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// Every DNS changelog row of one node (`/api/changelog`, paged).
fn changelog_rows(node: &Node, a: &ureq::Agent) -> Vec<Value> {
    let mut out = Vec::new();
    let mut after = 0;
    loop {
        let page = ok(
            call(
                &Auth::Session(a),
                "GET",
                &node.api(&format!("/changelog?after={after}&limit=3")),
                None,
            ),
            "changelog",
        );
        let e = page["entries"].as_array().unwrap().clone();
        if e.is_empty() {
            return out;
        }
        after = e.last().unwrap()["offset"].as_i64().unwrap();
        out.extend(e);
    }
}

const DNS_KINDS: [&str; 12] = [
    "zone_created",
    "zone_updated",
    "zone_deleted",
    "record_created",
    "record_updated",
    "record_expired",
    "record_reaped",
    "record_deleted",
    "serial_bumped",
    "member_set",
    "member_removed",
    "zone_resigned",
];

/// K3: a standby starts from a snapshot, which starts its own changelog
/// empty at the snapshot offset. It copies the primary's earlier DNS rows,
/// so its changelog page shows the same history as the primary's (paged,
/// recent, bounds), after a restart, after an in-place upgrade from a
/// version without the copy, and never an account row on either.
#[test]
fn a_standby_shows_the_primarys_dns_changelog() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-changelog-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let post = |path: &str, body: Value| {
        ok(
            call(&Auth::Session(&pr), "POST", &p.api(path), Some(body)),
            path,
        )
    };
    // DNS and account changes interleaved, before the standby exists.
    post(
        "/users",
        json!({ "username": "alice", "password": "alice-pass-1" }),
    );
    post("/zones", json!({ "name": "hist.test", "owner": "alice" }));
    for (n, v) in [("www", "192.0.2.1"), ("mail", "192.0.2.2")] {
        post(
            "/zones/hist.test/records",
            json!({ "name": n, "type": "A", "value": v }),
        );
        post("/tokens", json!({ "name": format!("t-{n}") }));
    }
    let token = post("/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &token));
    s.start();
    let sr = s.root();
    wait_for("standby has the zone", 15, || {
        record_names(&s, &sr, "hist.test").len() == 2
    });
    // And after the snapshot.
    post(
        "/zones/hist.test/records",
        json!({ "name": "late", "type": "A", "value": "192.0.2.3" }),
    );
    post(
        "/users",
        json!({ "username": "bob", "password": "bob-pass-12" }),
    );
    fn same(p: &Node, pr: &ureq::Agent, s: &Node, what: &str) {
        let sr = s.root();
        let want = changelog_rows(p, pr);
        wait_for(what, 15, || changelog_rows(s, &sr) == want);
        // 3 + 2 * 2 rows from before the standby's snapshot, 2 after.
        assert_eq!(want.len(), 7, "{what}: {want:?}");
        assert_eq!(want[0]["payload"]["kind"], "zone_created", "{what}");
        for e in &want {
            let kind = e["payload"]["kind"].as_str().unwrap();
            assert!(DNS_KINDS.contains(&kind), "{what}: account row {e}");
        }
        let page = |n: &Node, a: &ureq::Agent| {
            let v = ok(
                call(&Auth::Session(a), "GET", &n.api("/changelog?limit=4"), None),
                "recent",
            );
            (
                v["entries"].clone(),
                v["oldest_offset"].clone(),
                v["latest_offset"].clone(),
            )
        };
        assert_eq!(page(s, &sr), page(p, pr), "{what}: recent page");
    }
    same(&p, &pr, &s, "the standby shows the primary's changelog");
    // Restart: nothing copied twice.
    s.stop();
    s.start();
    same(&p, &pr, &s, "after a restart");
    // A standby upgraded in place from a version without the copy.
    s.stop();
    let c = rusqlite::Connection::open(s.dir.join("data.db")).unwrap();
    assert!(
        c.execute("DELETE FROM changelog_history", []).unwrap() > 0,
        "the copy was stored"
    );
    drop(c);
    s.start();
    same(&p, &pr, &s, "after an in-place upgrade");
    let st = status(&s, &s.root());
    assert!(st["follow"]["halted"].is_null(), "{st}");
    drop(s);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// M0a, mixed versions with K3/K1/L2: a standby of this version follows a
/// primary on the previous release (`RUST_DNS_PREV_BIN`) holding a signed
/// zone, copies the old primary's earlier DNS changelog through its
/// `/api/changelog` (the same rows, never an account row), publishes the
/// new status fields itself, and serves the signed zone. Then the primary
/// is upgraded in place (nothing copied twice), and a standby on the
/// previous release bootstraps from and follows the upgraded primary.
#[test]
fn a_new_standby_follows_an_old_primary_and_copies_its_changelog() {
    let Some(prev) = prev_bin() else { return };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-m0a-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let mut old = Node::new(&root_dir, "oldstandby", "rootpass-old");
    let new_bin = p.bin.clone();
    p.bin = prev.clone();
    old.bin = prev.clone();
    let transfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    p.configure(transfer);
    p.start();
    let pr = p.root();
    fn post(n: &Node, a: &ureq::Agent, path: &str, body: Value) -> Value {
        ok(
            call(&Auth::Session(a), "POST", &n.api(path), Some(body)),
            path,
        )
    }
    // DNS and account changes interleaved, before the standby exists.
    post(
        &p,
        &pr,
        "/users",
        json!({ "username": "alice", "password": "alice-pass-1" }),
    );
    post(
        &p,
        &pr,
        "/zones",
        json!({ "name": "old.test", "owner": "alice" }),
    );
    for (n, t, v) in [
        ("@", "NS", "ns1.old.test."),
        ("ns1", "A", "192.0.2.53"),
        ("www", "A", "192.0.2.1"),
    ] {
        post(
            &p,
            &pr,
            "/zones/old.test/records",
            json!({ "name": n, "type": t, "value": v }),
        );
        post(&p, &pr, "/tokens", json!({ "name": format!("t-{n}") }));
    }
    let on = ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/old.test/dnssec"),
            Some(json!({ "enabled": true })),
        ),
        "enable DNSSEC",
    );
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    let token = post(&p, &pr, "/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&format!("{transfer}{}", follow_cfg(&p, "dns2", &token)));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "new standby of an old primary");
    // And after the snapshot.
    post(
        &p,
        &pr,
        "/zones/old.test/records",
        json!({ "name": "late", "type": "A", "value": "192.0.2.3" }),
    );
    post(
        &p,
        &pr,
        "/users",
        json!({ "username": "bob", "password": "bob-pass-12" }),
    );
    let same = |p: &Node, pr: &ureq::Agent, s: &Node, what: &str| {
        let sr = s.root();
        let want = changelog_rows(p, pr);
        wait_for(what, 15, || changelog_rows(s, &sr) == want);
        assert!(want.len() >= 6, "{what}: {want:?}");
        for e in &want {
            let kind = e["payload"]["kind"].as_str().unwrap();
            assert!(DNS_KINDS.contains(&kind), "{what}: account row {e}");
        }
    };
    same(
        &p,
        &pr,
        &s,
        "the new standby shows the old primary's changelog",
    );
    wait_reconciled(&p, &pr, &s, &sr, "new standby, after changes");
    // The new fields are this server's own (the old primary has none).
    let server_status = |n: &Node, a: &ureq::Agent| {
        ok(
            call(&Auth::Session(a), "GET", &n.api("/status"), None),
            "status",
        )
    };
    let st = server_status(&s, &sr);
    let allow = st["replication"]["standby_writable"].as_array().unwrap();
    assert!(
        allow.contains(&json!({ "method": "POST", "path": "/replication/promote" })),
        "{st}"
    );
    assert!(server_status(&p, &pr)["replication"]
        .get("standby_writable")
        .is_none());
    let me = ok(call(&Auth::Session(&sr), "GET", &s.api("/me"), None), "me");
    assert_eq!(me["recovery_codes_left"], 0, "{me}");
    let cases = [
        ("www.old.test", "A", "; fully validated"),
        ("late.old.test", "A", "; fully validated"),
        ("nope.old.test", "A", "; negative response, fully validated"),
    ];
    verify_zone(&root_dir, s.dns, "old.test", "new standby of old primary");
    delv_all(&root_dir, &dnskey, "old.test", s.dns, &cases);

    // Upgrade the primary in place: the standby keeps following, its
    // history is not copied twice.
    p.stop();
    p.bin = new_bin.clone();
    p.start();
    let pr = p.root();
    s.stop();
    s.start();
    let sr = s.root();
    std::thread::sleep(Duration::from_millis(1100));
    post(
        &p,
        &pr,
        "/zones/old.test/records",
        json!({ "name": "upgraded", "type": "A", "value": "192.0.2.4" }),
    );
    wait_reconciled(&p, &pr, &s, &sr, "both new");
    same(&p, &pr, &s, "both new");

    // A standby on the previous release bootstraps from the new primary.
    old.configure(&format!("{transfer}{}", follow_cfg(&p, "dns3", &token)));
    old.start();
    let or = old.root();
    wait_reconciled(&p, &pr, &old, &or, "old standby of the new primary");
    std::thread::sleep(Duration::from_millis(1100));
    post(
        &p,
        &pr,
        "/zones/old.test/records",
        json!({ "name": "last", "type": "A", "value": "192.0.2.5" }),
    );
    wait_reconciled(&p, &pr, &old, &or, "old standby, after a change");
    wait_reconciled(&p, &pr, &s, &sr, "new standby, after a change");
    for (n, port) in [
        ("old standby", old.dns),
        ("new standby", s.dns),
        ("primary", p.dns),
    ] {
        verify_zone(&root_dir, port, "old.test", &format!("final {n}"));
        delv_all(
            &root_dir,
            &dnskey,
            "old.test",
            port,
            &[("last.old.test", "A", "; fully validated")],
        );
    }
    let st = status(&old, &or);
    assert_eq!(st["follow"]["state"], "following", "{st}");
    drop(old);
    drop(s);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// M1: a token's scope is part of its row: it replicates (created scoped,
/// changed, cleared) and the standby enforces it like the primary;
/// reconcile stays ok. With the previous release as standby: unscoped
/// tokens keep it following, and the first scoped token makes it halt
/// (diverged) — it cannot enforce a scope, so it must not look healthy.
/// Recorded in plan.md (Rollout): upgrade the standby first, create scoped
/// tokens only once both run this version.
#[test]
fn token_scopes_replicate_and_are_enforced_on_the_standby() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-scope-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    fn post(n: &Node, a: &ureq::Agent, path: &str, body: Value) -> Value {
        ok(
            call(&Auth::Session(a), "POST", &n.api(path), Some(body)),
            path,
        )
    }
    post(
        &p,
        &pr,
        "/users",
        json!({ "username": "alice", "password": "alice-pass-1" }),
    );
    for z in ["a.test", "b.test"] {
        post(&p, &pr, "/zones", json!({ "name": z, "owner": "alice" }));
    }
    let repl = post(&p, &pr, "/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    let alice = p.login("alice", "alice-pass-1");
    let scoped = post(
        &p,
        &alice,
        "/tokens",
        json!({ "name": "ro", "scope": { "zones": ["a.test"], "max_role": "viewer", "expires_at": "2999-01-01T00:00:00Z" } }),
    );
    let (tok, tid) = (
        scoped["token"].as_str().unwrap().to_string(),
        scoped["info"]["id"].as_i64().unwrap(),
    );
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "scoped token in the snapshot");
    let zones = |n: &Node| -> Vec<String> {
        let v = ok(
            call(&Auth::Token(&tok), "GET", &n.api("/zones"), None),
            "zones by token",
        );
        v["zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|z| {
                format!(
                    "{}:{}",
                    z["name"].as_str().unwrap(),
                    z["role"].as_str().unwrap()
                )
            })
            .collect()
    };
    assert_eq!(zones(&p), vec!["a.test:viewer"]);
    assert_eq!(zones(&s), vec!["a.test:viewer"], "enforced on the standby");
    assert_eq!(
        call(&Auth::Token(&tok), "GET", &s.api("/zones/b.test"), None).0,
        404
    );
    // Changed while following: replayed as `token_tags_set` with the scope.
    ok(
        call(
            &Auth::Session(&alice),
            "PUT",
            &p.api(&format!("/tokens/{tid}")),
            Some(json!({ "scope": { "max_role": "editor" } })),
        ),
        "rescope",
    );
    wait_for("the new scope reaches the standby", 20, || {
        zones(&s) == vec!["a.test:editor", "b.test:editor"]
    });
    wait_reconciled(&p, &pr, &s, &sr, "rescoped");
    ok(
        call(
            &Auth::Session(&alice),
            "PUT",
            &p.api(&format!("/tokens/{tid}")),
            Some(json!({ "scope": {} })),
        ),
        "unscope",
    );
    wait_for("the cleared scope reaches the standby", 20, || {
        zones(&s) == vec!["a.test:owner", "b.test:owner"]
    });
    wait_reconciled(&p, &pr, &s, &sr, "unscoped");
    drop(s);

    // The previous release as standby.
    let Some(prev) = prev_bin() else {
        drop(p);
        let _ = std::fs::remove_dir_all(&root_dir);
        return;
    };
    let mut old = Node::new(&root_dir, "old", "rootpass-old");
    old.bin = prev;
    old.configure(&follow_cfg(&p, "dns3", &repl));
    old.start();
    let or = old.root();
    wait_reconciled(&p, &pr, &old, &or, "old standby, no scoped token");
    post(
        &p,
        &alice,
        "/tokens",
        json!({ "name": "ro2", "scope": { "zones": ["a.test"] } }),
    );
    let mut last = Value::Null;
    wait_for("the old standby halts on the scoped token", 30, || {
        last = status(&old, &or);
        !last["follow"]["halted"].is_null()
    });
    assert_eq!(last["follow"]["halted"]["reason"], "diverged", "{last}");
    eprintln!("old standby with a scoped token: {last}");
    drop(old);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// M2: a zone's record expiry policy is part of the zone row: it reaches
/// the standby (snapshot and `zone_updated`), reconcile stays ok. With the
/// previous release as standby: no policy, it follows; the first policy
/// makes it halt (the per-zone checksum covers the zone row) — recorded in
/// plan.md (Rollout): upgrade the standby first.
#[test]
fn a_zone_record_policy_replicates() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-policy-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let req = |m: &str, path: &str, body: Value| {
        ok(call(&Auth::Session(&pr), m, &p.api(path), Some(body)), path)
    };
    req("POST", "/zones", json!({ "name": "dyn.test" }));
    req("POST", "/zones", json!({ "name": "late.test" }));
    req(
        "PUT",
        "/zones/dyn.test",
        json!({ "record_policy": { "default_expiry_secs": 3600, "max_expiry_secs": 86400 } }),
    );
    let repl = req("POST", "/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "policy in the snapshot");
    let policy = |n: &Node, a: &ureq::Agent, z: &str| {
        ok(
            call(
                &Auth::Session(a),
                "GET",
                &n.api(&format!("/zones/{z}")),
                None,
            ),
            "zone",
        )["record_policy"]
            .clone()
    };
    assert_eq!(policy(&s, &sr, "dyn.test")["max_expiry_secs"], 86400);
    req(
        "PUT",
        "/zones/late.test",
        json!({ "record_policy": { "max_expiry_secs": 600 } }),
    );
    req("PUT", "/zones/dyn.test", json!({ "record_policy": null }));
    wait_reconciled(&p, &pr, &s, &sr, "policy changed while following");
    assert_eq!(
        policy(&s, &sr, "late.test"),
        json!({ "max_expiry_secs": 600 })
    );
    assert!(policy(&s, &sr, "dyn.test").is_null());
    drop(s);

    let Some(prev) = prev_bin() else {
        drop(p);
        let _ = std::fs::remove_dir_all(&root_dir);
        return;
    };
    req("PUT", "/zones/late.test", json!({ "record_policy": null }));
    let mut old = Node::new(&root_dir, "old", "rootpass-old");
    old.bin = prev;
    old.configure(&follow_cfg(&p, "dns3", &repl));
    old.start();
    let or = old.root();
    wait_reconciled(&p, &pr, &old, &or, "old standby, no policy");
    req(
        "PUT",
        "/zones/dyn.test",
        json!({ "record_policy": { "max_expiry_secs": 600 } }),
    );
    let mut last = Value::Null;
    wait_for("the old standby halts on the policy", 30, || {
        last = status(&old, &or);
        !last["follow"]["halted"].is_null()
    });
    assert_eq!(last["follow"]["halted"]["reason"], "diverged", "{last}");
    eprintln!("old standby with a record policy: {last}");
    drop(old);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// Open a websocket with raw HTTP; returns the stream after the response
/// head, and the head.
fn ws_open(web: &str, path: &str, extra_headers: &str) -> (std::net::TcpStream, String) {
    use std::io::{Read, Write};
    let host = web.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(host).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra_headers}\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).unwrap_or(0) == 0 {
            break;
        }
        head.push(b[0]);
    }
    (s, String::from_utf8_lossy(&head).to_string())
}

/// Read server frames until a close frame: its code (None: ended or timed
/// out without one).
fn ws_wait_close(s: &mut std::net::TcpStream) -> Option<u16> {
    use std::io::Read;
    loop {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).ok()?;
        let op = h[0] & 0x0f;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut l = [0u8; 2];
            s.read_exact(&mut l).ok()?;
            len = u16::from_be_bytes(l) as usize;
        } else if len == 127 {
            let mut l = [0u8; 8];
            s.read_exact(&mut l).ok()?;
            len = u64::from_be_bytes(l) as usize;
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).ok()?;
        if op == 8 {
            return body.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]]));
        }
    }
}

/// O2: a token revoked on the primary closes a stream that uses it on the
/// standby as soon as the standby applies the revocation (it publishes an
/// access signal for the account changes it applied), well before the
/// periodic 10 s re-check.
#[test]
fn a_revocation_on_the_primary_closes_standby_streams_at_once() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-wscut-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let token = |name: &str| {
        let v = ok(
            call(
                &Auth::Session(&pr),
                "POST",
                &p.api("/tokens"),
                Some(json!({ "name": name })),
            ),
            "token",
        );
        (
            v["token"].as_str().unwrap().to_string(),
            v["info"]["id"].as_i64().unwrap(),
        )
    };
    let (repl, _) = token("repl");
    let (tok, tid) = token("stream");
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "token in the snapshot");
    let (mut ws, head) = ws_open(
        &s.url(),
        "/api/ws",
        &format!("Sec-WebSocket-Protocol: rust-dns, rust-dns.bearer.{tok}\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    ok(
        call(
            &Auth::Session(&pr),
            "DELETE",
            &p.api(&format!("/tokens/{tid}")),
            None,
        ),
        "revoke",
    );
    assert_eq!(ws_wait_close(&mut ws), Some(1008));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "closed after {:?}",
        started.elapsed()
    );
    drop(s);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O5: an authenticator enrolled by an administrator on the primary (the
/// secret travels in `user_updated`, as for any enrollment) works on the
/// standby, and the security settings replicate.
#[test]
fn an_admin_enrolled_authenticator_works_on_the_standby() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-adminmfa-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let post = |path: &str, body: Value| {
        ok(
            call(&Auth::Session(&pr), "POST", &p.api(path), Some(body)),
            path,
        )
    };
    let u = post(
        "/users",
        json!({ "username": "pia", "password": "pia-password-1" }),
    );
    let repl = post("/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "user in the snapshot");
    let e = post(&format!("/users/{}/mfa/enroll", u["id"]), json!({}));
    let secret = e["enroll"]["secret"].as_str().unwrap().to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/settings/security"),
            Some(json!({ "mfa_enrollment": "admin" })),
        ),
        "security settings",
    );
    wait_reconciled(&p, &pr, &s, &sr, "enrolled and settings");
    let v = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/settings/security"),
            None,
        ),
        "standby settings",
    );
    assert_eq!(v["settings"]["mfa_enrollment"], "admin", "{v}");
    let a = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let (st, v) = call(
        &Auth::Session(&a),
        "POST",
        &s.api("/auth/login"),
        Some(json!({ "username": "pia", "password": "pia-password-1" })),
    );
    assert_eq!(
        (st, v["status"].as_str()),
        (200, Some("mfa_required")),
        "{v}"
    );
    let (st, v) = call(
        &Auth::Session(&a),
        "POST",
        &s.api("/auth/mfa"),
        Some(json!({ "code": totp_at(&secret, step_now()) })),
    );
    assert_eq!(
        st, 200,
        "the administrator's QR code works on the standby: {v}"
    );
    drop(s);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O6: the security settings and a user's password history replicate
/// (reconcile stays ok: the history is part of the user row). With the previous
/// release as standby: it follows while no history is kept, and halts
/// (`diverged`) once one is (it would drop it): set a history only after
/// every standby is upgraded (plan.md, Rollout).
#[test]
fn a_password_history_replicates_and_an_old_standby_halts_on_it() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-pwhist-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let send = |m: &str, path: &str, body: Value| {
        ok(call(&Auth::Session(&pr), m, &p.api(path), Some(body)), path)
    };
    let u = send(
        "POST",
        "/users",
        json!({ "username": "rita", "password": "Rita-password-1" }),
    );
    let repl = send("POST", "/tokens", json!({ "name": "repl" }))["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "before a history");

    // The previous release as a second standby, before any history.
    let prev = prev_bin();
    let mut old = prev.map(|b| {
        let mut n = Node::new(&root_dir, "old", "rootpass-old");
        n.bin = b;
        n.configure(&follow_cfg(&p, "dns3", &repl));
        n.start();
        n
    });
    let or = old.as_ref().map(|n| n.root());
    if let (Some(o), Some(oa)) = (&old, &or) {
        wait_reconciled(&p, &pr, o, oa, "old standby, no history");
    }

    send(
        "PUT",
        "/settings/security",
        json!({ "password_history": 3 }),
    );
    send(
        "PUT",
        &format!("/users/{}", u["id"]),
        json!({ "password": "Rita-password-2" }),
    );
    wait_reconciled(&p, &pr, &s, &sr, "history kept");
    let v = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/settings/security"),
            None,
        ),
        "standby settings",
    );
    assert_eq!(v["settings"]["password_history"], 3, "{v}");
    if let (Some(o), Some(oa)) = (&old, &or) {
        let mut last = Value::Null;
        wait_for("the old standby halts on the password history", 30, || {
            last = status(o, oa);
            !last["follow"]["halted"].is_null()
        });
        assert_eq!(last["follow"]["halted"]["reason"], "diverged", "{last}");
        eprintln!("old standby with a password history: {last}");
    }
    drop(old.take());
    drop(s);
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O11: a renamed zone reaches the standby (the `zone_updated` row carries
/// the name; reconcile stays ok; DNS answers move to the new name), and
/// bulk edits and clones replicate as ordinary changes. With the previous
/// release following, the primary refuses a rename and names it (that
/// standby would ignore the new name and halt).
#[test]
fn a_zone_rename_replicates_and_waits_for_old_standbys() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-rename-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    p.configure("");
    p.start();
    let pr = p.root();
    let post =
        |path: &str, body: Value| call(&Auth::Session(&pr), "POST", &p.api(path), Some(body));
    ok(post("/zones", json!({ "name": "old.test" })), "zone");
    ok(
        post(
            "/zones/old.test/records/bulk",
            json!({ "add": "www A 192.0.2.7\nmail A 192.0.2.8" }),
        ),
        "bulk",
    );
    let repl = ok(post("/tokens", json!({ "name": "repl" })), "token")["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&follow_cfg(&p, "dns2", &repl));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "before the rename");
    ok(
        post("/zones/old.test/rename", json!({ "name": "new.test" })),
        "rename",
    );
    ok(
        post("/zones/new.test/clone", json!({ "name": "copy.test" })),
        "clone",
    );
    wait_reconciled(&p, &pr, &s, &sr, "renamed and cloned");
    let (rc, a) = answers(s.dns, "www.new.test.", RecordType::A);
    assert_eq!(
        (rc, a),
        (
            ResponseCode::NoError,
            vec!["www.new.test. 300 192.0.2.7".to_string()]
        )
    );
    let (rc, _) = answers(s.dns, "www.old.test.", RecordType::A);
    assert_ne!(
        rc,
        ResponseCode::NoError,
        "the old name is gone on the standby"
    );
    let (_, a) = answers(s.dns, "mail.copy.test.", RecordType::A);
    assert_eq!(a, vec!["mail.copy.test. 300 192.0.2.8".to_string()]);
    drop(s);

    if let Some(prev) = prev_bin() {
        let mut old = Node::new(&root_dir, "old", "rootpass-old");
        old.bin = prev;
        old.configure(&follow_cfg(&p, "dns3", &repl));
        old.start();
        let or = old.root();
        wait_reconciled(&p, &pr, &old, &or, "old standby");
        let (st, v) = post("/zones/new.test/rename", json!({ "name": "newer.test" }));
        assert_eq!(st, 409, "{v}");
        assert!(v["error"].as_str().unwrap().contains("dns3"), "{v}");
        drop(old);
    }
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// First message's rcode of an AXFR of `zone` over TCP.
fn axfr_rcode(port: u16, zone: &str) -> ResponseCode {
    use std::io::{Read, Write};
    let mut m = Message::new(0x4242, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(
        Name::from_ascii(format!("{zone}.")).unwrap(),
        RecordType::AXFR,
    ));
    let q = m.to_vec().unwrap();
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
    c.write_all(&q).unwrap();
    let mut len = [0u8; 2];
    c.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    c.read_exact(&mut buf).unwrap();
    Message::from_bytes(&buf).unwrap().metadata.response_code
}

/// O16: a zone's own settings replicate (a `zone_updated` without a serial
/// bump) and the standby applies them: it refuses the zone's transfer to
/// an address outside the zone's ACL while serving other zones, and stops
/// the zone's automatic PTR; clearing them replicates too; reconcile ok
/// throughout. A standby of the previous release (no `zone-settings`
/// feature) blocks setting them (409, naming it); clearing stays allowed.
#[test]
fn zone_settings_replicate_and_wait_for_old_standbys() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "rust-dns-follow-zset-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let xfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    p.configure(xfer);
    p.start();
    let pr = p.root();
    let post =
        |path: &str, body: Value| call(&Auth::Session(&pr), "POST", &p.api(path), Some(body));
    let put = |body: Value| {
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/zs.test/settings"),
            Some(body),
        )
    };
    for (z, ip) in [("zs.test", "10.7.7.1"), ("plain.test", "10.7.7.2")] {
        ok(post("/zones", json!({ "name": z })), "zone");
        ok(
            post(
                &format!("/zones/{z}/records"),
                json!({ "name": "host", "type": "A", "value": ip }),
            ),
            "record",
        );
    }
    let repl = ok(post("/tokens", json!({ "name": "repl" })), "token")["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&format!("{xfer}{}", follow_cfg(&p, "dns2", &repl)));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "before the settings");
    let ptr = |port: u16, name: &str| -> usize { query(port, name, RecordType::PTR).answers.len() };
    assert_eq!(axfr_rcode(s.dns, "zs.test"), ResponseCode::NoError);
    assert_eq!(ptr(s.dns, "1.7.7.10.in-addr.arpa."), 1);
    let serial = soa_serial(p.dns, "zs.test.");
    ok(
        put(json!({ "auto_ptr": false, "transfer_allow": ["192.0.2.0/24"] })),
        "settings",
    );
    wait_for("the standby refuses the zone's transfer", 20, || {
        axfr_rcode(s.dns, "zs.test") == ResponseCode::Refused
    });
    wait_reconciled(&p, &pr, &s, &sr, "settings set");
    assert_eq!(axfr_rcode(s.dns, "plain.test"), ResponseCode::NoError);
    assert_eq!(ptr(s.dns, "1.7.7.10.in-addr.arpa."), 0, "auto PTR off");
    assert_eq!(ptr(s.dns, "2.7.7.10.in-addr.arpa."), 1, "other zone's");
    assert_eq!(soa_serial(s.dns, "zs.test."), serial, "no serial bump");
    let v = ok(
        call(&Auth::Session(&sr), "GET", &s.api("/zones/zs.test"), None),
        "standby zone",
    );
    assert_eq!(v["settings"]["transfer_allow"], json!(["192.0.2.0/24"]));
    ok(put(json!({})), "cleared");
    wait_for("the standby serves the transfer again", 20, || {
        axfr_rcode(s.dns, "zs.test") == ResponseCode::NoError
    });
    wait_reconciled(&p, &pr, &s, &sr, "settings cleared");
    assert_eq!(ptr(s.dns, "1.7.7.10.in-addr.arpa."), 1);
    drop(s);

    if let Some(prev) = prev_bin() {
        let mut old = Node::new(&root_dir, "old", "rootpass-old");
        old.bin = prev;
        old.configure(&format!("{xfer}{}", follow_cfg(&p, "dns3", &repl)));
        old.start();
        let or = old.root();
        wait_reconciled(&p, &pr, &old, &or, "old standby");
        let (st, v) = put(json!({ "auto_ptr": false }));
        assert_eq!(st, 409, "{v}");
        assert!(v["error"].as_str().unwrap().contains("dns3"), "{v}");
        ok(put(json!({})), "clearing is allowed");
        wait_reconciled(&p, &pr, &old, &or, "old standby, after a no-op clear");
        drop(old);
    }
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O21 helpers: a standby's view of its replication, and a node's replicas.
fn follow_state(n: &Node, a: &ureq::Agent) -> Value {
    status(n, a)["follow"].clone()
}

fn replica_of(n: &Node, a: &ureq::Agent, id: &str) -> Value {
    ok(
        call(
            &Auth::Session(a),
            "GET",
            &n.api("/replication/replicas"),
            None,
        ),
        "replicas",
    )["replicas"]
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
    ok(
        call(
            &Auth::Session(a),
            "POST",
            &n.api(&format!("/zones/{zone}/records")),
            Some(json!({ "name": name, "type": "A", "value": value })),
        ),
        "record",
    );
}

/// O21: cascading standbys. A -> B -> C: C follows B (a standby) with the
/// same offsets and history; B lists C as its replica, A only B. Account
/// changes reach C promptly. A standby with another [root] username, and
/// a previous-release standby, are refused by B (not halted). Promoting B
/// in the middle of the chain: C adopts B's new history and keeps
/// following it.
#[test]
fn cascading_standbys_follow_and_survive_a_promotion_in_the_middle() {
    let root_dir = temp_root("cascade");
    let mut a = Node::new(&root_dir, "a", "rootpass-a");
    let mut b = Node::new(&root_dir, "b", "rootpass-b");
    let mut c = Node::new(&root_dir, "c", "rootpass-c");
    a.configure("");
    a.start();
    let ar = a.root();
    let token = ok(
        call(
            &Auth::Session(&ar),
            "POST",
            &a.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&ar),
            "POST",
            &a.api("/zones"),
            Some(json!({ "name": "c.test" })),
        ),
        "zone",
    );
    add_record(&a, &ar, "c.test", "www", "192.0.2.1");
    b.configure(&follow_cfg(&a, "dns2", &token));
    b.start();
    let br = b.root();
    wait_for("B has the data", 20, || {
        record_names(&b, &br, "c.test") == vec!["www A 192.0.2.1".to_string()]
    });
    c.configure(&follow_cfg(&b, "dns3", &token));
    c.start();
    let cr = c.root();
    wait_for("C has the data through B", 20, || {
        record_names(&c, &cr, "c.test") == vec!["www A 192.0.2.1".to_string()]
    });
    // Same history and offsets down the chain.
    add_record(&a, &ar, "c.test", "two", "192.0.2.2");
    wait_for("C has the new record", 20, || {
        answers(c.dns, "two.c.test.", RecordType::A).1.len() == 1
    });
    let (sa, sb, sc) = (status(&a, &ar), status(&b, &br), status(&c, &cr));
    assert_eq!(sc["history"]["history_id"], sa["history"]["history_id"]);
    assert_eq!(sb["history"]["history_id"], sa["history"]["history_id"]);
    wait_for("same head on all three", 10, || {
        let h = status(&a, &ar)["head"].clone();
        status(&b, &br)["head"] == h && status(&c, &cr)["head"] == h
    });
    assert_eq!(sc["follow"]["primary"], b.url().as_str());
    assert_eq!(sb["local_root"], "root", "a standby names its root: {sb}");
    assert!(sa.get("local_root").is_none(), "only standbys do: {sa}");
    // B tracks C; A tracks only B.
    wait_for("B lists dns3 up to date", 15, || {
        replica_of(&b, &br, "dns3")["state"] == "up_to_date"
    });
    assert!(replica_of(&a, &ar, "dns3").is_null());
    assert_eq!(replica_of(&a, &ar, "dns2")["state"], "up_to_date");
    // C reconciles against B.
    wait_for("C reconciled with B", 15, || {
        follow_state(&c, &cr)["last_reconcile_result"]
            .as_str()
            .is_some_and(|r| r.starts_with("ok"))
    });
    // An account change reaches C promptly (B wakes its long-polls).
    ok(
        call(
            &Auth::Session(&ar),
            "POST",
            &a.api("/users"),
            Some(json!({ "username": "carol", "password": "carolpass123" })),
        ),
        "user",
    );
    let t0 = Instant::now();
    wait_for("carol can sign in on C", 15, || {
        call(
            &Auth::None,
            "POST",
            &c.api("/auth/login"),
            Some(json!({ "username": "carol", "password": "carolpass123" })),
        )
        .0 == 200
    });
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());

    // A standby with another [root] username is refused (not halted).
    {
        let mut d = Node::new(&root_dir, "d", "rootpass-d");
        d.configure(&follow_cfg(&b, "dns4", &token));
        let cfg = std::fs::read_to_string(d.config_path()).unwrap();
        std::fs::write(
            d.config_path(),
            cfg.replace("username = \"root\"", "username = \"admin\""),
        )
        .unwrap();
        d.start();
        let dr = d.login("admin", "rootpass-d");
        wait_for("D refused", 15, || {
            follow_state(&d, &dr)["state"] == "refused"
        });
        let f = follow_state(&d, &dr);
        assert!(f["halted"].is_null(), "{f}");
        assert!(
            f["last_error"]
                .as_str()
                .unwrap()
                .contains("same [root] username"),
            "{f}"
        );
        assert!(record_names(&d, &dr, "c.test").is_empty());
    }
    // A previous-release standby cannot follow a standby: refused, not halted.
    if let Some(prev) = prev_bin() {
        let mut e = Node::new(&root_dir, "e", "rootpass-e");
        e.bin = prev;
        e.configure(&follow_cfg(&b, "dns5", &token));
        e.start();
        let er = e.root();
        wait_for("old E refused", 15, || {
            follow_state(&e, &er)["state"] == "refused"
        });
        assert!(follow_state(&e, &er)["halted"].is_null());
        assert!(record_names(&e, &er, "c.test").is_empty());
    }

    // Promotion in the middle: A goes away, B is promoted, C follows B's
    // new history.
    let old_history = sa["history"]["history_id"].as_str().unwrap().to_string();
    a.stop();
    let r = ok(
        call(
            &Auth::Session(&br),
            "POST",
            &b.api("/replication/promote"),
            Some(json!({ "confirm": true, "force": true })),
        ),
        "promote B",
    );
    let new_history = r["history"]["history_id"].as_str().unwrap().to_string();
    assert_eq!(r["history"]["parent_history_id"], old_history.as_str());
    add_record(&b, &br, "c.test", "three", "192.0.2.3");
    wait_for("C follows promoted B", 30, || {
        answers(c.dns, "three.c.test.", RecordType::A).1.len() == 1
    });
    let sc = status(&c, &cr);
    assert_eq!(sc["history"]["history_id"], new_history.as_str(), "{sc}");
    assert!(sc["follow"]["halted"].is_null(), "{sc}");
    assert!(
        c.log().contains("continuing in its history"),
        "C adopted B's history"
    );
    assert_eq!(status(&b, &br)["head"], sc["head"]);
    wait_for("dns3 up to date on promoted B", 15, || {
        replica_of(&b, &br, "dns3")["state"] == "up_to_date"
    });
    drop((a, b, c));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O21: a standby whose upstream standby halts halts too
/// (`upstream_halted`), at once (B wakes its long-polls), and stays halted
/// after B is rebuilt and follows again: its copy came from B. Rebuilt
/// itself, it follows B again.
#[test]
fn a_standby_of_a_halted_standby_halts_too() {
    let root_dir = temp_root("cascade-halt");
    let mut a = Node::new(&root_dir, "a", "rootpass-a");
    let mut b = Node::new(&root_dir, "b", "rootpass-b");
    let mut c = Node::new(&root_dir, "c", "rootpass-c");
    a.configure("");
    a.start();
    let ar = a.root();
    let token = ok(
        call(
            &Auth::Session(&ar),
            "POST",
            &a.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&ar),
            "POST",
            &a.api("/zones"),
            Some(json!({ "name": "h.test" })),
        ),
        "zone",
    );
    add_record(&a, &ar, "h.test", "www", "192.0.2.1");
    b.configure(&follow_cfg(&a, "dns2", &token));
    b.start();
    let br = b.root();
    wait_for("B has the data", 20, || {
        record_names(&b, &br, "h.test") == vec!["www A 192.0.2.1".to_string()]
    });
    // C's own reconcile is far away: only B's halt can stop it.
    c.configure(&follow_cfg(&b, "dns3", &token).replace(
        "reconcile_interval_secs = 2",
        "reconcile_interval_secs = 3600",
    ));
    c.start();
    let cr = c.root();
    wait_for("C has the data", 20, || {
        record_names(&c, &cr, "h.test") == vec!["www A 192.0.2.1".to_string()]
    });
    wait_for("C following", 10, || {
        follow_state(&c, &cr)["state"] == "following"
    });

    // B's data diverges behind its back; it halts at its next reconcile.
    b.stop();
    {
        let db = rusqlite::Connection::open(b.dir.join("data.db")).unwrap();
        db.execute(
            "UPDATE records SET value = '192.0.2.250' WHERE name = 'www'",
            [],
        )
        .unwrap();
    }
    b.start();
    let br = b.root();
    wait_for("B halts", 20, || follow_state(&b, &br)["state"] == "halted");
    let t0 = Instant::now();
    wait_for("C halts too", 20, || {
        follow_state(&c, &cr)["state"] == "halted"
    });
    assert!(t0.elapsed() < Duration::from_secs(15), "{:?}", t0.elapsed());
    let h = follow_state(&c, &cr)["halted"].clone();
    assert_eq!(h["reason"], "upstream_halted", "{h}");
    assert!(h["detail"].as_str().unwrap().contains(&b.url()), "{h}");
    assert!(std::path::Path::new(h["report_file"].as_str().unwrap()).is_file());
    assert!(c.log().contains("REPLICATION HALTED"));
    wait_for("B shows dns3 halted", 15, || {
        replica_of(&b, &br, "dns3")["state"] == "halted"
    });
    // B refuses to serve, with the code its followers act on.
    let r = ureq::get(&format!("{}?after=0", b.api("/replication/changes")))
        .set("Authorization", &format!("Bearer {token}"))
        .set("X-Rust-DNS-Instance", "probe")
        .call();
    match r {
        Err(ureq::Error::Status(409, resp)) => {
            let v: Value = resp.into_json().unwrap();
            assert_eq!(v["code"], "replication_halted", "{v}");
        }
        other => panic!("halted B must refuse with 409: {other:?}"),
    }

    // A moves on; B is rebuilt and follows again. C stays halted.
    add_record(&a, &ar, "h.test", "new", "192.0.2.2");
    b.stop();
    let run = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--prepare-standby", "--yes", "--config"])
        .arg(b.config_path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    b.start();
    let br = b.root();
    wait_for("rebuilt B follows", 20, || {
        answers(b.dns, "new.h.test.", RecordType::A).1.len() == 1
    });
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(follow_state(&c, &cr)["state"], "halted");
    assert!(
        answers(c.dns, "new.h.test.", RecordType::A).1.is_empty(),
        "a halted standby does not follow its rebuilt upstream"
    );
    // Rebuilt, C follows B again.
    c.stop();
    let run = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .args(["--prepare-standby", "--yes", "--config"])
        .arg(c.config_path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    c.start();
    let cr = c.root();
    wait_for("rebuilt C follows B", 20, || {
        record_names(&c, &cr, "h.test")
            == vec!["new A 192.0.2.2".to_string(), "www A 192.0.2.1".to_string()]
    });
    assert!(follow_state(&c, &cr)["halted"].is_null());
    let _ = &br;
    drop((a, b, c));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O22: the log line of `message` with `field` (e.g. `gzip=true`), if any.
fn log_has(n: &Node, message: &str, field: &str) -> bool {
    n.log()
        .lines()
        .any(|l| l.contains(message) && l.split_whitespace().any(|w| w == field))
}

/// A raw HTTP/1.1 GET (headers lower-cased, body as sent: no decoding).
fn raw_get(n: &Node, path: &str, headers: &[(&str, &str)]) -> (String, Vec<u8>) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", n.web)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).to_lowercase();
    let mut body = buf[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            let eol = i + body[i..].windows(2).position(|w| w == b"\r\n").unwrap();
            let len = usize::from_str_radix(std::str::from_utf8(&body[i..eol]).unwrap().trim(), 16)
                .unwrap();
            if len == 0 {
                break;
            }
            out.extend_from_slice(&body[eol + 2..eol + 2 + len]);
            i = eol + 2 + len + 2;
        }
        body = out;
    }
    (head, body)
}

/// O22: snapshots are gzip-compressed when the standby asks for it
/// (`Accept-Encoding: gzip`), identical once decompressed, and plain
/// otherwise. Mixed versions both ways: a previous-release standby (does
/// not ask) gets plain JSON from this primary, and a standby of this
/// version loads a previous-release primary's plain snapshot.
#[test]
fn snapshots_are_gzip_compressed_when_the_standby_asks() {
    use std::io::Read;
    let root_dir = temp_root("gzip");
    let mut p = Node::new(&root_dir, "primary", "rootpass-p");
    let mut s = Node::new(&root_dir, "standby", "rootpass-s");
    p.configure("");
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "gz.test" })),
        ),
        "zone",
    );
    for i in 0..40 {
        add_record(
            &p,
            &pr,
            "gz.test",
            &format!("host{i}"),
            &format!("192.0.2.{}", i + 1),
        );
    }
    s.configure(&follow_cfg(&p, "dns2", &token));
    s.start();
    let sr = s.root();
    wait_for("standby has the zone", 20, || {
        record_names(&s, &sr, "gz.test").len() == 40
    });
    assert!(
        log_has(&p, "replication snapshot served", "gzip=true"),
        "{}",
        p.log()
    );
    assert!(log_has(&s, "snapshot received", "gzip=true"), "{}", s.log());

    // The same document either way; compressed only when asked.
    let auth = format!("Bearer {token}");
    let hdrs = |gz: bool| {
        let mut v = vec![
            ("Authorization", auth.as_str()),
            ("X-Rust-DNS-Instance", "probe"),
        ];
        if gz {
            v.push(("Accept-Encoding", "gzip"));
        }
        v
    };
    let (h_plain, plain) = raw_get(&p, "/api/replication/snapshot", &hdrs(false));
    let (h_gz, gz) = raw_get(&p, "/api/replication/snapshot", &hdrs(true));
    assert!(h_plain.starts_with("http/1.1 200"), "{h_plain}");
    assert!(!h_plain.contains("content-encoding"), "{h_plain}");
    assert!(h_gz.contains("content-encoding: gzip"), "{h_gz}");
    assert!(h_gz.contains("cache-control: no-store"), "{h_gz}");
    let mut unzipped = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut unzipped)
        .unwrap();
    let mut a: Value = serde_json::from_slice(&plain).unwrap();
    let mut b: Value = serde_json::from_slice(&unzipped).unwrap();
    // Read twice: only the time it was taken differs.
    a["taken_at"] = Value::Null;
    b["taken_at"] = Value::Null;
    assert_eq!(a, b, "same snapshot");
    assert!(
        gz.len() * 3 < plain.len(),
        "compressed {} of {}",
        gz.len(),
        plain.len()
    );

    if let Some(prev) = prev_bin() {
        // A previous-release standby of this primary: plain JSON.
        let mut o = Node::new(&root_dir, "old-standby", "rootpass-o");
        o.bin = prev.clone();
        o.configure(&follow_cfg(&p, "dns3", &token));
        o.start();
        let or = o.root();
        wait_for("old standby has the zone", 20, || {
            record_names(&o, &or, "gz.test").len() == 40
        });
        assert!(
            log_has(&p, "replication snapshot served", "gzip=false"),
            "{}",
            p.log()
        );
        drop(o);
        // A standby of this version of a previous-release primary: plain.
        let mut op = Node::new(&root_dir, "old-primary", "rootpass-op");
        let mut n = Node::new(&root_dir, "new-standby", "rootpass-n");
        op.bin = prev;
        op.configure("");
        op.start();
        let opr = op.root();
        let t2 = ok(
            call(
                &Auth::Session(&opr),
                "POST",
                &op.api("/tokens"),
                Some(json!({ "name": "repl" })),
            ),
            "token",
        )["token"]
            .as_str()
            .unwrap()
            .to_string();
        ok(
            call(
                &Auth::Session(&opr),
                "POST",
                &op.api("/zones"),
                Some(json!({ "name": "old.test" })),
            ),
            "zone",
        );
        add_record(&op, &opr, "old.test", "www", "192.0.2.9");
        n.configure(&follow_cfg(&op, "dns4", &t2));
        n.start();
        let nr = n.root();
        wait_for("new standby has the old primary's zone", 20, || {
            record_names(&n, &nr, "old.test") == vec!["www A 192.0.2.9".to_string()]
        });
        assert!(
            log_has(&n, "snapshot received", "gzip=false"),
            "{}",
            n.log()
        );
    }
    drop((p, s));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O23: test certificates (tests/fixtures/tls, ECDSA P-256, valid until
/// 2126): `ca.pem` signed `server.pem` (SAN 127.0.0.1, localhost; key
/// `server.key`); `other-ca.pem` is an unrelated CA. Made with openssl:
/// `ecparam -genkey`, `req -x509 -addext basicConstraints=critical,CA:TRUE`
/// for the CAs, `x509 -req -extfile` (serverAuth, the SANs) for the leaf.
fn tls_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// O23: an HTTPS endpoint (the fixture certificate) in front of the plain
/// HTTP port `target`, for as long as the test process runs. Its port.
fn tls_proxy(target: u16) -> u16 {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(tls_fixture("server.pem"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
    let key = PrivateKeyDer::from_pem_file(tls_fixture("server.key")).unwrap();
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((tcp, _)) = l.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut up) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
                });
            }
        });
    });
    port
}

/// O23: `[follow].ca_file` / `[peer].ca_file`. A standby follows a primary
/// whose HTTPS certificate a private CA signed when `ca_file` names that CA;
/// without it (system trust store) or with another CA it refuses the
/// certificate and copies nothing. `[peer]` fencing checks reach an HTTPS
/// standby the same way. `--check` rejects a missing or non-PEM file.
#[test]
fn a_private_ca_from_ca_file_is_trusted_for_the_primary_and_the_peer() {
    let root_dir = temp_root("ca-file");
    let mut p = Node::new(&root_dir, "primary", "rootpass-p");
    p.configure("");
    p.start();
    let pr = p.root();
    let token = ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/tokens"),
            Some(json!({ "name": "repl" })),
        ),
        "token",
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    ok(
        call(
            &Auth::Session(&pr),
            "POST",
            &p.api("/zones"),
            Some(json!({ "name": "ca.test" })),
        ),
        "zone",
    );
    add_record(&p, &pr, "ca.test", "www", "192.0.2.1");
    let https = format!("https://127.0.0.1:{}", tls_proxy(p.web));
    let follow_https = |id: &str, ca: Option<&Path>| {
        let mut c = format!(
            "[follow]\nprimary = \"{https}\"\ninstance_id = \"{id}\"\ntoken = \"{token}\"\nreconcile_interval_secs = 2\ntimeout_secs = 5\n"
        );
        if let Some(ca) = ca {
            c.push_str(&format!("ca_file = \"{}\"\n", ca.display()));
        }
        c
    };
    // The private CA: follows over HTTPS.
    let mut s = Node::new(&root_dir, "standby", "rootpass-s");
    s.configure(&follow_https("dns2", Some(&tls_fixture("ca.pem"))));
    s.start();
    let sr = s.root();
    wait_for("standby follows over HTTPS", 20, || {
        record_names(&s, &sr, "ca.test") == vec!["www A 192.0.2.1".to_string()]
    });
    add_record(&p, &pr, "ca.test", "two", "192.0.2.2");
    wait_for("and keeps following", 20, || {
        answers(s.dns, "two.ca.test.", RecordType::A).1.len() == 1
    });
    // No ca_file (system trust store) or an unrelated CA: refused certificate.
    for (id, ca) in [("dns3", None), ("dns4", Some(tls_fixture("other-ca.pem")))] {
        let mut n = Node::new(
            &root_dir,
            if ca.is_some() { "other-ca" } else { "no-ca" },
            "rootpass-n",
        );
        n.configure(&follow_https(id, ca.as_deref()));
        n.start();
        let nr = n.root();
        wait_for("certificate refused", 20, || {
            follow_state(&n, &nr)["last_error"]
                .as_str()
                .is_some_and(|e| e.to_lowercase().contains("certificate"))
        });
        let f = follow_state(&n, &nr);
        assert!(f["halted"].is_null(), "{f}");
        assert!(
            record_names(&n, &nr, "ca.test").is_empty(),
            "{id} copied nothing"
        );
    }
    // --check: the file must exist and hold a PEM certificate.
    let check = |extra: &str| {
        let n = Node::new(&root_dir, "check", "rootpass-c");
        n.configure(&format!("{}{extra}", follow_https("dns5", None)));
        let out = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .args(["--check", "--config"])
            .arg(n.config_path())
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let missing = root_dir.join("missing.pem");
    let (good, out) = check(&format!("ca_file = \"{}\"\n", missing.display()));
    assert!(
        !good && out.contains("[follow].ca_file") && out.contains("cannot be read"),
        "{out}"
    );
    let (good, out) = check(&format!(
        "ca_file = \"{}\"\n",
        tls_fixture("server.key").display()
    ));
    assert!(!good && out.contains("no PEM certificate"), "{out}");
    let (good, out) = check(&format!(
        "ca_file = \"{}\"\n",
        tls_fixture("ca.pem").display()
    ));
    assert!(good, "{out}");

    // [peer]: the primary checks its standby over HTTPS with the private CA.
    let peer_https = format!("https://127.0.0.1:{}", tls_proxy(s.web));
    for (ca, want) in [
        (Some(tls_fixture("ca.pem")), "ok: peer is"),
        (None, "peer not reachable"),
    ] {
        p.stop();
        let mut extra = format!("[peer]\nurl = \"{peer_https}\"\ncheck_interval_secs = 1\n");
        if let Some(ca) = &ca {
            extra.push_str(&format!("ca_file = \"{}\"\n", ca.display()));
        }
        p.configure(&extra);
        p.start();
        let pr = p.root();
        wait_for("peer checked", 15, || {
            status(&p, &pr)["peer"]["last_result"]
                .as_str()
                .is_some_and(|r| r.starts_with(want))
        });
        let r = status(&p, &pr)["peer"]["last_result"]
            .as_str()
            .unwrap()
            .to_string();
        if ca.is_none() {
            assert!(r.to_lowercase().contains("certificate"), "{r}");
        }
        assert_eq!(status(&p, &pr)["writable"], true);
    }
    drop((p, s));
    let _ = std::fs::remove_dir_all(&root_dir);
}

/// O24: a zone switched to NSEC3 on the primary is signed with NSEC3 by
/// the standby too: the same NSEC3 chain (the records are deterministic;
/// only the ECDSA signatures differ) in the NXDOMAIN, NODATA and wildcard
/// proofs of both servers, the standby's zone passes dnssec-verify and
/// delv, its self-check is ok, and the reconcile stays ok through the
/// switch to NSEC3 and back. A standby of the previous release (no `nsec3`
/// feature) blocks the switch (409, naming it) and keeps following;
/// switching back to NSEC stays allowed.
#[test]
fn nsec3_replicates_and_waits_for_old_standbys() {
    let root_dir = temp_root("follow-nsec3");
    let mut p = Node::new(&root_dir, "primary", "rootpass-primary");
    let mut s = Node::new(&root_dir, "standby", "rootpass-standby");
    let xfer = "[transfer]\nallow = [\"127.0.0.0/8\"]\n";
    p.configure(xfer);
    p.start();
    let pr = p.root();
    let post =
        |path: &str, body: Value| call(&Auth::Session(&pr), "POST", &p.api(path), Some(body));
    let put = |body: Value| {
        call(
            &Auth::Session(&pr),
            "PUT",
            &p.api("/zones/n3.test/dnssec"),
            Some(body),
        )
    };
    ok(post("/zones", json!({ "name": "n3.test" })), "zone");
    for (name, t, v) in [
        ("@", "NS", "ns1.n3.test."),
        ("ns1", "A", "192.0.2.53"),
        ("www", "A", "192.0.2.80"),
        ("*.wild", "A", "192.0.2.81"),
        ("a.b.deep", "TXT", "below empty non-terminals"),
    ] {
        ok(
            post(
                "/zones/n3.test/records",
                json!({ "name": name, "type": t, "value": v }),
            ),
            "record",
        );
    }
    let on = ok(put(json!({ "enabled": true })), "signing on");
    assert_eq!(on["denial"], "nsec");
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    let repl = ok(post("/tokens", json!({ "name": "repl" })), "token")["token"]
        .as_str()
        .unwrap()
        .to_string();
    s.configure(&format!("{xfer}{}", follow_cfg(&p, "dns2", &repl)));
    s.start();
    let sr = s.root();
    wait_reconciled(&p, &pr, &s, &sr, "NSEC");

    // The proofs of both servers, without the (randomised) signatures.
    let probes = [
        ("nope.n3.test.", RecordType::A),
        ("www.n3.test.", RecordType::MX),
        ("deep.n3.test.", RecordType::A),
        ("x.y.a.b.deep.n3.test.", RecordType::A),
        ("q.wild.n3.test.", RecordType::A),
        ("q.wild.n3.test.", RecordType::AAAA),
    ];
    let proofs = |port: u16| -> Vec<(ResponseCode, Vec<String>)> {
        probes
            .iter()
            .map(|(n, t)| {
                let m = dnssec_query(port, n, *t);
                let mut v: Vec<String> = m
                    .authorities
                    .iter()
                    .filter(|r| matches!(u16::from(r.record_type()), 47 | 50))
                    .map(|r| format!("{} {:?}", r.name, r.data))
                    .collect();
                v.sort();
                (m.metadata.response_code, v)
            })
            .collect()
    };
    let nsec = proofs(p.dns);
    assert_eq!(nsec, proofs(s.dns), "same NSEC proofs");
    let r = ok(put(json!({ "enabled": true, "denial": "nsec3" })), "NSEC3");
    assert_eq!(r["denial"], "nsec3");
    wait_for("the standby serves NSEC3", 20, || {
        dnssec_query(s.dns, "nope.n3.test.", RecordType::A)
            .authorities
            .iter()
            .any(|r| u16::from(r.record_type()) == 50)
    });
    wait_reconciled(&p, &pr, &s, &sr, "NSEC3");
    let n3 = proofs(p.dns);
    assert_eq!(n3, proofs(s.dns), "same NSEC3 proofs on both servers");
    assert!(n3.iter().all(|(_, v)| !v.is_empty()), "{n3:?}");
    assert_ne!(n3, nsec);
    let st = dnssec_status(&s, &sr, "n3.test");
    assert_eq!(st["denial"], "nsec3", "{st}");
    let chk = ok(
        call(
            &Auth::Session(&sr),
            "GET",
            &s.api("/zones/n3.test/dnssec/check"),
            None,
        ),
        "standby check",
    );
    assert_eq!(chk["ok"], true, "{chk:#}");
    verify_zone(&root_dir, s.dns, "n3.test", "standby nsec3");
    let cases = [
        ("www.n3.test", "A", "; fully validated"),
        ("q.wild.n3.test", "A", "; fully validated"),
        ("nope.n3.test", "A", "; negative response, fully validated"),
        ("deep.n3.test", "A", "; negative response, fully validated"),
        (
            "q.wild.n3.test",
            "AAAA",
            "; negative response, fully validated",
        ),
    ];
    delv_all(&root_dir, &dnskey, "n3.test", s.dns, &cases);
    // A standby cannot switch it.
    let (st, _) = call(
        &Auth::Session(&sr),
        "PUT",
        &s.api("/zones/n3.test/dnssec"),
        Some(json!({ "enabled": true, "denial": "nsec" })),
    );
    assert_eq!(st, 409, "read-only standby");
    ok(
        put(json!({ "enabled": true, "denial": "nsec" })),
        "back to NSEC",
    );
    wait_reconciled(&p, &pr, &s, &sr, "NSEC again");
    assert_eq!(proofs(s.dns), proofs(p.dns));
    assert_eq!(dnssec_status(&s, &sr, "n3.test")["denial"], "nsec");
    drop(s);

    if let Some(prev) = prev_bin() {
        let mut old = Node::new(&root_dir, "old", "rootpass-old");
        old.bin = prev;
        old.configure(&format!("{xfer}{}", follow_cfg(&p, "dns3", &repl)));
        old.start();
        let or = old.root();
        wait_reconciled(&p, &pr, &old, &or, "old standby");
        let (st, v) = put(json!({ "enabled": true, "denial": "nsec3" }));
        assert_eq!(st, 409, "{v}");
        assert!(v["error"].as_str().unwrap().contains("dns3"), "{v}");
        assert_eq!(dnssec_status(&p, &pr, "n3.test")["denial"], "nsec");
        ok(
            put(json!({ "enabled": true, "denial": "nsec" })),
            "NSEC stays allowed",
        );
        // The old standby still serves valid NSEC answers and follows.
        add_record(&p, &pr, "n3.test", "late", "192.0.2.90");
        wait_reconciled(&p, &pr, &old, &or, "old standby after a change");
        verify_zone(&root_dir, old.dns, "n3.test", "old standby nsec");
        drop(old);
    }
    drop(p);
    let _ = std::fs::remove_dir_all(&root_dir);
}
