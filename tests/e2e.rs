//! End-to-end test: spawn the real binary on random ports, drive the API as
//! the root user, and verify DNS answers over UDP and TCP with hickory-proto.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    dns_port: u16,
    web: String,
    _dir: tempdir::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

mod tempdir {
    pub struct TempDir(pub std::path::PathBuf);
    impl TempDir {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "rust-dns-e2e-{}-{}",
                std::process::id(),
                rand_suffix()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn start() -> Server {
    let dir = tempdir::TempDir::new();
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
# totp() may idle up to 30 s waiting for a fresh time step.
request_header_timeout_secs = 300
# The flows make deliberate failed attempts; the back-off has its own tests.
login_backoff_after = 1000
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "warn"
[backup]
dir = ""
"#,
        db = dir.0.join("test.db").display()
    );
    let cfg_path = dir.0.join("test.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn rust-dns");
    let web = format!("http://127.0.0.1:{web_port}");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ureq::get(&format!("{web}/api/health"))
            .timeout(Duration::from_millis(500))
            .call()
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "server did not come up");
        std::thread::sleep(Duration::from_millis(100));
    }
    Server {
        child,
        dns_port,
        web,
        _dir: dir,
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build()
}

fn login(a: &ureq::Agent, web: &str) {
    let r = a
        .post(&format!("{web}/api/auth/login"))
        .send_json(serde_json::json!({ "username": "root", "password": "rootpass123" }))
        .expect("login");
    let v: serde_json::Value = r.into_json().unwrap();
    assert_eq!(v["status"], "ok");
}

fn post(a: &ureq::Agent, url: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    match a
        .post(url)
        .set("X-Requested-With", "rust-dns")
        .send_json(body)
    {
        Ok(r) => {
            let s = r.status();
            (s, r.into_json().unwrap_or(serde_json::Value::Null))
        }
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(serde_json::Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

fn query_udp(port: u16, name: &str, rtype: RecordType) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).expect("udp reply");
    Message::from_bytes(&buf[..n]).unwrap()
}

fn query_tcp(port: u16, name: &str, rtype: RecordType) -> Message {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    let w = m.to_vec().unwrap();
    s.write_all(&(w.len() as u16).to_be_bytes()).unwrap();
    s.write_all(&w).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    Message::from_bytes(&buf).unwrap()
}

#[test]
fn api_then_dns_roundtrip() {
    let srv = start();
    let a = agent();
    let web = srv.web.clone();

    // Unauthenticated access is refused.
    let (s, _) = post(
        &a,
        &format!("{web}/api/zones"),
        serde_json::json!({ "name": "x.test" }),
    );
    assert_eq!(s, 401);
    login(&a, &web);

    // Zone + records.
    let (s, z) = post(
        &a,
        &format!("{web}/api/zones"),
        serde_json::json!({ "name": "Example.Test.", "soa_rname": "hostmaster@example.test" }),
    );
    assert_eq!(s, 201, "{z}");
    assert_eq!(z["name"], "example.test");
    assert_eq!(z["soa_rname"], "hostmaster.example.test.");
    let recs = [
        ("@", "NS", "ns1.example.test"),
        ("ns1", "A", "10.0.0.53"),
        ("www", "A", "10.0.0.1"),
        ("www", "AAAA", "2001:db8::1"),
        ("alias", "CNAME", "www.example.test"),
        ("*.apps", "A", "10.0.0.9"),
        ("@", "MX", "10 mail.example.test"),
        ("mail", "A", "10.0.0.25"),
        ("@", "TXT", "v=spf1 mx -all"),
    ];
    for (n, t, v) in recs {
        let (s, r) = post(
            &a,
            &format!("{web}/api/zones/example.test/records"),
            serde_json::json!({ "name": n, "type": t, "value": v }),
        );
        assert_eq!(s, 201, "{n} {t} {v}: {r}");
    }
    // Validation and CNAME exclusivity.
    let (s, _) = post(
        &a,
        &format!("{web}/api/zones/example.test/records"),
        serde_json::json!({ "name": "bad", "type": "A", "value": "nope" }),
    );
    assert_eq!(s, 400);
    let (s, _) = post(
        &a,
        &format!("{web}/api/zones/example.test/records"),
        serde_json::json!({ "name": "www", "type": "CNAME", "value": "x.example.test" }),
    );
    assert_eq!(s, 409);
    let (s, _) = post(
        &a,
        &format!("{web}/api/zones/example.test/records"),
        serde_json::json!({ "name": "@", "type": "CNAME", "value": "x.example.test" }),
    );
    assert_eq!(s, 400);

    // DNS answers.
    let p = srv.dns_port;
    let r = query_udp(p, "www.example.test.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.metadata.authoritative);
    assert!(
        matches!(&r.answers[0].data, RData::A(a) if a.0 == std::net::Ipv4Addr::new(10, 0, 0, 1))
    );

    let r = query_tcp(p, "www.example.test.", RecordType::AAAA);
    assert_eq!(r.answers.len(), 1);

    let r = query_udp(p, "alias.example.test.", RecordType::A);
    assert_eq!(r.answers.len(), 2, "CNAME + A");

    let r = query_udp(p, "deep.apps.example.test.", RecordType::A);
    assert_eq!(r.answers.len(), 1, "wildcard");

    let r = query_udp(p, "missing.example.test.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(r.authorities.len(), 1, "SOA in authority");

    let r = query_udp(p, "example.test.", RecordType::MX);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.additionals.len(), 1, "glue for mail");

    let r = query_udp(p, "1.0.0.10.in-addr.arpa.", RecordType::PTR);
    assert_eq!(r.answers.len(), 1, "auto PTR");

    let r = query_udp(p, "example.org.", RecordType::A);
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::Refused,
        "no forwarders configured"
    );

    // Update propagates immediately and bumps the serial.
    let before = query_udp(p, "example.test.", RecordType::SOA);
    let www_id = a
        .get(&format!("{web}/api/zones/example.test"))
        .call()
        .unwrap()
        .into_json::<serde_json::Value>()
        .unwrap()["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "www" && r["type"] == "A")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    // Cookie-authenticated writes need the CSRF header.
    let r = a
        .put(&format!("{web}/api/zones/example.test/records/{www_id}"))
        .send_json(serde_json::json!({ "value": "10.0.0.2" }));
    assert!(
        matches!(r, Err(ureq::Error::Status(403, _))),
        "missing CSRF header rejected"
    );
    a.put(&format!("{web}/api/zones/example.test/records/{www_id}"))
        .set("X-Requested-With", "rust-dns")
        .send_json(serde_json::json!({ "value": "10.0.0.2" }))
        .unwrap();
    let r = query_udp(p, "www.example.test.", RecordType::A);
    assert!(
        matches!(&r.answers[0].data, RData::A(a) if a.0 == std::net::Ipv4Addr::new(10, 0, 0, 2))
    );
    // TTL on update: absent keeps it, a number sets it, null resets to the zone default.
    let put = |body: serde_json::Value| -> serde_json::Value {
        a.put(&format!("{web}/api/zones/example.test/records/{www_id}"))
            .set("X-Requested-With", "rust-dns")
            .send_json(body)
            .unwrap()
            .into_json()
            .unwrap()
    };
    assert_eq!(put(serde_json::json!({ "ttl": 120 }))["ttl"], 120);
    assert_eq!(
        put(serde_json::json!({ "value": "10.0.0.2" }))["ttl"],
        120,
        "an update without ttl keeps the TTL"
    );
    assert_eq!(
        put(serde_json::json!({ "ttl": null }))["ttl"],
        serde_json::Value::Null,
        "null switches to the zone default"
    );
    let after = query_udp(p, "example.test.", RecordType::SOA);
    let serial = |m: &Message| match &m.answers[0].data {
        RData::SOA(s) => s.serial,
        _ => 0,
    };
    assert!(serial(&after) > serial(&before), "serial bumped");

    // Changelog offsets are monotonic and resumable.
    let cl: serde_json::Value = a
        .get(&format!("{web}/api/changelog?after=0"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let offsets: Vec<i64> = cl["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["offset"].as_i64().unwrap())
        .collect();
    assert!(offsets.windows(2).all(|w| w[1] > w[0]));
    assert_eq!(
        cl["latest_offset"].as_i64().unwrap(),
        *offsets.last().unwrap()
    );

    // Export / import round trip into a second zone.
    let mut doc: serde_json::Value = a
        .get(&format!("{web}/api/export"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    doc["zones"][0]["name"] = serde_json::json!("copy.test");
    let (s, summary) = post(&a, &format!("{web}/api/import?mode=replace"), doc);
    assert_eq!(s, 200, "{summary}");
    assert_eq!(summary["zones_created"], 1);
    let r = query_udp(p, "www.copy.test.", RecordType::A);
    assert_eq!(r.answers.len(), 1);

    // API token works as bearer auth.
    let (s, t) = post(
        &a,
        &format!("{web}/api/tokens"),
        serde_json::json!({ "name": "ci" }),
    );
    assert_eq!(s, 201);
    let tok = t["token"].as_str().unwrap();
    let me: serde_json::Value = ureq::get(&format!("{web}/api/me"))
        .set("Authorization", &format!("Bearer {tok}"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(me["via"], "token");
    assert_eq!(me["user"]["username"], "root");

    // Newer record types, DNAME and IDN.
    for (n, t, v) in [
        ("@", "CAA", "0 issue \"letsencrypt.org\""),
        ("@", "HTTPS", "1 . alpn=h2,h3"),
        ("old", "DNAME", "www.example.test"),
        ("bücher", "A", "10.0.0.77"),
    ] {
        let (s, r) = post(
            &a,
            &format!("{web}/api/zones/example.test/records"),
            serde_json::json!({ "name": n, "type": t, "value": v }),
        );
        assert_eq!(s, 201, "{n} {t}: {r}");
    }
    let r = query_udp(p, "example.test.", RecordType::CAA);
    assert!(matches!(&r.answers[0].data, RData::CAA(_)));
    let r = query_udp(p, "example.test.", RecordType::HTTPS);
    assert!(matches!(&r.answers[0].data, RData::HTTPS(_)));
    let r = query_udp(p, "host.old.example.test.", RecordType::A);
    assert_eq!(r.answers.len(), 2, "DNAME + synthesized CNAME");
    let r = query_udp(p, "xn--bcher-kva.example.test.", RecordType::A);
    assert_eq!(r.answers.len(), 1, "IDN stored as punycode");

    // AXFR over TCP from an allowed client: SOA first and last.
    {
        let mut s = TcpStream::connect(("127.0.0.1", p)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut m = Message::new(9, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::AXFR,
        ));
        let w = m.to_vec().unwrap();
        s.write_all(&(w.len() as u16).to_be_bytes()).unwrap();
        s.write_all(&w).unwrap();
        let mut records = Vec::new();
        let mut soas = 0;
        while soas < 2 {
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).unwrap();
            let msg = Message::from_bytes(&buf).unwrap();
            for r in msg.answers {
                if r.record_type() == RecordType::SOA {
                    soas += 1;
                }
                records.push(r.clone());
            }
        }
        assert_eq!(records.first().unwrap().record_type(), RecordType::SOA);
        assert_eq!(records.last().unwrap().record_type(), RecordType::SOA);
        assert!(records.len() > 10);
    }
    let r = query_udp(p, "example.test.", RecordType::AXFR);
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::Refused,
        "AXFR over UDP refused"
    );

    // Config reload endpoint (admin).
    let (s, v) = post(
        &a,
        &format!("{web}/api/admin/reload"),
        serde_json::json!({}),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "ok");

    // Record expiry: answers until expires_at, then disappears without any request.
    let (s201, rec) = post(
        &a,
        &format!("{web}/api/zones/example.test/records"),
        serde_json::json!({ "name": "lease", "type": "A", "value": "10.0.0.66", "expires_in": 2 }),
    );
    assert_eq!(s201, 201, "{rec}");
    assert!(rec["expires_at"].is_string());
    assert_eq!(
        query_udp(p, "lease.example.test.", RecordType::A)
            .answers
            .len(),
        1
    );
    let (s200, renewed) = post(
        &a,
        &format!("{web}/api/zones/example.test/records"),
        serde_json::json!({ "name": "lease", "type": "A", "value": "10.0.0.66", "expires_in": 2 }),
    );
    assert_eq!(
        s200, 200,
        "identical record with an expiry is a renewal: {renewed}"
    );
    assert_eq!(renewed["id"], rec["id"]);
    std::thread::sleep(Duration::from_millis(2600));
    let gone = query_udp(p, "lease.example.test.", RecordType::A);
    assert_eq!(
        gone.metadata.response_code,
        ResponseCode::NXDomain,
        "expired record no longer answers"
    );
    let cl: serde_json::Value = a
        .get(&format!("{web}/api/changelog?limit=5"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert!(
        cl["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "expire" && e["actor"] == "system"),
        "the expiry was committed to the change log: {cl}"
    );

    // Websocket clients authenticate with ?token= (they cannot set headers).
    {
        let addr = web.trim_start_matches("http://");
        let mut ws = TcpStream::connect(addr).unwrap();
        ws.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(ws, "GET /api/ws?token={tok} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        let mut buf = [0u8; 64];
        let n = ws.read(&mut buf).unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"),
            "websocket upgrade with a token: {}",
            String::from_utf8_lossy(&buf[..n])
        );
    }

    // Metrics exposed.
    let metrics = ureq::get(&format!("{web}/metrics"))
        .set("Authorization", &format!("Bearer {tok}"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(metrics.contains("rustdns_queries_total"));
}

#[test]
fn rbac_and_mfa_enrollment() {
    let srv = start();
    let a = agent();
    let web = srv.web.clone();
    login(&a, &web);
    post(
        &a,
        &format!("{web}/api/zones"),
        serde_json::json!({ "name": "corp.test" }),
    );
    post(
        &a,
        &format!("{web}/api/zones"),
        serde_json::json!({ "name": "other.test" }),
    );
    let (s, _) = post(
        &a,
        &format!("{web}/api/users"),
        serde_json::json!({ "username": "bob", "password": "bobpass123", "mfa_required": true }),
    );
    assert_eq!(s, 201);
    a.put(&format!("{web}/api/zones/corp.test/members/bob"))
        .set("X-Requested-With", "rust-dns")
        .send_json(serde_json::json!({ "role": "viewer" }))
        .unwrap();

    let b = agent();
    let (s, v) = post(
        &b,
        &format!("{web}/api/auth/login"),
        serde_json::json!({ "username": "bob", "password": "bobpass123" }),
    );
    assert_eq!(s, 200);
    assert_eq!(v["status"], "enroll_required");
    assert!(v["enroll"]["qr_svg"].as_str().unwrap().starts_with("<svg"));
    // Blocked until enrolled.
    let r = b.get(&format!("{web}/api/zones")).call();
    assert!(matches!(r, Err(ureq::Error::Status(401, _))));
    // Wrong code rejected, then compute a valid one from the secret.
    let (s, _) = post(
        &b,
        &format!("{web}/api/auth/enroll"),
        serde_json::json!({ "code": "000000" }),
    );
    assert_eq!(s, 401);
    let secret = v["enroll"]["secret"].as_str().unwrap();
    let code = totp(secret);
    let (s, v2) = post(
        &b,
        &format!("{web}/api/auth/enroll"),
        serde_json::json!({ "code": code }),
    );
    assert_eq!(s, 200, "{v2}");
    // M6 regression: the code just used cannot be replayed to sign in.
    let replay = agent();
    let (_, lv) = post(
        &replay,
        &format!("{web}/api/auth/login"),
        serde_json::json!({ "username": "bob", "password": "bobpass123" }),
    );
    assert_eq!(lv["status"], "mfa_required");
    let (s, _) = post(
        &replay,
        &format!("{web}/api/auth/mfa"),
        serde_json::json!({ "code": code }),
    );
    assert_eq!(s, 401, "a TOTP code is accepted only once");
    let codes: Vec<String> = v2["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 8, "recovery codes issued once at enrollment");

    // Viewer sees only corp.test and cannot write.
    let zones: serde_json::Value = b
        .get(&format!("{web}/api/zones"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let names: Vec<&str> = zones["zones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["corp.test"]);
    assert_eq!(zones["zones"][0]["role"], "viewer");
    let (s, _) = post(
        &b,
        &format!("{web}/api/zones/corp.test/records"),
        serde_json::json!({ "name": "x", "type": "A", "value": "10.0.0.1" }),
    );
    assert_eq!(s, 403);
    let r = b.get(&format!("{web}/api/zones/other.test")).call();
    assert!(
        matches!(r, Err(ureq::Error::Status(404, _))),
        "invisible zone looks absent"
    );
    let r = b.get(&format!("{web}/api/users")).call();
    assert!(matches!(r, Err(ureq::Error::Status(403, _))));

    // Promote to editor: writes allowed.
    a.put(&format!("{web}/api/zones/corp.test/members/bob"))
        .set("X-Requested-With", "rust-dns")
        .send_json(serde_json::json!({ "role": "editor" }))
        .unwrap();
    let (s, _) = post(
        &b,
        &format!("{web}/api/zones/corp.test/records"),
        serde_json::json!({ "name": "x", "type": "A", "value": "10.0.0.1" }),
    );
    assert_eq!(s, 201);

    // Second login requires the code.
    let b2 = agent();
    let (_, v) = post(
        &b2,
        &format!("{web}/api/auth/login"),
        serde_json::json!({ "username": "bob", "password": "bobpass123" }),
    );
    assert_eq!(v["status"], "mfa_required");
    let (s, _) = post(
        &b2,
        &format!("{web}/api/auth/mfa"),
        serde_json::json!({ "code": totp(secret) }),
    );
    assert_eq!(s, 200);
    assert!(b2.get(&format!("{web}/api/me")).call().is_ok());

    // A recovery code works once.
    let b3 = agent();
    post(
        &b3,
        &format!("{web}/api/auth/login"),
        serde_json::json!({ "username": "bob", "password": "bobpass123" }),
    );
    let (s, v) = post(
        &b3,
        &format!("{web}/api/auth/mfa"),
        serde_json::json!({ "code": codes[0].to_uppercase() }),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["used_recovery_code"], true);
    assert_eq!(v["recovery_codes_left"], 7);
    let b4 = agent();
    post(
        &b4,
        &format!("{web}/api/auth/login"),
        serde_json::json!({ "username": "bob", "password": "bobpass123" }),
    );
    let (s, _) = post(
        &b4,
        &format!("{web}/api/auth/mfa"),
        serde_json::json!({ "code": &codes[0] }),
    );
    assert_eq!(s, 401, "a used recovery code is rejected");

    // Sessions: bob sees his sessions and revokes the others; a revoked agent is signed out.
    let me: serde_json::Value = b
        .get(&format!("{web}/api/me/sessions"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert!(me["sessions"].as_array().unwrap().len() >= 3);
    let (s, v) = post(
        &b,
        &format!("{web}/api/me/sessions/revoke-others"),
        serde_json::json!({}),
    );
    assert_eq!(s, 200);
    assert!(v["revoked"].as_i64().unwrap() >= 2);
    assert!(matches!(
        b2.get(&format!("{web}/api/me")).call(),
        Err(ureq::Error::Status(401, _))
    ));
    assert!(b.get(&format!("{web}/api/me")).call().is_ok());

    // Effective rights: generated from the permission table and matching enforcement.
    let bob_me: serde_json::Value = b
        .get(&format!("{web}/api/me"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let bob_id = bob_me["user"]["id"].as_i64().unwrap();
    let (s, tok) = post(
        &b,
        &format!("{web}/api/tokens"),
        serde_json::json!({ "name": "bob-ci" }),
    );
    assert_eq!(s, 201);
    let bob_token = tok["token"].as_str().unwrap().to_string();
    // Editor on corp.test (promoted above).
    let rights: serde_json::Value = a
        .get(&format!("{web}/api/users/{bob_id}/rights?via=token"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(rights["zones"].as_array().unwrap().len(), 1);
    assert_eq!(rights["zones"][0]["zone"], "corp.test");
    assert_eq!(rights["zones"][0]["role"], "editor");
    assert_eq!(rights["zones"][0]["source"], "member");
    let zp: Vec<&str> = rights["zones"][0]["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(zp, vec!["view", "export", "edit_records"]);
    let g = |perm: &str| {
        rights["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["perm"] == perm)
            .unwrap()
            .clone()
    };
    assert_eq!(g("manage_own_tokens")["allowed"], true);
    assert_eq!(
        g("change_own_password")["allowed"],
        false,
        "tokens cannot change passwords"
    );
    assert_eq!(g("create_zones")["allowed"], false);
    // ...and the API agrees with every one of those answers.
    let with_token = |m: &str, url: &str| {
        ureq::request(m, url).set("Authorization", &format!("Bearer {bob_token}"))
    };
    assert!(
        with_token("POST", &format!("{web}/api/zones/corp.test/records"))
            .send_json(serde_json::json!({"name":"t","type":"A","value":"10.0.0.2"}))
            .is_ok(),
        "edit_records allowed"
    );
    let r = with_token("PUT", &format!("{web}/api/zones/corp.test"))
        .send_json(serde_json::json!({"refresh": 100}));
    assert!(
        matches!(r, Err(ureq::Error::Status(403, _))),
        "edit_settings needs owner"
    );
    let r = with_token("PUT", &format!("{web}/api/me/password")).send_json(
        serde_json::json!({"current_password":"bobpass123","new_password":"whatever123"}),
    );
    assert!(
        matches!(r, Err(ureq::Error::Status(403, _))),
        "password change needs a session"
    );
    let r = with_token("POST", &format!("{web}/api/me/mfa/disable"))
        .send_json(serde_json::json!({"code":"000000"}));
    assert!(
        matches!(r, Err(ureq::Error::Status(403, _))),
        "MFA changes need a session"
    );
    let r = with_token("POST", &format!("{web}/api/zones"))
        .send_json(serde_json::json!({"name":"new.test"}));
    assert!(
        matches!(r, Err(ureq::Error::Status(403, _))),
        "create_zones is admin only"
    );
    // A user may read their own rights, not someone else's.
    assert!(b
        .get(&format!("{web}/api/users/{bob_id}/rights"))
        .call()
        .is_ok());
    assert!(matches!(
        b.get(&format!("{web}/api/users/1/rights")).call(),
        Err(ureq::Error::Status(403, _))
    ));
    // The session view differs only in the session-only permissions.
    let sess: serde_json::Value = b
        .get(&format!("{web}/api/users/{bob_id}/rights?via=session"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(
        sess["global"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["perm"] == "change_own_password")
            .unwrap()["allowed"],
        true
    );

    // Admin signs bob out everywhere.
    let users: serde_json::Value = a
        .get(&format!("{web}/api/users"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let bob = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "bob")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (s, _) = post(
        &a,
        &format!("{web}/api/users/{bob}/sessions/revoke"),
        serde_json::json!({}),
    );
    assert_eq!(s, 200);
    assert!(matches!(
        b.get(&format!("{web}/api/me")).call(),
        Err(ureq::Error::Status(401, _))
    ));
}

#[test]
fn json_import_and_record_paging() {
    let srv = start();
    let a = agent();
    let web = srv.web.clone();
    login(&a, &web);
    post(
        &a,
        &format!("{web}/api/zones"),
        serde_json::json!({ "name": "imp.test" }),
    );
    let doc = serde_json::json!({
        "version": 1,
        "exported_at": "2026-01-01T00:00:00Z",
        "zones": [{
            "name": "imp.test",
            "records": [
                { "name": "@", "type": "NS", "value": "ns1.imp.test." },
                { "name": "ns1", "type": "A", "value": "10.9.9.1" },
                { "name": "web", "type": "A", "value": "10.9.9.2", "ttl": 120 },
                { "name": "web", "type": "AAAA", "value": "2001:db8::9" },
                { "name": "@", "type": "MX", "value": "10 mail.imp.test." },
                { "name": "@", "type": "TXT", "value": "v=spf1 -all" },
                { "name": "@", "type": "CAA", "value": "0 issue \"letsencrypt.org\"" }
            ]
        }]
    });
    let r = a
        .post(&format!("{web}/api/import?mode=replace"))
        .set("X-Requested-With", "rust-dns")
        .send_json(doc)
        .unwrap();
    let v: serde_json::Value = r.into_json().unwrap();
    assert_eq!(v["records_added"], 7, "{v}");
    let recs: serde_json::Value = a
        .get(&format!("{web}/api/zones/imp.test/records"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let web_a = recs["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "web" && r["type"] == "A")
        .unwrap();
    assert_eq!(web_a["ttl"], 120, "explicit TTL kept");
    let p = srv.dns_port;
    let r = query_udp(p, "imp.test.", RecordType::CAA);
    assert_eq!(r.answers.len(), 1);

    // Paging and search.
    for i in 0..30 {
        post(
            &a,
            &format!("{web}/api/zones/imp.test/records"),
            serde_json::json!({ "name": format!("h{i}"), "type": "A", "value": format!("10.1.0.{i}") }),
        );
    }
    let page: serde_json::Value = a
        .get(&format!(
            "{web}/api/zones/imp.test/records?limit=10&offset=10"
        ))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(page["records"].as_array().unwrap().len(), 10);
    assert_eq!(page["total"], 37);
    let found: serde_json::Value = a
        .get(&format!("{web}/api/zones/imp.test/records?q=h2"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(found["total"], 11, "h2, h20..h29");
    let z: serde_json::Value = a
        .get(&format!("{web}/api/zones/imp.test"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(z["record_total"], 37);
    assert_eq!(z["records"][0]["name"], "@", "apex sorts first");

    // OpenAPI document is served.
    let spec: serde_json::Value = ureq::get(&format!("{web}/api/openapi.json"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert!(spec["paths"]["/import"].is_object());
    // BIND zone-file import and export were removed.
    assert!(spec["paths"]["/zones/{zone}/import-bind"].is_null());
    let gone = a
        .post(&format!("{web}/api/zones/imp.test/import-bind"))
        .set("X-Requested-With", "rust-dns")
        .set("Content-Type", "text/plain")
        .send_string("$INCLUDE /etc/passwd\n");
    assert!(
        matches!(gone, Err(ureq::Error::Status(404 | 405, _))),
        "import-bind is gone"
    );
    assert!(matches!(
        a.get(&format!("{web}/api/zones/imp.test/export?format=bind"))
            .call(),
        Err(ureq::Error::Status(400, _))
    ));
}

fn send(
    a: &ureq::Agent,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let req = a.request(method, url).set("X-Requested-With", "rust-dns");
    let r = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match r {
        Ok(r) => {
            let s = r.status();
            (s, r.into_json().unwrap_or(serde_json::Value::Null))
        }
        Err(ureq::Error::Status(s, r)) => (s, r.into_json().unwrap_or(serde_json::Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn token_tags_and_last_use() {
    let srv = start();
    let a = agent();
    let web = srv.web.clone();
    login(&a, &web);
    let api = |p: &str| format!("{web}/api{p}");

    // Create with tags: normalized (trimmed, deduped, sorted; case kept).
    let (s, created) = post(
        &a,
        &api("/tokens"),
        serde_json::json!({ "name": "deployer", "tags": [" ci ", "ansible", "ci"] }),
    );
    assert_eq!(s, 201, "{created}");
    let tok = created["token"].as_str().unwrap().to_string();
    let id = created["info"]["id"].as_i64().unwrap();
    assert_eq!(
        created["info"]["tags"],
        serde_json::json!(["ansible", "ci"])
    );
    assert!(created["info"]["last_used_at"].is_null());
    assert!(created["info"]["last_used_ip"].is_null());
    let (s, _) = post(
        &a,
        &api("/tokens"),
        serde_json::json!({ "name": "untagged" }),
    );
    assert_eq!(s, 201, "tags are optional");

    // The list shows tags; the tag filter narrows it.
    let (s, all) = send(&a, "GET", &api("/tokens"), None);
    assert_eq!(s, 200);
    let entry = |list: &serde_json::Value| {
        list["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == id)
            .cloned()
    };
    assert_eq!(all["tokens"].as_array().unwrap().len(), 2);
    assert_eq!(
        entry(&all).unwrap()["tags"],
        serde_json::json!(["ansible", "ci"])
    );
    let (_, upper) = send(&a, "GET", &api("/tokens?tag=CI"), None);
    assert!(
        upper["tokens"].as_array().unwrap().is_empty(),
        "tag filter is case-sensitive"
    );
    let (s, ci) = send(&a, "GET", &api("/tokens?tag=ci"), None);
    assert_eq!(s, 200);
    let ids: Vec<i64> = ci["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, vec![id]);
    let (_, none) = send(&a, "GET", &api("/tokens?tag=home-assistant"), None);
    assert!(none["tokens"].as_array().unwrap().is_empty());
    let (s, e) = send(&a, "GET", &api("/tokens?tag=bad%20tag"), None);
    assert_eq!(s, 400, "{e}");

    // Update the tags.
    let (s, upd) = send(
        &a,
        "PUT",
        &api(&format!("/tokens/{id}")),
        Some(serde_json::json!({ "tags": ["home-assistant", "ci"] })),
    );
    assert_eq!(s, 200, "{upd}");
    assert_eq!(upd["tags"], serde_json::json!(["ci", "home-assistant"]));
    let (_, ha) = send(&a, "GET", &api("/tokens?tag=home-assistant"), None);
    assert_eq!(ha["tokens"].as_array().unwrap().len(), 1);
    let (_, ansible) = send(&a, "GET", &api("/tokens?tag=ansible"), None);
    assert!(ansible["tokens"].as_array().unwrap().is_empty());

    // Use the token from 127.0.0.1: last use time and IP are recorded.
    let me: serde_json::Value = ureq::get(&api("/me"))
        .set("Authorization", &format!("Bearer {tok}"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(me["via"], "token");
    let (_, all) = send(&a, "GET", &api("/tokens"), None);
    let used = entry(&all).unwrap();
    assert_eq!(used["last_used_ip"], "127.0.0.1", "{used}");
    assert!(
        used["last_used_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z')),
        "{used}"
    );

    // Audit log: token.create with tags, token.update with before/after.
    let (s, audit) = send(&a, "GET", &api("/audit?limit=2000"), None);
    assert_eq!(s, 200);
    let entries = audit["entries"].as_array().unwrap();
    let find = |action: &str| {
        entries
            .iter()
            .find(|e| e["action"] == action && e["detail"]["token_id"] == id)
            .unwrap_or_else(|| panic!("no {action} for token {id} in {audit}"))
            .clone()
    };
    let c = find("token.create");
    assert_eq!(c["operation"], "create_token");
    assert_eq!(c["actor"], "root");
    assert_eq!(c["detail"]["name"], "deployer");
    assert_eq!(c["detail"]["tags"], serde_json::json!(["ansible", "ci"]));
    let u = find("token.update");
    assert_eq!(u["operation"], "update_token");
    assert_eq!(u["actor_ip"], "127.0.0.1");
    assert_eq!(
        u["detail"]["tags"],
        serde_json::json!({ "before": ["ansible", "ci"], "after": ["ci", "home-assistant"] })
    );
    // Token use is bookkeeping, never audited.
    assert!(!entries
        .iter()
        .any(|e| e["action"].as_str().is_some_and(|x| x.contains("use"))
            && e["detail"]["token_id"] == id));

    // A non-owner without manage_users cannot change the tags.
    let (s, _) = post(
        &a,
        &api("/users"),
        serde_json::json!({ "username": "carol", "password": "carolpass123" }),
    );
    assert_eq!(s, 201);
    let b = agent();
    let (s, v) = post(
        &b,
        &api("/auth/login"),
        serde_json::json!({ "username": "carol", "password": "carolpass123" }),
    );
    assert_eq!((s, v["status"].as_str()), (200, Some("ok")), "{v}");
    let (s, e) = send(
        &b,
        "PUT",
        &api(&format!("/tokens/{id}")),
        Some(serde_json::json!({ "tags": ["mine"] })),
    );
    assert_eq!(s, 403, "{e}");
    // ...but may tag their own.
    let (s, own) = post(
        &b,
        &api("/tokens"),
        serde_json::json!({ "name": "c", "tags": ["x"] }),
    );
    assert_eq!(s, 201);
    let own_id = own["info"]["id"].as_i64().unwrap();
    let (s, _) = send(
        &b,
        "PUT",
        &api(&format!("/tokens/{own_id}")),
        Some(serde_json::json!({ "tags": [] })),
    );
    assert_eq!(s, 200);
    // Carol's list does not include root's tokens.
    let (_, cl) = send(&b, "GET", &api("/tokens?all=true"), None);
    assert_eq!(cl["tokens"].as_array().unwrap().len(), 1);

    // Invalid tags: validation errors (400, no code) vs unparsable bodies
    // (400 invalid_request). Nothing changes.
    for bad in [
        serde_json::json!({ "tags": ["has space"] }),
        serde_json::json!({ "tags": ["x".repeat(257)] }),
        serde_json::json!({ "tags": ["v1.2"] }),
        serde_json::json!({ "tags": (0..17).map(|i| format!("t{i}")).collect::<Vec<_>>() }),
    ] {
        let (s, e) = send(&a, "PUT", &api(&format!("/tokens/{id}")), Some(bad.clone()));
        assert_eq!(s, 400, "{bad} -> {e}");
        assert!(e["code"].is_null(), "{e}");
        assert!(e["error"].as_str().unwrap().contains("tag"), "{e}");
    }
    let (s, e) = send(
        &a,
        "PUT",
        &api(&format!("/tokens/{id}")),
        Some(serde_json::json!({ "tags": "ci" })),
    );
    assert_eq!(
        (s, e["code"].as_str()),
        (400, Some("invalid_request")),
        "{e}"
    );
    let (s, e) = post(
        &a,
        &api("/tokens"),
        serde_json::json!({ "name": "bad", "tags": ["ok", "NOT OK"] }),
    );
    assert_eq!(s, 400, "{e}");
    let (_, all) = send(&a, "GET", &api("/tokens"), None);
    assert_eq!(
        all["tokens"].as_array().unwrap().len(),
        2,
        "bad create stored nothing"
    );
    assert_eq!(
        entry(&all).unwrap()["tags"],
        serde_json::json!(["ci", "home-assistant"])
    );

    // Revoked tokens cannot be re-tagged.
    let (s, _) = send(&a, "DELETE", &api(&format!("/tokens/{id}")), None);
    assert_eq!(s, 200);
    let (s, _) = send(
        &a,
        "PUT",
        &api(&format!("/tokens/{id}")),
        Some(serde_json::json!({ "tags": ["ci"] })),
    );
    assert_eq!(s, 404);
}

/// TOTP (RFC 6238, SHA-1, 30 s, 6 digits) for an explicit time step.
fn totp_at(secret_b32: &str, step: u64) -> String {
    use hmac::{Hmac, Mac};
    let key = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
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

/// A TOTP code the server has not seen yet: the server refuses a code whose
/// step is not later than the last one it accepted (replay protection), so
/// each call takes the next unused step of the three accepted (previous,
/// current, next), waiting for the next 30-second window when needed.
fn totp(secret_b32: &str) -> String {
    static LAST: std::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
        std::sync::Mutex::new(None);
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let cur = now.as_secs() / 30;
        let mut g = LAST.lock().unwrap();
        let map = g.get_or_insert_with(Default::default);
        let next = match map.get(secret_b32) {
            None => cur - 1,
            Some(l) => (l + 1).max(cur - 1),
        };
        if next <= cur + 1 {
            map.insert(secret_b32.to_string(), next);
            return totp_at(secret_b32, next);
        }
        drop(g);
        std::thread::sleep(Duration::from_millis(
            (30 - now.as_secs() % 30) * 1000 + 200,
        ));
    }
}

/// G2: an answer given before the request body was read (here 401 from
/// the auth check; a standby's 409 is the same) used to make the server
/// close with body bytes still arriving, and the client then sometimes
/// lost the response (macOS: `EINVAL` while reading its headers; about 7
/// in 400 requests). The API now reads the body first. Also: a body over
/// the limit is refused with a JSON 413.
#[test]
fn early_answers_reach_the_client_and_large_bodies_are_refused() {
    let srv = start();
    let mut transport = Vec::new();
    // A pooled agent first, then one connection per request (where it
    // showed: the body's second segment arrives after the early answer).
    for (n, pooled) in [(400, true), (1200, false)] {
        let mut b = ureq::AgentBuilder::new().timeout(Duration::from_secs(5));
        if !pooled {
            b = b.max_idle_connections(0);
        }
        let a = b.build();
        for i in 0..n {
            let body = serde_json::json!({ "name": format!("z{i}.test"), "pad": "x".repeat(i % 50 * 100) });
            match a
                .post(&format!("{}/api/zones", srv.web))
                .set("X-Requested-With", "rust-dns")
                .send_json(body)
            {
                Err(ureq::Error::Status(401, r)) => {
                    let _ = r.into_string();
                }
                Ok(r) => panic!("unexpected {}", r.status()),
                Err(ureq::Error::Status(s, _)) => panic!("unexpected {s}"),
                Err(e) => transport.push(e.to_string()),
            }
        }
    }
    let a = agent();
    assert!(
        transport.is_empty(),
        "{} lost: {:?}",
        transport.len(),
        transport.first()
    );
    let big = "x".repeat(16 * 1024 * 1024 + 1);
    match a
        .post(&format!("{}/api/auth/login", srv.web))
        .set("X-Requested-With", "rust-dns")
        .set("Content-Type", "application/json")
        .send_string(&big)
    {
        Err(ureq::Error::Status(413, r)) => {
            let v: serde_json::Value = r.into_json().unwrap();
            assert_eq!(v["code"], "invalid_request", "{v}");
        }
        other => panic!("expected 413, got {other:?}"),
    }
}
