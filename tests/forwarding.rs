//! End-to-end: forwarding (upstream resolvers) managed through the API.
//! Starts the real binary and a fake upstream resolver on 127.0.0.1.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
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

const ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// How a [`fake_upstream_with`] resolver behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Echo the question, answer A 203.0.113.77.
    Normal,
    /// Answer for a different name (a spoofed / mismatched reply).
    WrongQuestion,
    /// Echo the question in lower case (does not preserve 0x20).
    Lowercase,
    /// UDP: empty TC=1 reply; TCP: 80 A records (too big for 512 bytes).
    Big,
    /// Names starting with "big.": 40 A records over UDP and TCP (over 512
    /// bytes, under 1232); others as Normal.
    BigName,
}

/// A fake resolver on UDP and TCP (same port) that counts the queries it
/// receives and answers with the given TTL.
fn fake_upstream_with(
    mode: Mode,
    ttl: u32,
) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // The TCP port of the same number may be taken by something else
    // (seen once in the gate): pick another pair then.
    let (sock, port, tcp) = loop {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        if let Ok(tcp) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            break (sock, port, tcp);
        }
    };
    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let answer = move |q: &Message, over_tcp: bool| -> Vec<u8> {
        let mut r = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
        r.metadata.recursion_desired = true;
        r.metadata.recursion_available = true;
        for query in &q.queries {
            let name = match mode {
                Mode::WrongQuestion => Name::from_ascii("evil.example.").unwrap(),
                Mode::Lowercase => {
                    Name::from_ascii(query.name().to_ascii().to_ascii_lowercase()).unwrap()
                }
                _ => query.name().clone(),
            };
            r.add_query(Query::query(name.clone(), query.query_type()));
            let n = match (mode, over_tcp) {
                (Mode::Big, false) => {
                    r.metadata.truncation = true;
                    0
                }
                (Mode::Big, true) => 80,
                (Mode::BigName, _) if name.to_ascii().to_ascii_lowercase().starts_with("big.") => {
                    40
                }
                _ => 1,
            };
            for i in 0..n {
                let ip = if n == 1 {
                    ANSWER
                } else {
                    Ipv4Addr::new(198, 51, 100, i as u8)
                };
                r.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(A(ip))));
            }
        }
        r.to_vec().unwrap()
    };
    {
        let count = count.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    return;
                };
                let Ok(q) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let _ = sock.send_to(&answer(&q, false), peer);
            }
        });
    }
    {
        let count = count.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut c in tcp.incoming().flatten() {
                let mut len = [0u8; 2];
                if c.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if c.read_exact(&mut buf).is_err() {
                    continue;
                }
                let Ok(q) = Message::from_bytes(&buf) else {
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let out = answer(&q, true);
                let _ = c.write_all(&(out.len() as u16).to_be_bytes());
                let _ = c.write_all(&out);
            }
        });
    }
    (port, count)
}

/// A resolver that answers every query with A 203.0.113.77.
fn fake_upstream() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                return;
            };
            let Ok(q) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut r = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
            r.metadata.recursion_desired = true;
            r.metadata.recursion_available = true;
            for query in &q.queries {
                r.add_query(query.clone());
                r.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(ANSWER)),
                ));
            }
            let _ = sock.send_to(&r.to_vec().unwrap(), peer);
        }
    });
    port
}

const DEFAULT_FORWARDING: &str = "upstreams = []\nallowed_clients = [\"127.0.0.0/8\"]";

struct Server {
    child: Child,
    dns: u16,
    web: String,
}

impl Server {
    fn start(dir: PathBuf, dns: u16, web_port: u16) -> Server {
        Server::start_with(dir, dns, web_port, DEFAULT_FORWARDING)
    }

    /// `forwarding`: the body of `[forwarding]`.
    fn start_with(dir: PathBuf, dns: u16, web_port: u16, forwarding: &str) -> Server {
        let cfg = format!(
            r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[forwarding]
{forwarding}
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{db}"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{web_port}"
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "warn"
"#,
            db = dir.join("t.db").display()
        );
        std::fs::write(dir.join("t.toml"), cfg).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(dir.join("t.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let web = format!("http://127.0.0.1:{web_port}");
        let deadline = Instant::now() + Duration::from_secs(15);
        while ureq::get(&format!("{web}/api/health"))
            .timeout(Duration::from_millis(300))
            .call()
            .is_err()
        {
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        Server { child, dns, web }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn login(web: &str, user: &str, pw: &str) -> ureq::Agent {
    let a = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    a.post(&format!("{web}/api/auth/login"))
        .send_json(serde_json::json!({ "username": user, "password": pw }))
        .unwrap();
    a
}

fn call(
    a: &ureq::Agent,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let req = a
        .request(method, url)
        .set("X-Requested-With", "rust-dns")
        .set("X-CSRF-Token", &csrf_of(a));
    let res = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match res {
        Ok(r) => (r.status(), r.into_json().unwrap_or(serde_json::Value::Null)),
        Err(ureq::Error::Status(c, r)) => (c, r.into_json().unwrap_or(serde_json::Value::Null)),
        Err(e) => panic!("{e}"),
    }
}

fn query(port: u16, name: &str) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).unwrap();
    Message::from_bytes(&buf[..n]).unwrap()
}

fn rand_id() -> u16 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        & 0xffff) as u16
}

fn answered_by_fake(m: &Message) -> bool {
    m.metadata.response_code == ResponseCode::NoError
        && m.answers
            .iter()
            .any(|r| matches!(&r.data, RData::A(a) if a.0 == ANSWER))
}

#[test]
fn forwarding_is_managed_through_the_api() {
    let dir =
        std::env::temp_dir().join(format!("rust-dns-fwd-{}-{}", std::process::id(), rand_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (dns, web_port) = (free_port(), free_port());
    let upstream = format!("127.0.0.1:{}", fake_upstream());
    let dead = format!("127.0.0.1:{}", free_port());
    let mut srv = Server::start(dir.clone(), dns, web_port);
    let web = srv.web.clone();
    let root = login(&web, "root", "rootpass123");
    let url = format!("{web}/api/settings/forwarding");

    // From the config file: no upstreams, so foreign names are refused.
    let (s, v) = call(&root, "GET", &url, None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["source"], "config");
    assert_eq!(v["upstreams"], serde_json::json!([]));
    assert_eq!(
        query(srv.dns, "anything.example.").metadata.response_code,
        ResponseCode::Refused
    );

    // Probe before saving: the fake answers, a closed port does not.
    let (s, v) = call(
        &root,
        "POST",
        &format!("{url}/test"),
        Some(serde_json::json!({ "upstreams": [upstream, dead, "not-an-ip"], "timeout_ms": 400 })),
    );
    assert_eq!(s, 200, "{v}");
    let r = v["results"].as_array().unwrap();
    assert_eq!(r[0]["ok"], true, "{v}");
    assert!(r[0]["ms"].is_number());
    assert_eq!(r[1]["ok"], false);
    assert_eq!(r[2]["ok"], false);
    assert!(r[2]["error"]
        .as_str()
        .unwrap()
        .contains("not an IP address"));

    // Invalid input is refused with every problem listed; nothing changes.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": ["dns.google"], "allowed_clients": ["0.0.0.0/0"], "timeout_ms": 5 }),
        ),
    );
    assert_eq!(s, 400);
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("host names are not supported")
            && msg.contains("open resolver")
            && msg.contains("timeout_ms"),
        "{msg}"
    );
    assert_eq!(call(&root, "GET", &url, None).1["source"], "config");

    // Save: applied immediately, recorded in the audit log.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 800 }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["source"], "console");
    assert_eq!(v["updated_by"], "root");
    assert_eq!(v["upstreams"], serde_json::json!([upstream]));
    assert_eq!(
        v["config"]["upstreams"],
        serde_json::json!([]),
        "config file values are shown too"
    );
    assert!(
        answered_by_fake(&query(srv.dns, "forwarded.example.")),
        "queries now go to the new upstream"
    );
    let status = call(&root, "GET", &format!("{web}/api/status"), None).1;
    assert_eq!(
        status["forwarding"]["upstreams"],
        serde_json::json!([upstream])
    );
    let audit = call(&root, "GET", &format!("{web}/api/audit?limit=20"), None).1;
    assert!(audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["action"] == "settings.forwarding.update"
            && e["detail"]["after"]["timeout_ms"] == 800));

    // A non-admin may not read or change it.
    let (s, _) = call(
        &root,
        "POST",
        &format!("{web}/api/users"),
        Some(serde_json::json!({ "username": "bob", "password": "bobpass123" })),
    );
    assert_eq!(s, 201);
    let bob = login(&web, "bob", "bobpass123");
    assert_eq!(call(&bob, "GET", &url, None).0, 403);
    assert_eq!(
        call(
            &bob,
            "PUT",
            &url,
            Some(serde_json::json!({ "upstreams": [], "allowed_clients": [], "timeout_ms": 1000 }))
        )
        .0,
        403
    );

    // The override survives a restart (stored in the database, not the process).
    drop(srv);
    srv = Server::start(dir.clone(), dns, web_port);
    assert!(
        answered_by_fake(&query(srv.dns, "after-restart.example.")),
        "override still applied after restart"
    );
    let root = login(&web, "root", "rootpass123");
    assert_eq!(call(&root, "GET", &url, None).1["source"], "console");

    // Reset: the config file applies again (no upstreams: refused), audited.
    let (s, v) = call(&root, "DELETE", &url, None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["source"], "config");
    assert_eq!(
        query(srv.dns, "after-reset.example.")
            .metadata
            .response_code,
        ResponseCode::Refused
    );
    let audit = call(&root, "GET", &format!("{web}/api/audit?limit=20"), None).1;
    assert!(audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["action"] == "settings.forwarding.reset"));

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

fn query_ttl(m: &Message) -> u32 {
    m.answers.iter().map(|r| r.ttl).max().unwrap_or(0)
}

/// Owner request (forward cache TTL caps): caps set through the API bound
/// the TTL of cached answers; flushing empties the cache (the next query
/// reaches the upstream again); both are audited.
#[test]
fn forward_cache_caps_and_flush() {
    use std::sync::atomic::Ordering;
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-fwdcache-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (dns, web_port) = (free_port(), free_port());
    let (up_port, upstream_queries) = fake_upstream_with(Mode::Normal, 3600);
    let upstream = format!("127.0.0.1:{up_port}");
    let srv = Server::start(dir.clone(), dns, web_port);
    let web = srv.web.clone();
    let root = login(&web, "root", "rootpass123");
    let url = format!("{web}/api/settings/forwarding");

    let (s, v) = call(&root, "GET", &url, None);
    assert_eq!(s, 200);
    assert_eq!(v["cache_max_ttl"], 86400);
    assert_eq!(v["cache_negative_max_ttl"], 3600);
    // Invalid caps are refused.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 1000, "cache_max_ttl": 60, "cache_negative_max_ttl": 120 }),
        ),
    );
    assert_eq!(s, 400, "{v}");
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 1000, "cache_max_ttl": 300, "cache_negative_max_ttl": 60 }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["cache_max_ttl"], 300);

    let first = query(srv.dns, "cached.example.");
    assert!(answered_by_fake(&first));
    assert_eq!(
        query_ttl(&first),
        3600,
        "the first answer is the upstream's own"
    );
    let n0 = upstream_queries.load(Ordering::SeqCst);
    let cached = query(srv.dns, "cached.example.");
    assert!(answered_by_fake(&cached));
    assert!(
        query_ttl(&cached) <= 300,
        "cached TTL within the cap: {}",
        query_ttl(&cached)
    );
    assert_eq!(
        upstream_queries.load(Ordering::SeqCst),
        n0,
        "served from the cache"
    );

    let (s, v) = call(&root, "GET", &url, None);
    assert_eq!(s, 200);
    assert_eq!(v["cache"]["entries"], 1, "{v}");
    assert!(v["cache"]["hits"].as_u64().unwrap() >= 1);

    // Flush: dropped count, empty cache, next query goes upstream, audited.
    let (s, v) = call(&root, "POST", &format!("{url}/cache/flush"), None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["dropped"], 1);
    assert_eq!(call(&root, "GET", &url, None).1["cache"]["entries"], 0);
    assert!(answered_by_fake(&query(srv.dns, "cached.example.")));
    assert_eq!(
        upstream_queries.load(Ordering::SeqCst),
        n0 + 1,
        "after a flush the upstream is asked again"
    );
    let audit = call(&root, "GET", &format!("{web}/api/audit?limit=50"), None).1;
    let entries = audit["entries"].as_array().unwrap();
    assert!(entries
        .iter()
        .any(|e| e["action"] == "settings.forwarding.cache_flush" && e["detail"]["dropped"] == 1));
    assert!(entries
        .iter()
        .any(|e| e["action"] == "settings.forwarding.update"
            && e["detail"]["after"]["cache_max_ttl"] == 300));

    // Non-admins may not flush.
    call(
        &root,
        "POST",
        &format!("{web}/api/users"),
        Some(serde_json::json!({ "username": "bob", "password": "bobpass123" })),
    );
    let bob = login(&web, "bob", "bobpass123");
    assert_eq!(
        call(&bob, "POST", &format!("{url}/cache/flush"), None).0,
        403
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

fn start_forwarding_to(upstream: u16) -> (Server, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-fwdm5-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let srv = Server::start(dir.clone(), free_port(), free_port());
    let root = login(&srv.web, "root", "rootpass123");
    let (s, v) = call(
        &root,
        "PUT",
        &format!("{}/api/settings/forwarding", srv.web),
        Some(
            serde_json::json!({ "upstreams": [format!("127.0.0.1:{upstream}")], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 800 }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    (srv, dir)
}

/// M5 regression: a reply for another question (same ID) used to be
/// accepted, relayed and cached for every client.
#[test]
fn mismatched_upstream_replies_are_not_accepted() {
    let (up, _) = fake_upstream_with(Mode::WrongQuestion, 3600);
    let (srv, dir) = start_forwarding_to(up);
    let r = query(srv.dns, "victim.example.");
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail, "{r:?}");
    assert!(r.answers.is_empty());
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M5: 0x20 is optional for upstreams; one that lower-cases the question is
/// retried without it and still works.
#[test]
fn upstreams_without_0x20_still_work() {
    let (up, count) = fake_upstream_with(Mode::Lowercase, 60);
    let (srv, dir) = start_forwarding_to(up);
    let r = query(srv.dns, "MixedCase.Example.");
    assert!(answered_by_fake(&r), "{r:?}");
    assert_eq!(
        r.queries[0].name().to_ascii(),
        "MixedCase.Example.",
        "client case restored"
    );
    assert!(count.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M5 regression: an answer fetched over TCP after an upstream TC used to
/// be returned over UDP whole, beyond the client's 512-byte limit.
#[test]
fn tcp_fallback_answers_are_truncated_for_udp_clients() {
    let (up, _) = fake_upstream_with(Mode::Big, 60);
    let (srv, dir) = start_forwarding_to(up);
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii("big.example.").unwrap(),
        RecordType::A,
    ));
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", srv.dns))
        .unwrap();
    let mut buf = [0u8; 65535];
    let n = sock.recv(&mut buf).unwrap();
    assert!(
        n <= 512,
        "UDP reply of {n} bytes exceeds the client's 512-byte limit"
    );
    let r = Message::from_bytes(&buf[..n]).unwrap();
    assert!(
        r.metadata.truncation,
        "TC=1 tells the client to retry over TCP"
    );
    assert_eq!(r.metadata.id, m.metadata.id);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A UDP query with EDNS (payload 4096); None when no reply came in time.
fn query_udp_edns(
    port: u16,
    name: &str,
    qtype: RecordType,
    wait: Duration,
) -> Option<(usize, Message)> {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(wait)).unwrap();
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(4096);
    m.set_edns(e);
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 65535];
    let n = sock.recv(&mut buf).ok()?;
    Some((n, Message::from_bytes(&buf[..n]).unwrap()))
}

fn query_tcp(port: u16, name: &str, qtype: RecordType) -> Message {
    use std::io::{Read, Write};
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    let q = m.to_vec().unwrap();
    c.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
    c.write_all(&q).unwrap();
    let mut len = [0u8; 2];
    c.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    c.read_exact(&mut buf).unwrap();
    Message::from_bytes(&buf).unwrap()
}

fn metric(web: &str, a: &ureq::Agent, name: &str) -> String {
    let text = a
        .get(&format!("{web}/metrics"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    text.lines()
        .find(|l| l.starts_with(&format!("{name} ")))
        .unwrap_or_else(|| panic!("{name} missing from /metrics"))
        .split(' ')
        .nth(1)
        .unwrap()
        .to_string()
}

/// Open resolver mode: explicit opt-in through the API (audited), then the
/// safeguards: UDP answers over the cap come back TC (complete over TCP),
/// ANY is not forwarded, and the per-client forwarding limit engages.
/// Turning it off restores the usual behaviour.
#[test]
fn open_resolver_mode_and_safeguards() {
    use std::sync::atomic::Ordering::SeqCst;
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-open-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (up, count) = fake_upstream_with(Mode::BigName, 300);
    let srv = Server::start_with(
        dir.clone(),
        free_port(),
        free_port(),
        &format!("{DEFAULT_FORWARDING}\nopen_resolver_rate_per_second = 10"),
    );
    let (web, dns) = (srv.web.clone(), srv.dns);
    let root = login(&web, "root", "rootpass123");
    let url = format!("{web}/api/settings/forwarding");
    let upstream = format!("127.0.0.1:{up}");
    let wide = serde_json::json!(["0.0.0.0/0", "::/0"]);
    let pause = || std::thread::sleep(Duration::from_millis(1100)); // new limiter window

    // The guard is the default: a wide ACL without the flag is refused.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": wide, "timeout_ms": 1000 }),
        ),
    );
    assert_eq!(s, 400, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("open resolver"),
        "{v}"
    );
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": wide, "timeout_ms": 1000, "open_resolver": false }),
        ),
    );
    assert_eq!(s, 400, "{v}");

    // Off (ordinary ACL): a 40-record answer fits the client's EDNS size.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 1000 }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["open_resolver"], false);
    let (n, r) = query_udp_edns(
        dns,
        "big.off.example.",
        RecordType::A,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        n > 512 && !r.metadata.truncation && r.answers.len() == 40,
        "{n} {r:?}"
    );
    let (_, st) = call(&root, "GET", &format!("{web}/api/status"), None);
    assert_eq!(st["forwarding"]["open_resolver"], false);
    assert_eq!(metric(&web, &root, "rustdns_open_resolver"), "0");

    // Turn it on, explicitly.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": wide, "timeout_ms": 1000, "open_resolver": true }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["open_resolver"], true);
    assert_eq!(v["allowed_clients"], wide);
    assert_eq!(v["open_resolver_max_udp_payload"], 512);
    assert_eq!(v["open_resolver_rate_per_second"], 10);
    let (_, st) = call(&root, "GET", &format!("{web}/api/status"), None);
    assert_eq!(st["forwarding"]["open_resolver"], true, "{st}");
    assert_eq!(metric(&web, &root, "rustdns_open_resolver"), "1");
    let (_, audit) = call(&root, "GET", &format!("{web}/api/audit?limit=50"), None);
    let e = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["action"] == "settings.forwarding.update"
                && e["detail"]["after"]["open_resolver"] == true
        })
        .unwrap_or_else(|| panic!("audited: {audit}"));
    assert_eq!(e["detail"]["before"]["open_resolver"], false, "{e}");

    // A client (inside 0.0.0.0/0) is answered via the upstream.
    pause();
    assert!(answered_by_fake(&query(dns, "hello.example.")));

    // Over the UDP cap: TC=1 with the answer removed, from the upstream and
    // from the cache alike; TCP gets the whole answer.
    for i in 0..2 {
        let (n, r) = query_udp_edns(
            dns,
            "big.on.example.",
            RecordType::A,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(n <= 512, "#{i}: {n} bytes");
        assert!(r.metadata.truncation && r.answers.is_empty(), "#{i}: {r:?}");
    }
    let r = query_tcp(dns, "big.on.example.", RecordType::A);
    assert!(!r.metadata.truncation && r.answers.len() == 40, "{r:?}");

    // ANY is not forwarded: a minimal RFC 8482 answer instead.
    let before = count.load(SeqCst);
    let (_, r) =
        query_udp_edns(dns, "any.example.", RecordType::ANY, Duration::from_secs(5)).unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.answers.len(), 1, "{r:?}");
    assert!(
        matches!(&r.answers[0].data, RData::HINFO(h) if &*h.cpu == b"RFC8482"),
        "{r:?}"
    );
    assert_eq!(count.load(SeqCst), before, "ANY reached the upstream");

    // The per-client forwarding limit (10/s here): a burst of 30 gets
    // at most two windows' worth of answers.
    pause();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    for i in 0..30u16 {
        let mut m = Message::new(i, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(
            Name::from_ascii("hello.example.").unwrap(),
            RecordType::A,
        ));
        sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", dns))
            .unwrap();
    }
    let (mut full, mut buf) = (0, [0u8; 4096]);
    while let Ok(n) = sock.recv(&mut buf) {
        let r = Message::from_bytes(&buf[..n]).unwrap();
        if answered_by_fake(&r) {
            full += 1;
        }
    }
    assert!((1..=20).contains(&full), "answered {full} of 30");
    let (_, st) = call(&root, "GET", &format!("{web}/api/status"), None);
    let d = &st["dns"];
    assert!(
        d["open_resolver_rate_limited"].as_u64().unwrap() >= 10,
        "{d}"
    );
    assert!(d["open_resolver_truncated"].as_u64().unwrap() >= 2, "{d}");
    assert_eq!(d["open_resolver_any"], 1, "{d}");
    assert_ne!(
        metric(&web, &root, "rustdns_open_resolver_rate_limited_total"),
        "0"
    );

    // Off again: the guard applies, and the cap no longer does.
    let (s, v) = call(
        &root,
        "PUT",
        &url,
        Some(
            serde_json::json!({ "upstreams": [upstream], "allowed_clients": ["127.0.0.0/8"], "timeout_ms": 1000, "open_resolver": false }),
        ),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["open_resolver"], false);
    assert_eq!(metric(&web, &root, "rustdns_open_resolver"), "0");
    let (n, r) = query_udp_edns(
        dns,
        "big.on.example.",
        RecordType::A,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(n > 512 && !r.metadata.truncation, "{n} {r:?}");
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `[forwarding].open_resolver = true` in the config file: a wide ACL is
/// accepted at startup, and `--check` says so loudly.
#[test]
fn open_resolver_from_the_config_file() {
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-openfile-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let up = fake_upstream();
    let fwd = format!("open_resolver = true\nupstreams = [\"127.0.0.1:{up}\"]\nallowed_clients = [\"0.0.0.0/0\", \"::/0\"]");
    let srv = Server::start_with(dir.clone(), free_port(), free_port(), &fwd);
    let out = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .arg("--config")
        .arg(dir.join("t.toml"))
        .arg("--check")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("WARNING: [forwarding].open_resolver is ON"),
        "{stdout}"
    );
    let root = login(&srv.web, "root", "rootpass123");
    let (_, v) = call(
        &root,
        "GET",
        &format!("{}/api/settings/forwarding", srv.web),
        None,
    );
    assert_eq!(v["source"], "config");
    assert_eq!(v["open_resolver"], true);
    assert_eq!(v["config"]["open_resolver"], true);
    assert!(answered_by_fake(&query(srv.dns, "hello.example.")));
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// C1: forwarded queries waiting for an upstream are capped
/// (`[forwarding].max_inflight`). With a stalled upstream, queries over the
/// cap are turned away at once (UDP dropped, TCP SERVFAIL) and counted, and
/// authoritative answers are not delayed.
#[test]
fn forwarding_is_capped_and_authoritative_answers_do_not_wait() {
    // A resolver that receives and never answers.
    let stalled = UdpSocket::bind("127.0.0.1:0").unwrap();
    let up = stalled.local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-fwdcap-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let srv = Server::start_with(
        dir.clone(),
        free_port(),
        free_port(),
        &format!(
            "upstreams = [\"127.0.0.1:{up}\"]\nallowed_clients = [\"127.0.0.0/8\"]\ntimeout_ms = 3000\ncache_entries = 0\nmax_inflight = 4"
        ),
    );
    let web = srv.web.clone();
    let root = login(&web, "root", "rootpass123");
    let (s, v) = call(
        &root,
        "POST",
        &format!("{web}/api/zones"),
        Some(serde_json::json!({ "name": "cap.test" })),
    );
    assert_eq!(s, 201, "{v}");
    let (s, v) = call(
        &root,
        "POST",
        &format!("{web}/api/zones/cap.test/records"),
        Some(serde_json::json!({ "name": "www", "type": "A", "value": "192.0.2.7" })),
    );
    assert_eq!(s, 201, "{v}");

    // 12 foreign names at once, each from its own socket.
    let started = Instant::now();
    let socks: Vec<UdpSocket> = (0..12)
        .map(|i| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut m = Message::new(1000 + i, MessageType::Query, OpCode::Query);
            m.metadata.recursion_desired = true;
            m.add_query(Query::query(
                Name::from_ascii(format!("n{i}.stalled.example.")).unwrap(),
                RecordType::A,
            ));
            sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", srv.dns))
                .unwrap();
            sock
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(metric(&web, &root, "rustdns_forward_inflight"), "4");
    assert_eq!(metric(&web, &root, "rustdns_forward_overflow_total"), "8");

    // Authoritative answers do not wait behind the stalled forwards.
    for _ in 0..20 {
        let t = Instant::now();
        let r = query(srv.dns, "www.cap.test.");
        assert_eq!(r.answers.len(), 1, "{r:?}");
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "authoritative answer took {:?}",
            t.elapsed()
        );
    }
    // Over the cap, TCP is told at once (not after the upstream timeout).
    let t = Instant::now();
    let r = query_tcp(srv.dns, "tcp.stalled.example.", RecordType::A);
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(metric(&web, &root, "rustdns_forward_overflow_total"), "9");
    let (_, st) = call(&root, "GET", &format!("{web}/api/status"), None);
    assert_eq!(st["dns"]["forward_overflow"], 9, "{st}");
    assert!(started.elapsed() < Duration::from_millis(2500));

    // After the upstream timeout exactly the 4 admitted queries get their
    // SERVFAIL; the 8 over the cap were dropped (the client retries).
    std::thread::sleep(Duration::from_millis(3200).saturating_sub(started.elapsed()));
    let mut servfail = 0;
    let mut buf = [0u8; 4096];
    for s in &socks {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        if let Ok(n) = s.recv(&mut buf) {
            let m = Message::from_bytes(&buf[..n]).unwrap();
            assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
            servfail += 1;
        }
    }
    assert_eq!(servfail, 4);
    // The slots are free again: forwarding resumes (and times out again).
    assert_eq!(metric(&web, &root, "rustdns_forward_inflight"), "0");
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut m = Message::new(77, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii("again.stalled.example.").unwrap(),
        RecordType::A,
    ));
    s.send_to(&m.to_vec().unwrap(), ("127.0.0.1", srv.dns))
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(metric(&web, &root, "rustdns_forward_inflight"), "1");
    assert_eq!(metric(&web, &root, "rustdns_forward_overflow_total"), "9");
    drop(stalled);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
