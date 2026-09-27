//! End-to-end: forwarding (upstream resolvers) managed through the API.
//! Starts the real binary and a fake upstream resolver on 127.0.0.1.

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
            let mut r = Message::new();
            r.set_id(q.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            for query in q.queries() {
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

struct Server {
    child: Child,
    dns: u16,
    web: String,
}

impl Server {
    fn start(dir: PathBuf, dns: u16, web_port: u16) -> Server {
        let cfg = format!(
            r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[forwarding]
upstreams = []
allowed_clients = ["127.0.0.0/8"]
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
    let req = a.request(method, url).set("X-Requested-With", "rust-dns");
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
    let mut m = Message::new();
    m.set_id(rand_id())
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
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
    m.response_code() == ResponseCode::NoError
        && m.answers()
            .iter()
            .any(|r| matches!(r.data(), RData::A(a) if a.0 == ANSWER))
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
        query(srv.dns, "anything.example.").response_code(),
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
        query(srv.dns, "after-reset.example.").response_code(),
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
