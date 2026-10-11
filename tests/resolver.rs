//! End-to-end: the resolver features of phase I on the query pipeline
//! (override zones, domain-needed, bogus-priv, rebinding protection, serve
//! stale, upstream strategies and health, filtered types, EDNS Client
//! Subnet, blocklists). The real binary, fake upstreams on 127.0.0.1, the
//! settings changed through the API as the console does.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

/// A fake upstream resolver (UDP). It answers A with its own address
/// `tag`, AAAA with 2001:db8::77, and by the first label of the name:
/// `rebind` A 10.0.0.1; `cnrebind` a CNAME to target.example. with A
/// 192.168.1.5; `ad` sets the AD bit; `ttl1` TTL 1. It echoes an EDNS
/// Client Subnet option (scope = source prefix) and records what it got.
/// (name, subnet received as "addr/prefix")
type Seen = (String, Option<String>);

#[derive(Clone)]
struct Fake {
    port: u16,
    down: Arc<AtomicBool>,
    queries: Arc<AtomicUsize>,
    /// (name, subnet received as "addr/prefix")
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn start(tag: Ipv4Addr, delay_ms: u64) -> Fake {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let f = Fake {
            port: sock.local_addr().unwrap().port(),
            down: Default::default(),
            queries: Default::default(),
            seen: Default::default(),
        };
        let me = f.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    return;
                };
                let Ok(q) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                if me.down.load(Ordering::SeqCst) {
                    continue;
                }
                me.queries.fetch_add(1, Ordering::SeqCst);
                let reply = Self::answer(&q, tag, &me);
                let sock = sock.try_clone().unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                    let _ = sock.send_to(&reply, peer);
                });
            }
        });
        f
    }

    fn answer(q: &Message, tag: Ipv4Addr, me: &Fake) -> Vec<u8> {
        let mut r = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
        r.metadata.recursion_desired = true;
        r.metadata.recursion_available = true;
        let query = &q.queries[0];
        r.add_query(query.clone());
        let name = query.name().clone();
        let first = name.to_ascii().to_ascii_lowercase();
        let first = first.split('.').next().unwrap_or("").to_string();
        let subnet = q
            .edns
            .as_ref()
            .and_then(|e| match e.options().get(EdnsCode::Subnet) {
                Some(EdnsOption::Subnet(s)) => Some(*s),
                _ => None,
            });
        me.seen.lock().unwrap().push((
            name.to_ascii(),
            subnet.map(|s| format!("{}/{}", s.addr(), s.source_prefix())),
        ));
        if let Some(e) = &q.edns {
            let mut ours = Edns::new();
            ours.set_max_payload(1232).set_version(0);
            if let Some(s) = subnet {
                ours.options_mut()
                    .insert(EdnsOption::Subnet(ClientSubnet::new(
                        s.addr(),
                        s.source_prefix(),
                        s.source_prefix(),
                    )));
            }
            let _ = e;
            r.set_edns(ours);
        }
        let ttl = if first == "ttl1" { 1 } else { 60 };
        match (first.as_str(), query.query_type()) {
            ("rebind", _) => {
                r.add_answer(Record::from_rdata(name, ttl, RData::A(A::new(10, 0, 0, 1))));
            }
            ("cnrebind", _) => {
                let t = Name::from_ascii("target.example.").unwrap();
                r.add_answer(Record::from_rdata(
                    name,
                    ttl,
                    RData::CNAME(CNAME(t.clone())),
                ));
                r.add_answer(Record::from_rdata(t, ttl, RData::A(A::new(192, 168, 1, 5))));
            }
            (_, RecordType::AAAA) => {
                r.add_answer(Record::from_rdata(
                    name,
                    ttl,
                    RData::AAAA(AAAA("2001:db8::77".parse().unwrap())),
                ));
            }
            (_, RecordType::A) => {
                if first == "ad" {
                    r.metadata.authentic_data = true;
                }
                r.add_answer(Record::from_rdata(name, ttl, RData::A(A(tag))));
            }
            _ => {}
        }
        r.to_vec().unwrap()
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

struct Server {
    child: Child,
    dns: u16,
    web: String,
    a: ureq::Agent,
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, forwarding: &str) -> Server {
        let dir = std::env::temp_dir().join(format!(
            "rust-dns-resolver-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (dns, web_port) = (free_port(), free_port());
        std::fs::write(
            dir.join("t.toml"),
            format!(
                "[server]\nbind = [\"127.0.0.1\"]\nport = {dns}\n[forwarding]\n{forwarding}\n[rate_limit]\nmax_resolutions_per_second_per_address = 0\n[transfer]\nallow = [\"127.0.0.0/8\"]\n[database]\npath = \"{}\"\n[backup]\ndir = \"\"\n[web_console]\nbind = \"127.0.0.1:{web_port}\"\nlogin_attempts_per_minute = 1000\n[root]\nusername = \"root\"\npassword = \"rootpass123\"\n[logging]\nlevel = \"warn\"\n",
                dir.join("t.db").display()
            ),
        )
        .unwrap();
        let mut dns = dns;
        let web = format!("http://127.0.0.1:{web_port}");
        let mut attempts = 0;
        let child = loop {
            attempts += 1;
            assert!(
                attempts <= 5,
                "the server never came up with all its listeners"
            );
            let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
                .arg("--config")
                .arg(dir.join("t.toml"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                // O0c: the server exits when this test process is gone.
                .env("RUST_DNS_EXIT_WITH_STDIN", "1")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while ureq::get(&format!("{web}/rust-dns/api/health"))
                .timeout(Duration::from_millis(300))
                .call()
                .is_err()
            {
                assert!(Instant::now() < deadline, "server did not start");
                std::thread::sleep(Duration::from_millis(100));
            }
            if common::came_up(&mut child, dns) {
                break child;
            }
            // O0a: the DNS port was taken; move it.
            dns = common::move_dns_port(&dir.join("t.toml"), dns);
        };
        let a = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .build();
        a.post(&format!("{web}/rust-dns/api/auth/login"))
            .send_json(json!({ "username": "root", "password": "rootpass123" }))
            .unwrap();
        Server {
            child,
            dns,
            web,
            a,
            dir,
        }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .a
            .request(method, &format!("{}/rust-dns/api{path}", self.web))
            .set("X-Requested-With", "rust-dns")
            .set("X-CSRF-Token", &csrf_of(&self.a));
        let r = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match r {
            Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, r.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("{method} {path}: {e}"),
        }
    }

    fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(method, path, body);
        assert!((200..300).contains(&s), "{method} {path}: {s} {v}");
        v
    }

    fn resolver(&self, settings: Value) -> Value {
        self.ok("PUT", "/settings/resolver", Some(settings))
    }

    fn add(&self, zone: &str, name: &str, t: &str, v: &str) {
        self.ok(
            "POST",
            &format!("/zones/{zone}/records"),
            Some(json!({ "name": name, "type": t, "value": v })),
        );
    }

    fn metrics(&self) -> String {
        self.a
            .get(&format!("{}/rust-dns/metrics", self.web))
            .call()
            .unwrap()
            .into_string()
            .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ask_with(port: u16, name: &str, t: RecordType, edns: Option<Edns>, rd: bool) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = rd;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    if let Some(e) = edns {
        m.set_edns(e);
    }
    sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).ok()?;
    Some(Message::from_bytes(&buf[..n]).unwrap())
}

fn ask(port: u16, name: &str, t: RecordType) -> Message {
    ask_with(port, name, t, None, true).unwrap_or_else(|| panic!("no answer for {name} {t}"))
}

fn addrs(m: &Message) -> Vec<String> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

fn forwarding(upstreams: &[&Fake]) -> String {
    let ups: Vec<String> = upstreams
        .iter()
        .map(|f| format!("\"{}\"", f.addr()))
        .collect();
    format!(
        "upstreams = [{}]\nallowed_clients = [\"127.0.0.0/8\"]\ntimeout_ms = 600",
        ups.join(", ")
    )
}

const TAG: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

/// I2, I3, I9: domain-needed and bogus-priv are on by default; own zones
/// and automatic PTR still win; both can be switched off from the API;
/// filtered types get NODATA without asking upstream.
#[test]
fn domain_needed_bogus_priv_and_filtered_types() {
    let up = Fake::start(TAG, 0);
    let srv = Server::start("dn", &forwarding(&[&up]));
    let v = srv.ok("GET", "/settings/resolver", None);
    assert_eq!(v["source"], "config");
    assert_eq!(v["settings"]["domain_needed"], true);
    assert_eq!(v["settings"]["bogus_priv"], true);

    // Single label: NXDOMAIN here, the upstream never asked.
    let m = ask(srv.dns, "wpad.", RecordType::A);
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(!m.metadata.authoritative);
    // The root and two-label names are forwarded.
    assert_eq!(
        addrs(&ask(srv.dns, "www.example.", RecordType::A)),
        vec![TAG.to_string()]
    );
    assert_eq!(up.count(), 1);
    // A single-label own zone still answers.
    srv.ok("POST", "/zones", Some(json!({ "name": "lan" })));
    srv.add("lan", "@", "A", "10.9.9.1");
    let m = ask(srv.dns, "lan.", RecordType::A);
    assert!(m.metadata.authoritative);
    assert_eq!(addrs(&m), vec!["10.9.9.1"]);

    // Private reverse: NXDOMAIN here...
    let m = ask(srv.dns, "5.1.168.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    let m = ask(
        srv.dns,
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
        RecordType::PTR,
    );
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(up.count(), 1, "nothing forwarded");
    // ...but automatic PTR (10.9.9.1 in the own zone) and own reverse
    // zones win.
    let m = ask(srv.dns, "1.9.9.10.in-addr.arpa.", RecordType::PTR);
    assert_eq!(m.answers.len(), 1, "auto PTR");
    srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "168.192.in-addr.arpa" })),
    );
    srv.add("168.192.in-addr.arpa", "5.1", "PTR", "printer.lan.");
    let m = ask(srv.dns, "5.1.168.192.in-addr.arpa.", RecordType::PTR);
    assert!(m.metadata.authoritative && m.answers.len() == 1);
    // Public reverse names are forwarded as before.
    ask(srv.dns, "8.8.8.8.in-addr.arpa.", RecordType::PTR);
    assert_eq!(up.count(), 2);
    let v = srv.ok("GET", "/settings/resolver", None);
    assert_eq!(v["domain_needed_answered"], 1);
    assert_eq!(v["bogus_priv_answered"], 2);
    assert!(srv
        .metrics()
        .contains("rustdns_filter_queries_total{filter=\"domain_needed\",outcome=\"answered\"} 1"));

    // Off: forwarded.
    let v = srv.resolver(json!({ "domain_needed": false, "bogus_priv": false }));
    assert_eq!(v["source"], "console");
    assert_eq!(
        addrs(&ask(srv.dns, "wpad.", RecordType::A)),
        vec![TAG.to_string()]
    );
    ask(srv.dns, "2.2.0.10.in-addr.arpa.", RecordType::PTR);
    assert_eq!(up.count(), 4);

    // Filtered types: NODATA without asking.
    srv.resolver(json!({ "filter_types": ["aaaa"] }));
    let v = srv.ok("GET", "/settings/resolver", None);
    assert_eq!(v["settings"]["filter_types"], json!(["AAAA"]));
    let m = ask(srv.dns, "v6.example.", RecordType::AAAA);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(m.answers.is_empty());
    assert_eq!(up.count(), 4);
    assert_eq!(
        addrs(&ask(srv.dns, "v6.example.", RecordType::A)),
        vec![TAG.to_string()]
    );
    // Own zones are not filtered.
    srv.add("lan", "@", "AAAA", "fd00::1");
    assert_eq!(
        addrs(&ask(srv.dns, "lan.", RecordType::AAAA)),
        vec!["fd00::1"]
    );
    // Invalid input is refused with every problem listed.
    let (s, v) = srv.call(
        "PUT",
        "/settings/resolver",
        Some(
            json!({ "filter_types": ["BOGUS"], "max_stale_age_secs": 1, "rebind_allow": ["a..b"] }),
        ),
    );
    assert_eq!(s, 400, "{v}");
    let msg = v.to_string();
    assert!(
        msg.contains("BOGUS") && msg.contains("max_stale_age_secs") && msg.contains("a..b"),
        "{msg}"
    );
    // Reset: the defaults (on) again.
    srv.ok("DELETE", "/settings/resolver", None);
    assert_eq!(
        ask(srv.dns, "wpad.", RecordType::A).metadata.response_code,
        ResponseCode::NXDomain
    );
}

/// I4: rebinding protection refuses forwarded answers with private
/// addresses (also from the cache and at the end of a CNAME chain),
/// except for allowlisted domains; own and override zones are never
/// checked; refused names are listed with counts.
#[test]
fn rebinding_protection() {
    let up = Fake::start(TAG, 0);
    let srv = Server::start("rebind", &forwarding(&[&up]));
    // Off (default): private answers pass.
    assert_eq!(
        addrs(&ask(srv.dns, "rebind.evil.example.", RecordType::A)),
        vec!["10.0.0.1"]
    );
    srv.resolver(json!({ "rebind_protection": true, "rebind_allow": ["Corp.Example."] }));
    // From the cache (filled above) and fresh: refused.
    for _ in 0..2 {
        let m = ask(srv.dns, "rebind.evil.example.", RecordType::A);
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
        assert!(m.answers.is_empty());
    }
    let m = ask(srv.dns, "cnrebind.evil.example.", RecordType::A);
    assert_eq!(
        m.metadata.response_code,
        ResponseCode::Refused,
        "CNAME chain to a private address"
    );
    // Allowlisted (suffix): passes.
    assert_eq!(
        addrs(&ask(srv.dns, "rebind.corp.example.", RecordType::A)),
        vec!["10.0.0.1"]
    );
    // Public answers pass.
    assert_eq!(
        addrs(&ask(srv.dns, "www.example.", RecordType::A)),
        vec![TAG.to_string()]
    );
    // Own zone with a private address: unaffected.
    srv.ok("POST", "/zones", Some(json!({ "name": "home.test" })));
    srv.add("home.test", "nas", "A", "192.168.1.10");
    assert_eq!(
        addrs(&ask(srv.dns, "nas.home.test.", RecordType::A)),
        vec!["192.168.1.10"]
    );
    // Override zone with a private address: unaffected.
    srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "vpn.test", "override": { "mode": "static" } })),
    );
    srv.add("vpn.test", "gw", "A", "10.8.0.1");
    assert_eq!(
        addrs(&ask(srv.dns, "gw.vpn.test.", RecordType::A)),
        vec!["10.8.0.1"]
    );
    let v = srv.ok("GET", "/settings/resolver", None);
    assert_eq!(v["rebind_blocked_total"], 3);
    let list = v["rebind_blocked"].as_array().unwrap();
    let e = list
        .iter()
        .find(|e| e["name"] == "rebind.evil.example")
        .unwrap();
    assert_eq!(e["count"], 2);
    assert_eq!(e["address"], "10.0.0.1");
}

/// I5: with serve stale on, an expired answer is served (TTL 30) when the
/// upstream stops answering; off, SERVFAIL.
#[test]
fn serve_stale_when_every_upstream_fails() {
    let up = Fake::start(TAG, 0);
    let srv = Server::start("stale", &forwarding(&[&up]));
    srv.resolver(json!({ "serve_stale": true, "max_stale_age_secs": 600 }));
    let m = ask(srv.dns, "ttl1.example.", RecordType::A);
    assert_eq!(m.answers[0].ttl, 1);
    std::thread::sleep(Duration::from_millis(2100));
    up.down.store(true, Ordering::SeqCst);
    let m = ask(srv.dns, "ttl1.example.", RecordType::A);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addrs(&m), vec![TAG.to_string()]);
    assert_eq!(m.answers[0].ttl, 30, "RFC 8767 stale TTL");
    assert_eq!(
        srv.ok("GET", "/settings/resolver", None)["stale_answers"],
        1
    );
    // A name never seen: SERVFAIL.
    assert_eq!(
        ask(srv.dns, "other.example.", RecordType::A)
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    // Off: no stale answer.
    srv.resolver(json!({ "serve_stale": false }));
    assert_eq!(
        ask(srv.dns, "ttl1.example.", RecordType::A)
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    // Upstream back: answered normally.
    up.down.store(false, Ordering::SeqCst);
    assert_eq!(
        ask(srv.dns, "ttl1.example.", RecordType::A).answers[0].ttl,
        1
    );
}

/// I6: in_order tries upstreams in order (a dead first one costs a
/// timeout); fastest prefers the quickest healthy one; parallel answers
/// with the first; a dead upstream is marked down after 3 failures and
/// shows in the health table.
#[test]
fn upstream_strategies_and_health() {
    let dead = Fake::start(Ipv4Addr::new(192, 0, 2, 1), 0);
    dead.down.store(true, Ordering::SeqCst);
    let slow = Fake::start(Ipv4Addr::new(192, 0, 2, 2), 250);
    let fast = Fake::start(Ipv4Addr::new(192, 0, 2, 3), 0);
    let srv = Server::start("strategy", &forwarding(&[&dead, &slow, &fast]));
    let timed = |name: &str| {
        let t = Instant::now();
        let m = ask(srv.dns, name, RecordType::A);
        (addrs(&m), t.elapsed())
    };
    // in_order: the dead one times out (600 ms), then the slow one answers.
    let (a, took) = timed("n1.example.");
    assert_eq!(a, vec!["192.0.2.2"]);
    assert!(took >= Duration::from_millis(600), "{took:?}");
    for i in 2..4 {
        timed(&format!("n{i}.example."));
    }
    let v = srv.ok("GET", "/settings/resolver", None);
    let h = v["upstream_health"].as_array().unwrap();
    assert_eq!(h.len(), 3);
    assert_eq!(h[0]["upstream"], dead.addr());
    assert_eq!(h[0]["down"], true, "{h:?}");
    assert_eq!(h[0]["consecutive_failures"], 3);
    assert!(h[0]["last_error"].as_str().unwrap().contains("timed out"));
    assert_eq!(h[1]["successes"], 3);
    assert!(h[1]["latency_ms"].as_f64().unwrap() >= 200.0);
    assert_eq!(h[2]["successes"], 0, "in_order never reached the third");

    // fastest: the unmeasured fast one is tried first, then preferred.
    srv.resolver(json!({ "strategy": "fastest" }));
    for i in 0..5 {
        let (a, took) = timed(&format!("f{i}.example."));
        assert_eq!(a, vec!["192.0.2.3"]);
        assert!(took < Duration::from_millis(200), "{took:?}");
    }
    // parallel: the first answer wins.
    srv.resolver(json!({ "strategy": "parallel" }));
    let before = slow.count();
    for i in 0..5 {
        let (a, took) = timed(&format!("p{i}.example."));
        assert_eq!(a, vec!["192.0.2.3"]);
        assert!(took < Duration::from_millis(200), "{took:?}");
    }
    assert_eq!(slow.count() - before, 5, "the slow one was asked too");
    assert_eq!(dead.count(), 0);
}

/// I10: EDNS Client Subnet is off by default; on, the client's subnet
/// (truncated) goes upstream, the option is not shown to a client that
/// did not send EDNS, answers are cached per subnet scope, and a client's
/// own subnet option is passed through.
#[test]
fn edns_client_subnet() {
    let up = Fake::start(TAG, 0);
    let srv = Server::start("ecs", &forwarding(&[&up]));
    ask(srv.dns, "plain.example.", RecordType::A);
    assert_eq!(
        up.seen.lock().unwrap().last().unwrap().1,
        None,
        "off by default"
    );
    // Clients on 127.0.0.0/8 are special: no ECS unless chosen.
    srv.resolver(json!({ "ecs": true, "ecs_ipv4_prefix": 16 }));
    ask(srv.dns, "private.example.", RecordType::A);
    assert_eq!(up.seen.lock().unwrap().last().unwrap().1, None);
    srv.resolver(json!({ "ecs": true, "ecs_ipv4_prefix": 16, "ecs_private_clients": true }));
    let m = ask(srv.dns, "ecs.example.", RecordType::A);
    assert_eq!(
        up.seen.lock().unwrap().last().unwrap().1.as_deref(),
        Some("127.0.0.0/16")
    );
    assert!(m.edns.is_none(), "no OPT for a client that sent none");
    assert_eq!(addrs(&m), vec![TAG.to_string()]);
    // Cached for this subnet: not asked again.
    let n = up.count();
    let mut e = Edns::new();
    e.set_max_payload(1232);
    let m = ask_with(srv.dns, "ecs.example.", RecordType::A, Some(e), true).unwrap();
    assert_eq!(up.count(), n, "cache hit");
    let opt = m.edns.expect("OPT echoed to an EDNS client");
    assert!(
        opt.options().get(EdnsCode::Subnet).is_none(),
        "our ECS option is not shown"
    );
    // A client's own subnet goes upstream unchanged.
    let mut e = Edns::new();
    e.set_max_payload(1232);
    e.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        24,
        0,
    )));
    ask_with(srv.dns, "own.example.", RecordType::A, Some(e), true).unwrap();
    assert_eq!(
        up.seen.lock().unwrap().last().unwrap().1.as_deref(),
        Some("198.51.100.0/24")
    );
}

/// I1: override zones. Local data answered non-authoritatively, other
/// types and names to the zone's upstreams (transparent), NXDOMAIN in
/// static mode, conditional forwarding, a local CNAME chased upstream,
/// REFUSED for clients that may not forward, never in AXFR, never AD,
/// never signed.
#[test]
fn override_zones() {
    let global = Fake::start(TAG, 0);
    let corp = Fake::start(Ipv4Addr::new(198, 51, 100, 9), 0);
    let srv = Server::start("override", &forwarding(&[&global]));
    let v = srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "corp.test", "override": { "upstreams": [corp.addr()] } })),
    );
    assert_eq!(v["override"]["mode"], "transparent");
    srv.add("corp.test", "www", "A", "10.1.1.1");
    srv.add("corp.test", "alias", "CNAME", "app.elsewhere.example.");
    srv.add("corp.test", "*.wild", "A", "10.1.1.2");
    // Local name and type: from here, not authoritative.
    let m = ask(srv.dns, "www.corp.test.", RecordType::A);
    assert_eq!(addrs(&m), vec!["10.1.1.1"]);
    assert!(!m.metadata.authoritative);
    assert!(m.metadata.recursion_available);
    assert_eq!(
        addrs(&ask(srv.dns, "x.wild.corp.test.", RecordType::A)),
        vec!["10.1.1.2"]
    );
    assert_eq!(corp.count(), 0);
    // Another type of a local name, and a name not here: the zone's
    // upstreams, not the global ones.
    assert_eq!(
        addrs(&ask(srv.dns, "www.corp.test.", RecordType::AAAA)),
        vec!["2001:db8::77"]
    );
    assert_eq!(
        addrs(&ask(srv.dns, "other.corp.test.", RecordType::A)),
        vec!["198.51.100.9"]
    );
    assert_eq!((corp.count(), global.count()), (2, 0));
    // A local CNAME to a name elsewhere: chased through the zone's upstreams.
    let m = ask(srv.dns, "alias.corp.test.", RecordType::A);
    assert!(matches!(m.answers[0].data, RData::CNAME(_)));
    assert_eq!(addrs(&m), vec!["198.51.100.9"]);
    // Never AD, even if the upstream sets it.
    let m = ask(srv.dns, "ad.corp.test.", RecordType::A);
    assert!(!m.metadata.authentic_data);
    // Static: names not here are NXDOMAIN, with the zone's SOA.
    srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "blocked.test", "override": { "mode": "static" } })),
    );
    let m = ask(srv.dns, "anything.blocked.test.", RecordType::A);
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(!m.metadata.authoritative && m.authorities.len() == 1);
    // Conditional forwarding: an override zone without records.
    srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "partner.test", "override": { "upstreams": [corp.addr()] } })),
    );
    assert_eq!(
        addrs(&ask(srv.dns, "host.partner.test.", RecordType::A)),
        vec!["198.51.100.9"]
    );
    // Mode and upstreams can change; the type cannot.
    let v = srv.ok(
        "PUT",
        "/zones/partner.test",
        Some(json!({ "override": { "upstreams": [global.addr()] } })),
    );
    assert_eq!(v["override"]["upstreams"], json!([global.addr()]));
    assert_eq!(
        addrs(&ask(srv.dns, "host2.partner.test.", RecordType::A)),
        vec![TAG.to_string()]
    );
    srv.ok("POST", "/zones", Some(json!({ "name": "auth.test" })));
    let (s, _) = srv.call(
        "PUT",
        "/zones/auth.test",
        Some(json!({ "override": { "mode": "static" } })),
    );
    assert_eq!(s, 400);
    // Never signed, never transferred.
    let (s, v) = srv.call(
        "PUT",
        "/zones/corp.test/dnssec",
        Some(json!({ "enabled": true })),
    );
    assert_eq!(s, 400, "{v}");
    let m = ask(srv.dns, "corp.test.", RecordType::AXFR);
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    // The console's zone list shows the type.
    let zones = srv.ok("GET", "/zones", None);
    let z = zones["zones"]
        .as_array()
        .unwrap()
        .iter()
        .find(|z| z["name"] == "corp.test")
        .unwrap()
        .clone();
    assert_eq!(z["override"]["mode"], "transparent");
    // Export carries the type; importing it as a new zone recreates it.
    let doc = srv.ok("GET", "/zones/corp.test/export", None);
    assert_eq!(doc["zones"][0]["override"]["mode"], "transparent", "{doc}");
    let mut doc2 = doc.clone();
    doc2["zones"][0]["name"] = json!("copy.test");
    srv.ok("POST", "/import", Some(doc2));
    let v = srv.ok("GET", "/zones/copy.test", None);
    assert_eq!(v["override"]["upstreams"], json!([corp.addr()]), "{v}");
    assert_eq!(
        addrs(&ask(srv.dns, "www.copy.test.", RecordType::A)),
        vec!["10.1.1.1"]
    );
    // Clients that may not forward: REFUSED.
    srv.ok(
        "PUT",
        "/settings/forwarding",
        Some(json!({ "upstreams": [global.addr()], "allowed_clients": ["10.0.0.0/8"], "timeout_ms": 600 })),
    );
    assert_eq!(
        ask(srv.dns, "www.corp.test.", RecordType::A)
            .metadata
            .response_code,
        ResponseCode::Refused
    );
    // Authoritative answers are unaffected.
    srv.add("auth.test", "h", "A", "192.0.2.4");
    assert!(
        ask(srv.dns, "h.auth.test.", RecordType::A)
            .metadata
            .authoritative
    );
}

/// I7: blocklists from a local HTTP server: every format, suffix match,
/// the allowlist, both actions, own zones win, the test endpoint, the
/// last good copy kept when a refresh fails.
#[test]
fn blocklists_block_forwarded_names() {
    use std::io::{Read, Write};
    let up = Fake::start(TAG, 0);
    let srv = Server::start("block", &forwarding(&[&up]));
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hosts.txt",
        http.local_addr().unwrap().port()
    );
    let fail = Arc::new(AtomicBool::new(false));
    {
        let fail = fail.clone();
        std::thread::spawn(move || {
            for mut c in http.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = c.read(&mut buf);
                let r = if fail.load(Ordering::SeqCst) {
                    "HTTP/1.1 503 Busy\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_string()
                } else {
                    let body = "# test list\n0.0.0.0 ads.example.net\n||tracker.example.org^\nplain.example.io\n0.0.0.0 home.test\n";
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = c.write_all(r.as_bytes());
            }
        });
    }
    srv.ok("POST", "/zones", Some(json!({ "name": "home.test" })));
    srv.add("home.test", "@", "A", "192.0.2.10");
    srv.ok(
        "PUT",
        "/blocklists",
        Some(
            json!({ "lists": [{ "name": "local", "url": url }], "allow": ["ok.ads.example.net"] }),
        ),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let v = loop {
        let v = srv.ok("GET", "/blocklists", None);
        if v["lists"][0]["entries"] == 4 {
            break v;
        }
        assert!(Instant::now() < deadline, "not downloaded: {v}");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(v["lists"][0]["loaded_at"].is_string());
    assert_eq!(v["memory_bytes"], 32);
    for n in [
        "ads.example.net.",
        "x.ads.example.net.",
        "tracker.example.org.",
        "plain.example.io.",
    ] {
        let m = ask(srv.dns, n, RecordType::A);
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain, "{n}");
    }
    assert_eq!(up.count(), 0);
    // Allowlisted, not listed, and own zones (even when listed): answered.
    assert_eq!(
        addrs(&ask(srv.dns, "ok.ads.example.net.", RecordType::A)),
        vec![TAG.to_string()]
    );
    assert_eq!(
        addrs(&ask(srv.dns, "example.net.", RecordType::A)),
        vec![TAG.to_string()]
    );
    assert_eq!(
        addrs(&ask(srv.dns, "home.test.", RecordType::A)),
        vec!["192.0.2.10"]
    );
    let t = srv.ok(
        "POST",
        "/blocklists/test",
        Some(json!({ "name": "A.Ads.Example.Net." })),
    );
    assert_eq!(t["blocked"], true);
    assert_eq!(t["matches"][0]["entry"], "ads.example.net");
    let t = srv.ok(
        "POST",
        "/blocklists/test",
        Some(json!({ "name": "ok.ads.example.net" })),
    );
    assert_eq!(
        (t["blocked"].clone(), t["allowed_by"].clone()),
        (json!(false), json!("ok.ads.example.net"))
    );
    // Null address action.
    srv.ok(
        "PUT",
        "/blocklists",
        Some(json!({ "lists": [{ "name": "local", "url": url }], "action": "null_address" })),
    );
    assert_eq!(
        addrs(&ask(srv.dns, "ads.example.net.", RecordType::A)),
        vec!["0.0.0.0"]
    );
    assert_eq!(
        addrs(&ask(srv.dns, "ads.example.net.", RecordType::AAAA)),
        vec!["::"]
    );
    let m = ask(srv.dns, "ads.example.net.", RecordType::MX);
    assert!(m.answers.is_empty() && m.metadata.response_code == ResponseCode::NoError);
    // A failed refresh keeps the last good copy.
    fail.store(true, Ordering::SeqCst);
    srv.ok("POST", "/blocklists/refresh", None);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let v = srv.ok("GET", "/blocklists", None);
        if v["lists"][0]["error"].is_string() {
            assert_eq!(v["lists"][0]["entries"], 4);
            assert!(v["blocked"].as_u64().unwrap() >= 7);
            break;
        }
        assert!(Instant::now() < deadline, "no refresh: {v}");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        addrs(&ask(srv.dns, "ads.example.net.", RecordType::A)),
        vec!["0.0.0.0"]
    );
    // Off: forwarded again.
    srv.ok(
        "PUT",
        "/blocklists",
        Some(json!({ "lists": [{ "name": "local", "url": url, "enabled": false }] })),
    );
    assert_eq!(
        addrs(&ask(srv.dns, "ads.example.net.", RecordType::A)),
        vec![TAG.to_string()]
    );
    let (s, _) = srv.call(
        "PUT",
        "/blocklists",
        Some(json!({ "lists": [{ "name": "x", "url": "ftp://x" }] })),
    );
    assert_eq!(s, 400);
}

fn bind_tool(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = ["/opt/homebrew/opt/bind/bin", "/usr/local/bin", "/usr/bin"]
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
        eprintln!("resolver: {name} not found; skipping that check");
    }
    t
}

/// I1 under a signed parent: an override zone `vpn.parent.test` inside the
/// signed `parent.test` changes nothing of the parent: its AXFR is still
/// fully signed (`dnssec-verify`), `delv` still validates the parent's
/// names and negative answers, and the override names are answered (not
/// authoritative, no RRSIG, no AD) only to clients allowed to forward.
#[test]
fn an_override_zone_under_a_signed_parent() {
    let up = Fake::start(TAG, 0);
    let srv = Server::start("ovsigned", &forwarding(&[&up]));
    srv.ok("POST", "/zones", Some(json!({ "name": "parent.test" })));
    srv.add("parent.test", "@", "NS", "ns1.parent.test.");
    srv.add("parent.test", "ns1", "A", "192.0.2.53");
    srv.add("parent.test", "www", "A", "192.0.2.1");
    srv.add("parent.test", "*.wild", "A", "192.0.2.3");
    let on = srv.ok(
        "PUT",
        "/zones/parent.test/dnssec",
        Some(json!({ "enabled": true })),
    );
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    let rrsets = on["signatures"]["signed_rrsets"].clone();
    srv.ok(
        "POST",
        "/zones",
        Some(json!({ "name": "vpn.parent.test", "override": { "mode": "static" } })),
    );
    srv.add("vpn.parent.test", "gw", "A", "10.8.0.1");
    // The parent's signed data is unchanged by the override zone.
    let st = srv.ok("GET", "/zones/parent.test/dnssec", None);
    assert_eq!(st["signatures"]["signed_rrsets"], rrsets);
    // Override names: answered from the override zone, unsigned, not AA.
    let mut e = Edns::new();
    e.set_max_payload(1232).set_dnssec_ok(true);
    let m = ask_with(srv.dns, "gw.vpn.parent.test.", RecordType::A, Some(e), true).unwrap();
    assert_eq!(addrs(&m), vec!["10.8.0.1"]);
    assert!(!m.metadata.authoritative && !m.metadata.authentic_data);
    assert!(
        m.answers
            .iter()
            .all(|r| r.record_type() != RecordType::RRSIG),
        "never signed"
    );
    if let (Some(dig), Some(verify)) = (bind_tool("dig"), bind_tool("dnssec-verify")) {
        let out = Command::new(&dig)
            .args([
                "@127.0.0.1",
                "-p",
                &srv.dns.to_string(),
                "parent.test",
                "AXFR",
                "+nocmd",
                "+nocomments",
                "+nostats",
            ])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            !text.contains("gw.vpn"),
            "override data is not in the parent's AXFR"
        );
        let zf = srv.dir.join("axfr.zone");
        std::fs::write(&zf, &out.stdout).unwrap();
        let v = Command::new(&verify)
            .args(["-z", "-o", "parent.test", zf.to_str().unwrap()])
            .output()
            .unwrap();
        let t =
            String::from_utf8_lossy(&v.stdout).to_string() + &String::from_utf8_lossy(&v.stderr);
        assert!(v.status.success() && t.contains("Zone fully signed"), "{t}");
    }
    if let Some(delv) = bind_tool("delv") {
        let f: Vec<&str> = dnskey.split_whitespace().collect();
        let anchor = srv.dir.join("anchor.conf");
        std::fs::write(
            &anchor,
            format!(
                "trust-anchors {{ \"{}\" static-key {} {} {} \"{}\"; }};\n",
                f[0], f[4], f[5], f[6], f[7]
            ),
        )
        .unwrap();
        for (name, t, want) in [
            ("www.parent.test", "A", "; fully validated"),
            ("x.wild.parent.test", "A", "; fully validated"),
            ("parent.test", "SOA", "; fully validated"),
            (
                "nope.parent.test",
                "A",
                "; negative response, fully validated",
            ),
            (
                "www.parent.test",
                "AAAA",
                "; negative response, fully validated",
            ),
        ] {
            let out = Command::new(&delv)
                .args([
                    "@127.0.0.1",
                    "-p",
                    &srv.dns.to_string(),
                    "-a",
                    anchor.to_str().unwrap(),
                    "+root=parent.test",
                    name,
                    t,
                ])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr);
            assert!(
                text.lines().any(|l| l.starts_with(want)),
                "delv {name} {t}: {text}"
            );
        }
        // How the override looks to a validator: the parent's signed data
        // says the name does not exist, and the override answer is
        // unsigned, so a validating resolver asking through this server
        // treats it as bogus (documented: override zones under a signed
        // parent are for clients that do not validate them, or for names
        // the validator is told to trust, e.g. a negative trust anchor).
        let out = Command::new(&delv)
            .args([
                "@127.0.0.1",
                "-p",
                &srv.dns.to_string(),
                "-a",
                anchor.to_str().unwrap(),
                "+root=parent.test",
                "gw.vpn.parent.test",
                "A",
            ])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(
            !text.lines().any(|l| l.starts_with("; fully validated")),
            "an unsigned override answer cannot validate: {text}"
        );
        eprintln!("delv gw.vpn.parent.test A:\n{text}");
    }
}
