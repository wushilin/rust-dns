//! DNSSEC end to end: the real binary signs a zone shaped like the owner's
//! public zone (apex A/NS/MX/TXT, wildcards next to their explicit parents,
//! CNAMEs in and out of the zone, long TXT, delegations with and without DS,
//! an expired record) and the answers are checked by independent validators:
//!
//! - BIND `dnssec-dsfromkey` (DS digests), `dnssec-verify` (the zone
//!   transferred with AXFR: every signature and the NSEC chain), `delv`
//!   ("fully validated" for positive, wildcard, NXDOMAIN, NODATA, CNAME,
//!   DNAME, DS answers, mixed-case names and TCP) and, when `named` is
//!   installed, a validating BIND resolver (AD flag, no SERVFAIL).
//!   Without BIND tools these parts are skipped (a note is printed);
//!   `REQUIRE_BIND_TOOLS=1` (set in CI) makes a missing tool a failure.
//! - dnspython validation lives in scripts/conformance.py.
//!
//! Also: without DO the answers are those of the unsigned zone byte for
//! byte (apart from the SOA serial the change bumped), truncation never
//! splits an RRset from its RRSIG, re-signing bumps the serial, and turning
//! signing off is refused while the parent (a second rust-dns hosting the
//! parent zone, reached as the forwarding upstream) publishes a DS.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
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

const ZONE: &str = "wushilin.test";

mod common;
use common::free_port;

fn long_dkim() -> String {
    format!(
        "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA{}IDAQAB",
        "x".repeat(360)
    )
}

/// The zone: the shape of wushilin.net.
fn records() -> Vec<(&'static str, &'static str, String, Option<u32>)> {
    let mut v: Vec<(&str, &str, String, Option<u32>)> = vec![
        ("@", "NS", "ns1.wushilin.test.".into(), Some(86400)),
        ("@", "NS", "ns2.wushilin.test.".into(), Some(86400)),
        ("@", "A", "116.15.54.86".into(), Some(14400)),
        ("@", "MX", "10 mail.wushilin.test.".into(), Some(1800)),
        (
            "@",
            "TXT",
            "v=spf1 a:mail.wushilin.test ~all".into(),
            Some(1800),
        ),
        ("@", "CAA", "0 issue \"letsencrypt.org\"".into(), None),
        ("ns1", "A", "3.1.237.225".into(), Some(1800)),
        ("ns2", "A", "47.237.120.106".into(), Some(1800)),
        ("mail", "A", "3.1.237.225".into(), Some(1800)),
        ("gate", "A", "3.1.237.225".into(), Some(1800)),
        ("*.gate", "A", "3.1.237.225".into(), Some(1800)),
        ("ap-southeast-1", "A", "3.1.237.225".into(), Some(1800)),
        ("*.ap-southeast-1", "A", "3.1.237.225".into(), Some(1800)),
        ("rusts3api", "A", "43.230.99.31".into(), Some(1800)),
        ("*.rusts3api", "A", "43.230.99.31".into(), Some(14400)),
        ("registry", "CNAME", "vq.wushilin.test.".into(), Some(300)),
        ("vq", "A", "43.230.99.31".into(), Some(1800)),
        (
            "ymhh3kyr3evt",
            "CNAME",
            "gv-q67lhs3ob66b6o.dv.googlehosted.com.".into(),
            Some(14400),
        ),
        ("mercury", "A", "43.230.99.31".into(), Some(14400)),
        (
            "mercury",
            "AAAA",
            "2001:d98:b450:9c00::ffff:101a".into(),
            Some(14400),
        ),
        ("www", "A", "3.1.237.225".into(), Some(300)),
        ("www", "A", "3.1.237.226".into(), Some(600)),
        (
            "_dmarc",
            "TXT",
            "v=DMARC1; p=none; rua=mailto:dmarc@wushilin.test".into(),
            None,
        ),
        ("sel1._domainkey", "TXT", long_dkim(), None),
        (
            "_sip._tcp",
            "SRV",
            "10 20 5060 sip.wushilin.test.".into(),
            None,
        ),
        ("svc", "HTTPS", "1 . alpn=h2,h3".into(), None),
        ("legacy", "DNAME", "gate.wushilin.test.".into(), None),
        ("sub", "NS", "ns.sub.wushilin.test.".into(), None),
        ("ns.sub", "A", "192.0.2.53".into(), None),
        ("secure", "NS", "ns.secure.wushilin.test.".into(), None),
        ("ns.secure", "A", "192.0.2.54".into(), None),
        (
            "secure",
            "DS",
            format!("12345 13 2 {}", "AB".repeat(32)),
            None,
        ),
        ("a.b.deep", "TXT", "empty non-terminals above".into(), None),
    ];
    for i in 1..=40 {
        v.push(("many", "A", format!("10.9.9.{i}"), None));
    }
    v
}

// ---------------------------------------------------------------------------
// BIND tools
// ---------------------------------------------------------------------------

fn tool(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("BIND_BIN") {
        dirs.push(d.into());
    }
    for d in [
        "/opt/homebrew/opt/bind/bin",
        "/opt/homebrew/opt/bind/sbin",
        "/usr/local/opt/bind/bin",
        "/usr/local/opt/bind/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
    ] {
        dirs.push(d.into());
    }
    if let Some(p) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&p));
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

/// A BIND tool, or `None` (skip) when it is not installed. With
/// `REQUIRE_BIND_TOOLS=1` a missing tool fails the test.
fn bind_tool(name: &str) -> Option<PathBuf> {
    let t = tool(name);
    if t.is_none() {
        assert!(
            std::env::var("REQUIRE_BIND_TOOLS").is_err(),
            "{name} not found (install BIND: bind9-utils / bind9-dnsutils, or brew install bind)"
        );
        eprintln!("dnssec: {name} not found; skipping that independent check");
    }
    t
}

fn run(cmd: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(cmd).args(args).output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

// ---------------------------------------------------------------------------
// Servers and the API
// ---------------------------------------------------------------------------

struct Server {
    child: Option<Child>,
    dir: PathBuf,
    dns: u16,
    web: String,
    agent: ureq::Agent,
}

fn write_config(dir: &Path, dns: u16, web: u16, extra: &str) {
    let cfg = format!(
        r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[transfer]
allow = ["127.0.0.0/8"]
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{db}"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{web}"
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "info"
file = "{log}"
{extra}
"#,
        db = dir.join("t.db").display(),
        log = dir.join("server.log").display(),
    );
    std::fs::write(dir.join("t.toml"), cfg).unwrap();
}

impl Server {
    fn new(dir: PathBuf, extra: &str) -> Server {
        std::fs::create_dir_all(&dir).unwrap();
        let (dns, web) = (free_port(), free_port());
        write_config(&dir, dns, web, extra);
        let mut s = Server {
            child: None,
            dir,
            dns,
            web: format!("http://127.0.0.1:{web}"),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        };
        s.start();
        s
    }

    /// Start (or restart) the server; `self.dns` moves when its port was
    /// taken (O0a).
    fn start(&mut self) {
        for attempt in 0.. {
            assert!(
                attempt < 5,
                "the server never came up with all its listeners"
            );
            let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
                .arg("--config")
                .arg(self.dir.join("t.toml"))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                // O0c: the server exits when this test process is gone.
                .env("RUST_DNS_EXIT_WITH_STDIN", "1")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while ureq::get(&format!("{}/api/health", self.web))
                .timeout(Duration::from_millis(300))
                .call()
                .is_err()
            {
                assert!(Instant::now() < deadline, "server did not start");
                std::thread::sleep(Duration::from_millis(100));
            }
            if common::came_up(&mut child, self.dns) {
                self.child = Some(child);
                break;
            }
            self.dns = common::move_dns_port(&self.dir.join("t.toml"), self.dns);
        }
        self.agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        let (st, _) = self.api(
            "POST",
            "/api/auth/login",
            Some(json!({ "username": "root", "password": "rootpass123" })),
        );
        assert_eq!(st, 200);
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn api(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .agent
            .request(method, &format!("{}{path}", self.web))
            .set("X-Requested-With", "rust-dns")
            .set("X-CSRF-Token", &csrf_of(&self.agent));
        let res = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match res {
            Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, r.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("{method} {path}: {e}"),
        }
    }

    fn import(&self, zone: &str, recs: &[(&str, &str, String, Option<u32>)]) {
        let records: Vec<Value> = recs
            .iter()
            .map(|(n, t, v, ttl)| {
                let mut r = json!({ "name": n, "type": t, "value": v });
                if let Some(ttl) = ttl {
                    r["ttl"] = json!(ttl);
                }
                r
            })
            .collect();
        let doc = json!({ "version": 1, "exported_at": "2026-01-01T00:00:00Z", "zones": [{
            "name": zone, "soa_mname": format!("ns1.{zone}."), "soa_rname": format!("hostmaster.{zone}."),
            "default_ttl": 3600, "minimum": 300, "records": records }] });
        let (st, r) = self.api("POST", "/api/import?mode=merge", Some(doc));
        assert_eq!(st, 200, "{r}");
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rust-dns-dnssec-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// A query with a fixed ID. `edns`: None = no OPT, Some(size) = OPT with
/// that payload and the DO bit as given.
fn query_bytes(name: &str, t: RecordType, edns: Option<u16>, dnssec_ok: bool) -> Vec<u8> {
    let mut m = Message::new(0x4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = false;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    if let Some(size) = edns {
        let mut e = Edns::new();
        e.set_max_payload(size)
            .set_version(0)
            .set_dnssec_ok(dnssec_ok);
        m.set_edns(e);
    }
    m.to_vec().unwrap()
}

fn udp(port: u16, q: &[u8]) -> Vec<u8> {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.send_to(q, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 65535];
    let (n, _) = s.recv_from(&mut buf).unwrap();
    buf[..n].to_vec()
}

fn tcp(port: u16, q: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
    s.write_all(q).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    buf
}

fn parse(b: &[u8]) -> Message {
    Message::from_bytes(b).unwrap()
}

fn soa_serial(port: u16) -> u32 {
    let m = parse(&udp(
        port,
        &query_bytes(&format!("{ZONE}."), RecordType::SOA, None, false),
    ));
    match &m.answers[0].data {
        RData::SOA(s) => s.serial,
        _ => panic!("no SOA"),
    }
}

/// The response with SOA serials zeroed (a signing change bumps the serial).
fn without_serial(b: &[u8]) -> Vec<u8> {
    let mut m = parse(b);
    for r in m.answers.iter_mut().chain(m.authorities.iter_mut()) {
        if let RData::SOA(s) = &mut r.data {
            *s = hickory_proto::rr::rdata::SOA::new(
                s.mname.clone(),
                s.rname.clone(),
                0,
                s.refresh,
                s.retry,
                s.expire,
                s.minimum,
            );
        }
    }
    m.to_vec().unwrap()
}

const NO_DO_PROBES: &[(&str, RecordType)] = &[
    ("wushilin.test.", RecordType::A),
    ("wushilin.test.", RecordType::MX),
    ("wushilin.test.", RecordType::NS),
    ("wushilin.test.", RecordType::TXT),
    ("wushilin.test.", RecordType::SOA),
    ("wushilin.test.", RecordType::ANY),
    ("www.wushilin.test.", RecordType::A),
    ("WwW.WuShIlIn.TeSt.", RecordType::A),
    ("foo.gate.wushilin.test.", RecordType::A),
    ("foo.gate.wushilin.test.", RecordType::AAAA),
    ("x.ap-southeast-1.wushilin.test.", RecordType::A),
    ("registry.wushilin.test.", RecordType::A),
    ("ymhh3kyr3evt.wushilin.test.", RecordType::A),
    ("x.legacy.wushilin.test.", RecordType::A),
    ("nope.wushilin.test.", RecordType::A),
    ("deep.wushilin.test.", RecordType::A),
    ("www.wushilin.test.", RecordType::MX),
    ("host.sub.wushilin.test.", RecordType::A),
    ("host.secure.wushilin.test.", RecordType::A),
    ("sel1._domainkey.wushilin.test.", RecordType::TXT),
    ("many.wushilin.test.", RecordType::A),
];

/// Responses to the probes without DO: plain, with EDNS, and over TCP.
fn no_do_answers(port: u16) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (n, t) in NO_DO_PROBES {
        for (label, edns) in [("plain", None), ("edns", Some(1232))] {
            let q = query_bytes(n, *t, edns, false);
            out.push((format!("{n} {t} {label} udp"), udp(port, &q)));
            out.push((format!("{n} {t} {label} tcp"), tcp(port, &q)));
        }
    }
    out
}

fn delv_cases() -> Vec<(
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
)> {
    // (expected, name, type, extra delv options)
    vec![
        ("fully validated", "wushilin.test", "SOA", &[]),
        ("fully validated", "wushilin.test", "NS", &[]),
        ("fully validated", "wushilin.test", "DNSKEY", &[]),
        ("fully validated", "wushilin.test", "MX", &[]),
        ("fully validated", "wushilin.test", "TXT", &[]),
        ("fully validated", "wushilin.test", "A", &[]),
        ("fully validated", "wushilin.test", "CAA", &[]),
        ("fully validated", "wushilin.test", "ANY", &[]),
        ("fully validated", "www.wushilin.test", "A", &[]),
        ("fully validated", "WwW.WuShIlIn.TeSt", "A", &[]),
        ("fully validated", "mercury.wushilin.test", "AAAA", &[]),
        ("fully validated", "gate.wushilin.test", "A", &[]),
        ("fully validated", "foo.gate.wushilin.test", "A", &[]),
        ("fully validated", "a.b.c.gate.wushilin.test", "A", &[]),
        ("fully validated", "ap-southeast-1.wushilin.test", "A", &[]),
        (
            "fully validated",
            "x.ap-southeast-1.wushilin.test",
            "A",
            &[],
        ),
        ("fully validated", "rusts3api.wushilin.test", "A", &[]),
        (
            "fully validated",
            "bucket.rusts3api.wushilin.test",
            "A",
            &[],
        ),
        ("fully validated", "registry.wushilin.test", "A", &[]),
        (
            "fully validated",
            "ymhh3kyr3evt.wushilin.test",
            "CNAME",
            &[],
        ),
        ("fully validated", "_dmarc.wushilin.test", "TXT", &[]),
        (
            "fully validated",
            "sel1._domainkey.wushilin.test",
            "TXT",
            &[],
        ),
        ("fully validated", "_sip._tcp.wushilin.test", "SRV", &[]),
        ("fully validated", "svc.wushilin.test", "HTTPS", &[]),
        ("fully validated", "legacy.wushilin.test", "DNAME", &[]),
        ("fully validated", "x.legacy.wushilin.test", "A", &[]),
        ("fully validated", "secure.wushilin.test", "DS", &[]),
        ("fully validated", "many.wushilin.test", "A", &["+tcp"]),
        ("fully validated", "www.wushilin.test", "A", &["+tcp"]),
        (
            "negative response, fully validated",
            "nope.wushilin.test",
            "A",
            &[],
        ),
        (
            "negative response, fully validated",
            "NoPe.WuShIlIn.TeSt",
            "A",
            &[],
        ),
        (
            "negative response, fully validated",
            "nope.deep.wushilin.test",
            "A",
            &[],
        ),
        (
            "negative response, fully validated",
            "www.wushilin.test",
            "MX",
            &[],
        ),
        (
            "negative response, fully validated",
            "foo.gate.wushilin.test",
            "AAAA",
            &[],
        ),
        (
            "negative response, fully validated",
            "deep.wushilin.test",
            "A",
            &[],
        ),
        (
            "negative response, fully validated",
            "b.deep.wushilin.test",
            "TXT",
            &[],
        ),
        (
            "negative response, fully validated",
            "wushilin.test",
            "SRV",
            &[],
        ),
        (
            "negative response, fully validated",
            "sub.wushilin.test",
            "DS",
            &[],
        ),
        (
            "negative response, fully validated",
            "expired.wushilin.test",
            "A",
            &[],
        ),
        (
            "negative response, fully validated",
            "nx.gate.x.wushilin.test",
            "A",
            &["+tcp"],
        ),
    ]
}

fn delv_line(out: &str) -> String {
    out.lines()
        .find(|l| {
            l.starts_with("; fully validated")
                || l.starts_with("; negative response")
                || l.starts_with("; unsigned answer")
                || l.contains("resolution failed")
                || l.contains("validation failed")
        })
        .unwrap_or("")
        .to_string()
}

fn run_delv(delv: &Path, port: u16, anchor: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let p = port.to_string();
    for (expect, name, t, extra) in delv_cases() {
        let mut args = vec![
            "@127.0.0.1",
            "-p",
            &p,
            "-a",
            anchor.to_str().unwrap(),
            "+root=wushilin.test",
        ];
        args.extend_from_slice(extra);
        args.push(name);
        args.push(t);
        let (_, out) = run(delv, &args);
        let line = delv_line(&out);
        if !line.starts_with(&format!("; {expect}")) {
            failures.push(format!("delv {name} {t} {extra:?}: {line:?}\n{out}"));
        }
    }
    failures
}

fn anchor_file(dir: &Path, dnskey_text: &str, name: &str) -> PathBuf {
    // "wushilin.test. 3600 IN DNSKEY 257 3 13 <b64>"
    let f: Vec<&str> = dnskey_text.split_whitespace().collect();
    let conf = format!(
        "trust-anchors {{ \"{}\" static-key {} {} {} \"{}\"; }};\n",
        f[0], f[4], f[5], f[6], f[7]
    );
    let p = dir.join(name);
    std::fs::write(&p, conf).unwrap();
    p
}

/// A validating BIND resolver forwarding the zone to rust-dns, with a
/// static trust anchor. Returns failures (empty = every answer had AD).
fn run_named(named: &Path, dig: &Path, dir: &Path, port: u16, anchor: &Path) -> Vec<String> {
    let np = free_port();
    let wd = dir.join("named");
    std::fs::create_dir_all(&wd).unwrap();
    let conf = format!(
        r#"options {{
  directory "{wd}";
  pid-file "{wd}/named.pid";
  listen-on port {np} {{ 127.0.0.1; }};
  listen-on-v6 {{ none; }};
  recursion yes;
  allow-query {{ 127.0.0.1; }};
  allow-recursion {{ 127.0.0.1; }};
  dnssec-validation yes;
  qname-minimization off;
}};
{anchor}
zone "{ZONE}" {{ type forward; forward only; forwarders {{ 127.0.0.1 port {port}; }}; }};
"#,
        wd = wd.display(),
        anchor = std::fs::read_to_string(anchor).unwrap(),
    );
    std::fs::write(wd.join("named.conf"), conf).unwrap();
    let mut child = Command::new(named)
        .args(["-g", "-c"])
        .arg(wd.join("named.conf"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(wd.join("named.log")).unwrap())
        .spawn()
        .unwrap();
    let npp = np.to_string();
    let dig_args = |name: &str, t: &str| -> Vec<String> {
        vec![
            "@127.0.0.1".into(),
            "-p".into(),
            npp.clone(),
            "+dnssec".into(),
            "+time=5".into(),
            "+tries=1".into(),
            name.into(),
            t.into(),
        ]
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let args = dig_args("version.bind", "TXT");
        let (_, out) = run(dig, &args.iter().map(String::as_str).collect::<Vec<_>>());
        if out.contains("status:") || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut failures = Vec::new();
    for (expect, name, t, _) in delv_cases() {
        let status = if expect.starts_with("negative")
            && (name.starts_with("nope")
                || name.starts_with("NoPe")
                || name.starts_with("nope.deep")
                || name.starts_with("expired")
                || name.starts_with("nx."))
        {
            "NXDOMAIN"
        } else {
            "NOERROR"
        };
        let args = dig_args(name, t);
        let (_, out) = run(dig, &args.iter().map(String::as_str).collect::<Vec<_>>());
        let flags = out
            .lines()
            .find(|l| l.starts_with(";; flags:"))
            .unwrap_or("")
            .to_string();
        // ";; flags: qr rd ra ad; QUERY: ..."
        let ad = flags
            .split("flags:")
            .nth(1)
            .and_then(|f| f.split(';').next())
            .is_some_and(|f| f.split_whitespace().any(|x| x == "ad"));
        if !out.contains(&format!("status: {status}")) || !ad {
            failures.push(format!(
                "named {name} {t}: want {status} + AD: {flags}\n{out}"
            ));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    failures
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn signed_zone_validates_with_independent_validators() {
    let dir = tmpdir("main");
    let s = Server::new(dir.clone(), "");
    s.import(ZONE, &records());
    // An expired record: stored, not served, not in the NSEC chain.
    let (st, r) = s.api(
        "POST",
        &format!("/api/zones/{ZONE}/records"),
        Some(json!({ "name": "expired", "type": "A", "value": "192.0.2.99", "expires_in": 1 })),
    );
    assert_eq!(st, 201, "{r}");
    std::thread::sleep(Duration::from_millis(1500));

    // RFC 3225: DO echoed even for an unsigned zone.
    let m = parse(&udp(
        s.dns,
        &query_bytes("www.wushilin.test.", RecordType::A, Some(1232), true),
    ));
    assert!(m.edns.as_ref().unwrap().flags().dnssec_ok, "DO bit copied");
    let m = parse(&udp(
        s.dns,
        &query_bytes("www.wushilin.test.", RecordType::A, Some(1232), false),
    ));
    assert!(!m.edns.as_ref().unwrap().flags().dnssec_ok);

    // Signing off: status, no key, no DS.
    let (st, off) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec"), None);
    assert_eq!(st, 200);
    assert_eq!(off["state"], "off");
    assert!(off["key"].is_null() && off["ds"].as_array().unwrap().is_empty());
    let (_, ds) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/ds"), None);
    assert!(ds["key_tag"].is_null());
    let (st, _) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/check"), None);
    assert_eq!(st, 409, "self-check needs signing on");
    let before = no_do_answers(s.dns);
    let serial_before = soa_serial(s.dns);

    // Turn signing on.
    let (st, on) = s.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": true })),
    );
    assert_eq!(st, 200, "{on}");
    assert_eq!(on["state"], "signing");
    assert_eq!(on["key"]["algorithm"], 13);
    assert_eq!(on["key"]["flags"], 257);
    assert_eq!(
        soa_serial(s.dns),
        serial_before + 1,
        "enabling bumps the serial"
    );
    let sig = &on["signatures"];
    assert!(sig["signed_rrsets"].as_u64().unwrap() > 30);
    let inc = chrono::DateTime::parse_from_rfc3339(sig["inception"].as_str().unwrap()).unwrap();
    let exp = chrono::DateTime::parse_from_rfc3339(sig["expiration"].as_str().unwrap()).unwrap();
    assert_eq!((exp - inc).num_days(), 14, "validity 14 days");
    assert!(
        inc < chrono::Utc::now() - chrono::Duration::minutes(50),
        "inception 1 h back"
    );
    assert!(!sig["next_resign"].is_null());
    let dnskey_text = on["key"]["dnskey"].as_str().unwrap().to_string();
    let key_tag = on["key"]["key_tag"].as_u64().unwrap();
    let log = s.log();
    assert!(log.contains("zone signed"), "signing is logged");
    let (_, dsl) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/ds"), None);
    let ds_records: Vec<String> = dsl["ds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["record"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ds_records.len(), 2);
    assert_eq!(dsl["key_tag"], json!(key_tag));

    // Self-check through the API.
    let (st, chk) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/check"), None);
    assert_eq!(st, 200);
    assert_eq!(chk["ok"], true, "{chk:#}");
    // No private key anywhere in the API, the changelog API or the log.
    let (_, cl) = s.api("GET", "/api/changelog?limit=1000", None);
    let blob = format!("{on}{dsl}{chk}{cl}");
    assert!(!blob.contains("private") && !blob.contains("dnssec_key_set"));
    let db = rusqlite::Connection::open(dir.join("t.db")).unwrap();
    let private: String = db
        .query_row("SELECT private_key FROM dnssec_keys", [], |r| r.get(0))
        .unwrap();
    assert!(!blob.contains(&private) && !s.log().contains(&private));

    // Without DO, answers are those of the unsigned zone (serial aside).
    let after = no_do_answers(s.dns);
    let mut identical = 0;
    for ((what, a), (_, b)) in before.iter().zip(&after) {
        if a == b {
            identical += 1;
            continue;
        }
        // Only the SOA serial (bumped by turning signing on) may differ.
        let has_soa = parse(a)
            .answers
            .iter()
            .chain(parse(a).authorities.iter())
            .any(|r| r.record_type() == RecordType::SOA);
        assert!(
            has_soa && without_serial(a) == without_serial(b),
            "{what}: answer without DO changed when signing was turned on"
        );
    }
    assert!(identical > 40, "most answers byte-identical ({identical})");
    // Truncation: a signed answer over 512 bytes never carries a partial RRset.
    let small = parse(&udp(
        s.dns,
        &query_bytes("many.wushilin.test.", RecordType::A, Some(512), true),
    ));
    assert!(small.metadata.truncation, "TC set");
    assert!(small.answers.is_empty() && small.authorities.is_empty());
    let full = parse(&tcp(
        s.dns,
        &query_bytes("many.wushilin.test.", RecordType::A, Some(512), true),
    ));
    assert!(!full.metadata.truncation);
    assert_eq!(full.answers.len(), 41, "40 A + RRSIG over TCP");
    let plain = parse(&udp(
        s.dns,
        &query_bytes("many.wushilin.test.", RecordType::A, None, false),
    ));
    assert!(
        plain.metadata.truncation && plain.answers.is_empty(),
        "no EDNS: 512 limit"
    );

    // ---- independent validation (BIND) ------------------------------------
    let mut failures = Vec::new();
    if let Some(dsfromkey) = bind_tool("dnssec-dsfromkey") {
        let kf = dir.join("K.key");
        std::fs::write(&kf, format!("{dnskey_text}\n")).unwrap();
        for (arg, want) in [("-2", &ds_records[0]), ("-a", &ds_records[1])] {
            let args: Vec<&str> = if arg == "-a" {
                vec!["-a", "SHA-384", kf.to_str().unwrap()]
            } else {
                vec!["-2", kf.to_str().unwrap()]
            };
            let (ok, out) = run(&dsfromkey, &args);
            assert!(ok, "{out}");
            assert_eq!(out.trim(), want, "DS equals dnssec-dsfromkey {arg}");
        }
    }
    if let (Some(dig), Some(verify)) = (bind_tool("dig"), bind_tool("dnssec-verify")) {
        let p = s.dns.to_string();
        let (ok, axfr) = run(
            &dig,
            &[
                "@127.0.0.1",
                "-p",
                &p,
                ZONE,
                "AXFR",
                "+nocmd",
                "+nocomments",
                "+nostats",
            ],
        );
        assert!(
            ok && axfr.contains("RRSIG") && axfr.contains("NSEC"),
            "{axfr}"
        );
        assert!(
            !axfr.contains("expired.wushilin.test"),
            "expired record not transferred"
        );
        let zf = dir.join("axfr.zone");
        std::fs::write(&zf, &axfr).unwrap();
        let (ok, out) = run(&verify, &["-z", "-o", ZONE, zf.to_str().unwrap()]);
        assert!(
            ok && out.contains("Zone fully signed"),
            "dnssec-verify:\n{out}"
        );
    }
    if let Some(delv) = bind_tool("delv") {
        let anchor = anchor_file(&dir, &dnskey_text, "anchor.conf");
        failures.extend(run_delv(&delv, s.dns, &anchor));
        // Negative control: a wrong trust anchor must not validate.
        let mut f: Vec<String> = dnskey_text.split_whitespace().map(String::from).collect();
        f[7] = f[7].replacen(&f[7][..2].to_string(), "AA", 1);
        let bad = anchor_file(&dir, &f.join(" "), "bad-anchor.conf");
        let (_, out) = run(
            &delv,
            &[
                "@127.0.0.1",
                "-p",
                &s.dns.to_string(),
                "-a",
                bad.to_str().unwrap(),
                "+root=wushilin.test",
                "www.wushilin.test",
                "A",
            ],
        );
        assert!(
            !delv_line(&out).starts_with("; fully validated"),
            "wrong anchor must fail: {out}"
        );
    }
    if let (Some(named), Some(dig)) = (tool("named"), tool("dig")) {
        let anchor = anchor_file(&dir, &dnskey_text, "anchor.conf");
        failures.extend(run_named(&named, &dig, &dir, s.dns, &anchor));
    } else {
        eprintln!("dnssec: named not found; skipping the validating-resolver check");
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resign_bumps_the_serial_and_keeps_validating() {
    let dir = tmpdir("resign");
    let mut s = Server::new(dir.clone(), "");
    s.import(ZONE, &records()[..12]);
    let (st, _) = s.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": true })),
    );
    assert_eq!(st, 200);
    let serial = soa_serial(s.dns);
    // Pretend the zone was signed 8 days ago (server stopped): the re-sign
    // is due (validity 14, re-sign 7 days before expiry). The window comes
    // from the signing epoch (`signed_at`), not from the last change.
    s.stop();
    let eight_days_ago = (chrono::Utc::now() - chrono::Duration::days(8))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let db = rusqlite::Connection::open(dir.join("t.db")).unwrap();
    db.execute(
        "UPDATE zones SET updated_at = ?1, signed_at = ?1 WHERE name = ?2",
        rusqlite::params![eight_days_ago, ZONE],
    )
    .unwrap();
    drop(db);
    s.start();
    let deadline = Instant::now() + Duration::from_secs(20);
    while soa_serial(s.dns) == serial {
        assert!(Instant::now() < deadline, "no re-sign within 20 s");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(soa_serial(s.dns), serial + 1);
    let (_, cl) = s.api("GET", "/api/changelog?limit=100", None);
    let entries = cl["entries"].as_array().cloned().unwrap_or_default();
    assert!(
        entries
            .iter()
            .any(|e| e["payload"]["kind"] == "zone_resigned"),
        "zone_resigned in the changelog: {cl}"
    );
    let (_, st) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec"), None);
    let inc = chrono::DateTime::parse_from_rfc3339(st["signatures"]["inception"].as_str().unwrap())
        .unwrap();
    assert!(
        chrono::Utc::now() - inc.with_timezone(&chrono::Utc) < chrono::Duration::hours(2),
        "fresh window after the re-sign: {st}"
    );
    let (_, chk) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/check"), None);
    assert_eq!(chk["ok"], true, "{chk:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn turning_signing_off_is_refused_while_the_parent_publishes_a_ds() {
    let dir = tmpdir("parent");
    // The parent: zone "test" delegating wushilin.test, reached by the child
    // as its forwarding upstream (a recursive resolver would find the same).
    let parent = Server::new(dir.join("parent"), "");
    let child = Server::new(
        dir.join("child"),
        &format!(
            "[forwarding]\nupstreams = [\"127.0.0.1:{}\"]\nallowed_clients = [\"127.0.0.0/8\"]\n",
            parent.dns
        ),
    );
    child.import(ZONE, &records()[..12]);
    let (_, on) = child.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": true })),
    );
    let ds = on["ds"][0]["record"].as_str().unwrap().to_string();
    let ds_value = ds.split(" IN DS ").nth(1).unwrap().to_string();
    let parent_recs = vec![
        ("@", "NS", "ns1.test.".to_string(), None),
        ("ns1", "A", "192.0.2.1".to_string(), None),
        ("wushilin", "NS", "ns1.wushilin.test.".to_string(), None),
    ];
    parent.import("test", &parent_recs);

    // No DS at the parent yet: absent; turning off would be allowed.
    let (_, p) = child.api("GET", &format!("/api/zones/{ZONE}/dnssec/parent"), None);
    assert_eq!(p["state"], "absent", "{p}");

    // Publish the DS at the parent: present; turning off is refused.
    let (st, r) = parent.api(
        "POST",
        "/api/zones/test/records",
        Some(json!({ "name": "wushilin", "type": "DS", "value": ds_value })),
    );
    assert_eq!(st, 201, "{r}");
    let (_, p) = child.api("GET", &format!("/api/zones/{ZONE}/dnssec/parent"), None);
    assert_eq!(p["state"], "present", "{p}");
    assert_eq!(p["parent_ds"].as_array().unwrap().len(), 1);
    let (st, r) = child.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": false })),
    );
    assert_eq!(st, 409, "{r}");
    assert_eq!(r["code"], "ds_published");
    assert!(r["error"]
        .as_str()
        .unwrap()
        .contains("Remove the DS record at your registrar"));
    let (_, s) = child.api("GET", &format!("/api/zones/{ZONE}/dnssec"), None);
    assert_eq!(s["enabled"], true, "still signing");

    // A DS for another key: mismatch, still refused.
    let (_, recs) = parent.api("GET", "/api/zones/test/records", None);
    let ds_id = recs["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == "DS")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (st, _) = parent.api(
        "PUT",
        &format!("/api/zones/test/records/{ds_id}"),
        Some(json!({ "value": format!("1 13 2 {}", "00".repeat(32)) })),
    );
    assert_eq!(st, 200);
    let (_, p) = child.api("GET", &format!("/api/zones/{ZONE}/dnssec/parent"), None);
    assert_eq!(p["state"], "mismatch", "{p}");
    let (st, _) = child.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": false })),
    );
    assert_eq!(st, 409);

    // The DS removed at the parent: turning off is allowed.
    let (st, _) = parent.api("DELETE", &format!("/api/zones/test/records/{ds_id}"), None);
    assert_eq!(st, 200);
    let (st, r) = child.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": false })),
    );
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["state"], "off");
    // The key is kept: turning on again reuses it (same DS).
    let (_, again) = child.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": true })),
    );
    assert_eq!(again["ds"][0]["record"].as_str().unwrap(), ds);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The AXFR of the zone as text (dig), checked with dnssec-verify. Returns
/// the transfer.
fn axfr_verified(dig: &Path, verify: &Path, dir: &Path, port: u16, file: &str) -> String {
    let p = port.to_string();
    let (ok, axfr) = run(
        dig,
        &[
            "@127.0.0.1",
            "-p",
            &p,
            ZONE,
            "AXFR",
            "+nocmd",
            "+nocomments",
            "+nostats",
        ],
    );
    assert!(ok && axfr.contains("RRSIG"), "{axfr}");
    let zf = dir.join(file);
    std::fs::write(&zf, &axfr).unwrap();
    let (ok, out) = run(verify, &["-z", "-o", ZONE, zf.to_str().unwrap()]);
    assert!(
        ok && out.contains("Zone fully signed"),
        "dnssec-verify ({file}):\n{out}"
    );
    axfr
}

/// Records of one type in a dig transfer (tab-separated presentation form).
fn axfr_count(axfr: &str, t: &str) -> usize {
    axfr.lines()
        .filter(|l| l.split_whitespace().nth(3) == Some(t))
        .count()
}

/// O24: a zone signed with NSEC3 (RFC 5155, RFC 9276 parameters) validates
/// with BIND (delv on positive, NXDOMAIN, NODATA, wildcard, empty
/// non-terminal, delegation and DS answers; dnssec-verify on the AXFR;
/// a validating named when installed), and switching a signed zone
/// between NSEC and NSEC3 keeps every answer validating at every moment:
/// delv runs in a loop while the zone is switched back and forth, and no
/// answer fails. Answers without DO do not change (serial aside).
#[test]
fn nsec3_validates_and_switching_denial_keeps_every_answer_valid() {
    let dir = tmpdir("nsec3");
    let s = Server::new(dir.clone(), "");
    s.import(ZONE, &records());
    let set = |body: Value| -> Value {
        let (st, r) = s.api("PUT", &format!("/api/zones/{ZONE}/dnssec"), Some(body));
        assert_eq!(st, 200, "{r}");
        r
    };
    // Denial applies only while signing is on.
    let (st, r) = s.api(
        "PUT",
        &format!("/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": false, "denial": "nsec3" })),
    );
    assert_eq!(st, 400, "{r}");
    let before = no_do_answers(s.dns);
    let on = set(json!({ "enabled": true }));
    assert_eq!(on["denial"], "nsec", "NSEC by default");
    let dnskey_text = on["key"]["dnskey"].as_str().unwrap().to_string();
    let nsec_names = on["signatures"]["nsec_names"].as_u64().unwrap();
    let (Some(dig), Some(verify), Some(delv)) = (
        bind_tool("dig"),
        bind_tool("dnssec-verify"),
        bind_tool("delv"),
    ) else {
        return;
    };
    let anchor = anchor_file(&dir, &dnskey_text, "anchor.conf");
    let axfr = axfr_verified(&dig, &verify, &dir, s.dns, "nsec.zone");
    assert!(axfr_count(&axfr, "NSEC") > 10 && axfr_count(&axfr, "NSEC3") == 0);
    let f = run_delv(&delv, s.dns, &anchor);
    assert!(f.is_empty(), "NSEC zone: {}", f.join("\n"));

    // delv in a loop over the denial cases while the zone is switched.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_handle = {
        let (stop, delv, anchor, port) = (stop.clone(), delv.clone(), anchor.clone(), s.dns);
        std::thread::spawn(move || {
            let cases: &[(&str, &str, &str)] = &[
                (
                    "negative response, fully validated",
                    "nope.wushilin.test",
                    "A",
                ),
                (
                    "negative response, fully validated",
                    "www.wushilin.test",
                    "MX",
                ),
                (
                    "negative response, fully validated",
                    "deep.wushilin.test",
                    "A",
                ),
                (
                    "negative response, fully validated",
                    "foo.gate.wushilin.test",
                    "AAAA",
                ),
                (
                    "negative response, fully validated",
                    "sub.wushilin.test",
                    "DS",
                ),
                ("fully validated", "foo.gate.wushilin.test", "A"),
                ("fully validated", "www.wushilin.test", "A"),
            ];
            let p = port.to_string();
            let (mut runs, mut failures) = (0usize, Vec::new());
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                for (expect, name, t) in cases {
                    let (_, out) = run(
                        &delv,
                        &[
                            "@127.0.0.1",
                            "-p",
                            &p,
                            "-a",
                            anchor.to_str().unwrap(),
                            "+root=wushilin.test",
                            name,
                            t,
                        ],
                    );
                    runs += 1;
                    let line = delv_line(&out);
                    if !line.starts_with(&format!("; {expect}")) {
                        failures.push(format!("{name} {t}: {line:?}\n{out}"));
                    }
                }
            }
            (runs, failures)
        })
    };
    let mut denials = Vec::new();
    for want in ["nsec3", "nsec", "nsec3", "nsec", "nsec3"] {
        std::thread::sleep(Duration::from_millis(700));
        let r = set(json!({ "enabled": true, "denial": want }));
        assert_eq!(r["denial"], want, "{r}");
        assert_eq!(r["state"], "signing");
        assert_eq!(
            r["key"]["dnskey"].as_str().unwrap(),
            dnskey_text,
            "same key: no DS change"
        );
        denials.push(r["signatures"]["nsec_names"].as_u64().unwrap());
        // What the server serves right after the switch.
        let m = parse(&tcp(
            s.dns,
            &query_bytes("nope.wushilin.test.", RecordType::A, Some(1232), true),
        ));
        let has = |code: u16| {
            m.authorities
                .iter()
                .any(|r| u16::from(r.record_type()) == code)
        };
        assert_eq!(
            (has(50), has(47)),
            (want == "nsec3", want == "nsec"),
            "{want}: NSEC3 / NSEC in the NXDOMAIN proof"
        );
    }
    std::thread::sleep(Duration::from_millis(700));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (runs, failures) = loop_handle.join().unwrap();
    assert!(
        failures.is_empty(),
        "{} of {runs} delv answers failed during the switches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(runs >= 21, "the loop ran across the switches ({runs})");
    eprintln!("nsec3: {runs} delv answers during 5 switches, all validated");
    // NSEC3 counts the empty non-terminals too (deep, b.deep, _tcp,
    // _domainkey).
    assert!(denials[0] > nsec_names, "{denials:?} vs {nsec_names}");

    // Now NSEC3: the whole zone validates.
    let axfr = axfr_verified(&dig, &verify, &dir, s.dns, "nsec3.zone");
    assert_eq!(axfr_count(&axfr, "NSEC"), 0, "{axfr}");
    assert_eq!(axfr_count(&axfr, "NSEC3PARAM"), 1);
    assert_eq!(axfr_count(&axfr, "NSEC3") as u64, denials[0]);
    let mut failures = run_delv(&delv, s.dns, &anchor);
    if let Some(named) = tool("named") {
        failures.extend(run_named(&named, &dig, &dir, s.dns, &anchor));
    }
    assert!(
        failures.is_empty(),
        "NSEC3 zone, {} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // NSEC3PARAM is served (signed with DO, plain without).
    let m = parse(&tcp(
        s.dns,
        &query_bytes("wushilin.test.", RecordType::NSEC3PARAM, Some(1232), true),
    ));
    assert_eq!(m.answers.len(), 2, "NSEC3PARAM + RRSIG");
    let m = parse(&udp(
        s.dns,
        &query_bytes("wushilin.test.", RecordType::NSEC3PARAM, None, false),
    ));
    assert_eq!(m.answers.len(), 1);
    // BIND's own hash of the apex is the NSEC3 owner it validated. An extra
    // cross-check only: Ubuntu's bind9 packages do not ship `nsec3hash`
    // (CI), and the hash itself is pinned against the RFC 5155 vectors in
    // `dnssec::wire::tests::nsec3_hashes_match_rfc5155_and_bind`; delv and
    // dnssec-verify above already validated the NSEC3 chain. So never
    // required, even with REQUIRE_BIND_TOOLS.
    if let Some(nsec3hash) = tool("nsec3hash") {
        let (ok, out) = run(&nsec3hash, &["-", "1", "0", "wushilin.test."]);
        let h = out.split_whitespace().next().unwrap_or("").to_lowercase();
        assert!(
            ok && axfr.to_lowercase().contains(&format!("{h}.wushilin.test.")),
            "{out}"
        );
    }
    // Without DO nothing changed but the serial.
    let after = no_do_answers(s.dns);
    for ((what, a), (_, b)) in before.iter().zip(&after) {
        assert!(
            a == b || without_serial(a) == without_serial(b),
            "{what}: answer without DO changed"
        );
    }
    // The self-check of the API understands NSEC3 zones too.
    let (_, chk) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/check"), None);
    assert_eq!(chk["ok"], true, "{chk:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// O25: a zone signed with an Ed25519 key (algorithm 15, RFC 8080)
/// validates with BIND: the DS equals `dnssec-dsfromkey`, the AXFR passes
/// `dnssec-verify`, every delv case (positive, wildcard, NXDOMAIN, NODATA,
/// CNAME, DNAME, DS, TCP) is fully validated, also after switching to
/// NSEC3, and a validating named when installed. The algorithm is chosen
/// for a new key only: asking for another one with the existing key is
/// refused (an algorithm rollover is not automated), unknown ones are 400.
#[test]
fn ed25519_zone_validates_with_independent_validators() {
    let dir = tmpdir("ed25519");
    let s = Server::new(dir.clone(), "");
    s.import(ZONE, &records());
    let put = |body: Value| s.api("PUT", &format!("/api/zones/{ZONE}/dnssec"), Some(body));
    let (st, r) = put(json!({ "enabled": true, "algorithm": 8 }));
    assert_eq!(st, 400, "unsupported algorithm: {r}");
    let (st, r) = put(json!({ "enabled": false, "algorithm": 15 }));
    assert_eq!(st, 400, "algorithm only with enabled: {r}");
    let before = no_do_answers(s.dns);
    let (st, on) = put(json!({ "enabled": true, "algorithm": 15 }));
    assert_eq!(st, 200, "{on}");
    assert_eq!(on["state"], "signing", "{on}");
    assert_eq!(on["key"]["algorithm"], 15);
    assert_eq!(on["key"]["algorithm_name"], "ED25519");
    let pk = on["key"]["public_key"].as_str().unwrap();
    assert_eq!(
        data_encoding::BASE64.decode(pk.as_bytes()).unwrap().len(),
        32,
        "RFC 8080: 32-byte public key"
    );
    let dnskey_text = on["key"]["dnskey"].as_str().unwrap().to_string();
    assert!(dnskey_text.contains(" 257 3 15 "), "{dnskey_text}");
    let ds2 = on["ds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["digest_type"] == 2)
        .unwrap()["record"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(ds2.contains(" DS ") && ds2.contains(" 15 2 "), "{ds2}");
    // Another algorithm for the existing key: refused, whatever the state.
    let (st, r) = put(json!({ "enabled": true, "algorithm": 13 }));
    assert_eq!(st, 409, "{r}");
    assert!(r.to_string().contains("algorithm rollover"), "{r}");
    // RRSIGs carry algorithm 15.
    let m = parse(&tcp(
        s.dns,
        &query_bytes("www.wushilin.test.", RecordType::A, Some(1232), true),
    ));
    let sig = m
        .answers
        .iter()
        .find(|r| r.record_type() == RecordType::RRSIG)
        .expect("RRSIG");
    let raw = hickory_proto::serialize::binary::BinEncodable::to_bytes(&sig.data).unwrap();
    assert_eq!(raw[2], 15, "RRSIG algorithm");
    // Without DO nothing changed but the serial.
    let after = no_do_answers(s.dns);
    for ((what, a), (_, b)) in before.iter().zip(&after) {
        assert!(
            a == b || without_serial(a) == without_serial(b),
            "{what}: answer without DO changed"
        );
    }
    let (_, chk) = s.api("GET", &format!("/api/zones/{ZONE}/dnssec/check"), None);
    assert_eq!(chk["ok"], true, "{chk:#}");

    let (Some(dig), Some(verify), Some(delv), Some(dsfromkey)) = (
        bind_tool("dig"),
        bind_tool("dnssec-verify"),
        bind_tool("delv"),
        bind_tool("dnssec-dsfromkey"),
    ) else {
        return;
    };
    let kf = dir.join("K15.key");
    std::fs::write(&kf, format!("{dnskey_text}\n")).unwrap();
    let (ok, out) = run(&dsfromkey, &["-2", kf.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert_eq!(out.trim(), ds2, "DS equals dnssec-dsfromkey -2");
    let anchor = anchor_file(&dir, &dnskey_text, "anchor15.conf");
    let mut failures = Vec::new();
    for denial in ["nsec", "nsec3"] {
        let (st, r) = put(json!({ "enabled": true, "denial": denial }));
        assert_eq!(st, 200, "{r}");
        assert_eq!(r["key"]["dnskey"].as_str().unwrap(), dnskey_text);
        let axfr = axfr_verified(
            &dig,
            &verify,
            &dir,
            s.dns,
            &format!("ed25519-{denial}.zone"),
        );
        assert!(
            axfr.lines()
                .filter(|l| l.split_whitespace().nth(3) == Some("RRSIG"))
                .all(|l| l.split_whitespace().nth(5) == Some("15")),
            "every RRSIG is algorithm 15"
        );
        failures.extend(
            run_delv(&delv, s.dns, &anchor)
                .into_iter()
                .map(|f| format!("{denial}: {f}")),
        );
    }
    // A validating named (NSEC3 now).
    if let Some(named) = tool("named") {
        failures.extend(run_named(&named, &dig, &dir, s.dns, &anchor));
    }
    assert!(
        failures.is_empty(),
        "Ed25519 zone, {} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "ed25519: dsfromkey, dnssec-verify (NSEC, NSEC3), {} delv cases x2 validated",
        delv_cases().len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
