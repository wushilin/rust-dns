//! End-to-end: TSIG (RFC 8945) for zone transfers and NOTIFY. Starts the
//! real binary; acts as a TSIG-signing secondary with the server's own TSIG
//! module (included verbatim, independent of the server process).

#[path = "../src/dns/tsig.rs"]
#[allow(dead_code)]
mod tsig;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tsig::{Algorithm, Chain, Key, ResponseError, ResponseVerifier, SignParams};

const ZONE: &str = "example.test";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn rand_id() -> u16 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        & 0xffff) as u16
}

fn write_config(dir: &Path, dns: u16, web: u16, notify_port: u16, require_tsig: bool) {
    let cfg = format!(
        r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[transfer]
allow = ["127.0.0.0/8"]
require_tsig = {require_tsig}
notify_key = "hn-secondary."
notify = ["127.0.0.1:{notify_port}"]
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
level = "warn"
file = "{log}"
"#,
        db = dir.join("t.db").display(),
        log = dir.join("server.log").display(),
    );
    std::fs::write(dir.join("t.toml"), cfg).unwrap();
}

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Server {
    fn start(dir: PathBuf, web_port: u16) -> Server {
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
        Server { child, dir }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
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

fn b64(s: &str) -> Vec<u8> {
    data_encoding::BASE64.decode(s.as_bytes()).unwrap()
}

fn query_bytes(id: u16, zone: &str, qtype: RecordType) -> Vec<u8> {
    let mut m = Message::new();
    m.set_id(id).set_message_type(MessageType::Query);
    m.add_query(Query::query(
        Name::from_ascii(format!("{zone}.")).unwrap(),
        qtype,
    ));
    m.to_vec().unwrap()
}

/// Sign a request; returns the wire message and its MAC.
fn signed(msg: &[u8], key: &Key, time: u64) -> (Vec<u8>, Vec<u8>) {
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    tsig::sign(
        msg,
        key,
        Chain::Request,
        &SignParams {
            time,
            fudge: 300,
            original_id: id,
            error: 0,
            other: vec![],
        },
    )
}

/// Send over TCP; read messages until the transfer's closing SOA, an error
/// rcode, or the connection closes.
fn tcp_exchange(port: u16, req: &[u8]) -> Vec<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = (req.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(req);
    s.write_all(&out).unwrap();
    let mut msgs = Vec::new();
    let mut soas = 0;
    loop {
        let mut len = [0u8; 2];
        if s.read_exact(&mut len).is_err() {
            break;
        }
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).unwrap();
        let m = Message::from_bytes(&buf).unwrap();
        soas += m
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::SOA)
            .count();
        let done = m.response_code() != ResponseCode::NoError || soas >= 2;
        msgs.push(buf);
        if done {
            break;
        }
    }
    msgs
}

fn udp_exchange(port: u16, req: &[u8]) -> Vec<u8> {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.send_to(req, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 65535];
    let n = sock.recv(&mut buf).unwrap();
    buf[..n].to_vec()
}

fn rcode(m: &[u8]) -> ResponseCode {
    Message::from_bytes(m).unwrap().response_code()
}

fn tsig_of(m: &[u8]) -> tsig::TsigRecord {
    tsig::find(m).unwrap().expect("response carries TSIG").tsig
}

fn answer_count(msgs: &[Vec<u8>]) -> usize {
    msgs.iter()
        .map(|m| Message::from_bytes(m).unwrap().answers().len())
        .sum()
}

#[test]
fn tsig_keys_transfers_and_notify() {
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-tsig-{}-{}",
        std::process::id(),
        rand_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (dns, web_port) = (free_port(), free_port());
    let notify_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    notify_sock
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let notify_port = notify_sock.local_addr().unwrap().port();
    write_config(&dir, dns, web_port, notify_port, false);
    let srv = Server::start(dir.clone(), web_port);
    let web = format!("http://127.0.0.1:{web_port}");
    let root = login(&web, "root", "rootpass123");
    let keys = format!("{web}/api/tsig/keys");

    // ---- key lifecycle through the API ---------------------------------------
    let (s, created) = call(
        &root,
        "POST",
        &keys,
        Some(serde_json::json!({ "name": "HN-Secondary" })),
    );
    assert_eq!(s, 201, "{created}");
    assert_eq!(created["name"], "hn-secondary.");
    assert_eq!(created["algorithm"], "hmac-sha256", "default algorithm");
    assert_eq!(created["zones"], serde_json::json!([]));
    let secret_b64 = created["secret"].as_str().unwrap().to_string();
    let secret = b64(&secret_b64);
    assert_eq!(secret.len(), 32, "generated secret is as long as the hash");

    let imported = [0x5au8; 48];
    let imported_b64 = data_encoding::BASE64.encode(&imported);
    let (s, v) = call(
        &root,
        "POST",
        &keys,
        Some(
            serde_json::json!({ "name": "other-zone.", "algorithm": "hmac-sha384", "secret": imported_b64, "zones": ["other.test"] }),
        ),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["secret"], imported_b64.as_str(), "imported secret kept");
    assert_eq!(v["zones"], serde_json::json!(["other.test"]));

    // Duplicates, bad names, bad secrets and bad algorithms are refused.
    let (s, _) = call(
        &root,
        "POST",
        &keys,
        Some(serde_json::json!({ "name": "hn-secondary." })),
    );
    assert_eq!(s, 409);
    let (s, v) = call(
        &root,
        "POST",
        &keys,
        Some(serde_json::json!({ "name": "bad..name" })),
    );
    assert_eq!(s, 400, "{v}");
    let (s, v) = call(
        &root,
        "POST",
        &keys,
        Some(serde_json::json!({ "name": "short.", "secret": "c2VjcmV0" })),
    );
    assert_eq!(s, 400, "{v}");
    assert!(
        !v["error"].as_str().unwrap().contains("c2VjcmV0"),
        "input not echoed"
    );
    let (s, _) = call(
        &root,
        "POST",
        &keys,
        Some(serde_json::json!({ "name": "md5.", "algorithm": "hmac-md5" })),
    );
    assert_eq!(s, 400);

    // The list never carries secrets.
    let (s, list) = call(&root, "GET", &keys, None);
    assert_eq!(s, 200);
    let names: Vec<&str> = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["hn-secondary.", "other-zone."]);
    assert!(!list.to_string().contains(&secret_b64));
    assert!(list["keys"][0].get("secret").is_none());

    // Reveal (audited) returns the same secret; unknown keys are 404.
    let (s, v) = call(&root, "POST", &format!("{keys}/hn-secondary./reveal"), None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["secret"], secret_b64.as_str());
    let (s, _) = call(&root, "POST", &format!("{keys}/nobody./reveal"), None);
    assert_eq!(s, 404);

    // Scope change, audited.
    let (s, v) = call(
        &root,
        "PUT",
        &format!("{keys}/other-zone"),
        Some(serde_json::json!({ "zones": ["other.test", "More.Test."] })),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["zones"], serde_json::json!(["more.test", "other.test"]));

    // Non-admins get nothing.
    let (s, _) = call(
        &root,
        "POST",
        &format!("{web}/api/users"),
        Some(serde_json::json!({ "username": "bob", "password": "bobpass123" })),
    );
    assert_eq!(s, 201);
    let bob = login(&web, "bob", "bobpass123");
    assert_eq!(call(&bob, "GET", &keys, None).0, 403);
    assert_eq!(
        call(&bob, "POST", &format!("{keys}/hn-secondary./reveal"), None).0,
        403
    );
    assert_eq!(
        call(&bob, "GET", &format!("{web}/api/settings/transfer"), None).0,
        403
    );

    // Transfer policy view.
    let (s, pol) = call(&root, "GET", &format!("{web}/api/settings/transfer"), None);
    assert_eq!(s, 200, "{pol}");
    assert_eq!(pol["require_tsig"], false);
    assert_eq!(pol["notify_key"], "hn-secondary.");
    assert_eq!(pol["notify"][0]["key_exists"], true);
    assert_eq!(pol["port"], dns);

    // ---- a zone large enough for a multi-message AXFR ------------------------
    let (s, v) = call(
        &root,
        "POST",
        &format!("{web}/api/zones"),
        Some(serde_json::json!({ "name": ZONE })),
    );
    assert_eq!(s, 201, "{v}");
    let mut text = format!("$ORIGIN {ZONE}.\n$TTL 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n");
    for i in 0..1500 {
        text.push_str(&format!(
            "h{i} IN TXT \"padding record {i} so the transfer needs several messages\"\n"
        ));
    }
    let r = root
        .post(&format!("{web}/api/zones/{ZONE}/import-bind"))
        .set("X-Requested-With", "rust-dns")
        .set("content-type", "text/plain")
        .send_string(&text)
        .unwrap();
    assert_eq!(r.status(), 200);
    // The zone change also triggered a NOTIFY; drain it (checked below).
    let mut nbuf = [0u8; 4096];
    let first_notify = notify_sock
        .recv_from(&mut nbuf)
        .map(|(n, from)| (nbuf[..n].to_vec(), from));

    let key = Key {
        name: "hn-secondary.".into(),
        algorithm: Algorithm::HmacSha256,
        secret: secret.clone(),
    };
    let now = tsig::now();

    // ---- AXFR with a valid key: every message signed, MACs chained -----------
    let (req, mac) = signed(&query_bytes(0x1111, ZONE, RecordType::AXFR), &key, now);
    let msgs = tcp_exchange(dns, &req);
    assert!(
        msgs.len() >= 3,
        "multi-message transfer, got {}",
        msgs.len()
    );
    let mut v = ResponseVerifier::new(key.clone(), &mac);
    for (i, m) in msgs.iter().enumerate() {
        v.verify(m, tsig::now())
            .unwrap_or_else(|e| panic!("message {i}: {e}"));
    }
    assert_eq!(answer_count(&msgs), 1500 + 4, "SOA NS A TXT*1500 SOA");
    // Chained MACs: verifying message 2 as if it were the first fails.
    let mut v = ResponseVerifier::new(key.clone(), &mac);
    assert!(v.verify(&msgs[1], tsig::now()).is_err());

    // A signed SOA query over UDP gets a signed answer too (secondaries' refresh check).
    let (req, mac) = signed(&query_bytes(0x2222, ZONE, RecordType::SOA), &key, now);
    let resp = udp_exchange(dns, &req);
    assert_eq!(rcode(&resp), ResponseCode::NoError);
    ResponseVerifier::new(key.clone(), &mac)
        .verify(&resp, tsig::now())
        .unwrap();

    // ---- wrong secret: NOTAUTH + BADSIG, unsigned ------------------------------
    let wrong = Key {
        secret: vec![1; 32],
        ..key.clone()
    };
    let (req, mac) = signed(&query_bytes(0x3333, ZONE, RecordType::AXFR), &wrong, now);
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(msgs.len(), 1);
    assert_eq!(u16::from(rcode(&msgs[0])), 9, "NOTAUTH");
    let t = tsig_of(&msgs[0]);
    assert_eq!(t.error, tsig::BADSIG);
    assert!(t.mac.is_empty(), "BADSIG reply is unsigned");
    assert_eq!(
        ResponseVerifier::new(wrong.clone(), &mac).verify(&msgs[0], tsig::now()),
        Err(ResponseError::Peer(tsig::BADSIG))
    );
    assert_eq!(answer_count(&msgs), 0);

    // ---- unknown key: BADKEY, unsigned, key name echoed -------------------------
    let stranger = Key {
        name: "stranger.".into(),
        ..key.clone()
    };
    let (req, _) = signed(&query_bytes(0x4444, ZONE, RecordType::AXFR), &stranger, now);
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(u16::from(rcode(&msgs[0])), 9);
    let t = tsig_of(&msgs[0]);
    assert_eq!((t.error, t.key_name.as_str()), (tsig::BADKEY, "stranger."));
    assert!(t.mac.is_empty());

    // Right name, wrong algorithm: BADKEY as well.
    let other_alg = Key {
        algorithm: Algorithm::HmacSha512,
        ..key.clone()
    };
    let (req, _) = signed(&query_bytes(0x4545, ZONE, RecordType::SOA), &other_alg, now);
    let resp = udp_exchange(dns, &req);
    assert_eq!(tsig_of(&resp).error, tsig::BADKEY);

    // ---- clock skew beyond the fudge: BADTIME, signed, server time in Other ---
    let (req, mac) = signed(
        &query_bytes(0x5555, ZONE, RecordType::AXFR),
        &key,
        now - 1000,
    );
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(u16::from(rcode(&msgs[0])), 9);
    let t = tsig_of(&msgs[0]);
    assert_eq!(t.error, tsig::BADTIME);
    assert_eq!(t.time_signed, now - 1000, "echoes the request's time");
    assert_eq!(t.other.len(), 6);
    let server_time = u64::from_be_bytes([
        0, 0, t.other[0], t.other[1], t.other[2], t.other[3], t.other[4], t.other[5],
    ]);
    assert!(server_time.abs_diff(tsig::now()) < 5);
    // The BADTIME reply is signed with the key (verify the MAC directly).
    let s = tsig::find(&msgs[0]).unwrap().unwrap();
    tsig::verify(&msgs[0], &s, Some(&key), Chain::Response(&mac), now - 1000).unwrap();
    // Inside the fudge: fine.
    let (req, _) = signed(&query_bytes(0x5656, ZONE, RecordType::SOA), &key, now - 200);
    assert_eq!(rcode(&udp_exchange(dns, &req)), ResponseCode::NoError);

    // ---- a tampered request is never treated as unsigned ------------------------
    let (mut req, _) = signed(&query_bytes(0x5757, ZONE, RecordType::AXFR), &key, now);
    req[3] ^= 0x10; // flip a header bit covered by the MAC
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(tsig_of(&msgs[0]).error, tsig::BADSIG);
    assert_eq!(answer_count(&msgs), 0);

    // ---- a key scoped to other zones is refused (signed REFUSED) ---------------
    let scoped = Key {
        name: "other-zone.".into(),
        algorithm: Algorithm::HmacSha384,
        secret: imported.to_vec(),
    };
    let (req, mac) = signed(&query_bytes(0x6666, ZONE, RecordType::AXFR), &scoped, now);
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(rcode(&msgs[0]), ResponseCode::Refused);
    ResponseVerifier::new(scoped.clone(), &mac)
        .verify(&msgs[0], tsig::now())
        .unwrap();

    // ---- unsigned transfers still work while require_tsig is off -----------------
    let msgs = tcp_exchange(dns, &query_bytes(0x7777, ZONE, RecordType::AXFR));
    assert_eq!(answer_count(&msgs), 1504);
    assert!(
        tsig::find(&msgs[0]).unwrap().is_none(),
        "unsigned request, unsigned answer"
    );

    // ---- NOTIFY is signed with notify_key -----------------------------------------
    let check_notify = |m: &[u8]| {
        let s = tsig::find(m).unwrap().expect("NOTIFY is signed");
        tsig::verify(m, &s, Some(&key), Chain::Request, tsig::now()).unwrap();
        let parsed = Message::from_bytes(&tsig::strip(m, &s)).unwrap();
        assert_eq!(parsed.op_code(), OpCode::Notify);
        assert_eq!(parsed.queries()[0].name().to_ascii(), format!("{ZONE}."));
    };
    // Acknowledge with a signed response (as BIND does), so no retries follow.
    let ack = |m: &[u8], from: std::net::SocketAddr| {
        let s = tsig::find(m).unwrap().unwrap();
        let mut a = Message::from_bytes(&tsig::strip(m, &s)).unwrap();
        a.set_message_type(MessageType::Response);
        let (a, _) = tsig::sign(
            &a.to_vec().unwrap(),
            &key,
            Chain::Response(&s.tsig.mac),
            &SignParams {
                time: tsig::now(),
                fudge: 300,
                original_id: s.tsig.original_id,
                error: 0,
                other: vec![],
            },
        );
        notify_sock.send_to(&a, from).unwrap();
    };
    let (m, from) = first_notify.expect("NOTIFY after the import");
    check_notify(&m);
    ack(&m, from);
    // Acknowledge anything still pending, then change a record.
    notify_sock
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    while let Ok((n, from)) = notify_sock.recv_from(&mut nbuf) {
        let m = nbuf[..n].to_vec();
        check_notify(&m);
        ack(&m, from);
    }
    notify_sock
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let (s, _) = call(
        &root,
        "POST",
        &format!("{web}/api/zones/{ZONE}/records"),
        Some(serde_json::json!({ "name": "changed", "type": "A", "value": "192.0.2.99" })),
    );
    assert_eq!(s, 201);
    let (n, from) = notify_sock
        .recv_from(&mut nbuf)
        .expect("NOTIFY after a change");
    let m = nbuf[..n].to_vec();
    check_notify(&m);
    ack(&m, from);

    // ---- require_tsig on (config reload): unsigned refused, signed fine ------
    write_config(&dir, dns, web_port, notify_port, true);
    let (s, v) = call(&root, "POST", &format!("{web}/api/admin/reload"), None);
    assert_eq!(s, 200, "{v}");
    let msgs = tcp_exchange(dns, &query_bytes(0x8888, ZONE, RecordType::AXFR));
    assert_eq!(rcode(&msgs[0]), ResponseCode::Refused);
    assert_eq!(answer_count(&msgs), 0);
    let (req, mac) = signed(
        &query_bytes(0x9999, ZONE, RecordType::AXFR),
        &key,
        tsig::now(),
    );
    let msgs = tcp_exchange(dns, &req);
    let mut v = ResponseVerifier::new(key.clone(), &mac);
    for m in &msgs {
        v.verify(m, tsig::now()).unwrap();
    }
    assert_eq!(answer_count(&msgs), 1505, "includes the new record");
    let status = call(&root, "GET", &format!("{web}/api/status"), None).1;
    assert_eq!(status["transfer"]["require_tsig"], true);
    assert!(status["dns"]["tsig_errors"].as_u64().unwrap() >= 5);

    // ---- delete: the key stops working at once ------------------------------------
    let (s, v) = call(&root, "DELETE", &format!("{keys}/hn-secondary."), None);
    assert_eq!(s, 200, "{v}");
    let (req, _) = signed(
        &query_bytes(0xAAAA, ZONE, RecordType::AXFR),
        &key,
        tsig::now(),
    );
    let msgs = tcp_exchange(dns, &req);
    assert_eq!(tsig_of(&msgs[0]).error, tsig::BADKEY);
    let (s, _) = call(&root, "DELETE", &format!("{keys}/hn-secondary."), None);
    assert_eq!(s, 404);
    let pol = call(&root, "GET", &format!("{web}/api/settings/transfer"), None).1;
    assert_eq!(pol["notify"][0]["key_exists"], false);
    assert!(!pol["warnings"].as_array().unwrap().is_empty());

    // ---- audit rows: every step, never the secret ---------------------------------
    let audit = call(&root, "GET", &format!("{web}/api/audit?limit=500"), None).1;
    let entries = audit["entries"].as_array().unwrap();
    let actions: Vec<(&str, &str)> = entries
        .iter()
        .filter(|e| e["action"].as_str().unwrap().starts_with("tsig."))
        .map(|e| (e["action"].as_str().unwrap(), e["target"].as_str().unwrap()))
        .collect();
    assert_eq!(
        actions,
        [
            ("tsig.create", "hn-secondary."),
            ("tsig.create", "other-zone."),
            ("tsig.reveal", "hn-secondary."),
            ("tsig.update", "other-zone."),
            ("tsig.delete", "hn-secondary."),
        ]
    );
    let all = audit.to_string();
    assert!(
        !all.contains(&secret_b64) && !all.contains(&imported_b64),
        "secret in the audit log"
    );
    // ... nor in the server log.
    let log = srv.log();
    assert!(log.contains("rejected TSIG-signed request"), "{log}");
    assert!(
        !log.contains(&secret_b64) && !log.contains(&imported_b64),
        "secret in the log"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
