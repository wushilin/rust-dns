//! End-to-end regression tests for the security review fixes. Each test
//! starts the real binary on free ports with a throwaway configuration.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rust-dns-hardening-{tag}-{}-{}",
        std::process::id(),
        free_port()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Server {
    child: Child,
    dns: u16,
    web: String,
    dir: PathBuf,
}

impl Server {
    /// `server_extra` goes into `[server]`, `web_extra` into
    /// `[web_console]`, `tail` after everything (whole sections).
    fn start(tag: &str, server_extra: &str, web_extra: &str, tail: &str) -> Server {
        let dir = tempdir(tag);
        let dns = free_port();
        let web_port = free_port();
        let cfg = format!(
            r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
{server_extra}
[forwarding]
upstreams = []
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{db}"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{web_port}"
login_attempts_per_minute = 1000
{web_extra}
[root]
username = "root"
password = "rootpass123"
[logging]
level = "warn"
{tail}
"#,
            db = dir.join("t.db").display()
        );
        std::fs::write(dir.join("t.toml"), cfg).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(dir.join("t.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let web = format!("http://127.0.0.1:{web_port}");
        let deadline = Instant::now() + Duration::from_secs(20);
        while ureq::get(&format!("{web}/api/health"))
            .timeout(Duration::from_millis(300))
            .call()
            .is_err()
        {
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        Server {
            child,
            dns,
            web,
            dir,
        }
    }
}

impl Server {
    /// Stop the process and start it again on the same config and database.
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(self.dir.join("t.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while ureq::get(&format!("{}/api/health", self.web))
            .timeout(Duration::from_millis(300))
            .call()
            .is_err()
        {
            assert!(Instant::now() < deadline, "server did not restart");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
}

fn login(web: &str, user: &str, pw: &str) -> ureq::Agent {
    let a = agent();
    a.post(&format!("{web}/api/auth/login"))
        .send_json(serde_json::json!({ "username": user, "password": pw }))
        .expect("login");
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
        Err(e) => panic!("{method} {url}: {e}"),
    }
}

fn query_wire(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    m[..2].copy_from_slice(&id.to_be_bytes());
    m[5] = 1;
    for l in name.trim_end_matches('.').split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

/// One query over an existing TCP stream; `None` when the server closed it.
fn tcp_ask(s: &mut TcpStream, name: &str, qtype: u16) -> Option<Vec<u8>> {
    s.write_all(&framed(&query_wire(7, name, qtype))).ok()?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn tcp_query(port: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp_ask(&mut s, name, qtype)
}

/// A zone with a ~5 KB TXT RRset so pipelined answers fill socket buffers fast.
fn big_zone(web: &str) {
    let a = login(web, "root", "rootpass123");
    let records: Vec<serde_json::Value> = (0..20)
        .map(|i| serde_json::json!({ "name": "big", "type": "TXT", "value": format!("{i:03}").repeat(80) }))
        .collect();
    let (s, v) = call(
        &a,
        "POST",
        &format!("{web}/api/import"),
        Some(
            serde_json::json!({ "version": 1, "exported_at": "", "zones": [{ "name": "pin.test", "records": records }] }),
        ),
    );
    assert_eq!(s, 200, "{v}");
}

/// H3 regression: clients that pipeline queries and never read used to
/// block the server in `write_all` forever, holding every TCP slot.
#[test]
fn tcp_clients_that_never_read_cannot_pin_all_slots() {
    let srv = Server::start(
        "tcp-pin",
        "max_tcp_connections = 4\ntcp_write_timeout_secs = 1\nmax_tcp_connections_per_client = 0",
        "",
        "",
    );
    big_zone(&srv.web);
    assert!(tcp_query(srv.dns, "big.pin.test", 16).is_some());
    let mut attackers = Vec::new();
    for _ in 0..4 {
        let s = TcpStream::connect(("127.0.0.1", srv.dns)).unwrap();
        let mut w = s.try_clone().unwrap();
        std::thread::spawn(move || {
            let q = framed(&query_wire(1, "big.pin.test", 16));
            for _ in 0..20_000 {
                if w.write_all(&q).is_err() {
                    return;
                }
            }
        });
        attackers.push(s); // held open, never read
    }
    // The server fills the attackers' buffers, then gives up on each within
    // one write timeout and frees the slots.
    std::thread::sleep(Duration::from_secs(4));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut answered = false;
    while Instant::now() < deadline {
        if tcp_query(srv.dns, "big.pin.test", 16).is_some() {
            answered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        answered,
        "a fresh TCP client is served while the pinning clients are still connected"
    );
    drop(attackers);
}

/// H3: per-client connection cap and per-connection query cap.
#[test]
fn tcp_per_client_and_per_connection_limits() {
    let srv = Server::start(
        "tcp-limits",
        "max_tcp_connections_per_client = 2\ntcp_max_queries_per_connection = 3",
        "",
        "",
    );
    let hold1 = TcpStream::connect(("127.0.0.1", srv.dns)).unwrap();
    let hold2 = TcpStream::connect(("127.0.0.1", srv.dns)).unwrap();
    // Let the server register both before the third arrives.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        tcp_query(srv.dns, "version.bind", 16).is_none(),
        "third connection from the same client is closed"
    );
    drop(hold1);
    drop(hold2);
    std::thread::sleep(Duration::from_millis(300));
    let mut s = TcpStream::connect(("127.0.0.1", srv.dns)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for i in 0..3 {
        assert!(tcp_ask(&mut s, "x.test", 1).is_some(), "query {i} answered");
    }
    assert!(
        tcp_ask(&mut s, "x.test", 1).is_none(),
        "connection closed after tcp_max_queries_per_connection"
    );
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rust-dns"))
}

/// A2 regression: `--init-config` writes a 0600 config with a random,
/// already hashed root password and prints it once on stdout; the sample
/// placeholder is refused by `--check` and at startup.
#[test]
fn init_config_and_placeholder_refusal() {
    let dir = tempdir("init");
    let cfg = dir.join("rust-dns.toml");
    let out = bin().arg("--init-config").arg(&cfg).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pw = stdout
        .lines()
        .find_map(|l| l.strip_prefix("root password: "))
        .expect("password printed")
        .to_string();
    assert!(stdout.contains("root username: root"), "{stdout}");
    let text = std::fs::read_to_string(&cfg).unwrap();
    assert!(!text.contains(&pw), "only the hash is stored");
    assert!(text.contains("$argon2"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let check = bin()
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");
    // Refuses to overwrite.
    let again = bin().arg("--init-config").arg(&cfg).output().unwrap();
    assert!(!again.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), text);

    // The sample's placeholder is refused, by --check and by a real start.
    let sample = bin().arg("--print-sample-config").output().unwrap();
    let sample_text = String::from_utf8_lossy(&sample.stdout).to_string();
    assert!(sample_text.contains("\"change-me\""));
    assert!(sample_text.contains("must") || sample_text.contains("refuses"));
    let sample_cfg = dir.join("sample.toml");
    std::fs::write(&sample_cfg, &sample_text).unwrap();
    let check = bin()
        .arg("--check")
        .arg("--config")
        .arg(&sample_cfg)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(
        String::from_utf8_lossy(&check.stderr).contains("placeholder"),
        "{check:?}"
    );
    let start = bin()
        .arg("--config")
        .arg(&sample_cfg)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!start.status.success(), "startup refuses the placeholder");
    assert!(String::from_utf8_lossy(&start.stderr).contains("placeholder"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// L6 regression: a generated root password used to be logged through
/// tracing (so it ended up in log files). It is now printed on stderr only.
#[test]
fn generated_root_password_is_not_logged() {
    let dir = tempdir("genpw");
    let cfg = dir.join("missing.toml");
    let mut child = bin()
        .arg("--config")
        .arg(&cfg)
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait for the credentials on stderr, then stop the process.
    let mut stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut all = String::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            all.push_str(&String::from_utf8_lossy(&buf[..n]));
            if all.contains("Root login") && all.contains("shown once") {
                break;
            }
        }
        let _ = tx.send(all);
    });
    let err_text = rx.recv_timeout(Duration::from_secs(20)).unwrap_or_default();
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let log_text = String::from_utf8_lossy(&out.stdout);
    let pw = err_text
        .split("Root login: root  /  ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .expect("credentials on stderr")
        .to_string();
    assert!(pw.len() >= 20);
    assert!(
        !log_text.contains(&pw),
        "the password must not reach the log: {log_text}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "generated config is owner-only");
        let db = dir.join("rust-dns.db");
        if db.exists() {
            let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "database is owner-only");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// TOTP (RFC 6238, SHA-1, 30 s, 6 digits) for an explicit time step.
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

/// Owner test 2 (restart): the last accepted TOTP step is stored in the
/// database, so a code used before a restart is still refused after it,
/// while the next step's code works.
#[test]
fn totp_replay_rejected_after_restart() {
    let mut srv = Server::start("totp-restart", "", "request_header_timeout_secs = 300", "");
    let web = srv.web.clone();
    // Fix "now" for the test: stay well inside one 30 s window.
    let secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    if secs() % 30 > 18 {
        std::thread::sleep(Duration::from_secs(30 - secs() % 30 + 1));
    }
    let step = secs() / 30;

    let root = login(&web, "root", "rootpass123");
    let (s, e) = call(
        &root,
        "POST",
        &format!("{web}/api/me/mfa/start"),
        Some(serde_json::json!({})),
    );
    assert_eq!(s, 200, "{e}");
    let secret = e["secret"].as_str().unwrap().to_string();
    let (s, v) = call(
        &root,
        "POST",
        &format!("{web}/api/me/mfa/confirm"),
        Some(serde_json::json!({ "code": totp_at(&secret, step - 1) })),
    );
    assert_eq!(s, 200, "{v}");

    let x = totp_at(&secret, step);
    let a = agent();
    let (s, v) = call(
        &a,
        "POST",
        &format!("{web}/api/auth/login"),
        Some(serde_json::json!({ "username": "root", "password": "rootpass123" })),
    );
    assert_eq!((s, v["status"].as_str()), (200, Some("mfa_required")));
    let (s, v) = call(
        &a,
        "POST",
        &format!("{web}/api/auth/mfa"),
        Some(serde_json::json!({ "code": x })),
    );
    assert_eq!(s, 200, "{v}");

    srv.restart();

    let b = agent();
    let (s, v) = call(
        &b,
        "POST",
        &format!("{web}/api/auth/login"),
        Some(serde_json::json!({ "username": "root", "password": "rootpass123" })),
    );
    assert_eq!(
        (s, v["status"].as_str()),
        (200, Some("mfa_required")),
        "{v}"
    );
    let (s, v) = call(
        &b,
        "POST",
        &format!("{web}/api/auth/mfa"),
        Some(serde_json::json!({ "code": x })),
    );
    assert_eq!(s, 401, "the code used before the restart is refused: {v}");
    let (s, v) = call(
        &b,
        "POST",
        &format!("{web}/api/auth/mfa"),
        Some(serde_json::json!({ "code": totp_at(&secret, step + 1) })),
    );
    assert_eq!(s, 200, "the next step's code works: {v}");
    let (s, _) = call(&b, "GET", &format!("{web}/api/me"), None);
    assert_eq!(s, 200);
}

/// Open a websocket with raw HTTP; returns the stream (after the headers)
/// and the response head.
fn ws_open(web: &str, path: &str, extra_headers: &str) -> (TcpStream, String) {
    let host = web.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).unwrap();
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

/// Read server frames until a close frame; returns its code, or None when
/// the connection ended without one (or timed out).
fn ws_wait_close(s: &mut TcpStream) -> Option<u16> {
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

/// Sign in and return the session cookie as a `name=value` pair.
fn login_cookie(web: &str, user: &str, pw: &str) -> String {
    agent()
        .post(&format!("{web}/api/auth/login"))
        .send_json(serde_json::json!({ "username": user, "password": pw }))
        .unwrap()
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// M4 + L5 regression: a websocket opened with an API token (sent as a
/// subprotocol, not in the URL) kept streaming after the token was revoked.
#[test]
fn websocket_closes_when_its_token_is_revoked() {
    let srv = Server::start("ws-revoke", "", "", "");
    let web = srv.web.clone();
    let root = login(&web, "root", "rootpass123");
    let (s, t) = call(
        &root,
        "POST",
        &format!("{web}/api/tokens"),
        Some(serde_json::json!({ "name": "ws" })),
    );
    assert_eq!(s, 201, "{t}");
    let token = t["token"].as_str().unwrap().to_string();
    let id = t["info"]["id"].as_i64().unwrap();
    let (mut ws, head) = ws_open(
        &web,
        "/api/ws?after=0",
        &format!("Sec-WebSocket-Protocol: rust-dns, rust-dns.bearer.{token}\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-protocol: rust-dns\r\n"),
        "the server selects the plain protocol, never echoes the token: {head}"
    );
    let (s, _) = call(&root, "DELETE", &format!("{web}/api/tokens/{id}"), None);
    assert_eq!(s, 200);
    let started = Instant::now();
    assert_eq!(
        ws_wait_close(&mut ws),
        Some(1008),
        "closed with policy violation"
    );
    assert!(started.elapsed() < Duration::from_secs(15));
}

/// M4 regression: a cookie websocket kept streaming after the account was
/// disabled. L4 regression: a cookie upgrade from another site's page.
#[test]
fn websocket_origin_and_disabled_account() {
    let srv = Server::start("ws-origin", "", "", "");
    let web = srv.web.clone();
    let root = login(&web, "root", "rootpass123");
    let (s, u) = call(
        &root,
        "POST",
        &format!("{web}/api/users"),
        Some(serde_json::json!({ "username": "wendy", "password": "wendypass1" })),
    );
    assert_eq!(s, 201, "{u}");
    let cookie = login_cookie(&web, "wendy", "wendypass1");
    let host = web.trim_start_matches("http://");
    let (_, head) = ws_open(
        &web,
        "/api/ws",
        &format!("Cookie: {cookie}\r\nOrigin: http://evil.example\r\n"),
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "cross-site upgrade refused: {head}"
    );
    let (mut ws, head) = ws_open(
        &web,
        "/api/ws",
        &format!("Cookie: {cookie}\r\nOrigin: http://{host}\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let (s, _) = call(
        &root,
        "PUT",
        &format!("{web}/api/users/{}", u["id"]),
        Some(serde_json::json!({ "disabled": true })),
    );
    assert_eq!(s, 200);
    assert_eq!(ws_wait_close(&mut ws), Some(1008));
}

/// L2: the session cookie is `__Host-` prefixed and Secure when a trusted
/// proxy reports HTTPS; plain HTTP (or an untrusted header) keeps the
/// plain cookie so LAN use over HTTP still works.
#[test]
fn secure_cookie_over_https_via_trusted_proxy() {
    let srv = Server::start("cookie", "", "proxy_trust = \"127.0.0.1/32\"", "");
    let web = srv.web.clone();
    let set_cookie = |proto: Option<&str>| {
        let mut r = agent().post(&format!("{web}/api/auth/login"));
        if let Some(p) = proto {
            r = r.set("X-Forwarded-Proto", p);
        }
        r.send_json(serde_json::json!({ "username": "root", "password": "rootpass123" }))
            .unwrap()
            .header("set-cookie")
            .unwrap()
            .to_string()
    };
    let https = set_cookie(Some("https"));
    assert!(https.starts_with("__Host-rdns_session="), "{https}");
    assert!(https.contains("; Secure") && https.contains("Path=/") && !https.contains("Domain"));
    let http = set_cookie(None);
    assert!(
        http.starts_with("rdns_session=") && !http.contains("Secure"),
        "{http}"
    );
    drop(srv);
    // The header from an untrusted peer is ignored.
    let srv = Server::start("cookie2", "", "", "");
    let r = agent()
        .post(&format!("{}/api/auth/login", srv.web))
        .set("X-Forwarded-Proto", "https")
        .send_json(serde_json::json!({ "username": "root", "password": "rootpass123" }))
        .unwrap();
    assert!(r.header("set-cookie").unwrap().starts_with("rdns_session="));
}

/// L1 regression: hyper ran without a timer, so a client that never
/// finished its request headers held the connection forever; there was no
/// connection cap either.
#[test]
fn slow_web_clients_are_cut_off_and_connections_capped() {
    let srv = Server::start(
        "slowloris",
        "",
        "request_header_timeout_secs = 2\nmax_connections = 4",
        "",
    );
    let host = srv.web.trim_start_matches("http://").to_string();
    let mut slow = TcpStream::connect(&host).unwrap();
    slow.write_all(b"GET /api/health HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 256];
    let n = slow.read(&mut buf).unwrap_or(0);
    let _ = n;
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "an incomplete request is dropped after the header timeout"
    );
    // Cap: 4 idle connections held open, a fifth is refused at once.
    let held: Vec<TcpStream> = (0..4).map(|_| TcpStream::connect(&host).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(300));
    let r = ureq::get(&format!("{}/api/health", srv.web))
        .timeout(Duration::from_secs(1))
        .call();
    assert!(r.is_err(), "over the connection cap");
    drop(held);
    std::thread::sleep(Duration::from_millis(300));
    assert!(ureq::get(&format!("{}/api/health", srv.web)).call().is_ok());
}

/// L3: the console and the API explorer carry a real Content-Security-Policy
/// (no inline script without a hash), plus the other security headers.
#[test]
fn pages_carry_a_strict_content_security_policy() {
    let srv = Server::start("csp", "", "", "");
    for path in ["/", "/docs"] {
        let r = ureq::get(&format!("{}{path}", srv.web)).call().unwrap();
        let csp = r.header("content-security-policy").unwrap().to_string();
        for d in [
            "default-src 'self'",
            "script-src 'self' 'sha256-",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'self'",
            "connect-src 'self'",
            "img-src 'self' data:",
        ] {
            assert!(csp.contains(d), "{path}: missing {d} in {csp}");
        }
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"), "{csp}");
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        assert!(r.header("permissions-policy").is_some());
        assert_eq!(r.header("referrer-policy"), Some("same-origin"));
        assert!(
            r.header("strict-transport-security").is_none(),
            "plain HTTP: no HSTS"
        );
    }
}
