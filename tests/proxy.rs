//! O14: the console and its live updates through a reverse proxy (nginx
//! with the websocket upgrade headers of the README). Starts the real
//! binary and an unprivileged nginx (own prefix, config and temp paths in
//! a temporary directory, high loopback ports) in front of it.
//!
//! Needs `nginx` on PATH (or `NGINX_BIN`); skipped without it, unless
//! `REQUIRE_NGINX_TEST=1` (CI installs nginx and sets it), which makes a
//! missing nginx a failure.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn nginx_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NGINX_BIN") {
        return Some(PathBuf::from(p));
    }
    let mut dirs: Vec<PathBuf> = [
        "/usr/sbin",
        "/usr/local/sbin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    dirs.into_iter()
        .map(|d| d.join("nginx"))
        .find(|p| p.is_file())
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn csrf_of(a: &ureq::Agent) -> String {
    a.cookie_store()
        .iter_unexpired()
        .find(|c| c.name() == "rdns_csrf" || c.name() == "__Host-rdns_csrf")
        .map(|c| c.value().to_string())
        .unwrap_or_default()
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
        Err(e) => panic!("{method} {url}: {e}"),
    }
}

/// The server, its web port free; started again on other ports when one
/// was taken (`common::came_up`).
fn start_server(dir: &Path) -> (Proc, u16) {
    for _ in 0..5 {
        let (dns, web) = (free_port(), free_port());
        std::fs::write(
            dir.join("rust-dns.toml"),
            format!(
                r#"
[server]
bind = ["127.0.0.1"]
port = {dns}
[database]
path = "{db}"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{web}"
proxy_trust = "127.0.0.1/32"
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "warn"
"#,
                db = dir.join("t.db").display()
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(dir.join("rust-dns.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            // O0c: the server exits when this test process is gone.
            .env("RUST_DNS_EXIT_WITH_STDIN", "1")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while ureq::get(&format!("http://127.0.0.1:{web}/rust-dns/api/health"))
            .timeout(Duration::from_millis(300))
            .call()
            .is_err()
        {
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        if common::came_up(&mut child, dns) {
            return (Proc(child), web);
        }
    }
    panic!("the server never came up");
}

/// nginx in front of `upstream`, listening on a free loopback port, with
/// the settings of `examples/proxy/nginx.conf` (without TLS; `Host` keeps
/// the port, which a proxy on 443 does not need).
fn start_nginx(bin: &Path, dir: &Path, upstream: u16) -> (Proc, u16) {
    for _ in 0..5 {
        let port = free_port();
        for t in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi", "logs"] {
            std::fs::create_dir_all(dir.join(t)).unwrap();
        }
        let d = dir.display();
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                r#"
worker_processes 1;
pid {d}/nginx.pid;
error_log {d}/logs/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/client_body;
    proxy_temp_path {d}/proxy;
    fastcgi_temp_path {d}/fastcgi;
    uwsgi_temp_path {d}/uwsgi;
    scgi_temp_path {d}/scgi;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        ''      close;
    }}
    server {{
        listen 127.0.0.1:{port};
        location / {{
            proxy_pass http://127.0.0.1:{upstream};
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 1h;
        }}
    }}
}}
"#
            ),
        )
        .unwrap();
        let mut child = Command::new(bin)
            .arg("-p")
            .arg(dir)
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg("daemon off;")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start nginx");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                break; // the port was taken (or nginx failed): try another
            }
            if ureq::get(&format!("http://127.0.0.1:{port}/rust-dns/api/health"))
                .timeout(Duration::from_millis(300))
                .call()
                .is_ok()
            {
                return (Proc(child), port);
            }
            assert!(Instant::now() < deadline, "nginx did not come up");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    panic!("nginx never came up");
}

/// Open a websocket through `port` (raw HTTP/1.1 upgrade); returns the
/// stream and the response head.
fn ws_open(port: u16, path: &str, extra_headers: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra_headers}\r\n"
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

/// Read text frames until one contains `needle`; None on close/timeout.
fn ws_wait_text(s: &mut TcpStream, needle: &str) -> Option<String> {
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
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).ok()?;
        match op {
            0x8 => return None,
            0x1 => {
                let t = String::from_utf8_lossy(&payload).to_string();
                if t.contains(needle) {
                    return Some(t);
                }
            }
            0x9 => {
                // Ping: answer with a masked pong (clients must mask).
                let mut f = vec![0x8a, 0x80 | payload.len() as u8, 0, 0, 0, 0];
                f.extend_from_slice(&payload);
                s.write_all(&f).ok()?;
            }
            _ => {}
        }
    }
}

#[test]
fn live_updates_through_nginx() {
    let Some(nginx) = nginx_bin() else {
        assert!(
            std::env::var("REQUIRE_NGINX_TEST").map_or(true, |v| v != "1"),
            "REQUIRE_NGINX_TEST=1 but nginx was not found (set NGINX_BIN)"
        );
        eprintln!("skipping: nginx not found (CI runs this with REQUIRE_NGINX_TEST=1)");
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rust-dns-proxy-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("srv")).unwrap();
    std::fs::create_dir_all(dir.join("nginx")).unwrap();
    let (_srv, web) = start_server(&dir.join("srv"));
    let (_nginx, port) = start_nginx(&nginx, &dir.join("nginx"), web);
    let base = format!("http://127.0.0.1:{port}");

    // The console page and the API, through the proxy.
    let page = ureq::get(&format!("{base}/"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(page.contains("<html"), "console page through nginx");
    let a = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    a.post(&format!("{base}/rust-dns/api/auth/login"))
        .send_json(serde_json::json!({ "username": "root", "password": "rootpass123" }))
        .unwrap();
    let (s, v) = call(
        &a,
        "POST",
        &format!("{base}/rust-dns/api/zones"),
        Some(serde_json::json!({ "name": "proxied.test" })),
    );
    assert_eq!(s, 201, "{v}");
    // The client address the server saw is nginx's forwarded one (trusted).
    let (s, me) = call(&a, "GET", &format!("{base}/rust-dns/api/me"), None);
    assert_eq!(s, 200, "{me}");

    // Websocket with the session cookie: Origin and Host as a browser on
    // the proxy's address sends them; nginx passes the upgrade through.
    let cookies: String = a
        .cookie_store()
        .iter_unexpired()
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect::<Vec<_>>()
        .join("; ");
    let (mut ws, head) = ws_open(
        port,
        "/rust-dns/api/ws",
        &format!("Origin: http://127.0.0.1:{port}\r\nCookie: {cookies}\r\n"),
    );
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "session websocket through nginx: {head}"
    );
    // A token client (subprotocol) through the proxy as well.
    let (s, t) = call(
        &a,
        "POST",
        &format!("{base}/rust-dns/api/tokens"),
        Some(serde_json::json!({ "name": "proxy" })),
    );
    assert_eq!(s, 201, "{t}");
    let token = t["token"].as_str().unwrap().to_string();
    let (mut ws2, head2) = ws_open(
        port,
        "/rust-dns/api/ws",
        &format!("Sec-WebSocket-Protocol: rust-dns, rust-dns.bearer.{token}\r\n"),
    );
    assert!(
        head2.starts_with("HTTP/1.1 101"),
        "token websocket through nginx: {head2}"
    );
    // A change made through the proxy reaches both live feeds.
    let (s, v) = call(
        &a,
        "POST",
        &format!("{base}/rust-dns/api/zones/proxied.test/records"),
        Some(
            serde_json::json!({ "name": "live-through-nginx", "type": "A", "value": "192.0.2.80" }),
        ),
    );
    assert_eq!(s, 201, "{v}");
    let ev = ws_wait_text(&mut ws, "live-through-nginx").expect("event on the session stream");
    assert!(ev.contains("proxied.test"), "{ev}");
    ws_wait_text(&mut ws2, "live-through-nginx").expect("event on the token stream");
    // A cross-site page cannot open it through the proxy either.
    let (_, head3) = ws_open(
        port,
        "/rust-dns/api/ws",
        &format!("Origin: http://evil.example\r\nCookie: {cookies}\r\n"),
    );
    assert!(
        !head3.starts_with("HTTP/1.1 101"),
        "cross-site upgrade refused: {head3}"
    );
    drop(ws);
    drop(ws2);
    let _ = std::fs::remove_dir_all(&dir);
}
