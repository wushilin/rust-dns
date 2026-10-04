//! O29 end-to-end: DNS over TLS and DNS over HTTPS with real clients and
//! servers. Inbound: BIND's `dig +tls` and `+https` (POST and GET) against
//! rust-dns with the test CA's certificate; a client that does not trust
//! the CA gets nothing; the per-client rate limit (C2) applies to both.
//! Upstream: rust-dns forwards over DoT and DoH to BIND's `named`
//! (`tls` / `http` listeners) and refuses an upstream it does not trust.

mod common;

use common::free_port;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn tool(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/opt/homebrew/opt/bind/bin",
        "/opt/homebrew/opt/bind/sbin",
        "/usr/local/opt/bind/bin",
        "/usr/local/opt/bind/sbin",
        "/usr/bin",
        "/usr/sbin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(p) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&p));
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

fn fixture(f: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(f)
        .display()
        .to_string()
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Server {
    _child: Proc,
    dns: u16,
    web: String,
    dot: u16,
    doh: u16,
}

fn start(dir: &Path, extra: &str, encrypted: &str) -> Server {
    // A fresh database each time.
    let dir = &dir.join(format!("srv-{}", free_port()));
    std::fs::create_dir_all(dir).unwrap();
    for _ in 0..5 {
        let (dns, web_port, dot, doh) = (free_port(), free_port(), free_port(), free_port());
        let cfg = dir.join("t.toml");
        std::fs::write(
            &cfg,
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
bind = "127.0.0.1:{web_port}"
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "info"
file = "{log}"
{extra}
[encrypted_dns]
cert_file = "{cert}"
key_file = "{key}"
dot_listen = ["127.0.0.1:{dot}"]
doh_listen = ["127.0.0.1:{doh}"]
{encrypted}
"#,
                db = dir.join("t.db").display(),
                log = dir.join("server.log").display(),
                cert = fixture("server.pem"),
                key = fixture("server.key"),
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
            .arg("--config")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // O0c: the server exits when this test process is gone.
            .env("RUST_DNS_EXIT_WITH_STDIN", "1")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let web = format!("http://127.0.0.1:{web_port}");
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut up = false;
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            if ureq::get(&format!("{web}/api/health"))
                .timeout(Duration::from_millis(300))
                .call()
                .is_ok()
            {
                up = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if up && common::came_up(&mut child, dns) {
            // The DoT / DoH ports must be ours too.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline
                && !(std::net::TcpStream::connect(("127.0.0.1", dot)).is_ok()
                    && std::net::TcpStream::connect(("127.0.0.1", doh)).is_ok())
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            return Server {
                _child: Proc(child),
                dns,
                web,
                dot,
                doh,
            };
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("the server never came up");
}

fn admin(web: &str) -> (ureq::Agent, String) {
    let a = ureq::AgentBuilder::new().build();
    let r: Value = a
        .post(&format!("{web}/api/auth/login"))
        .set("X-Requested-With", "rust-dns")
        .send_json(json!({ "username": "root", "password": "rootpass123" }))
        .unwrap()
        .into_json()
        .unwrap();
    (a, r["csrf_token"].as_str().unwrap_or("").to_string())
}

fn post(s: &(ureq::Agent, String), web: &str, path: &str, body: Value) {
    let r =
        s.0.post(&format!("{web}/api{path}"))
            .set("X-Requested-With", "rust-dns")
            .set("X-CSRF-Token", &s.1)
            .send_json(body);
    assert!(r.is_ok(), "POST {path}: {r:?}");
}

fn dig(dig: &Path, args: &[&str]) -> String {
    let o = Command::new(dig).args(args).output().unwrap();
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
}

#[test]
fn dns_over_tls_and_https_inbound_and_upstream() {
    let Some(dig_bin) = tool("dig") else {
        assert!(
            std::env::var("REQUIRE_BIND_TOOLS").is_err(),
            "dig not found"
        );
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-encrypted-{}-{}",
        std::process::id(),
        free_port()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // ---- inbound ----
    let s = start(
        &dir,
        "[rate_limit]\nmax_resolutions_per_second_per_address = 0\n",
        "",
    );
    let a = admin(&s.web);
    post(&a, &s.web, "/zones", json!({ "name": "enc.test" }));
    post(
        &a,
        &s.web,
        "/zones/enc.test/records",
        json!({ "name": "www", "type": "A", "value": "192.0.2.80" }),
    );
    let ca = format!("+tls-ca={}", fixture("ca.pem"));
    let other_ca = format!("+tls-ca={}", fixture("other-ca.pem"));
    let (dot, doh) = (s.dot.to_string(), s.doh.to_string());
    let base = ["@127.0.0.1", "+tries=1", "+time=3"];
    let q = |extra: &[&str]| {
        let mut v: Vec<&str> = base.to_vec();
        v.extend_from_slice(extra);
        dig(&dig_bin, &v)
    };
    let over_tls = q(&[
        "-p",
        &dot,
        "+tls",
        &ca,
        "+tls-hostname=localhost",
        "www.enc.test",
        "A",
    ]);
    assert!(
        over_tls.contains("192.0.2.80") && over_tls.contains("status: NOERROR"),
        "DoT: {over_tls}"
    );
    assert!(
        over_tls.contains("(TLS)"),
        "the answer came over TLS: {over_tls}"
    );
    let post_ = q(&[
        "-p",
        &doh,
        "+https",
        &ca,
        "+tls-hostname=localhost",
        "www.enc.test",
        "A",
    ]);
    assert!(
        post_.contains("192.0.2.80") && post_.contains("(HTTPS)"),
        "DoH POST: {post_}"
    );
    let get = q(&[
        "-p",
        &doh,
        "+https-get",
        &ca,
        "+tls-hostname=localhost",
        "www.enc.test",
        "A",
    ]);
    assert!(
        get.contains("192.0.2.80") && get.contains("(HTTPS-GET)"),
        "DoH GET: {get}"
    );
    let nx = q(&[
        "-p",
        &doh,
        "+https",
        &ca,
        "+tls-hostname=localhost",
        "nope.enc.test",
        "A",
    ]);
    assert!(nx.contains("NXDOMAIN"), "{nx}");
    // A client that does not trust our certificate gets nothing.
    let untrusted = q(&[
        "-p",
        &dot,
        "+tls",
        &other_ca,
        "+tls-hostname=localhost",
        "www.enc.test",
        "A",
    ]);
    assert!(
        !untrusted.contains("192.0.2.80"),
        "untrusted CA: {untrusted}"
    );
    // Plain DNS keeps working; the counters see the encrypted traffic.
    let plain = q(&["-p", &s.dns.to_string(), "+short", "www.enc.test", "A"]);
    assert_eq!(plain.trim(), "192.0.2.80");
    let metrics =
        a.0.get(&format!("{}/metrics", s.web))
            .call()
            .unwrap()
            .into_string()
            .unwrap();
    let count = |m: &str| -> u64 {
        metrics
            .lines()
            .find(|l| l.starts_with(m))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    assert!(count("rustdns_dot_connections_total") >= 1, "{metrics}");
    assert!(count("rustdns_doh_requests_total") >= 3, "{metrics}");
    drop(s);

    // ---- admission (C2) applies: 3 queries a second per client ----
    let s = start(
        &dir,
        "[rate_limit]\nmax_resolutions_per_second_per_address = 3\nslip = 0\n",
        "",
    );
    let a = admin(&s.web);
    post(&a, &s.web, "/zones", json!({ "name": "enc.test" }));
    post(
        &a,
        &s.web,
        "/zones/enc.test/records",
        json!({ "name": "www", "type": "A", "value": "192.0.2.80" }),
    );
    std::thread::sleep(Duration::from_millis(1100));
    let (dot, doh) = (s.dot.to_string(), s.doh.to_string());
    let mut refused = 0;
    for i in 0..10 {
        let (p, mode) = if i % 2 == 0 {
            (&dot, "+tls")
        } else {
            (&doh, "+https")
        };
        let out = dig(
            &dig_bin,
            &[
                "@127.0.0.1",
                "+tries=1",
                "+time=2",
                "-p",
                p,
                mode,
                &ca,
                "+tls-hostname=localhost",
                "www.enc.test",
                "A",
            ],
        );
        if out.contains("status: REFUSED") {
            refused += 1;
        }
    }
    assert!(
        refused >= 3,
        "the per-client limit refuses DoT / DoH queries too: {refused} of 10"
    );
    drop(s);

    // ---- upstream: rust-dns forwards over DoT and DoH to named ----
    // The upstream part needs `named` (CI installs only BIND's utilities):
    // skipped without it unless REQUIRE_NAMED=1.
    let Some(named) = tool("named") else {
        assert!(std::env::var("REQUIRE_NAMED").is_err(), "named not found");
        eprintln!("encrypted: named not found; skipping the upstream part");
        return;
    };
    let wd = dir.join("bind");
    std::fs::create_dir_all(&wd).unwrap();
    std::fs::write(
        wd.join("up.test.db"),
        "$TTL 300\n@ IN SOA ns1.up.test. h.up.test. 1 3600 600 86400 300\n@ IN NS ns1.up.test.\nns1 IN A 127.0.0.1\nwww IN A 198.51.100.7\n",
    )
    .unwrap();
    let (pt, ph, pu) = (free_port(), free_port(), free_port());
    std::fs::write(
        wd.join("named.conf"),
        format!(
            r#"tls local {{ cert-file "{cert}"; key-file "{key}"; }};
http local {{ endpoints {{ "/dns-query"; }}; }};
options {{
  directory "{wd}";
  pid-file "{wd}/named.pid";
  listen-on port {pu} {{ 127.0.0.1; }};
  listen-on port {pt} tls local {{ 127.0.0.1; }};
  listen-on port {ph} tls local http local {{ 127.0.0.1; }};
  listen-on-v6 {{ none; }};
  recursion no;
  dnssec-validation no;
}};
controls {{ }};
zone "up.test" {{ type primary; file "up.test.db"; }};
"#,
            cert = fixture("server.pem"),
            key = fixture("server.key"),
            wd = wd.display(),
        ),
    )
    .unwrap();
    let _named = Proc(
        Command::new(&named)
            .args(["-g", "-c"])
            .arg(wd.join("named.conf"))
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(wd.join("named.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !dig(
        &dig_bin,
        &[
            "@127.0.0.1",
            "-p",
            &pu.to_string(),
            "+short",
            "www.up.test",
            "A",
        ],
    )
    .contains("198.51.100.7")
    {
        assert!(Instant::now() < deadline, "named did not start");
        std::thread::sleep(Duration::from_millis(200));
    }
    let fwd = "[forwarding]\nupstreams = []\nallowed_clients = [\"127.0.0.0/8\"]\n[rate_limit]\nmax_resolutions_per_second_per_address = 0\n";
    for (what, up, ca_file, want) in [
        (
            "DoT",
            format!("tls://127.0.0.1:{pt}#localhost"),
            fixture("ca.pem"),
            true,
        ),
        (
            "DoH",
            format!("https://127.0.0.1:{ph}/dns-query"),
            fixture("ca.pem"),
            true,
        ),
        (
            "DoT, untrusted CA",
            format!("tls://127.0.0.1:{pt}#localhost"),
            fixture("other-ca.pem"),
            false,
        ),
        (
            "DoH, untrusted CA",
            format!("https://127.0.0.1:{ph}/dns-query"),
            fixture("other-ca.pem"),
            false,
        ),
    ] {
        let s = start(
            &dir,
            fwd,
            &format!("upstreams = [\"{up}\"]\nupstream_ca_file = \"{ca_file}\"\n"),
        );
        let out = dig(
            &dig_bin,
            &[
                "@127.0.0.1",
                "-p",
                &s.dns.to_string(),
                "+tries=1",
                "+time=4",
                "www.up.test",
                "A",
            ],
        );
        if want {
            assert!(
                out.contains("198.51.100.7") && out.contains("status: NOERROR"),
                "{what}: {out}"
            );
        } else {
            assert!(
                !out.contains("198.51.100.7") && out.contains("SERVFAIL"),
                "{what}: {out}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
