//! O27 end-to-end: rust-dns as a secondary of a real BIND primary
//! (`named`): AXFR, IXFR after dynamic updates, NOTIFY signed with TSIG,
//! TSIG on every transfer (a wrong secret is refused), pre-signed zones
//! (NSEC and NSEC3) served with the primary's signatures and validated by
//! `delv`, read-only records, the local copy surviving a restart, and
//! expiry (SERVFAIL) when the primary is gone.
//!
//! `named`, `dnssec-keygen`, `dnssec-signzone`, `nsupdate`, `dig` and
//! `delv` come from BIND; with `REQUIRE_BIND_TOOLS=1` they must exist
//! (`named` too: unlike CI's utilities-only install, this suite cannot run
//! without a primary).

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

fn tools() -> Option<[PathBuf; 6]> {
    let names = [
        "named",
        "dnssec-keygen",
        "dnssec-signzone",
        "nsupdate",
        "dig",
        "delv",
    ];
    let found: Vec<Option<PathBuf>> = names.iter().map(|n| tool(n)).collect();
    if found.iter().any(|t| t.is_none()) {
        assert!(
            std::env::var("REQUIRE_BIND_TOOLS").is_err(),
            "BIND tools missing: {:?}",
            names
                .iter()
                .zip(&found)
                .filter(|(_, t)| t.is_none())
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
        );
        eprintln!("secondary: BIND tools missing; skipping");
        return None;
    }
    let v: Vec<PathBuf> = found.into_iter().map(Option::unwrap).collect();
    Some(v.try_into().unwrap())
}

fn run(cmd: &Path, args: &[&str], dir: &Path) -> String {
    let o = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{} {args:?}: {text}", cmd.display());
    text
}

fn out(cmd: &Path, args: &[&str]) -> String {
    let o = Command::new(cmd).args(args).output().unwrap();
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
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
}

fn start_server(dir: &Path) -> Server {
    for _ in 0..5 {
        let dns = free_port();
        let web_port = free_port();
        let cfg = dir.join("t.toml");
        std::fs::write(
            &cfg,
            format!(
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
bind = "127.0.0.1:{web_port}"
login_attempts_per_minute = 1000
[root]
username = "root"
password = "rootpass123"
[logging]
level = "info"
file = "{log}"
"#,
                db = dir.join("t.db").display(),
                log = dir.join("server.log").display(),
            ),
        )
        .unwrap();
        if let Some(s) = spawn(cfg, dns, web_port) {
            return s;
        }
    }
    panic!("the server never came up");
}

fn spawn(cfg: PathBuf, dns: u16, web_port: u16) -> Option<Server> {
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
    while ureq::get(&format!("{web}/api/health"))
        .timeout(Duration::from_millis(300))
        .call()
        .is_err()
    {
        if matches!(child.try_wait(), Ok(Some(_))) || Instant::now() > deadline {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !common::came_up(&mut child, dns) {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    Some(Server {
        _child: Proc(child),
        dns,
        web,
    })
}

fn login(web: &str) -> (ureq::Agent, String) {
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

fn call(
    s: &(ureq::Agent, String),
    web: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let req =
        s.0.request(method, &format!("{web}/api{path}"))
            .set("X-Requested-With", "rust-dns")
            .set("X-CSRF-Token", &s.1);
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

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `dig +short` (or the status line with `full`).
fn dig(dig: &Path, port: u16, args: &[&str]) -> String {
    let p = port.to_string();
    let mut a = vec!["@127.0.0.1", "-p", &p, "+tries=1", "+time=2"];
    a.extend_from_slice(args);
    out(dig, &a)
}

fn zone_file(zone: &str, serial: u32, timers: &str, extra: &str) -> String {
    format!(
        "$TTL 300\n@ IN SOA ns1.{zone}. hostmaster.{zone}. {serial} {timers}\n@ IN NS ns1.{zone}.\nns1 IN A 127.0.0.1\nwww IN A 192.0.2.80\nwww IN TXT \"hello from bind\"\n*.wild IN A 192.0.2.81\na.b.deep IN A 192.0.2.82\nmail IN MX 10 www.{zone}.\n{extra}"
    )
}

#[test]
fn secondary_zones_from_a_bind_primary() {
    let Some([named, keygen, signzone, nsupdate, dig_bin, delv]) = tools() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-secondary-{}-{}",
        std::process::id(),
        free_port()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let wd = dir.join("bind");
    std::fs::create_dir_all(&wd).unwrap();

    // rust-dns first (named NOTIFYs it).
    let srv = start_server(&dir);
    let rp = srv.dns;
    let web = srv.web.clone();
    let root = login(&web);

    // The primary: four zones. sec.test takes dynamic updates (IXFR from
    // its journal); signed.test (NSEC) and nsec3.test (NSEC3, no salt) are
    // pre-signed with one CSK each; exp.test has a 4 s expire.
    let secret = data_encoding::BASE64.encode(&rand_bytes());
    for z in ["signed.test", "nsec3.test"] {
        std::fs::write(
            wd.join(format!("{z}.db")),
            zone_file(z, 1, "3600 600 86400 300", ""),
        )
        .unwrap();
        run(
            &keygen,
            &["-K", ".", "-a", "ECDSAP256SHA256", "-f", "KSK", z],
            &wd,
        );
        let mut args = vec!["-K", ".", "-S", "-z", "-o", z, "-f"];
        let outf = format!("{z}.signed");
        args.push(&outf);
        if z == "nsec3.test" {
            args.extend(["-3", "-"]);
        }
        let inf = format!("{z}.db");
        args.push(&inf);
        run(&signzone, &args, &wd);
    }
    std::fs::write(
        wd.join("sec.test.db"),
        zone_file("sec.test", 1, "3600 600 86400 300", ""),
    )
    .unwrap();
    std::fs::write(
        wd.join("exp.test.db"),
        zone_file("exp.test", 1, "1 1 4 300", ""),
    )
    .unwrap();
    let named_port = free_port();
    let conf = format!(
        r#"key "xfr." {{ algorithm hmac-sha256; secret "{secret}"; }};
options {{
  directory "{wd}";
  pid-file "{wd}/named.pid";
  listen-on port {named_port} {{ 127.0.0.1; }};
  listen-on-v6 {{ none; }};
  recursion no;
  dnssec-validation no;
  notify explicit;
  also-notify {{ 127.0.0.1 port {rp} key "xfr."; }};
  allow-transfer {{ key "xfr."; }};
  allow-query {{ any; }};
}};
controls {{ }};
zone "sec.test" {{ type primary; file "sec.test.db"; allow-update {{ key "xfr."; }}; }};
zone "signed.test" {{ type primary; file "signed.test.signed"; }};
zone "nsec3.test" {{ type primary; file "nsec3.test.signed"; }};
zone "exp.test" {{ type primary; file "exp.test.db"; }};
"#,
        wd = wd.display(),
    );
    std::fs::write(wd.join("named.conf"), conf).unwrap();
    let start_named = || {
        Proc(
            Command::new(&named)
                .args(["-g", "-c"])
                .arg(wd.join("named.conf"))
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(wd.join("named.log")).unwrap())
                .spawn()
                .unwrap(),
        )
    };
    let mut bind = Some(start_named());
    wait_for("named answers", 20, || {
        dig(&dig_bin, named_port, &["+short", "sec.test", "SOA"]).contains("hostmaster")
    });

    // The TSIG key, as BIND knows it, and the secondary zones.
    let (st, v) = call(
        &root,
        &web,
        "POST",
        "/tsig/keys",
        Some(json!({ "name": "xfr.", "algorithm": "hmac-sha256", "secret": secret })),
    );
    assert!(st == 200 || st == 201, "{v}");
    let primary = format!("127.0.0.1:{named_port}");
    for z in ["sec.test", "signed.test", "nsec3.test", "exp.test"] {
        let (st, v) = call(
            &root,
            &web,
            "POST",
            "/zones",
            Some(json!({ "name": z, "secondary": { "primaries": [primary], "key": "xfr." } })),
        );
        assert_eq!(st, 201, "{z}: {v}");
        assert_eq!(v["secondary"]["primaries"][0], primary, "{v}");
    }
    // A wrong secret: refused by BIND (BADSIG), nothing served.
    let (st, v) = call(
        &root,
        &web,
        "POST",
        "/tsig/keys",
        Some(
            json!({ "name": "wrong.", "algorithm": "hmac-sha256", "secret": data_encoding::BASE64.encode(&rand_bytes()) }),
        ),
    );
    assert!(st == 200 || st == 201, "{v}");
    let status = |z: &str| call(&root, &web, "GET", &format!("/zones/{z}/secondary"), None).1;
    for z in ["sec.test", "signed.test", "nsec3.test", "exp.test"] {
        wait_for(&format!("{z} transferred"), 30, || {
            status(z)["state"] == "ok"
        });
    }
    let st = status("sec.test");
    assert_eq!(st["serial"], 1, "{st}");
    assert_eq!(st["last_transfer"], "axfr", "{st}");
    assert_eq!(st["signed"], false, "{st}");
    assert_eq!(status("signed.test")["signed"], true);

    // Answers equal BIND's, with AA.
    for (name, t) in [
        ("www.sec.test", "A"),
        ("www.sec.test", "TXT"),
        ("x.wild.sec.test", "A"),
        ("mail.sec.test", "MX"),
        ("sec.test", "NS"),
    ] {
        let a = dig(&dig_bin, rp, &["+short", name, t]);
        let b = dig(&dig_bin, named_port, &["+short", name, t]);
        assert!(
            !a.trim().is_empty() && a == b,
            "{name} {t}: ours {a:?}, BIND {b:?}"
        );
    }
    let full = dig(&dig_bin, rp, &["www.sec.test", "A"]);
    assert!(full.contains("flags: qr aa"), "{full}");
    let nx = dig(&dig_bin, rp, &["nope.sec.test", "A"]);
    assert!(nx.contains("NXDOMAIN") && nx.contains("SOA"), "{nx}");

    // Read-only: no record or signing change here.
    let (st, v) = call(
        &root,
        &web,
        "POST",
        "/zones/sec.test/records",
        Some(json!({ "name": "x", "type": "A", "value": "192.0.2.1" })),
    );
    assert_eq!(st, 409, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("secondary zone"),
        "{v}"
    );
    let (st, v) = call(
        &root,
        &web,
        "PUT",
        "/zones/sec.test/dnssec",
        Some(json!({ "enabled": true })),
    );
    assert_eq!(st, 409, "{v}");
    let (st, v) = call(
        &root,
        &web,
        "PUT",
        "/zones/sec.test",
        Some(json!({ "refresh": 60 })),
    );
    assert_eq!(st, 400, "{v}");
    let (st, v) = call(
        &root,
        &web,
        "POST",
        "/zones/sec.test/rename",
        Some(json!({ "name": "other.test" })),
    );
    assert_eq!(st, 409, "{v}");

    // A dynamic update on BIND: it NOTIFYs us (signed with the key) and we
    // transfer the difference (IXFR) within seconds.
    let key_arg = format!("hmac-sha256:xfr.:{secret}");
    let update = |cmds: &str| {
        let script = wd.join("nsupdate.txt");
        std::fs::write(
            &script,
            format!("server 127.0.0.1 {named_port}\nzone sec.test\n{cmds}\nsend\n"),
        )
        .unwrap();
        run(&nsupdate, &["-y", &key_arg, script.to_str().unwrap()], &wd);
    };
    update("update add new.sec.test 300 A 192.0.2.99");
    wait_for("NOTIFY + IXFR: new.sec.test", 15, || {
        dig(&dig_bin, rp, &["+short", "new.sec.test", "A"]).trim() == "192.0.2.99"
    });
    let st = status("sec.test");
    assert_eq!(st["last_transfer"], "ixfr", "{st}");
    assert_eq!(st["serial"], 2, "{st}");
    assert!(st["notifies"].as_u64().unwrap() >= 1, "{st}");
    update("update delete www.sec.test A");
    wait_for("IXFR deletion", 15, || {
        let a = dig(&dig_bin, rp, &["www.sec.test", "A"]);
        a.contains("NOERROR") && a.contains("ANSWER: 0")
    });
    assert_eq!(
        dig(&dig_bin, rp, &["+short", "www.sec.test", "TXT"]),
        dig(&dig_bin, named_port, &["+short", "www.sec.test", "TXT"])
    );
    let log = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
    assert!(log.contains("NOTIFY accepted"), "NOTIFY logged");
    // A NOTIFY from elsewhere (not a primary address, unsigned) is refused:
    // ours come from 127.0.0.1, which is the primary's address, so check
    // a NOTIFY for a zone that is not a secondary zone here.
    let n = out(
        &dig_bin,
        &[
            "@127.0.0.1",
            "-p",
            &rp.to_string(),
            "+opcode=notify",
            "+norec",
            "unknown.test",
            "SOA",
        ],
    );
    assert!(n.contains("REFUSED"), "{n}");

    // The outbound transfer of a secondary zone (to our own secondaries).
    let axfr = dig(&dig_bin, rp, &["sec.test", "AXFR"]);
    assert!(
        axfr.contains("new.sec.test.") && !axfr.contains("Transfer failed"),
        "{axfr}"
    );

    // Pre-signed zones, validated by delv against the primary's key.
    for (z, denial) in [("signed.test", "NSEC"), ("nsec3.test", "NSEC3")] {
        let key = std::fs::read_dir(&wd)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| {
                let n = p.file_name().unwrap().to_string_lossy().to_string();
                n.starts_with(&format!("K{z}.+013+")) && n.ends_with(".key")
            })
            .unwrap();
        let text = std::fs::read_to_string(&key).unwrap();
        let line = text.lines().find(|l| l.contains("DNSKEY")).unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let i = f.iter().position(|x| *x == "DNSKEY").unwrap();
        let anchor = dir.join(format!("{z}.anchor"));
        std::fs::write(
            &anchor,
            format!(
                "trust-anchors {{ \"{z}.\" static-key {} {} {} \"{}\"; }};\n",
                f[i + 1],
                f[i + 2],
                f[i + 3],
                f[i + 4..].join("")
            ),
        )
        .unwrap();
        for (name, t, want) in [
            (format!("www.{z}"), "A", "; fully validated"),
            (format!("x.wild.{z}"), "A", "; fully validated"),
            (
                format!("nope.{z}"),
                "A",
                "; negative response, fully validated",
            ),
            (
                format!("www.{z}"),
                "AAAA",
                "; negative response, fully validated",
            ),
            (
                format!("deep.{z}"),
                "A",
                "; negative response, fully validated",
            ),
            (z.to_string(), "DNSKEY", "; fully validated"),
        ] {
            let o = out(
                &delv,
                &[
                    "@127.0.0.1",
                    "-p",
                    &rp.to_string(),
                    "-a",
                    anchor.to_str().unwrap(),
                    &format!("+root={z}"),
                    &name,
                    t,
                ],
            );
            assert!(
                o.lines().any(|l| l.starts_with(want)),
                "{denial}: delv {name} {t}: {o}"
            );
        }
        let d = dig(&dig_bin, rp, &["+dnssec", &format!("nope.{z}"), "A"]);
        assert!(
            d.contains(&format!("IN\t{denial}")) || d.contains(&format!("IN {denial}")),
            "{d}"
        );
    }

    // The primary goes away: the last transfer keeps being served, also
    // after a restart (local copy) ...
    drop(bind.take());
    drop(srv);
    let srv = spawn(
        dir.join("t.toml"),
        rp,
        web.rsplit(':').next().unwrap().parse().unwrap(),
    )
    .expect("restart");
    assert_eq!(
        dig(&dig_bin, srv.dns, &["+short", "new.sec.test", "A"]).trim(),
        "192.0.2.99",
        "served from the local copy after a restart"
    );
    let root = login(&web);
    let st = call(&root, &web, "GET", "/zones/sec.test/secondary", None).1;
    assert_eq!(st["serial"], 3, "{st}");
    // ... until it expires: exp.test (expire 4 s) is answered SERVFAIL.
    wait_for("exp.test expires", 20, || {
        dig(&dig_bin, srv.dns, &["www.exp.test", "A"]).contains("SERVFAIL")
    });
    let st = call(&root, &web, "GET", "/zones/exp.test/secondary", None).1;
    assert_eq!(st["state"], "expired", "{st}");
    assert!(st["last_error"].is_string(), "{st}");
    // Back: the primary returns and the zone is transferred again.
    bind = Some(start_named());
    wait_for("exp.test refreshed", 30, || {
        dig(&dig_bin, srv.dns, &["+short", "www.exp.test", "A"]).trim() == "192.0.2.80"
    });

    // A key with the wrong secret: refused by BIND (the refresh fails),
    // and once the data expires the zone is answered SERVFAIL.
    let (st, v) = call(
        &root,
        &web,
        "PUT",
        "/zones/exp.test",
        Some(json!({ "secondary": { "key": "wrong." } })),
    );
    assert_eq!(st, 200, "{v}");
    wait_for("wrong key reported", 20, || {
        let s = call(&root, &web, "GET", "/zones/exp.test/secondary", None).1;
        s["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("BADSIG") || e.contains("BADKEY") || e.contains("signed"))
    });
    wait_for("exp.test SERVFAIL with the wrong key", 20, || {
        dig(&dig_bin, srv.dns, &["www.exp.test", "A"]).contains("SERVFAIL")
    });
    // An unknown key: 400.
    let (st, v) = call(
        &root,
        &web,
        "POST",
        "/zones",
        Some(json!({ "name": "x.test", "secondary": { "primaries": [primary], "key": "nope." } })),
    );
    assert_eq!(st, 400, "{v}");
    drop(bind);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

fn rand_bytes() -> [u8; 32] {
    rand::random()
}
