//! `rdns`, the command-line client, against a real server: sign in, then
//! records, zones, access, users and tokens, each checked through the
//! client's own `--json` output.

use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

struct Server {
    child: Child,
    web: String,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Server {
    for _ in 0..5 {
        if let Some(s) = try_start() {
            return s;
        }
    }
    panic!("the server never came up with all its listeners");
}

fn try_start() -> Option<Server> {
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let dns_port = free_port();
    let web_port = free_port();
    let cfg = format!(
        r#"
[server]
bind = ["127.0.0.1"]
port = {dns_port}
[database]
path = "{db}"
[web_console]
bind = "127.0.0.1:{web_port}"
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
        db = dir.join("test.db").display()
    );
    let cfg_path = dir.join("test.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-dns"))
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env("RUST_DNS_EXIT_WITH_STDIN", "1")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn rust-dns");
    let web = format!("http://127.0.0.1:{web_port}");
    let deadline = Instant::now() + Duration::from_secs(15);
    while ureq::get(&format!("{web}/rust-dns/api/health"))
        .timeout(Duration::from_millis(500))
        .call()
        .is_err()
    {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return None;
        }
        assert!(Instant::now() < deadline, "server did not come up");
        std::thread::sleep(Duration::from_millis(100));
    }
    if !common::came_up(&mut child, dns_port) {
        return None;
    }
    Some(Server { child, web, dir })
}

/// One `rdns` run with its own config file: (exit ok, stdout, stderr).
fn rdns(cfg: &Path, args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rdns"))
        .args(args)
        .env("RDNS_CONFIG", cfg)
        .env_remove("RDNS_SERVER")
        .env_remove("RDNS_TOKEN")
        .env_remove("RDNS_PROFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rdns");
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `rdns` that must succeed; its stdout.
fn ok(cfg: &Path, args: &[&str]) -> String {
    let (good, out, err) = rdns(cfg, args, "");
    assert!(good, "rdns {args:?} failed:\n{err}{out}");
    out
}

/// `rdns --json ...` that must succeed, parsed.
fn json(cfg: &Path, args: &[&str]) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    serde_json::from_str(&ok(cfg, &a)).expect("JSON output")
}

/// `rdns` that must fail; its stderr.
fn fails(cfg: &Path, args: &[&str]) -> String {
    let (good, out, err) = rdns(cfg, args, "");
    assert!(!good, "rdns {args:?} should have failed:\n{out}");
    err
}

/// (name, type, value, ttl) of a record list.
fn rows(v: &Value) -> Vec<(String, String, String, Option<u64>)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["type"].as_str().unwrap().to_string(),
                r["value"].as_str().unwrap().to_string(),
                r["ttl"].as_u64(),
            )
        })
        .collect()
}

#[test]
fn cli_manages_records_zones_users_and_tokens() {
    let s = start();
    let cfg = s.dir.join("rdns.toml");
    let cfg = cfg.as_path();

    // Not signed in yet.
    assert!(fails(cfg, &["zone", "ls"]).contains("rdns login"));
    let (good, out, err) = rdns(
        cfg,
        &[
            "login",
            &s.web,
            "-u",
            "root",
            "--password-stdin",
            "--as",
            "test",
        ],
        "rootpass123\n",
    );
    assert!(good, "login failed: {err}{out}");
    let saved = std::fs::read_to_string(cfg).unwrap();
    assert!(saved.contains("rdns_") && saved.contains("default = \"test\""));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(cfg).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the token file must be private");
    }
    assert!(ok(cfg, &["whoami"]).starts_with("root (root)"));

    // Signing in again replaces the profile's token and revokes the old one.
    let first = saved_token(&saved, "test");
    let (good, out, err) = rdns(
        cfg,
        &[
            "login",
            &s.web,
            "-u",
            "root",
            "--password-stdin",
            "--as",
            "test",
        ],
        "rootpass123\n",
    );
    assert!(good, "second login failed: {err}{out}");
    assert_eq!(me_status(&s.web, &first), 401);
    let saved = std::fs::read_to_string(cfg).unwrap();

    // Zones.
    ok(
        cfg,
        &[
            "zone",
            "add",
            "example.test",
            "--ns",
            "ns1.example.test.",
            "--email",
            "hostmaster@example.test",
            "--ttl",
            "3600",
        ],
    );
    let zones = json(cfg, &["zone", "ls"]);
    assert_eq!(zones["zones"][0]["name"], "example.test");
    ok(cfg, &["zone", "set", "example.test", "--minimum", "120"]);
    assert_eq!(json(cfg, &["zone", "show", "example.test"])["minimum"], 120);

    // Records, by full name.
    ok(
        cfg,
        &[
            "dns",
            "add",
            "www.example.test",
            "A",
            "192.0.2.10",
            "--ttl",
            "300",
        ],
    );
    ok(
        cfg,
        &[
            "dns",
            "add",
            "example.test",
            "MX",
            "10",
            "mail.example.test.",
        ],
    );
    ok(cfg, &["dns", "add", "example.test", "TXT", "v=spf1 -all"]);
    ok(
        cfg,
        &[
            "r",
            "add",
            "_sip._tcp",
            "SRV",
            "10 5 5060 sip.example.test.",
            "-z",
            "example.test",
        ],
    );
    let all = rows(&json(cfg, &["dns", "ls", "example.test"]));
    for want in [
        ("www", "A"),
        ("@", "MX"),
        ("@", "TXT"),
        ("_sip._tcp", "SRV"),
    ] {
        assert!(
            all.iter().any(|r| (r.0.as_str(), r.1.as_str()) == want),
            "{want:?} missing from {all:?}"
        );
    }
    // A name lists only its own records; -t filters by type.
    let www = rows(&json(cfg, &["dns", "ls", "www.example.test"]));
    assert_eq!(
        www,
        vec![("www".into(), "A".into(), "192.0.2.10".into(), Some(300))]
    );
    assert_eq!(
        rows(&json(cfg, &["dns", "ls", "example.test", "-t", "mx"])).len(),
        1
    );
    // Anything outside the zones is a search.
    let hits = rows(&json(cfg, &["dns", "ls", "192.0.2.10"]));
    assert_eq!(hits.len(), 1);

    // set replaces the RRset and keeps its TTL; set --ttl only changes the TTL.
    ok(
        cfg,
        &[
            "dns",
            "add",
            "www.example.test",
            "A",
            "192.0.2.11",
            "--ttl",
            "300",
        ],
    );
    ok(cfg, &["dns", "set", "www.example.test", "A", "192.0.2.20"]);
    let www = rows(&json(cfg, &["dns", "ls", "www.example.test"]));
    assert_eq!(
        www,
        vec![("www".into(), "A".into(), "192.0.2.20".into(), Some(300))]
    );
    ok(
        cfg,
        &["dns", "set", "www.example.test", "A", "--ttl", "600"],
    );
    assert_eq!(
        rows(&json(cfg, &["dns", "ls", "www.example.test"]))[0].3,
        Some(600)
    );
    ok(
        cfg,
        &["dns", "set", "www.example.test", "A", "--ttl", "default"],
    );
    assert_eq!(
        rows(&json(cfg, &["dns", "ls", "www.example.test"]))[0].3,
        None
    );
    // A bad value changes nothing.
    assert!(fails(
        cfg,
        &["dns", "set", "www.example.test", "A", "not-an-address"]
    )
    .contains("nothing was changed"));
    assert_eq!(
        rows(&json(cfg, &["dns", "ls", "www.example.test"]))[0].2,
        "192.0.2.20"
    );

    // rm: one value (matched loosely), or several after confirmation.
    ok(
        cfg,
        &["dns", "rm", "example.test", "MX", "10", "Mail.example.test"],
    );
    assert!(rows(&json(cfg, &["dns", "ls", "example.test", "-t", "MX"])).is_empty());
    ok(cfg, &["dns", "add", "www.example.test", "A", "192.0.2.21"]);
    assert!(fails(cfg, &["dns", "delete", "www.example.test", "A"]).contains("--yes"));
    ok(cfg, &["dns", "delete", "www.example.test", "A", "-y"]);
    assert!(rows(&json(cfg, &["dns", "ls", "www.example.test"])).is_empty());
    assert!(fails(cfg, &["dns", "rm", "nope.example.test"]).contains("no record matches"));
    assert!(
        fails(cfg, &["dns", "add", "www.elsewhere.test", "A", "192.0.2.1"])
            .contains("not in any zone")
    );

    // apply: many lines in one transaction; a bad line applies none.
    let lines = s.dir.join("lines.txt");
    std::fs::write(&lines, "a 300 A 192.0.2.31\nb A 192.0.2.32\n; comment\n").unwrap();
    let lines = lines.to_str().unwrap();
    ok(cfg, &["dns", "apply", "example.test", lines, "--dry-run"]);
    assert!(rows(&json(cfg, &["dns", "ls", "a.example.test"])).is_empty());
    ok(cfg, &["dns", "apply", "example.test", lines]);
    assert_eq!(rows(&json(cfg, &["dns", "ls", "b.example.test"])).len(), 1);

    // Users and zone access.
    ok(
        cfg,
        &[
            "user",
            "add",
            "bob",
            "--password",
            "correct-horse-battery",
            "--name",
            "Bob",
        ],
    );
    let users = json(cfg, &["user", "ls"]);
    assert!(users
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["username"] == "bob"));
    ok(
        cfg,
        &["zone", "grant", "example.test", "bob", "--role", "viewer"],
    );
    let access = json(cfg, &["zone", "access", "example.test"]);
    assert_eq!(access["members"][0]["username"], "bob");
    assert_eq!(access["members"][0]["role"], "viewer");
    let shown = json(cfg, &["user", "show", "bob"]);
    assert_eq!(shown["rights"]["zones"][0]["zone"], "example.test");
    ok(cfg, &["zone", "revoke", "example.test", "bob"]);
    ok(cfg, &["user", "set", "bob", "--admin", "--disable"]);
    let bob = json(cfg, &["user", "show", "bob"]);
    assert_eq!(bob["user"]["is_admin"], true);
    assert!(bob["user"]["disabled_at"].is_string());
    ok(
        cfg,
        &[
            "user",
            "set",
            "bob",
            "--no-admin",
            "--enable",
            "--password",
            "another-long-password",
        ],
    );
    assert_eq!(
        json(cfg, &["user", "show", "bob"])["user"]["is_admin"],
        false
    );
    assert!(fails(cfg, &["user", "rm", "root", "-y"]).contains("cannot delete yourself"));
    assert!(fails(cfg, &["user", "rm", "bob"]).contains("--yes"));
    ok(cfg, &["user", "del", "bob", "-y"]);
    assert!(fails(cfg, &["user", "show", "bob"]).contains("no user 'bob'"));

    // Export, delete, import back.
    let export = s.dir.join("export.json");
    let export = export.to_str().unwrap();
    ok(cfg, &["zone", "export", "example.test", "-o", export]);
    ok(cfg, &["zone", "clone", "example.test", "copy.test"]);
    ok(cfg, &["zone", "rename", "copy.test", "moved.test"]);
    assert_eq!(rows(&json(cfg, &["dns", "ls", "b.moved.test"])).len(), 1);
    ok(cfg, &["zone", "rm", "moved.test", "-y"]);
    assert!(fails(cfg, &["zone", "rm", "example.test"]).contains("--yes"));
    ok(cfg, &["zone", "rm", "example.test", "-y"]);
    assert!(json(cfg, &["zone", "ls"])["zones"]
        .as_array()
        .unwrap()
        .is_empty());
    ok(cfg, &["zone", "import", export]);
    assert_eq!(rows(&json(cfg, &["dns", "ls", "a.example.test"])).len(), 1);

    // Tokens: a scoped one works through RDNS_SERVER / RDNS_TOKEN.
    let created = json(
        cfg,
        &[
            "token",
            "add",
            "ci",
            "--zone",
            "example.test",
            "--role",
            "editor",
            "--expires",
            "30d",
        ],
    );
    let token = created["token"].as_str().unwrap().to_string();
    let id = created["info"]["id"].as_i64().unwrap().to_string();
    let scoped = Command::new(env!("CARGO_BIN_EXE_rdns"))
        .args(["--json", "dns", "ls", "example.test"])
        .env("RDNS_CONFIG", s.dir.join("none.toml"))
        .env("RDNS_SERVER", &s.web)
        .env("RDNS_TOKEN", &token)
        .output()
        .unwrap();
    assert!(
        scoped.status.success(),
        "{}",
        String::from_utf8_lossy(&scoped.stderr)
    );
    ok(cfg, &["token", "rm", &id]);

    // An existing token comes from stdin (never the command line), and
    // logout leaves a token it did not create alone.
    let given = json(cfg, &["token", "add", "laptop"])["token"]
        .as_str()
        .unwrap()
        .to_string();
    let (good, out, err) = rdns(
        cfg,
        &["login", &s.web, "--token-stdin", "--as", "given"],
        &format!("{given}\n"),
    );
    assert!(good, "token login failed: {err}{out}");
    assert!(ok(cfg, &["-p", "given", "whoami"]).starts_with("root (root)"));
    ok(cfg, &["-p", "given", "logout"]);
    assert_eq!(me_status(&s.web, &given), 200);
    assert!(!rdns(cfg, &["login", &s.web, "--with-token", "rdns_x"], "").0);

    // An expiring login token is scoped: logout cannot revoke it, says so,
    // and still forgets it.
    let (good, out, err) = rdns(
        cfg,
        &[
            "login",
            &s.web,
            "-u",
            "root",
            "--password-stdin",
            "--as",
            "exp",
            "--expires",
            "30d",
        ],
        "rootpass123\n",
    );
    assert!(good, "expiring login failed: {err}{out}");
    assert!(out.contains("expires at"), "{out}");
    let exp = saved_token(&std::fs::read_to_string(cfg).unwrap(), "exp");
    let (good, _, err) = rdns(cfg, &["-p", "exp", "logout"], "");
    assert!(good && err.contains("could not revoke"), "{err}");
    assert_eq!(me_status(&s.web, &exp), 200);
    assert!(!std::fs::read_to_string(cfg)
        .unwrap()
        .contains("[profiles.exp]"));

    // Sign out revokes the login token and forgets the profile.
    ok(cfg, &["logout"]);
    assert!(fails(cfg, &["zone", "ls"]).contains("rdns login"));
    assert_eq!(me_status(&s.web, &saved_token(&saved, "test")), 401);
}

fn saved_token(saved: &str, profile: &str) -> String {
    let v: toml::Value = toml::from_str(saved).unwrap();
    v["profiles"][profile]["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The status of `GET /me` with a bearer token.
fn me_status(web: &str, token: &str) -> u16 {
    match ureq::get(&format!("{web}/rust-dns/api/me"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(e) => panic!("{e}"),
    }
}
