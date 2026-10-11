//! D2/D3 end to end, validated independently with BIND tools: after single
//! record changes in a signed zone (signatures reused per RRset, catalog
//! rebuilt per zone) the zone transfers as fully signed (`dnssec-verify`)
//! and `delv` validates a changed record, an unchanged record, NXDOMAIN and
//! a wildcard answer; each change computes only a few signatures.
//!
//! A file of its own (not tests/dnssec.rs) with its own small helpers.

use serde_json::{json, Value};
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

const ZONE: &str = "changes.test";

mod common;
use common::free_port;

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
        eprintln!("dnssec_changes: {name} not found; skipping that check");
    }
    t
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn call(a: &ureq::Agent, method: &str, url: &str, body: Option<Value>) -> Value {
    let req = a
        .request(method, url)
        .set("X-Requested-With", "rust-dns")
        .set("X-CSRF-Token", &csrf_of(a));
    let r = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match r {
        Ok(r) => r.into_json().unwrap_or(Value::Null),
        Err(ureq::Error::Status(c, r)) => {
            panic!(
                "{method} {url}: {c} {}",
                r.into_string().unwrap_or_default()
            )
        }
        Err(e) => panic!("{method} {url}: {e}"),
    }
}

fn metric(a: &ureq::Agent, web: &str, name: &str) -> u64 {
    let text = a
        .get(&format!("{web}/rust-dns/metrics"))
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
        .parse()
        .unwrap()
}

#[test]
fn single_changes_in_a_signed_zone_stay_valid() {
    let dir = std::env::temp_dir().join(format!(
        "rust-dns-dnssec-changes-{}-{}",
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
            "[server]\nbind = [\"127.0.0.1\"]\nport = {dns}\n[rate_limit]\nmax_resolutions_per_second_per_address = 0\n[transfer]\nallow = [\"127.0.0.0/8\"]\n[database]\npath = \"{}\"\n[backup]\ndir = \"\"\n[web_console]\nbind = \"127.0.0.1:{web_port}\"\n[root]\nusername = \"root\"\npassword = \"rootpass123\"\n[logging]\nlevel = \"warn\"\n",
            dir.join("t.db").display()
        ),
    )
    .unwrap();
    let web = format!("http://127.0.0.1:{web_port}");
    let mut dns = dns;
    let mut attempts = 0;
    let _srv = loop {
        attempts += 1;
        assert!(
            attempts <= 5,
            "the server never came up with all its listeners"
        );
        let mut srv = Server(
            Command::new(env!("CARGO_BIN_EXE_rust-dns"))
                .arg("--config")
                .arg(dir.join("t.toml"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                // O0c: the server exits when this test process is gone.
                .env("RUST_DNS_EXIT_WITH_STDIN", "1")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while ureq::get(&format!("{web}/rust-dns/api/health"))
            .timeout(Duration::from_millis(300))
            .call()
            .is_err()
        {
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        if common::came_up(&mut srv.0, dns) {
            break srv;
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
    call(
        &a,
        "POST",
        &format!("{web}/rust-dns/api/zones"),
        Some(json!({ "name": ZONE })),
    );
    let add = |name: &str, t: &str, v: &str| -> i64 {
        call(
            &a,
            "POST",
            &format!("{web}/rust-dns/api/zones/{ZONE}/records"),
            Some(json!({ "name": name, "type": t, "value": v })),
        )["id"]
            .as_i64()
            .unwrap()
    };
    add("@", "NS", &format!("ns1.{ZONE}."));
    add("ns1", "A", "192.0.2.53");
    let changed = add("changed", "A", "192.0.2.1");
    add("unchanged", "A", "192.0.2.2");
    add("*.wild", "A", "192.0.2.3");
    for i in 0..200 {
        add(
            &format!("h{i}"),
            "A",
            &format!("198.51.100.{}", i % 250 + 1),
        );
    }
    // A second signed zone: it must not be signed again by changes here.
    call(
        &a,
        "POST",
        &format!("{web}/rust-dns/api/zones"),
        Some(json!({ "name": "bystander.test" })),
    );
    call(
        &a,
        "PUT",
        &format!("{web}/rust-dns/api/zones/bystander.test/dnssec"),
        Some(json!({ "enabled": true })),
    );
    let on = call(
        &a,
        "PUT",
        &format!("{web}/rust-dns/api/zones/{ZONE}/dnssec"),
        Some(json!({ "enabled": true })),
    );
    let dnskey = on["key"]["dnskey"].as_str().unwrap().to_string();
    let inception = on["signatures"]["inception"].clone();
    let total = on["signatures"]["signed_rrsets"].as_u64().unwrap();
    assert!(total > 400, "{on}");

    let validate = |what: &str| {
        if let (Some(dig), Some(verify)) = (bind_tool("dig"), bind_tool("dnssec-verify")) {
            let out = Command::new(&dig)
                .args([
                    "@127.0.0.1",
                    "-p",
                    &dns.to_string(),
                    ZONE,
                    "AXFR",
                    "+nocmd",
                    "+nocomments",
                    "+nostats",
                ])
                .output()
                .unwrap();
            let zf = dir.join("axfr.zone");
            std::fs::write(&zf, &out.stdout).unwrap();
            let v = Command::new(&verify)
                .args(["-z", "-o", ZONE, zf.to_str().unwrap()])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&v.stdout).to_string()
                + &String::from_utf8_lossy(&v.stderr);
            assert!(
                v.status.success() && text.contains("Zone fully signed"),
                "{what}: dnssec-verify: {text}"
            );
        }
        if let Some(delv) = bind_tool("delv") {
            let f: Vec<&str> = dnskey.split_whitespace().collect();
            let anchor = dir.join("anchor.conf");
            std::fs::write(
                &anchor,
                format!(
                    "trust-anchors {{ \"{}\" static-key {} {} {} \"{}\"; }};\n",
                    f[0], f[4], f[5], f[6], f[7]
                ),
            )
            .unwrap();
            for (name, t, want) in [
                (format!("changed.{ZONE}"), "A", "; fully validated"),
                (format!("unchanged.{ZONE}"), "A", "; fully validated"),
                (format!("any.wild.{ZONE}"), "A", "; fully validated"),
                (format!("h7.{ZONE}"), "A", "; fully validated"),
                (ZONE.to_string(), "SOA", "; fully validated"),
                (
                    format!("nope.{ZONE}"),
                    "A",
                    "; negative response, fully validated",
                ),
                (
                    format!("changed.{ZONE}"),
                    "AAAA",
                    "; negative response, fully validated",
                ),
            ] {
                let out = Command::new(&delv)
                    .args([
                        "@127.0.0.1",
                        "-p",
                        &dns.to_string(),
                        "-a",
                        anchor.to_str().unwrap(),
                        &format!("+root={ZONE}"),
                        &name,
                        t,
                    ])
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&out.stdout).to_string()
                    + &String::from_utf8_lossy(&out.stderr);
                assert!(
                    text.lines().any(|l| l.starts_with(want)),
                    "{what}: delv {name} {t}: {text}"
                );
            }
        }
    };
    validate("freshly signed");

    let signed = || metric(&a, &web, "rustdns_dnssec_signatures_total");
    let status = || {
        call(
            &a,
            "GET",
            &format!("{web}/rust-dns/api/zones/{ZONE}/dnssec"),
            None,
        )
    };
    // Change one record: its RRset and the SOA are signed, nothing else.
    let before = signed();
    call(
        &a,
        "PUT",
        &format!("{web}/rust-dns/api/zones/{ZONE}/records/{changed}"),
        Some(json!({ "value": "192.0.2.99" })),
    );
    assert_eq!(signed() - before, 2, "a changed record");
    assert_eq!(
        status()["signatures"]["inception"],
        inception,
        "same window"
    );
    validate("after changing a record");
    // Add a name: its RRset, its NSEC, the previous NSEC, the SOA.
    let before = signed();
    let added = add("added", "A", "192.0.2.77");
    assert_eq!(signed() - before, 4, "an added name");
    validate("after adding a name");
    // Remove it again: the previous NSEC and the SOA.
    let before = signed();
    call(
        &a,
        "DELETE",
        &format!("{web}/rust-dns/api/zones/{ZONE}/records/{added}"),
        None,
    );
    assert_eq!(signed() - before, 2, "a removed name");
    assert_eq!(status()["signatures"]["signed_rrsets"], total);
    assert_eq!(status()["signatures"]["inception"], inception);
    validate("after removing a name");
    drop(_srv);
    let _ = std::fs::remove_dir_all(&dir);
}
