//! L1 (Linux only): `[server].interfaces` follows address changes through
//! netlink, not the poll interval. The server runs in a private network
//! namespace (`unshare -rn`, or `unshare -n` as root / through passwordless
//! sudo, as on CI runners) with `interface_poll_secs = 3600`; an address
//! added to and removed from `lo` there must be bound and released within
//! seconds. Skipped when no namespace can be made, unless
//! `REQUIRE_NETLINK_TEST=1` (CI sets it).
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Stdio};

/// A command prefix that runs its arguments in a new network namespace
/// with the right to configure it.
fn namespace() -> Option<Vec<&'static str>> {
    let euid = unsafe { libc::geteuid() };
    let mut tries: Vec<Vec<&'static str>> = vec![vec!["unshare", "-rn"]];
    if euid == 0 {
        tries.insert(0, vec!["unshare", "-n"]);
    } else {
        tries.push(vec!["sudo", "-n", "unshare", "-n"]);
    }
    tries.into_iter().find(|p| {
        Command::new(p[0])
            .args(&p[1..])
            .args(["ip", "link", "set", "lo", "up"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

// Paths as arguments, not environment: `sudo` resets the environment.
const SCRIPT: &str = r#"
set -e
BIN="$1"; DIR="$2"
ip link set lo up
"$BIN" --config "$DIR/rust-dns.toml" > "$DIR/stdout.log" 2>&1 & pid=$!
# wait_log <text> <tenths of a second>
wait_log() { for i in $(seq "$2"); do grep -q "$1" "$DIR/server.log" 2>/dev/null && return 0; sleep 0.1; done; echo "timeout: $1"; return 0; }
# Startup (a debug build hashing the root password) can take many seconds.
wait_log "following interface addresses through netlink" 1800
wait_log "127.0.0.1:25353" 600
echo "--- add"
ip addr add 192.0.2.77/32 dev lo
wait_log "192.0.2.77:25353" 30
echo "--- del"
ip addr del 192.0.2.77/32 dev lo
wait_log "interface address gone" 30
kill $pid; wait $pid || true
# The server runs with umask 0077: under `sudo` its log is root-only, so
# print it from inside the namespace (same privileges as the server).
echo "=== server.log"
cat "$DIR/server.log" 2>/dev/null || true
"#;

#[test]
fn interface_addresses_are_followed_through_netlink() {
    let Some(ns) = namespace() else {
        assert!(
            std::env::var("REQUIRE_NETLINK_TEST").as_deref() != Ok("1"),
            "REQUIRE_NETLINK_TEST=1 but no network namespace can be made (unshare -rn / sudo -n)"
        );
        eprintln!("SKIPPED: no network namespace (unshare -rn / sudo -n unshare -n)");
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rust-dns-netlink-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_config(&dir);
    let out = Command::new(ns[0])
        .args(&ns[1..])
        .args(["sh", "-c", SCRIPT, "sh", env!("CARGO_BIN_EXE_rust-dns")])
        .arg(&dir)
        .output()
        .expect("run the namespace script");
    // The log as printed by the script (readable even when the server ran as
    // root under `sudo`), else the file.
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let log = match stdout.split_once("=== server.log\n") {
        Some((_, l)) if !l.trim().is_empty() => l.to_string(),
        _ => std::fs::read_to_string(dir.join("server.log")).unwrap_or_default(),
    };
    let ctx = format!(
        "script: {}{}\nlog:\n{log}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{ctx}");
    assert!(!ctx.contains("timeout:"), "{ctx}");
    assert!(
        log.contains("following interface addresses through netlink"),
        "{ctx}"
    );
    assert!(log.contains("192.0.2.77:25353"), "bound: {ctx}");
    assert!(
        log.lines()
            .any(|l| l.contains("interface address gone") && l.contains("192.0.2.77")),
        "released: {ctx}"
    );
    // The removal also cleans up after `sudo` (files owned by root).
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_config(dir: &Path) {
    // Poll once an hour: only netlink can explain a change seen in seconds.
    let cfg = format!(
        r#"
[server]
interfaces = ["lo"]
interface_poll_secs = 3600
port = 25353
[database]
path = "{db}"
[web_console]
bind = "127.0.0.1:25380"
[root]
username = "root"
password = "rootpass-netlink"
[logging]
level = "info"
file = "{log}"
[backup]
dir = ""
"#,
        db = dir.join("data.db").display(),
        log = dir.join("server.log").display(),
    );
    std::fs::write(dir.join("rust-dns.toml"), cfg).unwrap();
}
