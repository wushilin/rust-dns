//! Shared by the integration test suites (each includes it with
//! `mod common;`; not every suite uses every helper).
#![allow(dead_code)]

use std::net::{TcpListener, UdpSocket};
use std::time::{Duration, Instant};

/// A loopback port free for both TCP and UDP right now (port 5353 is never
/// returned). Still only a hint: another process may take it before the
/// server binds it, which is why servers are checked with
/// [`dns_listening`] after they start.
pub fn free_port() -> u16 {
    loop {
        let t = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = t.local_addr().unwrap().port();
        if p != 5353 && UdpSocket::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

/// O0a: the server's DNS listeners on `port` answer, over UDP and TCP,
/// within `wait`. The server only logs (to its stdout, discarded by the
/// suites) when it cannot bind one of its DNS sockets and keeps running
/// with the other one and the web console, so a server whose UDP port
/// was taken by another process between [`free_port`] and its own bind
/// looked healthy and dropped every UDP query (seen under load as a 5 s
/// receive timeout in `forwarding::tcp_fallback_answers_are_truncated_
/// for_udp_clients`). A probe answered with its own ID proves the
/// listener; the caller starts the server again on other ports when not.
pub fn dns_listening(port: u16, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    let id: u16 = (std::process::id() as u16) ^ (port.rotate_left(7)) ^ 0x5a5a;
    // Header (RD clear), one question: "version.bind." TXT CH, answered
    // by the server itself (never forwarded, never a zone lookup).
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in ["version", "bind"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 16, 0, 3]);
    let udp_ok = loop {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let _ = s.send_to(&q, ("127.0.0.1", port));
        let mut buf = [0u8; 512];
        if let Ok(n) = s.recv(&mut buf) {
            if n >= 12 && buf[..2] == id.to_be_bytes() && buf[2] & 0x80 != 0 {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
    };
    if !udp_ok {
        return false;
    }
    loop {
        if std::net::TcpStream::connect_timeout(
            &([127, 0, 0, 1], port).into(),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// O0a: whether a freshly spawned server came up with every listener: it
/// is still running (it exits when the web port was taken, and the health
/// check may then have reached another process) and its DNS answers on
/// `dns` ([`dns_listening`]). `false`: kill it and start another on new
/// ports.
pub fn came_up(child: &mut std::process::Child, dns: u16) -> bool {
    let listening = dns_listening(dns, Duration::from_secs(5));
    if matches!(child.try_wait(), Ok(Some(_))) {
        eprintln!("the server exited at start (a port was taken); starting another");
        return false;
    }
    if !listening {
        eprintln!("DNS port {dns} could not be bound; starting another server");
        let _ = child.kill();
        let _ = child.wait();
    }
    listening
}

/// O0a: move a server config's DNS port (`port = <old>` in `[server]`) to a
/// fresh one after [`came_up`] said the old one was taken; returns it.
pub fn move_dns_port(cfg: &std::path::Path, old: u16) -> u16 {
    let text = std::fs::read_to_string(cfg).unwrap();
    let new = free_port();
    let from = format!("\nport = {old}\n");
    assert!(
        text.contains(&from),
        "no `port = {old}` line in {}",
        cfg.display()
    );
    std::fs::write(cfg, text.replacen(&from, &format!("\nport = {new}\n"), 1)).unwrap();
    new
}
