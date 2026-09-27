//! DNS over TCP (RFC 7766).
//!
//! A connection holds one of `max_tcp_connections` global slots and one of
//! `max_tcp_connections_per_client` slots for its client (IPv4 address or
//! IPv6 /64, after PROXY protocol resolution). Queries are handled one at a
//! time: the next one is read only after the previous answer was written,
//! so a pipelining client that never reads cannot make the server buffer
//! anything beyond one response; the kernel socket buffers hold the rest.
//! Every read is bounded by `tcp_idle_timeout_secs`, every write (each AXFR
//! message separately) by `tcp_write_timeout_secs`, and a connection is
//! closed after `tcp_max_queries_per_connection` queries or once it is older
//! than `tcp_max_connection_secs` (checked between queries, so a long zone
//! transfer is not cut off). A client that stops reading therefore frees
//! its slots within one write timeout.

use super::{DnsServer, Proto, Reply};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Open connections per client key (see [`crate::ratelimit::client_key`]).
#[derive(Default)]
pub struct PerClient {
    open: Mutex<HashMap<u128, usize>>,
}

/// Releases a per-client slot when the connection ends.
pub struct ClientSlot {
    owner: Arc<PerClient>,
    key: u128,
}

impl PerClient {
    /// Take a slot for `ip` unless it already holds `max` (0 = unlimited).
    pub fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<ClientSlot> {
        let key = crate::ratelimit::client_key(ip);
        let mut g = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let n = g.entry(key).or_insert(0);
        if max > 0 && *n >= max {
            return None;
        }
        *n += 1;
        Some(ClientSlot {
            owner: self.clone(),
            key,
        })
    }

    #[cfg(test)]
    pub fn open_for(&self, ip: IpAddr) -> usize {
        let key = crate::ratelimit::client_key(ip);
        let g = self.open.lock().unwrap_or_else(|p| p.into_inner());
        g.get(&key).copied().unwrap_or(0)
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut g = self.owner.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = g.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                g.remove(&self.key);
            }
        }
    }
}

pub async fn run(server: Arc<DnsServer>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let permit = match server.tcp_slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!(%peer, "tcp connection limit reached; dropping connection");
                drop(stream);
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_conn(server, stream, peer).await;
        });
    }
}

async fn write_timed(stream: &mut TcpStream, buf: &[u8], limit: Duration) -> std::io::Result<()> {
    match tokio::time::timeout(limit, stream.write_all(buf)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "client is not reading",
        )),
    }
}

async fn handle_conn(
    server: Arc<DnsServer>,
    mut stream: TcpStream,
    mut peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    let listen = &server.listen;
    let idle = Duration::from_secs(listen.tcp_idle_timeout_secs.max(1));
    let write_limit = Duration::from_secs(listen.tcp_write_timeout_secs.max(1));
    let lifetime = Duration::from_secs(listen.tcp_max_connection_secs.max(1));
    let max_queries = listen.tcp_max_queries_per_connection.max(1);
    let opened = Instant::now();
    let _ = stream.set_nodelay(true);
    if server.tcp_proxy.proxy_on && server.tcp_proxy_trust.iter().any(|c| c.contains(peer.ip())) {
        use crate::api::proxy::{read_proxy_header, ProxyHeader};
        match read_proxy_header(&mut stream, server.tcp_proxy.proxy_version).await {
            ProxyHeader::Source(src) => peer = src,
            ProxyHeader::Absent => {}
            ProxyHeader::Rejected(why) => {
                tracing::warn!(%peer, why, "rejecting DNS TCP connection");
                return Ok(());
            }
        }
    }
    let Some(_client_slot) = server
        .tcp_per_client
        .acquire(peer.ip(), listen.max_tcp_connections_per_client)
    else {
        tracing::debug!(%peer, "per-client TCP connection limit reached; closing");
        return Ok(());
    };
    let mut served = 0u32;
    loop {
        if served >= max_queries || opened.elapsed() >= lifetime {
            return Ok(()); // the client reconnects if it has more to ask
        }
        let mut lenbuf = [0u8; 2];
        match tokio::time::timeout(idle, stream.read_exact(&mut lenbuf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // idle timeout or EOF
        }
        let n = u16::from_be_bytes(lenbuf) as usize;
        if n == 0 {
            return Ok(());
        }
        let mut req = vec![0u8; n];
        match tokio::time::timeout(idle, stream.read_exact(&mut req)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        served += 1;
        let messages = match server.handle(&req, peer, Proto::Tcp).await {
            Reply::None => continue,
            Reply::One(m) => vec![m],
            Reply::Many(ms) => ms,
        };
        for resp in messages {
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            if let Err(e) = write_timed(&mut stream, &out, write_limit).await {
                tracing::debug!(%peer, error = %e, "closing DNS TCP connection");
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_client_slots_group_ipv6_by_64_and_release_on_drop() {
        let pc = Arc::new(PerClient::default());
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        let s1 = pc.acquire(a, 2).unwrap();
        let s2 = pc.acquire(b, 2).unwrap();
        assert!(pc.acquire(a, 2).is_none(), "same /64 is one client");
        assert!(pc.acquire(other, 2).is_some(), "another /64 is not");
        drop(s1);
        assert_eq!(pc.open_for(b), 1);
        let _s3 = pc.acquire(b, 2).unwrap();
        drop(s2);
        assert!(pc.acquire("192.0.2.1".parse().unwrap(), 0).is_some());
    }
}
