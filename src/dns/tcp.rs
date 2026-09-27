use super::{DnsServer, Proto, Reply};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn handle_conn(
    server: Arc<DnsServer>,
    mut stream: TcpStream,
    mut peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    let idle = Duration::from_secs(server.listen.tcp_idle_timeout_secs.max(1));
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
    loop {
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
        let messages = match server.handle(&req, peer, Proto::Tcp).await {
            Reply::None => continue,
            Reply::One(m) => vec![m],
            Reply::Many(ms) => ms,
        };
        for resp in messages {
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            stream.write_all(&out).await?;
        }
    }
}
