//! Forward a raw query to upstream resolvers. The client's request bytes
//! are relayed unchanged from a fresh ephemeral socket; the reply is
//! returned as-is (same ID), so the caller can send it straight back.

use super::Proto;
use crate::config::ForwardingConfig;
use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub async fn forward(cfg: &ForwardingConfig, req: &[u8], proto: Proto) -> Result<Vec<u8>> {
    let to = Duration::from_millis(cfg.timeout_ms.max(100));
    let mut last_err = anyhow!("no upstreams configured");
    for upstream in &cfg.upstreams {
        let res = match proto {
            Proto::Tcp => forward_tcp(*upstream, req, to).await,
            Proto::Udp => match forward_udp(*upstream, req, to).await {
                // Upstream truncated: retry over TCP so we can relay a full answer;
                // the UDP path will re-truncate for the client if it must.
                Ok(b) if b.len() >= 3 && (b[2] & 0x02) != 0 => {
                    forward_tcp(*upstream, req, to).await.or(Ok(b))
                }
                other => other,
            },
        };
        match res {
            Ok(b) => return Ok(b),
            Err(e) => {
                tracing::debug!(%upstream, error = %e, "upstream failed");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

async fn forward_udp(upstream: SocketAddr, req: &[u8], to: Duration) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = UdpSocket::bind(bind)
        .await
        .context("binding forwarding socket")?;
    sock.connect(upstream).await?;
    sock.send(req).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(to, sock.recv(&mut buf))
        .await
        .context("upstream timed out")??;
    buf.truncate(n);
    if n < 12 || buf[..2] != req[..2] {
        bail!("upstream reply id mismatch");
    }
    Ok(buf)
}

async fn forward_tcp(upstream: SocketAddr, req: &[u8], to: Duration) -> Result<Vec<u8>> {
    let mut s = timeout(to, TcpStream::connect(upstream))
        .await
        .context("upstream connect timed out")??;
    let len = (req.len() as u16).to_be_bytes();
    s.write_all(&len).await?;
    s.write_all(req).await?;
    let mut lenbuf = [0u8; 2];
    timeout(to, s.read_exact(&mut lenbuf))
        .await
        .context("upstream timed out")??;
    let n = u16::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; n];
    timeout(to, s.read_exact(&mut buf))
        .await
        .context("upstream timed out")??;
    if n < 12 || buf[..2] != req[..2] {
        bail!("upstream reply id mismatch");
    }
    Ok(buf)
}
