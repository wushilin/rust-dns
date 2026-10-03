use super::{DnsServer, Proto, Reply};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn run(server: Arc<DnsServer>, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "udp recv failed");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
        };
        // Admission first: an over-limit packet is dropped (or gets the
        // slip reply) right here, without a copy, a task or a decode.
        if let Some(reply) = server.admit(&buf[..n], peer, Proto::Udp) {
            if let Reply::One(m) = reply {
                let _ = sock.send_to(&m, peer).await;
            }
            continue;
        }
        let req = buf[..n].to_vec();
        let server = server.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let resp = match server.handle_admitted(&req, peer, Proto::Udp).await {
                Reply::None => return,
                Reply::One(m) => m,
                Reply::Many(mut ms) => ms.remove(0),
            };
            if let Err(e) = sock.send_to(&resp, peer).await {
                tracing::debug!(%peer, error = %e, "udp send failed");
            }
        });
    }
}
