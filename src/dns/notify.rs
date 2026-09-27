//! Send NOTIFY (RFC 1996) to configured secondaries when a zone changes.

use super::DnsServer;
use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Subscribe to change events and send debounced NOTIFYs.
pub async fn run(server: Arc<DnsServer>) {
    let Some(rx) = server.bus.subscribe_changes() else {
        return;
    };
    let mut pending: HashMap<String, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            r = rx.recv_async() => match r {
                Ok(ev) => {
                    if matches!(ev.entity.as_str(), "zone" | "record") && !ev.zone.is_empty() {
                        pending.insert(ev.zone.clone(), Instant::now());
                    }
                }
                Err(_) => return,
            },
            _ = tick.tick() => {
                let due: Vec<String> = pending.iter().filter(|(_, t)| t.elapsed() >= Duration::from_secs(1)).map(|(z, _)| z.clone()).collect();
                for zone in due {
                    pending.remove(&zone);
                    let targets = server.runtime.load().notify.clone();
                    if targets.is_empty() { continue; }
                    let still_exists = server.cache.load().zones.contains_key(&crate::model::zone_fqdn(&zone));
                    if !still_exists { continue; }
                    for t in targets {
                        let s = server.clone();
                        let z = zone.clone();
                        tokio::spawn(async move { send_notify(s, z, t).await });
                    }
                }
            }
        }
    }
}

async fn send_notify(server: Arc<DnsServer>, zone: String, to: std::net::SocketAddr) {
    let Ok(name) = Name::from_ascii(crate::model::zone_fqdn(&zone)) else {
        return;
    };
    let mut h = Header::new();
    h.set_id(rand::random::<u16>())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Notify)
        .set_authoritative(true);
    let mut m = Message::new();
    m.set_header(h);
    m.add_query(Query::query(name, RecordType::SOA));
    let Ok(bytes) = m.to_vec() else { return };
    let bind = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else {
        return;
    };
    server
        .stats
        .notifies
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Up to 3 attempts, 2 s apart, until the secondary acknowledges.
    for attempt in 1..=3 {
        if sock.send_to(&bytes, to).await.is_err() {
            break;
        }
        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 2 && buf[..2] == bytes[..2] => {
                tracing::info!(zone = %zone, secondary = %to, attempt, "NOTIFY acknowledged");
                return;
            }
            _ => {}
        }
    }
    tracing::warn!(zone = %zone, secondary = %to, "NOTIFY not acknowledged");
}
