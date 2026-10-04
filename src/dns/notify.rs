//! Send NOTIFY (RFC 1996) to configured secondaries when a zone changes,
//! signed with a TSIG key (RFC 8945) when `[transfer]` names one.

use super::tsig::{self, Chain, ResponseVerifier, SignParams};
use super::DnsServer;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::collections::HashMap;
use std::net::SocketAddr;
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
                    // Override zones are never announced (not authoritative).
                    let catalog = server.cache.load();
                    let Some(z) = catalog.zones.get(&crate::model::zone_fqdn(&zone)).filter(|z| !z.zone.is_override()) else { continue; };
                    // O16: the zone's own targets replace [transfer].notify.
                    let targets = z.zone.settings.as_ref().and_then(|s| s.notify_targets()).unwrap_or_else(|| server.runtime.load().notify.clone());
                    if targets.is_empty() { continue; }
                    for (to, key) in targets {
                        let s = server.clone();
                        let z = zone.clone();
                        tokio::spawn(async move { send_notify(s, z, to, key).await });
                    }
                }
            }
        }
    }
}

/// The NOTIFY query for `zone`, signed with `key` when given. Returns the
/// wire message and the request MAC (empty when unsigned).
pub fn build_notify(
    zone: &str,
    id: u16,
    key: Option<&tsig::Key>,
    now: u64,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let name = Name::from_ascii(crate::model::zone_fqdn(zone)).ok()?;
    let mut m = Message::new(id, MessageType::Query, OpCode::Notify);
    m.metadata.authoritative = true;
    m.add_query(Query::query(name, RecordType::SOA));
    let bytes = m.to_vec().ok()?;
    Some(match key {
        None => (bytes, Vec::new()),
        Some(k) => tsig::sign(
            &bytes,
            k,
            Chain::Request,
            &SignParams {
                time: now,
                fudge: tsig::MAX_FUDGE,
                original_id: id,
                error: 0,
                other: Vec::new(),
            },
        ),
    })
}

async fn send_notify(
    server: Arc<DnsServer>,
    zone: String,
    to: SocketAddr,
    key_name: Option<String>,
) {
    // A configured key that does not exist: do not fall back to unsigned.
    let key = match &key_name {
        None => None,
        Some(k) => match server.tsig_keys.load().get(k) {
            Some(e) => Some(e.key.clone()),
            None => {
                tracing::error!(zone = %zone, secondary = %to, key = %k, "NOTIFY not sent: TSIG key does not exist (create it under TSIG keys or fix [transfer] in the config)");
                return;
            }
        },
    };
    let id = rand::random::<u16>();
    let Some((bytes, request_mac)) = build_notify(&zone, id, key.as_ref(), tsig::now()) else {
        return;
    };
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
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let n = match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if n >= 12 && buf[..2] == bytes[..2] => n,
                Ok(Ok(_)) => continue, // stray datagram
                _ => break,            // timeout or socket error: retry
            };
            let reply = &buf[..n];
            let rcode = reply[3] & 0x0F;
            match &key {
                None => {
                    tracing::info!(zone = %zone, secondary = %to, attempt, rcode, "NOTIFY acknowledged");
                }
                Some(k) => match ResponseVerifier::new(k.clone(), &request_mac)
                    .verify(reply, tsig::now())
                {
                    Ok(()) => {
                        tracing::info!(zone = %zone, secondary = %to, attempt, rcode, key = %k.name, "NOTIFY acknowledged (TSIG verified)")
                    }
                    Err(e) => {
                        tracing::warn!(zone = %zone, secondary = %to, key = %k.name, rcode, error = %e, "NOTIFY response failed TSIG verification")
                    }
                },
            }
            return;
        }
    }
    tracing::warn!(zone = %zone, secondary = %to, "NOTIFY not acknowledged");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tsig::{find, verify, Algorithm, Key};

    #[test]
    fn signed_notify_verifies() {
        let key = Key {
            name: "hn-secondary.".into(),
            algorithm: Algorithm::HmacSha256,
            secret: vec![3; 32],
        };
        let now = 1_800_000_000;
        let (m, mac) = build_notify("example.com", 77, Some(&key), now).unwrap();
        let s = find(&m).unwrap().unwrap();
        assert_eq!(s.tsig.mac, mac);
        verify(&m, &s, Some(&key), Chain::Request, now).unwrap();
        let parsed =
            hickory_proto::serialize::binary::BinDecodable::from_bytes(&tsig::strip(&m, &s))
                .map(|m: Message| (m.metadata.op_code, m.queries[0].name().to_ascii()))
                .unwrap();
        assert_eq!(parsed, (OpCode::Notify, "example.com.".to_string()));
        let (u, mac) = build_notify("example.com", 77, None, now).unwrap();
        assert!(mac.is_empty());
        assert!(find(&u).unwrap().is_none());
    }
}
