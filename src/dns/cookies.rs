//! DNS cookies (RFC 7873 with the RFC 9018 server-cookie format).
//!
//! Server cookie = version(1) | reserved(3) | timestamp(4) | hash(8), where
//! hash = HMAC-SHA256(secret, client_cookie | version | reserved | timestamp | client_ip)[..8].

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::net::IpAddr;

const VERSION: u8 = 1;
/// Cookies older than this are rejected.
const MAX_AGE: u32 = 3600;
/// Cookies older than this are still accepted but refreshed.
const REFRESH_AFTER: u32 = 1800;
/// Allowed clock skew into the future.
const MAX_FUTURE: u32 = 300;

pub struct CookieJar {
    secret: [u8; 32],
}

pub enum CookieCheck {
    /// Malformed option (client cookie not 8 bytes, bad server cookie size): FORMERR.
    Malformed,
    /// Only a client cookie, or an invalid/expired server cookie: reply with a fresh one.
    Invalid(Vec<u8>),
    /// A valid server cookie; the reply carries the (possibly refreshed) cookie.
    Valid(Vec<u8>),
}

impl CookieJar {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        CookieJar { secret }
    }

    fn now() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    fn hash(&self, client: &[u8], ts: u32, ip: IpAddr) -> [u8; 8] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("any key length");
        mac.update(client);
        mac.update(&[VERSION, 0, 0, 0]);
        mac.update(&ts.to_be_bytes());
        match ip {
            IpAddr::V4(v) => mac.update(&v.octets()),
            IpAddr::V6(v) => mac.update(&v.octets()),
        }
        let out = mac.finalize().into_bytes();
        let mut h = [0u8; 8];
        h.copy_from_slice(&out[..8]);
        h
    }

    fn mint_at(&self, client: &[u8], ip: IpAddr, ts: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(client);
        out.extend_from_slice(&[VERSION, 0, 0, 0]);
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&self.hash(client, ts, ip));
        out
    }

    /// O15: the COOKIE option data carries a valid, unexpired server
    /// cookie for `ip`.
    pub fn is_valid(&self, data: &[u8], ip: IpAddr) -> bool {
        matches!(self.check(data, ip), CookieCheck::Valid(_))
    }

    /// Evaluate the COOKIE option data from a request.
    pub fn check(&self, data: &[u8], ip: IpAddr) -> CookieCheck {
        self.check_at(data, ip, Self::now())
    }

    fn check_at(&self, data: &[u8], ip: IpAddr, now: u32) -> CookieCheck {
        if data.len() < 8 || (data.len() > 8 && !(16..=40).contains(&data.len())) {
            return CookieCheck::Malformed;
        }
        let client = &data[..8];
        if data.len() == 8 {
            return CookieCheck::Invalid(self.mint_at(client, ip, now));
        }
        let server = &data[8..];
        if server.len() != 16 || server[0] != VERSION {
            return CookieCheck::Invalid(self.mint_at(client, ip, now));
        }
        let ts = u32::from_be_bytes([server[4], server[5], server[6], server[7]]);
        let age_ok = if ts <= now {
            now - ts <= MAX_AGE
        } else {
            ts - now <= MAX_FUTURE
        };
        if !age_ok || self.hash(client, ts, ip) != server[8..16] {
            return CookieCheck::Invalid(self.mint_at(client, ip, now));
        }
        if now.saturating_sub(ts) > REFRESH_AFTER {
            CookieCheck::Valid(self.mint_at(client, ip, now))
        } else {
            CookieCheck::Valid(data.to_vec())
        }
    }
}

/// EDNS option code of COOKIE (RFC 7873).
const OPTION_COOKIE: u16 = 10;
/// Record type of OPT.
const TYPE_OPT: u16 = 41;

/// O15: the COOKIE option data of a request, read straight from the wire
/// (no decode, no allocation): the OPT record in the additional section,
/// then its options. `None` for a malformed message or one without it.
pub fn find_option(msg: &[u8]) -> Option<&[u8]> {
    use super::tsig::{skip_name, u16_at};
    let qd = u16_at(msg, 4).ok()?;
    let an = u16_at(msg, 6).ok()? as usize;
    let ns = u16_at(msg, 8).ok()? as usize;
    let ar = u16_at(msg, 10).ok()? as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(msg, i).ok()? + 4;
    }
    for n in 0..an + ns + ar {
        let after_name = skip_name(msg, i).ok()?;
        let rtype = u16_at(msg, after_name).ok()?;
        let rdlen = u16_at(msg, after_name + 8).ok()? as usize;
        let rdata = after_name + 10;
        let next = rdata.checked_add(rdlen)?;
        if next > msg.len() {
            return None;
        }
        if rtype == TYPE_OPT && n >= an + ns {
            let mut o = rdata;
            while o + 4 <= next {
                let code = u16_at(msg, o).ok()?;
                let len = u16_at(msg, o + 2).ok()? as usize;
                let end = o + 4 + len;
                if end > next {
                    return None;
                }
                if code == OPTION_COOKIE {
                    return Some(&msg[o + 4..end]);
                }
                o = end;
            }
            return None;
        }
        i = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O15: the COOKIE option is found in a request built by hickory, with
    /// other options around it; absent, malformed or cut short: none.
    #[test]
    fn cookie_option_is_found_on_the_wire() {
        use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
        use hickory_proto::rr::{Name, RecordType};
        let cookie: Vec<u8> = (1..=24).collect();
        let mut m = Message::new(7, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(
            Name::from_ascii("www.example.").unwrap(),
            RecordType::A,
        ));
        let mut e = Edns::new();
        e.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::NSID), vec![]));
        e.options_mut()
            .insert(EdnsOption::Unknown(10, cookie.clone()));
        m.set_edns(e);
        let wire = m.to_vec().unwrap();
        assert_eq!(find_option(&wire), Some(&cookie[..]));
        for cut in [wire.len() - 1, wire.len() - 20, 14] {
            assert_eq!(find_option(&wire[..cut]), None, "cut at {cut}");
        }
        let mut plain = Message::new(7, MessageType::Query, OpCode::Query);
        plain.add_query(Query::query(
            Name::from_ascii("www.example.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(find_option(&plain.to_vec().unwrap()), None);
        plain.set_edns(Edns::new());
        assert_eq!(find_option(&plain.to_vec().unwrap()), None);
    }

    #[test]
    fn roundtrip_and_expiry() {
        let jar = CookieJar::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let CookieCheck::Invalid(fresh) = jar.check_at(&client, ip, 1000) else {
            panic!("client-only cookie should mint")
        };
        assert_eq!(fresh.len(), 24);
        assert!(matches!(
            jar.check_at(&fresh, ip, 1000),
            CookieCheck::Valid(_)
        ));
        // Different client IP invalidates.
        assert!(matches!(
            jar.check_at(&fresh, "203.0.113.10".parse().unwrap(), 1000),
            CookieCheck::Invalid(_)
        ));
        // Refreshed after 30 minutes, rejected after an hour.
        match jar.check_at(&fresh, ip, 1000 + 1801) {
            CookieCheck::Valid(c) => assert_ne!(c, fresh),
            _ => panic!(),
        }
        assert!(matches!(
            jar.check_at(&fresh, ip, 1000 + 3601),
            CookieCheck::Invalid(_)
        ));
        // Tampered hash.
        let mut bad = fresh.clone();
        bad[23] ^= 1;
        assert!(matches!(
            jar.check_at(&bad, ip, 1000),
            CookieCheck::Invalid(_)
        ));
        assert!(matches!(
            jar.check_at(&client[..5], ip, 1000),
            CookieCheck::Malformed
        ));
        assert!(matches!(
            jar.check_at(&[0u8; 12], ip, 1000),
            CookieCheck::Malformed
        ));
    }
}
