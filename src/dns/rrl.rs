//! O26: response rate limiting (RRL), after BIND's `rate-limit`.
//!
//! The per-client limiter ([`crate::ratelimit`]) counts queries per source.
//! A reflection attack sends queries with the victim's (spoofed) address,
//! each one modest, from many directions: the per-client limit sees one
//! busy "client" only if the attacker is careless. RRL counts identical
//! *responses* to one client network instead: the same answer (name and
//! type), the same NXDOMAIN for a zone (whatever random name was asked:
//! keyed by the zone, so random subdomains do not escape), the same
//! referral, or any error, sent to one IPv4 /24 (IPv6 /56) more than N
//! times a second. Over the limit a UDP response is dropped, except every
//! `slip`th, which is replaced by an empty truncated (TC=1) answer no
//! larger than the query, so a genuine client behind the spoofed address
//! retries over TCP and gets its answer.
//!
//! Never limited: TCP (the peer is real), TSIG-signed requests, queries
//! carrying a valid server cookie (RFC 7873: the address is proven), and
//! clients in `exempt`. Off by default (`responses_per_second = 0`);
//! configured per server in the file (`[rate_limit.rrl]`), not replicated.
//!
//! Counting reuses the bounded count-min sketch of the per-client limiter
//! (fixed memory, a flood cannot evict a counted tuple), with one-second
//! windows (BIND averages over `window` seconds; a one-second window reacts
//! faster and needs no state per tuple).

use crate::config::{Cidr, RrlConfig};
use crate::ratelimit::{Decision, RateLimiter};
use arc_swap::ArcSwapOption;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

/// The response classes counted separately (BIND's categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A non-empty answer: keyed by name and type.
    Answer,
    /// NOERROR without answers (NODATA): keyed by name and type.
    Nodata,
    /// NXDOMAIN: keyed by the zone (the SOA owner of the proof).
    Nxdomain,
    /// A delegation: keyed by the delegated name.
    Referral,
    /// Any other response code: one bucket per client network.
    Error,
}

/// The tuple a response is counted under (besides the client network).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub kind: Kind,
    pub name: Name,
    pub qtype: u16,
}

/// Classify a response. `None`: not counted (truncated, unparsable, or a
/// response that is not a query answer).
pub fn classify(resp: &Message) -> Option<Tuple> {
    if resp.metadata.truncation {
        return None;
    }
    let q = resp.queries.first()?;
    let qname = q.name().to_lowercase();
    let qtype = u16::from(q.query_type());
    let soa_owner = || {
        resp.authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .map(|r| r.name.to_lowercase())
    };
    let t = match resp.metadata.response_code {
        ResponseCode::NoError => {
            if !resp.answers.is_empty() {
                Tuple {
                    kind: Kind::Answer,
                    name: qname,
                    qtype,
                }
            } else if let (false, Some(ns)) = (
                resp.metadata.authoritative,
                resp.authorities
                    .iter()
                    .find(|r| r.record_type() == RecordType::NS),
            ) {
                Tuple {
                    kind: Kind::Referral,
                    name: ns.name.to_lowercase(),
                    qtype: u16::from(RecordType::NS),
                }
            } else {
                Tuple {
                    kind: Kind::Nodata,
                    name: qname,
                    qtype,
                }
            }
        }
        ResponseCode::NXDomain => Tuple {
            kind: Kind::Nxdomain,
            name: soa_owner().unwrap_or(qname),
            qtype: 0,
        },
        _ => Tuple {
            kind: Kind::Error,
            name: Name::root(),
            qtype: 0,
        },
    };
    Some(t)
}

/// The client network a response is counted for.
fn network(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            let p = v4.min(32) as u32;
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            IpAddr::V4((u32::from(a) & mask).into())
        }
        IpAddr::V6(a) => {
            let p = v6.min(128) as u32;
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            IpAddr::V6((u128::from(a) & mask).into())
        }
    }
}

fn key(net: IpAddr, t: &Tuple) -> u128 {
    let half = |seed: u64| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h);
        net.hash(&mut h);
        t.hash(&mut h);
        h.finish()
    };
    ((half(0x5252_4c31) as u128) << 64) | half(0x5252_4c32) as u128
}

struct Active {
    responses: u32,
    nxdomains: u32,
    errors: u32,
    v4: u8,
    v6: u8,
    exempt: Vec<Cidr>,
}

/// What to do with a response.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Send,
    /// Replace it with the empty truncated slip answer.
    Slip,
    Drop,
}

pub struct Rrl {
    active: ArcSwapOption<Active>,
    counts: RateLimiter,
    pub dropped: AtomicU64,
    pub slipped: AtomicU64,
    last_warn: AtomicU64,
}

impl Rrl {
    pub fn new(cfg: &RrlConfig) -> Self {
        let r = Rrl {
            active: ArcSwapOption::empty(),
            // The limit passed per check; this one is a placeholder.
            counts: RateLimiter::new(1, Duration::from_secs(1), cfg.max_tracked.max(1)),
            dropped: AtomicU64::new(0),
            slipped: AtomicU64::new(0),
            last_warn: AtomicU64::new(0),
        };
        r.configure(cfg);
        r
    }

    /// Apply the file's settings (startup and reload).
    pub fn configure(&self, cfg: &RrlConfig) {
        self.counts.reconfigure(1, cfg.max_tracked.max(1));
        self.counts.set_slip(cfg.slip);
        if cfg.responses_per_second == 0 {
            self.active.store(None);
            return;
        }
        self.active.store(Some(Arc::new(Active {
            responses: cfg.responses_per_second,
            nxdomains: cfg.nxdomains_per_second.unwrap_or(cfg.responses_per_second),
            errors: cfg.errors_per_second.unwrap_or(cfg.responses_per_second),
            v4: cfg.ipv4_prefix_length,
            v6: cfg.ipv6_prefix_length,
            exempt: crate::config::parse_cidrs(&cfg.exempt),
        })));
    }

    pub fn enabled(&self) -> bool {
        self.active.load().is_some()
    }

    /// Whether this client is never limited (an `exempt` network). Cheap;
    /// the caller checks it (and cookies) before decoding the response.
    pub fn exempt(&self, ip: IpAddr) -> bool {
        match &*self.active.load() {
            None => true,
            Some(a) => {
                let ip = ip.to_canonical();
                a.exempt.iter().any(|c| c.contains(ip))
            }
        }
    }

    /// Count one UDP response for `client`.
    pub fn check(&self, client: IpAddr, t: &Tuple) -> Verdict {
        let Some(a) = self.active.load_full() else {
            return Verdict::Send;
        };
        let limit = match t.kind {
            Kind::Nxdomain => a.nxdomains,
            Kind::Error => a.errors,
            _ => a.responses,
        };
        if limit == 0 {
            return Verdict::Send;
        }
        let net = network(client, a.v4, a.v6);
        match self.counts.check_key(key(net, t), limit) {
            Decision::Allow => Verdict::Send,
            d => {
                self.warn(net, t);
                // slip 1: every limited answer is truncated (the first too).
                if d == Decision::Slip || (d == Decision::RejectFirst && self.counts.slip() == 1) {
                    self.slipped.fetch_add(1, Relaxed);
                    Verdict::Slip
                } else {
                    self.dropped.fetch_add(1, Relaxed);
                    Verdict::Drop
                }
            }
        }
    }

    /// One warning a minute at most (a reflection attack limits many
    /// tuples every second).
    fn warn(&self, net: IpAddr, t: &Tuple) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_warn.load(Relaxed);
        if now >= last + 60
            && self
                .last_warn
                .compare_exchange(last, now, Relaxed, Relaxed)
                .is_ok()
        {
            tracing::warn!(client_network = %net, kind = ?t.kind, name = %t.name, "response rate limit exceeded (RRL); dropping or slipping identical responses (one warning a minute)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, NS, SOA};
    use hickory_proto::rr::{RData, Record};

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn resp(q: &str, t: RecordType, rcode: ResponseCode) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.authoritative = true;
        m.add_query(Query::query(name(q), t));
        m
    }

    fn soa(zone: &str) -> Record {
        Record::from_rdata(
            name(zone),
            300,
            RData::SOA(SOA::new(name("ns1.x."), name("h.x."), 1, 2, 3, 4, 5)),
        )
    }

    #[test]
    fn responses_are_classified_by_tuple() {
        let mut a = resp("WWW.Example.com.", RecordType::A, ResponseCode::NoError);
        a.add_answer(Record::from_rdata(
            name("www.example.com."),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let t = classify(&a).unwrap();
        assert_eq!(
            (t.kind, t.name.to_string(), t.qtype),
            (Kind::Answer, "www.example.com.".into(), 1)
        );

        // NXDOMAIN: keyed by the zone, whatever name was asked.
        let mut nx = resp("r4nd0m.example.com.", RecordType::A, ResponseCode::NXDomain);
        nx.add_authority(soa("example.com."));
        let t1 = classify(&nx).unwrap();
        let mut nx2 = resp(
            "other.example.com.",
            RecordType::AAAA,
            ResponseCode::NXDomain,
        );
        nx2.add_authority(soa("example.com."));
        assert_eq!(t1, classify(&nx2).unwrap());
        assert_eq!(t1.kind, Kind::Nxdomain);

        let mut nodata = resp("www.example.com.", RecordType::MX, ResponseCode::NoError);
        nodata.add_authority(soa("example.com."));
        assert_eq!(classify(&nodata).unwrap().kind, Kind::Nodata);

        let mut referral = resp("a.sub.example.com.", RecordType::A, ResponseCode::NoError);
        referral.metadata.authoritative = false;
        referral.add_authority(Record::from_rdata(
            name("sub.example.com."),
            60,
            RData::NS(NS(name("ns.sub.example.com."))),
        ));
        let t = classify(&referral).unwrap();
        assert_eq!(
            (t.kind, t.name.to_string()),
            (Kind::Referral, "sub.example.com.".into())
        );

        let e1 = classify(&resp("a.", RecordType::A, ResponseCode::Refused)).unwrap();
        let e2 = classify(&resp("b.", RecordType::MX, ResponseCode::ServFail)).unwrap();
        assert_eq!(e1, e2, "all errors share one bucket");

        let mut tc = a.clone();
        tc.metadata.truncation = true;
        assert!(classify(&tc).is_none(), "truncated answers are not counted");
    }

    #[test]
    fn networks_are_masked() {
        assert_eq!(
            network("192.0.2.77".parse().unwrap(), 24, 56),
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network("::ffff:192.0.2.77".parse().unwrap(), 24, 56),
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network("2001:db8:1:2ff::1".parse().unwrap(), 24, 56),
            "2001:db8:1:200::".parse::<IpAddr>().unwrap()
        );
    }

    fn on(rps: u32, slip: u32) -> RrlConfig {
        RrlConfig {
            responses_per_second: rps,
            slip,
            exempt: vec!["198.51.100.0/24".into()],
            ..Default::default()
        }
    }

    #[test]
    fn identical_responses_are_limited_with_slip_and_others_are_not() {
        let t = Tuple {
            kind: Kind::Answer,
            name: name("www.example.com."),
            qtype: 1,
        };
        let victim: IpAddr = "192.0.2.10".parse().unwrap();
        let off = Rrl::new(&RrlConfig::default());
        assert!(!off.enabled());
        assert!(
            (0..100).all(|_| off.check(victim, &t) == Verdict::Send),
            "off by default"
        );

        let r = Rrl::new(&on(3, 2));
        let v: Vec<Verdict> = (0..9).map(|_| r.check(victim, &t)).collect();
        use Verdict::*;
        assert_eq!(v, [Send, Send, Send, Drop, Slip, Drop, Slip, Drop, Slip]);
        assert_eq!((r.dropped.load(Relaxed), r.slipped.load(Relaxed)), (3, 3));
        // The same /24, another address: the same network.
        assert_eq!(r.check("192.0.2.200".parse().unwrap(), &t), Drop);
        // Another network, another name, another type: own budgets.
        assert_eq!(r.check("203.0.113.1".parse().unwrap(), &t), Send);
        let t2 = Tuple {
            qtype: 28,
            ..t.clone()
        };
        assert_eq!(r.check(victim, &t2), Send);
        assert!(r.exempt("198.51.100.9".parse().unwrap()));
        assert!(!r.exempt(victim));

        // slip 1: every limited answer is truncated; slip 0: all dropped.
        let r1 = Rrl::new(&on(1, 1));
        let v: Vec<Verdict> = (0..4).map(|_| r1.check(victim, &t)).collect();
        assert_eq!(v, [Send, Slip, Slip, Slip]);
        let r0 = Rrl::new(&on(1, 0));
        let v: Vec<Verdict> = (0..4).map(|_| r0.check(victim, &t)).collect();
        assert_eq!(v, [Send, Drop, Drop, Drop]);

        // Reconfigured off at runtime.
        r.configure(&RrlConfig::default());
        assert_eq!(r.check(victim, &t), Send);
    }
}
