//! TTL-aware LRU cache for forwarded answers.
//!
//! How long an answer is kept:
//! * positive answers: the lowest TTL of any record in the response, capped
//!   at `[forwarding].cache_max_ttl`;
//! * negative answers (NXDOMAIN, or NOERROR without answers): the lower of
//!   the SOA MINIMUM and the SOA record's TTL (RFC 2308 §5), capped at
//!   `cache_negative_max_ttl`; without an SOA they are not cached.
//!
//! Upstream TTLs are never raised. The caps in effect are applied again on
//! every hit, so lowering a cap at runtime (reload, console) takes effect
//! for entries already cached: none is served past the new cap, and the
//! TTLs handed out never exceed it. The number of entries is bounded
//! (`cache_entries`, least recently used evicted first); an expired entry is
//! dropped when it is next looked up, or evicted like any other.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct Key {
    name: String,
    qtype: RecordType,
    class: DNSClass,
    dnssec_ok: bool,
    /// What else the answer depends on: 0 for the global upstreams; a hash
    /// of the upstream set for an override zone, of the client subnet sent
    /// with EDNS Client Subnet.
    scope: u64,
}

impl Key {
    pub fn new(name: &Name, qtype: RecordType, class: DNSClass, dnssec_ok: bool) -> Self {
        Key {
            name: crate::zones::key_of(name),
            qtype,
            class,
            dnssec_ok,
            scope: 0,
        }
    }

    /// The same question in another scope (see the field).
    pub fn scoped(mut self, scope: u64) -> Self {
        self.scope = scope;
        self
    }
}

/// The TTL caps in effect (seconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub max_ttl: u32,
    pub negative_max_ttl: u32,
    /// Serve stale (RFC 8767): how long past its expiry an entry is kept
    /// for [`ForwardCache::get_stale`]; 0 = off (expired entries are
    /// dropped when looked up).
    pub stale_secs: u32,
}

/// TTL of a stale answer (RFC 8767 §4).
pub const STALE_TTL: u32 = 30;

struct Entry {
    message: Message,
    stored: Instant,
    /// Lifetime from the response itself (before any cap).
    ttl: u32,
    negative: bool,
}

impl Entry {
    fn lifetime(&self, caps: Caps) -> u32 {
        let cap = if self.negative {
            caps.negative_max_ttl
        } else {
            caps.max_ttl
        };
        self.ttl.min(cap)
    }
}

pub struct ForwardCache {
    capacity: usize,
    inner: Mutex<LruCache<Key, Entry>>,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

/// Cache size and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
}

/// The response's own lifetime and whether it is negative; `None` when it
/// must not be cached.
fn response_ttl(message: &Message) -> Option<(u32, bool)> {
    let negative =
        message.answers.is_empty() || message.metadata.response_code == ResponseCode::NXDomain;
    if negative {
        // RFC 2308 §5: min(SOA MINIMUM, SOA TTL); no SOA, no caching.
        return message
            .authorities
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) => Some(soa.minimum.min(r.ttl)),
                _ => None,
            })
            .map(|t| (t, true));
    }
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| r.ttl)
        .min()
        .map(|t| (t, false))
}

impl ForwardCache {
    pub fn new(entries: usize) -> Self {
        let capacity = entries.max(1);
        ForwardCache {
            capacity,
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            hits: Default::default(),
            misses: Default::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruCache<Key, Entry>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Cache a response for its own TTL, within the caps.
    pub fn store(&self, key: Key, message: &Message, caps: Caps) {
        self.store_at(key, message, caps, Instant::now())
    }

    fn store_at(&self, key: Key, message: &Message, caps: Caps, now: Instant) {
        let Some((ttl, negative)) = response_ttl(message) else {
            return;
        };
        let entry = Entry {
            message: message.clone(),
            stored: now,
            ttl,
            negative,
        };
        if entry.lifetime(caps) == 0 {
            return;
        }
        self.lock().put(key, entry);
    }

    /// Fetch a still-valid response. Record TTLs are counted down by the
    /// time in cache and never exceed the remaining (capped) lifetime.
    pub fn get(&self, key: &Key, caps: Caps) -> Option<Message> {
        self.get_at(key, caps, Instant::now())
    }

    fn get_at(&self, key: &Key, caps: Caps, now: Instant) -> Option<Message> {
        let mut g = self.lock();
        let Some(e) = g.get(key) else {
            self.misses.fetch_add(1, Relaxed);
            return None;
        };
        let age = now.saturating_duration_since(e.stored).as_secs() as u32;
        let lifetime = e.lifetime(caps);
        if age >= lifetime {
            // Kept while it may still be served stale.
            if caps.stale_secs == 0 || age >= lifetime.saturating_add(caps.stale_secs) {
                g.pop(key);
            }
            self.misses.fetch_add(1, Relaxed);
            return None;
        }
        self.hits.fetch_add(1, Relaxed);
        let remaining = lifetime - age;
        let mut m = e.message.clone();
        let adjust = |records: &mut Vec<hickory_proto::rr::Record>| {
            for r in records.iter_mut() {
                if r.record_type() != RecordType::OPT {
                    r.ttl = r.ttl.saturating_sub(age).min(remaining);
                }
            }
        };
        adjust(&mut m.answers);
        adjust(&mut m.authorities);
        adjust(&mut m.additionals);
        Some(m)
    }

    /// An expired entry within the stale window (RFC 8767), every TTL set
    /// to [`STALE_TTL`]; for when every upstream failed.
    pub fn get_stale(&self, key: &Key, caps: Caps) -> Option<Message> {
        self.get_stale_at(key, caps, Instant::now())
    }

    fn get_stale_at(&self, key: &Key, caps: Caps, now: Instant) -> Option<Message> {
        if caps.stale_secs == 0 {
            return None;
        }
        let g = self.lock();
        let e = g.peek(key)?;
        let age = now.saturating_duration_since(e.stored).as_secs() as u32;
        if age >= e.lifetime(caps).saturating_add(caps.stale_secs) {
            return None;
        }
        let mut m = e.message.clone();
        for r in m
            .answers
            .iter_mut()
            .chain(m.authorities.iter_mut())
            .chain(m.additionals.iter_mut())
        {
            if r.record_type() != RecordType::OPT {
                r.ttl = STALE_TTL;
            }
        }
        Some(m)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Drop every entry; returns how many there were.
    pub fn clear(&self) -> usize {
        let mut g = self.lock();
        let n = g.len();
        g.clear();
        n
    }

    pub fn stats(&self) -> Stats {
        Stats {
            entries: self.len(),
            capacity: self.capacity,
            hits: self.hits.load(Relaxed),
            misses: self.misses.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::Record;
    use std::time::Duration;

    const CAPS: Caps = Caps {
        max_ttl: 86_400,
        negative_max_ttl: 3_600,
        stale_secs: 0,
    };

    fn name(n: &str) -> Name {
        Name::from_ascii(n).unwrap()
    }

    fn key(n: &str) -> Key {
        Key::new(&name(n), RecordType::A, DNSClass::IN, false)
    }

    fn positive(n: &str, ttls: &[u32]) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        for (i, t) in ttls.iter().enumerate() {
            m.add_answer(Record::from_rdata(
                name(n),
                *t,
                RData::A(A::new(192, 0, 2, i as u8)),
            ));
        }
        m
    }

    fn negative(soa_ttl: u32, minimum: u32) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        m.add_authority(Record::from_rdata(
            name("example."),
            soa_ttl,
            RData::SOA(SOA::new(
                name("ns.example."),
                name("host.example."),
                1,
                3600,
                600,
                86400,
                minimum,
            )),
        ));
        m
    }

    fn ttls(m: &Message) -> Vec<u32> {
        m.answers
            .iter()
            .chain(&m.authorities)
            .map(|r| r.ttl)
            .collect()
    }

    #[test]
    fn positive_ttl_is_the_lowest_record_ttl_within_the_cap() {
        let c = ForwardCache::new(10);
        let t0 = Instant::now();
        c.store_at(key("a."), &positive("a.", &[300, 120]), CAPS, t0);
        let caps = Caps {
            max_ttl: 100,
            negative_max_ttl: 50,
            stale_secs: 0,
        };
        c.store_at(key("b."), &positive("b.", &[3600]), caps, t0);
        // a: lives 120 s (lowest record TTL), never raised.
        assert!(c
            .get_at(&key("a."), CAPS, t0 + Duration::from_secs(119))
            .is_some());
        assert!(c
            .get_at(&key("a."), CAPS, t0 + Duration::from_secs(120))
            .is_none());
        // b: capped at 100 s; handed-out TTLs never above what is left.
        let m = c
            .get_at(&key("b."), caps, t0 + Duration::from_secs(30))
            .unwrap();
        assert_eq!(ttls(&m), vec![70]);
        assert!(c
            .get_at(&key("b."), caps, t0 + Duration::from_secs(100))
            .is_none());
    }

    #[test]
    fn negative_ttl_is_min_of_soa_minimum_soa_ttl_and_cap() {
        let c = ForwardCache::new(10);
        let t0 = Instant::now();
        c.store_at(key("n1."), &negative(900, 300), CAPS, t0); // min 300
        c.store_at(key("n2."), &negative(120, 3000), CAPS, t0); // soa ttl 120
        c.store_at(key("n3."), &negative(86400, 86400), CAPS, t0); // cap 3600
        let at = |k: &str, s: u64| c.get_at(&key(k), CAPS, t0 + Duration::from_secs(s));
        assert!(at("n1.", 299).is_some() && at("n1.", 300).is_none());
        assert!(at("n2.", 119).is_some() && at("n2.", 120).is_none());
        let m = at("n3.", 600).unwrap();
        assert_eq!(ttls(&m), vec![3000], "never above the negative cap");
        assert!(at("n3.", 3600).is_none());
        // A negative answer without SOA is not cached.
        let mut bare = Message::new(1, MessageType::Response, OpCode::Query);
        bare.metadata.response_code = ResponseCode::NXDomain;
        c.store_at(key("n4."), &bare, CAPS, t0);
        assert!(at("n4.", 0).is_none());
    }

    #[test]
    fn lowering_a_cap_at_runtime_applies_to_cached_entries() {
        let c = ForwardCache::new(10);
        let t0 = Instant::now();
        c.store_at(key("a."), &positive("a.", &[86_400]), CAPS, t0);
        let lowered = Caps {
            max_ttl: 60,
            negative_max_ttl: 60,
            stale_secs: 0,
        };
        let m = c
            .get_at(&key("a."), lowered, t0 + Duration::from_secs(10))
            .unwrap();
        assert_eq!(ttls(&m), vec![50]);
        assert!(
            c.get_at(&key("a."), lowered, t0 + Duration::from_secs(60))
                .is_none(),
            "not served past the new cap"
        );
        // Raising the cap again does not resurrect or extend anything
        // beyond the response's own TTL.
        c.store_at(key("b."), &positive("b.", &[200]), lowered, t0);
        let m = c
            .get_at(&key("b."), CAPS, t0 + Duration::from_secs(100))
            .unwrap();
        assert_eq!(ttls(&m), vec![100]);
    }

    #[test]
    fn ttl_counts_down_on_hits_and_never_exceeds_the_cap() {
        let c = ForwardCache::new(10);
        let t0 = Instant::now();
        let caps = Caps {
            max_ttl: 300,
            negative_max_ttl: 60,
            stale_secs: 0,
        };
        c.store_at(key("a."), &positive("a.", &[1000, 250]), caps, t0);
        for s in [0u64, 1, 100, 249] {
            let m = c
                .get_at(&key("a."), caps, t0 + Duration::from_secs(s))
                .unwrap();
            for t in ttls(&m) {
                assert!(t as u64 <= 250 - s, "at {s}s got ttl {t}");
            }
        }
    }

    /// I5: with serve-stale on, an expired entry stays (a miss for normal
    /// lookups) and is served stale with TTL 30 until the stale window ends;
    /// with it off, nothing stale is kept. Scopes do not mix.
    #[test]
    fn expired_entries_are_served_stale_within_the_window() {
        let c = ForwardCache::new(10);
        let t0 = Instant::now();
        let stale = Caps {
            stale_secs: 600,
            ..CAPS
        };
        c.store_at(key("a."), &positive("a.", &[100]), stale, t0);
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert!(
            c.get_stale_at(&key("a."), stale, at(50)).is_some(),
            "not expired yet is fine too"
        );
        assert!(
            c.get_at(&key("a."), stale, at(100)).is_none(),
            "expired: a miss"
        );
        let m = c.get_stale_at(&key("a."), stale, at(300)).unwrap();
        assert_eq!(ttls(&m), vec![STALE_TTL]);
        assert!(
            c.get_stale_at(&key("a."), stale, at(700)).is_none(),
            "past the window"
        );
        assert!(c.get_at(&key("a."), stale, at(700)).is_none());
        assert!(
            c.get_stale_at(&key("a."), stale, at(300)).is_none(),
            "dropped after the window"
        );
        // Off: the expired entry is dropped at the first lookup.
        c.store_at(key("b."), &positive("b.", &[100]), CAPS, t0);
        assert!(c.get_at(&key("b."), CAPS, at(100)).is_none());
        assert!(c.get_stale_at(&key("b."), stale, at(101)).is_none());
        // Scope: another upstream set is another entry.
        c.store_at(key("s.").scoped(7), &positive("s.", &[100]), CAPS, t0);
        assert!(c.get_at(&key("s."), CAPS, t0).is_none());
        assert!(c.get_at(&key("s.").scoped(7), CAPS, t0).is_some());
    }

    #[test]
    fn lru_evicts_at_capacity_and_flush_counts() {
        let c = ForwardCache::new(2);
        let t0 = Instant::now();
        c.store_at(key("a."), &positive("a.", &[300]), CAPS, t0);
        c.store_at(key("b."), &positive("b.", &[300]), CAPS, t0);
        assert!(c.get_at(&key("a."), CAPS, t0).is_some()); // a is now most recent
        c.store_at(key("c."), &positive("c.", &[300]), CAPS, t0); // evicts b
        assert!(c.get_at(&key("b."), CAPS, t0).is_none());
        assert!(c.get_at(&key("a."), CAPS, t0).is_some());
        assert!(c.get_at(&key("c."), CAPS, t0).is_some());
        let st = c.stats();
        assert_eq!((st.entries, st.capacity), (2, 2));
        assert_eq!((st.hits, st.misses), (3, 1));
        assert_eq!(c.clear(), 2);
        assert_eq!(c.len(), 0);
    }
}
