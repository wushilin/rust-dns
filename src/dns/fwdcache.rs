//! TTL-aware LRU cache for forwarded answers.

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Key {
    name: String,
    qtype: RecordType,
    class: DNSClass,
    dnssec_ok: bool,
}

impl Key {
    pub fn new(name: &Name, qtype: RecordType, class: DNSClass, dnssec_ok: bool) -> Self {
        Key {
            name: crate::zones::key_of(name),
            qtype,
            class,
            dnssec_ok,
        }
    }
}

struct Entry {
    message: Message,
    stored: Instant,
    ttl: u32,
}

pub struct ForwardCache {
    inner: Mutex<LruCache<Key, Entry>>,
    pub hits: std::sync::atomic::AtomicU64,
    pub misses: std::sync::atomic::AtomicU64,
}

impl ForwardCache {
    pub fn new(entries: usize) -> Self {
        let cap = NonZeroUsize::new(entries.max(1)).unwrap();
        ForwardCache {
            inner: Mutex::new(LruCache::new(cap)),
            hits: Default::default(),
            misses: Default::default(),
        }
    }

    /// Cache a response. TTL = smallest record TTL; negative answers use the
    /// SOA MINIMUM from the authority section (RFC 2308 §5), capped at one day.
    pub fn store(&self, key: Key, message: &Message) {
        let mut ttl: Option<u32> = None;
        for r in message
            .answers()
            .iter()
            .chain(message.name_servers())
            .chain(message.additionals())
        {
            if r.record_type() == RecordType::OPT {
                continue;
            }
            ttl = Some(ttl.map_or(r.ttl(), |t| t.min(r.ttl())));
        }
        if message.answers().is_empty() {
            if let Some(hickory_proto::rr::RData::SOA(soa)) = message
                .name_servers()
                .iter()
                .find(|r| r.record_type() == RecordType::SOA)
                .map(|r| r.data())
            {
                ttl = Some(ttl.map_or(soa.minimum(), |t| t.min(soa.minimum())));
            }
        }
        let Some(ttl) = ttl else { return };
        let ttl = ttl.min(86_400);
        if ttl == 0 {
            return;
        }
        self.inner.lock().unwrap().put(
            key,
            Entry {
                message: message.clone(),
                stored: Instant::now(),
                ttl,
            },
        );
    }

    /// Fetch a still-valid response with TTLs decremented by the time in cache.
    pub fn get(&self, key: &Key) -> Option<Message> {
        use std::sync::atomic::Ordering::Relaxed;
        let mut g = self.inner.lock().unwrap();
        let Some(e) = g.get(key) else {
            self.misses.fetch_add(1, Relaxed);
            return None;
        };
        let age = e.stored.elapsed().as_secs() as u32;
        if age >= e.ttl {
            g.pop(key);
            self.misses.fetch_add(1, Relaxed);
            return None;
        }
        self.hits.fetch_add(1, Relaxed);
        let mut m = e.message.clone();
        let adjust = |records: &mut Vec<hickory_proto::rr::Record>| {
            for r in records.iter_mut() {
                if r.record_type() != RecordType::OPT {
                    r.set_ttl(r.ttl().saturating_sub(age));
                }
            }
        };
        adjust(m.answers_mut());
        adjust(m.name_servers_mut());
        adjust(m.additionals_mut());
        Some(m)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}
