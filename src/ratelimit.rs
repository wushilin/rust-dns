//! Per-client rate limiting with bounded memory that floods cannot reset.
//!
//! Clients are grouped by network prefix ([`client_key`]): an IPv4 address
//! counts on its own, an IPv6 address counts as its /64 (one customer
//! allocation), so rotating addresses inside a /64 gains nothing.
//!
//! Counts live in a fixed-size count-min sketch: `ROWS` tables of
//! `max_tracked` counters, each indexed by an independent keyed hash of the
//! prefix. A client's count is the minimum over its counters, so it is never
//! under-counted. Nothing is ever evicted: a flood from many (possibly
//! spoofed) sources cannot push a limited client out of the table and reset
//! its counter, as an LRU map could. The price is that colliding clients can
//! be over-counted; with the default table (2 x 10 000 counters) that needs
//! millions of queries per second spread across the table.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Independent hash rows in the sketch.
const ROWS: usize = 2;

/// The rate-limited unit for an address: the IPv4 address itself, or the
/// /64 prefix of an IPv6 address. IPv4-mapped IPv6 counts as IPv4.
pub fn client_key(ip: IpAddr) -> u128 {
    match ip.to_canonical() {
        IpAddr::V4(v4) => u32::from(v4) as u128 | (1u128 << 64),
        IpAddr::V6(v6) => (u128::from(v6) >> 64) | (2u128 << 64),
    }
}

#[derive(Clone, Copy, Default)]
struct Counter {
    window: u64,
    count: u32,
}

struct Sketch {
    width: usize,
    rows: Vec<Counter>,
    keys: [(u64, u64); ROWS],
}

impl Sketch {
    fn new(width: usize) -> Self {
        let width = width.max(1);
        Sketch {
            width,
            rows: vec![Counter::default(); width * ROWS],
            keys: std::array::from_fn(|_| (rand::random(), rand::random())),
        }
    }

    fn index(&self, row: usize, key: u128) -> usize {
        use std::hash::{BuildHasher, Hasher};
        let (k0, k1) = self.keys[row];
        let mut h =
            std::hash::BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default()
                .build_hasher();
        h.write_u64(k0);
        h.write_u128(key);
        h.write_u64(k1);
        row * self.width + (h.finish() % self.width as u64) as usize
    }
}

pub struct RateLimiter {
    limit: AtomicU32,
    window: Duration,
    max_tracked: AtomicUsize,
    /// Every Nth limited UDP response is answered truncated instead of
    /// dropped (0 = always drop).
    slip: AtomicU32,
    started: Instant,
    inner: Mutex<Sketch>,
    pub dropped: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// First rejection in this window for this client (worth logging).
    RejectFirst,
    Reject,
    /// Over the limit, but answer with an empty truncated response so a
    /// real client behind a spoofed flood can retry over TCP.
    Slip,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        *self == Decision::Allow
    }
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration, max_tracked: usize) -> Self {
        RateLimiter {
            limit: AtomicU32::new(limit),
            window,
            max_tracked: AtomicUsize::new(max_tracked.max(1)),
            slip: AtomicU32::new(0),
            started: Instant::now(),
            inner: Mutex::new(Sketch::new(max_tracked)),
            dropped: AtomicU64::new(0),
        }
    }

    /// Change limits at runtime (config reload). A new table size starts
    /// empty.
    pub fn reconfigure(&self, limit: u32, max_tracked: usize) {
        self.limit.store(limit, Relaxed);
        let max_tracked = max_tracked.max(1);
        if self.max_tracked.swap(max_tracked, Relaxed) != max_tracked {
            *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = Sketch::new(max_tracked);
        }
    }

    pub fn set_slip(&self, slip: u32) {
        self.slip.store(slip, Relaxed);
    }

    pub fn slip(&self) -> u32 {
        self.slip.load(Relaxed)
    }

    pub fn limit(&self) -> u32 {
        self.limit.load(Relaxed)
    }

    pub fn max_tracked(&self) -> usize {
        self.max_tracked.load(Relaxed)
    }

    pub fn check(&self, ip: IpAddr) -> Decision {
        self.check_at(ip, Instant::now())
    }

    fn window_of(&self, now: Instant) -> u64 {
        let w = self.window.as_millis().max(1);
        (now.saturating_duration_since(self.started).as_millis() / w) as u64 + 1
    }

    pub fn check_at(&self, ip: IpAddr, now: Instant) -> Decision {
        let limit = self.limit();
        if limit == 0 {
            return Decision::Allow;
        }
        let window = self.window_of(now);
        let key = client_key(ip);
        let estimate = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut min = u32::MAX;
            for row in 0..ROWS {
                let i = g.index(row, key);
                let c = &mut g.rows[i];
                if c.window != window {
                    *c = Counter { window, count: 0 };
                }
                c.count = c.count.saturating_add(1);
                min = min.min(c.count);
            }
            min
        };
        if estimate <= limit {
            return Decision::Allow;
        }
        self.dropped.fetch_add(1, Relaxed);
        let over = estimate - limit;
        let slip = self.slip.load(Relaxed);
        if over == 1 {
            Decision::RejectFirst
        } else if slip > 0 && over.is_multiple_of(slip) {
            Decision::Slip
        } else {
            Decision::Reject
        }
    }

    /// Counters in use in the current window (an upper bound on the number
    /// of distinct clients seen in it).
    pub fn tracked(&self) -> usize {
        let window = self.window_of(Instant::now());
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.rows[..g.width]
            .iter()
            .filter(|c| c.window == window && c.count > 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(1), 10);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = rl.started + Duration::from_millis(10);
        assert_eq!(rl.check_at(ip, t0), Decision::Allow);
        assert_eq!(rl.check_at(ip, t0), Decision::Allow);
        assert_eq!(rl.check_at(ip, t0), Decision::Allow);
        assert_eq!(rl.check_at(ip, t0), Decision::RejectFirst);
        assert_eq!(rl.check_at(ip, t0), Decision::Reject);
        assert_eq!(
            rl.check_at(ip, t0 + Duration::from_secs(1)),
            Decision::Allow
        );
        assert_eq!(rl.dropped.load(Relaxed), 2);
    }

    #[test]
    fn bounded_memory() {
        let rl = RateLimiter::new(100, Duration::from_secs(1), 50);
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            rl.check_at(IpAddr::from(std::net::Ipv4Addr::from(i)), t0);
        }
        assert_eq!(rl.inner.lock().unwrap().rows.len(), 50 * ROWS);
        assert!(rl.tracked() <= 50);
    }

    /// M2 regression: with the old LRU map a flood from many random sources
    /// evicted a limited client's entry and reset its counter.
    #[test]
    fn random_source_flood_does_not_reset_a_limited_client() {
        let rl = RateLimiter::new(5, Duration::from_secs(1), 1000);
        let t0 = rl.started + Duration::from_millis(10);
        let victim: IpAddr = "198.51.100.7".parse().unwrap();
        for _ in 0..6 {
            rl.check_at(victim, t0);
        }
        assert_ne!(rl.check_at(victim, t0), Decision::Allow);
        // 50 000 distinct sources (50x the table size), one query each.
        for i in 0..50_000u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            rl.check_at(ip, t0);
        }
        assert_ne!(
            rl.check_at(victim, t0),
            Decision::Allow,
            "the flood must not reset the limited client's counter"
        );
    }

    /// M2 regression: every address of an IPv6 /64 shares one budget.
    #[test]
    fn ipv6_is_limited_per_slash_64() {
        let rl = RateLimiter::new(10, Duration::from_secs(60), 100);
        let t0 = rl.started + Duration::from_millis(10);
        let mut allowed = 0;
        for i in 0..100u128 {
            let ip = IpAddr::from(std::net::Ipv6Addr::from(
                0x2001_0db8_0000_0001_0000_0000_0000_0000u128 + i * 0x1_0000_0001,
            ));
            if rl.check_at(ip, t0).allowed() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "100 addresses in one /64 share 10 attempts");
        // A different /64 has its own budget.
        let other: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        assert!(rl.check_at(other, t0).allowed());
        // IPv4 keeps per-address limits; IPv4-mapped IPv6 is the same client.
        assert_eq!(
            client_key("192.0.2.1".parse().unwrap()),
            client_key("::ffff:192.0.2.1".parse().unwrap())
        );
        assert_ne!(
            client_key("192.0.2.1".parse().unwrap()),
            client_key("192.0.2.2".parse().unwrap())
        );
    }

    #[test]
    fn slip_answers_every_nth_limited_query() {
        let rl = RateLimiter::new(2, Duration::from_secs(1), 100);
        rl.set_slip(2);
        let t0 = rl.started + Duration::from_millis(10);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let got: Vec<Decision> = (0..8).map(|_| rl.check_at(ip, t0)).collect();
        assert_eq!(
            got,
            vec![
                Decision::Allow,
                Decision::Allow,
                Decision::RejectFirst,
                Decision::Slip,
                Decision::Reject,
                Decision::Slip,
                Decision::Reject,
                Decision::Slip,
            ]
        );
    }

    #[test]
    fn disabled() {
        let rl = RateLimiter::new(0, Duration::from_secs(1), 2);
        for _ in 0..1000 {
            assert!(rl.check("1.1.1.1".parse().unwrap()).allowed());
        }
    }
}
