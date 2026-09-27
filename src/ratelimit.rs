//! Per-client query rate limiting with bounded memory.
//!
//! A fixed window counter per source IP, kept in an LRU map capped at
//! `max_tracked` entries. Under a flood from many addresses the oldest
//! entries are evicted, so memory never grows past the cap.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    window_start: Instant,
    count: u32,
    /// Generation stamp used for LRU bookkeeping.
    gen: u64,
}

struct Inner {
    map: HashMap<IpAddr, Entry>,
    /// (ip, gen) pairs in touch order; stale pairs are skipped on eviction.
    order: VecDeque<(IpAddr, u64)>,
    next_gen: u64,
}

pub struct RateLimiter {
    limit: std::sync::atomic::AtomicU32,
    window: Duration,
    max_tracked: std::sync::atomic::AtomicUsize,
    inner: Mutex<Inner>,
    pub dropped: std::sync::atomic::AtomicU64,
}

pub enum Decision {
    Allow,
    /// First rejection in this window for this client (worth logging).
    RejectFirst,
    Reject,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration, max_tracked: usize) -> Self {
        RateLimiter {
            limit: std::sync::atomic::AtomicU32::new(limit),
            window,
            max_tracked: std::sync::atomic::AtomicUsize::new(max_tracked.max(1)),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                next_gen: 0,
            }),
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Change limits at runtime (config reload).
    pub fn reconfigure(&self, limit: u32, max_tracked: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        self.limit.store(limit, Relaxed);
        self.max_tracked.store(max_tracked.max(1), Relaxed);
    }

    pub fn limit(&self) -> u32 {
        self.limit.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn max_tracked(&self) -> usize {
        self.max_tracked.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn check(&self, ip: IpAddr) -> Decision {
        self.check_at(ip, Instant::now())
    }

    pub fn check_at(&self, ip: IpAddr, now: Instant) -> Decision {
        let limit = self.limit();
        let max_tracked = self.max_tracked();
        if limit == 0 {
            return Decision::Allow;
        }
        let mut g = self.inner.lock().unwrap();
        let gen = g.next_gen;
        g.next_gen += 1;
        let Inner { map, order, .. } = &mut *g;
        let decision = match map.get_mut(&ip) {
            Some(e) => {
                if now.duration_since(e.window_start) >= self.window {
                    e.window_start = now;
                    e.count = 0;
                }
                e.count = e.count.saturating_add(1);
                e.gen = gen;
                if e.count <= limit {
                    Decision::Allow
                } else if e.count == limit + 1 {
                    Decision::RejectFirst
                } else {
                    Decision::Reject
                }
            }
            None => {
                map.insert(
                    ip,
                    Entry {
                        window_start: now,
                        count: 1,
                        gen,
                    },
                );
                Decision::Allow
            }
        };
        order.push_back((ip, gen));
        // Evict least-recently-touched entries beyond the cap; also keep the
        // order queue from growing without bound by discarding stale stamps.
        while map.len() > max_tracked || order.len() > max_tracked * 4 {
            match order.pop_front() {
                Some((old_ip, old_gen)) => {
                    if map.get(&old_ip).map(|e| e.gen == old_gen).unwrap_or(false) {
                        map.remove(&old_ip);
                    }
                }
                None => break,
            }
        }
        if !matches!(decision, Decision::Allow) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        decision
    }

    pub fn tracked(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(1), 10);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(matches!(rl.check_at(ip, t0), Decision::Allow));
        assert!(matches!(rl.check_at(ip, t0), Decision::Allow));
        assert!(matches!(rl.check_at(ip, t0), Decision::Allow));
        assert!(matches!(rl.check_at(ip, t0), Decision::RejectFirst));
        assert!(matches!(rl.check_at(ip, t0), Decision::Reject));
        assert!(matches!(
            rl.check_at(ip, t0 + Duration::from_secs(1)),
            Decision::Allow
        ));
        assert_eq!(rl.dropped.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn bounded_memory() {
        let rl = RateLimiter::new(100, Duration::from_secs(1), 50);
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(i));
            rl.check_at(ip, t0);
        }
        assert!(rl.tracked() <= 50);
        assert!(rl.inner.lock().unwrap().order.len() <= 200);
    }

    #[test]
    fn lru_keeps_active_clients() {
        let rl = RateLimiter::new(100, Duration::from_secs(1), 2);
        let t0 = Instant::now();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();
        rl.check_at(a, t0);
        rl.check_at(b, t0);
        rl.check_at(a, t0); // touch a: b is now least recent
        rl.check_at(c, t0); // evicts b
        let g = rl.inner.lock().unwrap();
        assert!(g.map.contains_key(&a));
        assert!(!g.map.contains_key(&b));
        assert!(g.map.contains_key(&c));
    }

    #[test]
    fn disabled() {
        let rl = RateLimiter::new(0, Duration::from_secs(1), 2);
        for _ in 0..1000 {
            assert!(matches!(
                rl.check("1.1.1.1".parse().unwrap()),
                Decision::Allow
            ));
        }
    }
}
