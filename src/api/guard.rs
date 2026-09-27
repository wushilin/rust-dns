//! Failed sign-in bookkeeping (in memory; a restart forgets it).
//!
//! Three independent brakes, on top of the per-client request rate limit:
//!
//! * **Per account and client network** (IPv4 address / IPv6 /64): after
//!   `login_backoff_after` failures (default [`FREE_PER_CLIENT`]), each further failure doubles a wait
//!   (1 s, 2 s, 4 s, ... up to [`MAX_CLIENT_DELAY`]). One attacker network
//!   is slowed to a crawl against one account.
//! * **Per account, from anywhere**: after four times as many failures
//!   (default 20) the
//!   same doubling applies, capped at only [`MAX_ACCOUNT_DELAY`]. A
//!   distributed attack gets at most about one guess per minute per
//!   account, while the real user is never locked out for more than that
//!   minute (the account is never disabled).
//! * **Per session**: a session waiting for a TOTP / recovery code, or a
//!   signed-in session asked for its code (disable MFA, new recovery codes,
//!   re-enrollment) gets [`MAX_CODE_ATTEMPTS`] wrong codes; then the session
//!   is deleted and the user must sign in again.
//!
//! While a wait is in effect attempts are refused with 429 before any
//! password or code is checked, so refusals reveal nothing. Failures older
//! than [`FORGET_AFTER`] are forgotten; a successful sign-in clears the
//! caller's own per-network counter (not the account-wide one).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Defaults; the per-network value is `[web_console].login_backoff_after`
/// and the account-wide one four times that.
pub const FREE_PER_CLIENT: u32 = 5;
pub const MAX_CLIENT_DELAY: Duration = Duration::from_secs(15 * 60);
pub const MAX_ACCOUNT_DELAY: Duration = Duration::from_secs(60);
pub const MAX_CODE_ATTEMPTS: u32 = 5;
pub const FORGET_AFTER: Duration = Duration::from_secs(30 * 60);
/// Upper bound on tracked accounts / (account, network) pairs / sessions.
const MAX_ENTRIES: usize = 20_000;

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    last: Instant,
    blocked_until: Instant,
}

fn backoff(count: u32, free: u32, cap: Duration) -> Duration {
    if count <= free {
        return Duration::ZERO;
    }
    let exp = (count - free - 1).min(20);
    Duration::from_secs(1u64 << exp).min(cap)
}

#[derive(Default)]
struct Table<K: std::hash::Hash + Eq + Clone> {
    map: HashMap<K, Failures>,
}

impl<K: std::hash::Hash + Eq + Clone> Table<K> {
    fn blocked(&self, k: &K, now: Instant) -> Option<Duration> {
        let f = self.map.get(k)?;
        (f.blocked_until > now).then(|| f.blocked_until - now)
    }

    fn fail(&mut self, k: K, now: Instant, free: u32, cap: Duration) -> u32 {
        if self.map.len() >= MAX_ENTRIES && !self.map.contains_key(&k) {
            self.shrink(now);
        }
        let f = self.map.entry(k).or_insert(Failures {
            count: 0,
            last: now,
            blocked_until: now,
        });
        if now.duration_since(f.last) > FORGET_AFTER {
            f.count = 0;
        }
        f.count = f.count.saturating_add(1);
        f.last = now;
        f.blocked_until = now + backoff(f.count, free, cap);
        f.count
    }

    /// Make room without resetting anyone under attack: forget stale
    /// entries first, then those with the fewest failures.
    fn shrink(&mut self, now: Instant) {
        self.map
            .retain(|_, f| now.duration_since(f.last) <= FORGET_AFTER && f.blocked_until > now);
        if self.map.len() >= MAX_ENTRIES {
            let mut counts: Vec<u32> = self.map.values().map(|f| f.count).collect();
            counts.sort_unstable();
            let cut = counts[counts.len() / 2];
            self.map.retain(|_, f| f.count > cut);
        }
    }

    fn clear(&mut self, k: &K) {
        self.map.remove(k);
    }
}

#[derive(Default)]
struct Inner {
    per_client: Table<(String, u128)>,
    per_account: Table<String>,
    codes: HashMap<i64, (u32, Instant)>,
}

pub struct AttemptGuard {
    inner: Mutex<Inner>,
    free_client: u32,
    free_account: u32,
}

impl Default for AttemptGuard {
    fn default() -> Self {
        Self::new(FREE_PER_CLIENT)
    }
}

impl AttemptGuard {
    /// `free` failures per account and network before waits start; the
    /// account as a whole gets `4 * free`.
    pub fn new(free: u32) -> Self {
        AttemptGuard {
            inner: Mutex::new(Inner::default()),
            free_client: free,
            free_account: free.saturating_mul(4),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How long `username` must wait before another attempt from `ip`.
    pub fn wait(&self, username: &str, ip: IpAddr) -> Option<Duration> {
        self.wait_at(username, ip, Instant::now())
    }

    pub fn wait_at(&self, username: &str, ip: IpAddr, now: Instant) -> Option<Duration> {
        let g = self.lock();
        let a = g.per_account.blocked(&username.to_string(), now);
        let c = g.per_client.blocked(
            &(username.to_string(), crate::ratelimit::client_key(ip)),
            now,
        );
        a.max(c)
    }

    /// Record a failed password or code for `username` from `ip`.
    pub fn failure(&self, username: &str, ip: IpAddr) {
        self.failure_at(username, ip, Instant::now())
    }

    pub fn failure_at(&self, username: &str, ip: IpAddr, now: Instant) {
        let (free_client, free_account) = (self.free_client, self.free_account);
        let mut g = self.lock();
        g.per_client.fail(
            (username.to_string(), crate::ratelimit::client_key(ip)),
            now,
            free_client,
            MAX_CLIENT_DELAY,
        );
        let n = g
            .per_account
            .fail(username.to_string(), now, free_account, MAX_ACCOUNT_DELAY);
        if n == free_account + 1 {
            tracing::warn!(user = %username, "repeated failed sign-ins for this account; slowing down attempts from every address");
        }
    }

    /// A successful sign-in clears this network's counter for the account.
    pub fn success(&self, username: &str, ip: IpAddr) {
        self.lock()
            .per_client
            .clear(&(username.to_string(), crate::ratelimit::client_key(ip)));
    }

    /// Count a wrong code on `session_id`. Returns true when the session has
    /// used up its attempts and must be deleted.
    pub fn code_failure(&self, session_id: i64) -> bool {
        let now = Instant::now();
        let mut g = self.lock();
        if g.codes.len() >= MAX_ENTRIES && !g.codes.contains_key(&session_id) {
            g.codes
                .retain(|_, (_, at)| now.duration_since(*at) <= FORGET_AFTER);
        }
        let e = g.codes.entry(session_id).or_insert((0, now));
        e.0 += 1;
        e.1 = now;
        let exhausted = e.0 >= MAX_CODE_ATTEMPTS;
        if exhausted {
            g.codes.remove(&session_id);
        }
        exhausted
    }

    /// A correct code resets the session's counter.
    pub fn code_success(&self, session_id: i64) {
        self.lock().codes.remove(&session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_network_backoff_grows_and_is_scoped() {
        let g = AttemptGuard::default();
        let t0 = Instant::now();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..FREE_PER_CLIENT {
            g.failure_at("alice", ip, t0);
            assert!(g.wait_at("alice", ip, t0).is_none(), "free attempts");
        }
        g.failure_at("alice", ip, t0);
        assert_eq!(g.wait_at("alice", ip, t0), Some(Duration::from_secs(1)));
        g.failure_at("alice", ip, t0);
        assert_eq!(g.wait_at("alice", ip, t0), Some(Duration::from_secs(2)));
        // Another network, and another account, are unaffected.
        assert!(g
            .wait_at("alice", "198.51.100.1".parse().unwrap(), t0)
            .is_none());
        assert!(g.wait_at("bob", ip, t0).is_none());
        // Same IPv6 /64 is the same network.
        let a: IpAddr = "2001:db8:5:5::1".parse().unwrap();
        let b: IpAddr = "2001:db8:5:5::2".parse().unwrap();
        for _ in 0..=FREE_PER_CLIENT {
            g.failure_at("carol", a, t0);
        }
        assert!(g.wait_at("carol", b, t0).is_some());
        // Success clears the caller's network counter.
        g.success("alice", ip);
        assert!(g.wait_at("alice", ip, t0).is_none());
    }

    #[test]
    fn distributed_attack_hits_the_account_wide_cap() {
        let g = AttemptGuard::default();
        let t0 = Instant::now();
        for i in 0..40u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            g.failure_at("root", ip, t0);
        }
        let fresh: IpAddr = "192.0.2.200".parse().unwrap();
        let w = g.wait_at("root", fresh, t0).expect("account-wide wait");
        assert!(w <= MAX_ACCOUNT_DELAY, "never more than a minute: {w:?}");
        assert_eq!(w, MAX_ACCOUNT_DELAY);
        // Forgotten after a quiet period.
        let later = t0 + FORGET_AFTER + Duration::from_secs(1);
        assert!(g.wait_at("root", fresh, later).is_none());
    }

    #[test]
    fn code_attempts_per_session() {
        let g = AttemptGuard::default();
        for _ in 1..MAX_CODE_ATTEMPTS {
            assert!(!g.code_failure(7));
        }
        assert!(g.code_failure(7), "fifth wrong code ends the session");
        assert!(!g.code_failure(7), "counter restarts for a new session id");
        g.code_success(7);
        assert!(!g.code_failure(8));
    }
}
