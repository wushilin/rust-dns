//! Failed sign-in bookkeeping: in memory, written through to the local
//! `login_failures` table (O3) so a restart does not reset a back-off
//! (`AttemptGuard::persist_to` loads it at startup).
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
//! The per-session code counters stay in memory only (a restart ends
//! nothing: the session is still limited by the account back-off).

use crate::storage::{LoginFailureRow, Storage};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        self.fail_locking(k, now, free, cap, None)
    }

    /// `lockout` (O6): from this many failures on, the wait is at least
    /// this long.
    fn fail_locking(
        &mut self,
        k: K,
        now: Instant,
        free: u32,
        cap: Duration,
        lockout: Option<(u32, Duration)>,
    ) -> u32 {
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
        if let Some((after, d)) = lockout {
            if f.count >= after {
                f.blocked_until = f.blocked_until.max(now + d);
            }
        }
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

    fn clear(&mut self, k: &K) -> bool {
        self.map.remove(k).is_some()
    }
}

const SCOPE_ACCOUNT: &str = "account";
const SCOPE_NETWORK: &str = "network";

fn network_key(username: &str, net: u128) -> String {
    format!("{username}\t{net:x}")
}

/// Wall-clock milliseconds of `at` (an `Instant` near now).
fn wall_ms(at: Instant, now: Instant, now_ms: i64) -> i64 {
    if at >= now {
        now_ms.saturating_add(at.duration_since(now).as_millis() as i64)
    } else {
        now_ms.saturating_sub(now.duration_since(at).as_millis() as i64)
    }
}

/// The `Instant` of wall-clock `ms` (clamped to what `Instant` can hold).
fn instant_of(ms: i64, now: Instant, now_ms: i64) -> Instant {
    if ms >= now_ms {
        now + Duration::from_millis((ms - now_ms) as u64)
    } else {
        let back = Duration::from_millis((now_ms - ms) as u64);
        now.checked_sub(back).unwrap_or(now)
    }
}

pub fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    /// O3: where counters are written through (unset in unit tests).
    store: OnceLock<Arc<Storage>>,
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
            store: OnceLock::new(),
        }
    }

    /// O3: load the stored counters (those not yet forgotten) and write
    /// every later change through to `storage`. Call once, at startup.
    pub fn persist_to(&self, storage: Arc<Storage>) -> anyhow::Result<usize> {
        let (now, now_ms) = (Instant::now(), unix_ms_now());
        let forget_ms = FORGET_AFTER.as_millis() as i64;
        let rows = storage.load_login_failures()?;
        let mut loaded = 0;
        {
            let mut g = self.lock();
            for r in rows {
                if r.last_ms < now_ms - forget_ms && r.blocked_until_ms <= now_ms {
                    continue; // forgotten; the prune task deletes it
                }
                let f = Failures {
                    count: r.count,
                    last: instant_of(r.last_ms, now, now_ms),
                    blocked_until: instant_of(r.blocked_until_ms, now, now_ms),
                };
                match r.scope.as_str() {
                    SCOPE_ACCOUNT => {
                        g.per_account.map.insert(r.key, f);
                    }
                    SCOPE_NETWORK => {
                        let Some((user, net)) = r.key.split_once('\t') else {
                            continue;
                        };
                        let Ok(net) = u128::from_str_radix(net, 16) else {
                            continue;
                        };
                        g.per_client.map.insert((user.to_string(), net), f);
                    }
                    _ => continue,
                }
                loaded += 1;
            }
        }
        let _ = self.store.set(storage);
        Ok(loaded)
    }

    /// Write counters through (after the lock is released).
    fn save(&self, rows: &[(&str, String, Failures)], now: Instant) {
        let Some(store) = self.store.get() else {
            return;
        };
        let now_ms = unix_ms_now();
        for (scope, key, f) in rows {
            let row = LoginFailureRow {
                scope: scope.to_string(),
                key: key.clone(),
                count: f.count,
                last_ms: wall_ms(f.last, now, now_ms),
                blocked_until_ms: wall_ms(f.blocked_until, now, now_ms),
            };
            if let Err(e) = store.save_login_failure(&row) {
                tracing::warn!(error = %e, "could not store a failed sign-in counter");
            }
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
    #[cfg(test)]
    pub fn failure(&self, username: &str, ip: IpAddr) {
        self.failure_at(username, ip, Instant::now())
    }

    #[cfg(test)]
    pub fn failure_at(&self, username: &str, ip: IpAddr, now: Instant) {
        self.failure_locking_at(username, ip, now, None)
    }

    /// O6: a failure that also counts toward the account lockout
    /// (`(failures, duration)`; `None`: back-off only).
    pub fn failure_locking(&self, username: &str, ip: IpAddr, lockout: Option<(u32, Duration)>) {
        self.failure_locking_at(username, ip, Instant::now(), lockout)
    }

    pub fn failure_locking_at(
        &self,
        username: &str,
        ip: IpAddr,
        now: Instant,
        lockout: Option<(u32, Duration)>,
    ) {
        let (free_client, free_account) = (self.free_client, self.free_account);
        let net = crate::ratelimit::client_key(ip);
        let (client, account, n) = {
            let mut g = self.lock();
            let ck = (username.to_string(), net);
            g.per_client
                .fail(ck.clone(), now, free_client, MAX_CLIENT_DELAY);
            let n = g.per_account.fail_locking(
                username.to_string(),
                now,
                free_account,
                MAX_ACCOUNT_DELAY,
                lockout,
            );
            (g.per_client.map[&ck], g.per_account.map[username], n)
        };
        if lockout.is_some_and(|(after, _)| n == after) {
            tracing::warn!(user = %username, failures = n, "account locked after repeated failed sign-ins");
        }
        if n == free_account + 1 {
            tracing::warn!(user = %username, "repeated failed sign-ins for this account; slowing down attempts from every address");
        }
        self.save(
            &[
                (SCOPE_NETWORK, network_key(username, net), client),
                (SCOPE_ACCOUNT, username.to_string(), account),
            ],
            now,
        );
    }

    /// A successful sign-in clears this network's counter for the account.
    pub fn success(&self, username: &str, ip: IpAddr) {
        let net = crate::ratelimit::client_key(ip);
        let had = self.lock().per_client.clear(&(username.to_string(), net));
        if let (true, Some(store)) = (had, self.store.get()) {
            let _ = store.delete_login_failure(SCOPE_NETWORK, &network_key(username, net));
        }
    }

    /// O6: forget every counter of `username` (an administrator reset its
    /// password or re-enabled it): lifts a lockout.
    pub fn clear_account(&self, username: &str) {
        {
            let mut g = self.lock();
            g.per_account.map.remove(username);
            g.per_client.map.retain(|(u, _), _| u != username);
        }
        if let Some(store) = self.store.get() {
            let _ = store.delete_login_failures_of(username);
        }
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

    /// O3: counters written through to the local table come back after a
    /// "restart" (a new guard on the same database): a back-off in effect
    /// stays in effect; success deletes the network row; forgotten rows are
    /// skipped and pruned.
    #[test]
    fn backoff_survives_a_restart() {
        let storage = Arc::new(Storage::open_memory().unwrap());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let g = AttemptGuard::new(2);
        g.persist_to(storage.clone()).unwrap();
        for _ in 0..4 {
            g.failure("alice", ip);
        }
        let before = g.wait("alice", ip).expect("waiting");
        assert!(before >= Duration::from_millis(1500), "{before:?}");
        let rows = storage.load_login_failures().unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|r| r.count == 4));

        let g2 = AttemptGuard::new(2);
        assert_eq!(g2.persist_to(storage.clone()).unwrap(), 2);
        let after = g2
            .wait("alice", ip)
            .expect("still waiting after the restart");
        assert!(
            after.abs_diff(before) < Duration::from_millis(500),
            "{after:?} vs {before:?}"
        );
        // The count goes on from where it was.
        g2.failure("alice", ip);
        assert!(storage
            .load_login_failures()
            .unwrap()
            .iter()
            .all(|r| r.count == 5));
        g2.success("alice", ip);
        let rows = storage.load_login_failures().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "the network row is gone, the account row stays"
        );
        assert_eq!(rows[0].scope, "account");

        // A row forgotten long ago is not loaded, and the prune deletes it.
        let old = unix_ms_now() - FORGET_AFTER.as_millis() as i64 - 60_000;
        storage
            .save_login_failure(&LoginFailureRow {
                scope: "account".into(),
                key: "bob".into(),
                count: 50,
                last_ms: old,
                blocked_until_ms: old,
            })
            .unwrap();
        let g3 = AttemptGuard::new(2);
        g3.persist_to(storage.clone()).unwrap();
        assert!(g3.wait("bob", ip).is_none());
        let cut = unix_ms_now() - FORGET_AFTER.as_millis() as i64;
        assert_eq!(storage.prune_login_failures(cut, unix_ms_now()).unwrap(), 1);
    }

    /// O6: with a lockout, the account waits the whole lockout once it has
    /// that many failures (from any network), beyond the capped back-off;
    /// clearing the account lifts it.
    #[test]
    fn lockout_after_n_failures() {
        let g = AttemptGuard::new(5);
        let t0 = Instant::now();
        let lock = Some((3, Duration::from_secs(600)));
        for i in 0..2u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0001 + i));
            g.failure_locking_at("alice", ip, t0, lock);
        }
        let fresh: IpAddr = "192.0.2.7".parse().unwrap();
        assert!(
            g.wait_at("alice", fresh, t0).is_none(),
            "two failures: free"
        );
        g.failure_locking_at("alice", "10.9.9.9".parse().unwrap(), t0, lock);
        assert_eq!(
            g.wait_at("alice", fresh, t0),
            Some(Duration::from_secs(600)),
            "locked from everywhere"
        );
        assert!(g.wait_at("bob", fresh, t0).is_none());
        g.clear_account("alice");
        assert!(g.wait_at("alice", fresh, t0).is_none(), "lifted");
        // Without a lockout the same failures only back off (capped).
        let g = AttemptGuard::new(1);
        for _ in 0..10 {
            g.failure_at("carol", fresh, t0);
        }
        assert!(
            g.wait_at("carol", "198.51.100.3".parse().unwrap(), t0)
                .unwrap()
                <= MAX_ACCOUNT_DELAY
        );
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
