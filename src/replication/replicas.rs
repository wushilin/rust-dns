//! Primary side: which standbys (replicas) follow this server and how far
//! behind they are, Kafka style.
//!
//! Every replication request carries the standby's `[follow].instance_id`
//! (header `X-Rust-DNS-Instance`), its version and a per-process session id.
//! A standby commits a batch before it asks for the next one, so the
//! `after` of a changes request is the offset the standby has applied.
//!
//! States (see [`state`]): `up_to_date` (lag 0, or caught up within the
//! grace period), `catching_up` (behind, within the thresholds),
//! `falling_behind` (more than `max_lag_changes` behind, or not caught up
//! for more than `max_lag_secs`), `offline` (no request for
//! `offline_after_secs`), `bootstrapping` (a snapshot is being served or
//! loaded). `conflict` flags one id used by two processes at once.
//!
//! The list is kept in the local `replicas` table (bookkeeping, not
//! replicated, not changelogged), so it survives a restart; entries not seen
//! for `forget_after_days` are pruned.

use crate::config::ReplicationConfig;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use utoipa::ToSchema;

pub const HEADER_INSTANCE: &str = "x-rust-dns-instance";
pub const HEADER_VERSION: &str = "x-rust-dns-version";
/// What a standby of this build can follow, as semver build metadata on
/// its version header (`0.1.0+dnssec-rollover`): the primary refuses to
/// start what a following standby could not represent (N1: a DNSKEY
/// rollover). Older standbys send the bare version.
/// O11: `zone-rename` (a renamed zone's row; older versions ignore the new
/// name and would halt at the next reconcile).
/// O16: `zone-settings` (a zone's own auto-PTR / transfer / NOTIFY
/// settings; older versions drop them and would halt at the reconcile).
pub const VERSION_WITH_FEATURES: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+dnssec-rollover.zone-rename.zone-settings"
);

/// Whether a standby's reported version names `feature`.
pub fn has_feature(version: &str, feature: &str) -> bool {
    version
        .split_once('+')
        .is_some_and(|(_, meta)| meta.split(['.', '+']).any(|f| f == feature))
}
pub const HEADER_SESSION: &str = "x-rust-dns-session";

/// `[follow].instance_id` rules: a hostname label.
pub fn instance_id_problem(id: &str) -> Option<String> {
    if id.is_empty() || id.len() > 63 {
        return Some("must be 1-63 characters".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Some("may contain only a-z, 0-9 and '-' (lowercase, like a host name)".into());
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Some("must not start or end with '-'".into());
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaState {
    UpToDate,
    CatchingUp,
    FallingBehind,
    Offline,
    Bootstrapping,
    /// The standby reported that it stopped because its data diverged.
    Halted,
}

impl ReplicaState {
    pub const ALL: [ReplicaState; 6] = [
        ReplicaState::UpToDate,
        ReplicaState::CatchingUp,
        ReplicaState::FallingBehind,
        ReplicaState::Offline,
        ReplicaState::Bootstrapping,
        ReplicaState::Halted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReplicaState::UpToDate => "up_to_date",
            ReplicaState::CatchingUp => "catching_up",
            ReplicaState::FallingBehind => "falling_behind",
            ReplicaState::Offline => "offline",
            ReplicaState::Bootstrapping => "bootstrapping",
            ReplicaState::Halted => "halted",
        }
    }
}

/// What is stored per instance (the local `replicas` table, as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub instance: String,
    pub applied_offset: i64,
    /// The primary's head when the standby last reported its offset.
    pub head_at_report: i64,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    /// Last time the standby's applied offset equalled the primary's head.
    pub last_caught_up: Option<DateTime<Utc>>,
    pub address: String,
    pub session: String,
    pub version: String,
    pub user: String,
    pub bootstrapping_since: Option<DateTime<Utc>>,
    /// Previous lag seen, to tell catching up from standing still.
    pub prev_lag: Option<i64>,
    /// Sources (session id, or the address of a standby that sends none)
    /// this id was recently used from before the current one, with the time
    /// each was last seen. A conflict is one of them coming back.
    #[serde(default)]
    pub earlier: Vec<(String, DateTime<Utc>)>,
    #[serde(default)]
    pub conflict_since: Option<DateTime<Utc>>,
    /// The standby reported "halted" with this reason (cleared when it
    /// follows again).
    #[serde(default)]
    pub halted: Option<String>,
}

/// A replica as the API shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "instance": "dns2", "state": "up_to_date", "conflict": false, "applied_offset": 1834, "head": 1834, "lag_changes": 0, "lag_seconds": 0, "last_seen_at": "2026-01-15T09:30:00.000Z", "last_caught_up_at": "2026-01-15T09:30:00.000Z", "first_seen_at": "2026-01-10T08:00:00.000Z", "address": "192.0.2.53", "version": "0.1.0", "user": "root", "bootstrapping": false, "halted_reason": null }))]
pub struct ReplicaInfo {
    pub instance: String,
    pub state: ReplicaState,
    /// The same id is used by two processes (addresses or sessions) at once.
    pub conflict: bool,
    /// The offset the standby has applied (the `after` of its last request).
    pub applied_offset: i64,
    /// This server's latest offset now.
    pub head: i64,
    pub lag_changes: i64,
    /// Seconds since the standby was last caught up (0 when it is).
    pub lag_seconds: i64,
    #[schema(format = DateTime)]
    pub last_seen_at: String,
    #[schema(required = true, format = DateTime)]
    pub last_caught_up_at: Option<String>,
    #[schema(format = DateTime)]
    pub first_seen_at: String,
    pub address: String,
    pub version: String,
    /// The token user the standby authenticates as.
    pub user: String,
    pub bootstrapping: bool,
    /// Why the standby halted (state `halted`).
    #[schema(required = true)]
    pub halted_reason: Option<String>,
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The state of `e` at `now`, with this server's head `head`.
pub fn state(e: &Entry, head: i64, now: DateTime<Utc>, cfg: &ReplicationConfig) -> ReplicaState {
    if e.halted.is_some() {
        return ReplicaState::Halted;
    }
    if now - e.last_seen > Duration::seconds(cfg.offline_after_secs as i64) {
        return ReplicaState::Offline;
    }
    if e.bootstrapping_since.is_some() {
        return ReplicaState::Bootstrapping;
    }
    let lag = (head - e.applied_offset).max(0);
    if lag == 0 {
        return ReplicaState::UpToDate;
    }
    let behind_for = now - e.last_caught_up.unwrap_or(e.first_seen);
    if behind_for <= Duration::seconds(cfg.up_to_date_grace_secs as i64) {
        return ReplicaState::UpToDate;
    }
    if lag > cfg.max_lag_changes as i64 || behind_for > Duration::seconds(cfg.max_lag_secs as i64) {
        return ReplicaState::FallingBehind;
    }
    ReplicaState::CatchingUp
}

pub fn info(e: &Entry, head: i64, now: DateTime<Utc>, cfg: &ReplicationConfig) -> ReplicaInfo {
    let st = state(e, head, now, cfg);
    let lag = (head - e.applied_offset).max(0);
    ReplicaInfo {
        instance: e.instance.clone(),
        state: st,
        conflict: e
            .conflict_since
            .is_some_and(|c| now - c < Duration::seconds(cfg.offline_after_secs as i64)),
        applied_offset: e.applied_offset,
        head,
        lag_changes: lag,
        lag_seconds: if lag == 0 {
            0
        } else {
            (now - e.last_caught_up.unwrap_or(e.first_seen))
                .num_seconds()
                .max(0)
        },
        last_seen_at: ts(e.last_seen),
        last_caught_up_at: e.last_caught_up.map(ts),
        first_seen_at: ts(e.first_seen),
        address: e.address.clone(),
        version: e.version.clone(),
        user: e.user.clone(),
        bootstrapping: e.bootstrapping_since.is_some(),
        halted_reason: e.halted.clone(),
    }
}

/// One replication request of a standby.
pub struct Seen<'a> {
    pub instance: &'a str,
    pub address: &'a str,
    pub session: &'a str,
    pub version: &'a str,
    pub user: &'a str,
}

/// What a request tells about the standby.
pub enum Report {
    /// A changes request: the offset it has applied (`after`).
    Applied(i64),
    /// A snapshot is being served.
    Bootstrapping,
    /// Checksum / status / probe: only "alive".
    Alive,
    /// The standby stopped: its data diverged (reason and detail).
    Halted(String),
}

/// In-memory table, loaded from and saved to the local `replicas` table.
#[derive(Default)]
pub struct Tracker {
    entries: Mutex<HashMap<String, Entry>>,
    /// When each instance was last written to the database.
    saved: Mutex<HashMap<String, (DateTime<Utc>, ReplicaState)>>,
}

impl Tracker {
    pub fn load(&self, entries: Vec<Entry>) {
        let mut m = self.entries.lock().unwrap();
        for e in entries {
            m.insert(e.instance.clone(), e);
        }
    }

    /// Record a request. Returns the entry to persist when it should be
    /// written now (first sight, a state change, or every 30 s), and
    /// whether a conflict started.
    pub fn note(
        &self,
        s: &Seen,
        report: Report,
        head: i64,
        now: DateTime<Utc>,
        cfg: &ReplicationConfig,
    ) -> (Option<Entry>, bool) {
        let mut m = self.entries.lock().unwrap();
        let e = m.entry(s.instance.to_string()).or_insert_with(|| Entry {
            instance: s.instance.to_string(),
            applied_offset: 0,
            head_at_report: head,
            last_seen: now,
            first_seen: now,
            last_caught_up: None,
            address: s.address.to_string(),
            session: s.session.to_string(),
            version: s.version.to_string(),
            user: s.user.to_string(),
            bootstrapping_since: None,
            prev_lag: None,
            earlier: Vec::new(),
            conflict_since: None,
            halted: None,
        });
        let window = Duration::seconds(cfg.offline_after_secs as i64);
        let mut new_conflict = false;
        // Another process with the same id. A restart (or two quick ones)
        // gives a new session each time and the old ones never return; two
        // running processes alternate, so a session seen earlier comes
        // back (A, B, A). Only that is a conflict.
        let source = |address: &str, session: &str| {
            if session.is_empty() {
                format!("addr:{address}")
            } else {
                format!("session:{session}")
            }
        };
        let (was, is) = (source(&e.address, &e.session), source(s.address, s.session));
        e.earlier.retain(|(_, t)| now - *t < window);
        if was != is {
            let returned = e.earlier.iter().any(|(id, _)| *id == is);
            e.earlier.retain(|(id, _)| *id != is && *id != was);
            if now - e.last_seen < window {
                e.earlier.push((was, e.last_seen));
            }
            // Bounded: a crash loop must not grow the entry.
            let extra = e.earlier.len().saturating_sub(8);
            e.earlier.drain(..extra);
            if returned && e.conflict_since.is_none_or(|c| now - c >= window) {
                e.conflict_since = Some(now);
                new_conflict = true;
            } else if returned {
                e.conflict_since = e.conflict_since.or(Some(now));
            }
        }
        e.address = s.address.to_string();
        e.session = s.session.to_string();
        e.version = s.version.to_string();
        e.user = s.user.to_string();
        e.last_seen = now;
        match report {
            Report::Applied(after) => {
                e.bootstrapping_since = None;
                e.halted = None;
                let lag = (head - after).max(0);
                e.prev_lag = Some(lag);
                e.applied_offset = after;
                e.head_at_report = head;
                if lag == 0 {
                    e.last_caught_up = Some(now);
                }
            }
            Report::Bootstrapping => {
                e.bootstrapping_since = Some(now);
                e.halted = None;
            }
            Report::Halted(why) => {
                e.halted = Some(why);
            }
            Report::Alive => {}
        }
        let after = state(e, head, now, cfg);
        let mut saved = self.saved.lock().unwrap();
        let due = match saved.get(&e.instance) {
            None => true,
            Some((t, st)) => *st != after || now - *t >= Duration::seconds(30) || new_conflict,
        };
        if due {
            saved.insert(e.instance.clone(), (now, after));
            (Some(e.clone()), new_conflict)
        } else {
            (None, new_conflict)
        }
    }

    pub fn list(&self, head: i64, now: DateTime<Utc>, cfg: &ReplicationConfig) -> Vec<ReplicaInfo> {
        let mut v: Vec<ReplicaInfo> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .map(|e| info(e, head, now, cfg))
            .collect();
        v.sort_by(|a, b| a.instance.cmp(&b.instance));
        v
    }

    pub fn forget(&self, instance: &str) -> bool {
        self.saved.lock().unwrap().remove(instance);
        self.entries.lock().unwrap().remove(instance).is_some()
    }

    /// Drop entries not seen for `days`; returns their ids.
    pub fn prune(&self, now: DateTime<Utc>, days: u32) -> Vec<String> {
        let mut m = self.entries.lock().unwrap();
        let old: Vec<String> = m
            .values()
            .filter(|e| now - e.last_seen > Duration::days(days as i64))
            .map(|e| e.instance.clone())
            .collect();
        for id in &old {
            m.remove(id);
        }
        old
    }
}

#[cfg(test)]
mod tests {

    /// N1: this build advertises the rollover; older version strings do not.
    #[test]
    fn the_version_header_names_the_features() {
        assert!(has_feature(VERSION_WITH_FEATURES, "dnssec-rollover"));
        assert!(VERSION_WITH_FEATURES.starts_with(env!("CARGO_PKG_VERSION")));
        assert!(!has_feature("0.1.0", "dnssec-rollover"));
        assert!(!has_feature("", "dnssec-rollover"));
        assert!(has_feature("0.2.0+x.dnssec-rollover", "dnssec-rollover"));
        assert!(!has_feature("0.2.0+dnssec-rollover-v0", "dnssec-rollover"));
    }
    use super::*;

    fn cfg() -> ReplicationConfig {
        ReplicationConfig {
            up_to_date_grace_secs: 5,
            max_lag_changes: 100,
            max_lag_secs: 30,
            offline_after_secs: 60,
            forget_after_days: 30,
        }
    }

    fn t0() -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse().unwrap()
    }

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    fn seen<'a>(addr: &'a str, session: &'a str) -> Seen<'a> {
        Seen {
            instance: "dns2",
            address: addr,
            session,
            version: "0.1.0",
            user: "root",
        }
    }

    fn st(t: &Tracker, head: i64, now: DateTime<Utc>) -> ReplicaInfo {
        t.list(head, now, &cfg()).remove(0)
    }

    #[test]
    fn lag_grace_and_falling_behind() {
        let t = Tracker::default();
        let c = cfg();
        let a = seen("192.0.2.2", "s1");
        // Caught up.
        t.note(&a, Report::Applied(10), 10, at(0), &c);
        assert_eq!(st(&t, 10, at(1)).state, ReplicaState::UpToDate);
        // New writes: within the grace period it still counts as up to date.
        assert_eq!(st(&t, 15, at(3)).state, ReplicaState::UpToDate);
        // Behind, within the thresholds.
        let i = st(&t, 15, at(10));
        assert_eq!(i.state, ReplicaState::CatchingUp);
        assert_eq!((i.lag_changes, i.lag_seconds), (5, 10));
        // Not caught up for longer than max_lag_secs.
        assert_eq!(st(&t, 15, at(31)).state, ReplicaState::FallingBehind);
        // Too many changes behind, at once.
        assert_eq!(st(&t, 200, at(10)).state, ReplicaState::FallingBehind);
        // The standby reports progress, then catches up.
        t.note(&a, Report::Applied(14), 15, at(32), &c);
        assert_eq!(
            st(&t, 15, at(32)).state,
            ReplicaState::FallingBehind,
            "still not caught up since t=0"
        );
        t.note(&a, Report::Applied(15), 15, at(33), &c);
        let i = st(&t, 15, at(33));
        assert_eq!(i.state, ReplicaState::UpToDate);
        assert_eq!((i.lag_changes, i.lag_seconds), (0, 0));
    }

    #[test]
    fn offline_and_bootstrapping() {
        let t = Tracker::default();
        let c = cfg();
        let a = seen("192.0.2.2", "s1");
        t.note(&a, Report::Bootstrapping, 50, at(0), &c);
        assert_eq!(st(&t, 50, at(1)).state, ReplicaState::Bootstrapping);
        assert!(st(&t, 50, at(1)).bootstrapping);
        t.note(&a, Report::Applied(50), 50, at(2), &c);
        assert_eq!(st(&t, 50, at(2)).state, ReplicaState::UpToDate);
        // No request for longer than offline_after_secs.
        assert_eq!(st(&t, 50, at(62)).state, ReplicaState::UpToDate);
        assert_eq!(st(&t, 50, at(63)).state, ReplicaState::Offline);
        // Back: alive again.
        t.note(&a, Report::Applied(50), 50, at(100), &c);
        assert_eq!(st(&t, 50, at(100)).state, ReplicaState::UpToDate);
    }

    #[test]
    fn two_processes_with_one_id_conflict_but_a_restart_does_not() {
        let t = Tracker::default();
        let c = cfg();
        t.note(&seen("192.0.2.2", "s1"), Report::Applied(1), 1, at(0), &c);
        // Restart (new session) or a move to a new address: one switch.
        let (_, conflict) = t.note(&seen("192.0.2.2", "s2"), Report::Applied(1), 1, at(5), &c);
        assert!(!conflict);
        assert!(!st(&t, 1, at(6)).conflict);
        for i in 0..3 {
            t.note(
                &seen("192.0.2.2", "s2"),
                Report::Applied(1),
                1,
                at(10 + i),
                &c,
            );
        }
        assert!(!st(&t, 1, at(14)).conflict);
        // Another process interleaves: A, B, A.
        let (_, c1) = t.note(&seen("192.0.2.9", "x"), Report::Applied(1), 1, at(20), &c);
        let (_, c2) = t.note(&seen("192.0.2.2", "s2"), Report::Applied(1), 1, at(21), &c);
        assert!(c1 || c2);
        assert!(!c1, "a new session alone is not a conflict");
        assert!(c2, "the earlier session came back");
        assert!(st(&t, 1, at(22)).conflict);
        // The flag clears once the window passes without new switches.
        t.note(&seen("192.0.2.2", "s2"), Report::Applied(1), 1, at(90), &c);
        assert!(!st(&t, 1, at(90)).conflict);
    }

    /// F2: a standby restarted twice in a row has three sessions, none of
    /// which returns: no conflict. (Seen on baba2 after two quick restarts.)
    #[test]
    fn two_quick_restarts_are_not_a_conflict() {
        let t = Tracker::default();
        let c = cfg();
        t.note(&seen("192.0.2.2", "s1"), Report::Applied(1), 1, at(0), &c);
        let (_, c1) = t.note(&seen("192.0.2.2", "s2"), Report::Applied(1), 1, at(3), &c);
        let (_, c2) = t.note(&seen("192.0.2.2", "s3"), Report::Applied(1), 1, at(6), &c);
        let (_, c3) = t.note(&seen("192.0.2.2", "s3"), Report::Applied(1), 1, at(7), &c);
        assert!(!c1 && !c2 && !c3);
        assert!(!st(&t, 1, at(8)).conflict);
        // One session reached over two addresses (dual stack) is one process.
        let (_, c4) = t.note(&seen("2001:db8::2", "s3"), Report::Applied(1), 1, at(9), &c);
        let (_, c5) = t.note(&seen("192.0.2.2", "s3"), Report::Applied(1), 1, at(10), &c);
        assert!(!c4 && !c5);
        // A session that was replaced long ago (outside the window) and
        // shows up again is not "at once".
        let (_, c6) = t.note(&seen("192.0.2.2", "s1"), Report::Applied(1), 1, at(200), &c);
        assert!(!c6);
        // But s3 coming back now is: s1 and s3 both run.
        let (_, c7) = t.note(&seen("192.0.2.2", "s3"), Report::Applied(1), 1, at(201), &c);
        assert!(!c7, "s3 was last seen before the window");
        let (_, c8) = t.note(&seen("192.0.2.2", "s1"), Report::Applied(1), 1, at(202), &c);
        assert!(c8);
        assert!(st(&t, 1, at(203)).conflict);
        // Entries stored by the previous version (with `switches`) load.
        let old = r#"{"instance":"dns2","applied_offset":1,"head_at_report":1,"last_seen":"2026-01-01T00:00:00Z","first_seen":"2026-01-01T00:00:00Z","last_caught_up":null,"address":"a","session":"s","version":"v","user":"u","bootstrapping_since":null,"prev_lag":0,"switches":["2026-01-01T00:00:00Z"],"conflict_since":null,"halted":null}"#;
        let e: Entry = serde_json::from_str(old).unwrap();
        assert!(e.earlier.is_empty());
    }

    #[test]
    fn persistence_is_throttled_and_pruning_forgets_old_entries() {
        let t = Tracker::default();
        let c = cfg();
        let a = seen("192.0.2.2", "s1");
        assert!(
            t.note(&a, Report::Applied(1), 1, at(0), &c).0.is_some(),
            "first sight"
        );
        assert!(
            t.note(&a, Report::Applied(1), 1, at(5), &c).0.is_none(),
            "nothing new"
        );
        assert!(
            t.note(&a, Report::Bootstrapping, 1, at(6), &c).0.is_some(),
            "state change"
        );
        assert!(
            t.note(&a, Report::Bootstrapping, 1, at(40), &c).0.is_some(),
            "every 30 s"
        );
        // Reload from storage, prune after N days.
        let t2 = Tracker::default();
        t2.load(t.entries.lock().unwrap().values().cloned().collect());
        assert_eq!(t2.list(1, at(41), &c).len(), 1);
        assert!(t2.prune(at(41) + Duration::days(29), 30).is_empty());
        assert_eq!(
            t2.prune(at(41) + Duration::days(31), 30),
            vec!["dns2".to_string()]
        );
        assert!(t2.list(1, at(41), &c).is_empty());
    }

    #[test]
    fn halted_reports_stick_until_the_standby_follows_again() {
        let t = Tracker::default();
        let c = cfg();
        let a = seen("192.0.2.2", "s1");
        t.note(&a, Report::Applied(5), 5, at(0), &c);
        t.note(
            &a,
            Report::Halted("diverged: table users".into()),
            5,
            at(1),
            &c,
        );
        let i = st(&t, 5, at(500));
        assert_eq!(i.state, ReplicaState::Halted, "halted wins over offline");
        assert_eq!(i.halted_reason.as_deref(), Some("diverged: table users"));
        // Rebuilt (--prepare-standby): it loads a snapshot and follows again.
        t.note(&a, Report::Bootstrapping, 5, at(600), &c);
        assert_eq!(st(&t, 5, at(600)).state, ReplicaState::Bootstrapping);
        t.note(&a, Report::Applied(5), 5, at(601), &c);
        assert_eq!(st(&t, 5, at(601)).state, ReplicaState::UpToDate);
    }

    #[test]
    fn instance_ids_are_host_labels() {
        for ok in ["dns2", "a", "standby-1", &"a".repeat(63)] {
            assert!(instance_id_problem(ok).is_none(), "{ok}");
        }
        for bad in ["", "DNS2", "dns_2", "-a", "a-", "a.b", &"a".repeat(64)] {
            assert!(instance_id_problem(bad).is_some(), "{bad}");
        }
    }
}
