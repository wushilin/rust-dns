//! Standby ("follow") mode: a second rust-dns mirrors a primary so it can
//! answer every DNS query while the primary is down, refuses mutations,
//! and can be promoted by hand. Not a load-balanced cluster.
//!
//! * Roles: `primary` (writable), `promoted` (writable, was a standby),
//!   `standby` (`[follow]` in the config: read-only mirror) and `fenced`
//!   (an old primary whose `[peer]` was promoted from its history:
//!   read-only). The role is decided at startup from the config and the
//!   database; promotion switches a standby to `promoted` at runtime.
//! * The standby pulls from the primary's admin-only replication API
//!   (`/api/replication/*`, see `api::replication`) over HTTPS: a snapshot
//!   (logical entities read in one transaction) to start, then a long-poll
//!   of the changelog (whole transactions of DNS and account/settings/TSIG
//!   changes in one sequence, applied with the primary's offsets), plus a
//!   periodic checksum reconcile. All writes go through `mutation::replica`.
//! * Every database has a history id. A standby adopts its primary's; a
//!   promotion starts a new one whose parent is the old one (forked at the
//!   current offset). [`lineage::plan`] uses this to continue, adopt a
//!   promoted primary's history, refuse to follow a stale old primary, or
//!   re-bootstrap within the same lineage (gap, reconcile mismatch) or
//!   copy the primary into a fresh database. A database with other data is
//!   never replaced implicitly: `--prepare-standby` backs it up and empties
//!   it on the operator's explicit request.

pub mod data;
pub mod lineage;
pub mod replicas;
pub mod tables;
pub mod types;

use crate::config::{FollowConfig, PeerConfig};
use crate::dns::DnsServer;
use crate::model::{now_rfc3339, Actor};
use crate::mutation::replica::{LocalRoot, K_FOLLOWING};
use crate::mutation::{Mutator, WriteGate};
use crate::storage::Storage;
use anyhow::{anyhow, Context, Result};
use lineage::{LocalView, Plan, RemoteView};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use types::*;

/// Long-poll wait the standby asks for (seconds).
const POLL_WAIT_SECS: u64 = 25;
/// Changes per long-poll answer (extended to whole transactions).
const POLL_LIMIT: usize = 2000;
/// A primary contacted within this long counts as reachable for promotion.
const REACHABLE_WITHIN: Duration = Duration::from_secs(60);

/// Why a request to the primary failed.
#[derive(Debug)]
enum CallError {
    /// 401/403: the token was rejected or is not an administrator's.
    Auth(String),
    /// 409 or similar: the server is not a writable primary.
    Refused(String),
    Other(String),
    /// Divergence or an invariant violation: stop for good (see `halt`).
    Halt {
        reason: &'static str,
        detail: String,
        evidence: serde_json::Value,
    },
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Auth(m) | CallError::Refused(m) | CallError::Other(m) => f.write_str(m),
            CallError::Halt { reason, detail, .. } => write!(f, "{reason}: {detail}"),
        }
    }
}

/// Everything the replication runtime needs from the rest of the server.
pub struct Replication {
    storage: Arc<Storage>,
    mutator: Arc<Mutator>,
    gate: Arc<WriteGate>,
    dns: Arc<DnsServer>,
    reloader: Arc<crate::reload::Reloader>,
    config_path: PathBuf,
    follow: Option<FollowConfig>,
    peer: Option<PeerConfig>,
    role: RwLock<Role>,
    follow_status: Mutex<FollowStatus>,
    peer_status: Mutex<Option<PeerStatus>>,
    warning: RwLock<Option<String>>,
    last_contact: Mutex<Option<Instant>>,
    // Primary side.
    /// Ticks when an account transaction appended to the changelog
    /// (account changes are not on the event bus): wakes long-polls.
    changelog_tick: tokio::sync::watch::Sender<u64>,
    replicas: replicas::Tracker,
    /// Sent with every request as `X-Rust-DNS-Session` (conflict detection).
    session: String,
    // Standby side.
    follower: Mutex<Option<tokio::task::JoinHandle<()>>>,
    promote_lock: tokio::sync::Mutex<()>,
    reconnects: AtomicU64,
    rebootstraps: AtomicU64,
    reconcile_mismatches: AtomicU64,
    http: reqwest::Client,
}

fn ensure_crypto() {
    // ring: builds on every release target without cmake/NASM.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl Replication {
    pub fn new(
        storage: Arc<Storage>,
        mutator: Arc<Mutator>,
        dns: Arc<DnsServer>,
        reloader: Arc<crate::reload::Reloader>,
        config_path: PathBuf,
    ) -> Arc<Self> {
        ensure_crypto();
        let cfg = reloader.current.load_full();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("rust-dns/", env!("CARGO_PKG_VERSION"), " standby"))
            .https_only(false)
            .build()
            .expect("HTTP client");
        let follow_status = FollowStatus {
            primary: cfg
                .follow
                .as_ref()
                .map(|f| f.primary.clone())
                .unwrap_or_default(),
            instance_id: cfg
                .follow
                .as_ref()
                .map(|f| f.instance_id.trim().to_string())
                .unwrap_or_default(),
            state: "starting".into(),
            ..Default::default()
        };
        let (changelog_tick, _) = tokio::sync::watch::channel(0u64);
        Arc::new(Replication {
            gate: mutator.gate(),
            storage,
            mutator,
            dns,
            reloader,
            config_path,
            follow: cfg.follow.clone(),
            peer: cfg.peer.clone(),
            role: RwLock::new(Role::Primary),
            follow_status: Mutex::new(follow_status),
            peer_status: Mutex::new(cfg.peer.as_ref().map(|p| PeerStatus {
                url: p.url.clone(),
                last_check_at: None,
                last_result: None,
            })),
            warning: RwLock::new(None),
            last_contact: Mutex::new(None),
            changelog_tick,
            replicas: replicas::Tracker::default(),
            session: crate::auth::random_token(8),
            follower: Mutex::new(None),
            promote_lock: tokio::sync::Mutex::new(()),
            reconnects: AtomicU64::new(0),
            rebootstraps: AtomicU64::new(0),
            reconcile_mismatches: AtomicU64::new(0),
            http,
        })
    }

    // ---- role -------------------------------------------------------------

    pub fn role(&self) -> Role {
        *self.role.read().unwrap_or_else(|p| p.into_inner())
    }

    fn set_role(&self, r: Role) {
        *self.role.write().unwrap_or_else(|p| p.into_inner()) = r;
    }

    pub fn writable(&self) -> bool {
        !self.gate.read_only()
    }

    /// The message for refused writes, when read-only.
    pub fn read_only_reason(&self) -> Option<String> {
        self.gate.read_only().then(|| self.gate.reason())
    }

    fn primary_url(&self) -> String {
        self.follow
            .as_ref()
            .map(|f| f.primary.trim().trim_end_matches('/').to_string())
            .unwrap_or_default()
    }

    fn local_root(&self) -> LocalRoot {
        let cfg = self.reloader.current.load();
        LocalRoot {
            username: cfg.root.username.clone(),
        }
    }

    fn history(&self) -> History {
        self.storage.read_tx(data::history).unwrap_or_default()
    }

    /// Decide the role and start the background tasks. Runs before the
    /// web listener starts, so a standby or fenced server never accepts a
    /// write, not even briefly.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let st = self.storage.replication_state()?;
        if self.follow.is_some() {
            let url = self.primary_url();
            self.set_role(Role::Standby);
            self.gate.close(format!(
                "this server is a read-only standby of {url}; make changes on the primary"
            ));
            let h = self.history();
            if h.promoted_at.is_some() && h.promoted_from.as_deref() == Some(url.as_str()) {
                let w = format!("this server was promoted from {url} on {} but [follow] still names it: it stays a read-only standby and will refuse to follow the old primary; remove [follow] from {}", h.promoted_at.clone().unwrap_or_default(), self.config_path.display());
                tracing::warn!("{w}");
                *self.warning.write().unwrap() = Some(w);
            }
            tracing::info!(primary = %url, "standby mode: mirroring the primary, writes refused");
            let me = self.clone();
            *self.follower.lock().unwrap() =
                Some(tokio::spawn(async move { me.run_follower().await }));
            return Ok(());
        }
        // Not following. A database that was a standby and has no promotion
        // record was un-followed by editing the config: record the promotion
        // now, so it gets a new history and a returning old primary can tell.
        if let Some(from) = st.get(K_FOLLOWING).cloned() {
            tracing::warn!(previous_primary = %from, "[follow] was removed from the configuration: recording the promotion of this former standby (new history id)");
            self.mutator
                .replica_promote(
                    Actor {
                        name: "system".into(),
                        ip: "config".into(),
                    },
                    from,
                    "follow_removed",
                )
                .await
                .map_err(|e| anyhow!("recording the promotion: {e}"))?;
        }
        self.start_replica_tracking();
        let h = self.history();
        self.set_role(if h.promoted_at.is_some() {
            Role::Promoted
        } else {
            Role::Primary
        });
        if let Some(p) = self.peer.clone() {
            // First check before accepting writes (bounded wait).
            self.check_peer(&p).await;
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(p.check_interval_secs.max(1))).await;
                    if me.role() == Role::Fenced {
                        return;
                    }
                    me.check_peer(&p).await;
                }
            });
        }
        Ok(())
    }

    // ---- primary side -------------------------------------------------------

    /// Account data changed: wake long-polling standbys.
    pub fn changelog_appended(&self) {
        self.changelog_tick.send_modify(|g| *g += 1);
    }

    pub fn subscribe_changelog_tick(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changelog_tick.subscribe()
    }

    fn replication_cfg(&self) -> crate::config::ReplicationConfig {
        self.reloader.current.load().replication.clone()
    }

    /// Load the persisted replica list and prune it now and daily.
    fn start_replica_tracking(self: &Arc<Self>) {
        match self.storage.load_replicas() {
            Ok(rows) => self.replicas.load(
                rows.iter()
                    .filter_map(|r| serde_json::from_str::<replicas::Entry>(r).ok())
                    .collect(),
            ),
            Err(e) => tracing::warn!(error = %e, "cannot load the replica list"),
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let days = me.replication_cfg().forget_after_days;
                let now = chrono::Utc::now();
                for id in me.replicas.prune(now, days) {
                    tracing::info!(instance = %id, days, "forgetting a replica not seen for a long time");
                }
                let cutoff = (now - chrono::Duration::days(days as i64))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                let _ = me.storage.prune_replicas(&cutoff);
            }
        });
    }

    /// Record a standby's request (primary side).
    pub fn note_replica(&self, seen: &replicas::Seen, report: replicas::Report) {
        let cfg = self.replication_cfg();
        let head = self.storage.changelog_head().unwrap_or(0);
        let now = chrono::Utc::now();
        let (save, conflict) = self.replicas.note(seen, report, head, now, &cfg);
        if conflict {
            tracing::warn!(instance = %seen.instance, address = %seen.address, "CONFLICT: two standbys use the same [follow].instance_id; give each a unique instance_id");
        }
        if let Some(e) = save {
            if let Ok(json) = serde_json::to_string(&e) {
                let at = e
                    .last_seen
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                if let Err(err) = self.storage.save_replica(&e.instance, &json, &at) {
                    tracing::warn!(error = %err, "cannot save the replica list");
                }
            }
        }
    }

    pub fn replica_list(&self) -> Vec<replicas::ReplicaInfo> {
        let head = self.storage.changelog_head().unwrap_or(0);
        self.replicas
            .list(head, chrono::Utc::now(), &self.replication_cfg())
    }

    /// Forget an instance (after the audited database delete).
    pub fn forget_replica(&self, instance: &str) -> bool {
        self.replicas.forget(instance)
    }

    // ---- status -------------------------------------------------------------

    pub fn identity(&self) -> Identity {
        Identity {
            protocol: REPLICATION_PROTOCOL,
            role: self.role(),
            writable: self.writable(),
            history: self.history(),
        }
    }

    fn follow_snapshot(&self) -> FollowStatus {
        let mut f = self.follow_status.lock().unwrap().clone();
        f.reconnects = self.reconnects.load(Ordering::Relaxed);
        f.rebootstraps = self.rebootstraps.load(Ordering::Relaxed);
        f.last_applied_offset = self.storage.changelog_head().unwrap_or(0);
        f.lag_changes = f.primary_head.map(|h| (h - f.last_applied_offset).max(0));
        f.seconds_since_last_applied = f.last_applied_at.as_deref().and_then(|t| {
            chrono::DateTime::parse_from_rfc3339(t)
                .ok()
                .map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds())
        });
        f
    }

    pub fn status(&self) -> ReplicationStatus {
        let role = self.role();
        ReplicationStatus {
            protocol: REPLICATION_PROTOCOL,
            role,
            writable: self.writable(),
            history: self.history(),
            head: self.storage.changelog_head().unwrap_or(0),
            read_only_reason: self.read_only_reason(),
            follow: (role == Role::Standby).then(|| self.follow_snapshot()),
            peer: self.peer_status.lock().unwrap().clone(),
            replicas: self.replica_list(),
            warning: self.warning.read().unwrap().clone(),
        }
    }

    pub fn summary(&self) -> ReplicationSummary {
        let role = self.role();
        let mut halted = false;
        let (primary, connected, lag, since, problem) = match role {
            Role::Standby => {
                let f = self.follow_snapshot();
                halted = f.halted.is_some();
                let problem = if let Some(h) = &f.halted {
                    Some(format!(
                        "Replication halted ({}): {}. Rebuild with rust-dns --prepare-standby --yes",
                        h.reason, h.detail
                    ))
                } else if f.state == "refused" {
                    f.last_error.clone()
                } else {
                    None
                };
                (
                    Some(f.primary),
                    f.connected,
                    f.lag_changes,
                    f.disconnected_since,
                    problem,
                )
            }
            Role::Fenced => (
                self.peer.as_ref().map(|p| p.url.clone()),
                false,
                None,
                None,
                None,
            ),
            _ => (None, false, None, None, None),
        };
        ReplicationSummary {
            role,
            writable: self.writable(),
            primary,
            connected,
            lag_changes: lag,
            disconnected_since: since,
            read_only_reason: self.read_only_reason(),
            problem,
            halted,
        }
    }

    /// Prometheus lines.
    pub fn metrics_text(&self) -> String {
        let role = self.role();
        let mut out = String::new();
        let g = |out: &mut String, name: &str, help: &str, v: i64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n"
            ));
        };
        g(
            &mut out,
            "rustdns_replication_writable",
            "1 if this server accepts writes (primary), 0 on a standby or fenced server",
            self.writable() as i64,
        );
        g(
            &mut out,
            "rustdns_replication_standby",
            "1 if this server is a standby ([follow])",
            (role == Role::Standby) as i64,
        );
        let reps = self.replica_list();
        if !reps.is_empty() || role != Role::Standby {
            out.push_str("# HELP rustdns_replication_replica_lag_changes Changes a replica is behind this server\n# TYPE rustdns_replication_replica_lag_changes gauge\n");
            for r in &reps {
                out.push_str(&format!(
                    "rustdns_replication_replica_lag_changes{{instance=\"{}\"}} {}\n",
                    r.instance, r.lag_changes
                ));
            }
            out.push_str("# HELP rustdns_replication_replica_lag_seconds Seconds since a replica was last caught up\n# TYPE rustdns_replication_replica_lag_seconds gauge\n");
            for r in &reps {
                out.push_str(&format!(
                    "rustdns_replication_replica_lag_seconds{{instance=\"{}\"}} {}\n",
                    r.instance, r.lag_seconds
                ));
            }
            out.push_str("# HELP rustdns_replication_replica_state 1 for the current state of each replica\n# TYPE rustdns_replication_replica_state gauge\n");
            for r in &reps {
                for st in replicas::ReplicaState::ALL {
                    out.push_str(&format!(
                        "rustdns_replication_replica_state{{instance=\"{}\",state=\"{}\"}} {}\n",
                        r.instance,
                        st.as_str(),
                        (r.state == st) as u8
                    ));
                }
            }
            out.push_str("# HELP rustdns_replication_replicas Replicas per state\n# TYPE rustdns_replication_replicas gauge\n");
            for st in replicas::ReplicaState::ALL {
                out.push_str(&format!(
                    "rustdns_replication_replicas{{state=\"{}\"}} {}\n",
                    st.as_str(),
                    reps.iter().filter(|r| r.state == st).count()
                ));
            }
            out.push_str(&format!(
                "# HELP rustdns_replication_replica_conflicts Replicas whose instance id is used by two processes\n# TYPE rustdns_replication_replica_conflicts gauge\nrustdns_replication_replica_conflicts {}\n",
                reps.iter().filter(|r| r.conflict).count()
            ));
        }
        if role == Role::Standby {
            let f = self.follow_snapshot();
            g(
                &mut out,
                "rustdns_replication_halted",
                "1 if replication halted because the data diverged (terminal until --prepare-standby)",
                f.halted.is_some() as i64,
            );
            g(
                &mut out,
                "rustdns_replication_connected",
                "1 if the last request to the primary succeeded",
                f.connected as i64,
            );
            g(
                &mut out,
                "rustdns_replication_lag_changes",
                "Changes the standby is behind the primary (as of the last contact)",
                f.lag_changes.unwrap_or(0),
            );
            g(
                &mut out,
                "rustdns_replication_last_applied_offset",
                "Latest changelog offset applied on this standby",
                f.last_applied_offset,
            );
            g(
                &mut out,
                "rustdns_replication_seconds_since_last_applied",
                "Seconds since a change from the primary was applied (-1: none yet)",
                f.seconds_since_last_applied.unwrap_or(-1),
            );
            out.push_str(&format!("# HELP rustdns_replication_reconnects_total Connections to the primary lost or refused\n# TYPE rustdns_replication_reconnects_total counter\nrustdns_replication_reconnects_total {}\n", f.reconnects));
            out.push_str(&format!("# HELP rustdns_replication_reconcile_mismatches_total Reconciles that found data differing from the primary\n# TYPE rustdns_replication_reconcile_mismatches_total counter\nrustdns_replication_reconcile_mismatches_total {}\n", self.reconcile_mismatches.load(Ordering::Relaxed)));
            out.push_str(&format!("# HELP rustdns_replication_rebootstraps_total Snapshots loaded from the primary\n# TYPE rustdns_replication_rebootstraps_total counter\nrustdns_replication_rebootstraps_total {}\n", f.rebootstraps));
        }
        out
    }

    fn update(&self, f: impl FnOnce(&mut FollowStatus)) {
        f(&mut self.follow_status.lock().unwrap());
    }

    fn contact_ok(&self) {
        *self.last_contact.lock().unwrap() = Some(Instant::now());
        self.update(|s| {
            s.connected = true;
            s.disconnected_since = None;
            s.last_contact_at = Some(now_rfc3339());
        });
    }

    // ---- HTTP ---------------------------------------------------------------

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        base: &str,
        token: Option<&str>,
        path: &str,
        timeout: Duration,
    ) -> std::result::Result<T, CallError> {
        let url = format!("{base}{path}");
        let mut req = self
            .http
            .get(&url)
            .timeout(timeout)
            .header(replicas::HEADER_VERSION, env!("CARGO_PKG_VERSION"))
            .header(replicas::HEADER_SESSION, &self.session);
        if let Some(f) = &self.follow {
            req = req.header(replicas::HEADER_INSTANCE, f.instance_id.trim());
        }
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| CallError::Other(format!("cannot reach {base}: {}", error_chain(&e))))?;
        let status = resp.status();
        if status.is_success() {
            return resp
                .json::<T>()
                .await
                .map_err(|e| CallError::Other(format!("bad answer from {base}{path}: {e}")));
        }
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"].as_str().unwrap_or("").to_string();
        Err(match status.as_u16() {
            401 => CallError::Auth(format!(
                "the primary rejected the replication token ({msg}); create a new API token of an administrator on the primary and put it in [follow].token"
            )),
            403 => CallError::Auth(format!(
                "the replication token's user is not an administrator on the primary ({msg})"
            )),
            409 => CallError::Refused(format!("{base} refused: {msg}")),
            404 => CallError::Other(format!(
                "{base}{path}: not found (is it a rust-dns web API URL, and a version with standby support?)"
            )),
            s => CallError::Other(format!("{base}{path}: HTTP {s} {msg}")),
        })
    }

    // ---- fencing (primary with [peer]) --------------------------------------

    async fn check_peer(&self, p: &PeerConfig) {
        let base = p.url.trim().trim_end_matches('/').to_string();
        let r: std::result::Result<Identity, _> = self
            .get(
                &base,
                None,
                "/api/replication/identity",
                Duration::from_secs(5),
            )
            .await;
        let mine = self.history();
        let result = match r {
            Err(e) => format!("peer not reachable: {e}"),
            Ok(id) => {
                if id.writable
                    && id.history.parent_history_id.as_deref() == Some(mine.history_id.as_str())
                {
                    let why = format!(
                        "this server is an old primary: {base} was promoted from its history{} and accepts writes; this server is read-only now. Make it a standby of the new primary ([follow] primary = \"{base}\" with an administrator token) or promote nothing and investigate",
                        id.history
                            .promoted_at
                            .as_deref()
                            .map(|t| format!(" on {t}"))
                            .unwrap_or_default()
                    );
                    tracing::error!("{why}");
                    self.set_role(Role::Fenced);
                    self.gate.close(why.clone());
                    why
                } else {
                    format!(
                        "ok: peer is {:?} with history {}",
                        id.role, id.history.history_id
                    )
                }
            }
        };
        if let Some(ps) = self.peer_status.lock().unwrap().as_mut() {
            ps.last_check_at = Some(now_rfc3339());
            ps.last_result = Some(result);
        }
    }

    // ---- promotion ------------------------------------------------------------

    /// Promote this standby. `Err((status, message))` for the API.
    pub async fn promote(
        self: &Arc<Self>,
        actor: Actor,
        force: bool,
        how: &'static str,
    ) -> std::result::Result<PromoteResult, (u16, String)> {
        let _g = self.promote_lock.lock().await;
        if self.role() != Role::Standby {
            return Err((
                409,
                format!(
                    "this server is not a standby (role: {:?}); nothing to promote",
                    self.role()
                )
                .to_lowercase(),
            ));
        }
        let url = self.primary_url();
        let reachable = self.follow_status.lock().unwrap().connected
            && self
                .last_contact
                .lock()
                .unwrap()
                .is_some_and(|t| t.elapsed() < REACHABLE_WITHIN);
        if reachable && !force {
            return Err((409, format!("the primary {url} is reachable: promoting now makes two writable servers. Stop the primary first, or send \"force\": true")));
        }
        // 1. The config file: no [follow] any more (abort if it cannot be written).
        let note = format!(
            "promoted to primary on {} (was a standby of {url})",
            now_rfc3339()
        );
        let config_updated = crate::config::remove_follow_section(&self.config_path, &note)
            .map_err(|e| {
                (
                    500,
                    format!(
                        "cannot remove [follow] from {}: {e:#}; nothing was changed",
                        self.config_path.display()
                    ),
                )
            })?;
        {
            // The running config matches the file again (a later reload
            // must not report [follow] as a pending change).
            let mut c = (*self.reloader.current.load_full()).clone();
            c.follow = None;
            self.reloader.current.store(Arc::new(c));
        }
        // 2. Stop following (an apply in flight completes or rolls back atomically).
        if let Some(h) = self.follower.lock().unwrap().take() {
            h.abort();
        }
        // 3. The database: new history, forked at the current offset.
        let h = self
            .mutator
            .replica_promote(actor, url.clone(), how)
            .await
            .map_err(|e| (500, format!("recording the promotion failed: {e}; the config no longer has [follow], so a restart completes the promotion")))?;
        // 4. Writable now; standbys will report to this server.
        self.set_role(Role::Promoted);
        self.start_replica_tracking();
        self.gate.open();
        self.update(|s| {
            s.state = "stopped".into();
            s.connected = false;
        });
        let _ = self.mutator.rebuild();
        self.mutator.wake_expiry();
        *self.warning.write().unwrap() = None;
        tracing::warn!(history_id = %h.history_id, parent = ?h.parent_history_id, fork_offset = ?h.fork_offset, previous_primary = %url, "PROMOTED: this server is now the primary and accepts writes");
        let mut notes = vec![format!(
            "This server now accepts writes. New history id {} (forked from {} at offset {}).",
            h.history_id,
            h.parent_history_id.clone().unwrap_or_default(),
            h.fork_offset.unwrap_or(0)
        )];
        notes.push(if config_updated {
            format!("[follow] was removed from {}.", self.config_path.display())
        } else {
            format!("{} had no [follow] section.", self.config_path.display())
        });
        notes.push(format!("Keep the old primary ({url}) from accepting writes: stop it, or give it [peer] url = <this server> so it starts read-only, then make it a standby of this server ([follow] primary = <this server's URL>, then rust-dns --prepare-standby --yes with it stopped). Its changes after offset {} are saved to a divergence file by --prepare-standby.", h.fork_offset.unwrap_or(0)));
        notes.push("Point zone secondaries (NOTIFY / AXFR) and the registrar's NS/glue at this server if they named the old primary.".into());
        Ok(PromoteResult {
            history: h,
            config_updated,
            notes,
        })
    }

    // ---- standby side -----------------------------------------------------------

    async fn run_follower(self: Arc<Self>) {
        if let Some(h) = crate::mutation::replica::halted(&self.storage) {
            tracing::error!(reason = %h.reason, detail = %h.detail, since = %h.at, report = ?h.report_file, "REPLICATION HALTED: this standby's data diverged from the primary; it serves its last state read-only and does not follow. Investigate, then rebuild it: stop it and run rust-dns --prepare-standby --yes");
            self.enter_halted(h).await;
            return;
        }
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            let err = self.follow_session().await;
            if let CallError::Halt {
                reason,
                detail,
                evidence,
            } = err
            {
                let h = self.halt(reason, detail, evidence).await;
                self.enter_halted(h).await;
                return;
            }
            let refused = matches!(err, CallError::Auth(_) | CallError::Refused(_));
            tracing::error!(primary = %self.primary_url(), error = %err, "replication: not following the primary; retrying");
            self.reconnects.fetch_add(1, Ordering::Relaxed);
            self.update(|s| {
                s.connected = false;
                s.state = if refused { "refused" } else { "error" }.into();
                s.last_error = Some(err.to_string());
                if s.disconnected_since.is_none() {
                    s.disconnected_since = Some(now_rfc3339());
                }
            });
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(if refused { 300 } else { 60 }));
        }
    }

    fn follow_cfg(&self) -> (String, String, Duration, Duration) {
        let f = self.follow.as_ref().expect("standby");
        (
            self.primary_url(),
            f.token.trim().to_string(),
            Duration::from_secs(f.timeout_secs.max(1)),
            Duration::from_secs(f.reconcile_interval_secs.max(1)),
        )
    }

    /// One connection: validate, align histories, then tail until an error.
    async fn follow_session(&self) -> CallError {
        match self.follow_session_inner().await {
            Ok(()) => CallError::Other("stopped".into()),
            Err(e) => e,
        }
    }

    async fn follow_session_inner(&self) -> std::result::Result<(), CallError> {
        let (base, token, timeout, reconcile_every) = self.follow_cfg();
        self.update(|s| s.state = "connecting".into());
        // Token valid and an administrator's (also re-checked by every call).
        let remote: ReplicationStatus = self
            .get(&base, Some(&token), "/api/replication/status", timeout)
            .await?;
        if remote.protocol != REPLICATION_PROTOCOL {
            return Err(CallError::Refused(format!(
                "{base} speaks replication protocol {} and this server {}: run the same rust-dns version on both (upgrade the primary first)",
                remote.protocol, REPLICATION_PROTOCOL
            )));
        }
        if !remote.writable {
            return Err(CallError::Refused(format!(
                "{base} is not a writable primary (role {:?}); a standby can only follow a primary",
                remote.role
            )));
        }
        self.contact_ok();
        self.update(|s| s.last_error = None);
        let local = self
            .local_view()
            .map_err(|e| CallError::Other(e.to_string()))?;
        let oldest = self
            .get::<ChangesResponse>(
                &base,
                Some(&token),
                &format!(
                    "/api/replication/changes?after={}&limit=1&wait=0&probe=true",
                    (local.head - 1).max(0)
                ),
                timeout,
            )
            .await?;
        let txn_matches = if local.history.history_id == remote.history.history_id && local.head > 0
        {
            let mine = self
                .storage
                .read_tx(|c| data::changelog_row(c, local.head))
                .ok()
                .flatten();
            match (mine, oldest.events.iter().find(|e| e.offset == local.head)) {
                (Some(a), Some(b)) => Some(a.txn == b.txn && a.ts == b.ts),
                _ => None,
            }
        } else {
            None
        };
        let rv = RemoteView {
            history: remote.history.clone(),
            head: oldest.head,
            oldest: oldest.oldest_offset,
            txn_matches_at_local_head: txn_matches,
        };
        let mut history_id = remote.history.history_id.clone();
        match lineage::plan(&local, &rv) {
            Plan::Refuse(why) => return Err(CallError::Refused(format!("{base}: {why}"))),
            Plan::Diverged { reason, detail } => {
                return Err(CallError::Halt {
                    reason,
                    detail,
                    evidence: serde_json::json!({
                        "local_history": local.history,
                        "local_head": local.head,
                        "primary_history": remote.history,
                        "primary_head": rv.head,
                        "primary_oldest": rv.oldest,
                    }),
                })
            }
            Plan::Tail { adopt } => {
                if adopt {
                    tracing::warn!(from = %local.history.history_id, to = %remote.history.history_id, "the primary was promoted from this server's history; continuing in its history");
                    self.mutator
                        .replica_adopt_history(remote.history.clone(), base.clone())
                        .await
                        .map_err(|e| CallError::Other(e.to_string()))?;
                }
            }
            Plan::NeedsFresh { why, data } => {
                return Err(CallError::Refused(format!(
                    "refusing to follow {base}: {why}. This server has data that following would replace: {}. Nothing was changed and it stays read-only. To discard its data on purpose (a backup and a divergence report are written first), stop the server and run: rust-dns --prepare-standby --yes --config {}",
                    data.join(", "),
                    self.config_path.display()
                )))
            }
            Plan::Bootstrap { reason } => {
                tracing::info!(reason = %reason, "replication: loading a snapshot from the primary");
                history_id = self.bootstrap(&base, &token, &reason).await?;
            }
        }
        let mut last_reconcile = Instant::now();
        self.update(|s| s.state = "following".into());
        loop {
            let head = self.storage.changelog_head().unwrap_or(0);
            // Wake up in time for the next reconcile.
            let wait = POLL_WAIT_SECS.min(
                reconcile_every
                    .saturating_sub(last_reconcile.elapsed())
                    .as_secs()
                    .max(1),
            );
            let resp: ChangesResponse = self
                .get(
                    &base,
                    Some(&token),
                    &format!(
                        "/api/replication/changes?after={head}&limit={POLL_LIMIT}&wait={wait}"
                    ),
                    timeout + Duration::from_secs(wait),
                )
                .await?;
            self.contact_ok();
            if resp.history_id != history_id {
                return Err(CallError::Other(format!(
                    "the primary's history changed ({} -> {}); reconnecting",
                    history_id, resp.history_id
                )));
            }
            self.update(|s| s.primary_head = Some(resp.head));
            if resp.gap {
                // Snapshots are loaded only when connecting: reconnect, and
                // the connection decides (same lineage + gap = snapshot).
                return Err(CallError::Other(
                    "the primary no longer has the changes this standby needs (retention); reconnecting".into(),
                ));
            }
            if !resp.events.is_empty() {
                // After the initial snapshot everything is changelog driven.
                // A change that does not apply means this copy is not the
                // primary's: halt, never "fix" it by reloading.
                let first = resp.events.first().map(|e| e.offset);
                let last = resp.events.last().map(|e| e.offset);
                if let Err(e) = self.apply(&history_id, resp.events).await {
                    return Err(CallError::Halt {
                        reason: "apply_failed",
                        detail: format!("a change from the primary did not apply: {e:#}"),
                        evidence: serde_json::json!({
                            "local_head": self.storage.changelog_head().unwrap_or(0),
                            "batch_first_offset": first,
                            "batch_last_offset": last,
                            "history_id": history_id,
                        }),
                    });
                }
            }
            let caught_up = self.storage.changelog_head().unwrap_or(0) == resp.head;
            if caught_up && last_reconcile.elapsed() >= reconcile_every {
                self.reconcile(&base, &token, timeout).await?;
                last_reconcile = Instant::now();
            }
        }
    }

    async fn apply(&self, history_id: &str, events: Vec<crate::model::ChangeEvent>) -> Result<()> {
        let n = events.len();
        let (head, runtime) = self
            .mutator
            .replica_apply(history_id.to_string(), events, self.local_root())
            .await
            .map_err(|e| anyhow!("{e}"))?;
        if runtime {
            self.after_accounts_change();
        }
        tracing::debug!(changes = n, head, "replication: applied");
        self.update(|s| s.last_applied_at = Some(now_rfc3339()));
        Ok(())
    }

    fn local_view(&self) -> Result<LocalView> {
        let root = self.local_root().username;
        self.storage.read_tx(|c| {
            let head = data::changelog_head(c)?;
            Ok(LocalView {
                history: data::history(c)?,
                head,
                data: data::fresh_problems(c, &root)?,
            })
        })
    }

    /// Load a snapshot. Returns its history id.
    async fn bootstrap(
        &self,
        base: &str,
        token: &str,
        reason: &str,
    ) -> std::result::Result<String, CallError> {
        self.update(|s| s.state = "bootstrapping".into());
        let timeout = Duration::from_secs(
            self.follow
                .as_ref()
                .map(|f| f.timeout_secs)
                .unwrap_or(30)
                .max(120),
        );
        let snap: Snapshot = match self
            .get(base, Some(token), "/api/replication/snapshot", timeout)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                self.update(|s| {
                    s.last_snapshot_at = Some(now_rfc3339());
                    s.last_snapshot_result = Some(format!("failed: {e}"));
                });
                return Err(e);
            }
        };
        if snap.format != REPLICATION_PROTOCOL {
            return Err(CallError::Refused(format!(
                "{base} sent a snapshot of format {} and this server reads {}: run the same rust-dns version on both",
                snap.format, REPLICATION_PROTOCOL
            )));
        }
        let h = snap.history.history_id.clone();
        let result = self
            .mutator
            .replica_bootstrap(snap, self.local_root(), base.to_string())
            .await;
        self.rebootstraps.fetch_add(1, Ordering::Relaxed);
        match result {
            Ok(sum) => {
                tracing::warn!(
                    reason,
                    offset = sum.offset,
                    zones = sum.zones,
                    records = sum.records,
                    users = sum.users,
                    "replication: snapshot loaded"
                );
                self.after_accounts_change();
                self.update(|s| {
                    s.last_snapshot_at = Some(now_rfc3339());
                    s.last_snapshot_result = Some(format!(
                        "ok: {} zones, {} records, {} users at offset {} ({reason})",
                        sum.zones, sum.records, sum.users, sum.offset
                    ));
                    s.last_applied_at = Some(now_rfc3339());
                    s.primary_head = Some(sum.offset);
                    s.state = "following".into();
                });
                Ok(h)
            }
            Err(e) => {
                self.update(|s| {
                    s.last_snapshot_at = Some(now_rfc3339());
                    s.last_snapshot_result = Some(format!("failed: {e}"));
                });
                Err(CallError::Other(format!(
                    "loading the snapshot failed: {e}"
                )))
            }
        }
    }

    /// Settings and TSIG keys may have changed: apply them to DNS now.
    fn after_accounts_change(&self) {
        if let Err(e) = self.dns.reload_tsig_keys(&self.storage) {
            tracing::error!(error = %e, "reloading TSIG keys after replication failed");
        }
        let cfg = self.reloader.current.load_full();
        match crate::mutation::settings::load_forwarding(&self.storage) {
            Ok(o) => self.dns.set_forwarding_override(o.map(|(f, _, _)| f), &cfg),
            Err(e) => tracing::error!(error = %e, "replicated forwarding settings are unreadable"),
        }
    }

    /// Compare checksums with the primary. A difference means a change was
    /// lost or misapplied (a bug): it is reported (log, status, metric) and
    /// following continues; the standby does not reload by itself (rebuild
    /// it on purpose with `--prepare-standby`).
    async fn reconcile(
        &self,
        base: &str,
        token: &str,
        timeout: Duration,
    ) -> std::result::Result<(), CallError> {
        let root = self.local_root().username;
        let remote: Checksums = self
            .get(
                base,
                Some(token),
                &format!(
                    "/api/replication/checksum?exclude_user={}",
                    url_encode(&root)
                ),
                timeout,
            )
            .await?;
        let (head, tables, zones) = self
            .storage
            .read_tx(|c| {
                Ok((
                    data::changelog_head(c)?,
                    tables::checksums(c, &root)?,
                    data::zone_checksums(c)?,
                ))
            })
            .map_err(|e| CallError::Other(e.to_string()))?;
        if remote.offset != head {
            // The primary moved on meanwhile; compare next time.
            return Ok(());
        }
        let mut diffs = Vec::new();
        let lmap: HashMap<&str, &ZoneChecksum> =
            zones.iter().map(|z| (z.name.as_str(), z)).collect();
        let rmap: HashMap<&str, &ZoneChecksum> =
            remote.zones.iter().map(|z| (z.name.as_str(), z)).collect();
        for (n, r) in &rmap {
            match lmap.get(n) {
                None => diffs.push(format!("zone {n}: missing here")),
                Some(l) if l.checksum != r.checksum => diffs.push(format!(
                    "zone {n}: differs (serial here {}, primary {})",
                    l.serial, r.serial
                )),
                _ => {}
            }
        }
        for n in lmap.keys() {
            if !rmap.contains_key(n) {
                diffs.push(format!("zone {n}: not on the primary"));
            }
        }
        for t in &tables {
            match remote.tables.iter().find(|r| r.table == t.table) {
                Some(r) if r.checksum == t.checksum => {}
                Some(r) => diffs.push(format!(
                    "table {}: differs ({} rows here, {} on the primary)",
                    t.table, t.rows, r.rows
                )),
                None => diffs.push(format!("table {}: unknown to the primary", t.table)),
            }
        }
        diffs.sort();
        let result = if diffs.is_empty() {
            format!(
                "ok: {} tables and {} zones match at offset {head}",
                tables.len(),
                zones.len()
            )
        } else {
            self.reconcile_mismatches.fetch_add(1, Ordering::Relaxed);
            format!("MISMATCH at offset {head}: {}", diffs.join("; "))
        };
        self.update(|s| {
            s.last_reconcile_at = Some(now_rfc3339());
            s.last_reconcile_result = Some(result);
        });
        if diffs.is_empty() {
            return Ok(());
        }
        Err(CallError::Halt {
            reason: "diverged",
            detail: format!(
                "reconcile at offset {head} found data that differs from the primary: {}",
                diffs.join("; ")
            ),
            evidence: serde_json::json!({
                "offset": head,
                "history_id": remote.history_id,
                "differences": diffs,
                "local": { "tables": tables, "zones": zones },
                "primary": { "tables": remote.tables, "zones": remote.zones },
            }),
        })
    }

    /// Record a halt: divergence report next to the database (no secrets:
    /// names, offsets and checksums), the terminal state in the database,
    /// the error log.
    async fn halt(
        &self,
        reason: &'static str,
        detail: String,
        evidence: serde_json::Value,
    ) -> HaltInfo {
        let offset = self.storage.changelog_head().unwrap_or(0);
        let db = self.reloader.current.load().database.path.clone();
        let dir = db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let path = dir.join(format!(
            "diverged-{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
        ));
        let doc = serde_json::json!({
            "written_at": now_rfc3339(),
            "instance_id": self.follow.as_ref().map(|f| f.instance_id.clone()),
            "primary": self.primary_url(),
            "reason": reason,
            "detail": detail,
            "offset": offset,
            "local_history": self.history(),
            "evidence": evidence,
            "what_now": "This standby stopped replicating because its copy differs from the primary (a bug: a standby never changes replicated data itself). It keeps answering DNS from its last state. Keep this file and the logs for the bug report, then rebuild the standby: stop it and run rust-dns --prepare-standby --yes --config <config>.",
        });
        let report_file = match serde_json::to_string_pretty(&doc)
            .map_err(anyhow::Error::from)
            .and_then(|t| crate::config::create_private(&path, &t))
        {
            Ok(()) => Some(path.display().to_string()),
            Err(e) => {
                tracing::error!(error = %e, "cannot write the divergence report");
                None
            }
        };
        let info = HaltInfo {
            reason: reason.to_string(),
            detail,
            at: now_rfc3339(),
            offset,
            report_file,
        };
        tracing::error!(reason = %info.reason, detail = %info.detail, offset, report = ?info.report_file, "REPLICATION HALTED: this standby's data diverged from the primary; it stops following and serves its last state read-only. Investigate, then rebuild it: stop it and run rust-dns --prepare-standby --yes");
        if let Err(e) = self.mutator.replica_halt(info.clone()).await {
            tracing::error!(error = %e, "cannot record the halt in the database (it is re-detected at the next start)");
        }
        info
    }

    /// Halted: stop replicating; tell the primary (until it has heard it,
    /// once per start).
    async fn enter_halted(&self, h: HaltInfo) {
        self.update(|s| {
            s.state = "halted".into();
            s.connected = false;
            s.halted = Some(h.clone());
            s.last_error = Some(format!("replication halted ({}): {}", h.reason, h.detail));
        });
        let (base, token, timeout, _) = self.follow_cfg();
        let Some(f) = &self.follow else { return };
        let body = ReplicaReport {
            state: "halted".into(),
            reason: h.reason.clone(),
            detail: h.detail.clone(),
        };
        let url = format!(
            "{base}/api/replication/replicas/{}/report",
            url_encode(f.instance_id.trim())
        );
        let mut backoff = Duration::from_secs(1);
        loop {
            let r = self
                .http
                .post(&url)
                .timeout(timeout)
                .bearer_auth(&token)
                .header(replicas::HEADER_INSTANCE, f.instance_id.trim())
                .header(replicas::HEADER_VERSION, env!("CARGO_PKG_VERSION"))
                .header(replicas::HEADER_SESSION, &self.session)
                .json(&body)
                .send()
                .await;
            match r {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("reported the halt to the primary");
                    return;
                }
                Ok(resp) if resp.status().is_client_error() => {
                    tracing::warn!(status = %resp.status(), "the primary refused the halt report; not retrying");
                    return;
                }
                _ => {}
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
    }
}

/// Percent-encode a query value.
fn url_encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `reqwest` errors hide the useful part (connection refused, TLS) in the
/// source chain.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        s.push_str(": ");
        s.push_str(&c.to_string());
        src = c.source();
    }
    s
}

/// `rust-dns --promote`: promote a stopped standby from the command line.
pub async fn promote_offline(config_path: &std::path::Path) -> Result<History> {
    let cfg = crate::config::check(config_path)?;
    let storage = Arc::new(Storage::open(&cfg.database.path)?);
    let st = storage.replication_state()?;
    let from = match (&cfg.follow, st.get(K_FOLLOWING)) {
        (Some(f), _) => f.primary.trim().trim_end_matches('/').to_string(),
        (None, Some(u)) => u.clone(),
        (None, None) => anyhow::bail!(
            "{} has no [follow] section and the database is not a standby: nothing to promote",
            config_path.display()
        ),
    };
    if let Err(e) = std::net::TcpListener::bind(cfg.web_console.bind) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::bail!(
                "the web console address {} is in use: is rust-dns running? Promote a running server from the console (Admin -> Replication) or with POST /api/replication/promote, or stop it first",
                cfg.web_console.bind
            );
        }
    }
    if cfg.follow.is_some() {
        crate::config::remove_follow_section(
            config_path,
            &format!(
                "promoted to primary with --promote on {} (was a standby of {from})",
                now_rfc3339()
            ),
        )?;
    }
    let cache = Arc::new(crate::cache::Cache::new(crate::cache::Catalog::empty()));
    let bus = Arc::new(crate::events::Bus::new(8, 8));
    let m = Mutator::new(storage, cache, bus, "", "");
    let h = m
        .replica_promote(
            Actor {
                name: "cli".into(),
                ip: "local".into(),
            },
            from,
            "cli",
        )
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(h)
}

/// `rust-dns --prepare-standby [--yes]`: discard this server's data on
/// purpose so it can follow the `[follow]` primary. Without `yes` it only
/// prints what would be deleted and returns `Ok(false)`. With `yes` it
/// writes a full online backup next to the database, a divergence report
/// (the changes the primary does not have) when there is one, then empties
/// the database (see `mutation::replica::prepare_standby`).
pub async fn prepare_standby_offline(config_path: &std::path::Path, yes: bool) -> Result<bool> {
    let cfg = crate::config::check(config_path)?;
    let Some(follow) = cfg.follow.clone() else {
        anyhow::bail!(
            "{} has no [follow] section: add the [follow] section for the primary this server should mirror first",
            config_path.display()
        );
    };
    let db = cfg.database.path.clone();
    if !db.exists() {
        println!(
            "{} does not exist yet: nothing to prepare, the server starts fresh",
            db.display()
        );
        return Ok(true);
    }
    if let Err(e) = std::net::TcpListener::bind(cfg.web_console.bind) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::bail!(
                "the web console address {} is in use: stop rust-dns before preparing it as a standby",
                cfg.web_console.bind
            );
        }
    }
    let root = cfg.root.username.clone();
    // Inspect read-only: a dry run must not touch the database at all.
    let (data_list, rows, head, local_hist, lineage_markers) = {
        let ro =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let rows: i64 = ro.query_row("SELECT COUNT(*) FROM changelog", [], |r| r.get(0))?;
        let st = crate::storage::replication_state(&ro).unwrap_or_default();
        (
            data::fresh_problems(&ro, &root)?,
            rows,
            data::changelog_head(&ro)?,
            data::history(&ro).unwrap_or_default(),
            st.keys().any(|k| k != "history_id"),
        )
    };
    if data_list.is_empty() && rows == 0 && !lineage_markers {
        println!("{} is already fresh: nothing to delete", db.display());
        return Ok(true);
    }
    println!("--prepare-standby would delete from {}:", db.display());
    for d in &data_list {
        println!("  - {d}");
    }
    if rows > 0 {
        println!(
            "  - {rows} changelog rows (history {})",
            local_hist.history_id
        );
    }
    if lineage_markers {
        println!("  - the replication lineage (history, promotion and standby records)");
    }
    println!("and keep: the config root '{root}', the audit log.");
    if !yes {
        println!(
            "Nothing was changed. Re-run with --yes to back up the database and delete this data."
        );
        return Ok(false);
    }
    {
        // Another process holding a write lock (or a crashed writer) refuses.
        let probe = rusqlite::Connection::open(&db)?;
        probe.busy_timeout(Duration::from_millis(0))?;
        probe
            .execute_batch("BEGIN EXCLUSIVE; ROLLBACK;")
            .with_context(|| {
                format!("{} is locked or in use; stop rust-dns first", db.display())
            })?;
    }
    let storage = Storage::open(&db)?;
    let dir = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let stem = db
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rust-dns.db".into());
    let backup = dir.join(format!("{stem}.pre-standby-{stamp}"));
    storage.backup_to(&backup)?;
    Storage::open(&backup)
        .and_then(|b| b.check())
        .with_context(|| format!("verifying the backup {}", backup.display()))?;
    println!("backup written: {}", backup.display());
    // Divergence report: the local changes the primary does not have.
    let mut divergence = None;
    if rows > 0 {
        ensure_crypto();
        let base = follow.primary.trim().trim_end_matches('/').to_string();
        let remote = reqwest::Client::new()
            .get(format!("{base}/api/replication/identity"))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()
            .filter(|r| r.status().is_success());
        let remote = match remote {
            Some(r) => r.json::<Identity>().await.ok(),
            None => None,
        };
        let (fork, note) = match &remote {
            Some(id) if id.history.history_id == local_hist.history_id => {
                (Some(head), "same history as the primary: no divergent changes")
            }
            Some(id) if id.history.parent_history_id.as_deref() == Some(local_hist.history_id.as_str()) => (
                id.history.fork_offset,
                "the primary was promoted from this server's history: changes after fork_offset exist only here",
            ),
            Some(_) => (None, "unrelated history: every retained local change is listed"),
            None => (None, "the primary was not reachable, so the fork point is unknown: every retained local change is listed"),
        };
        let tail = storage.read_tx(|c| data::changelog_tail(c, fork.unwrap_or(0)))?;
        if !tail.is_empty() {
            let dump = storage.read_tx(data::dns_dump)?;
            let doc = serde_json::json!({
                "written_at": now_rfc3339(),
                "primary": base,
                "local_history": local_hist,
                "local_head": head,
                "primary_history": remote.as_ref().map(|r| &r.history),
                "fork_offset": fork,
                "note": note,
                "divergent_changes": tail,
                "local_dns_data": dump,
                "backup": backup.display().to_string(),
            });
            let path = dir.join(format!("divergent-{stamp}.json"));
            crate::config::create_private(&path, &serde_json::to_string_pretty(&doc)?)?;
            println!(
                "divergent changes ({}) written: {}",
                tail.len(),
                path.display()
            );
            divergence = Some(path.display().to_string());
        }
    }
    let sum = crate::mutation::replica::prepare_standby(
        &storage,
        &root,
        &backup.display().to_string(),
        divergence.as_deref(),
    )?;
    println!(
        "deleted: {} zones, {} records, {} zone members, {} changelog rows, {} TSIG keys, {} settings, {} API tokens, {} users, {} sessions",
        sum.zones, sum.records, sum.zone_members, sum.changelog_rows, sum.tsig_keys, sum.settings, sum.api_tokens, sum.users, sum.sessions
    );
    println!(
        "This server is fresh now. Start it: it will copy {base} and follow it.",
        base = follow.primary
    );
    Ok(true)
}
