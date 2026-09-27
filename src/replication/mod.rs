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
//!   (one read transaction) to start, then a long-poll of the changelog
//!   (whole transactions, applied with the primary's offsets) and the
//!   account data whenever its generation changes, plus a periodic checksum
//!   reconcile. All writes go through `mutation::replica`.
//! * Every database has a history id. A standby adopts its primary's; a
//!   promotion starts a new one whose parent is the old one (forked at the
//!   current offset). [`lineage::plan`] uses this to continue, adopt a
//!   promoted primary's history, refuse to follow a stale old primary, or
//!   re-bootstrap after saving divergent changes to a JSON file.

pub mod data;
pub mod lineage;
pub mod types;

use crate::config::{FollowConfig, PeerConfig};
use crate::dns::DnsServer;
use crate::model::{now_rfc3339, Actor};
use crate::mutation::replica::{LocalRoot, K_ACCOUNTS_CHECKSUM, K_FOLLOWING};
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

/// Audit actions that change replicated account data (everything except
/// sessions, reveals, cache flushes and replication bookkeeping).
pub fn replicated_action(action: &str) -> bool {
    !(action.starts_with("session.")
        || action.starts_with("replication.")
        || action == "tsig.reveal"
        || action == "settings.forwarding.cache_flush")
}

/// Why a request to the primary failed.
#[derive(Debug)]
enum CallError {
    /// 401/403: the token was rejected or is not an administrator's.
    Auth(String),
    /// 409 or similar: the server is not a writable primary.
    Refused(String),
    Other(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Auth(m) | CallError::Refused(m) | CallError::Other(m) => f.write_str(m),
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
    epoch: String,
    generation: tokio::sync::watch::Sender<u64>,
    standbys: Mutex<HashMap<String, (StandbySeen, Instant)>>,
    // Standby side.
    follower: Mutex<Option<tokio::task::JoinHandle<()>>>,
    promote_lock: tokio::sync::Mutex<()>,
    reconnects: AtomicU64,
    rebootstraps: AtomicU64,
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
            state: "starting".into(),
            ..Default::default()
        };
        let (generation, _) = tokio::sync::watch::channel(0u64);
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
            epoch: crate::auth::random_token(6),
            generation,
            standbys: Mutex::new(HashMap::new()),
            follower: Mutex::new(None),
            promote_lock: tokio::sync::Mutex::new(()),
            reconnects: AtomicU64::new(0),
            rebootstraps: AtomicU64::new(0),
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
            password_hash: cfg.root.password.clone(),
            mfa_required: cfg.root.mfa_required,
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
    pub fn bump_generation(&self) {
        self.generation.send_modify(|g| *g += 1);
    }

    pub fn generation(&self) -> String {
        format!("{}-{}", self.epoch, *self.generation.borrow())
    }

    pub fn subscribe_generation(&self) -> tokio::sync::watch::Receiver<u64> {
        self.generation.subscribe()
    }

    pub fn note_standby(&self, address: String, user: String, after: i64) {
        let mut m = self.standbys.lock().unwrap();
        m.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(600));
        let key = format!("{address} {user}");
        m.insert(
            key,
            (
                StandbySeen {
                    address,
                    user,
                    after,
                    last_seen_at: now_rfc3339(),
                },
                Instant::now(),
            ),
        );
    }

    // ---- status -------------------------------------------------------------

    pub fn identity(&self) -> Identity {
        Identity {
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
        let mut standbys: Vec<StandbySeen> = self
            .standbys
            .lock()
            .unwrap()
            .values()
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(600))
            .map(|(s, _)| s.clone())
            .collect();
        standbys.sort_by(|a, b| a.address.cmp(&b.address));
        ReplicationStatus {
            role,
            writable: self.writable(),
            history: self.history(),
            head: self.storage.changelog_head().unwrap_or(0),
            read_only_reason: self.read_only_reason(),
            follow: (role == Role::Standby).then(|| self.follow_snapshot()),
            peer: self.peer_status.lock().unwrap().clone(),
            standbys,
            warning: self.warning.read().unwrap().clone(),
        }
    }

    pub fn summary(&self) -> ReplicationSummary {
        let role = self.role();
        let (primary, connected, lag, since) = match role {
            Role::Standby => {
                let f = self.follow_snapshot();
                (
                    Some(f.primary),
                    f.connected,
                    f.lag_changes,
                    f.disconnected_since,
                )
            }
            Role::Fenced => (self.peer.as_ref().map(|p| p.url.clone()), false, None, None),
            _ => (None, false, None, None),
        };
        ReplicationSummary {
            role,
            writable: self.writable(),
            primary,
            connected,
            lag_changes: lag,
            disconnected_since: since,
            read_only_reason: self.read_only_reason(),
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
        if role == Role::Standby {
            let f = self.follow_snapshot();
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
        let mut req = self.http.get(&url).timeout(timeout);
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
        // 4. Writable now.
        self.set_role(Role::Promoted);
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
        notes.push(format!("Keep the old primary ({url}) from accepting writes: stop it, or give it [peer] url = <this server> so it starts read-only, then make it a standby of this server ([follow] primary = <this server's URL>). Changes it made after offset {} are saved to a divergence file when it rejoins.", h.fork_offset.unwrap_or(0)));
        notes.push("Point zone secondaries (NOTIFY / AXFR) and the registrar's NS/glue at this server if they named the old primary.".into());
        Ok(PromoteResult {
            history: h,
            config_updated,
            notes,
        })
    }

    // ---- standby side -----------------------------------------------------------

    async fn run_follower(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            let err = self.follow_session().await;
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
                    "/api/replication/changes?after={}&limit=1&wait=0",
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
        let mut generation = String::new();
        match lineage::plan(&local, &rv) {
            Plan::Refuse(why) => return Err(CallError::Refused(format!("{base}: {why}"))),
            Plan::Tail { adopt } => {
                if adopt {
                    tracing::warn!(from = %local.history.history_id, to = %remote.history.history_id, "the primary was promoted from this server's history; continuing in its history");
                    self.mutator
                        .replica_adopt_history(remote.history.clone(), base.clone())
                        .await
                        .map_err(|e| CallError::Other(e.to_string()))?;
                }
            }
            Plan::Bootstrap {
                divergent,
                fork,
                reason,
            } => {
                if divergent {
                    self.save_divergence(&reason, fork, &local, &remote.history)
                        .map_err(|e| {
                            CallError::Other(format!("saving divergent changes: {e:#}"))
                        })?;
                }
                tracing::info!(reason = %reason, "replication: loading a snapshot from the primary");
                let (h, g) = self.bootstrap(&base, &token, &reason).await?;
                history_id = h;
                generation = g;
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
                let (h, g) = self
                    .bootstrap(
                        &base,
                        &token,
                        "the primary no longer has the changes this standby needs (retention)",
                    )
                    .await?;
                history_id = h;
                generation = g;
                continue;
            }
            if !resp.events.is_empty() {
                if let Err(e) = self.apply(&history_id, resp.events.clone()).await {
                    // Usually a change that refers to a user the standby has
                    // not seen yet: sync accounts and retry once.
                    tracing::warn!(error = %e, "replication: a change did not apply; re-syncing accounts and retrying");
                    generation = self.sync_accounts(&base, &token, timeout).await?;
                    if let Err(e) = self.apply(&history_id, resp.events).await {
                        let (h, g) = self
                            .bootstrap(
                                &base,
                                &token,
                                &format!("a change from the primary did not apply: {e}"),
                            )
                            .await?;
                        history_id = h;
                        generation = g;
                        continue;
                    }
                }
            }
            if resp.accounts_generation != generation {
                generation = self.sync_accounts(&base, &token, timeout).await?;
            }
            let caught_up = self.storage.changelog_head().unwrap_or(0) == resp.head;
            if caught_up && last_reconcile.elapsed() >= reconcile_every {
                if let Some(reason) = self.reconcile(&base, &token, timeout).await? {
                    let (h, g) = self.bootstrap(&base, &token, &reason).await?;
                    history_id = h;
                    generation = g;
                }
                last_reconcile = Instant::now();
            }
        }
    }

    async fn apply(&self, history_id: &str, events: Vec<crate::model::ChangeEvent>) -> Result<()> {
        let n = events.len();
        let head = self
            .mutator
            .replica_apply(history_id.to_string(), events)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        tracing::debug!(changes = n, head, "replication: applied");
        self.update(|s| s.last_applied_at = Some(now_rfc3339()));
        Ok(())
    }

    fn local_view(&self) -> Result<LocalView> {
        self.storage.read_tx(|c| {
            let head = data::changelog_head(c)?;
            let zones: i64 = c.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?;
            Ok(LocalView {
                history: data::history(c)?,
                head,
                empty: head == 0 && zones == 0,
            })
        })
    }

    /// Load a snapshot. Returns (history id, account generation).
    async fn bootstrap(
        &self,
        base: &str,
        token: &str,
        reason: &str,
    ) -> std::result::Result<(String, String), CallError> {
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
        let (h, g) = (
            snap.history.history_id.clone(),
            snap.accounts.generation.clone(),
        );
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
                    users = sum.accounts.users,
                    "replication: snapshot loaded"
                );
                self.after_accounts_change();
                self.update(|s| {
                    s.last_snapshot_at = Some(now_rfc3339());
                    s.last_snapshot_result = Some(format!(
                        "ok: {} zones, {} records, {} users at offset {} ({reason})",
                        sum.zones, sum.records, sum.accounts.users, sum.offset
                    ));
                    s.last_accounts_sync_at = Some(now_rfc3339());
                    s.last_applied_at = Some(now_rfc3339());
                    s.primary_head = Some(sum.offset);
                    s.state = "following".into();
                });
                Ok((h, g))
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

    /// Fetch and apply the account data; returns its generation.
    async fn sync_accounts(
        &self,
        base: &str,
        token: &str,
        timeout: Duration,
    ) -> std::result::Result<String, CallError> {
        let acc: AccountsSnapshot = self
            .get(base, Some(token), "/api/replication/accounts", timeout)
            .await?;
        let generation = acc.generation.clone();
        match self
            .mutator
            .replica_accounts(acc, self.local_root(), base.to_string())
            .await
        {
            Ok(Some(sum)) => {
                tracing::info!(
                    users = sum.users,
                    added = sum.users_added,
                    updated = sum.users_updated,
                    removed = sum.users_removed,
                    tokens = sum.tokens,
                    tsig_keys = sum.tsig_keys,
                    "replication: account data synced"
                );
                self.after_accounts_change();
            }
            Ok(None) => {}
            Err(e) => {
                return Err(CallError::Other(format!(
                    "applying account data failed: {e}"
                )))
            }
        }
        self.update(|s| s.last_accounts_sync_at = Some(now_rfc3339()));
        Ok(generation)
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

    /// Compare checksums with the primary. `Some(reason)`: re-bootstrap.
    async fn reconcile(
        &self,
        base: &str,
        token: &str,
        timeout: Duration,
    ) -> std::result::Result<Option<String>, CallError> {
        let remote: Checksums = self
            .get(base, Some(token), "/api/replication/checksum", timeout)
            .await?;
        let (head, local) = self
            .storage
            .read_tx(|c| Ok((data::changelog_head(c)?, data::zone_checksums(c)?)))
            .map_err(|e| CallError::Other(e.to_string()))?;
        if remote.offset != head {
            // The primary moved on meanwhile; compare next time.
            return Ok(None);
        }
        let mut diffs = Vec::new();
        let lmap: HashMap<&str, &ZoneChecksum> =
            local.iter().map(|z| (z.name.as_str(), z)).collect();
        let rmap: HashMap<&str, &ZoneChecksum> =
            remote.zones.iter().map(|z| (z.name.as_str(), z)).collect();
        for (n, r) in &rmap {
            match lmap.get(n) {
                None => diffs.push(format!("{n}: missing here")),
                Some(l) if l.checksum != r.checksum => diffs.push(format!(
                    "{n}: differs (serial here {}, primary {})",
                    l.serial, r.serial
                )),
                _ => {}
            }
        }
        for n in lmap.keys() {
            if !rmap.contains_key(n) {
                diffs.push(format!("{n}: not on the primary"));
            }
        }
        diffs.sort();
        let accounts_ok = self
            .storage
            .replication_state()
            .ok()
            .and_then(|s| s.get(K_ACCOUNTS_CHECKSUM).cloned())
            == Some(remote.accounts_checksum.clone());
        if !accounts_ok {
            tracing::warn!(
                "replication reconcile: account data differs from the primary; re-syncing"
            );
            self.sync_accounts(base, token, timeout).await?;
        }
        let result = if diffs.is_empty() {
            format!(
                "ok: {} zones match at offset {head}{}",
                local.len(),
                if accounts_ok {
                    ""
                } else {
                    "; account data re-synced"
                }
            )
        } else {
            tracing::warn!(differences = ?diffs, "replication reconcile: zone data differs from the primary; re-bootstrapping");
            format!("mismatch, re-bootstrapped: {}", diffs.join("; "))
        };
        self.update(|s| {
            s.last_reconcile_at = Some(now_rfc3339());
            s.last_reconcile_result = Some(result);
        });
        Ok((!diffs.is_empty())
            .then(|| format!("reconcile found differences: {}", diffs.join("; "))))
    }

    /// Write the local changes the primary does not have (and the local DNS
    /// data) to a JSON file next to the database, before a snapshot replaces
    /// them. No account data or secrets.
    fn save_divergence(
        &self,
        reason: &str,
        fork: Option<i64>,
        local: &LocalView,
        remote: &History,
    ) -> Result<PathBuf> {
        let db = self.reloader.current.load().database.path.clone();
        let dir = db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let (tail, dump) = self.storage.read_tx(|c| {
            Ok((
                data::changelog_tail(c, fork.unwrap_or(0))?,
                data::dns_dump(c)?,
            ))
        })?;
        let doc = serde_json::json!({
            "written_at": now_rfc3339(),
            "reason": reason,
            "primary": self.primary_url(),
            "local_history": local.history,
            "local_head": local.head,
            "primary_history": remote,
            "fork_offset": fork,
            "note": if fork.is_some() { "changes after fork_offset exist only on this server" } else { "fork point unknown: every retained local change is listed" },
            "divergent_changes": tail,
            "local_dns_data_before_rebootstrap": dump,
        });
        let path = dir.join(format!(
            "divergent-{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
        ));
        crate::config::create_private(&path, &serde_json::to_string_pretty(&doc)?)
            .with_context(|| format!("writing {}", path.display()))?;
        tracing::warn!(path = %path.display(), changes = tail.len(), reason, "DIVERGED: this server's changes that the primary does not have were saved for manual review; re-bootstrapping from the primary");
        Ok(path)
    }
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
