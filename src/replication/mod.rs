//! Standby ("follow") mode: a second rust-dns mirrors a primary so it can
//! answer every DNS query while the primary is down, refuses mutations,
//! and can be promoted by hand. Not a load-balanced cluster.
//!
//! * Roles: `primary` (writable), `promoted` (writable, was a standby),
//!   `standby` (`[follow]` in the config: read-only mirror) and `fenced`
//!   (an old primary whose `[peer]` was promoted from its history:
//!   read-only). The role is decided at startup from the config and the
//!   database; promotion switches a standby to `promoted` at runtime.
//! * Replication is changelog v2 (`crates/sqlite-cdc`): the primary serves
//!   its trigger-captured log at `/rust-dns/changelog-api/v2` (behind the
//!   `replicate` permission); a standby follows it with the crate's `Node`
//!   (a snapshot first, then a stream, with periodic verification), and
//!   halts on any divergence until an operator rebootstraps it.
//! * Every database also keeps a v1 history id (`replication_state`): a
//!   promotion starts a new one whose parent is the old one, which is how
//!   a returning old primary with `[peer]` finds out it was replaced
//!   (fencing). A database with other data is never replaced implicitly:
//!   `--prepare-standby` backs it up and empties it on the operator's
//!   explicit request.

pub mod data;
pub mod replicas;
pub mod tables;
pub mod types;

use crate::config::{FollowConfig, PeerConfig};
use crate::dns::DnsServer;
use crate::model::{now_rfc3339, Actor};
use crate::mutation::replica::K_FOLLOWING;
use crate::mutation::{Mutator, WriteGate};
use crate::storage::Storage;
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use types::*;

/// Everything the replication runtime needs from the rest of the server.
pub struct Replication {
    storage: Arc<Storage>,
    mutator: Arc<Mutator>,
    gate: Arc<WriteGate>,
    reloader: Arc<crate::reload::Reloader>,
    config_path: PathBuf,
    /// `[follow]`: changes at runtime only through a rebootstrap with new
    /// parameters (which also rewrites the config file).
    follow: RwLock<Option<FollowConfig>>,
    /// Changelog v2: the follower on a standby, the client tracker and the
    /// served protocol on a primary (`/rust-dns/changelog-api/v2`).
    cdc: Option<Arc<sqlite_cdc::node::Node>>,
    peer: Option<PeerConfig>,
    role: RwLock<Role>,
    peer_status: Mutex<Option<PeerStatus>>,
    warning: RwLock<Option<String>>,
    /// Serializes promotion and rebootstrap.
    promote_lock: tokio::sync::Mutex<()>,
    /// To the primary (`[follow]`, its `ca_file`).
    http: reqwest::Client,
    /// To the standby of `[peer]` (its `ca_file`).
    peer_http: reqwest::Client,
}

/// The HTTPS client of a replication peer. O23: with a `ca_file` (PEM),
/// only the CA certificates in it are trusted for that peer (a private
/// CA; verified by webpki the same way on every OS); without one, the
/// system's trust store.
pub fn https_client(ca_file: Option<&str>, key: &str) -> Result<reqwest::Client> {
    ensure_crypto();
    let mut b = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("rust-dns/", env!("CARGO_PKG_VERSION"), " standby"))
        .https_only(false);
    if let Some(path) = ca_file.map(str::trim).filter(|p| !p.is_empty()) {
        b = b.tls_certs_only(crate::config::load_ca_file(key, path)?);
    }
    b.build().map_err(|e| anyhow!("HTTP client ({key}): {e}"))
}

pub(crate) fn ensure_crypto() {
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
        // The CA files were checked with the rest of the configuration.
        let http = https_client(
            cfg.follow.as_ref().map(|f| f.ca_file.as_str()),
            "[follow].ca_file",
        )
        .expect("HTTP client for [follow]");
        let peer_http = https_client(
            cfg.peer.as_ref().map(|p| p.ca_file.as_str()),
            "[peer].ca_file",
        )
        .expect("HTTP client for [peer]");
        let cdc = storage.cdc().map(|store| {
            let mut nc = sqlite_cdc::node::NodeConfig::new("");
            nc.client = Some(sqlite_cdc::client::ClientTemplate {
                http: http.clone(),
                headers: cdc_headers(cfg.follow.as_ref()),
            });
            nc.name = cfg
                .follow
                .as_ref()
                .map(|f| f.instance_id.trim().to_string());
            nc.mode = sqlite_cdc::node::FollowMode::Stream;
            nc.verify_every = cfg
                .follow
                .as_ref()
                .map(|f| Duration::from_secs(f.reconcile_interval_secs.max(60)));
            nc.on_applied = Some(applied_hook(
                storage.clone(),
                mutator.clone(),
                dns,
                reloader.clone(),
            ));
            sqlite_cdc::node::Node::new(store.clone(), nc)
        });
        Arc::new(Replication {
            gate: mutator.gate(),
            storage,
            mutator,
            reloader,
            config_path,
            follow: RwLock::new(cfg.follow.clone()),
            cdc,
            peer: cfg.peer.clone(),
            role: RwLock::new(Role::Primary),
            peer_status: Mutex::new(cfg.peer.as_ref().map(|p| PeerStatus {
                url: p.url.clone(),
                last_check_at: None,
                last_result: None,
            })),
            warning: RwLock::new(None),
            promote_lock: tokio::sync::Mutex::new(()),
            http,
            peer_http,
        })
    }

    // ---- role -------------------------------------------------------------

    pub fn role(&self) -> Role {
        *self.role.read().unwrap_or_else(|p| p.into_inner())
    }

    fn set_role(&self, r: Role) {
        *self.role.write().unwrap_or_else(|p| p.into_inner()) = r;
        // Changelog v2 follows the role: only a writable primary is
        // its leader.
        self.storage
            .cdc_set_leader(matches!(r, Role::Primary | Role::Promoted));
    }

    pub fn writable(&self) -> bool {
        !self.gate.read_only()
    }

    /// The message for refused writes, when read-only.
    pub fn read_only_reason(&self) -> Option<String> {
        self.gate.read_only().then(|| self.gate.reason())
    }

    /// The current `[follow]` (None on a primary).
    fn follow(&self) -> Option<FollowConfig> {
        self.follow
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn primary_url(&self) -> String {
        self.follow()
            .map(|f| f.primary.trim().trim_end_matches('/').to_string())
            .unwrap_or_default()
    }

    /// This server's own `[root]` username.
    fn local_root(&self) -> String {
        self.reloader.current.load().root.username.clone()
    }

    fn history(&self) -> History {
        self.storage.read_tx(data::history).unwrap_or_default()
    }

    /// Decide the role and start the background tasks. Runs before the
    /// web listener starts, so a standby or fenced server never accepts a
    /// write, not even briefly.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let st = self.storage.replication_state()?;
        if self.follow().is_some() {
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
            // Changelog v2: follow the primary's v2 log (a fresh database
            // first loads a snapshot, then streams).
            let node = self.cdc.clone().ok_or_else(|| {
                anyhow!("changelog v2 is not attached: this server cannot follow")
            })?;
            let v2 = format!("{url}/rust-dns/changelog-api/v2");
            node.start_follow(&v2)
                .await
                .map_err(|e| anyhow!("starting to follow {v2}: {e}"))?;
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

    /// The standbys following this server's v2 log.
    pub fn replica_list(&self) -> Vec<replicas::ReplicaInfo> {
        let Some(n) = &self.cdc else {
            return Vec::new();
        };
        let head = n.store.state().map(|s| s.last_txn).unwrap_or(0);
        let cfg = self.reloader.current.load().replication.clone();
        let now = chrono::Utc::now();
        n.clients
            .list(head)
            .into_iter()
            .map(|c| {
                let seen = chrono::DateTime::from_timestamp(c.last_seen as i64, 0).unwrap_or(now);
                let first = chrono::DateTime::from_timestamp(c.first_seen as i64, 0).unwrap_or(now);
                let idle = (now - seen).num_seconds().max(0);
                let state = if c.mode == "snapshot" && !c.up_to_date {
                    replicas::ReplicaState::Bootstrapping
                } else if !c.connected && idle as u64 > cfg.offline_after_secs {
                    replicas::ReplicaState::Offline
                } else if c.up_to_date {
                    replicas::ReplicaState::UpToDate
                } else if c.lag_txns > cfg.max_lag_changes {
                    replicas::ReplicaState::FallingBehind
                } else {
                    replicas::ReplicaState::CatchingUp
                };
                replicas::ReplicaInfo {
                    instance: c.name.clone(),
                    state,
                    conflict: false,
                    applied_offset: c.position as i64,
                    head: head as i64,
                    lag_changes: c.lag_txns as i64,
                    lag_seconds: if c.up_to_date { 0 } else { idle },
                    last_seen_at: seen.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    last_caught_up_at: c
                        .up_to_date
                        .then(|| seen.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                    first_seen_at: first.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    address: c.addr.clone().unwrap_or_default(),
                    version: "changelog v2".into(),
                    user: c.principal.clone().unwrap_or_default(),
                    bootstrapping: c.mode == "snapshot" && !c.up_to_date,
                    halted_reason: None,
                }
            })
            .collect()
    }

    /// Whether `instance` is in the replica list (changelog v2 keeps it in
    /// memory and drops a follower by itself a day after its last request).
    pub fn knows_replica(&self, instance: &str) -> bool {
        self.replica_list().iter().any(|r| r.instance == instance)
    }

    // ---- status -------------------------------------------------------------

    pub fn identity(&self) -> Identity {
        Identity {
            protocol: REPLICATION_PROTOCOL,
            role: self.role(),
            writable: self.writable(),
            history: self.history(),
            changelog_v2: self.cdc_identity(),
        }
    }

    fn cdc_identity(&self) -> Option<CdcIdentity> {
        let st = self.cdc.as_ref()?.store.state().ok()?;
        Some(CdcIdentity {
            history: st.history,
            role: st.role.as_str().into(),
            last_txn: st.last_txn,
        })
    }

    /// The v2 follower's state, in the shape the API and console know.
    fn follow_snapshot(&self) -> FollowStatus {
        let cfg = self.follow();
        let mut f = FollowStatus {
            primary: cfg.as_ref().map(|c| c.primary.clone()).unwrap_or_default(),
            instance_id: cfg
                .as_ref()
                .map(|c| c.instance_id.trim().to_string())
                .unwrap_or_default(),
            state: "starting".into(),
            ..Default::default()
        };
        let Some(n) = &self.cdc else {
            f.state = "stopped".into();
            f.last_error = Some("changelog v2 is not attached".into());
            return f;
        };
        let fs = n.follow_status();
        let st = n.store.state().ok();
        f.state = match fs.state.as_str() {
            s if s.starts_with("following") => "following",
            "snapshotting" => "bootstrapping",
            "halted" => "halted",
            s if s.starts_with("blocked") => "refused",
            "retrying" => "error",
            "stopped" => "stopped",
            _ => "connecting",
        }
        .into();
        f.connected = fs.up_to_date || f.state == "following";
        f.last_applied_offset = st.as_ref().map_or(0, |s| s.last_txn as i64);
        f.primary_head = Some(fs.upstream_last as i64);
        f.lag_changes = Some((fs.upstream_last as i64 - f.last_applied_offset).max(0));
        f.last_error = fs.last_error.clone();
        f.rebootstraps = fs.snapshots;
        f.last_reconcile_result = fs.last_verify.as_ref().map(|v| {
            format!(
                "verify at txn {}: {}",
                v["at"],
                if v["ok"] == true { "ok" } else { "DIFFERENCES" }
            )
        });
        f.halted = st.and_then(|s| s.halted).map(|h| HaltInfo {
            reason: h["kind"].as_str().unwrap_or("diverged").to_string(),
            detail: h["detail"].as_str().unwrap_or_default().to_string(),
            at: h["at"].as_str().unwrap_or_default().to_string(),
            offset: f.last_applied_offset,
            report_file: None,
        });
        f
    }

    /// The changelog v2 node (the router serves its protocol).
    pub fn cdc_node(&self) -> Option<Arc<sqlite_cdc::node::Node>> {
        self.cdc.clone()
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
            local_root: (role == Role::Standby).then(|| self.local_root()),
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
            standby_writable: crate::api::standby_writable(),
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
            out.push_str(&format!("# HELP rustdns_replication_rebootstraps_total Snapshots loaded from the primary\n# TYPE rustdns_replication_rebootstraps_total counter\nrustdns_replication_rebootstraps_total {}\n", f.rebootstraps));
        }
        out
    }

    // ---- fencing (primary with [peer]) --------------------------------------

    async fn check_peer(&self, p: &PeerConfig) {
        let base = p.url.trim().trim_end_matches('/').to_string();
        let r = self.peer_identity(&base).await;
        let mine = self.history();
        let result = match r {
            Err(e) => format!("peer not reachable: {e}"),
            Ok(id) => {
                // The peer took over this server's replication: it leads
                // the same changelog v2 history (a promoted standby keeps
                // it, in a new epoch) and was promoted after this server
                // last was. (v1: its history's parent is this history.)
                let mine_v2 = self.cdc_identity();
                let same_v2 = matches!(
                    (&id.changelog_v2, &mine_v2),
                    (Some(p), Some(m)) if p.history.is_some() && p.history == m.history && p.role == "leader" && m.role == "leader"
                );
                let peer_newer = id.history.promoted_at.is_some()
                    && mine.promoted_at.as_deref() < id.history.promoted_at.as_deref();
                if id.writable
                    && (id.history.parent_history_id.as_deref() == Some(mine.history_id.as_str())
                        || (same_v2 && peer_newer))
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

    /// The peer's public identity (`GET /replication/identity`).
    async fn peer_identity(&self, base: &str) -> std::result::Result<Identity, String> {
        let url = format!("{base}/rust-dns/api/replication/identity");
        let resp = self
            .peer_http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("cannot reach {base}: {}", error_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("{url}: HTTP {status}"));
        }
        resp.json()
            .await
            .map_err(|e| format!("bad answer from {url}: {e}"))
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
        let reachable = self
            .cdc
            .as_ref()
            .is_some_and(|n| n.follow_status().up_to_date);
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
        if let Some(n) = &self.cdc {
            n.stop_follow().await;
        }
        // 3. The database: new history, forked at the current offset.
        let h = self
            .mutator
            .replica_promote(actor, url.clone(), how)
            .await
            .map_err(|e| (500, format!("recording the promotion failed: {e}; the config no longer has [follow], so a restart completes the promotion")))?;
        // 3b. Changelog v2: this server leads now, in a new epoch (a random
        // nonce), so its log differs from anything the old primary writes.
        if let Some(n) = &self.cdc {
            let store = n.store.clone();
            let e = tokio::task::spawn_blocking(move || store.promote(true))
                .await
                .map_err(|e| (500, e.to_string()))?;
            if let Err(e) = e {
                tracing::error!(error = %e, "changelog v2: promotion failed");
            }
        }
        // 4. Writable now; standbys will report to this server.
        self.set_role(Role::Promoted);
        self.gate.open();
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

    /// Operator rebootstrap (changelog v2): replace this standby's data with
    /// a fresh snapshot of the primary, atomically (it keeps serving its
    /// data until the snapshot replaces everything in one transaction),
    /// clearing a halt. With new `[follow]` parameters it also repoints:
    /// the config file is rewritten first (nothing changes if that fails).
    /// A fenced old primary becomes a standby this way. The snapshot is
    /// loaded by the follow loop: progress and outcome are in the status
    /// (the request returns once it started). Audited.
    pub async fn rebootstrap(
        self: &Arc<Self>,
        actor: Actor,
        primary: Option<String>,
        token: Option<String>,
        instance_id: Option<String>,
    ) -> std::result::Result<String, (u16, String)> {
        let _g = self.promote_lock.lock().await;
        let role = self.role();
        if !matches!(role, Role::Standby | Role::Fenced) {
            return Err((409, format!("only a standby (or a fenced old primary) can rebootstrap; this server is {role:?}").to_lowercase()));
        }
        let Some(node) = self.cdc.clone() else {
            return Err((409, "changelog v2 is not attached".into()));
        };
        let cur = self.follow();
        let pick = |new: Option<String>, old: Option<String>| {
            new.map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .or(old)
        };
        let primary = pick(primary, cur.as_ref().map(|f| f.primary.clone())).ok_or((
            400,
            "no primary: pass \"primary\" (this server has no [follow])".to_string(),
        ))?;
        let token = pick(token, cur.as_ref().map(|f| f.token.clone()))
            .ok_or((400, "no token: pass \"token\"".to_string()))?;
        let instance_id = pick(instance_id, cur.as_ref().map(|f| f.instance_id.clone()))
            .ok_or((400, "no instance_id: pass \"instance_id\"".to_string()))?;
        let primary = primary.trim_end_matches('/').to_string();
        let changed = cur.as_ref().is_none_or(|f| {
            f.primary.trim_end_matches('/') != primary
                || f.token.trim() != token
                || f.instance_id.trim() != instance_id
        });
        if changed {
            crate::config::set_follow_section(&self.config_path, &primary, &token, &instance_id)
                .map_err(|e| {
                    (
                        500,
                        format!(
                            "cannot write [follow] to {}: {e:#}; nothing was changed",
                            self.config_path.display()
                        ),
                    )
                })?;
            let mut f = cur.clone().unwrap_or_default();
            f.primary = primary.clone();
            f.token = token.clone();
            f.instance_id = instance_id.clone();
            let mut c = (*self.reloader.current.load_full()).clone();
            c.follow = Some(f.clone());
            self.reloader.current.store(Arc::new(c));
            *self.follow.write().unwrap_or_else(|p| p.into_inner()) = Some(f.clone());
            node.set_client(
                sqlite_cdc::client::ClientTemplate {
                    http: self.http.clone(),
                    headers: cdc_headers(Some(&f)),
                },
                Some(instance_id.clone()),
            );
        }
        if role == Role::Fenced {
            self.set_role(Role::Standby);
            self.gate.close(format!(
                "this server is a read-only standby of {primary}; make changes on the primary"
            ));
        }
        let v2 = format!("{primary}/rust-dns/changelog-api/v2");
        tracing::warn!(actor = %actor.name, primary = %primary, repointed = changed, "REBOOTSTRAP: loading a fresh snapshot of the primary (the current data stays until it is replaced)");
        node.rebootstrap(Some(&v2))
            .await
            .map_err(|e| (502, format!("rebootstrap: {e}")))?;
        if let Err(e) = self
            .mutator
            .replica_audit(
                actor,
                "replication.rebootstrap",
                primary.clone(),
                serde_json::json!({"primary": primary, "instance_id": instance_id, "repointed": changed}),
            )
            .await
        {
            tracing::error!(error = %e, "auditing the rebootstrap failed");
        }
        *self.warning.write().unwrap() = None;
        Ok(format!("rebootstrap started from {primary}: the snapshot loads in the background; follow its progress in the replication status"))
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
                "the web console address {} is in use: is rust-dns running? Promote a running server from the console (Admin -> Replication) or with POST /rust-dns/api/replication/promote, or stop it first",
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
    let (data_list, rows, head, local_hist, lineage_markers, v2_history) = {
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
            // Changelog v2 has a history (a database of an older version
            // has no `_cdc_state` yet).
            ro.query_row(
                "SELECT COUNT(*) FROM _cdc_state WHERE k = 'history'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false),
        )
    };
    if data_list.is_empty() && rows == 0 && !lineage_markers && !v2_history {
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
    if v2_history {
        println!("  - the changelog v2 log and history (the standby starts a fresh copy)");
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
        let base = follow.primary.trim().trim_end_matches('/').to_string();
        let remote = https_client(Some(&follow.ca_file), "[follow].ca_file")?
            .get(format!("{base}/rust-dns/api/replication/identity"))
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
    // Changelog v2: drop the log and its history (after the deletes above,
    // which it may have captured), so the server starts as a fresh follower
    // and loads a snapshot of the primary.
    if let Some(cdc) = storage.cdc() {
        cdc.forget_history()
            .context("dropping the changelog v2 history")?;
    }
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

/// Headers of the v2 follower's requests: the `[follow]` token (the crate
/// names the follower itself, `NodeConfig::name`).
fn cdc_headers(f: Option<&FollowConfig>) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Some(Ok(v)) = f.map(|f| format!("Bearer {}", f.token.trim()).parse()) {
        h.insert(reqwest::header::AUTHORIZATION, v);
    }
    h
}

/// After the v2 follower changed data: rebuild the catalog, wake the
/// expiry sweeper, refresh the console's live views, and reload what is
/// kept in memory from the database (TSIG keys, forwarding, resolver and
/// blocklist settings).
fn applied_hook(
    storage: Arc<Storage>,
    mutator: Arc<Mutator>,
    dns: Arc<DnsServer>,
    reloader: Arc<crate::reload::Reloader>,
) -> sqlite_cdc::node::AppliedHook {
    Arc::new(move |applied| {
        let (storage, mutator, dns, reloader) = (
            storage.clone(),
            mutator.clone(),
            dns.clone(),
            reloader.clone(),
        );
        let everything = matches!(applied, sqlite_cdc::node::Applied::Everything);
        let events = match &applied {
            sqlite_cdc::node::Applied::Txns(txns) => replicated_events(&storage, txns),
            sqlite_cdc::node::Applied::Everything => Vec::new(),
        };
        tokio::spawn(async move {
            if everything {
                // The users were replaced wholesale: a session could now
                // name another account. Everyone signs in again.
                match storage.delete_all_sessions() {
                    Ok(n) => tracing::warn!(
                        sessions = n,
                        "replicated data replaced (snapshot): everyone signs in again"
                    ),
                    Err(e) => {
                        tracing::error!(error = %e, "deleting sessions after a snapshot failed")
                    }
                }
            }
            mutator.replica_applied().await;
            for ev in events {
                mutator.publish_replicated(ev);
            }
            if let Err(e) = dns.reload_tsig_keys(&storage) {
                tracing::error!(error = %e, "reloading TSIG keys after replication failed");
            }
            dns.load_console_settings(&storage, &reloader.current.load_full());
        });
    })
}

/// Console events for applied v2 transactions: one per (transaction, zone)
/// of the DNS tables, with entity, action and who did it. No row data.
fn replicated_events(
    storage: &Storage,
    txns: &[sqlite_cdc::wire::Txn],
) -> Vec<crate::model::ChangeEvent> {
    let mut out = Vec::new();
    for t in txns {
        let meta: serde_json::Value = serde_json::from_str(t.meta.get()).unwrap_or_default();
        let s = |k: &str| meta[k].as_str().unwrap_or_default().to_string();
        // Zone names this transaction knows from its own zone rows (a
        // deleted zone is gone from the database by now).
        let mut names: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
        for r in t.rows.iter().filter(|r| r.tbl == "zones") {
            for img in [&r.before, &r.after].into_iter().flatten() {
                let v: serde_json::Value = serde_json::from_str(img.get()).unwrap_or_default();
                if let (Some(id), Some(n)) = (v["id"].as_i64(), v["name"].as_str()) {
                    names.insert(id, n.to_string());
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        for r in &t.rows {
            let entity = match r.tbl.as_str() {
                "zones" => "zone",
                "records" => "record",
                "zone_members" => "member",
                "dnssec_keys" => "dnssec",
                _ => continue,
            };
            let img = r.after.as_ref().or(r.before.as_ref());
            let v: serde_json::Value = img
                .and_then(|i| serde_json::from_str(i.get()).ok())
                .unwrap_or_default();
            let zid = if r.tbl == "zones" {
                v["id"].as_i64()
            } else {
                v["zone_id"].as_i64()
            };
            let Some(zid) = zid else { continue };
            let zone = match names.get(&zid) {
                Some(n) => n.clone(),
                None => match storage.read_tx(|c| crate::storage::get_zone_by_id(c, zid)) {
                    Ok(Some(z)) => z.name,
                    _ => continue,
                },
            };
            let action = match r.op.as_str() {
                "I" => "create",
                "D" => "delete",
                _ => "update",
            };
            if !seen.insert((zone.clone(), entity, action)) {
                continue;
            }
            out.push(crate::model::ChangeEvent {
                offset: t.txn_id as i64,
                ts: now_rfc3339(),
                actor: s("actor"),
                actor_ip: s("ip"),
                action: action.into(),
                entity: entity.into(),
                zone,
                entity_id: v["id"].as_i64(),
                payload: serde_json::json!({ "kind": "replicated", "txn_id": t.txn_id }),
                txn: s("v1_txn"),
                command: s("command"),
            });
        }
    }
    out
}
