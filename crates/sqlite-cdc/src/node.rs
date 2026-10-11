//! A node: a store, its HTTP server, and (on a follower) the follow loop.
//! Also the operator actions: promote, rejoin, reset, repoint, verify.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use futures::StreamExt;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::client::{Client, PollOpts};
use crate::server::{Metrics, blocking};
use crate::store::{CdcError, Kind, Progress, Role, State, Store, err};
use crate::wire::{StreamLine, Txn};

#[derive(Debug, Clone)]
pub enum FollowMode {
    Poll(PollOpts),
    Stream,
}

/// What changed the data on a follower, for the host's caches.
#[derive(Debug, Clone)]
pub enum Applied {
    /// These transactions were applied (committed).
    Txns(Vec<Txn>),
    /// Everything was replaced: a snapshot load, a reset or a rewind.
    Everything,
}

/// Called after data changed on a follower (in the follow loop's task).
pub type AppliedHook = Arc<dyn Fn(Applied) + Send + Sync>;

#[derive(Clone)]
pub struct NodeConfig {
    /// Bearer token for [`Node::serve`] and for outgoing requests (when
    /// `client` is not set).
    pub token: String,
    /// Outgoing requests to upstreams and peers (TLS, authentication).
    pub client: Option<crate::client::ClientTemplate>,
    /// How this node names itself to its upstream (default: its node id).
    pub name: Option<String>,
    pub mode: FollowMode,
    /// On a gap in the same history (rows pruned), load a new snapshot
    /// instead of halting.
    pub auto_snapshot_on_gap: bool,
    pub verify_every: Option<Duration>,
    pub verify_buckets: u64,
    /// The host's caches follow the data (rebuild what changed).
    pub on_applied: Option<AppliedHook>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("client", &self.client)
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("auto_snapshot_on_gap", &self.auto_snapshot_on_gap)
            .field("verify_every", &self.verify_every)
            .finish_non_exhaustive()
    }
}

impl NodeConfig {
    pub fn new(token: &str) -> NodeConfig {
        NodeConfig {
            token: token.into(),
            client: None,
            name: None,
            mode: FollowMode::Poll(PollOpts::default()),
            auto_snapshot_on_gap: true,
            verify_every: Some(Duration::from_secs(3600)),
            verify_buckets: 256,
            on_applied: None,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FollowStatus {
    pub state: String,
    pub upstream: Option<String>,
    pub upstream_last: u64,
    pub last_error: Option<String>,
    pub snapshots: u64,
    pub batches: u64,
    pub applied_txns: u64,
    pub last_verify: Option<Value>,
    /// This follower's own view: caught up with what the upstream last
    /// reported, and heard from it within the last 30 s.
    pub up_to_date: bool,
    /// The upstream's view of this follower (it tracks every client).
    pub server_view: Option<crate::wire::ClientView>,
}

struct FollowTask {
    stop: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

pub struct Node {
    pub store: Arc<Store>,
    pub token: String,
    pub cfg: NodeConfig,
    pub metrics: Metrics,
    pub progress: Arc<Progress>,
    /// Followers of this node, as seen by its server.
    pub clients: crate::clients::Clients,
    follow: tokio::sync::Mutex<Option<FollowTask>>,
    last_contact: std::sync::Mutex<Option<Instant>>,
    /// Replaces `cfg.client` / `cfg.name` (a repoint with new credentials).
    client_override: std::sync::Mutex<Option<(crate::client::ClientTemplate, Option<String>)>>,
    fstat: std::sync::Mutex<FollowStatus>,
}

async fn sleep_or_stop(d: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => *stop.borrow(),
        _ = stop.changed() => true,
    }
}

impl Node {
    pub fn new(store: Arc<Store>, cfg: NodeConfig) -> Arc<Node> {
        Arc::new(Node {
            store,
            token: cfg.token.clone(),
            cfg,
            metrics: Metrics::default(),
            progress: Arc::new(Progress::default()),
            clients: crate::clients::Clients::default(),
            follow: tokio::sync::Mutex::new(None),
            last_contact: std::sync::Mutex::new(None),
            client_override: std::sync::Mutex::new(None),
            fstat: std::sync::Mutex::new(FollowStatus::default()),
        })
    }

    /// Serve the protocol on `addr` (port 0 for any). Aborting the
    /// returned task stops the server (tests use it to "kill" a node).
    pub async fn serve(
        self: &Arc<Node>,
        addr: &str,
    ) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        self.serve_with(addr, axum::Router::new()).await
    }

    /// [`Node::serve`] with extra routes of the caller merged in.
    pub async fn serve_with(
        self: &Arc<Node>,
        addr: &str,
        extra: axum::Router,
    ) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let l = tokio::net::TcpListener::bind(addr).await?;
        let a = l.local_addr()?;
        let app = crate::server::router(
            self.clone(),
            crate::server::RouterOptions {
                auth: Some(Arc::new(crate::server::BearerToken(self.token.clone()))),
                admin: true,
            },
        )
        .merge(extra)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let h = tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        Ok((a, h))
    }

    /// A client for `base`, identifying this node.
    pub fn client(&self, base: &str) -> Client {
        let over = self
            .client_override
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let (t, name) = match over {
            Some((t, n)) => (t, n),
            None => (
                self.cfg
                    .client
                    .clone()
                    .unwrap_or_else(|| crate::client::ClientTemplate::bearer(&self.token)),
                self.cfg.name.clone(),
            ),
        };
        let id = self.store.state().map(|s| s.node_id).unwrap_or_default();
        let name = name.unwrap_or_else(|| id.clone());
        t.client(base).identify(&id, &name)
    }

    /// New credentials or name for requests to upstreams and peers (a
    /// repoint); takes effect at the next (re)start of following.
    pub fn set_client(&self, template: crate::client::ClientTemplate, name: Option<String>) {
        *self
            .client_override
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some((template, name));
    }

    /// The upstream answered: remember when, and drop an error from an
    /// earlier attempt (the status must not show a fixed problem).
    fn contact(&self) {
        *self.last_contact.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        self.fs().last_error = None;
    }

    fn fs(&self) -> std::sync::MutexGuard<'_, FollowStatus> {
        self.fstat.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn follow_status(&self) -> FollowStatus {
        let mut f = self.fs().clone();
        let applied = self.store.state().map(|s| s.last_txn).unwrap_or(0);
        let recent = self
            .last_contact
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|t| t.elapsed() < Duration::from_secs(30));
        f.up_to_date = recent
            && f.upstream.is_some()
            && applied >= f.upstream_last
            && f.state.starts_with("following");
        f
    }

    pub fn status(&self) -> Result<crate::wire::Status, CdcError> {
        let st = self.store.state()?;
        let mut f = serde_json::to_value(self.follow_status())?;
        f["snapshot_progress"] = json!({
            "loaded": self.progress.loaded_rows.load(Ordering::Relaxed),
            "total": self.progress.total_rows.load(Ordering::Relaxed),
        });
        f["lag_txns"] = json!(self.fs().upstream_last.saturating_sub(st.last_txn));
        Ok(crate::wire::Status {
            node_id: st.node_id,
            role: st.role.as_str().into(),
            history: st.history,
            last_txn: st.last_txn,
            last_hash: st.last_hash,
            oldest_full: st.oldest_full,
            halted: st.halted,
            upstream: st.upstream,
            follow: Some(f),
            schema: self.store.schema_fp().to_string(),
            health: self.store.health()?,
        })
    }

    // ---- follow loop --------------------------------------------------

    /// Follow `upstream` (also: repoint to another upstream). The position
    /// is checked against the new upstream's chain on the first request.
    pub async fn start_follow(self: &Arc<Node>, upstream: &str) -> Result<(), CdcError> {
        self.stop_follow().await;
        let st = self.store.state()?;
        if matches!(st.role, Role::Leader | Role::Fenced) {
            return Err(err(Kind::Refused, "a leader does not follow; use rejoin"));
        }
        self.store.set_upstream(Some(upstream))?;
        let (tx, rx) = watch::channel(false);
        {
            let mut f = self.fs();
            f.upstream = Some(upstream.into());
            f.state = "starting".into();
            f.last_error = None;
        }
        let node = self.clone();
        let up = upstream.to_string();
        let handle = tokio::spawn(async move { node.follow_loop(up, rx).await });
        *self.follow.lock().await = Some(FollowTask { stop: tx, handle });
        Ok(())
    }

    pub async fn stop_follow(&self) {
        if let Some(t) = self.follow.lock().await.take() {
            let _ = t.stop.send(true);
            let _ = t.handle.await;
            self.fs().state = "stopped".into();
        }
    }

    fn set_state(&self, s: &str) {
        self.fs().state = s.into();
    }

    async fn follow_loop(self: Arc<Node>, upstream: String, mut stop: watch::Receiver<bool>) {
        let client = self.client(&upstream);
        let mut backoff = Duration::from_millis(100);
        let mut last_verify = Instant::now();
        loop {
            if *stop.borrow() {
                return;
            }
            let st = match self.store.state() {
                Ok(s) => s,
                Err(e) => {
                    self.fs().last_error = Some(e.to_string());
                    if sleep_or_stop(backoff, &mut stop).await {
                        return;
                    }
                    continue;
                }
            };
            if st.halted.is_some() {
                self.set_state("halted");
                return;
            }
            let res = match st.role {
                Role::Fresh => self.snapshot_then_verify(&client, None).await,
                Role::Follower => self.step(&client, &st, &mut stop).await,
                r => {
                    self.set_state(&format!("not following ({})", r.as_str()));
                    return;
                }
            };
            let res = match res {
                Err(e) if e.kind == Kind::Gap => {
                    if self.cfg.auto_snapshot_on_gap {
                        tracing::warn!("gap in the same history ({}); taking a snapshot", e.detail);
                        self.snapshot_then_verify(&client, st.history.clone()).await
                    } else {
                        Err(err(
                            Kind::Diverged,
                            format!("gap and auto snapshot is off: {}", e.detail),
                        ))
                    }
                }
                other => other,
            };
            match res {
                Ok(()) => {
                    backoff = Duration::from_millis(100);
                    self.fs().last_error = None;
                    if let Some(every) = self.cfg.verify_every
                        && last_verify.elapsed() >= every
                    {
                        last_verify = Instant::now();
                        if let Err(e) = self.verify_with(&client, self.cfg.verify_buckets).await {
                            self.fs().last_error = Some(format!("verify: {e}"));
                        }
                    }
                }
                Err(e) if e.kind == Kind::SchemaMismatch => {
                    let diff = match client.schema().await {
                        Ok(theirs) => crate::store::schema_diff(self.store.tables(), &theirs),
                        Err(x) => format!("(could not fetch the upstream schema: {x})"),
                    };
                    let msg = format!(
                        "blocked: upstream schema differs, waiting for both to run the same version: {diff}"
                    );
                    tracing::error!("{msg}");
                    self.fs().last_error = Some(msg);
                    self.set_state("blocked (schema mismatch)");
                    if sleep_or_stop(Duration::from_secs(2), &mut stop).await {
                        return;
                    }
                }
                Err(e) if e.kind.is_divergence() => {
                    let _ = self.store.halt(e.kind, &e.detail);
                    self.fs().last_error = Some(e.to_string());
                    self.set_state("halted");
                    return;
                }
                Err(e) => {
                    self.fs().last_error = Some(e.to_string());
                    self.set_state("retrying");
                    if sleep_or_stop(backoff, &mut stop).await {
                        return;
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    fn notify(&self, a: Applied) {
        if let Some(h) = &self.cfg.on_applied {
            h(a);
        }
    }

    /// Tell the upstream what this stream follower has applied: when it
    /// catches up, and at most twice a second while catching up. Keeps the
    /// upstream's answer (its view of this follower).
    async fn report_progress(&self, client: &Client, caught_up: bool, last: &mut Option<Instant>) {
        if !caught_up && last.is_some_and(|t| t.elapsed() < Duration::from_millis(500)) {
            return;
        }
        *last = Some(Instant::now());
        let Ok(st) = self.store.state() else { return };
        if let Ok(v) = client.progress(st.last_txn).await {
            self.fs().server_view = Some(v);
        }
    }

    async fn apply(&self, batch: Vec<Txn>) -> Result<(), CdcError> {
        let n = batch.len() as u64;
        let store = self.store.clone();
        let batch = blocking(move || store.apply(&batch).map(|_| batch)).await?;
        {
            let mut f = self.fs();
            f.batches += 1;
            f.applied_txns += n;
        }
        self.notify(Applied::Txns(batch));
        Ok(())
    }

    async fn step(
        &self,
        client: &Client,
        st: &State,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<(), CdcError> {
        let pos = st.position().expect("a follower has a history");
        match &self.cfg.mode {
            FollowMode::Poll(o) => {
                self.set_state("following (poll)");
                let r = tokio::select! {
                    r = client.changes(&pos, self.store.schema_fp(), o) => r?,
                    _ = stop.changed() => return Ok(()),
                };
                self.contact();
                {
                    let mut f = self.fs();
                    f.upstream_last = r.last_txn;
                    f.server_view = r.client.clone();
                }
                if !r.txns.is_empty() {
                    self.apply(r.txns).await?;
                }
                Ok(())
            }
            FollowMode::Stream => {
                self.set_state("following (stream)");
                let s = client.stream(&pos, self.store.schema_fp()).await?;
                // The upstream accepted the position: it is reachable now.
                self.contact();
                let mut s = std::pin::pin!(s);
                let mut batch: Vec<Txn> = Vec::new();
                let mut up_last = 0u64;
                let mut last_report: Option<Instant> = None;
                self.report_progress(client, true, &mut last_report).await;
                loop {
                    // Apply once caught up with what the server had (live:
                    // at once), or when the batch is big (catching up).
                    let caught_up = batch.last().is_some_and(|t| t.txn_id >= up_last);
                    if caught_up || batch.len() >= 2000 {
                        self.apply(std::mem::take(&mut batch)).await?;
                        self.report_progress(client, caught_up, &mut last_report)
                            .await;
                        continue;
                    }
                    let next = if batch.is_empty() {
                        tokio::select! {
                            i = s.next() => i,
                            _ = stop.changed() => return Ok(()),
                        }
                    } else {
                        match tokio::time::timeout(Duration::from_millis(200), s.next()).await {
                            Ok(i) => i,
                            Err(_) => {
                                self.apply(std::mem::take(&mut batch)).await?;
                                continue;
                            }
                        }
                    };
                    let end = match next {
                        None => Ok(()), // reconnect
                        Some(Err(e)) => Err(e),
                        Some(Ok(StreamLine::Error(b))) => Err(err(Kind::parse(&b.error), b.detail)),
                        Some(Ok(StreamLine::Heartbeat { last_txn })) => {
                            self.contact();
                            up_last = up_last.max(last_txn);
                            let mut f = self.fs();
                            f.upstream_last = f.upstream_last.max(last_txn);
                            continue;
                        }
                        Some(Ok(StreamLine::Txn(t))) => {
                            batch.push(t);
                            continue;
                        }
                    };
                    if !batch.is_empty() {
                        self.apply(batch).await?;
                    }
                    return end;
                }
            }
        }
    }

    /// Load a snapshot, then verify every table against the source at the
    /// snapshot's transaction: a bad load halts at once, before anything
    /// is built on it.
    async fn snapshot_then_verify(
        &self,
        client: &Client,
        same_history: Option<String>,
    ) -> Result<(), CdcError> {
        self.snapshot_from(client, same_history).await?;
        let r = self.verify_with(client, self.cfg.verify_buckets).await?;
        if r["ok"] != true {
            return Err(err(
                Kind::Diverged,
                format!("verify after snapshot failed: {r}"),
            ));
        }
        Ok(())
    }

    /// Load a snapshot from `client`: on a fresh node, or (`same_history`)
    /// after a gap.
    async fn snapshot_from(
        &self,
        client: &Client,
        same_history: Option<String>,
    ) -> Result<(), CdcError> {
        self.set_state("snapshotting");
        let mut lines = std::pin::pin!(client.snapshot().await?);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<anyhow::Result<Vec<u8>>>(1024);
        let store = self.store.clone();
        let progress = self.progress.clone();
        let loader = tokio::task::spawn_blocking(move || {
            let it = std::iter::from_fn(|| rx.blocking_recv());
            store.load_snapshot(it, same_history.as_deref(), &progress)
        });
        while let Some(l) = lines.next().await {
            if tx.send(l.map_err(anyhow::Error::new)).await.is_err() {
                break;
            }
        }
        drop(tx);
        let pos = loader
            .await
            .map_err(|e| err(Kind::Internal, e.to_string()))??;
        self.contact();
        self.fs().snapshots += 1;
        self.notify(Applied::Everything);
        tracing::info!(txn = pos.txn_id, "snapshot loaded");
        Ok(())
    }

    // ---- operator actions ---------------------------------------------

    /// Promote this follower. Refused (unless `force`) while a leader of
    /// this history is reachable among `peers` and the upstream, or while a
    /// reachable peer is further ahead (promote that one instead).
    pub async fn promote(
        self: &Arc<Node>,
        peers: &[String],
        force: bool,
    ) -> Result<Value, CdcError> {
        let st = self.store.state()?;
        if st.role == Role::Leader {
            return Ok(json!({"already_leader": true, "txn_id": st.last_txn}));
        }
        let mut all: Vec<String> = peers.to_vec();
        if let Some(u) = &st.upstream
            && !all.contains(u)
        {
            all.push(u.clone());
        }
        let mut notes = Vec::new();
        for p in &all {
            match self.client(p).status().await {
                Ok(s) if s.history == st.history => {
                    if s.role == "leader" && s.halted.is_none() && !force {
                        return Err(err(
                            Kind::Refused,
                            format!("a leader of this history is reachable at {p}"),
                        ));
                    }
                    if s.last_txn > st.last_txn && !force {
                        return Err(err(
                            Kind::Refused,
                            format!(
                                "{p} is at txn {}, this node at {}: promote the most advanced node",
                                s.last_txn, st.last_txn
                            ),
                        ));
                    }
                    notes.push(json!({"peer": p, "role": s.role, "last_txn": s.last_txn}));
                }
                Ok(s) => {
                    notes.push(json!({"peer": p, "note": "other history", "history": s.history}))
                }
                Err(e) => {
                    notes.push(json!({"peer": p, "note": "unreachable", "error": e.to_string()}))
                }
            }
        }
        self.stop_follow().await;
        let store = self.store.clone();
        let id = blocking(move || store.promote(force)).await?;
        self.set_state("leader");
        Ok(json!({"promoted": true, "epoch_txn": id, "peers": notes}))
    }

    /// Make this node (typically a former leader) follow `upstream`: find
    /// the last transaction both chains share, undo everything after it
    /// (only with `accept_loss`; the undone transactions are saved to a
    /// file), and follow from there.
    pub async fn rejoin(
        self: &Arc<Node>,
        upstream: &str,
        accept_loss: bool,
    ) -> Result<Value, CdcError> {
        let st = self.store.state()?;
        let client = self.client(upstream);
        let up = client.status().await?;
        if st.history.is_none() || up.history != st.history {
            return Err(err(
                Kind::History,
                "upstream is of another history; reset this node instead",
            ));
        }
        let fork = self
            .find_fork(&client, st.last_txn.min(up.last_txn))
            .await?;
        let lost = st.last_txn - fork;
        if lost > 0 && !accept_loss {
            return Err(err(
                Kind::Refused,
                format!(
                    "txns {}..={} of this node are not on the upstream's chain; accept_loss to undo them",
                    fork + 1,
                    st.last_txn
                ),
            ));
        }
        self.stop_follow().await;
        let store = self.store.clone();
        let discarded = blocking(move || store.rewind_to(fork)).await.map_err(|e| {
            err(
                Kind::Refused,
                format!(
                    "cannot undo txns after {fork} in place ({e}); nothing was changed. {}",
                    crate::store::REBOOTSTRAP_HINT
                ),
            )
        })?;
        self.notify(Applied::Everything);
        let file = if discarded.is_empty() {
            None
        } else {
            let path = format!(
                "{}.discarded-{}-{}.json",
                self.store.path().display(),
                fork + 1,
                st.last_txn
            );
            std::fs::write(&path, serde_json::to_vec_pretty(&discarded)?)
                .map_err(|e| err(Kind::Internal, e.to_string()))?;
            Some(path)
        };
        self.start_follow(upstream).await?;
        Ok(json!({"fork": fork, "discarded_txns": discarded.len(), "file": file}))
    }

    async fn find_fork(&self, client: &Client, start: u64) -> Result<u64, CdcError> {
        let mut hi = start;
        while hi > 0 {
            let lo = hi.saturating_sub(999).max(1);
            let remote: std::collections::HashMap<u64, String> =
                client.hashes(lo, hi).await?.into_iter().collect();
            let store = self.store.clone();
            let local = blocking(move || store.hashes(lo, hi)).await?;
            if let Some((t, _)) = local.iter().rev().find(|(t, h)| remote.get(t) == Some(h)) {
                return Ok(*t);
            }
            hi = lo - 1;
        }
        Ok(0) // the genesis: same history id
    }

    /// Replace this node's replicated data with a fresh snapshot from
    /// `upstream` (default: its current one), atomically: the data stays
    /// until the snapshot replaces it in one transaction. The answer to any
    /// divergence: an explicit operator action, never automatic. Refused on
    /// a leader.
    pub async fn rebootstrap(self: &Arc<Node>, upstream: Option<&str>) -> Result<(), CdcError> {
        let st = self.store.state()?;
        if st.role == Role::Leader {
            return Err(err(Kind::Refused, "refusing to rebootstrap a leader"));
        }
        let Some(up) = upstream.map(str::to_string).or(st.upstream) else {
            return Err(err(Kind::Refused, "no upstream: pass one"));
        };
        // Check the source before discarding anything.
        let s = self.client(&up).status().await?;
        if s.history.is_none() || s.halted.is_some() {
            return Err(err(
                Kind::Refused,
                format!(
                    "{up} cannot serve a snapshot (history {:?}, halted {:?})",
                    s.history, s.halted
                ),
            ));
        }
        self.stop_follow().await;
        // Atomic: only the replication state is dropped here (the node
        // keeps serving its data); the follow loop then loads a snapshot,
        // which replaces every table in one transaction.
        let store = self.store.clone();
        blocking(move || store.forget_history()).await?;
        self.start_follow(&up).await
    }

    /// Compare every table with the upstream as of this node's current
    /// transaction. A mismatch halts this node (divergence is never
    /// repaired silently); the report names the rows.
    pub async fn verify(self: &Arc<Node>, buckets: u64) -> Result<Value, CdcError> {
        let st = self.store.state()?;
        let Some(up) = st.upstream else {
            return Err(err(Kind::Refused, "no upstream to verify against"));
        };
        self.verify_with(&self.client(&up), buckets).await
    }

    async fn verify_with(&self, client: &Client, buckets: u64) -> Result<Value, CdcError> {
        let at = self.store.state()?.last_txn;
        let started = Instant::now();
        let mut tables = Vec::new();
        let mut bad = false;
        for t in self.store.tables().iter().map(|t| t.name.clone()) {
            let store = self.store.clone();
            let tn = t.clone();
            let local = blocking(move || store.bucket_hashes(&tn, at, buckets)).await?;
            let remote = client.bucket_hashes(&t, at, buckets).await?;
            let diff: Vec<usize> = (0..buckets as usize)
                .filter(|&i| local.buckets[i] != remote.buckets[i])
                .collect();
            let mut rows = Vec::new();
            for &b in diff.iter().take(16) {
                let store = self.store.clone();
                let tn = t.clone();
                let l = blocking(move || store.bucket_rows(&tn, at, buckets, b)).await?;
                let r = client.bucket_rows(&t, at, buckets, b).await?;
                let lm: std::collections::HashMap<_, _> =
                    l.into_iter().map(|x| (x.pk, x.hash)).collect();
                let rm: std::collections::HashMap<_, _> =
                    r.into_iter().map(|x| (x.pk, x.hash)).collect();
                for (pk, h) in &lm {
                    match rm.get(pk) {
                        None => rows.push(json!({"pk": pk, "problem": "only on this node"})),
                        Some(rh) if rh != h => rows.push(json!({"pk": pk, "problem": "different"})),
                        _ => {}
                    }
                }
                for pk in rm.keys().filter(|k| !lm.contains_key(*k)) {
                    rows.push(json!({"pk": pk, "problem": "missing on this node"}));
                }
            }
            bad |= !diff.is_empty();
            let n: u64 = local.buckets.iter().map(|b| b.0).sum();
            tables.push(json!({"table": t, "rows": n, "ok": diff.is_empty(), "bad_buckets": diff.len(), "diffs": rows}));
        }
        let report = json!({"at": at, "ok": !bad, "ms": started.elapsed().as_millis() as u64, "tables": tables});
        self.fs().last_verify = Some(report.clone());
        if bad {
            let _ = self.store.halt(
                Kind::Diverged,
                &format!("verify at txn {at} found differences"),
            );
        }
        Ok(report)
    }

    /// A leader starting up: fence itself if another leader of its history
    /// is reachable (it was replaced while it was down).
    pub async fn fence_check(&self, peers: &[String]) -> Result<bool, CdcError> {
        let st = self.store.state()?;
        if st.role != Role::Leader {
            return Ok(false);
        }
        for p in peers {
            if let Ok(s) = self.client(p).status().await
                && s.history == st.history
                && s.role == "leader"
            {
                tracing::error!(peer = %p, "another leader of this history is up; fencing this node");
                self.store.fence()?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
