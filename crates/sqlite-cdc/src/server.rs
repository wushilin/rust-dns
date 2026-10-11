//! The HTTP/JSON protocol. Every route needs `Authorization: Bearer <token>`.
//!
//! Replication (any node with a history serves it, so followers chain):
//! - `GET /status`
//! - `GET /snapshot`: NDJSON, one consistent read: header (position,
//!   schema, row counts for progress), rows, chain entries, digest footer.
//! - `GET /changes?history&after&hash&min_bytes&max_wait_ms&max_bytes`:
//!   long poll, Kafka style: returns once `min_bytes` are available or
//!   `max_wait_ms` passed.
//! - `GET /stream?history&after&hash`: NDJSON push of every transaction
//!   as it commits, with heartbeats.
//! - `GET /hashes?from&to`: chain entries, for finding a fork point.
//! - `GET /verify/{table}?at&buckets` and `.../rows?at&buckets&bucket`.
//!
//! The follower's position (`history`, `after`, `hash`) is checked on every
//! request: another history is 412, a position not on this chain or ahead
//! of it 409, pruned rows 410 (`gap`).
//!
//! Responses are gzip-compressed when the client accepts it; streams are
//! flushed per batch so compression does not delay them.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::clients::Caller;
use crate::node::Node;
use crate::store::{CdcError, Kind, err};
use crate::wire::{ChangesResponse, ErrorBody, Position, StreamLine};

#[derive(Default)]
pub struct Metrics {
    /// JSON bytes produced for changes and streams, before compression.
    pub changes_raw: AtomicU64,
    /// The same, as sent.
    pub changes_wire: AtomicU64,
    pub snapshot_raw: AtomicU64,
    pub snapshot_wire: AtomicU64,
    pub txns_sent: AtomicU64,
}

impl Metrics {
    pub fn json(&self) -> Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({
            "changes_raw": g(&self.changes_raw),
            "changes_wire": g(&self.changes_wire),
            "snapshot_raw": g(&self.snapshot_raw),
            "snapshot_wire": g(&self.snapshot_wire),
            "txns_sent": g(&self.txns_sent),
        })
    }
}

pub struct ApiError(pub CdcError);

impl From<CdcError> for ApiError {
    fn from(e: CdcError) -> Self {
        ApiError(e)
    }
}

pub fn status_of(k: Kind) -> StatusCode {
    match k {
        Kind::Gap => StatusCode::GONE,
        Kind::History => StatusCode::PRECONDITION_FAILED,
        Kind::Diverged
        | Kind::Ahead
        | Kind::Schema
        | Kind::NeedsReset
        | Kind::Refused
        | Kind::SchemaMismatch => StatusCode::CONFLICT,
        Kind::NotReady | Kind::Halted | Kind::Unreachable | Kind::Broken => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        Kind::NotLeader => StatusCode::MISDIRECTED_REQUEST,
        Kind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.0.kind.as_str().into(),
            detail: self.0.detail,
        };
        (status_of(self.0.kind), Json(body)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, CdcError> + Send + 'static,
) -> Result<T, CdcError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| err(Kind::Internal, e.to_string()))?
}

/// gzip with a sync flush after every chunk, so each chunk is decodable as
/// soon as it arrives.
pub struct Gz(Option<GzEncoder<Vec<u8>>>);

impl Gz {
    pub fn new(on: bool) -> Gz {
        Gz(on.then(|| GzEncoder::new(Vec::new(), Compression::fast())))
    }
    pub fn chunk(&mut self, data: &[u8]) -> Bytes {
        match &mut self.0 {
            None => Bytes::copy_from_slice(data),
            Some(e) => {
                e.write_all(data).expect("in-memory write");
                e.flush().expect("in-memory flush");
                Bytes::from(std::mem::take(e.get_mut()))
            }
        }
    }
    pub fn finish(self) -> Bytes {
        match self.0 {
            None => Bytes::new(),
            Some(e) => Bytes::from(e.finish().expect("in-memory finish")),
        }
    }
}

fn accepts_gzip(h: &HeaderMap) -> bool {
    h.get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"))
}

fn encoded(gzip: bool, content_type: &str, body: Body) -> Response {
    let mut r = Response::new(body);
    r.headers_mut()
        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    if gzip {
        r.headers_mut()
            .insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
    }
    r
}

/// A body fed by a channel; dropping the response stops the producer.
fn channel_body(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Body {
    let s = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|b| (Ok::<_, std::io::Error>(b), rx))
    });
    Body::from_stream(s)
}

/// Decides who may use the API. `admin` is true for routes that change
/// state (promote, rebootstrap, ...). Returns the caller's name.
pub trait Authorizer: Send + Sync + 'static {
    fn authorize<'a>(
        &'a self,
        req: &'a axum::http::request::Parts,
        admin: bool,
    ) -> futures::future::BoxFuture<'a, Result<String, String>>;
}

/// A single shared bearer token.
pub struct BearerToken(pub String);

impl Authorizer for BearerToken {
    fn authorize<'a>(
        &'a self,
        req: &'a axum::http::request::Parts,
        _admin: bool,
    ) -> futures::future::BoxFuture<'a, Result<String, String>> {
        use subtle::ConstantTimeEq;
        let ok = req
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| bool::from(t.as_bytes().ct_eq(self.0.as_bytes())));
        Box::pin(async move {
            if ok {
                Ok("token".into())
            } else {
                Err("bearer token required".into())
            }
        })
    }
}

/// How the router is built.
#[derive(Clone)]
pub struct RouterOptions {
    /// `None`: the host authenticates in front of the router.
    pub auth: Option<Arc<dyn Authorizer>>,
    /// Mount the operator routes (`/admin/...`).
    pub admin: bool,
}

#[derive(Clone)]
struct Guard {
    auth: Option<Arc<dyn Authorizer>>,
    admin: bool,
}

/// Authenticate, then attach the [`Caller`] (follower identity) to the
/// request. The peer address comes from axum's `ConnectInfo` when the
/// server provides it, or from a [`Caller`]-less host.
async fn guard(State(g): State<Guard>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let principal = match &g.auth {
        None => None,
        Some(a) => match a.authorize(&parts, g.admin).await {
            Ok(p) => Some(p),
            Err(detail) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "unauthorized", "detail": detail})),
                )
                    .into_response();
            }
        },
    };
    let addr = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string());
    let caller = Caller::from_headers(&parts.headers, principal, addr);
    parts.extensions.insert(caller);
    next.run(Request::from_parts(parts, body)).await
}

/// The protocol as a router without a prefix: the host nests it where it
/// wants (`/changelog/v2`, ...).
pub fn router(node: Arc<Node>, opts: RouterOptions) -> Router {
    let read = Router::new()
        .route("/status", get(status))
        .route("/snapshot", get(snapshot))
        .route("/changes", get(changes))
        .route("/stream", get(stream))
        .route("/progress", post(progress))
        .route("/clients", get(clients))
        .route("/hashes", get(hashes))
        .route("/self-check", get(self_check))
        .route("/schema", get(schema))
        .route("/verify/{table}", get(verify_buckets))
        .route("/verify/{table}/rows", get(verify_rows))
        .layer(middleware::from_fn_with_state(
            Guard {
                auth: opts.auth.clone(),
                admin: false,
            },
            guard,
        ));
    let mut r = read;
    if opts.admin {
        let admin = Router::new()
            .route("/admin/metrics", get(metrics))
            .route("/admin/promote", post(admin_promote))
            .route("/admin/rejoin", post(admin_rejoin))
            .route("/admin/reset", post(admin_reset))
            .route("/admin/rebootstrap", post(admin_rebootstrap))
            .route("/admin/restart-history", post(admin_restart_history))
            .route("/admin/follow", post(admin_follow))
            .route("/admin/verify", post(admin_verify))
            .route("/admin/prune", post(admin_prune))
            .layer(middleware::from_fn_with_state(
                Guard {
                    auth: opts.auth.clone(),
                    admin: true,
                },
                guard,
            ));
        r = r.merge(admin);
    }
    r.with_state(node)
}

async fn status(State(node): State<Arc<Node>>) -> ApiResult<Json<crate::wire::Status>> {
    Ok(Json(node.status()?))
}

async fn metrics(State(node): State<Arc<Node>>) -> Json<Value> {
    Json(node.metrics.json())
}

async fn snapshot(
    State(node): State<Arc<Node>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    node.clients.seen(&caller, "snapshot", None, 0);
    let gzip = accepts_gzip(&headers);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let (first_tx, first_rx) = tokio::sync::oneshot::channel::<Result<(), CdcError>>();
    let n2 = node.clone();
    std::thread::spawn(move || {
        let mut gz = Gz::new(gzip);
        let mut buf = Vec::with_capacity(128 * 1024);
        let mut first = Some(first_tx);
        let res = n2.store.snapshot(|line| {
            if let Some(f) = first.take() {
                let _ = f.send(Ok(()));
            }
            n2.metrics
                .snapshot_raw
                .fetch_add(line.len() as u64, Ordering::Relaxed);
            buf.extend_from_slice(&line);
            if buf.len() >= 64 * 1024 {
                let b = gz.chunk(&buf);
                buf.clear();
                n2.metrics
                    .snapshot_wire
                    .fetch_add(b.len() as u64, Ordering::Relaxed);
                tx.blocking_send(b)
                    .map_err(|_| anyhow::anyhow!("client went away"))?;
            }
            Ok(())
        });
        match res {
            Ok(_) => {
                let mut b = gz.chunk(&buf).to_vec();
                b.extend_from_slice(&gz.finish());
                n2.metrics
                    .snapshot_wire
                    .fetch_add(b.len() as u64, Ordering::Relaxed);
                let _ = tx.blocking_send(Bytes::from(b));
            }
            Err(e) => {
                if let Some(f) = first.take() {
                    let _ = f.send(Err(e));
                } else {
                    tracing::warn!("snapshot aborted: {e}");
                }
            }
        }
    });
    // Errors before the first line (no history, halted) are proper HTTP errors.
    match first_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(err(Kind::Internal, "snapshot producer failed").into()),
    }
    Ok(encoded(gzip, "application/x-ndjson", channel_body(rx)))
}

#[derive(Deserialize)]
struct PosQuery {
    history: String,
    after: u64,
    hash: String,
    #[serde(default = "one")]
    min_bytes: usize,
    #[serde(default)]
    max_wait_ms: u64,
    #[serde(default = "mib")]
    max_bytes: usize,
    #[serde(default = "many")]
    max_txns: usize,
    /// The follower's schema fingerprint; must equal ours.
    schema: Option<String>,
}

fn one() -> usize {
    1
}
fn mib() -> usize {
    1 << 20
}
fn many() -> usize {
    10_000
}

impl PosQuery {
    fn check_schema(&self, node: &Node) -> Result<(), CdcError> {
        match &self.schema {
            Some(fp) if fp != node.store.schema_fp() => Err(err(
                Kind::SchemaMismatch,
                "the follower's tables differ from this node's (see GET <api>/schema)",
            )),
            _ => Ok(()),
        }
    }

    fn pos(&self) -> Position {
        Position {
            history: self.history.clone(),
            txn_id: self.after,
            hash: self.hash.clone(),
        }
    }
}

async fn changes(
    State(node): State<Arc<Node>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(q): Query<PosQuery>,
) -> ApiResult<Response> {
    node.clients.seen(&caller, "poll", Some(q.after), 0);
    q.check_schema(&node)?;
    let deadline = Instant::now() + Duration::from_millis(q.max_wait_ms.min(60_000));
    let mut rx = node.store.subscribe();
    let pos = q.pos();
    let (txns, last) = loop {
        rx.borrow_and_update();
        let store = node.store.clone();
        let p = pos.clone();
        let (max_bytes, max_txns) = (q.max_bytes, q.max_txns);
        let (txns, last) = blocking(move || store.changes(&p, max_bytes, max_txns)).await?;
        let bytes: usize = txns.iter().map(|t| t.bytes()).sum();
        if bytes >= q.min_bytes || Instant::now() >= deadline {
            break (txns, last);
        }
        // Wait for a commit or the deadline (then one last read).
        let _ = tokio::time::timeout_at(deadline.into(), rx.changed()).await;
    };
    node.metrics
        .txns_sent
        .fetch_add(txns.len() as u64, Ordering::Relaxed);
    node.clients.seen(&caller, "poll", None, txns.len() as u64);
    let client = node.clients.view(&caller.id, last);
    let body = serde_json::to_vec(&ChangesResponse {
        txns,
        last_txn: last,
        client,
    })
    .map_err(CdcError::from)?;
    let gzip = accepts_gzip(&headers);
    let mut gz = Gz::new(gzip);
    let mut out = gz.chunk(&body).to_vec();
    out.extend_from_slice(&gz.finish());
    node.metrics
        .changes_raw
        .fetch_add(body.len() as u64, Ordering::Relaxed);
    node.metrics
        .changes_wire
        .fetch_add(out.len() as u64, Ordering::Relaxed);
    Ok(encoded(gzip, "application/json", Body::from(out)))
}

async fn stream(
    State(node): State<Arc<Node>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(q): Query<PosQuery>,
) -> ApiResult<Response> {
    node.clients.seen(&caller, "stream", Some(q.after), 0);
    q.check_schema(&node)?;
    let mut pos = q.pos();
    {
        // Refuse a bad position with a proper status before streaming.
        let store = node.store.clone();
        let p = pos.clone();
        blocking(move || store.changes(&p, 1, 1)).await?;
    }
    let gzip = accepts_gzip(&headers);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    node.clients.set_connected(&caller.id, true);
    tokio::spawn(async move {
        /// Marks the stream closed however the task ends.
        struct Open(Arc<Node>, String);
        impl Drop for Open {
            fn drop(&mut self) {
                self.0.clients.set_connected(&self.1, false);
            }
        }
        let _open = Open(node.clone(), caller.id.clone());
        let mut gz = Gz::new(gzip);
        let mut sub = node.store.subscribe();
        let line = |l: &StreamLine, buf: &mut Vec<u8>| {
            serde_json::to_writer(&mut *buf, l).expect("serializable");
            buf.push(b'\n');
        };
        loop {
            sub.borrow_and_update();
            let store = node.store.clone();
            let p = pos.clone();
            let mut buf = Vec::new();
            match blocking(move || store.changes(&p, 256 * 1024, 1000)).await {
                Ok((txns, last)) if txns.is_empty() => {
                    // Wait for a commit; a heartbeat every 5 s keeps the
                    // connection alive and reports the server position.
                    if tokio::time::timeout(Duration::from_secs(5), sub.changed())
                        .await
                        .is_ok()
                    {
                        continue;
                    }
                    line(&StreamLine::Heartbeat { last_txn: last }, &mut buf);
                }
                Ok((txns, last)) => {
                    // The server position first: the follower batches
                    // until it has reached it.
                    line(&StreamLine::Heartbeat { last_txn: last }, &mut buf);
                    node.metrics
                        .txns_sent
                        .fetch_add(txns.len() as u64, Ordering::Relaxed);
                    node.clients
                        .seen(&caller, "stream", None, txns.len() as u64);
                    for t in txns {
                        pos.txn_id = t.txn_id;
                        pos.hash = t.hash.clone();
                        line(&StreamLine::Txn(t), &mut buf);
                    }
                }
                Err(e) => {
                    line(
                        &StreamLine::Error(ErrorBody {
                            error: e.kind.as_str().into(),
                            detail: e.detail,
                        }),
                        &mut buf,
                    );
                    let mut b = gz.chunk(&buf).to_vec();
                    b.extend_from_slice(&gz.finish());
                    let _ = tx.send(Bytes::from(b)).await;
                    return;
                }
            }
            let b = gz.chunk(&buf);
            node.metrics
                .changes_raw
                .fetch_add(buf.len() as u64, Ordering::Relaxed);
            node.metrics
                .changes_wire
                .fetch_add(b.len() as u64, Ordering::Relaxed);
            if tx.send(b).await.is_err() {
                return; // client went away
            }
        }
    });
    Ok(encoded(gzip, "application/x-ndjson", channel_body(rx)))
}

async fn schema(State(node): State<Arc<Node>>) -> Json<Vec<crate::schema::TableSpec>> {
    Json(node.store.tables().to_vec())
}

#[derive(Deserialize)]
struct RangeQuery {
    from: u64,
    to: u64,
}

async fn hashes(
    State(node): State<Arc<Node>>,
    Query(q): Query<RangeQuery>,
) -> ApiResult<Json<Vec<(u64, String)>>> {
    let to = q.to.min(q.from.saturating_add(9_999));
    let store = node.store.clone();
    Ok(Json(blocking(move || store.hashes(q.from, to)).await?))
}

#[derive(Deserialize)]
struct VerifyQuery {
    at: u64,
    #[serde(default = "buckets")]
    buckets: u64,
    #[serde(default)]
    bucket: usize,
}

fn buckets() -> u64 {
    256
}

async fn verify_buckets(
    State(node): State<Arc<Node>>,
    Path(table): Path<String>,
    Query(q): Query<VerifyQuery>,
) -> ApiResult<Json<crate::wire::BucketReport>> {
    let store = node.store.clone();
    let b = q.buckets.clamp(1, 65_536);
    Ok(Json(
        blocking(move || store.bucket_hashes(&table, q.at, b)).await?,
    ))
}

async fn verify_rows(
    State(node): State<Arc<Node>>,
    Path(table): Path<String>,
    Query(q): Query<VerifyQuery>,
) -> ApiResult<Json<Vec<crate::wire::RowHash>>> {
    let store = node.store.clone();
    let b = q.buckets.clamp(1, 65_536);
    Ok(Json(
        blocking(move || store.bucket_rows(&table, q.at, b, q.bucket)).await?,
    ))
}

// ---- admin ---------------------------------------------------------------

#[derive(Deserialize)]
struct ProgressBody {
    txn_id: u64,
}

/// A streaming follower reports what it has applied (a poll follower's
/// `after` already says it). Answers with the server's view of it.
async fn progress(
    State(node): State<Arc<Node>>,
    Extension(caller): Extension<Caller>,
    Json(b): Json<ProgressBody>,
) -> ApiResult<Json<crate::wire::ClientView>> {
    node.clients.seen(&caller, "stream", Some(b.txn_id), 0);
    let head = node.store.state()?.last_txn;
    node.clients
        .view(&caller.id, head)
        .map(Json)
        .ok_or_else(|| err(Kind::Internal, "client vanished").into())
}

/// Does the log agree with the live data? See [`crate::store::Store::self_check`].
async fn self_check(State(node): State<Arc<Node>>) -> ApiResult<Json<Value>> {
    let store = node.store.clone();
    Ok(Json(blocking(move || store.self_check()).await?))
}

/// Every follower this node has heard from, with lag and up-to-date.
async fn clients(State(node): State<Arc<Node>>) -> ApiResult<Json<Value>> {
    let head = node.store.state()?.last_txn;
    let list = node.clients.list(head);
    let behind = list.iter().filter(|c| !c.up_to_date).count();
    Ok(Json(
        json!({"last_txn": head, "clients": list, "all_up_to_date": behind == 0}),
    ))
}

async fn admin_restart_history(State(node): State<Arc<Node>>) -> ApiResult<Json<Value>> {
    let store = node.store.clone();
    let st = blocking(move || store.restart_history()).await?;
    Ok(Json(json!({"history": st.history})))
}

#[derive(Deserialize)]
struct PromoteBody {
    #[serde(default)]
    peers: Vec<String>,
    #[serde(default)]
    force: bool,
}

async fn admin_promote(
    State(node): State<Arc<Node>>,
    Json(b): Json<PromoteBody>,
) -> ApiResult<Json<Value>> {
    Ok(Json(node.promote(&b.peers, b.force).await?))
}

#[derive(Deserialize)]
struct RejoinBody {
    upstream: String,
    #[serde(default)]
    accept_loss: bool,
}

async fn admin_rejoin(
    State(node): State<Arc<Node>>,
    Json(b): Json<RejoinBody>,
) -> ApiResult<Json<Value>> {
    Ok(Json(node.rejoin(&b.upstream, b.accept_loss).await?))
}

async fn admin_reset(State(node): State<Arc<Node>>) -> ApiResult<Json<Value>> {
    node.rebootstrap(None).await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize, Default)]
struct RebootstrapBody {
    upstream: Option<String>,
}

async fn admin_rebootstrap(
    State(node): State<Arc<Node>>,
    body: Option<Json<RebootstrapBody>>,
) -> ApiResult<Json<Value>> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    node.rebootstrap(b.upstream.as_deref()).await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct FollowBody {
    upstream: String,
}

/// Start following, or repoint to another upstream of the same history.
async fn admin_follow(
    State(node): State<Arc<Node>>,
    Json(b): Json<FollowBody>,
) -> ApiResult<Json<Value>> {
    node.start_follow(&b.upstream).await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct AdminVerifyBody {
    #[serde(default = "buckets")]
    buckets: u64,
}

async fn admin_verify(
    State(node): State<Arc<Node>>,
    Json(b): Json<AdminVerifyBody>,
) -> ApiResult<Json<Value>> {
    Ok(Json(node.verify(b.buckets).await?))
}

#[derive(Deserialize)]
struct PruneBody {
    keep: u64,
}

async fn admin_prune(
    State(node): State<Arc<Node>>,
    Json(b): Json<PruneBody>,
) -> ApiResult<Json<Value>> {
    let store = node.store.clone();
    let n = blocking(move || store.prune(b.keep)).await?;
    Ok(Json(json!({"rows_pruned": n})))
}
