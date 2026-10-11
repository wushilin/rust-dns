//! HTTP client for the protocol in [`crate::server`].

use std::time::Duration;

use futures::{Stream, StreamExt};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::store::{CdcError, Kind, err};
use crate::wire::{
    BucketReport, ChangesResponse, ErrorBody, Position, RowHash, Status, StreamLine,
};

/// A client of one node's API. `base` includes the host's mount prefix,
/// e.g. `https://dns1.example/rust-dns/changelog-api/v2`.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    /// Sent on every request: authentication and the follower identity.
    headers: reqwest::header::HeaderMap,
}

/// How a node's outgoing requests look: the HTTP client (TLS roots, ...)
/// and headers (authentication). The follower identity is added per node.
#[derive(Clone)]
pub struct ClientTemplate {
    pub http: reqwest::Client,
    pub headers: reqwest::header::HeaderMap,
}

impl std::fmt::Debug for ClientTemplate {
    /// Never prints the headers: they carry credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTemplate")
            .field("headers", &self.headers.len())
            .finish()
    }
}

impl ClientTemplate {
    pub fn bearer(token: &str) -> ClientTemplate {
        let mut headers = reqwest::header::HeaderMap::new();
        if !token.is_empty() {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .expect("token is a valid header"),
            );
        }
        ClientTemplate {
            http: default_http(),
            headers,
        }
    }

    pub fn client(&self, base: &str) -> Client {
        Client {
            http: self.http.clone(),
            base: base.trim_end_matches('/').to_string(),
            headers: self.headers.clone(),
        }
    }
}

fn default_http() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("http client")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PollOpts {
    pub min_bytes: usize,
    pub max_wait_ms: u64,
    pub max_bytes: usize,
}

impl Default for PollOpts {
    fn default() -> Self {
        PollOpts {
            min_bytes: 1,
            max_wait_ms: 25_000,
            max_bytes: 1 << 20,
        }
    }
}

fn net(e: reqwest::Error) -> CdcError {
    err(Kind::Unreachable, e.to_string())
}

fn is_gzip(r: &reqwest::Response) -> bool {
    r.headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("gzip"))
}

async fn json_body<T: DeserializeOwned>(r: reqwest::Response) -> Result<T, CdcError> {
    let gz = is_gzip(&r);
    let bytes = r.bytes().await.map_err(net)?;
    let raw = if gz {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .map_err(|e| err(Kind::Unreachable, format!("gzip: {e}")))?;
        out
    } else {
        bytes.to_vec()
    };
    serde_json::from_slice(&raw).map_err(CdcError::from)
}

/// The response body, gunzipped chunk by chunk when it is compressed (the
/// server flushes per batch, so each chunk decodes as it arrives).
fn decoded(
    r: reqwest::Response,
) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>> {
    if !is_gzip(&r) {
        return r.bytes_stream().boxed();
    }
    let dec = flate2::write::GzDecoder::new(Vec::new());
    futures::stream::unfold(
        (r.bytes_stream().boxed(), Some(dec)),
        |(mut inner, mut dec)| async move {
            use std::io::Write;
            let d = dec.as_mut()?;
            match inner.next().await {
                Some(Ok(c)) => {
                    // flush: everything decodable so far comes out now. A
                    // decoding error shows as a truncated stream, which the
                    // snapshot digest or the next request catches.
                    let _ = d.write_all(&c).and_then(|_| d.flush());
                    let out = bytes::Bytes::from(std::mem::take(d.get_mut()));
                    Some((Ok(out), (inner, dec)))
                }
                Some(Err(e)) => Some((Err(e), (inner, None))),
                None => {
                    // The end: whatever the decoder still holds.
                    let mut d = dec.take()?;
                    let _ = d.try_finish();
                    let out = bytes::Bytes::from(std::mem::take(d.get_mut()));
                    Some((Ok(out), (inner, None)))
                }
            }
        },
    )
    .boxed()
}

/// Split a byte stream into lines. Linear: each byte is scanned once and
/// consumed lines are dropped in bulk.
pub fn ndjson_lines(
    s: impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
) -> impl Stream<Item = Result<Vec<u8>, CdcError>> {
    struct St<S> {
        s: S,
        buf: Vec<u8>,
        /// Start of the next line in `buf`.
        start: usize,
        /// Bytes of `buf` already searched for a newline.
        scanned: usize,
        done: bool,
    }
    let st = St {
        s,
        buf: Vec::new(),
        start: 0,
        scanned: 0,
        done: false,
    };
    futures::stream::unfold(st, |mut st| async move {
        loop {
            if let Some(i) = st.buf[st.scanned..].iter().position(|&b| b == b'\n') {
                let end = st.scanned + i;
                let line = st.buf[st.start..end].to_vec();
                st.start = end + 1;
                st.scanned = st.start;
                return Some((Ok(line), st));
            }
            st.scanned = st.buf.len();
            if st.done {
                return None;
            }
            if st.start > 0 && st.start * 2 >= st.buf.len() {
                st.buf.drain(..st.start);
                st.scanned -= st.start;
                st.start = 0;
            }
            match st.s.next().await {
                Some(Ok(b)) => st.buf.extend_from_slice(&b),
                Some(Err(e)) => {
                    st.done = true;
                    return Some((Err(net(e)), st));
                }
                None => {
                    st.done = true;
                    if st.start < st.buf.len() {
                        let line = st.buf[st.start..].to_vec();
                        st.start = st.buf.len();
                        st.scanned = st.start;
                        return Some((Ok(line), st));
                    }
                    return None;
                }
            }
        }
    })
}

impl Client {
    pub fn new(base: &str, token: &str) -> Client {
        ClientTemplate::bearer(token).client(base)
    }

    /// Identify as follower `id` (shown on the server as `name`).
    pub fn identify(mut self, id: &str, name: &str) -> Client {
        for (k, v) in [
            (crate::clients::CLIENT_ID, id),
            (crate::clients::CLIENT_NAME, name),
        ] {
            if let Ok(v) = v.parse() {
                self.headers.insert(k, v);
            }
        }
        self
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, CdcError> {
        // gzip is negotiated and decoded here, not by reqwest's `gzip`
        // feature: enabling that feature would switch on automatic
        // decompression for every reqwest user in the host application.
        let r = req
            .headers(self.headers.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(net)?;
        if r.status().is_success() {
            return Ok(r);
        }
        let status = r.status();
        let text = r.text().await.unwrap_or_default();
        Err(match serde_json::from_str::<ErrorBody>(&text) {
            Ok(b) => err(Kind::parse(&b.error), b.detail),
            Err(_) => err(Kind::Internal, format!("HTTP {status}: {text}")),
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, timeout: Duration) -> Result<T, CdcError> {
        let r = self
            .send(
                self.http
                    .get(format!("{}{path}", self.base))
                    .timeout(timeout),
            )
            .await?;
        json_body(r).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T, CdcError> {
        let r = self
            .send(
                self.http
                    .post(format!("{}{path}", self.base))
                    .timeout(Duration::from_secs(120))
                    .json(&body),
            )
            .await?;
        json_body(r).await
    }

    fn pos_query(p: &Position, schema: &str) -> String {
        format!(
            "history={}&after={}&hash={}&schema={schema}",
            p.history, p.txn_id, p.hash
        )
    }

    pub async fn schema(&self) -> Result<Vec<crate::schema::TableSpec>, CdcError> {
        self.get("/schema", Duration::from_secs(10)).await
    }

    pub async fn status(&self) -> Result<Status, CdcError> {
        self.get("/status", Duration::from_secs(5)).await
    }

    pub async fn changes(
        &self,
        p: &Position,
        schema: &str,
        o: &PollOpts,
    ) -> Result<ChangesResponse, CdcError> {
        let q = format!(
            "/changes?{}&min_bytes={}&max_wait_ms={}&max_bytes={}",
            Self::pos_query(p, schema),
            o.min_bytes,
            o.max_wait_ms,
            o.max_bytes
        );
        self.get(
            &q,
            Duration::from_millis(o.max_wait_ms) + Duration::from_secs(30),
        )
        .await
    }

    /// The change stream, line by line.
    pub async fn stream(
        &self,
        p: &Position,
        schema: &str,
    ) -> Result<impl Stream<Item = Result<StreamLine, CdcError>>, CdcError> {
        let r = self
            .send(self.http.get(format!(
                "{}/stream?{}",
                self.base,
                Self::pos_query(p, schema)
            )))
            .await?;
        Ok(ndjson_lines(decoded(r)).map(|l| {
            l.and_then(|l| serde_json::from_slice::<StreamLine>(&l).map_err(CdcError::from))
        }))
    }

    /// The snapshot, as raw NDJSON lines (for the store's digest check).
    pub async fn snapshot(
        &self,
    ) -> Result<impl Stream<Item = Result<Vec<u8>, CdcError>>, CdcError> {
        let r = self
            .send(self.http.get(format!("{}/snapshot", self.base)))
            .await?;
        Ok(ndjson_lines(decoded(r)))
    }

    pub async fn hashes(&self, from: u64, to: u64) -> Result<Vec<(u64, String)>, CdcError> {
        self.get(
            &format!("/hashes?from={from}&to={to}"),
            Duration::from_secs(30),
        )
        .await
    }

    pub async fn bucket_hashes(
        &self,
        table: &str,
        at: u64,
        buckets: u64,
    ) -> Result<BucketReport, CdcError> {
        self.get(
            &format!("/verify/{table}?at={at}&buckets={buckets}"),
            Duration::from_secs(120),
        )
        .await
    }

    pub async fn bucket_rows(
        &self,
        table: &str,
        at: u64,
        buckets: u64,
        bucket: usize,
    ) -> Result<Vec<RowHash>, CdcError> {
        self.get(
            &format!("/verify/{table}/rows?at={at}&buckets={buckets}&bucket={bucket}"),
            Duration::from_secs(120),
        )
        .await
    }

    /// Report the applied position (stream mode); returns the server's view.
    pub async fn progress(&self, txn_id: u64) -> Result<crate::wire::ClientView, CdcError> {
        self.post("/progress", json!({"txn_id": txn_id})).await
    }

    pub async fn clients(&self) -> Result<Value, CdcError> {
        self.get("/clients", Duration::from_secs(10)).await
    }

    // ---- admin ----

    /// Only on servers that mount an `exec` route (the demo node).
    pub async fn exec(&self, sql: &[&str]) -> Result<Value, CdcError> {
        self.post(
            "/admin/exec",
            json!({"sql": sql, "meta": {"actor": "client"}}),
        )
        .await
    }

    pub async fn restart_history(&self) -> Result<Value, CdcError> {
        self.post("/admin/restart-history", json!({})).await
    }
    pub async fn promote(&self, peers: &[&str], force: bool) -> Result<Value, CdcError> {
        self.post("/admin/promote", json!({"peers": peers, "force": force}))
            .await
    }
    pub async fn rejoin(&self, upstream: &str, accept_loss: bool) -> Result<Value, CdcError> {
        self.post(
            "/admin/rejoin",
            json!({"upstream": upstream, "accept_loss": accept_loss}),
        )
        .await
    }
    pub async fn reset(&self) -> Result<Value, CdcError> {
        self.post("/admin/reset", json!({})).await
    }
    pub async fn rebootstrap(&self, upstream: Option<&str>) -> Result<Value, CdcError> {
        self.post("/admin/rebootstrap", json!({"upstream": upstream}))
            .await
    }
    pub async fn follow(&self, upstream: &str) -> Result<Value, CdcError> {
        self.post("/admin/follow", json!({"upstream": upstream}))
            .await
    }
    pub async fn verify(&self, buckets: u64) -> Result<Value, CdcError> {
        self.post("/admin/verify", json!({"buckets": buckets}))
            .await
    }
    pub async fn prune(&self, keep: u64) -> Result<Value, CdcError> {
        self.post("/admin/prune", json!({"keep": keep})).await
    }
    pub async fn metrics(&self) -> Result<Value, CdcError> {
        self.get("/admin/metrics", Duration::from_secs(5)).await
    }
}
