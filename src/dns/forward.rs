//! Forward a query to upstream resolvers.
//!
//! The client's request is relayed with a fresh random transaction ID and,
//! by default, a randomised letter case in the question name (DNS 0x20,
//! draft-vixie-dnsext-dns0x20). A reply is accepted only when it carries
//! that ID, QR=1, the same opcode and exactly the same question (name bytes,
//! type and class); anything else is ignored while the timeout runs, so an
//! off-path attacker has to guess 16 bits of ID plus one bit per letter of
//! the name. Upstreams that do not echo the case are retried once without
//! 0x20. The accepted reply gets the client's ID and question bytes back,
//! so it can be returned to the client (and cached) as-is.

use super::Proto;
use crate::config::ForwardingConfig;
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

/// Byte range of the (single) question in a message: name, type and class.
pub fn question_span(msg: &[u8]) -> Option<std::ops::Range<usize>> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // no compression pointers in a first question
        }
        i += 1 + len;
    }
    let end = i + 4;
    (end <= msg.len()).then_some(12..end)
}

/// How a reply relates to the query we sent.
#[derive(Debug, PartialEq, Eq)]
enum Match {
    Exact,
    /// Everything matches except the letter case of the question name.
    CaseOnly,
    No,
}

fn check_reply(sent: &[u8], span: &std::ops::Range<usize>, reply: &[u8]) -> Match {
    if reply.len() < 12
        || reply[..2] != sent[..2]
        || reply[2] & 0x80 == 0
        || (reply[2] >> 3) & 0x0F != (sent[2] >> 3) & 0x0F
    {
        return Match::No;
    }
    let Some(rspan) = question_span(reply) else {
        return Match::No;
    };
    let (q, r) = (&sent[span.clone()], &reply[rspan]);
    if q == r {
        Match::Exact
    } else if q.eq_ignore_ascii_case(r) {
        Match::CaseOnly
    } else {
        Match::No
    }
}

/// The request as sent upstream: new ID and (optionally) 0x20 case.
fn prepare(req: &[u8], span: &std::ops::Range<usize>, mix_case: bool) -> Vec<u8> {
    let mut out = req.to_vec();
    let mut rng = rand::rng();
    let id: u16 = rng.random();
    out[..2].copy_from_slice(&id.to_be_bytes());
    if mix_case {
        // Walk the labels so length octets are never touched.
        let mut i = span.start;
        while out[i] != 0 {
            let len = out[i] as usize;
            for b in &mut out[i + 1..=i + len] {
                if b.is_ascii_alphabetic() && rng.random::<bool>() {
                    *b ^= 0x20;
                }
            }
            i += 1 + len;
        }
    }
    out
}

/// Put the client's ID and question bytes back into an accepted reply.
pub(super) fn restore(
    client_req: &[u8],
    span: &std::ops::Range<usize>,
    mut reply: Vec<u8>,
) -> Vec<u8> {
    reply[..2].copy_from_slice(&client_req[..2]);
    reply[span.clone()].copy_from_slice(&client_req[span.clone()]);
    reply
}

/// Forward to the upstreams of `cfg`, in order (the upstream probe of the
/// console; queries go through [`forward_via`]).
pub async fn forward(cfg: &ForwardingConfig, req: &[u8], proto: Proto) -> Result<Vec<u8>> {
    forward_via(
        &cfg.upstreams,
        cfg.timeout_ms,
        UpstreamStrategy::InOrder,
        None,
        req,
        proto,
    )
    .await
}

/// Health of one upstream as this server saw it (I6).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct UpstreamHealth {
    /// `ip:port`.
    pub upstream: String,
    /// Average answer time (exponentially weighted, milliseconds); `null`
    /// before the first answer.
    #[schema(required = true)]
    pub latency_ms: Option<f64>,
    pub successes: u64,
    pub failures: u64,
    /// Failures in a row (3 mark the upstream down).
    pub consecutive_failures: u32,
    /// Marked down: skipped by the `fastest` and `parallel` strategies
    /// except for one probe every 30 seconds.
    pub down: bool,
    #[schema(required = true)]
    pub last_error: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub last_error_at: Option<String>,
}

struct HealthEntry {
    view: UpstreamHealth,
    last_attempt: Option<std::time::Instant>,
}

/// Failures in a row that mark an upstream down.
pub const DOWN_AFTER: u32 = 3;
/// How often a down upstream is tried again (one query).
pub const PROBE_EVERY: Duration = Duration::from_secs(30);

/// Per-upstream health, shared by all queries of this server.
#[derive(Default)]
pub struct Health {
    inner: std::sync::Mutex<std::collections::HashMap<SocketAddr, HealthEntry>>,
}

impl Health {
    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<SocketAddr, HealthEntry>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn entry(
        m: &mut std::collections::HashMap<SocketAddr, HealthEntry>,
        u: SocketAddr,
    ) -> &mut HealthEntry {
        m.entry(u).or_insert_with(|| HealthEntry {
            view: UpstreamHealth {
                upstream: u.to_string(),
                latency_ms: None,
                successes: 0,
                failures: 0,
                consecutive_failures: 0,
                down: false,
                last_error: None,
                last_error_at: None,
            },
            last_attempt: None,
        })
    }

    pub fn record_ok(&self, u: SocketAddr, elapsed: Duration) {
        let mut g = self.lock();
        let e = Self::entry(&mut g, u);
        let ms = elapsed.as_secs_f64() * 1000.0;
        e.view.latency_ms = Some(match e.view.latency_ms {
            None => ms,
            Some(old) => old * 0.8 + ms * 0.2,
        });
        e.view.successes += 1;
        e.view.consecutive_failures = 0;
        if e.view.down {
            tracing::info!(upstream = %u, "upstream answers again; marked up");
        }
        e.view.down = false;
    }

    pub fn record_err(&self, u: SocketAddr, err: &anyhow::Error) {
        let mut g = self.lock();
        let e = Self::entry(&mut g, u);
        e.view.failures += 1;
        e.view.consecutive_failures += 1;
        e.view.last_error = Some(format!("{err:#}"));
        e.view.last_error_at = Some(crate::model::now_rfc3339());
        if !e.view.down && e.view.consecutive_failures >= DOWN_AFTER {
            tracing::warn!(upstream = %u, error = %err, "upstream marked down after {DOWN_AFTER} failures in a row");
            e.view.down = true;
        }
    }

    /// The upstreams to try, in order, for `strategy`: `in_order` keeps
    /// the configured order (down or not); `fastest` puts usable upstreams
    /// by average latency first (unmeasured ones before measured ones, so
    /// they get measured) and down ones last; `parallel` returns the usable
    /// ones (all of them if none is usable). A down upstream counts as
    /// usable once per [`PROBE_EVERY`] (the probe).
    pub fn plan(&self, ups: &[SocketAddr], strategy: UpstreamStrategy) -> Vec<SocketAddr> {
        if strategy == UpstreamStrategy::InOrder || ups.len() <= 1 {
            return ups.to_vec();
        }
        let now = std::time::Instant::now();
        let mut g = self.lock();
        let mut usable: Vec<(SocketAddr, f64)> = Vec::new();
        let mut down: Vec<SocketAddr> = Vec::new();
        for u in ups {
            let e = Self::entry(&mut g, *u);
            let probe_due = e
                .last_attempt
                .is_none_or(|t| now.duration_since(t) >= PROBE_EVERY);
            if !e.view.down || probe_due {
                if e.view.down {
                    e.last_attempt = Some(now); // one probe per interval
                }
                usable.push((*u, e.view.latency_ms.unwrap_or(-1.0)));
            } else {
                down.push(*u);
            }
        }
        match strategy {
            UpstreamStrategy::Parallel if usable.is_empty() => down,
            UpstreamStrategy::Parallel => usable.into_iter().map(|(u, _)| u).collect(),
            _ => {
                usable.sort_by(|a, b| a.1.total_cmp(&b.1));
                usable.into_iter().map(|(u, _)| u).chain(down).collect()
            }
        }
    }

    fn attempted(&self, u: SocketAddr) {
        let mut g = self.lock();
        Self::entry(&mut g, u).last_attempt = Some(std::time::Instant::now());
    }

    /// Health of `ups`, in that order (upstreams never asked included).
    pub fn report(&self, ups: &[SocketAddr]) -> Vec<UpstreamHealth> {
        let mut g = self.lock();
        ups.iter()
            .map(|u| Self::entry(&mut g, *u).view.clone())
            .collect()
    }
}

pub use crate::mutation::settings::UpstreamStrategy;

/// Forward `req` to `upstreams` with `strategy`, recording each upstream's
/// health in `health`. The accepted reply carries the client's ID and
/// question bytes.
pub async fn forward_via(
    upstreams: &[SocketAddr],
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    health: Option<&Health>,
    req: &[u8],
    proto: Proto,
) -> Result<Vec<u8>> {
    let span = question_span(req).ok_or_else(|| anyhow!("query has no single question"))?;
    let to = Duration::from_millis(timeout_ms.max(100));
    let order = match health {
        Some(h) => h.plan(upstreams, strategy),
        None => upstreams.to_vec(),
    };
    let one = |upstream: SocketAddr| {
        let span = span.clone();
        async move {
            if let Some(h) = health {
                h.attempted(upstream);
            }
            let started = std::time::Instant::now();
            let r = exchange_with_fallbacks(upstream, req, &span, proto, to).await;
            if let Some(h) = health {
                match &r {
                    Ok(_) => h.record_ok(upstream, started.elapsed()),
                    Err(e) => h.record_err(upstream, e),
                }
            }
            if let Err(e) = &r {
                tracing::debug!(%upstream, error = %e, "upstream failed");
            }
            r
        }
    };
    if strategy == UpstreamStrategy::Parallel && order.len() > 1 {
        let all: Vec<_> = order.iter().map(|u| Box::pin(one(*u))).collect();
        return match futures::future::select_ok(all).await {
            Ok((b, _)) => Ok(restore(req, &span, b)),
            Err(e) => Err(e),
        };
    }
    let mut last_err = anyhow!("no upstreams configured");
    for upstream in order {
        match one(upstream).await {
            Ok(b) => return Ok(restore(req, &span, b)),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn exchange_with_fallbacks(
    upstream: SocketAddr,
    req: &[u8],
    span: &std::ops::Range<usize>,
    proto: Proto,
    to: Duration,
) -> Result<Vec<u8>> {
    match exchange(upstream, req, span, proto, to, true).await {
        Err(e) if e.downcast_ref::<CaseMismatch>().is_some() => {
            tracing::debug!(%upstream, "upstream does not preserve 0x20 case; retrying without");
            exchange(upstream, req, span, proto, to, false).await
        }
        other => other,
    }
}

#[derive(Debug)]
struct CaseMismatch;
impl std::fmt::Display for CaseMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream changed the letter case of the question")
    }
}
impl std::error::Error for CaseMismatch {}

async fn exchange(
    upstream: SocketAddr,
    req: &[u8],
    span: &std::ops::Range<usize>,
    proto: Proto,
    to: Duration,
    mix_case: bool,
) -> Result<Vec<u8>> {
    let sent = prepare(req, span, mix_case);
    let reply = match proto {
        Proto::Tcp => forward_tcp(upstream, &sent, span, to, mix_case).await?,
        Proto::Udp => {
            let b = forward_udp(upstream, &sent, span, to, mix_case).await?;
            if b[2] & 0x02 != 0 {
                // Truncated upstream: retry over TCP for a full answer; the
                // UDP path re-truncates it to the client's limit if needed.
                let sent = prepare(req, span, mix_case);
                forward_tcp(upstream, &sent, span, to, mix_case)
                    .await
                    .unwrap_or(b)
            } else {
                b
            }
        }
    };
    Ok(reply)
}

fn accept(
    sent: &[u8],
    span: &std::ops::Range<usize>,
    reply: &[u8],
    mix_case: bool,
) -> Result<bool> {
    match check_reply(sent, span, reply) {
        Match::Exact => Ok(true),
        Match::CaseOnly if !mix_case => Ok(true),
        Match::CaseOnly => Err(CaseMismatch.into()),
        Match::No => Ok(false),
    }
}

async fn forward_udp(
    upstream: SocketAddr,
    sent: &[u8],
    span: &std::ops::Range<usize>,
    to: Duration,
    mix_case: bool,
) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = UdpSocket::bind(bind)
        .await
        .context("binding forwarding socket")?;
    sock.connect(upstream).await?;
    sock.send(sent).await?;
    let deadline = Instant::now() + to;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .context("upstream timed out")??;
        // Replies that do not match are ignored (spoofing attempts, late
        // answers); keep waiting for the real one until the deadline.
        if accept(sent, span, &buf[..n], mix_case)? {
            return Ok(buf[..n].to_vec());
        }
        tracing::debug!(%upstream, "ignoring non-matching upstream reply");
    }
}

async fn forward_tcp(
    upstream: SocketAddr,
    sent: &[u8],
    span: &std::ops::Range<usize>,
    to: Duration,
    mix_case: bool,
) -> Result<Vec<u8>> {
    let mut s = timeout(to, TcpStream::connect(upstream))
        .await
        .context("upstream connect timed out")??;
    let mut msg = Vec::with_capacity(sent.len() + 2);
    msg.extend_from_slice(&(sent.len() as u16).to_be_bytes());
    msg.extend_from_slice(sent);
    timeout(to, s.write_all(&msg))
        .await
        .context("upstream write timed out")??;
    let mut lenbuf = [0u8; 2];
    timeout(to, s.read_exact(&mut lenbuf))
        .await
        .context("upstream timed out")??;
    let n = u16::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; n];
    timeout(to, s.read_exact(&mut buf))
        .await
        .context("upstream timed out")??;
    if !accept(sent, span, &buf, mix_case)? {
        bail!("upstream reply does not match the query (ID, QR, opcode or question)");
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[..2].copy_from_slice(&id.to_be_bytes());
        m[2] = 0x01; // RD
        m[5] = 1; // QDCOUNT
        for l in name.trim_end_matches('.').split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    fn reply_to(q: &[u8]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r
    }

    #[test]
    fn fresh_id_and_mixed_case_are_restored() {
        let req = query(0x1234, "www.example.com");
        let span = question_span(&req).unwrap();
        // Over many tries the ID changes and some letters flip case.
        let mut flipped = false;
        for _ in 0..50 {
            let sent = prepare(&req, &span, true);
            assert_eq!(sent.len(), req.len());
            assert!(sent[span.clone()].eq_ignore_ascii_case(&req[span.clone()]));
            flipped |= sent[span.clone()] != req[span.clone()];
            let r = reply_to(&sent);
            assert_eq!(check_reply(&sent, &span, &r), Match::Exact);
            let back = restore(&req, &span, r);
            assert_eq!(&back[..2], &req[..2], "client ID restored");
            assert_eq!(
                &back[span.clone()],
                &req[span.clone()],
                "client case restored"
            );
        }
        assert!(flipped, "0x20 changes the case of some letters");
        let ids: std::collections::HashSet<[u8; 2]> = (0..20)
            .map(|_| {
                let s = prepare(&req, &span, false);
                [s[0], s[1]]
            })
            .collect();
        assert!(ids.len() > 1, "a fresh ID per upstream query");
    }

    /// M5 regression: replies used to be accepted on a matching ID alone.
    #[test]
    fn replies_must_match_id_qr_opcode_and_question() {
        let sent = query(0xBEEF, "wWw.ExAmple.com");
        let span = question_span(&sent).unwrap();
        assert_eq!(check_reply(&sent, &span, &reply_to(&sent)), Match::Exact);
        // Not a response (QR=0): e.g. our own query reflected back.
        assert_eq!(check_reply(&sent, &span, &sent), Match::No);
        // Wrong ID.
        let mut r = reply_to(&sent);
        r[1] ^= 1;
        assert_eq!(check_reply(&sent, &span, &r), Match::No);
        // Different opcode.
        let mut r = reply_to(&sent);
        r[2] |= 2 << 3;
        assert_eq!(check_reply(&sent, &span, &r), Match::No);
        // A different question (same ID), e.g. a spoofed answer for another name.
        let other = reply_to(&query(0xBEEF, "www.evil.com"));
        assert_eq!(check_reply(&sent, &span, &other), Match::No);
        // Different qtype.
        let mut r = reply_to(&sent);
        let t = span.end - 3;
        r[t] = 28;
        assert_eq!(check_reply(&sent, &span, &r), Match::No);
        // Same name, other case: only a case mismatch (0x20 fallback).
        let r = reply_to(&query(0xBEEF, "www.example.com"));
        assert_eq!(check_reply(&sent, &span, &r), Match::CaseOnly);
        assert!(accept(&sent, &span, &r, true).is_err());
        assert!(accept(&sent, &span, &r, false).unwrap());
        // No question at all.
        let mut r = reply_to(&sent);
        r[5] = 0;
        assert_eq!(check_reply(&sent, &span, &r), Match::No);
    }
}
