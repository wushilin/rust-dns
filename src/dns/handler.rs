//! Turns a raw DNS request into a reply.

use super::keyring::KeyEntry;
use super::tsig::{self, Chain, SignParams, Signed, VerifyError};
use super::Runtime;
use super::{DnsServer, Proto, Reply};
use crate::model::QueryEvent;
use crate::ratelimit::Decision;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Instant;

pub const VERSION_STRING: &str = concat!("rust-dns ", env!("CARGO_PKG_VERSION"));

/// Minimal header-only response for requests we cannot parse.
pub(super) fn header_only(id: u16, rcode: ResponseCode) -> Vec<u8> {
    Message::error_msg(id, OpCode::Query, rcode)
        .to_vec()
        .unwrap_or_default()
}

/// Rate-limit "slip" answer: the request's header and question with QR and
/// TC set and nothing else. Never larger than the request, so it cannot be
/// used for amplification, and it tells a genuine client to retry over TCP.
pub(super) fn slip_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 12 || req[2] & 0x80 != 0 {
        return None;
    }
    let span = super::forward::question_span(req)?;
    let mut out = Vec::with_capacity(span.end);
    out.extend_from_slice(&req[..2]);
    out.push(0x80 | (req[2] & 0x78) | 0x02 | (req[2] & 0x01)); // QR, opcode, TC, RD
    out.push(0);
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&req[span]);
    Some(out)
}

/// One of the `[forwarding].max_inflight` slots; freed on drop.
pub(super) struct InflightSlot<'a>(&'a super::Stats);

impl<'a> InflightSlot<'a> {
    pub(super) fn take(stats: &'a super::Stats, max: usize) -> Option<Self> {
        let n = stats.forward_inflight.fetch_add(1, Relaxed);
        if n >= max.max(1) {
            stats.forward_inflight.fetch_sub(1, Relaxed);
            return None;
        }
        Some(InflightSlot(stats))
    }
}

impl Drop for InflightSlot<'_> {
    fn drop(&mut self) {
        self.0.forward_inflight.fetch_sub(1, Relaxed);
    }
}

/// Per-request facts the finish stage and the query event need.
pub(super) struct Ctx {
    pub(super) client: SocketAddr,
    pub(super) proto: Proto,
    pub(super) started: Instant,
    pub(super) udp_limit: usize,
    /// Bytes kept free in UDP responses for the TSIG record added afterwards.
    pub(super) reserve: usize,
    /// Open resolver mode lowered `udp_limit` from this value: truncation
    /// the client's own limit would not have needed is counted separately.
    pub(super) open_cap_from: Option<usize>,
    /// The query had the DO bit (RFC 3225).
    pub(super) dnssec_ok: bool,
    /// Someone listens to the query feed (live view, query log), decided
    /// when the request arrived. Without a listener no query event is
    /// built: no answer summary, no name / type / rcode strings.
    pub(super) listening: bool,
    /// The filter that produced the answer (query event); empty before
    /// the query stage (TSIG errors).
    pub(super) filter: &'static str,
}

/// A request whose TSIG signature verified.
pub(super) struct SignedBy {
    pub(super) entry: Arc<KeyEntry>,
}

impl DnsServer {
    /// Admission: the first thing done for a request, before it is copied,
    /// given a task or decoded. Counts the query and asks the per-client rate
    /// limiter. `None`: admitted, go on with [`handle_admitted`]. `Some`:
    /// the reply to send instead (`Reply::None` = drop). Costs one counter
    /// lookup; a flood never reaches the parser.
    ///
    /// [`handle_admitted`]: DnsServer::handle_admitted
    pub fn admit(&self, req: &[u8], client: SocketAddr, proto: Proto) -> Option<Reply> {
        let ip = client.ip().to_canonical();
        self.stats.queries.fetch_add(1, Relaxed);
        match proto {
            Proto::Udp => self.stats.udp.fetch_add(1, Relaxed),
            Proto::Tcp => self.stats.tcp.fetch_add(1, Relaxed),
        };
        let d = match self.limiter.check(ip) {
            Decision::Allow => return None,
            d => d,
        };
        self.stats.rate_limited.fetch_add(1, Relaxed);
        if matches!(d, Decision::RejectFirst) {
            tracing::warn!(client = %ip, "rate limit exceeded; dropping queries for this window");
        }
        // UDP: drop silently (no amplification), except that every Nth
        // limited query ("slip") gets an empty truncated answer so a real
        // client whose address is being spoofed can retry over TCP. The slip
        // reply echoes header and question bytes; nothing is decoded.
        // TCP: the peer is real, say REFUSED.
        Some(match proto {
            Proto::Udp if d == Decision::Slip => {
                slip_reply(req).map(Reply::One).unwrap_or(Reply::None)
            }
            Proto::Udp => Reply::None,
            Proto::Tcp => req
                .get(..2)
                .map(|id| {
                    Reply::One(header_only(
                        u16::from_be_bytes([id[0], id[1]]),
                        ResponseCode::Refused,
                    ))
                })
                .unwrap_or(Reply::None),
        })
    }

    /// Handle one request: admission, then the answer.
    pub async fn handle(&self, req: &[u8], client: SocketAddr, proto: Proto) -> Reply {
        match self.admit(req, client, proto) {
            Some(reply) => reply,
            None => self.handle_admitted(req, client, proto).await,
        }
    }

    /// Handle a request that [`admit`](DnsServer::admit) let through.
    pub async fn handle_admitted(&self, req: &[u8], client: SocketAddr, proto: Proto) -> Reply {
        // Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d; use the plain IPv4 form
        // for ACLs, cookies, logs and the live feed.
        let client = SocketAddr::new(client.ip().to_canonical(), client.port());
        let started = Instant::now();
        let rt = self.runtime.load_full();

        if req.len() < 12 {
            self.stats.errors.fetch_add(1, Relaxed);
            return Reply::None;
        }
        let id = u16::from_be_bytes([req[0], req[1]]);
        // TSIG (RFC 8945): a signed request is verified before anything else
        // and never falls back to being treated as unsigned.
        match tsig::find(req) {
            Ok(None) => {
                self.query_stage(req, client, proto, started, &rt, None)
                    .await
            }
            Ok(Some(_)) if req[2] & 0x80 != 0 => Reply::None, // a response
            Ok(Some(signed)) => {
                self.answer_signed(req, signed, client, proto, started, &rt)
                    .await
            }
            Err(e) => {
                if req[2] & 0x80 != 0 {
                    return Reply::None;
                }
                self.stats.errors.fetch_add(1, Relaxed);
                self.stats.tsig_errors.fetch_add(1, Relaxed);
                tracing::debug!(client = %client, error = e.0, "malformed TSIG record");
                Reply::One(header_only(id, ResponseCode::FormErr))
            }
        }
    }

    /// Answer a query from this server itself (the DNSSEC pre-publication
    /// check): the same code path as a TCP query from 127.0.0.1, without
    /// the client rate limit. Shows in the live feed like any query.
    pub async fn answer_internal(&self, req: &[u8]) -> Option<Vec<u8>> {
        let rt = self.runtime.load_full();
        let client = SocketAddr::from(([127, 0, 0, 1], 0));
        match self
            .query_stage(req, client, Proto::Tcp, Instant::now(), &rt, None)
            .await
        {
            Reply::One(b) => Some(b),
            _ => None,
        }
    }

    /// Verify a signed request, answer it, and sign the answer (every
    /// message of a multi-message transfer, chained per RFC 8945 §5.3.1).
    async fn answer_signed(
        &self,
        req: &[u8],
        signed: Signed,
        client: SocketAddr,
        proto: Proto,
        started: Instant,
        rt: &Runtime,
    ) -> Reply {
        let id = u16::from_be_bytes([req[0], req[1]]);
        let ring = self.tsig_keys.load_full();
        let entry = ring.get(&signed.tsig.key_name).cloned();
        let now = tsig::now();
        if let Err(e) = tsig::verify(
            req,
            &signed,
            entry.as_ref().map(|e| &e.key),
            Chain::Request,
            now,
        ) {
            self.stats.tsig_errors.fetch_add(1, Relaxed);
            tracing::warn!(client = %client.ip(), key = %signed.tsig.key_name, algorithm = %signed.tsig.algorithm_name, error = e.as_str(), "rejected TSIG-signed request");
            if let VerifyError::FormErr(_) = e {
                self.stats.errors.fetch_add(1, Relaxed);
                return Reply::One(header_only(id, ResponseCode::FormErr));
            }
            let ctx = Ctx {
                client,
                proto,
                started,
                udp_limit: 65535,
                reserve: 0,
                open_cap_from: None,
                dnssec_ok: false,
                listening: self.bus.has_query_subscribers(),
                filter: "",
            };
            return Reply::One(self.tsig_error_reply(
                req,
                &signed,
                &e,
                entry.as_deref(),
                now,
                &ctx,
            ));
        }
        let Some(entry) = entry else {
            return Reply::None; // verify() returns BADKEY without a key
        };
        let stripped = tsig::strip(req, &signed);
        let by = SignedBy {
            entry: entry.clone(),
        };
        let reply = self
            .query_stage(&stripped, client, proto, started, rt, Some(&by))
            .await;
        let p = SignParams {
            time: now,
            fudge: tsig::MAX_FUDGE,
            original_id: signed.tsig.original_id,
            error: 0,
            other: Vec::new(),
        };
        let sign_one = |m: &[u8], chain: Chain| -> (Vec<u8>, Vec<u8>) {
            if m.len() < 12 {
                return (m.to_vec(), Vec::new());
            }
            tsig::sign(m, &entry.key, chain, &p)
        };
        match reply {
            Reply::None => Reply::None,
            Reply::One(m) => Reply::One(sign_one(&m, Chain::Response(&signed.tsig.mac)).0),
            Reply::Many(ms) => {
                let mut prior = signed.tsig.mac.clone();
                let mut out = Vec::with_capacity(ms.len());
                for (i, m) in ms.iter().enumerate() {
                    let chain = if i == 0 {
                        Chain::Response(&prior)
                    } else {
                        Chain::Continuation(&prior)
                    };
                    let (signed_msg, mac) = sign_one(m, chain);
                    prior = mac;
                    out.push(signed_msg);
                }
                Reply::Many(out)
            }
        }
    }

    /// NOTAUTH with the TSIG error (RFC 8945 §5.2, §5.3.2): unsigned for an
    /// unknown key or a bad MAC, signed for BADTIME (with our clock in Other
    /// Data) and BADTRUNC.
    fn tsig_error_reply(
        &self,
        req: &[u8],
        signed: &Signed,
        err: &VerifyError,
        entry: Option<&KeyEntry>,
        now: u64,
        ctx: &Ctx,
    ) -> Vec<u8> {
        let t = &signed.tsig;
        let stripped = tsig::strip(req, signed);
        let mut resp = Message::error_msg(
            u16::from_be_bytes([req[0], req[1]]),
            OpCode::Query,
            ResponseCode::NotAuth,
        );
        if let Ok(m) = Message::from_bytes(&stripped) {
            resp.metadata.op_code = m.metadata.op_code;
            for q in &m.queries {
                resp.add_query(q.clone());
            }
        }
        let bytes = self.finish(resp, ctx, "refused");
        let p = SignParams {
            time: t.time_signed,
            fudge: t.fudge,
            original_id: t.original_id,
            error: err.code(),
            other: if *err == VerifyError::BadTime {
                tsig::time48(now).to_vec()
            } else {
                Vec::new()
            },
        };
        match entry {
            Some(e) if err.signed_reply() && bytes.len() >= 12 => {
                tsig::sign(&bytes, &e.key, Chain::Response(&t.mac), &p).0
            }
            _ if bytes.len() >= 12 => tsig::unsigned(&bytes, &t.key_name, &t.algorithm_name, &p),
            _ => bytes,
        }
    }

    /// Encode, truncate for UDP if needed, and emit the query event.
    pub(super) fn finish(&self, resp: Message, ctx: &Ctx, source: &'static str) -> Vec<u8> {
        let (qname, qtype) = resp
            .queries
            .first()
            .map(|q| (q.name().clone(), q.query_type()))
            .unwrap_or_else(|| (Name::root(), RecordType::ANY));
        let mut bytes = match resp.to_vec() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to encode response");
                header_only(resp.metadata.id, ResponseCode::ServFail)
            }
        };
        let mut result = if ctx.listening {
            summarize(&resp, &qname)
        } else {
            Vec::new()
        };
        let limit = ctx.udp_limit.saturating_sub(ctx.reserve);
        // A DO answer (RRSIGs make it larger) first loses its additional
        // section, which needs no TC (RFC 2181 §9); only if the answer and
        // authority sections still do not fit is it truncated.
        if ctx.proto == Proto::Udp
            && bytes.len() > limit
            && ctx.dnssec_ok
            && !resp.additionals.is_empty()
        {
            let mut trimmed = resp.clone();
            trimmed.additionals.clear();
            if let Ok(b) = trimmed.to_vec() {
                if b.len() <= limit {
                    bytes = b;
                }
            }
        }
        if ctx.proto == Proto::Udp && bytes.len() > limit {
            self.stats.truncated.fetch_add(1, Relaxed);
            let t = resp.truncate();
            bytes = t
                .to_vec()
                .unwrap_or_else(|_| header_only(resp.metadata.id, ResponseCode::ServFail));
            let full = resp.to_vec().map(|v| v.len()).unwrap_or(0);
            result.push(self.truncation_note(ctx, full, limit));
        }
        self.emit(
            ctx,
            &qname,
            qtype,
            resp.metadata.response_code,
            resp.answers.len(),
            result,
            source,
        );
        bytes
    }

    /// Query-log note for a truncated UDP answer; counts the truncations
    /// only the open-resolver payload cap caused.
    pub(super) fn truncation_note(&self, ctx: &Ctx, full: usize, limit: usize) -> String {
        match ctx.open_cap_from {
            Some(orig) if full <= orig.saturating_sub(ctx.reserve) => {
                self.stats.open_resolver_truncated.fetch_add(1, Relaxed);
                format!("truncated for UDP ({full} bytes > {limit}, open resolver cap); client retries over TCP")
            }
            _ => format!("truncated for UDP ({full} bytes > {limit}); client retries over TCP"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit(
        &self,
        ctx: &Ctx,
        qname: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        answers: usize,
        result: Vec<String>,
        source: &'static str,
    ) {
        let us = ctx.started.elapsed().as_micros() as u64;
        self.stats.observe_latency(us);
        if !ctx.listening {
            return;
        }
        self.bus.publish_query(QueryEvent {
            ts: crate::model::now_rfc3339(),
            client: ctx.client.ip().to_string(),
            proto: ctx.proto.as_str(),
            name: qname.to_ascii(),
            qtype: qtype.to_string(),
            rcode: rcode.to_string(),
            answers,
            result,
            source,
            filter: ctx.filter,
            duration_us: us,
        });
    }
}

const RESULT_MAX_ITEMS: usize = 8;
const RESULT_MAX_CHARS: usize = 160;

/// Human-readable summary of a response for the live query feed and query log.
pub(super) fn summarize(m: &Message, qname: &Name) -> Vec<String> {
    let qkey = crate::zones::key_of(qname);
    let mut out = Vec::new();
    let fmt = |r: &Record| {
        let rtype = if r.record_type() == crate::zones::DNAME_TYPE {
            "DNAME".to_string()
        } else {
            r.record_type().to_string()
        };
        let data = match &r.data {
            RData::Unknown { code, rdata }
                if crate::dnssec::wire::display_rdata(u16::from(*code), &rdata.anything)
                    .is_some() =>
            {
                crate::dnssec::wire::display_rdata(u16::from(*code), &rdata.anything)
                    .unwrap_or_default()
            }
            RData::Unknown { code, rdata } if *code == crate::zones::DNAME_TYPE => {
                let mut dec = hickory_proto::serialize::binary::BinDecoder::new(&rdata.anything);
                Name::read(&mut dec)
                    .map(|n| n.to_ascii())
                    .unwrap_or_default()
            }
            // hickory prints SVCB/HTTPS parameters as "alpn=h2,h3, port=1," - normalise to zone-file form.
            d @ (RData::SVCB(_) | RData::HTTPS(_)) => d
                .to_string()
                .replace(", ", " ")
                .trim_end_matches(',')
                .to_string(),
            d => d.to_string(),
        };
        let owner = crate::zones::key_of(&r.name);
        let mut line = if owner == qkey {
            format!("{rtype} {data}")
        } else {
            format!("{} {rtype} {data}", r.name)
        };
        if line.len() > RESULT_MAX_CHARS {
            let mut cut = RESULT_MAX_CHARS;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
            line.push('…');
        }
        line
    };
    for r in m.answers.iter().take(RESULT_MAX_ITEMS) {
        out.push(fmt(r));
    }
    if m.answers.len() > RESULT_MAX_ITEMS {
        out.push(format!("… {} more", m.answers.len() - RESULT_MAX_ITEMS));
    }
    if m.answers.is_empty() && !m.metadata.authoritative {
        let ns: Vec<String> = m
            .authorities
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .map(|r| r.data.to_string())
            .collect();
        if !ns.is_empty() {
            out.push(format!(
                "referral to {} ({})",
                m.authorities[0].name,
                ns.join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::MessageType;

    #[test]
    fn summarize_formats_answers_referrals_and_svcb() {
        let q = Name::from_ascii("www.example.com.").unwrap();
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        m.metadata.authoritative = true;
        m.add_answer(Record::from_rdata(
            q.clone(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_ascii("web.example.com.").unwrap(),
            )),
        ));
        m.add_answer(Record::from_rdata(
            Name::from_ascii("web.example.com.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A("192.0.2.1".parse().unwrap())),
        ));
        m.add_answer(Record::from_rdata(
            q.clone(),
            60,
            RData::try_from_str(RecordType::HTTPS, "1 . alpn=h2,h3 ipv4hint=192.0.2.1").unwrap(),
        ));
        let out = summarize(&m, &q);
        assert_eq!(out[0], "CNAME web.example.com.");
        assert_eq!(
            out[1], "web.example.com. A 192.0.2.1",
            "owner shown when it differs from the query name"
        );
        assert_eq!(out[2], "HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1");

        let mut r = Message::new(0, MessageType::Response, OpCode::Query);
        r.add_authority(Record::from_rdata(
            Name::from_ascii("sub.example.com.").unwrap(),
            60,
            RData::NS(hickory_proto::rr::rdata::NS(
                Name::from_ascii("ns.sub.example.com.").unwrap(),
            )),
        ));
        assert_eq!(
            summarize(&r, &q),
            vec!["referral to sub.example.com. (ns.sub.example.com.)"]
        );

        let mut many = Message::new(0, MessageType::Response, OpCode::Query);
        for i in 0..12 {
            many.add_answer(Record::from_rdata(
                q.clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                    192, 0, 2, i,
                ))),
            ));
        }
        let out = summarize(&many, &q);
        assert_eq!(out.len(), RESULT_MAX_ITEMS + 1);
        assert_eq!(out.last().unwrap(), "… 4 more");
    }

    #[test]
    fn over_limit_packets_are_refused_at_admission_without_decoding() {
        use crate::ratelimit::RateLimiter;
        let cfg = crate::config::Config::default();
        let server = DnsServer::new(
            std::sync::Arc::new(crate::cache::Cache::new(crate::cache::Catalog::empty())),
            std::sync::Arc::new(crate::events::Bus::new(8, 8)),
            std::sync::Arc::new(RateLimiter::new(3, std::time::Duration::from_secs(60), 100)),
            &cfg,
        );
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        // Garbage that no parser accepts: admission never looks inside.
        let junk = [0xffu8; 40];
        for _ in 0..3 {
            assert!(
                server.admit(&junk, peer, Proto::Udp).is_none(),
                "under the limit"
            );
        }
        for _ in 0..50 {
            assert!(
                matches!(server.admit(&junk, peer, Proto::Udp), Some(Reply::None)),
                "over the limit: dropped at admission"
            );
        }
        assert_eq!(server.stats.rate_limited.load(Relaxed), 50);
        assert_eq!(server.stats.errors.load(Relaxed), 0, "nothing was decoded");
        // TCP peers are real: REFUSED with the query id echoed.
        match server.admit(&[0x12, 0x34, 0, 0], peer, Proto::Tcp) {
            Some(Reply::One(m)) => assert_eq!(&m[..2], &[0x12, 0x34]),
            _ => panic!("expected REFUSED"),
        }
        // Another client is unaffected.
        assert!(server
            .admit(&junk, "192.0.2.10:5000".parse().unwrap(), Proto::Udp)
            .is_none());
    }
}
