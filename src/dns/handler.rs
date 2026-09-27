//! Turns a raw DNS request into a reply.

use super::keyring::KeyEntry;
use super::tsig::{self, Chain, SignParams, Signed, VerifyError};
use super::Runtime;
use super::{DnsServer, Proto, Reply};
use crate::model::QueryEvent;
use crate::ratelimit::Decision;
use crate::zones::{lookup, Lookup};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Instant;

pub const VERSION_STRING: &str = concat!("rust-dns ", env!("CARGO_PKG_VERSION"));

/// Minimal header-only response for requests we cannot parse.
fn header_only(id: u16, rcode: ResponseCode) -> Vec<u8> {
    Message::error_msg(id, OpCode::Query, rcode)
        .to_vec()
        .unwrap_or_default()
}

/// Rate-limit "slip" answer: the request's header and question with QR and
/// TC set and nothing else. Never larger than the request, so it cannot be
/// used for amplification, and it tells a genuine client to retry over TCP.
fn slip_reply(req: &[u8]) -> Option<Vec<u8>> {
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

/// Per-request context threaded through the handler.
struct Ctx {
    client: SocketAddr,
    proto: Proto,
    started: Instant,
    udp_limit: usize,
    /// Bytes kept free in UDP responses for the TSIG record added afterwards.
    reserve: usize,
    /// Open resolver mode lowered `udp_limit` from this value: truncation
    /// the client's own limit would not have needed is counted separately.
    open_cap_from: Option<usize>,
}

/// A request whose TSIG signature verified.
struct SignedBy {
    entry: Arc<KeyEntry>,
}

impl DnsServer {
    /// Handle one request.
    pub async fn handle(&self, req: &[u8], client: SocketAddr, proto: Proto) -> Reply {
        // Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d; use the plain IPv4 form
        // for rate limiting, ACLs, cookies, logs and the live feed.
        let client = SocketAddr::new(client.ip().to_canonical(), client.port());
        let started = Instant::now();
        self.stats.queries.fetch_add(1, Relaxed);
        match proto {
            Proto::Udp => self.stats.udp.fetch_add(1, Relaxed),
            Proto::Tcp => self.stats.tcp.fetch_add(1, Relaxed),
        };
        let rt = self.runtime.load_full();

        // Rate limit before parsing anything.
        match self.limiter.check(client.ip()) {
            Decision::Allow => {}
            d => {
                self.stats.rate_limited.fetch_add(1, Relaxed);
                if matches!(d, Decision::RejectFirst) {
                    tracing::warn!(client = %client.ip(), "rate limit exceeded; dropping queries for this window");
                }
                // UDP: drop silently (no amplification), except that every
                // Nth limited query ("slip") gets an empty truncated answer so
                // a real client whose address is being spoofed can retry over
                // TCP. TCP: the peer is real, say REFUSED.
                return match proto {
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
                };
            }
        }

        if req.len() < 12 {
            self.stats.errors.fetch_add(1, Relaxed);
            return Reply::None;
        }
        let id = u16::from_be_bytes([req[0], req[1]]);
        // TSIG (RFC 8945): a signed request is verified before anything else
        // and never falls back to being treated as unsigned.
        match tsig::find(req) {
            Ok(None) => self.answer(req, client, proto, started, &rt, None).await,
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
            .answer(&stripped, client, proto, started, rt, Some(&by))
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

    /// Answer a request (unsigned, or with its verified TSIG record removed).
    async fn answer(
        &self,
        req: &[u8],
        client: SocketAddr,
        proto: Proto,
        started: Instant,
        rt: &Runtime,
        signed_by: Option<&SignedBy>,
    ) -> Reply {
        let id = u16::from_be_bytes([req[0], req[1]]);
        let request = match Message::from_bytes(req) {
            Ok(m) => m,
            Err(e) => {
                self.stats.errors.fetch_add(1, Relaxed);
                tracing::debug!(client = %client, error = %e, "malformed query");
                return Reply::One(header_only(id, ResponseCode::FormErr));
            }
        };
        if request.metadata.message_type != MessageType::Query {
            return Reply::None;
        }
        let mut ctx = Ctx {
            client,
            proto,
            started,
            udp_limit: 512,
            reserve: signed_by
                .map(|b| tsig::record_len(&b.entry.key.name, b.entry.key.algorithm, 0))
                .unwrap_or(0),
            open_cap_from: None,
        };

        let mut resp = Message::response(id, request.metadata.op_code);
        if request.metadata.op_code == OpCode::Query {
            resp.metadata.recursion_desired = request.metadata.recursion_desired;
            resp.metadata.recursion_available = rt.may_forward(client.ip());
            for q in &request.queries {
                resp.add_query(q.clone());
            }
        }

        // EDNS (RFC 6891): echo an OPT with our payload size, NSID and cookies.
        let mut cookie_valid = false;
        if let Some(edns) = &request.edns {
            let mut ours = Edns::new();
            ours.set_max_payload(rt.udp_max_payload)
                .set_version(0)
                .set_dnssec_ok(false);
            ctx.udp_limit = (edns.max_payload() as usize).clamp(512, rt.udp_max_payload as usize);
            if edns.version() != 0 {
                resp.set_edns(ours);
                resp.metadata.response_code = ResponseCode::BADVERS;
                return Reply::One(self.finish(resp, &ctx, "error"));
            }
            if !rt.nsid.is_empty() && edns.options().get(EdnsCode::NSID).is_some() {
                ours.options_mut()
                    .insert(EdnsOption::Unknown(3, rt.nsid.as_bytes().to_vec()));
            }
            if rt.cookies {
                if let Some(EdnsOption::Unknown(_, data)) = edns.options().get(EdnsCode::Cookie) {
                    use super::cookies::CookieCheck;
                    match self.cookies.check(data.as_slice(), client.ip()) {
                        CookieCheck::Malformed => {
                            resp.set_edns(ours);
                            resp.metadata.response_code = ResponseCode::FormErr;
                            return Reply::One(self.finish(resp, &ctx, "error"));
                        }
                        CookieCheck::Valid(c) => {
                            cookie_valid = true;
                            ours.options_mut().insert(EdnsOption::Unknown(10, c));
                        }
                        CookieCheck::Invalid(c) => {
                            ours.options_mut().insert(EdnsOption::Unknown(10, c));
                            if rt.cookies_required && proto == Proto::Udp {
                                self.stats.bad_cookie.fetch_add(1, Relaxed);
                                resp.set_edns(ours);
                                resp.metadata.response_code = ResponseCode::BADCOOKIE;
                                return Reply::One(self.finish(resp, &ctx, "error"));
                            }
                        }
                    }
                }
            }
            resp.set_edns(ours);
        }
        let _ = cookie_valid;

        if request.metadata.op_code != OpCode::Query {
            resp.metadata.response_code = ResponseCode::NotImp;
            return Reply::One(self.finish(resp, &ctx, "error"));
        }
        if request.queries.len() != 1 {
            resp.metadata.response_code = ResponseCode::FormErr;
            return Reply::One(self.finish(resp, &ctx, "error"));
        }
        let q = &request.queries[0];
        let qname = q.name().clone();
        let qtype = q.query_type();

        // CHAOS class: only version.bind is answered.
        if q.query_class() == DNSClass::CH {
            let lname = qname.to_ascii().to_ascii_lowercase();
            if (qtype == RecordType::TXT || qtype == RecordType::ANY)
                && (lname == "version.bind." || lname == "version.server.")
            {
                let mut r = Record::from_rdata(
                    qname.clone(),
                    0,
                    RData::TXT(TXT::new(vec![VERSION_STRING.to_string()])),
                );
                r.dns_class = DNSClass::CH;
                resp.add_answer(r);
                resp.metadata.authoritative = true;
            } else {
                resp.metadata.response_code = ResponseCode::Refused;
            }
            return Reply::One(self.finish(resp, &ctx, "auth"));
        }
        if q.query_class() != DNSClass::IN && q.query_class() != DNSClass::ANY {
            self.stats.refused.fetch_add(1, Relaxed);
            resp.metadata.response_code = ResponseCode::Refused;
            return Reply::One(self.finish(resp, &ctx, "refused"));
        }

        let catalog = self.cache.load();

        // Zone transfers (RFC 5936 / 1995) for allowed secondaries.
        // Policy: the client address must be in [transfer].allow AND, when
        // signed, the key must cover the zone; unsigned requests are refused
        // when [transfer].require_tsig is on.
        if super::axfr::is_transfer(qtype) {
            let key = crate::zones::key_of(&qname);
            let zone = catalog.zones.get(&key);
            let key_name = signed_by.map(|b| b.entry.key.name.as_str());
            let refusal = match zone {
                None => Some((false, "not a zone on this server")),
                Some(_) if !rt.may_transfer(client.ip()) => {
                    Some((false, "client address is not in [transfer].allow"))
                }
                Some(z) => match signed_by {
                    Some(b) if !b.entry.allows_zone(&z.zone.name) => {
                        Some((true, "the TSIG key is not allowed to transfer this zone"))
                    }
                    None if rt.require_tsig => {
                        Some((true, "unsigned request and [transfer].require_tsig is on"))
                    }
                    _ => None,
                },
            };
            if let Some((notable, why)) = refusal {
                if notable {
                    tracing::info!(client = %client.ip(), zone = %qname, key = ?key_name, why, "zone transfer refused");
                } else {
                    tracing::debug!(client = %client.ip(), zone = %qname, key = ?key_name, why, "zone transfer refused");
                }
                self.stats.refused.fetch_add(1, Relaxed);
                resp.metadata.response_code = ResponseCode::Refused;
                return Reply::One(self.finish(resp, &ctx, "refused"));
            }
            let z = zone.expect("refused above when missing");
            self.stats.transfers.fetch_add(1, Relaxed);
            tracing::info!(client = %client.ip(), zone = %z.zone.name, qtype = %qtype, proto = proto.as_str(), key = ?key_name, "zone transfer");
            self.emit(
                &ctx,
                &qname,
                qtype,
                ResponseCode::NoError,
                0,
                vec![match key_name {
                    Some(k) => format!("zone transfer of {} (TSIG {k})", z.zone.name),
                    None => format!("zone transfer of {}", z.zone.name),
                }],
                "transfer",
            );
            return match proto {
                Proto::Tcp => Reply::Many(super::axfr::build(z, id, q)),
                Proto::Udp if qtype == RecordType::IXFR => super::axfr::soa_only(z, id, q)
                    .map(Reply::One)
                    .unwrap_or(Reply::None),
                Proto::Udp => {
                    resp.metadata.response_code = ResponseCode::Refused;
                    Reply::One(self.finish(resp, &ctx, "refused"))
                }
            };
        }
        if qtype == RecordType::OPT {
            resp.metadata.response_code = ResponseCode::FormErr;
            return Reply::One(self.finish(resp, &ctx, "error"));
        }

        // RFC 8482: answer ANY with a synthesized HINFO instead of everything.
        if qtype == RecordType::ANY && rt.minimal_any {
            let key = crate::zones::key_of(&qname);
            if let Some(z) = catalog.find_zone(&key) {
                self.stats.authoritative.fetch_add(1, Relaxed);
                resp.metadata.authoritative = true;
                if z.existing.contains(&key) || z.records_at(&key).is_some() {
                    let hinfo =
                        hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
                    resp.add_answer(Record::from_rdata(qname.clone(), 3789, RData::HINFO(hinfo)));
                } else if let Lookup::Answer(a) =
                    lookup(&catalog, &qname, RecordType::A, rt.auto_ptr)
                {
                    resp.metadata.response_code = a.rcode;
                    resp.insert_authorities(a.authority);
                }
                return Reply::One(self.finish(resp, &ctx, "auth"));
            }
        }

        match lookup(&catalog, &qname, qtype, rt.auto_ptr) {
            Lookup::Answer(a) => {
                self.stats.authoritative.fetch_add(1, Relaxed);
                if a.rcode == ResponseCode::NXDomain {
                    self.stats.nxdomain.fetch_add(1, Relaxed);
                }
                resp.metadata.authoritative = a.authoritative;
                resp.metadata.response_code = a.rcode;
                resp.insert_answers(a.answers);
                resp.insert_authorities(a.authority);
                resp.insert_additionals(a.additional);
                Reply::One(self.finish(resp, &ctx, "auth"))
            }
            Lookup::NotOurs => {
                if !rt.may_forward(client.ip()) || !request.metadata.recursion_desired {
                    self.stats.refused.fetch_add(1, Relaxed);
                    resp.metadata.response_code = ResponseCode::Refused;
                    return Reply::One(self.finish(resp, &ctx, "refused"));
                }
                if rt.open_resolver() {
                    if let Some(reply) = self.open_resolver_guard(req, &resp, &mut ctx, rt, qtype) {
                        return reply;
                    }
                }
                let dnssec_ok = request
                    .edns
                    .as_ref()
                    .map(|e| e.flags().dnssec_ok)
                    .unwrap_or(false);
                let key = super::fwdcache::Key::new(&qname, qtype, q.query_class(), dnssec_ok);
                if rt.forwarding.cache_entries > 0 {
                    if let Some(mut cached) = self.fwd_cache.get(&key, rt.cache_caps()) {
                        self.stats.cache_hits.fetch_add(1, Relaxed);
                        cached.metadata.id = id;
                        cached.metadata.recursion_desired = request.metadata.recursion_desired;
                        cached.metadata.recursion_available = true;
                        cached.queries = request.queries.clone();
                        cached.edns = resp.edns.clone();
                        return Reply::One(self.finish(cached, &ctx, "cache"));
                    }
                }
                match super::forward::forward(&rt.forwarding, req, proto).await {
                    Ok(bytes) => {
                        self.stats.forwarded.fetch_add(1, Relaxed);
                        let parsed = Message::from_bytes(&bytes);
                        let (rcode, answers, mut result) = match &parsed {
                            Ok(m) => {
                                if rt.forwarding.cache_entries > 0
                                    && !m.metadata.truncation
                                    && matches!(
                                        m.metadata.response_code,
                                        ResponseCode::NoError | ResponseCode::NXDomain
                                    )
                                {
                                    self.fwd_cache.store(key, m, rt.cache_caps());
                                }
                                (
                                    m.metadata.response_code,
                                    m.answers.len(),
                                    summarize(m, &qname),
                                )
                            }
                            Err(_) => (
                                ResponseCode::ServFail,
                                0,
                                vec!["unparseable upstream reply".into()],
                            ),
                        };
                        // A reply fetched over TCP (after an upstream TC) can
                        // exceed what this UDP client accepts: truncate it.
                        let limit = ctx.udp_limit.saturating_sub(ctx.reserve);
                        let bytes = match (&parsed, proto) {
                            (Ok(m), Proto::Udp) if bytes.len() > limit => {
                                self.stats.truncated.fetch_add(1, Relaxed);
                                result.push(self.truncation_note(&ctx, bytes.len(), limit));
                                m.truncate()
                                    .to_vec()
                                    .unwrap_or_else(|_| header_only(id, ResponseCode::ServFail))
                            }
                            (Err(_), Proto::Udp) if bytes.len() > limit => {
                                header_only(id, ResponseCode::ServFail)
                            }
                            _ => bytes,
                        };
                        self.emit(&ctx, &qname, qtype, rcode, answers, result, "forward");
                        Reply::One(bytes)
                    }
                    Err(e) => {
                        self.stats.errors.fetch_add(1, Relaxed);
                        tracing::warn!(name = %qname, error = %e, "forwarding failed");
                        resp.metadata.response_code = ResponseCode::ServFail;
                        Reply::One(self.finish(resp, &ctx, "error"))
                    }
                }
            }
        }
    }

    /// Encode, truncate for UDP if needed, and emit the query event.
    fn finish(&self, resp: Message, ctx: &Ctx, source: &'static str) -> Vec<u8> {
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
        let mut result = summarize(&resp, &qname);
        let limit = ctx.udp_limit.saturating_sub(ctx.reserve);
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
    fn truncation_note(&self, ctx: &Ctx, full: usize, limit: usize) -> String {
        match ctx.open_cap_from {
            Some(orig) if full <= orig.saturating_sub(ctx.reserve) => {
                self.stats.open_resolver_truncated.fetch_add(1, Relaxed);
                format!("truncated for UDP ({full} bytes > {limit}, open resolver cap); client retries over TCP")
            }
            _ => format!("truncated for UDP ({full} bytes > {limit}); client retries over TCP"),
        }
    }

    /// Open resolver safeguards for a query about to be forwarded: the
    /// per-client forwarding limit, no forwarded ANY (RFC 8482 minimal
    /// answer instead), and the UDP payload cap (lowers `ctx.udp_limit`).
    /// Returns the reply when the query must not be forwarded.
    fn open_resolver_guard(
        &self,
        req: &[u8],
        resp: &Message,
        ctx: &mut Ctx,
        rt: &Runtime,
        qtype: RecordType,
    ) -> Option<Reply> {
        match self.fwd_limiter.check(ctx.client.ip()) {
            Decision::Allow => {}
            d => {
                self.stats.open_resolver_rate_limited.fetch_add(1, Relaxed);
                if matches!(d, Decision::RejectFirst) {
                    tracing::warn!(client = %ctx.client.ip(), limit = rt.forwarding.open_resolver_rate_per_second, "open resolver: per-client forwarding limit exceeded; dropping forwarded queries for this window");
                }
                // As the global limiter: UDP drop (or slip), TCP REFUSED.
                return Some(match ctx.proto {
                    Proto::Udp if d == Decision::Slip => {
                        slip_reply(req).map(Reply::One).unwrap_or(Reply::None)
                    }
                    Proto::Udp => Reply::None,
                    Proto::Tcp => {
                        self.stats.refused.fetch_add(1, Relaxed);
                        let mut r = resp.clone();
                        r.metadata.response_code = ResponseCode::Refused;
                        Reply::One(self.finish(r, ctx, "refused"))
                    }
                });
            }
        }
        if qtype == RecordType::ANY {
            // RFC 8482 §4.2: a synthesized HINFO, as the authoritative
            // minimal-ANY path does; small, and never forwarded.
            self.stats.open_resolver_any.fetch_add(1, Relaxed);
            let q = resp.queries[0].name().clone();
            let mut r = resp.clone();
            let hinfo = hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
            r.add_answer(Record::from_rdata(q, 3789, RData::HINFO(hinfo)));
            return Some(Reply::One(self.finish(r, ctx, "forward")));
        }
        let cap = rt.forwarding.open_resolver_max_udp_payload as usize;
        if ctx.proto == Proto::Udp && cap < ctx.udp_limit {
            ctx.open_cap_from = Some(ctx.udp_limit);
            ctx.udp_limit = cap.max(512);
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
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
            duration_us: us,
        });
    }
}

const RESULT_MAX_ITEMS: usize = 8;
const RESULT_MAX_CHARS: usize = 160;

/// Human-readable summary of a response for the live query feed and query log.
fn summarize(m: &Message, qname: &Name) -> Vec<String> {
    let qkey = crate::zones::key_of(qname);
    let mut out = Vec::new();
    let fmt = |r: &Record| {
        let rtype = if r.record_type() == crate::zones::DNAME_TYPE {
            "DNAME".to_string()
        } else {
            r.record_type().to_string()
        };
        let data = match &r.data {
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
}
