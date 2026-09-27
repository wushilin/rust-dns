//! Turns a raw DNS request into a reply.

use super::{DnsServer, Proto, Reply};
use crate::model::QueryEvent;
use crate::ratelimit::Decision;
use crate::zones::{lookup, Lookup};
use hickory_proto::op::{Edns, Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

pub const VERSION_STRING: &str = concat!("rust-dns ", env!("CARGO_PKG_VERSION"));

/// Minimal header-only response for requests we cannot parse.
fn header_only(id: u16, rcode: ResponseCode) -> Vec<u8> {
    let mut h = Header::new();
    h.set_id(id)
        .set_message_type(MessageType::Response)
        .set_response_code(rcode);
    let mut m = Message::new();
    m.set_header(h);
    m.to_vec().unwrap_or_default()
}

/// Per-request context threaded through the handler.
struct Ctx {
    client: SocketAddr,
    proto: Proto,
    started: Instant,
    udp_limit: usize,
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
                // UDP: drop silently (no amplification). TCP: the peer is real, say REFUSED.
                return match proto {
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
        let request = match Message::from_bytes(req) {
            Ok(m) => m,
            Err(e) => {
                self.stats.errors.fetch_add(1, Relaxed);
                tracing::debug!(client = %client, error = %e, "malformed query");
                return Reply::One(header_only(id, ResponseCode::FormErr));
            }
        };
        if request.message_type() != MessageType::Query {
            return Reply::None;
        }
        let mut ctx = Ctx {
            client,
            proto,
            started,
            udp_limit: 512,
        };

        let mut resp = Message::new();
        resp.set_id(id)
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code());
        if request.op_code() == OpCode::Query {
            resp.set_recursion_desired(request.recursion_desired())
                .set_recursion_available(rt.may_forward(client.ip()));
            for q in request.queries() {
                resp.add_query(q.clone());
            }
        }

        // EDNS (RFC 6891): echo an OPT with our payload size, NSID and cookies.
        let mut cookie_valid = false;
        if let Some(edns) = request.extensions() {
            let mut ours = Edns::new();
            ours.set_max_payload(rt.udp_max_payload)
                .set_version(0)
                .set_dnssec_ok(false);
            ctx.udp_limit = (edns.max_payload() as usize).clamp(512, rt.udp_max_payload as usize);
            if edns.version() != 0 {
                resp.set_edns(ours);
                resp.set_response_code(ResponseCode::BADVERS);
                return Reply::One(self.finish(resp, &ctx, "error"));
            }
            if !rt.nsid.is_empty() && edns.options().get(EdnsCode::NSID).is_some() {
                ours.options_mut()
                    .insert(EdnsOption::Unknown(3, rt.nsid.as_bytes().to_vec()));
            }
            if rt.cookies {
                if let Some(EdnsOption::Unknown(_, data)) = edns.options().get(EdnsCode::Cookie) {
                    use super::cookies::CookieCheck;
                    match self.cookies.check(data, client.ip()) {
                        CookieCheck::Malformed => {
                            resp.set_edns(ours);
                            resp.set_response_code(ResponseCode::FormErr);
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
                                resp.set_response_code(ResponseCode::BADCOOKIE);
                                return Reply::One(self.finish(resp, &ctx, "error"));
                            }
                        }
                    }
                }
            }
            resp.set_edns(ours);
        }
        let _ = cookie_valid;

        if request.op_code() != OpCode::Query {
            resp.set_response_code(ResponseCode::NotImp);
            return Reply::One(self.finish(resp, &ctx, "error"));
        }
        if request.queries().len() != 1 {
            resp.set_response_code(ResponseCode::FormErr);
            return Reply::One(self.finish(resp, &ctx, "error"));
        }
        let q = &request.queries()[0];
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
                r.set_dns_class(DNSClass::CH);
                resp.add_answer(r);
                resp.set_authoritative(true);
            } else {
                resp.set_response_code(ResponseCode::Refused);
            }
            return Reply::One(self.finish(resp, &ctx, "auth"));
        }
        if q.query_class() != DNSClass::IN && q.query_class() != DNSClass::ANY {
            self.stats.refused.fetch_add(1, Relaxed);
            resp.set_response_code(ResponseCode::Refused);
            return Reply::One(self.finish(resp, &ctx, "refused"));
        }

        let catalog = self.cache.load();

        // Zone transfers (RFC 5936 / 1995) for allowed secondaries.
        if super::axfr::is_transfer(qtype) {
            let key = crate::zones::key_of(&qname);
            let zone = catalog.zones.get(&key);
            if zone.is_none() || !rt.may_transfer(client.ip()) {
                self.stats.refused.fetch_add(1, Relaxed);
                resp.set_response_code(ResponseCode::Refused);
                return Reply::One(self.finish(resp, &ctx, "refused"));
            }
            let z = zone.unwrap();
            self.stats.transfers.fetch_add(1, Relaxed);
            tracing::info!(client = %client.ip(), zone = %z.zone.name, qtype = %qtype, proto = proto.as_str(), "zone transfer");
            self.emit(
                &ctx,
                &qname,
                qtype,
                ResponseCode::NoError,
                0,
                vec![format!("zone transfer of {}", z.zone.name)],
                "transfer",
            );
            return match proto {
                Proto::Tcp => Reply::Many(super::axfr::build(z, id, q)),
                Proto::Udp if qtype == RecordType::IXFR => super::axfr::soa_only(z, id, q)
                    .map(Reply::One)
                    .unwrap_or(Reply::None),
                Proto::Udp => {
                    resp.set_response_code(ResponseCode::Refused);
                    Reply::One(self.finish(resp, &ctx, "refused"))
                }
            };
        }
        if qtype == RecordType::OPT {
            resp.set_response_code(ResponseCode::FormErr);
            return Reply::One(self.finish(resp, &ctx, "error"));
        }

        // RFC 8482: answer ANY with a synthesized HINFO instead of everything.
        if qtype == RecordType::ANY && rt.minimal_any {
            let key = crate::zones::key_of(&qname);
            if let Some(z) = catalog.find_zone(&key) {
                self.stats.authoritative.fetch_add(1, Relaxed);
                resp.set_authoritative(true);
                if z.existing.contains(&key) || z.records_at(&key).is_some() {
                    let hinfo =
                        hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
                    resp.add_answer(Record::from_rdata(qname.clone(), 3789, RData::HINFO(hinfo)));
                } else if let Lookup::Answer(a) =
                    lookup(&catalog, &qname, RecordType::A, rt.auto_ptr)
                {
                    resp.set_response_code(a.rcode);
                    resp.insert_name_servers(a.authority);
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
                resp.set_authoritative(a.authoritative);
                resp.set_response_code(a.rcode);
                resp.insert_answers(a.answers);
                resp.insert_name_servers(a.authority);
                resp.insert_additionals(a.additional);
                Reply::One(self.finish(resp, &ctx, "auth"))
            }
            Lookup::NotOurs => {
                if !rt.may_forward(client.ip()) || !request.recursion_desired() {
                    self.stats.refused.fetch_add(1, Relaxed);
                    resp.set_response_code(ResponseCode::Refused);
                    return Reply::One(self.finish(resp, &ctx, "refused"));
                }
                let dnssec_ok = request
                    .extensions()
                    .as_ref()
                    .map(|e| e.flags().dnssec_ok)
                    .unwrap_or(false);
                let key = super::fwdcache::Key::new(&qname, qtype, q.query_class(), dnssec_ok);
                if rt.forwarding.cache_entries > 0 {
                    if let Some(mut cached) = self.fwd_cache.get(&key) {
                        self.stats.cache_hits.fetch_add(1, Relaxed);
                        cached.set_id(id);
                        cached.set_recursion_desired(request.recursion_desired());
                        cached.set_recursion_available(true);
                        *cached.queries_mut() = request.queries().to_vec();
                        match resp.extensions().clone() {
                            Some(e) => {
                                cached.set_edns(e);
                            }
                            None => {
                                *cached.extensions_mut() = None;
                            }
                        }
                        return Reply::One(self.finish(cached, &ctx, "cache"));
                    }
                }
                match super::forward::forward(&rt.forwarding, req, proto).await {
                    Ok(bytes) => {
                        self.stats.forwarded.fetch_add(1, Relaxed);
                        let (rcode, answers, result) = match Message::from_bytes(&bytes) {
                            Ok(m) => {
                                if rt.forwarding.cache_entries > 0
                                    && !m.truncated()
                                    && matches!(
                                        m.response_code(),
                                        ResponseCode::NoError | ResponseCode::NXDomain
                                    )
                                {
                                    self.fwd_cache.store(key, &m);
                                }
                                (m.response_code(), m.answers().len(), summarize(&m, &qname))
                            }
                            Err(_) => (
                                ResponseCode::ServFail,
                                0,
                                vec!["unparseable upstream reply".into()],
                            ),
                        };
                        self.emit(&ctx, &qname, qtype, rcode, answers, result, "forward");
                        Reply::One(bytes)
                    }
                    Err(e) => {
                        self.stats.errors.fetch_add(1, Relaxed);
                        tracing::warn!(name = %qname, error = %e, "forwarding failed");
                        resp.set_response_code(ResponseCode::ServFail);
                        Reply::One(self.finish(resp, &ctx, "error"))
                    }
                }
            }
        }
    }

    /// Encode, truncate for UDP if needed, and emit the query event.
    fn finish(&self, resp: Message, ctx: &Ctx, source: &'static str) -> Vec<u8> {
        let (qname, qtype) = resp
            .queries()
            .first()
            .map(|q| (q.name().clone(), q.query_type()))
            .unwrap_or_else(|| (Name::root(), RecordType::ANY));
        let mut bytes = match resp.to_vec() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to encode response");
                header_only(resp.id(), ResponseCode::ServFail)
            }
        };
        let mut result = summarize(&resp, &qname);
        if ctx.proto == Proto::Udp && bytes.len() > ctx.udp_limit {
            self.stats.truncated.fetch_add(1, Relaxed);
            let t = resp.truncate();
            bytes = t
                .to_vec()
                .unwrap_or_else(|_| header_only(resp.id(), ResponseCode::ServFail));
            result.push(format!(
                "truncated for UDP ({} bytes > {}); client retries over TCP",
                resp.to_vec().map(|v| v.len()).unwrap_or(0),
                ctx.udp_limit
            ));
        }
        self.emit(
            ctx,
            &qname,
            qtype,
            resp.response_code(),
            resp.answers().len(),
            result,
            source,
        );
        bytes
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
        let data = match r.data() {
            RData::Unknown { code, rdata } if *code == crate::zones::DNAME_TYPE => {
                let mut dec = hickory_proto::serialize::binary::BinDecoder::new(rdata.anything());
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
        let owner = crate::zones::key_of(r.name());
        let mut line = if owner == qkey {
            format!("{rtype} {data}")
        } else {
            format!("{} {rtype} {data}", r.name())
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
    for r in m.answers().iter().take(RESULT_MAX_ITEMS) {
        out.push(fmt(r));
    }
    if m.answers().len() > RESULT_MAX_ITEMS {
        out.push(format!("… {} more", m.answers().len() - RESULT_MAX_ITEMS));
    }
    if m.answers().is_empty() && !m.authoritative() {
        let ns: Vec<String> = m
            .name_servers()
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .map(|r| r.data().to_string())
            .collect();
        if !ns.is_empty() {
            out.push(format!(
                "referral to {} ({})",
                m.name_servers()[0].name(),
                ns.join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::serialize::txt::RDataParser;

    #[test]
    fn summarize_formats_answers_referrals_and_svcb() {
        let q = Name::from_ascii("www.example.com.").unwrap();
        let mut m = Message::new();
        m.set_authoritative(true);
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

        let mut r = Message::new();
        r.add_name_server(Record::from_rdata(
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

        let mut many = Message::new();
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
