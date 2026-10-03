//! The filters of the query chain (see [`super::pipeline`] for the order
//! and the contract). Each is a method on [`DnsServer`] that looks at the
//! [`QueryCtx`] and answers, drops or passes.

use super::handler::{slip_reply, InflightSlot, VERSION_STRING};
use super::pipeline::{QueryCtx, Response, Step};
use super::{DnsServer, Proto};
use crate::ratelimit::Decision;
use crate::zones::{lookup, lookup_dnssec, Lookup};
use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::sync::atomic::Ordering::Relaxed;

impl DnsServer {
    /// `edns`: echo an OPT record with our payload size, NSID and cookies
    /// (RFC 6891, 5001, 7873); BADVERS for EDNS versions other than 0,
    /// FORMERR for a malformed cookie, BADCOOKIE for a missing/invalid
    /// server cookie when cookies are required (UDP).
    pub(super) fn filter_edns(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        let Some(edns) = &q.request.edns else {
            return Step::Next;
        };
        let mut ours = Edns::new();
        // RFC 3225 §3: the DO bit of the query is copied into the response.
        ours.set_max_payload(rt.udp_max_payload)
            .set_version(0)
            .set_dnssec_ok(q.meta.dnssec_ok);
        q.meta.udp_limit = (edns.max_payload() as usize).clamp(512, rt.udp_max_payload as usize);
        if edns.version() != 0 {
            q.resp.set_edns(ours);
            return q.reply(ResponseCode::BADVERS, "error");
        }
        if !rt.nsid.is_empty() && edns.options().get(EdnsCode::NSID).is_some() {
            ours.options_mut()
                .insert(EdnsOption::Unknown(3, rt.nsid.as_bytes().to_vec()));
        }
        if rt.cookies {
            if let Some(EdnsOption::Unknown(_, data)) = edns.options().get(EdnsCode::Cookie) {
                use super::cookies::CookieCheck;
                match self.cookies.check(data.as_slice(), q.meta.client.ip()) {
                    CookieCheck::Malformed => {
                        q.resp.set_edns(ours);
                        return q.reply(ResponseCode::FormErr, "error");
                    }
                    CookieCheck::Valid(c) => {
                        ours.options_mut().insert(EdnsOption::Unknown(10, c));
                    }
                    CookieCheck::Invalid(c) => {
                        ours.options_mut().insert(EdnsOption::Unknown(10, c));
                        if rt.cookies_required && q.meta.proto == Proto::Udp {
                            self.stats.bad_cookie.fetch_add(1, Relaxed);
                            q.resp.set_edns(ours);
                            return q.reply(ResponseCode::BADCOOKIE, "error");
                        }
                    }
                }
            }
        }
        q.resp.set_edns(ours);
        Step::Next
    }

    /// `request`: only standard queries (NOTIMP otherwise) with exactly one
    /// question (FORMERR otherwise).
    pub(super) fn filter_request(&self, q: &mut QueryCtx<'_>) -> Step {
        if q.request.metadata.op_code != OpCode::Query {
            return q.reply(ResponseCode::NotImp, "error");
        }
        if q.request.queries.len() != 1 {
            return q.reply(ResponseCode::FormErr, "error");
        }
        Step::Next
    }

    /// `special`: the CHAOS class answers only `version.bind` /
    /// `version.server` TXT; classes other than IN and ANY are REFUSED.
    pub(super) fn filter_special(&self, q: &mut QueryCtx<'_>) -> Step {
        let question = q.question();
        let class = question.query_class();
        if class == DNSClass::CH {
            let qtype = question.query_type();
            let qname = question.name().clone();
            let lname = qname.to_ascii().to_ascii_lowercase();
            let mut resp = q.take_resp();
            if (qtype == RecordType::TXT || qtype == RecordType::ANY)
                && (lname == "version.bind." || lname == "version.server.")
            {
                let mut r = Record::from_rdata(
                    qname,
                    0,
                    RData::TXT(TXT::new(vec![VERSION_STRING.to_string()])),
                );
                r.dns_class = DNSClass::CH;
                resp.add_answer(r);
                resp.metadata.authoritative = true;
            } else {
                resp.metadata.response_code = ResponseCode::Refused;
            }
            return Step::Answer(Response::Message(resp, "auth"));
        }
        if class != DNSClass::IN && class != DNSClass::ANY {
            self.stats.refused.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::Refused, "refused");
        }
        Step::Next
    }

    /// `transfer`: zone transfers (RFC 5936 / 1995) for allowed
    /// secondaries, and FORMERR for the meta type OPT as a question.
    /// Policy: the client address must be in [transfer].allow AND, when
    /// signed, the key must cover the zone; unsigned requests are refused
    /// when [transfer].require_tsig is on.
    pub(super) fn filter_transfer(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        let question = q.question();
        let qtype = question.query_type();
        if !super::axfr::is_transfer(qtype) {
            if qtype == RecordType::OPT {
                return q.reply(ResponseCode::FormErr, "error");
            }
            return Step::Next;
        }
        let qname = question.name().clone();
        let client = q.meta.client;
        let catalog = self.cache.load();
        let key = crate::zones::key_of(&qname);
        let zone = catalog.zones.get(&key);
        let signed_by = q.signed_by;
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
            return q.reply(ResponseCode::Refused, "refused");
        }
        let z = zone.expect("refused above when missing");
        let proto = q.meta.proto;
        self.stats.transfers.fetch_add(1, Relaxed);
        tracing::info!(client = %client.ip(), zone = %z.zone.name, qtype = %qtype, proto = proto.as_str(), key = ?key_name, "zone transfer");
        q.meta.filter = "transfer";
        self.emit(
            &q.meta,
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
        let id = q.resp.metadata.id;
        let question = q.question();
        match proto {
            Proto::Tcp => Step::Answer(Response::Transfer(super::axfr::build(z, id, question))),
            Proto::Udp if qtype == RecordType::IXFR => match super::axfr::soa_only(z, id, question)
            {
                Some(b) => Step::Answer(Response::Bytes(b)),
                None => Step::Drop,
            },
            Proto::Udp => q.reply(ResponseCode::Refused, "refused"),
        }
    }

    /// `authoritative`: names in our own zones (and automatic PTR). RFC
    /// 8482 minimal ANY; RRSIGs and NSEC proofs for DO queries to signed
    /// zones. Passes names that are not ours.
    pub(super) fn filter_authoritative(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        let catalog = self.cache.load();
        let question = q.question();
        let qname = question.name().clone();
        let qtype = question.query_type();
        let dnssec_ok = q.meta.dnssec_ok;

        // RFC 8482: answer ANY with a synthesized HINFO instead of everything.
        if qtype == RecordType::ANY && rt.minimal_any {
            let key = crate::zones::key_of(&qname);
            if let Some(z) = catalog.find_zone(&key) {
                self.stats.authoritative.fetch_add(1, Relaxed);
                let mut resp = q.take_resp();
                if dnssec_ok && z.signed.is_some() {
                    // Signed zone, DO query: a synthesized HINFO could not be
                    // validated, so answer one real RRset with its RRSIG
                    // (RFC 8482 §4.1), or the signed negative answer.
                    if let Lookup::Answer(mut a) =
                        lookup_dnssec(&catalog, &qname, RecordType::ANY, rt.auto_ptr, true)
                    {
                        a.keep_first_rrset();
                        if a.rcode == ResponseCode::NXDomain {
                            self.stats.nxdomain.fetch_add(1, Relaxed);
                        }
                        resp.metadata.authoritative = a.authoritative;
                        resp.metadata.response_code = a.rcode;
                        resp.insert_answers(a.answers);
                        resp.insert_authorities(a.authority);
                        resp.insert_additionals(a.additional);
                        return Step::Answer(Response::Message(resp, "auth"));
                    }
                }
                resp.metadata.authoritative = true;
                if z.existing.contains(&key) || z.records_at(&key).is_some() {
                    let hinfo =
                        hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
                    resp.add_answer(Record::from_rdata(qname, 3789, RData::HINFO(hinfo)));
                } else if let Lookup::Answer(a) =
                    lookup(&catalog, &qname, RecordType::A, rt.auto_ptr)
                {
                    resp.metadata.response_code = a.rcode;
                    resp.insert_authorities(a.authority);
                }
                return Step::Answer(Response::Message(resp, "auth"));
            }
        }

        match lookup_dnssec(&catalog, &qname, qtype, rt.auto_ptr, dnssec_ok) {
            Lookup::Answer(a) => {
                self.stats.authoritative.fetch_add(1, Relaxed);
                if a.rcode == ResponseCode::NXDomain {
                    self.stats.nxdomain.fetch_add(1, Relaxed);
                }
                let mut resp = q.take_resp();
                resp.metadata.authoritative = a.authoritative;
                resp.metadata.response_code = a.rcode;
                resp.insert_answers(a.answers);
                resp.insert_authorities(a.authority);
                resp.insert_additionals(a.additional);
                Step::Answer(Response::Message(resp, "auth"))
            }
            Lookup::NotOurs => Step::Next,
        }
    }

    /// `recursion`: a name that is not ours is only resolved for clients in
    /// the forwarding ACL that asked for recursion (RD); REFUSED otherwise.
    pub(super) fn filter_recursion(&self, q: &mut QueryCtx<'_>) -> Step {
        if !q.rt.may_forward(q.meta.client.ip()) || !q.request.metadata.recursion_desired {
            self.stats.refused.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::Refused, "refused");
        }
        Step::Next
    }

    /// `open_resolver` (in the chain only while open resolver mode is in
    /// effect): the per-client forwarding limit, no forwarded ANY (RFC 8482
    /// minimal answer instead), and the UDP payload cap (lowers the UDP
    /// limit of the answer).
    pub(super) fn filter_open_resolver(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        match self.fwd_limiter.check(q.meta.client.ip()) {
            Decision::Allow => {}
            d => {
                self.stats.open_resolver_rate_limited.fetch_add(1, Relaxed);
                if matches!(d, Decision::RejectFirst) {
                    tracing::warn!(client = %q.meta.client.ip(), limit = rt.forwarding.open_resolver_rate_per_second, "open resolver: per-client forwarding limit exceeded; dropping forwarded queries for this window");
                }
                // As the global limiter: UDP drop (or slip), TCP REFUSED.
                return match q.meta.proto {
                    Proto::Udp if d == Decision::Slip => match slip_reply(q.req) {
                        Some(b) => Step::Answer(Response::Bytes(b)),
                        None => Step::Drop,
                    },
                    Proto::Udp => Step::Drop,
                    Proto::Tcp => {
                        self.stats.refused.fetch_add(1, Relaxed);
                        q.reply(ResponseCode::Refused, "refused")
                    }
                };
            }
        }
        if q.question().query_type() == RecordType::ANY {
            // RFC 8482 §4.2: a synthesized HINFO, as the authoritative
            // minimal-ANY path does; small, and never forwarded.
            self.stats.open_resolver_any.fetch_add(1, Relaxed);
            let name = q.question().name().clone();
            let mut r = q.take_resp();
            let hinfo = hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
            r.add_answer(Record::from_rdata(name, 3789, RData::HINFO(hinfo)));
            return Step::Answer(Response::Message(r, "forward"));
        }
        let cap = rt.forwarding.open_resolver_max_udp_payload as usize;
        if q.meta.proto == Proto::Udp && cap < q.meta.udp_limit {
            q.meta.open_cap_from = Some(q.meta.udp_limit);
            q.meta.udp_limit = cap.max(512);
        }
        Step::Next
    }

    /// `forward`: the forward cache, then an upstream. Bounded: a slow or
    /// dead upstream must not pile up tasks and sockets without limit. Only
    /// forwarding takes a slot (a cache hit does not), and a query over the
    /// cap is turned away at once rather than queued: UDP dropped (no
    /// amplification, the client retries), TCP SERVFAIL.
    pub(super) async fn filter_forward(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        let question = q.question();
        let qtype = question.query_type();
        let key = super::fwdcache::Key::new(
            question.name(),
            qtype,
            question.query_class(),
            q.meta.dnssec_ok,
        );
        if rt.forwarding.cache_entries > 0 {
            if let Some(mut cached) = self.fwd_cache.get(&key, rt.cache_caps()) {
                self.stats.cache_hits.fetch_add(1, Relaxed);
                cached.metadata.id = q.resp.metadata.id;
                cached.metadata.recursion_desired = q.request.metadata.recursion_desired;
                cached.metadata.recursion_available = true;
                cached.queries = q.request.queries.clone();
                cached.edns = q.resp.edns.clone();
                return Step::Answer(Response::Message(cached, "cache"));
            }
        }
        let Some(_slot) = InflightSlot::take(&self.stats, rt.forwarding.max_inflight) else {
            self.stats.forward_overflow.fetch_add(1, Relaxed);
            // One warning a minute, not one per query.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let last = self.stats.forward_overflow_warned.load(Relaxed);
            if now >= last + 60
                && self
                    .stats
                    .forward_overflow_warned
                    .compare_exchange(last, now, Relaxed, Relaxed)
                    .is_ok()
            {
                tracing::warn!(max_inflight = rt.forwarding.max_inflight, "forwarding: [forwarding].max_inflight queries are waiting for upstreams; further queries are dropped (UDP) or answered SERVFAIL (TCP) until some finish");
            }
            return match q.meta.proto {
                Proto::Udp => Step::Drop,
                Proto::Tcp => q.reply(ResponseCode::ServFail, "error"),
            };
        };
        match super::forward::forward(&rt.forwarding, q.req, q.meta.proto).await {
            Ok(bytes) => {
                self.stats.forwarded.fetch_add(1, Relaxed);
                let parsed = Message::from_bytes(&bytes).map_err(|_| ());
                if let Ok(m) = &parsed {
                    if rt.forwarding.cache_entries > 0
                        && !m.metadata.truncation
                        && matches!(
                            m.metadata.response_code,
                            ResponseCode::NoError | ResponseCode::NXDomain
                        )
                    {
                        self.fwd_cache.store(key, m, rt.cache_caps());
                    }
                }
                Step::Answer(Response::Relayed { bytes, parsed })
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Relaxed);
                tracing::warn!(name = %q.question().name(), error = %e, "forwarding failed");
                q.reply(ResponseCode::ServFail, "error")
            }
        }
    }
}
