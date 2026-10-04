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
        if q.request.metadata.op_code == OpCode::Notify {
            return self.notify_in(q);
        }
        if q.request.metadata.op_code != OpCode::Query {
            return q.reply(ResponseCode::NotImp, "error");
        }
        if q.request.queries.len() != 1 {
            return q.reply(ResponseCode::FormErr, "error");
        }
        Step::Next
    }

    /// O27: an inbound NOTIFY (RFC 1996) for a secondary zone: accepted
    /// when signed with the zone's TSIG key or sent from one of its
    /// primaries' addresses; the zone is refreshed at once; REFUSED from
    /// anyone else. A NOTIFY for any other name is answered NOTIMP, as
    /// before secondary zones existed (unchanged answers by default).
    fn notify_in(&self, q: &mut QueryCtx<'_>) -> Step {
        let Some(question) = q.request.queries.first().cloned() else {
            return q.reply(ResponseCode::FormErr, "error");
        };
        let fqdn = question.name().to_lowercase().to_ascii();
        let cat = self.cache.load();
        let found = cat
            .zones
            .get(&fqdn)
            .and_then(|z| Some((z.zone.name.clone(), z.zone.secondary.as_deref()?.clone())));
        let client = q.meta.client.ip();
        let Some((zone, spec)) = found else {
            return q.reply(ResponseCode::NotImp, "error");
        };
        let by_key = match (q.signed_by, &spec.key) {
            (Some(b), Some(k)) => b.entry.key.name.eq_ignore_ascii_case(k),
            _ => false,
        };
        let from_primary = spec.primaries.iter().any(|p| p.ip() == client);
        if !by_key && !from_primary {
            tracing::warn!(%client, zone = %zone, "NOTIFY from an address that is not a primary of the zone (and not signed with its key): refused");
            return q.reply(ResponseCode::Refused, "refused");
        }
        tracing::info!(%client, zone = %zone, signed = by_key, "NOTIFY accepted; refreshing the secondary zone");
        if let Some(st) = self.secondaries.get() {
            st.notified(&zone);
        }
        let mut m = q.take_resp();
        m.metadata.authoritative = true;
        m.add_query(question);
        Step::Answer(Response::Message(m, "authoritative"))
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
        // Override zones are never transferred (not authoritative).
        // O27: a secondary zone without usable data is not transferred on.
        let zone = catalog
            .zones
            .get(&key)
            .filter(|z| !z.zone.is_override() && !z.unavailable);
        let signed_by = q.signed_by;
        let key_name = signed_by.map(|b| b.entry.key.name.as_str());
        // O16: a zone's own transfer ACL and TSIG requirement replace the
        // server's ([transfer]) for that zone.
        let own = zone.and_then(|z| z.zone.settings.as_deref());
        let allowed = |z_allow: Option<&Vec<String>>| match z_allow {
            Some(list) => list
                .iter()
                .filter_map(|c| crate::config::Cidr::parse(c))
                .any(|c| c.contains(client.ip())),
            None => rt.may_transfer(client.ip()),
        };
        let require_tsig = own.and_then(|s| s.require_tsig).unwrap_or(rt.require_tsig);
        let refusal = match zone {
            None => Some((false, "not a zone on this server")),
            Some(_) if !allowed(own.and_then(|s| s.transfer_allow.as_ref())) => Some((
                false,
                if own.is_some_and(|s| s.transfer_allow.is_some()) {
                    "client address is not in the zone's transfer_allow"
                } else {
                    "client address is not in [transfer].allow"
                },
            )),
            Some(z) => match signed_by {
                Some(b) if !b.entry.allows_zone(&z.zone.name) => {
                    Some((true, "the TSIG key is not allowed to transfer this zone"))
                }
                None if require_tsig => Some((
                    true,
                    "unsigned request and TSIG is required ([transfer].require_tsig or the zone's require_tsig)",
                )),
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
            if let Some(z) = catalog.find_auth_zone(&key) {
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
            Lookup::Override(z) => {
                q.override_zone = Some(z);
                Step::Next
            }
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

    /// The forward cache, then the upstreams, for `forward` and for an
    /// override zone's upstreams. Bounded: a slow or dead upstream must not
    /// pile up tasks and sockets without limit. Only forwarding takes a
    /// slot (a cache hit does not), and a query over the cap is turned away
    /// at once rather than queued: UDP dropped (no amplification, the
    /// client retries), TCP SERVFAIL. `upstream_req`: the request as sent
    /// upstream when it differs from the client's (EDNS Client Subnet).
    async fn relay(&self, q: &mut QueryCtx<'_>, r: Relay<'_>) -> Step {
        let rt = q.rt;
        let question = q.question();
        let key = super::fwdcache::Key::new(
            question.name(),
            question.query_type(),
            question.query_class(),
            q.meta.dnssec_ok,
        )
        .scoped(r.scope);
        if rt.forwarding.cache_entries > 0 {
            let hit = self.fwd_cache.get(&key, rt.cache_caps()).or_else(|| {
                r.alt_scope
                    .and_then(|s| self.fwd_cache.get(&key.clone().scoped(s), rt.cache_caps()))
            });
            if let Some(mut cached) = hit {
                self.stats.cache_hits.fetch_add(1, Relaxed);
                cached.metadata.id = q.resp.metadata.id;
                cached.metadata.recursion_desired = q.request.metadata.recursion_desired;
                cached.metadata.recursion_available = true;
                if r.clear_ad {
                    cached.metadata.authentic_data = false;
                }
                cached.queries = q.request.queries.clone();
                cached.edns = q.resp.edns.clone();
                return Step::Answer(Response::Message(cached, r.cache_source));
            }
        }
        q.fwd_key = Some(key.clone());
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
        let sent = r.upstream_req.as_deref().unwrap_or(q.req);
        // O29: global forwarding goes to the encrypted upstreams when set.
        let encrypted = r.scope == 0 || r.alt_scope == Some(ECS_SHARED);
        let answer = if encrypted && !rt.encrypted_upstreams.is_empty() {
            match &self.enc_clients {
                Some(c) => {
                    super::encrypted::forward(
                        c,
                        &rt.encrypted_upstreams,
                        sent,
                        rt.forwarding.timeout_ms,
                    )
                    .await
                }
                None => Err(anyhow::anyhow!(
                    "encrypted upstreams unusable (see the startup log)"
                )),
            }
        } else {
            super::forward::forward_via(
                r.upstreams,
                rt.forwarding.timeout_ms,
                rt.resolver.strategy,
                Some(&self.upstream_health),
                sent,
                q.meta.proto,
            )
            .await
        };
        match answer {
            Ok(mut bytes) => {
                self.stats.forwarded.fetch_add(1, Relaxed);
                if r.clear_ad && bytes.len() > 3 {
                    bytes[3] &= !0x20; // AD
                }
                let parsed = Message::from_bytes(&bytes).map_err(|_| ());
                if r.upstream_req.is_some() {
                    // ECS: the reply is made for the client (its own EDNS
                    // record, our subnet option removed) and re-encoded.
                    let Ok(mut m) = parsed else {
                        return q.reply(ResponseCode::ServFail, "error");
                    };
                    let scope = ecs_scope(&m);
                    m.edns = q.resp.edns.clone();
                    m.metadata.id = q.resp.metadata.id;
                    let store_scope = match (scope, r.ecs_source_prefix) {
                        (Some(0), _) => r.alt_scope,
                        (Some(sc), Some(src)) if sc <= src => Some(r.scope),
                        (None, _) => r.alt_scope, // upstream ignored ECS
                        _ => None,                // finer than we asked: not cached
                    };
                    if let Some(sc) = store_scope {
                        self.cache_store(rt, key.scoped(sc), &m);
                    }
                    return Step::Answer(Response::Message(m, r.source));
                }
                if let Ok(m) = &parsed {
                    self.cache_store(rt, key, m);
                }
                Step::Answer(Response::Relayed {
                    bytes,
                    parsed,
                    source: r.source,
                })
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Relaxed);
                q.upstream_failed = true;
                tracing::warn!(name = %q.question().name(), error = %e, "forwarding failed");
                q.reply(ResponseCode::ServFail, "error")
            }
        }
    }

    fn cache_store(&self, rt: &super::Runtime, key: super::fwdcache::Key, m: &Message) {
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

    /// `forward`: the forward cache, then the global upstreams (strategy
    /// and health: I6), with EDNS Client Subnet when on (I10).
    pub(super) async fn filter_forward(&self, q: &mut QueryCtx<'_>) -> Step {
        let rt = q.rt;
        let ups = &rt.forwarding.upstreams;
        if let Some(e) = self.ecs_request(q) {
            return self
                .relay(
                    q,
                    Relay {
                        upstreams: ups,
                        scope: e.scope,
                        alt_scope: Some(ECS_SHARED),
                        upstream_req: Some(e.request),
                        ecs_source_prefix: Some(e.source_prefix),
                        ..Relay::global(ups)
                    },
                )
                .await;
        }
        self.relay(q, Relay::global(ups)).await
    }

    /// The upstream request with an EDNS Client Subnet option for this
    /// client (I10), when ECS is on, the client is eligible and did not
    /// send a subnet itself.
    fn ecs_request(&self, q: &QueryCtx<'_>) -> Option<EcsRequest> {
        let r = &q.rt.resolver;
        if !r.ecs {
            return None;
        }
        let ip = q.meta.client.ip();
        if !r.ecs_private_clients && is_special_address(ip) {
            return None;
        }
        if q.request
            .edns
            .as_ref()
            .is_some_and(|e| e.options().get(EdnsCode::Subnet).is_some())
        {
            return None; // the client chose its own subnet
        }
        let (masked, prefix) = match ip {
            std::net::IpAddr::V4(a) => {
                let p = r.ecs_ipv4_prefix.min(32);
                let m = if p == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(p))
                };
                (std::net::IpAddr::V4((u32::from(a) & m).into()), p)
            }
            std::net::IpAddr::V6(a) => {
                let p = r.ecs_ipv6_prefix.min(128);
                let m = if p == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(p))
                };
                (std::net::IpAddr::V6((u128::from(a) & m).into()), p)
            }
        };
        let mut m = q.request.clone();
        let mut edns = m.edns.take().unwrap_or_else(|| {
            let mut e = Edns::new();
            e.set_max_payload(1232).set_version(0);
            e
        });
        edns.options_mut().insert(EdnsOption::Subnet(
            hickory_proto::rr::rdata::opt::ClientSubnet::new(masked, prefix, 0),
        ));
        m.set_edns(edns);
        let request = m.to_vec().ok()?;
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (masked, prefix).hash(&mut h);
        Some(EcsRequest {
            request,
            scope: h.finish() | 1, // never 0 (the global scope) nor ECS_SHARED
            source_prefix: prefix,
        })
    }

    /// `override` (I1): a name in an override zone. Only for clients in
    /// the forwarding ACL (others REFUSED, like forwarding). Local data
    /// first (never authoritative, never signed, no AD); a local CNAME to a
    /// name elsewhere is chased through the zone's upstreams; names and
    /// types the zone does not define go to its upstreams (`transparent`)
    /// or get the local negative answer (`static`, or no upstreams at all).
    pub(super) async fn filter_override(&self, q: &mut QueryCtx<'_>) -> Step {
        let Some(z) = q.override_zone.clone() else {
            return Step::Next;
        };
        let rt = q.rt;
        let client = q.meta.client.ip();
        if !rt.forward_acl.iter().any(|c| c.contains(client)) {
            self.stats.refused.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::Refused, "refused");
        }
        let spec = z.zone.overrides.as_deref().cloned().unwrap_or_default();
        let ups: Vec<std::net::SocketAddr> = if spec.upstreams.is_empty() {
            rt.forwarding.upstreams.clone()
        } else {
            spec.upstreams.clone()
        };
        let question = q.question().clone();
        let qtype = question.query_type();
        let catalog = self.cache.load();
        let a = crate::zones::lookup_override(&catalog, &z, question.name(), qtype);
        let rd = q.request.metadata.recursion_desired;
        if !a.answers.is_empty() {
            let chase = dangling_cname(&a.answers)
                .filter(|_| qtype != RecordType::CNAME && qtype != RecordType::ANY);
            let mut resp = q.take_resp();
            resp.metadata.authoritative = false;
            resp.metadata.response_code = a.rcode;
            resp.insert_answers(a.answers);
            resp.insert_authorities(a.authority);
            resp.insert_additionals(a.additional);
            if let (Some(target), true, false) = (chase, rd, ups.is_empty()) {
                match self.resolve_upstream(q, &ups, &target, qtype).await {
                    Ok(m) => {
                        resp.metadata.response_code = m.metadata.response_code;
                        for r in m.answers {
                            if !resp.answers.contains(&r) {
                                resp.add_answer(r);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(name = %target, error = %e, "override zone: CNAME target lookup failed");
                    }
                }
            }
            return Step::Answer(Response::Message(resp, "override"));
        }
        if spec.mode == crate::model::OverrideMode::Static || ups.is_empty() {
            if a.rcode == ResponseCode::NXDomain {
                self.stats.nxdomain.fetch_add(1, Relaxed);
            }
            let mut resp = q.take_resp();
            resp.metadata.authoritative = false;
            resp.metadata.response_code = a.rcode;
            resp.insert_authorities(a.authority);
            return Step::Answer(Response::Message(resp, "override"));
        }
        if !rd {
            self.stats.refused.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::Refused, "refused");
        }
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        ups.hash(&mut h);
        let scope = h.finish() | 2;
        self.relay(
            q,
            Relay {
                upstreams: &ups,
                scope,
                source: "override",
                cache_source: "override",
                clear_ad: true,
                ..Relay::global(&ups)
            },
        )
        .await
    }

    /// Ask `ups` for `name`/`qtype` (a CNAME target): a fresh recursive
    /// query, not cached.
    async fn resolve_upstream(
        &self,
        q: &QueryCtx<'_>,
        ups: &[std::net::SocketAddr],
        name: &hickory_proto::rr::Name,
        qtype: RecordType,
    ) -> anyhow::Result<Message> {
        let mut m = Message::query();
        m.metadata.id = rand::random();
        m.metadata.recursion_desired = true;
        m.add_query(hickory_proto::op::Query::query(name.clone(), qtype));
        let mut e = Edns::new();
        e.set_max_payload(1232).set_version(0);
        m.set_edns(e);
        let req = m.to_vec()?;
        let bytes = super::forward::forward_via(
            ups,
            q.rt.forwarding.timeout_ms,
            q.rt.resolver.strategy,
            Some(&self.upstream_health),
            &req,
            q.meta.proto,
        )
        .await?;
        Ok(Message::from_bytes(&bytes)?)
    }

    /// `domain_needed` (I2): a single-label name (`wpad.`, `printer.`) is
    /// never forwarded: NXDOMAIN here (own and override zones answered
    /// before this filter).
    pub(super) fn filter_domain_needed(&self, q: &mut QueryCtx<'_>) -> Step {
        if q.question().name().num_labels() == 1 {
            self.stats.nxdomain.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::NXDomain, "local");
        }
        Step::Next
    }

    /// `bogus_priv` (I3): reverse lookups of private and special ranges
    /// are never forwarded: NXDOMAIN here (own reverse zones and automatic
    /// PTR answered before this filter).
    pub(super) fn filter_bogus_priv(&self, q: &mut QueryCtx<'_>) -> Step {
        let key = crate::zones::key_of(q.question().name());
        if is_private_reverse(&key) {
            self.stats.nxdomain.fetch_add(1, Relaxed);
            return q.reply(ResponseCode::NXDomain, "local");
        }
        Step::Next
    }

    /// `filter_types` (I9): listed record types are never forwarded; the
    /// query gets an empty answer (NODATA).
    pub(super) fn filter_types(&self, q: &mut QueryCtx<'_>) -> Step {
        if q.rt.filter_types.contains(&q.question().query_type()) {
            return q.reply(ResponseCode::NoError, "local");
        }
        Step::Next
    }

    /// `blocklist` (I7): names on a downloaded blocklist (and below them)
    /// get NXDOMAIN or a null address, unless allowlisted.
    pub(super) fn filter_blocklist(&self, q: &mut QueryCtx<'_>) -> Step {
        let compiled = self.blocklists.compiled();
        let key = crate::zones::key_of(q.question().name());
        let name = key.trim_end_matches('.');
        let Some(i) = compiled.blocks(name) else {
            return Step::Next;
        };
        self.blocklists.count(&compiled, i);
        let qtype = q.question().query_type();
        let qname = q.question().name().clone();
        let mut resp = q.take_resp();
        match compiled.action {
            crate::blocklist::BlockAction::Nxdomain => {
                self.stats.nxdomain.fetch_add(1, Relaxed);
                resp.metadata.response_code = ResponseCode::NXDomain;
            }
            crate::blocklist::BlockAction::NullAddress => match qtype {
                RecordType::A => {
                    resp.add_answer(Record::from_rdata(
                        qname,
                        300,
                        RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::UNSPECIFIED)),
                    ));
                }
                RecordType::AAAA => {
                    resp.add_answer(Record::from_rdata(
                        qname,
                        300,
                        RData::AAAA(hickory_proto::rr::rdata::AAAA(
                            std::net::Ipv6Addr::UNSPECIFIED,
                        )),
                    ));
                }
                _ => {}
            },
        };
        Step::Answer(Response::Message(resp, "blocked"))
    }

    /// `rebind` (I4), on the way back: a forwarded answer (or cache hit)
    /// with a private, loopback, link-local, CGNAT, ULA or unspecified
    /// address is replaced by REFUSED, unless the name is allowlisted. Own
    /// and override zones are answered by other filters and never checked.
    pub(super) fn post_rebind(&self, q: &mut QueryCtx<'_>, resp: &mut Response) {
        if q.meta.filter != "forward" {
            return;
        }
        let m = match resp {
            Response::Relayed {
                parsed: Ok(m),
                source: "forward",
                ..
            } => m,
            Response::Message(m, "forward" | "cache") => m,
            _ => return,
        };
        let Some(bad) = m.answers.iter().find_map(|r| match &r.data {
            RData::A(a) if is_special_address(std::net::IpAddr::V4(a.0)) => Some(a.0.into()),
            RData::AAAA(a) if is_special_address(std::net::IpAddr::V6(a.0)) => Some(a.0.into()),
            _ => None,
        }) else {
            return;
        };
        let key = crate::zones::key_of(q.question().name());
        let name = key.trim_end_matches('.');
        if q.rt
            .resolver
            .rebind_allow
            .iter()
            .any(|a| name == a || name.ends_with(&format!(".{a}")))
        {
            return;
        }
        let bad: std::net::IpAddr = bad;
        self.rebind_log.note(name, bad);
        let id = q.resp.metadata.id;
        let mut r = Message::response(id, OpCode::Query);
        r.metadata.recursion_desired = q.request.metadata.recursion_desired;
        r.metadata.recursion_available = true;
        r.metadata.response_code = ResponseCode::Refused;
        r.add_query(q.question().clone());
        r.edns = q.resp.edns.clone();
        self.stats.refused.fetch_add(1, Relaxed);
        q.meta.filter = "rebind";
        *resp = Response::Message(r, "blocked");
    }

    /// `serve_stale` (I5), on the way back: when every upstream failed,
    /// an expired cache entry within `max_stale_age_secs` replaces the
    /// SERVFAIL (TTL 30 s, RFC 8767).
    pub(super) fn post_serve_stale(&self, q: &mut QueryCtx<'_>, resp: &mut Response) {
        if !q.upstream_failed || q.meta.filter != "forward" {
            return;
        }
        let Some(key) = &q.fwd_key else {
            return;
        };
        let Some(mut m) = self.fwd_cache.get_stale(key, q.rt.cache_caps()) else {
            return;
        };
        self.stats.stale_answers.fetch_add(1, Relaxed);
        m.metadata.id = q.resp.metadata.id;
        m.metadata.recursion_desired = q.request.metadata.recursion_desired;
        m.metadata.recursion_available = true;
        m.queries = q.request.queries.clone();
        m.edns = q.resp.edns.clone();
        q.meta.filter = "serve_stale";
        *resp = Response::Message(m, "stale");
    }
}

/// How [`DnsServer::relay`] forwards.
struct Relay<'a> {
    upstreams: &'a [std::net::SocketAddr],
    /// Forward cache scope (0: global upstreams).
    scope: u64,
    /// A second cache scope to look in (ECS: answers valid for everyone).
    alt_scope: Option<u64>,
    /// Event source of an upstream answer / a cache hit.
    source: &'static str,
    cache_source: &'static str,
    /// Clear AD (override zones).
    clear_ad: bool,
    upstream_req: Option<Vec<u8>>,
    ecs_source_prefix: Option<u8>,
}

impl<'a> Relay<'a> {
    fn global(upstreams: &'a [std::net::SocketAddr]) -> Self {
        Relay {
            upstreams,
            scope: 0,
            alt_scope: None,
            source: "forward",
            cache_source: "cache",
            clear_ad: false,
            upstream_req: None,
            ecs_source_prefix: None,
        }
    }
}

/// Cache scope of ECS answers whose scope is /0 (valid for every client).
const ECS_SHARED: u64 = 0xEC5;

struct EcsRequest {
    request: Vec<u8>,
    scope: u64,
    source_prefix: u8,
}

/// The scope prefix of an ECS option in a reply, if any.
fn ecs_scope(m: &Message) -> Option<u8> {
    match m.edns.as_ref()?.options().get(EdnsCode::Subnet)? {
        EdnsOption::Subnet(s) => Some(s.scope_prefix()),
        _ => None,
    }
}

/// The target of the last CNAME of an answer when nothing in the answer
/// is owned by it (the chase left our zones).
fn dangling_cname(answers: &[Record]) -> Option<hickory_proto::rr::Name> {
    let last = answers.last()?;
    let RData::CNAME(c) = &last.data else {
        return None;
    };
    let t = crate::zones::key_of(&c.0);
    (!answers.iter().any(|r| crate::zones::key_of(&r.name) == t)).then(|| c.0.clone())
}

/// Private, loopback, link-local, CGNAT, ULA, unspecified (I4, I10):
/// addresses an answer from the internet should not point to.
pub fn is_special_address(ip: std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
        }
        std::net::IpAddr::V6(a) => {
            let s = a.segments();
            a.is_unspecified()
                || a.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// A reverse name (`...in-addr.arpa.` / `...ip6.arpa.`, lower-case fqdn)
/// at or below an RFC 6303 zone: 10/8, 172.16/12, 192.168/16, 100.64/10,
/// 127/8, 169.254/16, 0/8, 255.255.255.255, fc00::/7, fe80::/10, ::1, ::.
pub fn is_private_reverse(key: &str) -> bool {
    if let Some(rest) = key.strip_suffix(".in-addr.arpa.") {
        let o: Vec<u8> = match rest.rsplit('.').map(|l| l.parse::<u8>()).collect() {
            Ok(v) => v,
            Err(_) => return false,
        };
        return match o.as_slice() {
            [0, ..] | [10, ..] | [127, ..] => true,
            [169, 254, ..] | [192, 168, ..] => true,
            [172, b, ..] => (16..=31).contains(b),
            [100, b, ..] => (64..=127).contains(b),
            [255, 255, 255, 255] => true,
            _ => false,
        };
    }
    if let Some(rest) = key.strip_suffix(".ip6.arpa.") {
        let mut nib: Vec<u8> = Vec::with_capacity(32);
        for l in rest.rsplit('.') {
            match (l.len(), u8::from_str_radix(l, 16)) {
                (1, Ok(v)) => nib.push(v),
                _ => return false,
            }
        }
        if nib.len() > 32 {
            return false;
        }
        return match nib.as_slice() {
            [0xf, 0xc | 0xd, ..] => true,
            [0xf, 0xe, 8..=0xb, ..] => true,
            n if n.len() == 32 => n[..31].iter().all(|x| *x == 0) && n[31] <= 1,
            _ => false,
        };
    }
    false
}

/// Names refused by rebinding protection: per name the count, the last
/// address and time (the most recent 100 names).
#[derive(Default)]
pub struct RebindLog {
    inner: std::sync::Mutex<std::collections::HashMap<String, RebindEntry>>,
    pub total: std::sync::atomic::AtomicU64,
}

/// One name refused by rebinding protection.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct RebindEntry {
    pub name: String,
    pub count: u64,
    /// The address that made the answer refused (last seen).
    pub address: String,
    #[schema(format = DateTime)]
    pub last_at: String,
}

impl RebindLog {
    fn note(&self, name: &str, ip: std::net::IpAddr) {
        self.total.fetch_add(1, Relaxed);
        tracing::warn!(name, address = %ip, "rebinding protection: refused a forwarded answer with a private address");
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = crate::model::now_rfc3339();
        let e = g.entry(name.to_string()).or_insert_with(|| RebindEntry {
            name: name.to_string(),
            count: 0,
            address: String::new(),
            last_at: String::new(),
        });
        e.count += 1;
        e.address = ip.to_string();
        e.last_at = now;
        if g.len() > 100 {
            if let Some(oldest) = g
                .values()
                .min_by(|a, b| a.last_at.cmp(&b.last_at))
                .map(|e| e.name.clone())
            {
                g.remove(&oldest);
            }
        }
    }

    /// Most recent first.
    pub fn recent(&self) -> Vec<RebindEntry> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<RebindEntry> = g.values().cloned().collect();
        v.sort_by(|a, b| b.last_at.cmp(&a.last_at));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_reverse_names() {
        for n in [
            "1.0.0.10.in-addr.arpa.",
            "10.in-addr.arpa.",
            "5.16.172.in-addr.arpa.",
            "31.172.in-addr.arpa.",
            "1.1.168.192.in-addr.arpa.",
            "64.100.in-addr.arpa.",
            "9.127.100.in-addr.arpa.",
            "1.0.0.127.in-addr.arpa.",
            "254.169.in-addr.arpa.",
            "0.in-addr.arpa.",
            "255.255.255.255.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "d.f.ip6.arpa.",
            "1.c.f.ip6.arpa.",
            "8.e.f.ip6.arpa.",
            "b.e.f.ip6.arpa.",
        ] {
            assert!(is_private_reverse(n), "{n}");
        }
        for n in [
            "1.1.1.1.in-addr.arpa.",
            "15.172.in-addr.arpa.",
            "32.172.in-addr.arpa.",
            "172.in-addr.arpa.",
            "192.in-addr.arpa.",
            "63.100.in-addr.arpa.",
            "in-addr.arpa.",
            "8.8.8.8.in-addr.arpa.",
            "x.10.in-addr.arpa.",
            "e.f.ip6.arpa.",
            "f.ip6.arpa.",
            "c.e.f.ip6.arpa.",
            "8.8.4.0.6.8.4.1.0.0.2.ip6.arpa.",
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "www.example.com.",
        ] {
            assert!(!is_private_reverse(n), "{n}");
        }
    }

    #[test]
    fn special_addresses() {
        for a in [
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "::",
            "::1",
            "fd00::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_special_address(a.parse().unwrap()), "{a}");
        }
        for a in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2001:db8::1",
            "1.1.1.1",
            "fec0::1",
        ] {
            assert!(!is_special_address(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn dangling_cnames() {
        let n = |s: &str| hickory_proto::rr::Name::from_ascii(s).unwrap();
        let cname = |o: &str, t: &str| {
            Record::from_rdata(
                n(o),
                60,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(n(t))),
            )
        };
        let a = |o: &str| {
            Record::from_rdata(
                n(o),
                60,
                RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
            )
        };
        assert_eq!(dangling_cname(&[cname("a.x.", "b.y.")]), Some(n("b.y.")));
        assert_eq!(dangling_cname(&[cname("a.x.", "b.y."), a("b.y.")]), None);
        assert_eq!(dangling_cname(&[a("a.x.")]), None);
    }
}
