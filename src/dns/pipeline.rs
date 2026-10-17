//! The query pipeline: how a request becomes a reply.
//!
//! Two stages, because admission must stay before decoding (C2):
//!
//! 1. **Raw stage** (`handler.rs`, bytes only, synchronous): admission
//!    ([`DnsServer::admit`]: the per-client rate limit, before the packet is
//!    copied, given a task or decoded), then TSIG ([`DnsServer::handle_admitted`]:
//!    a signed request is verified and its TSIG record removed; the reply is
//!    signed on the way out). Outcome: continue, or reply/drop at once.
//! 2. **Query stage** (here): the request is decoded once into a
//!    [`QueryCtx`] and handed to an ordered chain of [`Filter`]s. Each filter
//!    either answers ([`Step::Answer`]), drops the query ([`Step::Drop`]: UDP
//!    gets no reply) or passes it on ([`Step::Next`]). When a filter has
//!    answered, every filter before it that passed gets the response on the
//!    way back ([`DnsServer::post`]: inspect or replace it), innermost
//!    first, servlet-filter style. Finally the response is finished
//!    ([`DnsServer::complete`]: encoded, trimmed / truncated for UDP, the
//!    query event emitted).
//!
//! The chain is part of [`super::Runtime`]: built from the config and the
//! console settings, and replaced as a whole (`ArcSwap`) on reload or a
//! settings change, so a query runs start to end on one consistent chain.
//! A filter that is switched off is not in the chain at all.
//!
//! The chain, in order (see [`chain_for`]):
//!
//! | filter          | what it does                                                        |
//! |-----------------|---------------------------------------------------------------------|
//! | `edns`          | EDNS version (BADVERS), NSID, cookies (FORMERR / BADCOOKIE)        |
//! | `request`       | opcode (NOTIMP), exactly one question (FORMERR)                     |
//! | `special`       | CHAOS `version.bind` / `version.server`, classes other than IN/ANY |
//! | `transfer`      | AXFR / IXFR (ACL, TSIG key scope), qtype OPT (FORMERR)              |
//! | `authoritative` | own zones (minimal ANY, DNSSEC, wildcards, CNAME/DNAME, referrals, auto-PTR) |
//! | `override`      | override zones (I1): local data, else the zone's upstreams / NXDOMAIN |
//! | `recursion`     | the forwarding ACL and RD: REFUSED for clients that may not recurse |
//! | `domain_needed` | single-label names: NXDOMAIN, never forwarded (I2; console toggle) |
//! | `bogus_priv`    | reverse lookups of private ranges: NXDOMAIN (I3; console toggle)   |
//! | `filter_types`  | record types never forwarded: NODATA (I9; when types are listed)   |
//! | `blocklist`     | names on a blocklist: NXDOMAIN or 0.0.0.0 / :: (I7; when a list is on) |
//! | `open_resolver` | open resolver safeguards (only in the chain while that mode is on) |
//! | `rebind`        | post: refuses forwarded answers with private addresses (I4; toggle) |
//! | `serve_stale`   | post: an expired cache entry when every upstream failed (I5; toggle) |
//! | `forward`       | forward cache, in-flight cap (C1), upstream strategy (I6), ECS (I10) |
//!
//! Static dispatch: [`Filter`] is an enum and the chain a `Vec` of it, so a
//! query costs no allocation per filter and no boxed future; switching a
//! filter off removes it from the vector. A filter that panics does not take
//! the server down: the query gets SERVFAIL and the panic is logged with the
//! filter's name ([`DnsServer::query_stage`]).

use super::handler::{header_only, Ctx, SignedBy};
use super::{DnsServer, Proto, Reply, Runtime};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// One filter of the query chain. The order of the chain is decided by
/// [`chain_for`]; every variant has a stable name (metrics, query events).
#[derive(Clone)]
pub enum Filter {
    Edns,
    Request,
    Special,
    Transfer,
    Authoritative,
    Recursion,
    OpenResolver,
    Forward,
    Override,
    DomainNeeded,
    BogusPriv,
    Types,
    Blocklist,
    Rebind,
    ServeStale,
    /// A filter whose behaviour a test chooses (chain semantics tests).
    #[cfg(test)]
    Probe(std::sync::Arc<probe::Probe>),
}

/// Number of [`FilterStats`] slots (one per filter kind).
pub const FILTER_KINDS: usize = 16;

impl Filter {
    pub fn name(&self) -> &'static str {
        match self {
            Filter::Edns => "edns",
            Filter::Request => "request",
            Filter::Special => "special",
            Filter::Transfer => "transfer",
            Filter::Authoritative => "authoritative",
            Filter::Recursion => "recursion",
            Filter::OpenResolver => "open_resolver",
            Filter::Forward => "forward",
            Filter::Override => "override",
            Filter::DomainNeeded => "domain_needed",
            Filter::BogusPriv => "bogus_priv",
            Filter::Types => "filter_types",
            Filter::Blocklist => "blocklist",
            Filter::Rebind => "rebind",
            Filter::ServeStale => "serve_stale",
            #[cfg(test)]
            Filter::Probe(p) => p.name,
        }
    }

    /// Slot in [`FilterStats`].
    fn slot(&self) -> usize {
        match self {
            Filter::Edns => 0,
            Filter::Request => 1,
            Filter::Special => 2,
            Filter::Transfer => 3,
            Filter::Authoritative => 4,
            Filter::Recursion => 5,
            Filter::OpenResolver => 6,
            Filter::Forward => 7,
            Filter::Override => 8,
            Filter::DomainNeeded => 9,
            Filter::BogusPriv => 10,
            Filter::Types => 11,
            Filter::Blocklist => 12,
            Filter::Rebind => 13,
            Filter::ServeStale => 14,
            #[cfg(test)]
            Filter::Probe(_) => 15,
        }
    }

    /// Every filter kind, for metrics (the probe is test-only).
    pub const ALL: [&'static str; FILTER_KINDS - 1] = [
        "edns",
        "request",
        "special",
        "transfer",
        "authoritative",
        "recursion",
        "open_resolver",
        "forward",
        "override",
        "domain_needed",
        "bogus_priv",
        "filter_types",
        "blocklist",
        "rebind",
        "serve_stale",
    ];

    /// Whether [`DnsServer::post`] does anything for this filter (saves the
    /// walk back for chains without post-processing).
    fn has_post(&self) -> bool {
        match self {
            Filter::Rebind | Filter::ServeStale => true,
            #[cfg(test)]
            Filter::Probe(_) => true,
            _ => false,
        }
    }
}

/// The chain for a runtime snapshot, in the documented order.
pub fn chain_for(rt: &Runtime) -> Vec<Filter> {
    let mut c = vec![
        Filter::Edns,
        Filter::Request,
        Filter::Special,
        Filter::Transfer,
        Filter::Authoritative,
        Filter::Override,
        Filter::Recursion,
    ];
    if rt.resolver.domain_needed {
        c.push(Filter::DomainNeeded);
    }
    if rt.resolver.bogus_priv {
        c.push(Filter::BogusPriv);
    }
    if !rt.filter_types.is_empty() {
        c.push(Filter::Types);
    }
    if rt.blocklists {
        c.push(Filter::Blocklist);
    }
    if rt.open_resolver() {
        c.push(Filter::OpenResolver);
    }
    if rt.resolver.rebind_protection {
        c.push(Filter::Rebind);
    }
    if rt.resolver.serve_stale {
        c.push(Filter::ServeStale);
    }
    c.push(Filter::Forward);
    c
}

/// Per-filter counters: queries a filter answered, dropped or passed on
/// (handled = the sum), and panics.
pub struct FilterStats {
    counts: [[AtomicU64; 4]; FILTER_KINDS],
}

/// One filter's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterCounts {
    pub answered: u64,
    pub dropped: u64,
    pub passed: u64,
    pub panicked: u64,
}

/// One filter of the chain in effect, with its counters since start.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct FilterStatus {
    /// Filter name (`edns`, `request`, `special`, `transfer`,
    /// `authoritative`, `recursion`, `open_resolver`, `forward`, ...).
    #[schema(example = "authoritative")]
    pub name: &'static str,
    /// Queries this filter saw (answered + dropped + passed).
    pub handled: u64,
    /// Queries this filter answered.
    pub answered: u64,
    /// Queries this filter dropped (no reply).
    pub dropped: u64,
    /// Queries passed to the next filter.
    pub passed: u64,
    /// Queries that made this filter panic (answered SERVFAIL).
    pub panicked: u64,
}

const ANSWERED: usize = 0;
const DROPPED: usize = 1;
const PASSED: usize = 2;
const PANICKED: usize = 3;

impl Default for FilterStats {
    fn default() -> Self {
        FilterStats {
            counts: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }
}

impl FilterStats {
    fn add(&self, f: &Filter, outcome: usize) {
        self.counts[f.slot()][outcome].fetch_add(1, Relaxed);
    }

    /// Counters of every filter kind, by name.
    pub fn snapshot(&self) -> Vec<(&'static str, FilterCounts)> {
        Filter::ALL
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let c = &self.counts[i];
                (
                    *name,
                    FilterCounts {
                        answered: c[ANSWERED].load(Relaxed),
                        dropped: c[DROPPED].load(Relaxed),
                        passed: c[PASSED].load(Relaxed),
                        panicked: c[PANICKED].load(Relaxed),
                    },
                )
            })
            .collect()
    }
}

impl DnsServer {
    /// The chain in effect, in order, with each filter's counters.
    pub fn pipeline_status(&self) -> Vec<FilterStatus> {
        let rt = self.runtime.load();
        let counts = self.filter_stats.snapshot();
        rt.chain
            .iter()
            .map(|f| {
                let c = counts
                    .iter()
                    .find(|(n, _)| *n == f.name())
                    .map(|(_, c)| *c)
                    .unwrap_or_default();
                FilterStatus {
                    name: f.name(),
                    handled: c.answered + c.dropped + c.passed,
                    answered: c.answered,
                    dropped: c.dropped,
                    passed: c.passed,
                    panicked: c.panicked,
                }
            })
            .collect()
    }
}

/// What a filter decided.
pub enum Step {
    /// Pass the query to the next filter.
    Next,
    /// This is the response.
    Answer(Response),
    /// Send nothing (UDP: no reply; TCP: nothing for this query).
    Drop,
}

/// A response on its way back through the chain.
pub enum Response {
    /// A message the finish stage encodes (UDP trimming / truncation) and
    /// reports in the query event with `source`.
    Message(Message, &'static str),
    /// A reply relayed from an upstream, sent as received (the finish stage
    /// only truncates it for UDP). `parsed`: the decoded reply, or why it
    /// could not be decoded.
    Relayed {
        bytes: Vec<u8>,
        parsed: Result<Message, ()>,
        /// `forward`, or `override` for an override zone's upstreams.
        source: &'static str,
    },
    /// Several messages (AXFR over TCP); the query event was emitted.
    Transfer(Vec<Vec<u8>>),
    /// Final bytes; the query event was emitted.
    Bytes(Vec<u8>),
    /// Send nothing.
    Drop,
}

/// The decoded request and everything filters share about it.
pub(super) struct QueryCtx<'a> {
    /// Client, protocol, limits, DO, the source filter (see [`Ctx`]).
    pub(super) meta: Ctx,
    /// The request as received (TSIG record removed), for relaying.
    pub(super) req: &'a [u8],
    pub(super) request: Message,
    /// The response being prepared: header, question and OPT record. A
    /// filter that answers takes it ([`QueryCtx::take_resp`]).
    pub(super) resp: Message,
    /// The verified TSIG key of a signed request.
    pub(super) signed_by: Option<&'a SignedBy>,
    /// The runtime snapshot this query runs on (its chain included).
    pub(super) rt: &'a Runtime,
    /// Index of the filter running now (named in a panic report).
    current: usize,
    /// The override zone the name falls in (set by `authoritative`).
    pub(super) override_zone: Option<std::sync::Arc<crate::cache::ZoneData>>,
    /// The forward cache key of a forwarded query (set by `forward`).
    pub(super) fwd_key: Option<super::fwdcache::Key>,
    /// Every upstream failed or timed out (set by `forward`).
    pub(super) upstream_failed: bool,
}

impl QueryCtx<'_> {
    /// The response prepared so far, leaving an empty one behind.
    pub fn take_resp(&mut self) -> Message {
        let id = self.resp.metadata.id;
        let op = self.resp.metadata.op_code;
        std::mem::replace(&mut self.resp, Message::response(id, op))
    }

    /// The response prepared so far with `rcode`, reported as `source`.
    pub fn reply(&mut self, rcode: ResponseCode, source: &'static str) -> Step {
        let mut m = self.take_resp();
        m.metadata.response_code = rcode;
        Step::Answer(Response::Message(m, source))
    }

    /// The query's name and type (the chain runs past `request` only with
    /// exactly one question).
    pub fn question(&self) -> &hickory_proto::op::Query {
        &self.request.queries[0]
    }
}

impl DnsServer {
    /// Decode the request and run the query stage (see the module docs).
    pub(super) async fn query_stage(
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
        let dnssec_ok = request
            .edns
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);
        let meta = Ctx {
            client,
            proto,
            started,
            udp_limit: 512,
            reserve: signed_by
                .map(|b| super::tsig::record_len(&b.entry.key.name, b.entry.key.algorithm, 0))
                .unwrap_or(0),
            open_cap_from: None,
            dnssec_ok,
            listening: self.bus.has_query_subscribers(),
            filter: "",
        };
        let mut resp = Message::response(id, request.metadata.op_code);
        if request.metadata.op_code == OpCode::Query {
            resp.metadata.recursion_desired = request.metadata.recursion_desired;
            resp.metadata.recursion_available = rt.may_forward(client.ip());
            for q in &request.queries {
                resp.add_query(q.clone());
            }
        }
        let mut q = QueryCtx {
            meta,
            req,
            request,
            resp,
            signed_by,
            rt,
            current: 0,
            override_zone: None,
            fwd_key: None,
            upstream_failed: false,
        };
        let run = std::panic::AssertUnwindSafe(self.run_chain(&rt.chain, &mut q));
        match futures::FutureExt::catch_unwind(run).await {
            Ok(r) => self.complete(r, &q),
            Err(panic) => {
                let filter = rt.chain.get(q.current);
                if let Some(f) = filter {
                    self.filter_stats.add(f, PANICKED);
                }
                let why = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                tracing::error!(
                    filter = filter.map(Filter::name).unwrap_or("?"),
                    panic = %why,
                    client = %client.ip(),
                    "query filter panicked; answering SERVFAIL"
                );
                self.stats.errors.fetch_add(1, Relaxed);
                let mut m =
                    Message::error_msg(id, q.request.metadata.op_code, ResponseCode::ServFail);
                m.metadata.checking_disabled = q.request.metadata.op_code == OpCode::Query
                    && q.request.metadata.checking_disabled;
                for x in &q.request.queries {
                    m.add_query(x.clone());
                }
                q.meta.filter = filter.map(Filter::name).unwrap_or("");
                Reply::One(self.finish(m, &q.meta, "error"))
            }
        }
    }

    /// Run the chain: filters in order until one answers or drops, then the
    /// post-processing of the filters before it, innermost first.
    async fn run_chain(&self, chain: &[Filter], q: &mut QueryCtx<'_>) -> Response {
        let mut i = 0;
        let mut resp = loop {
            let Some(f) = chain.get(i) else {
                // Every chain ends with a filter that answers; this is the
                // fallback should one not.
                q.meta.filter = "";
                self.stats.refused.fetch_add(1, Relaxed);
                let mut m = q.take_resp();
                m.metadata.response_code = ResponseCode::Refused;
                break Response::Message(m, "refused");
            };
            q.current = i;
            match self.pre(f, q).await {
                Step::Next => {
                    self.filter_stats.add(f, PASSED);
                    i += 1;
                }
                Step::Answer(r) => {
                    self.filter_stats.add(f, ANSWERED);
                    q.meta.filter = f.name();
                    break r;
                }
                Step::Drop => {
                    self.filter_stats.add(f, DROPPED);
                    q.meta.filter = f.name();
                    break Response::Drop;
                }
            }
        };
        for (j, f) in chain[..i.min(chain.len())].iter().enumerate().rev() {
            if f.has_post() {
                q.current = j;
                self.post(f, q, &mut resp);
            }
        }
        resp
    }

    /// The forward half of one filter.
    async fn pre(&self, f: &Filter, q: &mut QueryCtx<'_>) -> Step {
        match f {
            Filter::Edns => self.filter_edns(q),
            Filter::Request => self.filter_request(q),
            Filter::Special => self.filter_special(q),
            Filter::Transfer => self.filter_transfer(q),
            Filter::Authoritative => self.filter_authoritative(q),
            Filter::Recursion => self.filter_recursion(q),
            Filter::OpenResolver => self.filter_open_resolver(q),
            Filter::Forward => self.filter_forward(q).await,
            Filter::Override => self.filter_override(q).await,
            Filter::DomainNeeded => self.filter_domain_needed(q),
            Filter::BogusPriv => self.filter_bogus_priv(q),
            Filter::Types => self.filter_types(q),
            Filter::Blocklist => self.filter_blocklist(q),
            Filter::Rebind | Filter::ServeStale => Step::Next,
            #[cfg(test)]
            Filter::Probe(p) => p.pre(q).await,
        }
    }

    /// The way back of one filter: inspect or replace the response a later
    /// filter produced.
    fn post(&self, f: &Filter, q: &mut QueryCtx<'_>, resp: &mut Response) {
        match f {
            Filter::Rebind => self.post_rebind(q, resp),
            Filter::ServeStale => self.post_serve_stale(q, resp),
            #[cfg(test)]
            Filter::Probe(p) => p.post(q, resp),
            _ => {
                let _ = (q, resp);
            }
        }
    }

    /// Finish a response: encode, fit it to UDP, emit the query event.
    /// Every response to a query carries the query's CD bit (RFC 4035
    /// §3.1.6: "MUST copy the CD bit from a query into the corresponding
    /// response"), whichever filter made it; TSIG signs the bytes later.
    fn complete(&self, resp: Response, q: &QueryCtx<'_>) -> Reply {
        let cd =
            q.request.metadata.op_code == OpCode::Query && q.request.metadata.checking_disabled;
        match resp {
            Response::Message(mut m, source) => {
                m.metadata.checking_disabled = cd;
                Reply::One(self.finish(m, &q.meta, source))
            }
            Response::Relayed {
                mut bytes,
                parsed,
                source,
            } => {
                set_cd(&mut bytes, cd);
                Reply::One(self.finish_relayed(bytes, parsed, source, q))
            }
            Response::Transfer(mut ms) => {
                for m in &mut ms {
                    set_cd(m, cd);
                }
                Reply::Many(ms)
            }
            Response::Bytes(mut b) => {
                set_cd(&mut b, cd);
                Reply::One(b)
            }
            Response::Drop => Reply::None,
        }
    }

    /// A reply relayed from an upstream: sent as received, truncated if it
    /// exceeds what this UDP client accepts (a reply fetched over TCP after
    /// an upstream TC can), reported with source `forward`.
    fn finish_relayed(
        &self,
        bytes: Vec<u8>,
        parsed: Result<Message, ()>,
        source: &'static str,
        q: &QueryCtx<'_>,
    ) -> Vec<u8> {
        let ctx = &q.meta;
        let id = u16::from_be_bytes([q.req[0], q.req[1]]);
        let question = q.question();
        let (rcode, answers, mut result) = match &parsed {
            Ok(m) => (
                m.metadata.response_code,
                m.answers.len(),
                if ctx.listening {
                    super::handler::summarize(m, question.name())
                } else {
                    Vec::new()
                },
            ),
            Err(_) => (
                ResponseCode::ServFail,
                0,
                vec!["unparseable upstream reply".into()],
            ),
        };
        let limit = ctx.udp_limit.saturating_sub(ctx.reserve);
        let bytes = match (&parsed, ctx.proto) {
            (Ok(m), Proto::Udp) if bytes.len() > limit => {
                self.stats.truncated.fetch_add(1, Relaxed);
                result.push(self.truncation_note(ctx, bytes.len(), limit));
                m.truncate()
                    .to_vec()
                    .unwrap_or_else(|_| header_only(id, ResponseCode::ServFail))
            }
            (Err(_), Proto::Udp) if bytes.len() > limit => header_only(id, ResponseCode::ServFail),
            _ => bytes,
        };
        self.emit(
            ctx,
            question.name(),
            question.query_type(),
            rcode,
            answers,
            result,
            source,
        );
        bytes
    }
}

/// Set or clear the CD bit in an encoded message's header.
fn set_cd(msg: &mut [u8], cd: bool) {
    if let Some(flags) = msg.get_mut(3) {
        if cd {
            *flags |= 0x10;
        } else {
            *flags &= !0x10;
        }
    }
}

#[cfg(test)]
pub mod probe {
    //! A configurable filter for the chain semantics tests.
    use super::*;
    use std::sync::Mutex;

    pub enum Act {
        Pass,
        Answer(ResponseCode),
        Drop,
        Panic,
    }

    pub struct Probe {
        pub name: &'static str,
        pub act: Act,
        /// Rcode to set on the way back (post-processing), if any.
        pub rewrite: Option<ResponseCode>,
        /// Shared log of (name, "pre"|"post") calls, in order.
        pub log: std::sync::Arc<Mutex<Vec<(&'static str, &'static str)>>>,
    }

    impl Probe {
        pub(in crate::dns) async fn pre(&self, q: &mut QueryCtx<'_>) -> Step {
            self.log.lock().unwrap().push((self.name, "pre"));
            match self.act {
                Act::Pass => Step::Next,
                Act::Answer(rc) => q.reply(rc, "auth"),
                Act::Drop => Step::Drop,
                Act::Panic => panic!("probe {} panics", self.name),
            }
        }

        pub(in crate::dns) fn post(&self, _q: &mut QueryCtx<'_>, resp: &mut Response) {
            self.log.lock().unwrap().push((self.name, "post"));
            if let (Some(rc), Response::Message(m, _)) = (self.rewrite, resp) {
                m.metadata.response_code = rc;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::probe::{Act, Probe};
    use super::*;
    use crate::mutation::settings::ResolverSettings;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

    fn server() -> DnsServer {
        let cfg = crate::config::Config::default();
        DnsServer::new(
            Arc::new(crate::cache::Cache::new(crate::cache::Catalog::empty())),
            Arc::new(crate::events::Bus::new(8, 64)),
            Arc::new(crate::ratelimit::RateLimiter::new(
                0,
                std::time::Duration::from_secs(1),
                100,
            )),
            &cfg,
        )
    }

    /// Install a chain of probes (and nothing else).
    fn with_chain(s: &DnsServer, chain: Vec<Filter>) {
        let mut rt = Runtime::from_config(&crate::config::Config::default(), None);
        rt.chain = chain;
        s.runtime.store(Arc::new(rt));
    }

    fn probe(name: &'static str, act: Act, rewrite: Option<ResponseCode>, log: &Log) -> Filter {
        Filter::Probe(Arc::new(Probe {
            name,
            act,
            rewrite,
            log: log.clone(),
        }))
    }

    fn query(id: u16) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = id;
        m.add_query(Query::query(
            Name::from_ascii("www.example.test.").unwrap(),
            RecordType::A,
        ));
        m.to_vec().unwrap()
    }

    async fn ask(s: &DnsServer, id: u16, proto: Proto) -> Option<Message> {
        let peer: SocketAddr = "192.0.2.7:5000".parse().unwrap();
        match s.handle(&query(id), peer, proto).await {
            Reply::One(b) => Some(Message::from_bytes(&b).unwrap()),
            Reply::None => None,
            Reply::Many(_) => panic!("unexpected multi-message reply"),
        }
    }

    /// Filters run in order until one answers; filters after it never
    /// run; the ones before it see the response on the way back,
    /// innermost first, and may replace it.
    #[tokio::test]
    async fn filters_answer_pass_and_post_process_in_order() {
        let s = server();
        let log: Log = Default::default();
        with_chain(
            &s,
            vec![
                probe("outer", Act::Pass, Some(ResponseCode::Refused), &log),
                probe("inner", Act::Pass, None, &log),
                probe("answers", Act::Answer(ResponseCode::NXDomain), None, &log),
                probe("never", Act::Answer(ResponseCode::NoError), None, &log),
            ],
        );
        let m = ask(&s, 0x4242, Proto::Udp).await.unwrap();
        assert_eq!(m.metadata.id, 0x4242);
        assert_eq!(
            m.metadata.response_code,
            ResponseCode::Refused,
            "the outer filter replaced the inner answer on the way back"
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![
                ("outer", "pre"),
                ("inner", "pre"),
                ("answers", "pre"),
                ("inner", "post"),
                ("outer", "post"),
            ]
        );
        // Without a rewrite the answering filter's response goes out.
        log.lock().unwrap().clear();
        with_chain(
            &s,
            vec![
                probe("pass", Act::Pass, None, &log),
                probe("answers", Act::Answer(ResponseCode::NXDomain), None, &log),
            ],
        );
        let m = ask(&s, 7, Proto::Tcp).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(m.queries.len(), 1, "the question is echoed");
    }

    /// A filter that drops the query: no reply, later filters never run,
    /// earlier ones still get the way back.
    #[tokio::test]
    async fn a_dropping_filter_sends_nothing() {
        let s = server();
        let log: Log = Default::default();
        with_chain(
            &s,
            vec![
                probe("pass", Act::Pass, None, &log),
                probe("drops", Act::Drop, None, &log),
                probe("never", Act::Answer(ResponseCode::NoError), None, &log),
            ],
        );
        assert!(ask(&s, 1, Proto::Udp).await.is_none());
        assert_eq!(
            *log.lock().unwrap(),
            vec![("pass", "pre"), ("drops", "pre"), ("pass", "post")]
        );
        // A chain where nobody answers is REFUSED (every real chain ends
        // with `forward`, which always answers).
        with_chain(&s, vec![probe("pass", Act::Pass, None, &log)]);
        let m = ask(&s, 2, Proto::Udp).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    }

    /// A panicking filter does not take the server down: that query gets
    /// SERVFAIL (with its id and question), the panic is counted, and the
    /// next query is answered normally.
    #[tokio::test]
    async fn a_panicking_filter_answers_servfail_and_the_server_goes_on() {
        let s = server();
        let log: Log = Default::default();
        let sub = s.bus.subscribe_queries().unwrap();
        with_chain(
            &s,
            vec![
                probe("pass", Act::Pass, None, &log),
                probe("boom", Act::Panic, None, &log),
            ],
        );
        for proto in [Proto::Udp, Proto::Tcp] {
            let m = ask(&s, 0x0bad, proto).await.unwrap();
            assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
            assert_eq!(m.metadata.id, 0x0bad);
            assert_eq!(m.queries.len(), 1);
        }
        let ev = sub.try_recv().unwrap();
        assert_eq!(
            (ev.source, ev.filter, ev.rcode.as_str()),
            ("error", "boom", "Server Failure")
        );
        assert_eq!(s.stats.errors.load(Relaxed), 2);
        let probes = &s.filter_stats.counts[15];
        assert_eq!(probes[PANICKED].load(Relaxed), 2);
        // The server keeps answering.
        with_chain(
            &s,
            vec![probe("ok", Act::Answer(ResponseCode::NoError), None, &log)],
        );
        let m = ask(&s, 3, Proto::Udp).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    }

    /// The default chain is the documented one; the open resolver filter is
    /// in it only while that mode is in effect. Counters per filter.
    #[tokio::test]
    async fn the_default_chain_and_its_counters() {
        let s = server();
        let names = |s: &DnsServer| -> Vec<&'static str> {
            s.runtime.load().chain.iter().map(Filter::name).collect()
        };
        // Defaults: domain_needed and bogus_priv on (I2, I3).
        assert_eq!(
            names(&s),
            vec![
                "edns",
                "request",
                "special",
                "transfer",
                "authoritative",
                "override",
                "recursion",
                "domain_needed",
                "bogus_priv",
                "forward"
            ]
        );
        let mut cfg = crate::config::Config::default();
        cfg.forwarding.upstreams = vec!["192.0.2.53:53".parse().unwrap()];
        cfg.forwarding.open_resolver = true;
        s.reload(&cfg);
        assert!(names(&s).contains(&"open_resolver"));
        // Every resolver filter switched on, in the documented order.
        s.set_resolver(
            Some(ResolverSettings {
                rebind_protection: true,
                serve_stale: true,
                filter_types: vec!["AAAA".into()],
                ..Default::default()
            }),
            &cfg,
        );
        assert_eq!(
            names(&s),
            vec![
                "edns",
                "request",
                "special",
                "transfer",
                "authoritative",
                "override",
                "recursion",
                "domain_needed",
                "bogus_priv",
                "filter_types",
                "open_resolver",
                "rebind",
                "serve_stale",
                "forward"
            ]
        );
        // Switched off: absent (the chain is rebuilt at once).
        s.set_resolver(
            Some(ResolverSettings {
                domain_needed: false,
                bogus_priv: false,
                ..Default::default()
            }),
            &cfg,
        );
        assert!(!names(&s).contains(&"domain_needed") && !names(&s).contains(&"bogus_priv"));
        s.set_resolver(None, &cfg);
        s.reload(&crate::config::Config::default());
        // A name in no zone, from a client that may not recurse: passed by
        // everything up to `recursion`, which refuses it.
        let sub = s.bus.subscribe_queries().unwrap();
        let m = ask(&s, 9, Proto::Udp).await.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
        let ev = sub.try_recv().unwrap();
        assert_eq!((ev.source, ev.filter), ("refused", "recursion"));
        let st = s.pipeline_status();
        let get = |n: &str| st.iter().find(|f| f.name == n).unwrap().clone();
        assert_eq!(get("edns").passed, 1);
        assert_eq!(get("authoritative").passed, 1);
        assert_eq!(
            (get("recursion").answered, get("recursion").handled),
            (1, 1)
        );
        assert_eq!(get("forward").handled, 0);
    }
}
