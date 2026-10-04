//! DNS front-end: UDP and TCP listeners feeding one query handler.

pub mod axfr;
pub mod cookies;
pub mod filters;
pub mod forward;
pub mod fwdcache;
pub mod handler;
pub mod ifaces;
pub mod keyring;
pub mod notify;
pub mod pipeline;
pub mod tcp;
pub mod tsig;
pub mod udp;

use crate::cache::Cache;
use crate::config::{Cidr, Config, ForwardingConfig, ProxyConfig, ServerConfig};
use crate::events::Bus;
use crate::mutation::settings::{ForwardingSettings, ResolverSettings};
use crate::ratelimit::RateLimiter;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub udp: AtomicU64,
    pub tcp: AtomicU64,
    pub authoritative: AtomicU64,
    pub forwarded: AtomicU64,
    pub cache_hits: AtomicU64,
    pub refused: AtomicU64,
    pub nxdomain: AtomicU64,
    pub errors: AtomicU64,
    pub rate_limited: AtomicU64,
    /// O15: over-limit UDP queries answered because of a valid server cookie.
    pub rate_limit_cookie_exempt: AtomicU64,
    pub truncated: AtomicU64,
    pub bad_cookie: AtomicU64,
    pub transfers: AtomicU64,
    pub notifies: AtomicU64,
    pub tsig_errors: AtomicU64,
    /// Open resolver: forwarded UDP answers truncated by the payload cap.
    pub open_resolver_truncated: AtomicU64,
    /// Open resolver: ANY queries not forwarded (answered minimally).
    pub open_resolver_any: AtomicU64,
    /// Open resolver: forwarded queries over the per-client limit.
    pub open_resolver_rate_limited: AtomicU64,
    /// Queries not forwarded because `[forwarding].max_inflight` forwarded
    /// queries were already waiting for an upstream.
    pub forward_overflow: AtomicU64,
    /// Forwarded queries waiting for an upstream right now.
    pub forward_inflight: std::sync::atomic::AtomicUsize,
    /// When the overflow warning was last logged (seconds since the epoch).
    pub forward_overflow_warned: AtomicU64,
    /// Stale cache entries served because every upstream failed (I5).
    pub stale_answers: AtomicU64,
    /// Latency histogram buckets in microseconds: <=100, <=500, <=1000, <=5000, <=20000, >20000
    pub latency: [AtomicU64; 6],
    pub latency_sum_us: AtomicU64,
}

pub const LATENCY_BOUNDS_US: [u64; 5] = [100, 500, 1000, 5000, 20000];

impl Stats {
    pub fn observe_latency(&self, us: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let idx = LATENCY_BOUNDS_US.iter().position(|b| us <= *b).unwrap_or(5);
        self.latency[idx].fetch_add(1, Relaxed);
        self.latency_sum_us.fetch_add(us, Relaxed);
    }

    pub fn snapshot(&self) -> DnsCounters {
        use std::sync::atomic::Ordering::Relaxed;
        DnsCounters {
            queries: self.queries.load(Relaxed),
            udp: self.udp.load(Relaxed),
            tcp: self.tcp.load(Relaxed),
            authoritative: self.authoritative.load(Relaxed),
            forwarded: self.forwarded.load(Relaxed),
            cache_hits: self.cache_hits.load(Relaxed),
            refused: self.refused.load(Relaxed),
            nxdomain: self.nxdomain.load(Relaxed),
            errors: self.errors.load(Relaxed),
            rate_limited: self.rate_limited.load(Relaxed),
            rate_limit_cookie_exempt: self.rate_limit_cookie_exempt.load(Relaxed),
            truncated: self.truncated.load(Relaxed),
            bad_cookie: self.bad_cookie.load(Relaxed),
            transfers: self.transfers.load(Relaxed),
            notifies: self.notifies.load(Relaxed),
            tsig_errors: self.tsig_errors.load(Relaxed),
            open_resolver_truncated: self.open_resolver_truncated.load(Relaxed),
            open_resolver_any: self.open_resolver_any.load(Relaxed),
            open_resolver_rate_limited: self.open_resolver_rate_limited.load(Relaxed),
            forward_overflow: self.forward_overflow.load(Relaxed),
            stale_answers: self.stale_answers.load(Relaxed),
        }
    }
}

/// DNS counters since start.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct DnsCounters {
    /// Queries received.
    pub queries: u64,
    /// Queries over UDP.
    pub udp: u64,
    /// Queries over TCP.
    pub tcp: u64,
    /// Authoritative answers.
    pub authoritative: u64,
    /// Answers forwarded to an upstream resolver.
    pub forwarded: u64,
    /// Forwarded answers served from the cache.
    pub cache_hits: u64,
    /// REFUSED answers.
    pub refused: u64,
    /// NXDOMAIN answers.
    pub nxdomain: u64,
    /// Malformed or failed queries.
    pub errors: u64,
    /// Queries dropped by rate limiting.
    pub rate_limited: u64,
    /// Over-limit UDP queries answered anyway because they carried a valid
    /// server cookie (`exempt_valid_cookies`, O15).
    pub rate_limit_cookie_exempt: u64,
    /// UDP responses truncated.
    pub truncated: u64,
    /// Requests with an invalid or malformed DNS cookie.
    pub bad_cookie: u64,
    /// Zone transfers (AXFR) served.
    pub transfers: u64,
    /// NOTIFY messages sent.
    pub notifies: u64,
    /// Signed requests rejected (unknown key, bad signature, clock skew, truncated MAC).
    pub tsig_errors: u64,
    /// Open resolver mode: forwarded UDP answers sent truncated because they
    /// exceeded `[forwarding].open_resolver_max_udp_payload`.
    pub open_resolver_truncated: u64,
    /// Open resolver mode: ANY queries for foreign names answered with the
    /// minimal RFC 8482 HINFO instead of being forwarded.
    pub open_resolver_any: u64,
    /// Open resolver mode: forwarded queries over
    /// `[forwarding].open_resolver_rate_per_second` for their client.
    pub open_resolver_rate_limited: u64,
    /// Queries not forwarded (UDP dropped, TCP SERVFAIL) because
    /// `[forwarding].max_inflight` forwarded queries were already waiting
    /// for an upstream.
    pub forward_overflow: u64,
    /// Stale cache entries served because every upstream failed (serve
    /// stale, RFC 8767).
    pub stale_answers: u64,
}

/// Settings that can change at runtime via config reload.
pub struct Runtime {
    /// Forwarding settings in effect; `forwarding.open_resolver` is the
    /// effective open resolver mode (see [`Runtime::from_config`]).
    pub forwarding: ForwardingConfig,
    pub forward_acl: Vec<Cidr>,
    pub transfer_allow: Vec<Cidr>,
    /// Transfers need a valid TSIG signature as well as an allowed address.
    pub require_tsig: bool,
    /// NOTIFY targets and the key that signs each (None = unsigned).
    pub notify: Vec<(SocketAddr, Option<String>)>,
    pub auto_ptr: bool,
    pub minimal_any: bool,
    pub udp_max_payload: u16,
    pub nsid: String,
    pub cookies: bool,
    pub cookies_required: bool,
    /// Resolver behaviour for forwarded queries (console settings, I2-I10).
    pub resolver: ResolverSettings,
    /// `resolver.filter_types` parsed.
    pub filter_types: Vec<hickory_proto::rr::RecordType>,
    /// A blocklist is switched on (the `blocklist` filter is in the chain).
    pub blocklists: bool,
    /// The query pipeline's filter chain for this snapshot (see
    /// [`pipeline::chain_for`]); replaced together with everything above.
    pub chain: Vec<pipeline::Filter>,
}

impl Runtime {
    /// Runtime settings from the config file, with the console/API forwarding
    /// override (if any) replacing upstreams, allowed clients and timeout.
    pub fn from_config(cfg: &Config, forwarding_override: Option<&ForwardingSettings>) -> Self {
        Self::with_settings(
            cfg,
            forwarding_override,
            &ResolverSettings::default(),
            false,
        )
    }

    /// Runtime settings from the config file and every console setting.
    pub fn with_settings(
        cfg: &Config,
        forwarding_override: Option<&ForwardingSettings>,
        resolver: &ResolverSettings,
        blocklists: bool,
    ) -> Self {
        let mut forwarding = cfg.forwarding.clone();
        if let Some(o) = forwarding_override {
            forwarding.upstreams = o.upstreams.clone();
            forwarding.allowed_clients = o.allowed_clients.clone();
            forwarding.timeout_ms = o.timeout_ms;
            if let Some(t) = o.cache_max_ttl {
                forwarding.cache_max_ttl = t;
            }
            if let Some(t) = o.cache_negative_max_ttl {
                forwarding.cache_negative_max_ttl = t;
            }
            if let Some(b) = o.open_resolver {
                forwarding.open_resolver = b;
            }
        }
        // Defence in depth: an ACL the guard would refuse always gets the
        // open-resolver safeguards, however it came to be in effect.
        if !forwarding.open_resolver
            && !crate::config::open_resolver_problems(&forwarding.allowed_clients).is_empty()
        {
            forwarding.open_resolver = true;
        }
        let mut rt = Runtime {
            forward_acl: crate::config::parse_cidrs(&forwarding.allowed_clients),
            forwarding,
            transfer_allow: crate::config::parse_cidrs(&cfg.transfer.allow),
            require_tsig: cfg.transfer.require_tsig,
            notify: cfg.transfer.notify_targets(),
            auto_ptr: cfg.server.auto_ptr,
            minimal_any: cfg.server.minimal_any,
            udp_max_payload: cfg.server.udp_max_payload.max(512),
            nsid: cfg.server.nsid.clone(),
            cookies: cfg.server.cookies,
            cookies_required: cfg.server.cookies_required,
            filter_types: resolver
                .filter_types
                .iter()
                .filter_map(|t| crate::mutation::settings::parse_filter_type(t).ok())
                .collect(),
            resolver: resolver.clone(),
            blocklists,
            chain: Vec::new(),
        };
        rt.chain = pipeline::chain_for(&rt);
        rt
    }

    pub fn may_forward(&self, client: std::net::IpAddr) -> bool {
        !self.forwarding.upstreams.is_empty() && self.forward_acl.iter().any(|c| c.contains(client))
    }

    /// Open resolver mode is in effect (with forwarding on at all).
    pub fn open_resolver(&self) -> bool {
        self.forwarding.open_resolver && !self.forwarding.upstreams.is_empty()
    }

    pub fn cache_caps(&self) -> fwdcache::Caps {
        fwdcache::Caps {
            max_ttl: self.forwarding.cache_max_ttl,
            negative_max_ttl: self.forwarding.cache_negative_max_ttl,
            stale_secs: if self.resolver.serve_stale {
                self.resolver.max_stale_age_secs
            } else {
                0
            },
        }
    }

    pub fn may_transfer(&self, client: std::net::IpAddr) -> bool {
        self.transfer_allow.iter().any(|c| c.contains(client))
    }
}

pub struct DnsServer {
    pub cache: Arc<Cache>,
    pub bus: Arc<Bus>,
    pub limiter: Arc<RateLimiter>,
    /// O15: over-limit UDP queries with a valid server cookie are answered
    /// (effective `exempt_valid_cookies`, with cookies on).
    pub cookie_exempt: std::sync::atomic::AtomicBool,
    /// O15: rate limiting set from the console (defaults: the file's).
    rate_limit: std::sync::RwLock<crate::mutation::settings::RateLimitSettings>,
    /// Open resolver mode: per-client limit on forwarded queries.
    pub fwd_limiter: RateLimiter,
    /// Listener settings (fixed for the process lifetime).
    pub listen: ServerConfig,
    pub tcp_proxy: ProxyConfig,
    pub tcp_proxy_trust: Vec<Cidr>,
    pub runtime: ArcSwap<Runtime>,
    pub stats: Arc<Stats>,
    /// Per-filter counters of the query pipeline.
    pub filter_stats: pipeline::FilterStats,
    pub tcp_slots: Arc<tokio::sync::Semaphore>,
    /// Open TCP connections per client (IPv4 address / IPv6 /64).
    pub tcp_per_client: Arc<tcp::PerClient>,
    pub cookies: cookies::CookieJar,
    pub fwd_cache: fwdcache::ForwardCache,
    /// TSIG keys (from the database), swapped whole after every change.
    pub tsig_keys: ArcSwap<keyring::Keyring>,
    /// M3: the newest Time Signed per key (replay protection, this server only).
    pub tsig_replay: tsig::ReplayGuard,
    /// Forwarding settings set from the console/API; override the config file.
    forwarding_override: std::sync::RwLock<Option<ForwardingSettings>>,
    /// Resolver settings set from the console/API (defaults when unset).
    resolver: std::sync::RwLock<ResolverSettings>,
    /// Health of every upstream (global and override zones), I6.
    pub upstream_health: forward::Health,
    /// Downloaded blocklists (I7; per server).
    pub blocklists: Arc<crate::blocklist::Blocklists>,
    /// Forwarded answers refused by rebinding protection, by name (I4).
    pub rebind_log: filters::RebindLog,
    /// Followed interfaces and their bound addresses (I11).
    pub interfaces: ifaces::Follower,
}

/// What the handler wants sent back.
pub enum Reply {
    /// Send nothing (rate limited, garbage, or a response mistaken for a query).
    None,
    One(Vec<u8>),
    /// Several length-prefixed messages (AXFR over TCP).
    Many(Vec<Vec<u8>>),
}

impl DnsServer {
    pub fn new(cache: Arc<Cache>, bus: Arc<Bus>, limiter: Arc<RateLimiter>, cfg: &Config) -> Self {
        let tcp_slots = Arc::new(tokio::sync::Semaphore::new(
            cfg.server.max_tcp_connections.max(1),
        ));
        DnsServer {
            cache,
            bus,
            limiter,
            cookie_exempt: std::sync::atomic::AtomicBool::new(
                cfg.rate_limit.exempt_valid_cookies && cfg.server.cookies,
            ),
            rate_limit: std::sync::RwLock::new(Default::default()),
            fwd_limiter: {
                let l = RateLimiter::new(
                    cfg.forwarding.open_resolver_rate_per_second,
                    std::time::Duration::from_secs(1),
                    fwd_limiter_size(&Runtime::from_config(cfg, None), cfg),
                );
                l.set_slip(cfg.rate_limit.slip);
                l
            },
            listen: cfg.server.clone(),
            tcp_proxy: cfg.tcp_dns.clone(),
            tcp_proxy_trust: cfg.tcp_dns.trusted_cidrs(),
            runtime: ArcSwap::from_pointee(Runtime::from_config(cfg, None)),
            stats: Arc::new(Stats::default()),
            filter_stats: pipeline::FilterStats::default(),
            tcp_slots,
            tcp_per_client: Arc::new(tcp::PerClient::default()),
            cookies: cookies::CookieJar::new(),
            fwd_cache: fwdcache::ForwardCache::new(cfg.forwarding.cache_entries),
            tsig_keys: ArcSwap::from_pointee(keyring::Keyring::default()),
            tsig_replay: tsig::ReplayGuard::default(),
            forwarding_override: std::sync::RwLock::new(None),
            resolver: std::sync::RwLock::new(ResolverSettings::default()),
            upstream_health: forward::Health::default(),
            blocklists: Arc::new(crate::blocklist::Blocklists::default()),
            rebind_log: filters::RebindLog::default(),
            interfaces: ifaces::Follower::default(),
        }
    }

    /// Replace (or clear) the console/API forwarding override and apply it now.
    pub fn set_forwarding_override(&self, o: Option<ForwardingSettings>, cfg: &Config) {
        *self
            .forwarding_override
            .write()
            .unwrap_or_else(|p| p.into_inner()) = o;
        self.reload(cfg);
    }

    /// Replace the resolver settings (`None`: the defaults) and apply them now.
    pub fn set_resolver(&self, r: Option<ResolverSettings>, cfg: &Config) {
        *self.resolver.write().unwrap_or_else(|p| p.into_inner()) = r.unwrap_or_default();
        self.reload(cfg);
    }

    /// O15: replace the console rate-limit settings (`None`: the file's)
    /// and apply them now.
    pub fn set_rate_limit(
        &self,
        r: Option<crate::mutation::settings::RateLimitSettings>,
        cfg: &Config,
    ) {
        *self.rate_limit.write().unwrap_or_else(|p| p.into_inner()) = r.unwrap_or_default();
        self.reload(cfg);
    }

    /// O15: the rate limiting in effect (console settings over the file).
    pub fn rate_limit_in_effect(&self, cfg: &Config) -> crate::config::RateLimitConfig {
        self.rate_limit
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .effective(&cfg.rate_limit)
    }

    pub fn resolver(&self) -> ResolverSettings {
        self.resolver
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replace the blocklist configuration (`None`: none) and apply it now.
    pub fn set_blocklists(&self, b: Option<crate::blocklist::BlocklistSettings>, cfg: &Config) {
        self.blocklists.configure(b.unwrap_or_default());
        self.reload(cfg);
    }

    /// Load every console setting from the database and apply it (startup;
    /// a standby after replicated changes). An unreadable setting is
    /// logged and left at its previous value.
    pub fn load_console_settings(&self, storage: &crate::storage::Storage, cfg: &Config) {
        use crate::mutation::settings as st;
        match st::load_forwarding(storage) {
            Ok(o) => {
                *self
                    .forwarding_override
                    .write()
                    .unwrap_or_else(|p| p.into_inner()) = o.map(|(f, _, _)| f)
            }
            Err(e) => tracing::error!(error = %e, "stored forwarding settings are unreadable"),
        }
        match st::load_resolver(storage) {
            Ok(o) => {
                *self.resolver.write().unwrap_or_else(|p| p.into_inner()) =
                    o.map(|(r, _, _)| r).unwrap_or_default()
            }
            Err(e) => tracing::error!(error = %e, "stored resolver settings are unreadable"),
        }
        match st::load_blocklists(storage) {
            Ok(o) => {
                let next = o.map(|(b, _, _)| b).unwrap_or_default();
                if next != self.blocklists.settings() {
                    self.blocklists.configure(next);
                }
            }
            Err(e) => tracing::error!(error = %e, "stored blocklist settings are unreadable"),
        }
        match st::load_rate_limit(storage) {
            Ok(o) => {
                *self.rate_limit.write().unwrap_or_else(|p| p.into_inner()) =
                    o.map(|(r, _, _)| r).unwrap_or_default()
            }
            Err(e) => tracing::error!(error = %e, "stored rate-limit settings are unreadable"),
        }
        self.reload(cfg);
    }

    /// Reload the TSIG keyring from the database (startup and after each change).
    pub fn reload_tsig_keys(&self, storage: &crate::storage::Storage) -> anyhow::Result<()> {
        let ring = keyring::Keyring::load(storage)?;
        tracing::debug!(keys = ring.len(), "TSIG keyring loaded");
        self.tsig_keys.store(Arc::new(ring));
        Ok(())
    }

    /// Human-readable problems with the transfer settings in effect (keys
    /// named in the config that do not exist, TSIG required without keys).
    pub fn transfer_warnings(&self) -> Vec<String> {
        let rt = self.runtime.load();
        let ring = self.tsig_keys.load();
        let mut out = Vec::new();
        let mut missing: Vec<&str> = rt
            .notify
            .iter()
            .filter_map(|(_, k)| k.as_deref())
            .filter(|k| ring.get(k).is_none())
            .collect();
        missing.sort();
        missing.dedup();
        for k in missing {
            out.push(format!(
                "[transfer] names TSIG key '{k}' for NOTIFY but no such key exists; NOTIFY to those targets is not sent until it is created"
            ));
        }
        if rt.require_tsig && ring.is_empty() && !rt.transfer_allow.is_empty() {
            out.push("[transfer].require_tsig is on but no TSIG keys exist; every zone transfer is refused".into());
        }
        out
    }

    pub fn forwarding_override(&self) -> Option<ForwardingSettings> {
        self.forwarding_override
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Apply a reloaded configuration to everything that can change at runtime.
    /// A console/API forwarding override keeps precedence over the file.
    pub fn reload(&self, cfg: &Config) {
        let o = self.forwarding_override();
        let next = Runtime::with_settings(
            cfg,
            o.as_ref(),
            &self.resolver(),
            self.blocklists.settings().active(),
        );
        let old = self.runtime.load();
        if old.forwarding.upstreams != next.forwarding.upstreams {
            self.fwd_cache.clear();
        }
        match (old.open_resolver(), next.open_resolver()) {
            (false, true) => tracing::warn!(
                allowed_clients = ?next.forwarding.allowed_clients,
                "open resolver mode is now ON"
            ),
            (true, false) => tracing::info!("open resolver mode is now off"),
            _ => {}
        }
        self.fwd_limiter.reconfigure(
            cfg.forwarding.open_resolver_rate_per_second,
            fwd_limiter_size(&next, cfg),
        );
        let rl = self.rate_limit_in_effect(cfg);
        self.fwd_limiter.set_slip(rl.slip);
        self.cookie_exempt.store(
            rl.exempt_valid_cookies && next.cookies,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.runtime.store(Arc::new(next));
        self.limiter.reconfigure(
            rl.max_resolutions_per_second_per_address,
            rl.max_tracked_addresses,
        );
        self.limiter.set_slip(rl.slip);
    }

    /// Loud warnings while open resolver mode is in effect (startup, reload).
    pub fn open_resolver_warnings(&self) -> Vec<String> {
        let rt = self.runtime.load();
        if !rt.forwarding.open_resolver {
            return Vec::new();
        }
        crate::config::open_resolver_warnings(&rt.forwarding)
    }
}

/// Counter table size of the open-resolver forwarding limiter: the
/// `[rate_limit]` size while the mode is in effect, a token table otherwise
/// (it is not consulted then; resizing starts it empty).
fn fwd_limiter_size(rt: &Runtime, cfg: &Config) -> usize {
    if rt.open_resolver() {
        cfg.rate_limit.max_tracked_addresses
    } else {
        1
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
}

/// A UDP socket for DNS (inside the runtime).
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let s = std::net::UdpSocket::bind(addr)?;
    s.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(s)
}

/// A TCP listener for DNS (inside the runtime).
pub fn bind_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let l = std::net::TcpListener::bind(addr)?;
    l.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(l)
}

/// Bind all configured listeners and run them until the process exits.
/// With `[server].interfaces`, the listeners follow those interfaces'
/// addresses instead ([`ifaces::follow`]).
pub async fn serve(server: Arc<DnsServer>) -> anyhow::Result<()> {
    if !server.listen.interfaces.is_empty() {
        tracing::info!(interfaces = ?server.listen.interfaces, "DNS listeners follow these interfaces' addresses");
        ifaces::follow(server).await;
        return Ok(());
    }
    let mut tasks = Vec::new();
    let mut bound = 0;
    for ip in &server.listen.bind {
        let addr = std::net::SocketAddr::new(*ip, server.listen.port);
        if server.listen.udp {
            match tokio::net::UdpSocket::bind(addr).await {
                Ok(sock) => {
                    tracing::info!(%addr, "listening for DNS over UDP");
                    bound += 1;
                    tasks.push(tokio::spawn(udp::run(server.clone(), Arc::new(sock))));
                }
                Err(e) => tracing::error!(%addr, error = %e, "cannot bind UDP"),
            }
        }
        if server.listen.tcp {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    tracing::info!(%addr, proxy_on = server.tcp_proxy.proxy_on, "listening for DNS over TCP");
                    bound += 1;
                    tasks.push(tokio::spawn(tcp::run(server.clone(), l)));
                }
                Err(e) => tracing::error!(%addr, error = %e, "cannot bind TCP"),
            }
        }
    }
    if bound == 0 {
        anyhow::bail!("no DNS listener could be bound (port {} - try running as root or change [server].port)", server.listen.port);
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(acl: &[&str], open: Option<bool>) -> ForwardingSettings {
        ForwardingSettings {
            upstreams: vec!["192.0.2.1:53".parse().unwrap()],
            allowed_clients: acl.iter().map(|s| s.to_string()).collect(),
            timeout_ms: 1000,
            cache_max_ttl: None,
            cache_negative_max_ttl: None,
            open_resolver: open,
        }
    }

    /// Effective open resolver mode: the override's explicit value, else the
    /// file's; a wide ACL always gets the safeguards.
    #[test]
    fn open_resolver_mode_in_effect() {
        let mut cfg: Config = toml::from_str("").unwrap();
        let rt = Runtime::from_config(&cfg, None);
        assert!(!rt.forwarding.open_resolver && !rt.open_resolver());
        let rt = Runtime::from_config(&cfg, Some(&fwd(&["10.0.0.0/8"], None)));
        assert!(!rt.open_resolver());
        let rt = Runtime::from_config(&cfg, Some(&fwd(&["0.0.0.0/0"], Some(true))));
        assert!(rt.open_resolver());
        // Old override (no field): the file decides.
        cfg.forwarding.open_resolver = true;
        let rt = Runtime::from_config(&cfg, Some(&fwd(&["10.0.0.0/8"], None)));
        assert!(rt.open_resolver());
        let rt = Runtime::from_config(&cfg, Some(&fwd(&["10.0.0.0/8"], Some(false))));
        assert!(!rt.open_resolver());
        // Without upstreams nothing is forwarded, so nothing is open.
        let rt = Runtime::from_config(&cfg, None);
        assert!(rt.forwarding.open_resolver && !rt.open_resolver());
        // Defence in depth: a wide ACL never runs without the safeguards.
        cfg.forwarding.open_resolver = false;
        let rt = Runtime::from_config(&cfg, Some(&fwd(&["0.0.0.0/1", "128.0.0.0/1"], Some(false))));
        assert!(rt.open_resolver());
    }
}
