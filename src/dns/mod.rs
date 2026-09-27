//! DNS front-end: UDP and TCP listeners feeding one query handler.

pub mod axfr;
pub mod cookies;
pub mod forward;
pub mod fwdcache;
pub mod handler;
pub mod keyring;
pub mod notify;
pub mod tcp;
pub mod tsig;
pub mod udp;

use crate::cache::Cache;
use crate::config::{Cidr, Config, ForwardingConfig, ProxyConfig, ServerConfig};
use crate::events::Bus;
use crate::mutation::settings::ForwardingSettings;
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
    pub truncated: AtomicU64,
    pub bad_cookie: AtomicU64,
    pub transfers: AtomicU64,
    pub notifies: AtomicU64,
    pub tsig_errors: AtomicU64,
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
            truncated: self.truncated.load(Relaxed),
            bad_cookie: self.bad_cookie.load(Relaxed),
            transfers: self.transfers.load(Relaxed),
            notifies: self.notifies.load(Relaxed),
            tsig_errors: self.tsig_errors.load(Relaxed),
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
}

/// Settings that can change at runtime via config reload.
pub struct Runtime {
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
}

impl Runtime {
    /// Runtime settings from the config file, with the console/API forwarding
    /// override (if any) replacing upstreams, allowed clients and timeout.
    pub fn from_config(cfg: &Config, forwarding_override: Option<&ForwardingSettings>) -> Self {
        let mut forwarding = cfg.forwarding.clone();
        if let Some(o) = forwarding_override {
            forwarding.upstreams = o.upstreams.clone();
            forwarding.allowed_clients = o.allowed_clients.clone();
            forwarding.timeout_ms = o.timeout_ms;
        }
        Runtime {
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
        }
    }

    pub fn may_forward(&self, client: std::net::IpAddr) -> bool {
        !self.forwarding.upstreams.is_empty() && self.forward_acl.iter().any(|c| c.contains(client))
    }

    pub fn may_transfer(&self, client: std::net::IpAddr) -> bool {
        self.transfer_allow.iter().any(|c| c.contains(client))
    }
}

pub struct DnsServer {
    pub cache: Arc<Cache>,
    pub bus: Arc<Bus>,
    pub limiter: Arc<RateLimiter>,
    /// Listener settings (fixed for the process lifetime).
    pub listen: ServerConfig,
    pub tcp_proxy: ProxyConfig,
    pub tcp_proxy_trust: Vec<Cidr>,
    pub runtime: ArcSwap<Runtime>,
    pub stats: Arc<Stats>,
    pub tcp_slots: Arc<tokio::sync::Semaphore>,
    pub cookies: cookies::CookieJar,
    pub fwd_cache: fwdcache::ForwardCache,
    /// TSIG keys (from the database), swapped whole after every change.
    pub tsig_keys: ArcSwap<keyring::Keyring>,
    /// Forwarding settings set from the console/API; override the config file.
    forwarding_override: std::sync::RwLock<Option<ForwardingSettings>>,
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
            listen: cfg.server.clone(),
            tcp_proxy: cfg.tcp_dns.clone(),
            tcp_proxy_trust: cfg.tcp_dns.trusted_cidrs(),
            runtime: ArcSwap::from_pointee(Runtime::from_config(cfg, None)),
            stats: Arc::new(Stats::default()),
            tcp_slots,
            cookies: cookies::CookieJar::new(),
            fwd_cache: fwdcache::ForwardCache::new(cfg.forwarding.cache_entries),
            tsig_keys: ArcSwap::from_pointee(keyring::Keyring::default()),
            forwarding_override: std::sync::RwLock::new(None),
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
        let next = Runtime::from_config(cfg, o.as_ref());
        let old = self.runtime.load();
        if old.forwarding.upstreams != next.forwarding.upstreams {
            self.fwd_cache.clear();
        }
        self.runtime.store(Arc::new(next));
        self.limiter.reconfigure(
            cfg.rate_limit.max_resolutions_per_second_per_address,
            cfg.rate_limit.max_tracked_addresses,
        );
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

/// Bind all configured listeners and run them until the process exits.
pub async fn serve(server: Arc<DnsServer>) -> anyhow::Result<()> {
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
