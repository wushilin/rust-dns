//! TOML configuration. See `rust-dns.toml` written on first start.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub server: ServerConfig,
    pub forwarding: ForwardingConfig,
    pub transfer: TransferConfig,
    pub rate_limit: RateLimitConfig,
    pub database: DatabaseConfig,
    pub backup: BackupConfig,
    pub tcp_dns: ProxyConfig,
    pub web_console: WebConfig,
    pub root: RootConfig,
    pub changelog: ChangelogConfig,
    pub expiry: ExpiryConfig,
    pub dnssec: DnssecConfig,
    pub logging: LoggingConfig,
    /// Standby mode: mirror another rust-dns (the primary) and refuse
    /// mutations. Absent = this server is a primary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow: Option<FollowConfig>,
    /// On a primary: the standby to ask, at startup and periodically,
    /// whether it has been promoted away from this server's history (then
    /// this server stays read-only instead of accepting writes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerConfig>,
    /// Primary side: how standbys (replicas) are judged and remembered.
    pub replication: ReplicationConfig,
}

/// `[replication]`: thresholds for the replica states shown on a primary
/// (reloadable).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplicationConfig {
    /// A replica that was caught up this recently still counts as up to date.
    pub up_to_date_grace_secs: u64,
    /// More changes behind than this: falling behind.
    pub max_lag_changes: u64,
    /// Not caught up for longer than this: falling behind.
    pub max_lag_secs: u64,
    /// No request for this long: offline (a standby polls at least every 25 s).
    pub offline_after_secs: u64,
    /// Forget replicas not seen for this many days.
    pub forget_after_days: u32,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        ReplicationConfig {
            up_to_date_grace_secs: 10,
            max_lag_changes: 1000,
            max_lag_secs: 60,
            offline_after_secs: 75,
            forget_after_days: 30,
        }
    }
}

/// `[follow]`: this server is a read-only standby of `primary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FollowConfig {
    /// Base URL of the primary's web API, e.g. `https://dns1.example.net:8053`.
    pub primary: String,
    /// This standby's name as the primary shows it (required; 1-63 of
    /// a-z, 0-9, '-', like a host name label). Must be unique per primary.
    pub instance_id: String,
    /// API token of an administrator on the primary (`rdns_...`).
    pub token: String,
    /// How often zone serials/checksums and the account data are compared
    /// with the primary; a mismatch re-bootstraps from a snapshot.
    pub reconcile_interval_secs: u64,
    /// Allow a plain `http://` primary URL. The replication stream carries
    /// password hashes, TOTP secrets and TSIG secrets, so this is refused
    /// unless set (loopback addresses are always allowed, for tests).
    pub allow_insecure_http: bool,
    /// Timeout of one request to the primary (the snapshot gets at least 120 s).
    pub timeout_secs: u64,
}

impl Default for FollowConfig {
    fn default() -> Self {
        FollowConfig {
            primary: String::new(),
            instance_id: String::new(),
            token: String::new(),
            reconcile_interval_secs: 3600,
            allow_insecure_http: false,
            timeout_secs: 30,
        }
    }
}

/// `[peer]`: fencing check on a primary (see [`Config::peer`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerConfig {
    /// Base URL of the standby's web API.
    pub url: String,
    pub check_interval_secs: u64,
    pub allow_insecure_http: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        PeerConfig {
            url: String::new(),
            check_interval_secs: 60,
            allow_insecure_http: false,
        }
    }
}

/// Problems with a replication URL (`key` names it in messages).
pub fn replication_url_problems(key: &str, url: &str, allow_insecure_http: bool) -> Vec<String> {
    let mut errs = Vec::new();
    let u = match reqwest::Url::parse(url.trim()) {
        Ok(u) => u,
        Err(e) => {
            errs.push(format!(
                "{key} '{url}' is not a URL ({e}); example: https://dns1.example.net:8053"
            ));
            return errs;
        }
    };
    match u.scheme() {
        "https" => {}
        "http" => {
            if !allow_insecure_http && !url_is_loopback(&u) {
                errs.push(format!(
                    "{key} '{url}' uses plain http: replication carries password hashes, TOTP and TSIG secrets; use https (set allow_insecure_http = true only on a trusted network)"
                ));
            }
        }
        other => errs.push(format!("{key} '{url}': scheme must be https (got {other})")),
    }
    if u.host_str().is_none_or(|h| h.is_empty()) {
        errs.push(format!("{key} '{url}' has no host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        errs.push(format!(
            "{key} must not contain credentials (use the token setting)"
        ));
    }
    if u.query().is_some() || u.fragment().is_some() {
        errs.push(format!("{key} '{url}' must not have a query or fragment"));
    }
    errs
}

/// `localhost` or a loopback address.
pub fn url_is_loopback(u: &reqwest::Url) -> bool {
    let Some(h) = u.host_str() else { return false };
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost") || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Records with `expires_at`: stop answering at expiry, deleted after the retention period.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExpiryConfig {
    /// Days an expired record is kept (visible in the console, not served) before deletion.
    pub retention_days: u32,
    /// Longest the sweeper sleeps; it also wakes exactly at the next due expiry.
    pub sweep_interval_secs: u64,
}

impl Default for ExpiryConfig {
    fn default() -> Self {
        ExpiryConfig {
            retention_days: 30,
            sweep_interval_secs: 60,
        }
    }
}

/// `[dnssec]`: online signing of the zones that have DNSSEC turned on
/// (per zone, in the console or API). Reloadable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnssecConfig {
    /// Validity of every signature (RRSIG), counted from one hour before
    /// the zone's last change (clock-skew margin).
    pub signature_validity_days: u32,
    /// The primary re-signs a zone (a serial bump, so secondaries transfer
    /// fresh signatures) when its signatures expire within this many days.
    pub resign_before_days: u32,
    /// Key rollover (N1): how often the primary asks the parent's servers
    /// while it waits for a DS change, seconds.
    pub rollover_check_secs: u64,
    /// Testing only: cap every rollover wait (DNSKEY and DS TTLs) at this
    /// many seconds. 0 = the real TTLs (always, in production).
    pub rollover_max_wait_secs: u64,
    /// Testing only: the port the parent's name servers are asked on.
    pub parent_port: u16,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        DnssecConfig {
            signature_validity_days: 14,
            resign_before_days: 7,
            rollover_check_secs: 300,
            rollover_max_wait_secs: 0,
            parent_port: 53,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Addresses to listen on for DNS. `::` covers IPv4 too on most systems.
    pub bind: Vec<IpAddr>,
    pub port: u16,
    pub udp: bool,
    pub tcp: bool,
    /// Largest UDP payload we advertise and send (EDNS). 1232 is the safe default.
    pub udp_max_payload: u16,
    /// Synthesize PTR answers from A/AAAA records when no explicit PTR exists.
    pub auto_ptr: bool,
    /// Idle timeout for TCP connections, seconds (also bounds each read).
    pub tcp_idle_timeout_secs: u64,
    /// Longest a single TCP write may take, seconds. A client that stops
    /// reading is disconnected after this (each AXFR message is one write).
    pub tcp_write_timeout_secs: u64,
    /// No new query is read on a TCP connection older than this, seconds.
    pub tcp_max_connection_secs: u64,
    /// Queries served on one TCP connection before it is closed.
    pub tcp_max_queries_per_connection: u32,
    /// Maximum concurrent DNS-over-TCP connections.
    pub max_tcp_connections: usize,
    /// Maximum concurrent DNS-over-TCP connections per client (an IPv4
    /// address or an IPv6 /64). 0 = no per-client limit.
    pub max_tcp_connections_per_client: usize,
    /// Answer ANY queries minimally (RFC 8482) to prevent amplification.
    pub minimal_any: bool,
    /// Default SOA primary nameserver for new zones, e.g. "ns1.example.com".
    /// Empty = "ns1.<zone>".
    pub default_primary_ns: String,
    /// Default SOA contact for new zones, e.g. "hostmaster@example.com". Empty = "hostmaster.<zone>".
    pub default_hostmaster: String,
    /// EDNS NSID (RFC 5001) reply string. Empty = do not answer NSID.
    pub nsid: String,
    /// Issue and verify server cookies (RFC 7873 / 9018).
    pub cookies: bool,
    /// Only answer UDP queries that carry a valid server cookie (RFC 7873 §5.2.3 strict mode).
    /// Off by default; on public servers it breaks clients without cookie support.
    pub cookies_required: bool,
    /// Listen on the addresses of these network interfaces instead of
    /// `bind`, following them as addresses appear and disappear (I11,
    /// dnsmasq `interface=` / `bind-dynamic`). Empty = use `bind`.
    pub interfaces: Vec<String>,
    /// How often the interfaces' addresses are checked, seconds, where
    /// netlink is not used (not Linux, or the socket cannot be opened).
    pub interface_poll_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardingConfig {
    /// Upstream resolvers for names we are not authoritative for. Empty = REFUSED.
    pub upstreams: Vec<SocketAddr>,
    pub timeout_ms: u64,
    /// Only these client networks may use forwarding (prevents an open resolver).
    pub allowed_clients: Vec<String>,
    /// Cache forwarded answers for their TTL. 0 disables.
    pub cache_entries: usize,
    /// Longest a positive forwarded answer is cached, seconds (the
    /// response's own lowest TTL is used when shorter; never raised).
    pub cache_max_ttl: u32,
    /// Longest a negative answer (NXDOMAIN / no data) is cached, seconds;
    /// otherwise min(SOA MINIMUM, SOA TTL) as in RFC 2308.
    pub cache_negative_max_ttl: u32,
    /// Deliberately run an open resolver: `allowed_clients` may then cover
    /// any network, including `0.0.0.0/0` and `::/0` (the open-resolver
    /// guard is skipped). An empty `allowed_clients` still means nobody;
    /// list the /0 entries explicitly. While on, forwarded answers get the
    /// safeguards below (UDP size cap, no forwarded ANY, per-client rate).
    pub open_resolver: bool,
    /// Open resolver only: forwarded answers over UDP larger than this are
    /// sent truncated (TC=1) so the client retries over TCP.
    pub open_resolver_max_udp_payload: u16,
    /// Open resolver only: forwarded queries per second per client (IPv4
    /// address / IPv6 /64), on top of `[rate_limit]`. 0 = no extra limit.
    pub open_resolver_rate_per_second: u32,
    /// Most forwarded queries waiting for an upstream at one time (each
    /// holds a task and a socket until the upstream answers or
    /// `timeout_ms` passes). Over the cap a query is not forwarded: UDP is
    /// dropped (the client retries), TCP gets SERVFAIL. Authoritative
    /// answers and cache hits are not affected.
    pub max_inflight: usize,
}

/// Largest accepted forwarding cache TTL cap (one week).
pub const MAX_CACHE_TTL_CAP: u32 = 604_800;

/// Problems with a pair of cache TTL caps.
pub fn cache_cap_problems(max_ttl: u32, negative_max_ttl: u32) -> Vec<String> {
    let mut errs = Vec::new();
    for (k, v) in [
        ("cache_max_ttl", max_ttl),
        ("cache_negative_max_ttl", negative_max_ttl),
    ] {
        if !(1..=MAX_CACHE_TTL_CAP).contains(&v) {
            errs.push(format!(
                "{k} must be between 1 and {MAX_CACHE_TTL_CAP} seconds (got {v})"
            ));
        }
    }
    if negative_max_ttl > max_ttl {
        errs.push(format!(
            "cache_negative_max_ttl ({negative_max_ttl}) must not exceed cache_max_ttl ({max_ttl})"
        ));
    }
    errs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Per client: an IPv4 address, or an IPv6 /64. 0 disables rate limiting.
    pub max_resolutions_per_second_per_address: u32,
    /// Size of the fixed counter table (memory is bounded by this; floods
    /// from many sources cannot evict or reset a limited client).
    pub max_tracked_addresses: usize,
    /// Every Nth rate-limited UDP query gets an empty truncated (TC=1) answer
    /// instead of being dropped, so a genuine client whose address is being
    /// spoofed can retry over TCP. 0 = always drop.
    pub slip: u32,
    /// O15: UDP queries with a valid server cookie (the client's address is
    /// proven) are answered even over the limit. Needs `[server].cookies`.
    pub exempt_valid_cookies: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupConfig {
    pub dir: PathBuf,
    pub interval_hours: u64,
    pub keep: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("backups"),
            interval_hours: 24,
            keep: 7,
        }
    }
}

/// Outbound zone transfers to secondaries (AXFR over TCP) and NOTIFY.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransferConfig {
    /// Client networks allowed to AXFR any zone. Empty = transfers disabled.
    pub allow: Vec<String>,
    /// Also require a valid TSIG signature (RFC 8945) from a key managed in
    /// the console. Unsigned transfer requests are refused. Recommended.
    pub require_tsig: bool,
    /// TSIG key that signs NOTIFY messages to targets without their own
    /// `key`. Empty = NOTIFY is sent unsigned.
    pub notify_key: String,
    /// Secondaries to NOTIFY when a zone changes: `"203.0.113.5:53"`, or
    /// `{ address = "203.0.113.5:53", key = "hn-secondary." }` to sign with a
    /// specific key (`key = ""` sends that target unsigned).
    pub notify: Vec<NotifyTarget>,
}

/// One NOTIFY target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotifyTarget {
    Address(SocketAddr),
    Detailed {
        address: SocketAddr,
        #[serde(default)]
        key: Option<String>,
    },
}

impl NotifyTarget {
    pub fn address(&self) -> SocketAddr {
        match self {
            NotifyTarget::Address(a) | NotifyTarget::Detailed { address: a, .. } => *a,
        }
    }
}

impl TransferConfig {
    /// NOTIFY targets with the (normalised) name of the key that signs them.
    /// Names that fail validation are dropped here; `validate` reports them.
    pub fn notify_targets(&self) -> Vec<(SocketAddr, Option<String>)> {
        let norm = |k: &str| {
            let k = k.trim();
            if k.is_empty() {
                None
            } else {
                crate::mutation::tsig::normalize_key_name(k).ok()
            }
        };
        self.notify
            .iter()
            .map(|t| {
                let key = match t {
                    NotifyTarget::Detailed { key: Some(k), .. } => norm(k),
                    _ => norm(&self.notify_key),
                };
                (t.address(), key)
            })
            .collect()
    }
}

/// PROXY protocol settings shared by the TCP DNS and web console listeners.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Accept HAProxy PROXY protocol headers from trusted peers.
    pub proxy_on: bool,
    /// 1 or 2.
    pub proxy_version: u8,
    /// Peers trusted to send PROXY headers (and, on the web console,
    /// X-Forwarded-For / X-Real-IP / X-Forwarded-Proto). `"cidr;cidr"` or a
    /// list. Empty = nobody: forwarded client information is ignored, and
    /// `proxy_on = true` is a configuration error.
    pub proxy_trust: ProxyTrust,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            proxy_on: false,
            proxy_version: 2,
            proxy_trust: ProxyTrust::default(),
        }
    }
}

impl ProxyConfig {
    /// Peers whose forwarded client information is believed. Only what is
    /// listed in `proxy_trust`: an empty list trusts nobody.
    pub fn trusted_cidrs(&self) -> Vec<Cidr> {
        parse_cidrs(&self.proxy_trust.entries())
    }

    /// Entries that trust a whole network rather than the proxy itself
    /// (shorter than /24 for IPv4 or /64 for IPv6): anything on that
    /// network, e.g. every container on a Docker bridge, can then claim to
    /// be any client.
    pub fn broad_trust_entries(&self) -> Vec<String> {
        self.proxy_trust
            .entries()
            .into_iter()
            .filter(|e| {
                Cidr::parse(e).is_some_and(|c| match c.ip {
                    IpAddr::V4(_) => c.prefix < 24,
                    IpAddr::V6(_) => c.prefix < 64,
                })
            })
            .collect()
    }
}

/// Accepts `"a;b"`, `"a,b"` or `["a", "b"]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProxyTrust {
    #[default]
    Unset,
    Text(String),
    List(Vec<String>),
}

impl ProxyTrust {
    pub fn entries(&self) -> Vec<String> {
        match self {
            ProxyTrust::Unset => vec![],
            ProxyTrust::Text(t) => t
                .split([';', ','])
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
            ProxyTrust::List(l) => l
                .iter()
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub enabled: bool,
    #[serde(flatten)]
    pub proxy: ProxyConfig,
    pub session_ttl_hours: u64,
    /// Always mark the session cookie `Secure` (and name it
    /// `__Host-rdns_session`). Also automatic per request when a trusted
    /// proxy sends `X-Forwarded-Proto: https`.
    pub secure_cookies: bool,
    /// Sign-in requests (password or code) allowed per client address
    /// (IPv6: per /64) per minute.
    pub login_attempts_per_minute: u32,
    /// Failed passwords/codes for one account from one network (IPv4
    /// address, IPv6 /64) before each further attempt must wait (1 s, 2 s,
    /// 4 s ... up to 15 min). Across all networks the account gets four
    /// times as many, then waits of at most one minute.
    pub login_backoff_after: u32,
    /// O1: API tokens may be created only from a signed-in browser session
    /// (not with another API token). Default false.
    pub token_creation_requires_session: bool,
    /// O7: cookie-authenticated writes must also send `X-CSRF-Token` (the
    /// session's CSRF token, given at sign-in and by `/auth/session`, also
    /// in the `rdns_csrf` cookie). Default true; false keeps only the
    /// `X-Requested-With` check (for old scripts that sign in with cookies).
    pub csrf_token_required: bool,
    /// Seconds a client has to send a request's headers; also how long an
    /// idle keep-alive connection stays open.
    pub request_header_timeout_secs: u64,
    /// Concurrent web connections (including websockets); more are refused.
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RootConfig {
    pub username: String,
    /// Plaintext on first write; replaced by an Argon2 hash at startup.
    pub password: String,
    /// Require TOTP for the root user.
    pub mfa_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChangelogConfig {
    pub retention_days: u32,
    /// Account, settings and TSIG changes carry password hashes, TOTP and
    /// TSIG secrets: their payloads are scrubbed after this many days (a
    /// standby further behind loads a snapshot).
    pub account_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// `text` or `json`
    pub format: String,
    /// e.g. `info`, `debug`, `rust_dns=debug,info`
    pub level: String,
    /// Log every DNS query.
    pub log_queries: bool,
    /// Log file path. Empty = stdout.
    pub file: String,
    /// Separate file for the query log. Empty = queries go to the main log.
    pub query_log_file: String,
    /// Rotate when a file exceeds this size.
    pub max_size_mb: u64,
    /// Rotated files to keep per log (oldest are deleted).
    pub max_files: usize,
    /// gzip rotated files.
    pub compress: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: vec!["::".parse().unwrap()],
            port: 53,
            udp: true,
            tcp: true,
            udp_max_payload: 1232,
            auto_ptr: true,
            tcp_idle_timeout_secs: 10,
            tcp_write_timeout_secs: 10,
            tcp_max_connection_secs: 120,
            tcp_max_queries_per_connection: 200,
            max_tcp_connections: 1000,
            max_tcp_connections_per_client: 16,
            minimal_any: true,
            default_primary_ns: String::new(),
            default_hostmaster: String::new(),
            nsid: String::new(),
            cookies: true,
            cookies_required: false,
            interfaces: Vec::new(),
            interface_poll_secs: 5,
        }
    }
}
impl Default for ForwardingConfig {
    fn default() -> Self {
        ForwardingConfig {
            upstreams: vec![],
            timeout_ms: 2000,
            allowed_clients: vec![
                "127.0.0.0/8".into(),
                "::1/128".into(),
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "fc00::/7".into(),
                "fe80::/10".into(),
            ],
            cache_entries: 10_000,
            cache_max_ttl: 86_400,
            cache_negative_max_ttl: 3_600,
            open_resolver: false,
            open_resolver_max_udp_payload: 512,
            open_resolver_rate_per_second: 20,
            max_inflight: 1024,
        }
    }
}
impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_resolutions_per_second_per_address: 500,
            max_tracked_addresses: 10_000,
            slip: 2,
            exempt_valid_cookies: false,
        }
    }
}
impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: PathBuf::from("rust-dns.db"),
        }
    }
}
impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            bind: "127.0.0.1:8053".parse().unwrap(),
            enabled: true,
            proxy: ProxyConfig::default(),
            session_ttl_hours: 12,
            secure_cookies: false,
            login_attempts_per_minute: 10,
            login_backoff_after: 5,
            token_creation_requires_session: false,
            csrf_token_required: true,
            request_header_timeout_secs: 60,
            max_connections: 512,
        }
    }
}
impl Default for RootConfig {
    fn default() -> Self {
        RootConfig {
            username: "root".into(),
            password: String::new(),
            mfa_required: false,
        }
    }
}
impl Default for ChangelogConfig {
    fn default() -> Self {
        ChangelogConfig {
            retention_days: 30,
            account_retention_days: 3,
        }
    }
}
impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            format: "text".into(),
            level: "info".into(),
            log_queries: false,
            file: String::new(),
            query_log_file: String::new(),
            max_size_mb: 50,
            max_files: 10,
            compress: true,
        }
    }
}

pub const SAMPLE: &str = r#"# rust-dns configuration

[server]
bind = ["::"]            # "::" also accepts IPv4 on Linux/macOS; add "0.0.0.0" if not
port = 53
udp = true
tcp = true
udp_max_payload = 1232
auto_ptr = true          # synthesize PTR answers from A/AAAA records
tcp_idle_timeout_secs = 10
tcp_write_timeout_secs = 10         # a client that stops reading is dropped after this
tcp_max_connection_secs = 120       # no new query is read on an older connection
tcp_max_queries_per_connection = 200
max_tcp_connections = 1000
max_tcp_connections_per_client = 16 # per IPv4 address / IPv6 /64; 0 = unlimited
minimal_any = true       # RFC 8482: minimal ANY answers (anti-amplification)
default_primary_ns = ""  # SOA MNAME for new zones, e.g. "ns1.example.com"; empty = ns1.<zone>
default_hostmaster = ""  # SOA RNAME for new zones, e.g. "hostmaster@example.com"; empty = hostmaster.<zone>
nsid = ""                # EDNS NSID reply (RFC 5001), e.g. the host name; empty = off
cookies = true           # issue/verify DNS server cookies (RFC 7873)
cookies_required = false # strict mode: UDP queries without a valid cookie get BADCOOKIE
interfaces = []          # e.g. ["eth0"]: listen on these interfaces' addresses (followed) instead of bind
interface_poll_secs = 5   # without netlink (not Linux): how often addresses are re-read

[forwarding]
upstreams = []           # e.g. ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]; empty = REFUSED for foreign names
timeout_ms = 2000
# Only these networks may use forwarding; never open this to the internet.
allowed_clients = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]
cache_entries = 10000    # TTL-aware cache for forwarded answers; 0 = off
cache_max_ttl = 86400    # cap on how long a forwarded answer is cached (its own TTL if lower; never raised)
cache_negative_max_ttl = 3600  # cap for NXDOMAIN/no-data answers (otherwise min(SOA MINIMUM, SOA TTL))
# open_resolver = true lifts the allowed_clients guard so it may list "0.0.0.0/0" and "::/0"
# (an empty list still means nobody). Only for a deliberate public resolver: see the README.
open_resolver = false
open_resolver_max_udp_payload = 512 # open resolver: larger forwarded UDP answers are sent truncated (TC=1)
open_resolver_rate_per_second = 20  # open resolver: forwarded queries/s per client (IPv4 / IPv6 /64); 0 = off
max_inflight = 1024      # forwarded queries waiting for an upstream at once; over it UDP is dropped, TCP gets SERVFAIL

[transfer]
allow = []               # networks allowed to AXFR zones (for BIND/NSD secondaries), e.g. ["203.0.113.5/32"]
require_tsig = false     # also require a TSIG key (create keys under "TSIG keys" in the console); recommended: true
notify_key = ""          # TSIG key that signs NOTIFY messages, e.g. "hn-secondary."; empty = unsigned
notify = []              # secondaries to NOTIFY on change, e.g. ["203.0.113.5:53"] or
                         # [{ address = "203.0.113.5:53", key = "hn-secondary." }]

[rate_limit]
max_resolutions_per_second_per_address = 500   # per IPv4 address / IPv6 /64
max_tracked_addresses = 10000
slip = 2                 # every 2nd limited UDP query gets an empty TC=1 answer; 0 = drop all
exempt_valid_cookies = false  # answer UDP queries with a valid server cookie even over the limit

[database]
path = "rust-dns.db"

[backup]
dir = "backups"             # online SQLite backups; empty disables backups
interval_hours = 24
keep = 7

# PROXY protocol for DNS over TCP (UDP has no PROXY protocol; the socket peer is used).
[tcp_dns]
proxy_on = false
proxy_version = 2        # 1 or 2
proxy_trust = ""         # "192.0.2.10/32;2001:db8::10/128" - the proxies allowed to send PROXY headers; empty = none (required with proxy_on)

[web_console]
bind = "127.0.0.1:8053"
enabled = true
proxy_on = false         # accept PROXY protocol from trusted peers
proxy_version = 2        # 1 or 2
proxy_trust = ""         # proxies whose PROXY header / X-Forwarded-For / X-Real-IP / X-Forwarded-Proto are believed; empty = none
session_ttl_hours = 12
secure_cookies = false   # always mark the session cookie Secure; it is also Secure automatically when a trusted proxy sends X-Forwarded-Proto: https
request_header_timeout_secs = 60  # a client must send each request's headers within this (also the keep-alive idle limit)
max_connections = 512    # concurrent web connections (websockets included)
login_attempts_per_minute = 10  # sign-in requests per client address (IPv6: per /64) per minute
login_backoff_after = 5  # failed attempts per account and network before waits start (account-wide: 4x, waits <= 1 min)
token_creation_requires_session = false  # true: API tokens can only be created from a signed-in browser session, not with another token
csrf_token_required = true  # cookie writes also send X-CSRF-Token (the console does); false: only X-Requested-With (old cookie scripts)

[root]
username = "root"
password = "__PASSWORD__"   # plaintext is hashed in place at start; "change-me" and "" are refused
mfa_required = false

[changelog]
retention_days = 30
account_retention_days = 3  # account/settings/TSIG change payloads (secrets) are scrubbed after this

[expiry]
retention_days = 30      # expired records stop answering at once and are deleted after this many days
sweep_interval_secs = 60 # upper bound on the sweeper's sleep; it also wakes at the next due expiry

[dnssec]
# Signing is off by default and turned on per zone (console: zone -> DNSSEC).
signature_validity_days = 14  # each RRSIG is valid this long (from 1 h before the zone's last change)
resign_before_days = 7        # the primary re-signs (serial bump) when signatures expire within this
rollover_check_secs = 300     # key rollover: how often the parent's servers are asked while a DS change is awaited

[logging]
format = "text"          # "text" or "json"
level = "info"           # e.g. "info", "debug", "rust_dns=debug,info"
log_queries = false      # log every DNS query
file = ""                # log file; empty = stdout
query_log_file = ""      # separate query log file; empty = queries go to the main log
max_size_mb = 50         # rotate when the file exceeds this size
max_files = 10           # rotated files to keep per log
compress = true          # gzip rotated files

# Standby mode: uncomment on the second server to mirror a primary (read-only,
# answers all DNS queries while the primary is down; promote it by hand).
# [follow]
# primary = "https://dns1.example.net:8053"  # the primary's web API (https required)
# instance_id = "dns2"                       # required: this standby's name on the primary (a-z 0-9 -)
# token = "rdns_..."                         # API token of an administrator on the primary
# reconcile_interval_secs = 3600             # compare serials/checksums with the primary
# allow_insecure_http = false                # plain http only on a trusted network (loopback always allowed)
# timeout_secs = 30

# On the primary: the standby to ask whether it has been promoted, so a returning
# old primary stays read-only instead of accepting writes (split brain).
# [peer]
# url = "https://dns2.example.net:8053"
# check_interval_secs = 60
# allow_insecure_http = false

# On a primary: how its standbys (replicas) are judged (reloadable).
[replication]
up_to_date_grace_secs = 10   # caught up this recently = up to date
max_lag_changes = 1000       # more changes behind = falling behind
max_lag_secs = 60            # not caught up for longer = falling behind
offline_after_secs = 75      # no request for this long = offline
forget_after_days = 30       # forget replicas not seen for this long
"#;

/// The sample configuration printed by `--print-sample-config`: the root
/// password is the placeholder `change-me`, which rust-dns refuses to run with.
pub fn sample_with_placeholder() -> String {
    format!(
        "# [root].password below is a placeholder: rust-dns refuses to start (and --check fails)\n\
         # until it is changed. `rust-dns --init-config <path>` writes a config with a random\n\
         # root password instead.\n{}",
        SAMPLE.replace("__PASSWORD__", PLACEHOLDER_PASSWORD)
    )
}

/// The documented placeholder root password; never accepted.
pub const PLACEHOLDER_PASSWORD: &str = "change-me";

/// Create `path` readable and writable by the owner only (0600 on unix).
/// Fails if it already exists: nothing is ever overwritten.
pub fn create_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}

/// Replace `path` atomically with `text`, leaving it owner-only (0600).
fn rewrite_private(path: &Path, text: &str) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rust-dns.toml".into());
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    create_private(&tmp, text)?;
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("replacing {}", path.display())
    })
}

/// A fresh configuration with a random root password, stored already
/// hashed. Returns (config text, root username, plaintext password).
pub fn generate() -> Result<(String, String, String)> {
    let pw = crate::auth::random_token(18);
    let hash = crate::auth::hash_password(&pw)?;
    let text = SAMPLE.replace("__PASSWORD__", &hash).replace(
        "   # plaintext is hashed in place at start; \"change-me\" and \"\" are refused",
        "   # Argon2 hash; set a new plaintext here to change it (hashed at start)",
    );
    Ok((text, RootConfig::default().username, pw))
}

/// `--init-config`: write a new config (0600) with a random root password.
/// Refuses to touch an existing file. Returns (username, plaintext password).
pub fn init_config(path: &Path) -> Result<(String, String)> {
    if path.exists() {
        anyhow::bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        );
    }
    let (text, user, pw) = generate()?;
    create_private(path, &text)?;
    Ok((user, pw))
}

/// Refuse an empty root password and the documented placeholder, whether
/// still in plaintext or already hashed by an earlier start.
pub fn check_root_password(cfg: &Config) -> Result<()> {
    let pw = cfg.root.password.trim();
    if pw.is_empty() {
        anyhow::bail!("[root].password must be set (run `rust-dns --init-config <path>` to generate a config with a random password)");
    }
    let placeholder = if crate::auth::is_password_hash(pw) {
        crate::auth::verify_password(PLACEHOLDER_PASSWORD, pw)
    } else {
        // Also the examples' "change-me-please" and similar.
        pw.to_ascii_lowercase().starts_with(PLACEHOLDER_PASSWORD) || pw == "__PASSWORD__"
    };
    if placeholder {
        anyhow::bail!(
            "[root].password is the placeholder \"{PLACEHOLDER_PASSWORD}\"; set a real password in the config file (it is hashed on start) or generate a new config with `rust-dns --init-config <path>`"
        );
    }
    Ok(())
}

/// Load the config, creating a default file (0600) with a random root
/// password if it does not exist; the password is returned so the caller
/// can print it once (never logged). Hashes a plaintext root password in
/// place, rewriting the file owner-only.
pub fn load_or_init(path: &Path) -> Result<(Config, Option<String>)> {
    let mut generated_password = None;
    if !path.exists() {
        let (text, _, pw) = generate()?;
        create_private(path, &text)?;
        tracing::info!(path = %path.display(), "wrote default configuration (mode 0600)");
        generated_password = Some(pw);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    validate(&cfg).with_context(|| format!("validating {}", path.display()))?;
    check_root_password(&cfg).with_context(|| format!("in {}", path.display()))?;
    if !crate::auth::is_password_hash(&cfg.root.password) {
        let hash = crate::auth::hash_password(&cfg.root.password)?;
        let mut doc: toml_edit::DocumentMut =
            text.parse().context("re-parsing config for rewrite")?;
        doc["root"]["password"] = toml_edit::value(hash.clone());
        rewrite_private(path, &doc.to_string())?;
        tracing::info!(
            "hashed the plaintext [root].password in the configuration file (now mode 0600)"
        );
        cfg.root.password = hash;
    }
    warn_if_world_readable(path);
    Ok((cfg, generated_password))
}

/// Promotion: remove the `[follow]` section from the config file (atomic,
/// owner-only rewrite), leaving a comment that says what happened. The
/// token is not copied into the comment. Returns false when there was no
/// `[follow]` section.
pub fn remove_follow_section(path: &Path, note: &str) -> Result<bool> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing config for rewrite")?;
    if doc.remove("follow").is_none() {
        return Ok(false);
    }
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "\n# [follow] was removed: {note}\n# To make this server a standby again, add a [follow] section (see the README, \"Standby / follow mode\").\n"
    ));
    // The result must still be a valid configuration.
    let cfg: Config = toml::from_str(&out).context("config after removing [follow]")?;
    validate(&cfg)?;
    rewrite_private(path, &out)?;
    Ok(true)
}

fn warn_if_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path) {
            if m.permissions().mode() & 0o007 != 0 {
                tracing::warn!(path = %path.display(), mode = format!("{:o}", m.permissions().mode() & 0o777), "the configuration file is readable by other users; chmod 600 it");
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Parse and validate an existing configuration without creating or rewriting it.
pub fn check(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    validate(&cfg).with_context(|| format!("validating {}", path.display()))?;
    check_root_password(&cfg).with_context(|| format!("in {}", path.display()))?;
    Ok(cfg)
}

/// Validate a parsed configuration. Collects every problem and returns a
/// single error listing each one on its own line, naming the TOML key.
/// `[dnssec]` problems (empty = valid).
pub fn dnssec_problems(d: &DnssecConfig) -> Vec<String> {
    let mut errs = Vec::new();
    if !(2..=365).contains(&d.signature_validity_days) {
        errs.push("[dnssec].signature_validity_days must be between 2 and 365".into());
    }
    if d.rollover_check_secs == 0 {
        errs.push("[dnssec].rollover_check_secs must be at least 1 (default 300)".into());
    }
    if d.parent_port == 0 {
        errs.push("[dnssec].parent_port must not be 0 (default 53)".into());
    }
    if d.resign_before_days == 0 || d.resign_before_days >= d.signature_validity_days {
        errs.push("[dnssec].resign_before_days must be at least 1 and less than signature_validity_days (default 7 of 14)".into());
    }
    errs
}

pub fn validate(cfg: &Config) -> Result<()> {
    let mut errs: Vec<String> = Vec::new();

    // [server]
    let s = &cfg.server;
    if s.port == 0 {
        errs.push("[server].port must not be 0".into());
    }
    if s.bind.is_empty() {
        errs.push("[server].bind must list at least one address".into());
    }
    if !s.udp && !s.tcp {
        errs.push("[server].udp and [server].tcp are both false; enable at least one".into());
    }
    for (key, v) in [
        ("tcp_idle_timeout_secs", s.tcp_idle_timeout_secs),
        ("tcp_write_timeout_secs", s.tcp_write_timeout_secs),
        ("tcp_max_connection_secs", s.tcp_max_connection_secs),
        (
            "tcp_max_queries_per_connection",
            s.tcp_max_queries_per_connection as u64,
        ),
        ("max_tcp_connections", s.max_tcp_connections as u64),
    ] {
        if v == 0 {
            errs.push(format!("[server].{key} must be greater than zero"));
        }
    }
    if s.udp_max_payload < 512 {
        errs.push(format!(
            "[server].udp_max_payload must be at least 512 (got {})",
            s.udp_max_payload
        ));
    }
    if !s.default_primary_ns.trim().is_empty() {
        if let Err(e) = crate::model::normalize_domain(&s.default_primary_ns, false) {
            errs.push(format!(
                "[server].default_primary_ns '{}' is invalid: {}",
                s.default_primary_ns, e.0
            ));
        }
    }
    let hm = s.default_hostmaster.trim();
    if !hm.is_empty() {
        let res = match hm.split_once('@') {
            Some((user, domain)) => {
                if user.is_empty() {
                    Err("mailbox part before '@' is empty".to_string())
                } else {
                    crate::model::normalize_domain(domain, false)
                        .map(|_| ())
                        .map_err(|e| e.0)
                }
            }
            None => crate::model::normalize_domain(hm, true)
                .map(|_| ())
                .map_err(|e| e.0),
        };
        if let Err(e) = res {
            errs.push(format!(
                "[server].default_hostmaster '{}' is invalid: {e}",
                s.default_hostmaster
            ));
        }
    }

    // [forwarding]
    check_cidrs(
        "[forwarding].allowed_clients",
        &cfg.forwarding.allowed_clients,
        &mut errs,
    );
    // The open-resolver guard, unless an open resolver is deliberate.
    if !cfg.forwarding.open_resolver {
        for e in open_resolver_problems(&cfg.forwarding.allowed_clients) {
            errs.push(format!(
                "[forwarding].allowed_clients: {e} (or set [forwarding].open_resolver = true if that is really intended; see the README)"
            ));
        }
    }
    if !(512..=4096).contains(&cfg.forwarding.open_resolver_max_udp_payload) {
        errs.push(format!(
            "[forwarding].open_resolver_max_udp_payload must be between 512 and 4096 (got {})",
            cfg.forwarding.open_resolver_max_udp_payload
        ));
    }
    for e in cache_cap_problems(
        cfg.forwarding.cache_max_ttl,
        cfg.forwarding.cache_negative_max_ttl,
    ) {
        errs.push(format!("[forwarding].{e}"));
    }
    if cfg.forwarding.max_inflight == 0 {
        errs.push("[forwarding].max_inflight must be at least 1".into());
    }
    if cfg.forwarding.timeout_ms == 0 {
        errs.push("[forwarding].timeout_ms must be greater than zero".into());
    }

    // [transfer]
    check_cidrs("[transfer].allow", &cfg.transfer.allow, &mut errs);
    let key_ok =
        |k: &str| k.trim().is_empty() || crate::mutation::tsig::normalize_key_name(k).is_ok();
    if !key_ok(&cfg.transfer.notify_key) {
        errs.push(format!(
            "[transfer].notify_key '{}' is not a valid key name (a DNS name such as \"hn-secondary.\")",
            cfg.transfer.notify_key
        ));
    }
    for t in &cfg.transfer.notify {
        if let NotifyTarget::Detailed {
            key: Some(k),
            address,
        } = t
        {
            if !key_ok(k) {
                errs.push(format!(
                    "[transfer].notify entry '{address}': key '{k}' is not a valid key name"
                ));
            }
        }
        let n = t.address();
        if n.ip().is_unspecified() {
            errs.push(format!(
                "[transfer].notify entry '{n}' is an unspecified address"
            ));
        }
        if n.port() == 0 {
            errs.push(format!("[transfer].notify entry '{n}' has port 0"));
        }
    }

    // [tcp_dns] / [web_console] PROXY settings
    for (section, p) in [
        ("[tcp_dns]", &cfg.tcp_dns),
        ("[web_console]", &cfg.web_console.proxy),
    ] {
        if !matches!(p.proxy_version, 1 | 2) {
            errs.push(format!(
                "{section}.proxy_version must be 1 or 2 (got {})",
                p.proxy_version
            ));
        }
        check_cidrs(
            &format!("{section}.proxy_trust"),
            &p.proxy_trust.entries(),
            &mut errs,
        );
        if p.proxy_on && p.proxy_trust.entries().is_empty() {
            errs.push(format!(
                "{section}.proxy_on = true needs {section}.proxy_trust listing the proxy's address (e.g. \"127.0.0.1/32\"); nobody is trusted by default"
            ));
        }
    }
    if cfg.web_console.request_header_timeout_secs == 0 {
        errs.push("[web_console].request_header_timeout_secs must be greater than zero".into());
    }
    if cfg.web_console.max_connections == 0 {
        errs.push("[web_console].max_connections must be greater than zero".into());
    }

    // [web_console] vs DNS TCP listener
    let w = &cfg.web_console;
    if w.enabled && s.tcp && w.bind.port() == s.port {
        let wip = w.bind.ip();
        if let Some(dip) = s
            .bind
            .iter()
            .find(|d| d.is_unspecified() || wip.is_unspecified() || **d == wip)
        {
            errs.push(format!(
                "[web_console].bind {} collides with DNS TCP listener {} (port {})",
                w.bind,
                SocketAddr::new(*dip, s.port),
                s.port
            ));
        }
    }

    // [backup]
    if cfg.backup.keep == 0 && !cfg.backup.dir.as_os_str().is_empty() {
        errs.push("[backup].keep must be greater than zero when backups are enabled".into());
    }
    if cfg.backup.interval_hours == 0 {
        errs.push("[backup].interval_hours must be greater than zero".into());
    }
    let r = &cfg.replication;
    if r.offline_after_secs == 0 || r.max_lag_secs == 0 || r.forget_after_days == 0 {
        errs.push("[replication].offline_after_secs, max_lag_secs and forget_after_days must be greater than zero (keep offline_after_secs above the 25 s long-poll, e.g. 75)".into());
    }
    if cfg.changelog.account_retention_days == 0 {
        errs.push("[changelog].account_retention_days must be greater than zero".into());
    }
    if cfg.expiry.sweep_interval_secs == 0 {
        errs.push("[expiry].sweep_interval_secs must be greater than zero".into());
    }
    errs.extend(dnssec_problems(&cfg.dnssec));

    // [root]
    if cfg.root.username.trim().is_empty() {
        errs.push("[root].username must not be empty".into());
    }

    // [follow] / [peer]
    if let Some(f) = &cfg.follow {
        if f.primary.trim().is_empty() {
            errs.push("[follow].primary must be set to the primary's web API URL, e.g. \"https://dns1.example.net:8053\"".into());
        } else {
            errs.extend(replication_url_problems(
                "[follow].primary",
                &f.primary,
                f.allow_insecure_http,
            ));
        }
        let t = f.token.trim();
        if t.is_empty() || t.contains("...") || !t.starts_with("rdns_") {
            errs.push(
                "[follow].token must be an API token (rdns_...) of an administrator on the primary"
                    .into(),
            );
        }
        match crate::replication::replicas::instance_id_problem(f.instance_id.trim()) {
            _ if f.instance_id.trim().is_empty() => errs.push(
                "[follow].instance_id is required: this standby's name as the primary lists it, e.g. instance_id = \"dns2\" (a-z, 0-9, '-', 1-63 characters, unique per primary)".into(),
            ),
            Some(p) => errs.push(format!("[follow].instance_id '{}' {p}", f.instance_id)),
            None => {}
        }
        if f.reconcile_interval_secs == 0 {
            errs.push("[follow].reconcile_interval_secs must be greater than zero".into());
        }
        if f.timeout_secs == 0 {
            errs.push("[follow].timeout_secs must be greater than zero".into());
        }
        if cfg.peer.is_some() {
            errs.push(
                "[peer] is for a primary; remove it from a standby (a [follow] config)".into(),
            );
        }
    }
    if let Some(p) = &cfg.peer {
        if p.url.trim().is_empty() {
            errs.push("[peer].url must be set to the standby's web API URL".into());
        } else {
            errs.extend(replication_url_problems(
                "[peer].url",
                &p.url,
                p.allow_insecure_http,
            ));
        }
        if p.check_interval_secs == 0 {
            errs.push("[peer].check_interval_secs must be greater than zero".into());
        }
    }

    // [logging]
    let l = &cfg.logging;
    if let Err(e) = tracing_subscriber::EnvFilter::try_new(&l.level) {
        errs.push(format!("[logging].level '{}' is invalid: {e}", l.level));
    }
    if !matches!(l.format.to_ascii_lowercase().as_str(), "text" | "json") {
        errs.push(format!(
            "[logging].format must be \"text\" or \"json\" (got \"{}\")",
            l.format
        ));
    }
    if !l.file.is_empty() || !l.query_log_file.is_empty() {
        if l.max_size_mb == 0 {
            errs.push(
                "[logging].max_size_mb must be greater than zero when logging to a file".into(),
            );
        }
        if l.max_files == 0 {
            errs.push(
                "[logging].max_files must be greater than zero when logging to a file".into(),
            );
        }
    }

    if errs.is_empty() {
        return Ok(());
    }
    let mut msg = format!("{} configuration error(s):", errs.len());
    for e in &errs {
        msg.push_str("\n  - ");
        msg.push_str(e);
    }
    Err(anyhow::anyhow!(msg))
}

fn check_cidrs(key: &str, list: &[String], errs: &mut Vec<String>) {
    for c in list {
        if Cidr::parse(c.trim()).is_none() {
            errs.push(format!("{key}: '{c}' is not a valid CIDR"));
        }
    }
}

/// A CIDR block used for trusted-proxy checks.
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, prefix) = match s.split_once('/') {
            Some((i, p)) => {
                let ip = i.parse::<IpAddr>().ok()?;
                let prefix = p.parse::<u8>().ok()?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                if prefix > max {
                    return None;
                }
                (ip, prefix)
            }
            None => {
                let ip = s.parse::<IpAddr>().ok()?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        Some(Cidr { ip, prefix })
    }

    pub fn contains(&self, other: IpAddr) -> bool {
        match (self.ip, other) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let p = self.prefix.min(32);
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let p = self.prefix.min(128);
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            (IpAddr::V4(_), IpAddr::V6(b)) => b
                .to_ipv4_mapped()
                .map(|b4| self.contains(IpAddr::V4(b4)))
                .unwrap_or(false),
            _ => false,
        }
    }
}

/// Shortest IPv4 prefix one forwarding ACL entry may have.
pub const MIN_ACL_PREFIX_V4: u8 = 8;
/// Shortest IPv6 prefix for an entry that includes global addresses.
pub const MIN_ACL_PREFIX_V6: u8 = 16;

/// Why a forwarding ACL would (nearly) make this an open resolver, if it
/// would: an entry shorter than /8 (IPv4) or /16 (IPv6, outside the
/// ULA/link-local/loopback ranges), or entries that together cover more
/// than 1/16 of IPv4 or 1/256 of IPv6. Catches `0.0.0.0/0` as well as
/// splits such as `0.0.0.0/1` + `128.0.0.0/1`.
pub fn open_resolver_problems(list: &[String]) -> Vec<String> {
    let local_v6: Vec<Cidr> = ["fc00::/7", "fe80::/10", "::1/128", "::/128"]
        .iter()
        .filter_map(|c| Cidr::parse(c))
        .collect();
    let mut errs = Vec::new();
    let mut v4: Vec<(u64, u64)> = Vec::new();
    let mut v6: Vec<(u128, u128)> = Vec::new();
    for raw in list {
        let Some(c) = Cidr::parse(raw.trim()) else {
            continue; // reported by the CIDR syntax check
        };
        match c.ip {
            IpAddr::V4(a) => {
                if c.prefix < MIN_ACL_PREFIX_V4 {
                    errs.push(format!(
                        "'{raw}' covers {} of the IPv4 internet and would make this an open resolver; list your own networks (at most /{MIN_ACL_PREFIX_V4} each)",
                        share(1u128 << (32 - c.prefix), 1u128 << 32)
                    ));
                }
                let size = 1u64 << (32 - c.prefix);
                let start = u32::from(a) as u64 & !(size - 1);
                v4.push((start, start + size));
            }
            IpAddr::V6(a) => {
                let inside_local = local_v6
                    .iter()
                    .any(|l| l.prefix <= c.prefix && l.contains(IpAddr::V6(a)));
                if inside_local {
                    continue;
                }
                if c.prefix < MIN_ACL_PREFIX_V6 {
                    errs.push(format!(
                        "'{raw}' covers a large part of the IPv6 internet and would make this an open resolver; list your own networks (at most /{MIN_ACL_PREFIX_V6} each for global addresses)"
                    ));
                    continue;
                }
                let size = 1u128 << (128 - c.prefix as u32);
                let start = u128::from(a) & !(size - 1);
                v6.push((start, start.saturating_add(size)));
            }
        }
    }
    let covered4 = merged_len(
        v4.into_iter()
            .map(|(a, b)| (a as u128, b as u128))
            .collect(),
    );
    if errs.is_empty() && covered4 > 1u128 << 28 {
        errs.push(format!(
            "together the IPv4 entries cover {} of all addresses; that is an open resolver in all but name. List your own networks",
            share(covered4, 1u128 << 32)
        ));
    }
    let covered6 = merged_len(v6);
    if errs.is_empty() && covered6 > 1u128 << 120 {
        errs.push("together the IPv6 entries cover more than 1/256 of all addresses; that is an open resolver in all but name. List your own networks".into());
    }
    errs
}

/// What `--check`, startup and reload say while `[forwarding].open_resolver`
/// is on (empty when it is off).
pub fn open_resolver_warnings(f: &ForwardingConfig) -> Vec<String> {
    if !f.open_resolver {
        return Vec::new();
    }
    let mut out = vec![format!(
        "[forwarding].open_resolver is ON: clients in allowed_clients ({}) may use this server as a recursive resolver; safeguards: forwarded UDP answers over {} bytes are truncated, ANY is not forwarded, {} forwarded queries/s per client",
        if f.allowed_clients.is_empty() {
            "none listed".to_string()
        } else {
            f.allowed_clients.join(", ")
        },
        f.open_resolver_max_udp_payload,
        if f.open_resolver_rate_per_second == 0 {
            "no limit on".to_string()
        } else {
            f.open_resolver_rate_per_second.to_string()
        }
    )];
    if f.open_resolver_rate_per_second == 0 {
        out.push("[forwarding].open_resolver_rate_per_second = 0: open-resolver clients are limited only by [rate_limit]".into());
    }
    if f.upstreams.is_empty() {
        out.push("[forwarding].open_resolver is on but no upstreams are set: foreign names are refused anyway".into());
    }
    out
}

fn share(part: u128, whole: u128) -> String {
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

/// Total length of the union of half-open ranges.
fn merged_len(mut r: Vec<(u128, u128)>) -> u128 {
    r.sort();
    let mut total: u128 = 0;
    let mut cur: Option<(u128, u128)> = None;
    for (a, b) in r {
        match cur {
            Some((ca, cb)) if a <= cb => cur = Some((ca, cb.max(b))),
            Some((ca, cb)) => {
                total = total.saturating_add(cb - ca);
                cur = Some((a, b));
            }
            None => cur = Some((a, b)),
        }
    }
    if let Some((ca, cb)) = cur {
        total = total.saturating_add(cb - ca);
    }
    total
}

pub fn parse_cidrs(list: &[String]) -> Vec<Cidr> {
    list.iter()
        .filter_map(|s| {
            let c = Cidr::parse(s);
            if c.is_none() {
                tracing::warn!(cidr = %s, "ignoring invalid trusted_proxies entry");
            }
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
        let v6 = Cidr::parse("fc00::/7").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("2001::1".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn sample_parses() {
        let cfg: Config = toml::from_str(&SAMPLE.replace("__PASSWORD__", "x")).unwrap();
        assert_eq!(cfg.server.port, 53);
        assert_eq!(cfg.rate_limit.max_resolutions_per_second_per_address, 500);
        let empty: Config = toml::from_str("").unwrap();
        assert_eq!(empty.web_console.bind.port(), 8053);
        assert!(!empty.web_console.proxy.proxy_on);
        let t: Config = toml::from_str("[web_console]\nproxy_on = true\nproxy_version = 1\nproxy_trust = \"192.168.44.0/24;fe80::/64\"\n[tcp_dns]\nproxy_trust = [\"10.1.0.0/16\"]").unwrap();
        assert_eq!(
            t.web_console.proxy.proxy_trust.entries(),
            vec!["192.168.44.0/24", "fe80::/64"]
        );
        assert_eq!(t.web_console.proxy.proxy_version, 1);
        assert_eq!(t.tcp_dns.proxy_trust.entries(), vec!["10.1.0.0/16"]);
        assert_eq!(t.tcp_dns.trusted_cidrs().len(), 1);
        assert!(
            cfg.tcp_dns.trusted_cidrs().is_empty(),
            "an empty proxy_trust trusts nobody"
        );
        assert!(cfg.web_console.proxy.trusted_cidrs().is_empty());
        validate(&cfg).unwrap();
        validate(&empty).unwrap();
        validate(&t).unwrap();
    }

    fn err_of(toml_text: &str) -> String {
        let cfg: Config = toml::from_str(toml_text).unwrap();
        format!("{:#}", validate(&cfg).unwrap_err())
    }

    #[test]
    fn validate_reports_all_errors() {
        let msg = err_of(
            r#"
[server]
port = 0
udp = false
tcp = false
udp_max_payload = 100
default_primary_ns = "bad..name"
default_hostmaster = "@example.com"
[forwarding]
timeout_ms = 0
max_inflight = 0
allowed_clients = ["10.0.0.0/33"]
[transfer]
allow = ["nope"]
notify_key = "bad key"
notify = ["0.0.0.0:53", { address = "192.0.2.1:53", key = "a..b" }]
[tcp_dns]
proxy_version = 3
proxy_trust = "1.2.3.4/8;garbage"
[web_console]
proxy_version = 0
proxy_trust = ["::/999"]
[backup]
keep = 0
interval_hours = 0
[root]
username = ""
[logging]
level = "info,=bogus[["
format = "xml"
file = "x.log"
max_size_mb = 0
max_files = 0
"#,
        );
        for needle in [
            "[server].port",
            "[server].udp and [server].tcp",
            "[server].udp_max_payload",
            "[server].default_primary_ns",
            "[server].default_hostmaster",
            "[forwarding].timeout_ms",
            "[forwarding].max_inflight",
            "[forwarding].allowed_clients: '10.0.0.0/33'",
            "[transfer].allow: 'nope'",
            "[transfer].notify entry '0.0.0.0:53'",
            "[transfer].notify_key",
            "[transfer].notify entry '192.0.2.1:53': key 'a..b'",
            "[tcp_dns].proxy_version",
            "[tcp_dns].proxy_trust: 'garbage'",
            "[web_console].proxy_version",
            "[web_console].proxy_trust: '::/999'",
            "[backup].keep",
            "[backup].interval_hours",
            "[root].username",
            "[logging].level",
            "[logging].format",
            "[logging].max_size_mb",
            "[logging].max_files",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in:\n{msg}");
        }
        assert!(msg.starts_with("23 configuration error(s):"), "{msg}");
    }

    #[test]
    fn notify_targets_and_keys() {
        // The old form still parses.
        let cfg: Config = toml::from_str("[transfer]\nnotify = [\"192.0.2.1:53\"]").unwrap();
        assert!(!cfg.transfer.require_tsig);
        assert_eq!(
            cfg.transfer.notify_targets(),
            vec![("192.0.2.1:53".parse().unwrap(), None)]
        );
        let cfg: Config = toml::from_str(
            r#"[transfer]
require_tsig = true
notify_key = "HN-Secondary"
notify = ["192.0.2.1:53", { address = "192.0.2.2:5300", key = "other." }, { address = "[2001:db8::1]:53", key = "" }, { address = "192.0.2.3:53" }]"#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert!(cfg.transfer.require_tsig);
        assert_eq!(
            cfg.transfer.notify_targets(),
            vec![
                (
                    "192.0.2.1:53".parse().unwrap(),
                    Some("hn-secondary.".to_string())
                ),
                (
                    "192.0.2.2:5300".parse().unwrap(),
                    Some("other.".to_string())
                ),
                ("[2001:db8::1]:53".parse().unwrap(), None),
                (
                    "192.0.2.3:53".parse().unwrap(),
                    Some("hn-secondary.".to_string())
                ),
            ]
        );
    }

    /// L10 regression: only a literal "/0" was refused (and only in the
    /// API): "0.0.0.0/1" + "128.0.0.0/1" passed, and the config file was
    /// not checked at all.
    #[test]
    fn open_resolver_acls_are_refused_everywhere() {
        let bad: &[&[&str]] = &[
            &["0.0.0.0/0"],
            &["::/0"],
            &["0.0.0.0/1", "128.0.0.0/1"],
            &["10.0.0.0/7"],
            &["2000::/3"],
            &["2001:db8::/15"],
        ];
        for list in bad {
            let list: Vec<String> = list.iter().map(|s| s.to_string()).collect();
            assert!(!open_resolver_problems(&list).is_empty(), "{list:?}");
            let text = format!("[forwarding]\nallowed_clients = {list:?}");
            let msg = err_of(&text);
            assert!(msg.contains("open resolver"), "{msg}");
        }
        // Many /8s that add up to a large share.
        let many: Vec<String> = (1..=20).map(|i| format!("{}.0.0.0/8", i * 10)).collect();
        assert!(open_resolver_problems(&many)
            .iter()
            .any(|e| e.contains("together")));
        // The defaults and ordinary networks are fine.
        let ok = ForwardingConfig::default().allowed_clients;
        assert!(open_resolver_problems(&ok).is_empty(), "{ok:?}");
        let ok: Vec<String> = [
            "203.0.113.0/24",
            "198.51.100.7",
            "2001:db8:1::/48",
            "fd00::/8",
            "100.64.0.0/10",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert!(open_resolver_problems(&ok).is_empty());
    }

    /// The guard stays the default; `open_resolver = true` is the explicit
    /// override that lets `allowed_clients` cover everything.
    #[test]
    fn open_resolver_flag_lifts_the_guard() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(!cfg.forwarding.open_resolver);
        assert_eq!(cfg.forwarding.open_resolver_max_udp_payload, 512);
        assert_eq!(cfg.forwarding.open_resolver_rate_per_second, 20);
        assert_eq!(cfg.forwarding.max_inflight, 1024);
        assert!(open_resolver_warnings(&cfg.forwarding).is_empty());
        // Without the flag: refused, and the message names the override.
        let msg = err_of("[forwarding]\nallowed_clients = [\"0.0.0.0/0\", \"::/0\"]");
        assert!(msg.contains("open resolver"), "{msg}");
        assert!(msg.contains("open_resolver = true"), "{msg}");
        // With it: accepted, and loudly reported.
        let cfg: Config = toml::from_str(
            "[forwarding]\nopen_resolver = true\nupstreams = [\"1.1.1.1:53\"]\nallowed_clients = [\"0.0.0.0/0\", \"::/0\"]",
        )
        .unwrap();
        validate(&cfg).unwrap();
        let w = open_resolver_warnings(&cfg.forwarding);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("open_resolver is ON"), "{w:?}");
        assert!(w[0].contains("0.0.0.0/0"), "{w:?}");
        // The payload cap is validated either way.
        let msg = err_of("[forwarding]\nopen_resolver_max_udp_payload = 100");
        assert!(msg.contains("open_resolver_max_udp_payload"), "{msg}");
        let msg =
            err_of("[forwarding]\nopen_resolver = true\nopen_resolver_max_udp_payload = 9000");
        assert!(msg.contains("open_resolver_max_udp_payload"), "{msg}");
        // No extra rate limit and no upstreams are pointed out.
        let cfg: Config = toml::from_str(
            "[forwarding]\nopen_resolver = true\nopen_resolver_rate_per_second = 0\nallowed_clients = []",
        )
        .unwrap();
        validate(&cfg).unwrap();
        let w = open_resolver_warnings(&cfg.forwarding);
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("none listed"), "{w:?}");
    }

    #[test]
    fn cache_ttl_caps_are_validated_and_default() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.forwarding.cache_max_ttl, 86_400);
        assert_eq!(cfg.forwarding.cache_negative_max_ttl, 3_600);
        let msg = err_of("[forwarding]\ncache_max_ttl = 0");
        assert!(
            msg.contains("[forwarding].cache_max_ttl must be between"),
            "{msg}"
        );
        let msg = err_of("[forwarding]\ncache_max_ttl = 700000");
        assert!(msg.contains("cache_max_ttl must be between"), "{msg}");
        let msg = err_of("[forwarding]\ncache_max_ttl = 60\ncache_negative_max_ttl = 120");
        assert!(msg.contains("must not exceed"), "{msg}");
        let cfg: Config =
            toml::from_str("[forwarding]\ncache_max_ttl = 600\ncache_negative_max_ttl = 60")
                .unwrap();
        validate(&cfg).unwrap();
    }

    #[test]
    fn proxy_on_needs_an_explicit_trust_list() {
        let msg = err_of("[web_console]\nproxy_on = true");
        assert!(msg.contains("[web_console].proxy_on = true needs"), "{msg}");
        let msg = err_of("[tcp_dns]\nproxy_on = true");
        assert!(msg.contains("[tcp_dns].proxy_on = true needs"), "{msg}");
        let cfg: Config =
            toml::from_str("[web_console]\nproxy_on = true\nproxy_trust = \"127.0.0.1/32\"")
                .unwrap();
        validate(&cfg).unwrap();
        assert!(cfg.web_console.proxy.broad_trust_entries().is_empty());
        let cfg: Config = toml::from_str("[web_console]\nproxy_trust = \"172.16.0.0/12\"").unwrap();
        assert_eq!(
            cfg.web_console.proxy.broad_trust_entries(),
            vec!["172.16.0.0/12"]
        );
    }

    #[test]
    fn validate_bad_cidr() {
        let msg = err_of("[forwarding]\nallowed_clients = [\"10.0.0.0/8\", \"10.0.0/8\"]");
        assert!(
            msg.contains("[forwarding].allowed_clients: '10.0.0/8'"),
            "{msg}"
        );
        assert!(!msg.contains("'10.0.0.0/8'"), "{msg}");
    }

    #[test]
    fn validate_proxy_version() {
        let msg = err_of("[tcp_dns]\nproxy_version = 3");
        assert!(
            msg.contains("[tcp_dns].proxy_version must be 1 or 2 (got 3)"),
            "{msg}"
        );
        let msg = err_of("[web_console]\nproxy_version = 3");
        assert!(msg.contains("[web_console].proxy_version"), "{msg}");
    }

    #[test]
    fn validate_log_level_and_format() {
        let msg = err_of("[logging]\nlevel = \"info,foo=notalevel\"");
        assert!(msg.contains("[logging].level"), "{msg}");
        let cfg: Config =
            toml::from_str("[logging]\nlevel = \"rust_dns=debug,info\"\nformat = \"JSON\"")
                .unwrap();
        validate(&cfg).unwrap();
    }

    #[test]
    fn validate_port_zero() {
        let msg = err_of("[server]\nport = 0");
        assert!(msg.contains("[server].port must not be 0"), "{msg}");
    }

    #[test]
    fn validate_web_dns_collision() {
        // Unspecified DNS bind overlaps any web address on the same port.
        let msg = err_of("[server]\nport = 8053\n[web_console]\nbind = \"127.0.0.1:8053\"");
        assert!(msg.contains("[web_console].bind"), "{msg}");
        // Equal addresses collide.
        let msg = err_of(
            "[server]\nbind = [\"10.0.0.1\"]\nport = 5353\n[web_console]\nbind = \"10.0.0.1:5353\"",
        );
        assert!(msg.contains("[web_console].bind"), "{msg}");
        // Distinct specific addresses do not.
        let cfg: Config = toml::from_str(
            "[server]\nbind = [\"10.0.0.1\"]\nport = 5353\n[web_console]\nbind = \"10.0.0.2:5353\"",
        )
        .unwrap();
        validate(&cfg).unwrap();
        // TCP DNS disabled: no collision.
        let cfg: Config = toml::from_str(
            "[server]\nport = 8053\ntcp = false\n[web_console]\nbind = \"127.0.0.1:8053\"",
        )
        .unwrap();
        validate(&cfg).unwrap();
    }

    #[test]
    fn validate_hostmaster_forms() {
        let cfg: Config = toml::from_str(
            "[server]\ndefault_primary_ns = \"ns1.example.com\"\ndefault_hostmaster = \"hostmaster@example.com\"",
        )
        .unwrap();
        validate(&cfg).unwrap();
        let cfg: Config =
            toml::from_str("[server]\ndefault_hostmaster = \"hostmaster.example.com\"").unwrap();
        validate(&cfg).unwrap();
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rust-dns-cfgtest-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A2 regression: a fresh install must not run with a known password.
    #[test]
    fn init_config_writes_a_private_file_with_a_random_hashed_password() {
        let d = scratch("init");
        let p = d.join("rust-dns.toml");
        let (user, pw) = init_config(&p).unwrap();
        assert_eq!(user, "root");
        assert!(pw.len() >= 20, "random password: {pw}");
        #[cfg(unix)]
        assert_eq!(mode(&p), 0o600);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains(&pw), "the plaintext is never written");
        let cfg = check(&p).unwrap();
        assert!(crate::auth::is_password_hash(&cfg.root.password));
        assert!(crate::auth::verify_password(&pw, &cfg.root.password));
        // Never overwrites.
        let err = format!("{:#}", init_config(&p).unwrap_err());
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
        // Two runs give different passwords.
        let (_, pw2) = init_config(&d.join("other.toml")).unwrap();
        assert_ne!(pw, pw2);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A2 regression: the documented placeholder and an empty password are
    /// refused by --check and at startup, also once hashed by an old start.
    #[test]
    fn placeholder_and_empty_root_passwords_are_refused() {
        let d = scratch("placeholder");
        let p = d.join("c.toml");
        std::fs::write(&p, sample_with_placeholder()).unwrap();
        let err = format!("{:#}", check(&p).unwrap_err());
        assert!(err.contains("placeholder"), "{err}");
        let err = format!("{:#}", load_or_init(&p).unwrap_err());
        assert!(err.contains("placeholder"), "{err}");
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .contains("\"change-me\""),
            "a refused config is not rewritten"
        );
        let hashed = crate::auth::hash_password("change-me").unwrap();
        std::fs::write(&p, SAMPLE.replace("__PASSWORD__", &hashed)).unwrap();
        assert!(format!("{:#}", check(&p).unwrap_err()).contains("placeholder"));
        std::fs::write(&p, SAMPLE.replace("__PASSWORD__", "Change-Me-Please")).unwrap();
        assert!(format!("{:#}", check(&p).unwrap_err()).contains("placeholder"));
        std::fs::write(&p, SAMPLE.replace("__PASSWORD__", "")).unwrap();
        assert!(format!("{:#}", check(&p).unwrap_err()).contains("must be set"));
        std::fs::write(&p, SAMPLE.replace("__PASSWORD__", "a-real-password")).unwrap();
        check(&p).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L7: the hashing rewrite and first-start creation leave the file 0600.
    #[cfg(unix)]
    #[test]
    fn config_rewrites_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("perms");
        let p = d.join("c.toml");
        std::fs::write(&p, SAMPLE.replace("__PASSWORD__", "a-real-password")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (cfg, generated) = load_or_init(&p).unwrap();
        assert!(generated.is_none());
        assert!(crate::auth::is_password_hash(&cfg.root.password));
        assert_eq!(mode(&p), 0o600, "rewritten owner-only");
        let fresh = d.join("fresh.toml");
        let (cfg, generated) = load_or_init(&fresh).unwrap();
        let pw = generated.expect("a generated password");
        assert!(crate::auth::verify_password(&pw, &cfg.root.password));
        assert_eq!(mode(&fresh), 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }
}
