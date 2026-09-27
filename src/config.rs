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
    pub logging: LoggingConfig,
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
    /// Idle timeout for TCP connections, seconds.
    pub tcp_idle_timeout_secs: u64,
    /// Maximum concurrent DNS-over-TCP connections.
    pub max_tcp_connections: usize,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// 0 disables rate limiting.
    pub max_resolutions_per_second_per_address: u32,
    /// Upper bound on tracked client addresses (LRU eviction beyond this).
    pub max_tracked_addresses: usize,
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
    /// Secondaries to NOTIFY when a zone changes, e.g. ["203.0.113.5:53"].
    pub notify: Vec<SocketAddr>,
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
    /// X-Forwarded-For / X-Real-IP). `"cidr;cidr"` or a list. Empty = LAN ranges.
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
    pub fn trusted_cidrs(&self) -> Vec<Cidr> {
        let list = self.proxy_trust.entries();
        if list.is_empty() {
            return parse_cidrs(&LAN_RANGES.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        }
        parse_cidrs(&list)
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

pub const LAN_RANGES: [&str; 8] = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub enabled: bool,
    #[serde(flatten)]
    pub proxy: ProxyConfig,
    pub session_ttl_hours: u64,
    /// Mark the session cookie `Secure` (set when served over HTTPS via a proxy).
    pub secure_cookies: bool,
    /// Failed login attempts allowed per address per minute.
    pub login_attempts_per_minute: u32,
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
            max_tcp_connections: 1000,
            minimal_any: true,
            default_primary_ns: String::new(),
            default_hostmaster: String::new(),
            nsid: String::new(),
            cookies: true,
            cookies_required: false,
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
        }
    }
}
impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_resolutions_per_second_per_address: 500,
            max_tracked_addresses: 10_000,
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
        ChangelogConfig { retention_days: 30 }
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
max_tcp_connections = 1000
minimal_any = true       # RFC 8482: minimal ANY answers (anti-amplification)
default_primary_ns = ""  # SOA MNAME for new zones, e.g. "ns1.example.com"; empty = ns1.<zone>
default_hostmaster = ""  # SOA RNAME for new zones, e.g. "hostmaster@example.com"; empty = hostmaster.<zone>
nsid = ""                # EDNS NSID reply (RFC 5001), e.g. the host name; empty = off
cookies = true           # issue/verify DNS server cookies (RFC 7873)
cookies_required = false # strict mode: UDP queries without a valid cookie get BADCOOKIE

[forwarding]
upstreams = []           # e.g. ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]; empty = REFUSED for foreign names
timeout_ms = 2000
# Only these networks may use forwarding; never open this to the internet.
allowed_clients = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]
cache_entries = 10000    # TTL-aware cache for forwarded answers; 0 = off

[transfer]
allow = []               # networks allowed to AXFR zones (for BIND/NSD secondaries), e.g. ["203.0.113.5/32"]
notify = []              # secondaries to NOTIFY on change, e.g. ["203.0.113.5:53"]

[rate_limit]
max_resolutions_per_second_per_address = 500
max_tracked_addresses = 10000

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
proxy_trust = ""         # "192.168.44.0/24;fe80::/64" - peers allowed to send PROXY headers; empty = local LAN ranges

[web_console]
bind = "127.0.0.1:8053"
enabled = true
proxy_on = false         # accept PROXY protocol from trusted peers
proxy_version = 2        # 1 or 2
proxy_trust = ""         # also governs X-Forwarded-For / X-Real-IP trust; empty = local LAN ranges
session_ttl_hours = 12
secure_cookies = false   # set true when served over HTTPS
login_attempts_per_minute = 10

[root]
username = "root"
password = "__PASSWORD__"   # plaintext is hashed in place on first start
mfa_required = false

[changelog]
retention_days = 30

[expiry]
retention_days = 30      # expired records stop answering at once and are deleted after this many days
sweep_interval_secs = 60 # upper bound on the sweeper's sleep; it also wakes at the next due expiry

[logging]
format = "text"          # "text" or "json"
level = "info"           # e.g. "info", "debug", "rust_dns=debug,info"
log_queries = false      # log every DNS query
file = ""                # log file; empty = stdout
query_log_file = ""      # separate query log file; empty = queries go to the main log
max_size_mb = 50         # rotate when the file exceeds this size
max_files = 10           # rotated files to keep per log
compress = true          # gzip rotated files
"#;

/// Load the config, creating a default file with a random root password if
/// it does not exist. Hashes a plaintext root password in place.
pub fn load_or_init(path: &Path) -> Result<(Config, Option<String>)> {
    let mut generated_password = None;
    if !path.exists() {
        let pw = crate::auth::random_token(12);
        let text = SAMPLE.replace("__PASSWORD__", &pw);
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        tracing::info!(path = %path.display(), "wrote default configuration");
        generated_password = Some(pw);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    validate(&cfg).with_context(|| format!("validating {}", path.display()))?;
    if cfg.root.password.is_empty() {
        anyhow::bail!("[root].password must be set in {}", path.display());
    }
    if !crate::auth::is_password_hash(&cfg.root.password) {
        let hash = crate::auth::hash_password(&cfg.root.password)?;
        let mut doc: toml_edit::DocumentMut =
            text.parse().context("re-parsing config for rewrite")?;
        doc["root"]["password"] = toml_edit::value(hash.clone());
        std::fs::write(path, doc.to_string())
            .with_context(|| format!("rewriting {}", path.display()))?;
        tracing::info!("hashed the plaintext [root].password in the configuration file");
        cfg.root.password = hash;
    }
    Ok((cfg, generated_password))
}

/// Parse and validate an existing configuration without creating or rewriting it.
pub fn check(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    anyhow::ensure!(!cfg.root.password.is_empty(), "[root].password must be set");
    validate(&cfg).with_context(|| format!("validating {}", path.display()))?;
    Ok(cfg)
}

/// Validate a parsed configuration. Collects every problem and returns a
/// single error listing each one on its own line, naming the TOML key.
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
    if cfg.forwarding.timeout_ms == 0 {
        errs.push("[forwarding].timeout_ms must be greater than zero".into());
    }

    // [transfer]
    check_cidrs("[transfer].allow", &cfg.transfer.allow, &mut errs);
    for n in &cfg.transfer.notify {
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
    if cfg.expiry.sweep_interval_secs == 0 {
        errs.push("[expiry].sweep_interval_secs must be greater than zero".into());
    }

    // [root]
    if cfg.root.username.trim().is_empty() {
        errs.push("[root].username must not be empty".into());
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
    ip: IpAddr,
    prefix: u8,
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
        assert_eq!(cfg.tcp_dns.trusted_cidrs().len(), LAN_RANGES.len());
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
allowed_clients = ["10.0.0.0/33"]
[transfer]
allow = ["nope"]
notify = ["0.0.0.0:53"]
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
            "[forwarding].allowed_clients: '10.0.0.0/33'",
            "[transfer].allow: 'nope'",
            "[transfer].notify",
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
        assert!(msg.starts_with("20 configuration error(s):"), "{msg}");
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
}
