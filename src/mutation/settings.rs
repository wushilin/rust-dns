//! Server settings changed from the console or API. They are stored in the
//! `settings` table and override the config file until reset. Writes go
//! through [`AuditTx`], so every change and its audit entry commit together.

use super::accounts::AuditTx;
use crate::config::Cidr;
use crate::storage::Storage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use utoipa::ToSchema;

pub const FORWARDING_KEY: &str = "forwarding";
pub const MAX_UPSTREAMS: usize = 8;

/// Forwarding settings that can be managed at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ForwardingSettings {
    /// Upstream resolvers, tried in order.
    #[schema(value_type = Vec<String>, example = json!(["192.168.44.99:53", "8.8.8.8:53", "[2001:4860:4860::8888]:53"]))]
    pub upstreams: Vec<SocketAddr>,
    /// Client networks allowed to use forwarding.
    #[schema(example = json!(["192.168.0.0/16", "fd00::/8"]))]
    pub allowed_clients: Vec<String>,
    /// Timeout per upstream, milliseconds.
    #[schema(example = 2000)]
    pub timeout_ms: u64,
    /// Cap on how long positive answers are cached, seconds. Absent: the
    /// config file's `cache_max_ttl` (also for overrides saved by older
    /// versions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, example = 86400)]
    pub cache_max_ttl: Option<u32>,
    /// Cap on how long negative answers are cached, seconds. Absent: the
    /// config file's `cache_negative_max_ttl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, example = 3600)]
    pub cache_negative_max_ttl: Option<u32>,
    /// Deliberate open resolver: `allowed_clients` may cover any network
    /// and the open-resolver safeguards apply. Always stored explicitly;
    /// absent (overrides saved by older versions): the config file's
    /// `open_resolver`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, example = false)]
    pub open_resolver: Option<bool>,
}

/// Parse one upstream: `1.1.1.1`, `1.1.1.1:5353`, `2606:4700:4700::1111`,
/// `[2606:4700:4700::1111]:53`. Port 53 when omitted. Host names are not
/// accepted (resolving them would need the resolver being configured).
pub fn parse_upstream(s: &str) -> Result<SocketAddr, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty upstream".into());
    }
    if let Ok(sa) = t.parse::<SocketAddr>() {
        if sa.port() == 0 {
            return Err(format!("'{t}': port must not be 0"));
        }
        return check_ip(sa.ip(), t).map(|_| sa);
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        check_ip(ip, t)?;
        return Ok(SocketAddr::new(ip, 53));
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            check_ip(ip, t)?;
            return Ok(SocketAddr::new(ip, 53));
        }
    }
    Err(format!(
        "'{t}' is not an IP address (host names are not supported); examples: 1.1.1.1, 8.8.8.8:53, [2606:4700:4700::1111]:53"
    ))
}

fn check_ip(ip: IpAddr, t: &str) -> Result<(), String> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("'{t}' is not a usable resolver address"));
    }
    Ok(())
}

/// Validate and normalise user input. Collects every problem.
/// `open_resolver`: `None` means the config file's value; the result always
/// stores it explicitly, so a later change of the file cannot turn a wide
/// ACL saved here into an open resolver without the safeguards.
pub fn validate(
    upstreams: &[String],
    allowed_clients: &[String],
    timeout_ms: u64,
    caps: (Option<u32>, Option<u32>),
    open_resolver: Option<bool>,
    file: &crate::config::ForwardingConfig,
) -> Result<ForwardingSettings, Vec<String>> {
    let open_resolver = open_resolver.unwrap_or(file.open_resolver);
    let mut errs = Vec::new();
    let mut ups: Vec<SocketAddr> = Vec::new();
    for u in upstreams.iter().map(|u| u.trim()).filter(|u| !u.is_empty()) {
        match parse_upstream(u) {
            Ok(sa) if ups.contains(&sa) => errs.push(format!("upstream {sa} is listed twice")),
            Ok(sa) => ups.push(sa),
            Err(e) => errs.push(e),
        }
    }
    if ups.len() > MAX_UPSTREAMS {
        errs.push(format!("at most {MAX_UPSTREAMS} upstreams"));
    }
    let mut acl: Vec<String> = Vec::new();
    for a in allowed_clients
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
    {
        match Cidr::parse(a) {
            None => errs.push(format!(
                "'{a}' is not a valid network (CIDR such as 192.168.0.0/16, or a single address)"
            )),
            Some(_) => {
                if !acl.iter().any(|x| x == a) {
                    acl.push(a.to_string());
                }
            }
        }
    }
    // Refuses 0.0.0.0/0 and anything close to it (e.g. 0.0.0.0/1 +
    // 128.0.0.0/1): see config::open_resolver_problems. Skipped only for a
    // deliberate open resolver.
    if !open_resolver {
        errs.extend(
            crate::config::open_resolver_problems(&acl)
                .into_iter()
                .map(|e| format!("{e} (or turn on open resolver mode if that is really intended)")),
        );
    }
    if !(100..=30_000).contains(&timeout_ms) {
        errs.push("timeout_ms must be between 100 and 30000".into());
    }
    // Checked as they would be in effect (a missing cap is the file's).
    errs.extend(crate::config::cache_cap_problems(
        caps.0.unwrap_or(file.cache_max_ttl),
        caps.1.unwrap_or(file.cache_negative_max_ttl),
    ));
    if errs.is_empty() {
        Ok(ForwardingSettings {
            upstreams: ups,
            allowed_clients: acl,
            timeout_ms,
            cache_max_ttl: caps.0,
            cache_negative_max_ttl: caps.1,
            open_resolver: Some(open_resolver),
        })
    } else {
        Err(errs)
    }
}

/// The stored override, with who set it and when.
pub fn load_forwarding(storage: &Storage) -> Result<Option<(ForwardingSettings, String, String)>> {
    match storage.get_setting(FORWARDING_KEY)? {
        None => Ok(None),
        Some((value, by, at)) => Ok(Some((serde_json::from_str(&value)?, by, at))),
    }
}

impl AuditTx<'_> {
    /// Store the forwarding override (replacing any previous one).
    pub fn set_forwarding(
        &mut self,
        actor: &str,
        before: Option<&ForwardingSettings>,
        after: &ForwardingSettings,
    ) -> Result<()> {
        self.record(crate::mutation::SecretChange::SettingSet {
            setting: crate::replication::types::ReplSetting {
                key: FORWARDING_KEY.into(),
                value: serde_json::to_string(after)?,
                updated_by: actor.to_string(),
                updated_at: crate::model::now_rfc3339(),
            },
        })?;
        self.push(
            "settings.forwarding.update",
            None,
            "forwarding",
            serde_json::json!({ "before": before, "after": after }),
        );
        Ok(())
    }

    /// Record a flush of the forwarding cache (no stored data changes).
    pub fn note_cache_flush(&mut self, dropped: usize) {
        self.push(
            "settings.forwarding.cache_flush",
            None,
            "forwarding",
            serde_json::json!({ "dropped": dropped }),
        );
    }

    /// Remove the override: the config file applies again.
    pub fn clear_forwarding(&mut self, before: &ForwardingSettings) -> Result<bool> {
        let stored = self.has_setting(FORWARDING_KEY)?;
        if stored {
            self.record(crate::mutation::SecretChange::SettingCleared {
                key: FORWARDING_KEY.into(),
            })?;
            self.push(
                "settings.forwarding.reset",
                None,
                "forwarding",
                serde_json::json!({ "before": before }),
            );
        }
        Ok(stored)
    }
}

pub const RESOLVER_KEY: &str = "resolver";

/// How forwarded queries pick among the upstreams (I6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStrategy {
    /// Try the upstreams one after the other, in the order listed (the
    /// behaviour before strategies existed).
    #[default]
    InOrder,
    /// Prefer the healthy upstream with the lowest average latency.
    Fastest,
    /// Ask every healthy upstream at once; the first valid answer wins.
    Parallel,
}

fn yes() -> bool {
    true
}
fn one_day() -> u32 {
    86_400
}
fn v4_prefix() -> u8 {
    24
}
fn v6_prefix() -> u8 {
    56
}

/// Resolver behaviour for forwarded queries, set from the console
/// (Server settings -> Forwarding). Stored as the `resolver` setting
/// (replicated as `setting_set`); absent: the defaults. Fields missing from
/// a stored value (saved by an older version) take their defaults, and
/// fields this version does not know are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolverSettings {
    /// `domain-needed`: never forward single-label names (`wpad`,
    /// `printer`); they get NXDOMAIN here unless an own or override zone
    /// has them. Default on.
    #[serde(default = "yes")]
    pub domain_needed: bool,
    /// `bogus-priv`: never forward reverse lookups of private and special
    /// ranges (RFC 6303: 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8,
    /// 169.254/16, 0/8, fc00::/7, fe80::/10, ::1, ::); NXDOMAIN here unless
    /// an own zone or automatic PTR covers the address. Default on.
    #[serde(default = "yes")]
    pub bogus_priv: bool,
    /// `stop-dns-rebind`: forwarded answers that contain private,
    /// loopback, link-local, CGNAT, ULA, `0.0.0.0` or `::` addresses are
    /// refused. Never applied to own or override zones. Default off.
    #[serde(default)]
    pub rebind_protection: bool,
    /// Domains (and everything below them) exempt from rebinding
    /// protection (`rebind-domain-ok`).
    #[serde(default)]
    #[schema(example = json!(["internal", "amazonaws.com"]))]
    pub rebind_allow: Vec<String>,
    /// Serve stale (RFC 8767): when every upstream fails or times out,
    /// answer from an expired cache entry (TTL 30 s). Default off.
    #[serde(default)]
    pub serve_stale: bool,
    /// How long past its expiry a cache entry may still be served stale,
    /// seconds (60 to 604800).
    #[serde(default = "one_day")]
    #[schema(example = 86400)]
    pub max_stale_age_secs: u32,
    #[serde(default)]
    pub strategy: UpstreamStrategy,
    /// Record types never forwarded (`filter-AAAA`, `filter-rr`): such a
    /// query gets an empty answer (NODATA) here. Default none.
    #[serde(default)]
    #[schema(example = json!(["AAAA"]))]
    pub filter_types: Vec<String>,
    /// EDNS Client Subnet (`add-subnet`, RFC 7871) on forwarded queries.
    /// Default off.
    #[serde(default)]
    pub ecs: bool,
    /// Prefix of an IPv4 client address sent upstream (1 to 32).
    #[serde(default = "v4_prefix")]
    #[schema(example = 24)]
    pub ecs_ipv4_prefix: u8,
    /// Prefix of an IPv6 client address sent upstream (1 to 128).
    #[serde(default = "v6_prefix")]
    #[schema(example = 56)]
    pub ecs_ipv6_prefix: u8,
    /// Also send the subnet of clients in private and special ranges.
    #[serde(default)]
    pub ecs_private_clients: bool,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        // One source of truth for the defaults: the serde defaults.
        serde_json::from_str("{}").expect("defaults")
    }
}

/// Record types that may be filtered (`filter_types`): data types only.
pub fn parse_filter_type(s: &str) -> Result<hickory_proto::rr::RecordType, String> {
    use hickory_proto::rr::RecordType as T;
    let t = s.trim().to_ascii_uppercase();
    let rt: T = t
        .parse()
        .map_err(|_| format!("'{s}' is not a record type"))?;
    match rt {
        T::A
        | T::AAAA
        | T::MX
        | T::TXT
        | T::SRV
        | T::HTTPS
        | T::SVCB
        | T::CNAME
        | T::PTR
        | T::NS
        | T::CAA
        | T::NAPTR
        | T::SSHFP
        | T::TLSA
        | T::ANY
        | T::SOA
        | T::DS
        | T::DNSKEY => Ok(rt),
        _ => Err(format!("'{s}' cannot be filtered")),
    }
}

impl ResolverSettings {
    /// Validate and normalise; every problem is listed.
    pub fn validate(mut self) -> Result<Self, Vec<String>> {
        let mut errs = Vec::new();
        let mut allow = Vec::new();
        for a in self
            .rebind_allow
            .iter()
            .map(|a| a.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|a| !a.is_empty())
        {
            let ok = a.len() <= 253
                && a.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && l.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                });
            if !ok {
                errs.push(format!("rebind allowlist: '{a}' is not a domain name"));
            } else if !allow.contains(&a) {
                allow.push(a);
            }
        }
        if allow.len() > 200 {
            errs.push("rebind allowlist: at most 200 domains".into());
        }
        self.rebind_allow = allow;
        if !(60..=604_800).contains(&self.max_stale_age_secs) {
            errs.push("max_stale_age_secs must be between 60 and 604800".into());
        }
        let mut types: Vec<String> = Vec::new();
        for t in self.filter_types.iter().filter(|t| !t.trim().is_empty()) {
            match parse_filter_type(t) {
                Ok(rt) => {
                    let s = rt.to_string();
                    if !types.contains(&s) {
                        types.push(s);
                    }
                }
                Err(e) => errs.push(e),
            }
        }
        self.filter_types = types;
        if !(1..=32).contains(&self.ecs_ipv4_prefix) {
            errs.push("ecs_ipv4_prefix must be between 1 and 32".into());
        }
        if !(1..=128).contains(&self.ecs_ipv6_prefix) {
            errs.push("ecs_ipv6_prefix must be between 1 and 128".into());
        }
        if errs.is_empty() {
            Ok(self)
        } else {
            Err(errs)
        }
    }
}

/// The stored resolver settings, with who set them and when.
pub fn load_resolver(storage: &Storage) -> Result<Option<(ResolverSettings, String, String)>> {
    match storage.get_setting(RESOLVER_KEY)? {
        None => Ok(None),
        Some((value, by, at)) => Ok(Some((serde_json::from_str(&value)?, by, at))),
    }
}

/// The stored blocklist configuration, with who set it and when.
pub fn load_blocklists(
    storage: &Storage,
) -> Result<Option<(crate::blocklist::BlocklistSettings, String, String)>> {
    match storage.get_setting(crate::blocklist::SETTINGS_KEY)? {
        None => Ok(None),
        Some((value, by, at)) => Ok(Some((serde_json::from_str(&value)?, by, at))),
    }
}

impl AuditTx<'_> {
    /// Store a console setting `key` (replacing any previous value) and
    /// audit it as `action` (`settings.<key>.update`) with before/after.
    pub fn set_setting<T: Serialize>(
        &mut self,
        key: &str,
        action: &'static str,
        actor: &str,
        before: Option<&T>,
        after: &T,
    ) -> Result<()> {
        self.record(crate::mutation::SecretChange::SettingSet {
            setting: crate::replication::types::ReplSetting {
                key: key.into(),
                value: serde_json::to_string(after)?,
                updated_by: actor.to_string(),
                updated_at: crate::model::now_rfc3339(),
            },
        })?;
        self.push(
            action,
            None,
            key,
            serde_json::json!({ "before": before, "after": after }),
        );
        Ok(())
    }

    /// Remove a console setting `key` (defaults apply again); audited as
    /// `settings.<key>.reset`. Returns whether there was one.
    pub fn clear_setting<T: Serialize>(
        &mut self,
        key: &str,
        action: &'static str,
        before: &T,
    ) -> Result<bool> {
        let stored = self.has_setting(key)?;
        if stored {
            self.record(crate::mutation::SecretChange::SettingCleared { key: key.into() })?;
            self.push(action, None, key, serde_json::json!({ "before": before }));
        }
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Actor;
    use crate::mutation::accounts::Accounts;
    use std::sync::Arc;

    #[test]
    fn upstream_forms() {
        assert_eq!(
            parse_upstream("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_upstream(" 8.8.8.8:5353 ").unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("2606:4700:4700::1111").unwrap(),
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("[2606:4700:4700::1111]").unwrap(),
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("[2001:db8::1]:853").unwrap(),
            "[2001:db8::1]:853".parse().unwrap()
        );
        assert!(parse_upstream("dns.google")
            .unwrap_err()
            .contains("host names are not supported"));
        assert!(parse_upstream("0.0.0.0").is_err());
        assert!(parse_upstream("1.1.1.1:0").is_err());
        assert!(parse_upstream("").is_err());
    }

    #[test]
    fn validation_collects_every_problem() {
        let errs = validate(
            &["1.1.1.1".into(), "1.1.1.1:53".into(), "bogus".into()],
            &[
                "0.0.0.0/0".into(),
                "10.0.0.0/33".into(),
                "192.168.0.0/16".into(),
            ],
            50,
            (None, None),
            None,
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap_err();
        assert_eq!(errs.len(), 5, "{errs:?}");
        assert!(errs.iter().any(|e| e.contains("listed twice")));
        assert!(errs.iter().any(|e| e.contains("open resolver")));
        assert!(errs.iter().any(|e| e.contains("10.0.0.0/33")));
        assert!(errs.iter().any(|e| e.contains("timeout_ms")));
        // L10: a /0 split in halves is just as open.
        let errs = validate(
            &["1.1.1.1".into()],
            &["0.0.0.0/1".into(), "128.0.0.0/1".into()],
            1000,
            (None, None),
            None,
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap_err();
        assert!(errs.iter().any(|e| e.contains("open resolver")), "{errs:?}");
        // Cache caps: validated as they would be in effect.
        let file = crate::config::ForwardingConfig::default();
        let errs = validate(&[], &[], 1000, (Some(60), Some(120)), None, &file).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("must not exceed")),
            "{errs:?}"
        );
        let errs = validate(&[], &[], 1000, (None, Some(90_000)), None, &file).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("must not exceed")),
            "{errs:?}"
        );
        let ok = validate(&[], &[], 1000, (Some(7200), None), None, &file).unwrap();
        assert_eq!(
            (ok.cache_max_ttl, ok.cache_negative_max_ttl),
            (Some(7200), None)
        );
        // Overrides stored before the caps existed still load.
        let old: ForwardingSettings = serde_json::from_str(
            r#"{"upstreams":["1.1.1.1:53"],"allowed_clients":[],"timeout_ms":2000}"#,
        )
        .unwrap();
        assert_eq!(old.cache_max_ttl, None);
        let ok = validate(
            &["8.8.8.8".into(), "".into()],
            &["192.168.0.0/16".into(), "192.168.0.0/16".into()],
            1500,
            (None, None),
            None,
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap();
        assert_eq!(
            ok.upstreams,
            vec!["8.8.8.8:53".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            ok.allowed_clients,
            vec!["192.168.0.0/16".to_string()],
            "blank lines and duplicates dropped"
        );
    }

    /// The open-resolver guard stays on by default; open resolver mode is
    /// the explicit override. The flag is always stored explicitly.
    #[test]
    fn open_resolver_mode_lifts_the_guard() {
        let file = crate::config::ForwardingConfig::default();
        let wide = ["0.0.0.0/0".to_string(), "::/0".to_string()];
        for flag in [None, Some(false)] {
            let errs =
                validate(&["1.1.1.1".into()], &wide, 1000, (None, None), flag, &file).unwrap_err();
            assert!(errs.iter().any(|e| e.contains("open resolver")), "{errs:?}");
        }
        let ok = validate(
            &["1.1.1.1".into()],
            &wide,
            1000,
            (None, None),
            Some(true),
            &file,
        )
        .unwrap();
        assert_eq!(ok.open_resolver, Some(true));
        assert_eq!(ok.allowed_clients, wide.to_vec());
        // Omitted: the config file's value, stored explicitly.
        let open_file = crate::config::ForwardingConfig {
            open_resolver: true,
            ..file.clone()
        };
        let ok = validate(
            &["1.1.1.1".into()],
            &wide,
            1000,
            (None, None),
            None,
            &open_file,
        )
        .unwrap();
        assert_eq!(ok.open_resolver, Some(true));
        let ok = validate(&[], &["10.0.0.0/8".into()], 1000, (None, None), None, &file).unwrap();
        assert_eq!(ok.open_resolver, Some(false));
        // Explicitly off overrides a file that turns it on.
        assert!(validate(&[], &wide, 1000, (None, None), Some(false), &open_file).is_err());
        // Overrides saved before the flag existed still load (None: the
        // file's value applies) and are written back without the field.
        let old: ForwardingSettings = serde_json::from_str(
            r#"{"upstreams":["1.1.1.1:53"],"allowed_clients":["10.0.0.0/8"],"timeout_ms":2000,"cache_max_ttl":600}"#,
        )
        .unwrap();
        assert_eq!(old.open_resolver, None);
        assert!(!serde_json::to_string(&old)
            .unwrap()
            .contains("open_resolver"));
        let on: ForwardingSettings = serde_json::from_str(
            r#"{"upstreams":[],"allowed_clients":["0.0.0.0/0"],"timeout_ms":2000,"open_resolver":true}"#,
        )
        .unwrap();
        assert_eq!(on.open_resolver, Some(true));
    }

    /// Turning open resolver mode on is a typed `setting_set` change: it is
    /// audited (before/after) and a standby replaying the changelog gets it.
    #[test]
    fn open_resolver_is_audited_and_replicated() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let actor = Actor {
            name: "root".into(),
            ip: "127.0.0.1".into(),
        };
        let file = crate::config::ForwardingConfig::default();
        let off = validate(
            &["9.9.9.9".into()],
            &["10.0.0.0/8".into()],
            1000,
            (None, None),
            None,
            &file,
        )
        .unwrap();
        let on = validate(
            &["9.9.9.9".into()],
            &["0.0.0.0/0".into(), "::/0".into()],
            1000,
            (None, None),
            Some(true),
            &file,
        )
        .unwrap();
        a.run(&actor, "update_forwarding", |t| {
            t.set_forwarding("root", None, &off)
        })
        .unwrap();
        a.run(&actor, "update_forwarding", |t| {
            t.set_forwarding("root", Some(&off), &on)
        })
        .unwrap();
        let audit = s.audit_after(0, 10).unwrap();
        let last = audit.last().unwrap();
        assert_eq!(last.action, "settings.forwarding.update");
        let detail = serde_json::to_string(&last.detail).unwrap();
        assert!(detail.contains(r#""open_resolver":false"#), "{detail}");
        assert!(detail.contains(r#""open_resolver":true"#), "{detail}");

        let events = s
            .read_tx(|c| crate::replication::data::changelog_tail(c, 0))
            .unwrap();
        assert!(events.iter().any(|e| e.payload["kind"] == "setting_set"));
        let standby = Storage::open_memory().unwrap();
        crate::mutation::replay::replay(&standby, &events).unwrap();
        let (got, by, _) = load_forwarding(&standby).unwrap().unwrap();
        assert_eq!(got, on);
        assert_eq!(got.open_resolver, Some(true));
        assert_eq!(by, "root");
    }

    #[test]
    fn override_is_stored_and_audited_in_one_transaction() {
        let s = Arc::new(Storage::open_memory().unwrap());
        let a = Accounts::new(s.clone());
        let actor = Actor {
            name: "root".into(),
            ip: "127.0.0.1".into(),
        };
        let f = validate(
            &["9.9.9.9".into()],
            &["10.0.0.0/8".into()],
            1000,
            (None, None),
            None,
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap();
        a.run(&actor, "update_forwarding", |t| {
            t.set_forwarding("root", None, &f)
        })
        .unwrap();
        let (loaded, by, _) = load_forwarding(&s).unwrap().unwrap();
        assert_eq!(loaded, f);
        assert_eq!(by, "root");
        let audit = s.audit_after(0, 10).unwrap();
        assert_eq!(audit.last().unwrap().action, "settings.forwarding.update");

        // A failing step rolls back the settings write and its audit entry.
        let before = s.audit_after(0, 10).unwrap().len();
        let g = validate(
            &["1.0.0.1".into()],
            &[],
            1000,
            (None, None),
            None,
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap();
        let r: Result<()> = a.run(&actor, "update_forwarding", |t| {
            t.set_forwarding("root", Some(&f), &g)?;
            anyhow::bail!("simulated failure")
        });
        assert!(r.is_err());
        assert_eq!(load_forwarding(&s).unwrap().unwrap().0, f, "unchanged");
        assert_eq!(s.audit_after(0, 10).unwrap().len(), before);

        a.run(&actor, "reset_forwarding", |t| t.clear_forwarding(&f))
            .unwrap();
        assert!(load_forwarding(&s).unwrap().is_none());
        assert_eq!(
            s.audit_after(0, 10).unwrap().last().unwrap().action,
            "settings.forwarding.reset"
        );
    }
}
