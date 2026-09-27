//! Server settings changed from the console or API. They are stored in the
//! `settings` table and override the config file until reset. Writes go
//! through [`AuditTx`], so every change and its audit entry commit together.

use super::accounts::AuditTx;
use crate::config::Cidr;
use crate::storage::Storage;
use anyhow::Result;
use rusqlite::params;
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
pub fn validate(
    upstreams: &[String],
    allowed_clients: &[String],
    timeout_ms: u64,
    caps: (Option<u32>, Option<u32>),
    file: &crate::config::ForwardingConfig,
) -> Result<ForwardingSettings, Vec<String>> {
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
    // 128.0.0.0/1): see config::open_resolver_problems.
    errs.extend(crate::config::open_resolver_problems(&acl));
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
        self.record(crate::mutation::Change::SettingSet {
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
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM settings WHERE key = ?1",
            params![FORWARDING_KEY],
            |r| r.get(0),
        )?;
        if n > 0 {
            self.record(crate::mutation::Change::SettingCleared {
                key: FORWARDING_KEY.into(),
            })?;
        }
        if n > 0 {
            self.push(
                "settings.forwarding.reset",
                None,
                "forwarding",
                serde_json::json!({ "before": before }),
            );
        }
        Ok(n > 0)
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
            &crate::config::ForwardingConfig::default(),
        )
        .unwrap_err();
        assert!(errs.iter().any(|e| e.contains("open resolver")), "{errs:?}");
        // Cache caps: validated as they would be in effect.
        let file = crate::config::ForwardingConfig::default();
        let errs = validate(&[], &[], 1000, (Some(60), Some(120)), &file).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("must not exceed")),
            "{errs:?}"
        );
        let errs = validate(&[], &[], 1000, (None, Some(90_000)), &file).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("must not exceed")),
            "{errs:?}"
        );
        let ok = validate(&[], &[], 1000, (Some(7200), None), &file).unwrap();
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
