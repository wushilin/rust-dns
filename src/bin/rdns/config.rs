//! Where `rdns` keeps its servers and tokens: a TOML file of named profiles,
//! mode 0600, at `$RDNS_CONFIG`, else `$XDG_CONFIG_HOME/rdns/config.toml`,
//! else `~/.config/rdns/config.toml` (`%APPDATA%\rdns\config.toml` on Windows).
//!
//! ```toml
//! default = "prod"
//!
//! [profiles.prod]
//! server = "https://dns.example.com"
//! token = "rdns_..."
//! token_id = 7          # set when `rdns login` minted the token (logout revokes it)
//! user = "alice"
//! ```

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct File {
    /// The profile used when none is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub server: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// PEM file of the CA certificates trusted for this server (a private
    /// CA); absent: the system trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
}

pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("RDNS_CONFIG").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let dir = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    let dir = dir.ok_or_else(|| anyhow!("cannot find a config directory; set RDNS_CONFIG"))?;
    Ok(dir.join("rdns").join("config.toml"))
}

impl File {
    pub fn load() -> Result<Self> {
        let p = path()?;
        match std::fs::read_to_string(&p) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("reading {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Written to a temporary file (0600) and renamed over the old one.
    pub fn save(&self) -> Result<PathBuf> {
        let p = path()?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = p.with_extension("toml.tmp");
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            std::io::Write::write_all(&mut f, toml::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p).with_context(|| format!("writing {}", p.display()))?;
        Ok(p)
    }

    /// The profile name in effect: the one asked for, else the default,
    /// else the only one there is.
    pub fn pick(&self, asked: Option<&str>) -> Option<String> {
        if let Some(a) = asked {
            return Some(a.to_string());
        }
        if let Some(d) = &self.default {
            return Some(d.clone());
        }
        if self.profiles.len() == 1 {
            return self.profiles.keys().next().cloned();
        }
        None
    }
}

/// `https://dns.example.com/`, `…/rust-dns` and `…/rust-dns/api` all mean
/// the same server; stored as the bare origin (plus any path prefix of a
/// reverse proxy).
pub fn normalize_server(s: &str) -> Result<String> {
    let mut s = s.trim().trim_end_matches('/').to_string();
    if s.is_empty() {
        return Err(anyhow!("the server URL is empty"));
    }
    if !s.contains("://") {
        s = format!("https://{s}");
    }
    for suffix in ["/rust-dns/api", "/rust-dns"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.to_string();
        }
    }
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return Err(anyhow!(
            "the server URL must start with http:// or https://"
        ));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_normalize() {
        for s in [
            "dns.example.com",
            "https://dns.example.com/",
            "https://dns.example.com/rust-dns",
            "https://dns.example.com/rust-dns/api/",
        ] {
            assert_eq!(normalize_server(s).unwrap(), "https://dns.example.com");
        }
        assert_eq!(
            normalize_server("http://127.0.0.1:8053").unwrap(),
            "http://127.0.0.1:8053"
        );
        assert!(normalize_server("ftp://x").is_err());
    }
}
