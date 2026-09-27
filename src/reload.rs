//! Runtime configuration reload (SIGHUP or `POST /api/admin/reload`).

use crate::config::{self, Config};
use crate::dns::DnsServer;
use crate::mutation::Mutator;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;

pub struct Reloader {
    pub path: PathBuf,
    pub current: ArcSwap<Config>,
    pub dns: Arc<DnsServer>,
    pub mutator: Arc<Mutator>,
    pub accounts: Arc<crate::mutation::accounts::Accounts>,
}

impl Reloader {
    /// Re-read the config file and apply everything that can change at runtime.
    /// Returns human-readable notes about what was applied or skipped.
    pub fn reload(&self) -> Result<Vec<String>> {
        let (cfg, _) = config::load_or_init(&self.path).context("re-reading configuration")?;
        let old = self.current.load_full();
        let mut notes = Vec::new();

        if cfg.logging.level != old.logging.level {
            crate::logging::set_level(&cfg.logging.level)?;
            notes.push(format!("log level -> {}", cfg.logging.level));
        }
        self.dns.reload(&cfg);
        notes.push(
            "forwarding, transfer, rate limit, cookies, nsid, auto_ptr, minimal_any applied".into(),
        );
        if self.dns.forwarding_override().is_some() {
            notes.push(
                "forwarding upstreams/allowed clients/timeout: the console settings still override [forwarding] in the file (reset them in Server settings to use the file)".into(),
            );
        }
        self.accounts.sync_root(
            &cfg.root.username,
            &cfg.root.password,
            cfg.root.mfa_required,
        )?;
        notes.push("root user synced".into());
        self.mutator.set_zone_defaults(
            &cfg.server.default_primary_ns,
            &cfg.server.default_hostmaster,
        );

        let fixed = [
            (
                cfg.server.bind != old.server.bind
                    || cfg.server.port != old.server.port
                    || cfg.server.udp != old.server.udp
                    || cfg.server.tcp != old.server.tcp,
                "[server] bind/port/udp/tcp",
            ),
            (
                cfg.web_console.bind != old.web_console.bind
                    || cfg.web_console.enabled != old.web_console.enabled,
                "[web_console] bind/enabled",
            ),
            (cfg.database.path != old.database.path, "[database].path"),
            (
                cfg.logging.file != old.logging.file
                    || cfg.logging.query_log_file != old.logging.query_log_file
                    || cfg.logging.format != old.logging.format,
                "[logging] file/format",
            ),
            (
                cfg.tcp_dns.proxy_on != old.tcp_dns.proxy_on
                    || cfg.tcp_dns.proxy_version != old.tcp_dns.proxy_version,
                "[tcp_dns] proxy settings",
            ),
            (
                cfg.web_console.proxy.proxy_on != old.web_console.proxy.proxy_on,
                "[web_console] proxy settings",
            ),
            (
                cfg.backup.dir != old.backup.dir
                    || cfg.backup.interval_hours != old.backup.interval_hours
                    || cfg.backup.keep != old.backup.keep,
                "[backup]",
            ),
        ];
        for (changed, what) in fixed {
            if changed {
                notes.push(format!("{what} changed: requires a restart"));
            }
        }
        self.current.store(Arc::new(cfg));
        tracing::info!(notes = ?notes, "configuration reloaded");
        Ok(notes)
    }
}
