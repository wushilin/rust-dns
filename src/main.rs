mod api;
mod auth;
mod backup;
mod cache;
mod config;
mod dns;
mod events;
mod logging;
mod model;
mod mutation;
mod ratelimit;
mod reload;
mod storage;
mod ui;
mod zones;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "rust-dns",
    version,
    about = "SQLite-backed authoritative DNS server with a realtime web UI"
)]
struct Cli {
    /// Path to the TOML configuration (created with defaults if missing).
    #[arg(short, long, env = "RUST_DNS_CONFIG", default_value = "rust-dns.toml")]
    config: PathBuf,
    /// Print a sample configuration and exit. Its root password is the
    /// placeholder "change-me", which must be changed before starting.
    #[arg(long)]
    print_sample_config: bool,
    /// Write a new configuration file (mode 0600) with a random root
    /// password, print the credentials once to stdout, and exit. Refuses to
    /// overwrite an existing file.
    #[arg(long, value_name = "PATH")]
    init_config: Option<PathBuf>,
    /// Validate the selected configuration and exit without starting listeners.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Everything this process creates (database, WAL, backups, logs, config)
    // is private to the service user.
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    if cli.print_sample_config {
        print!("{}", config::sample_with_placeholder());
        return Ok(());
    }
    if let Some(path) = &cli.init_config {
        let (user, pw) = match config::init_config(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("rust-dns: {e:#}");
                std::process::exit(1);
            }
        };
        // stdout only, never the log: the plaintext exists nowhere else.
        println!("wrote {} (mode 0600)", path.display());
        println!("root username: {user}");
        println!("root password: {pw}");
        println!("(shown once; the file stores only an Argon2 hash)");
        return Ok(());
    }
    if cli.check {
        config::check(&cli.config)?;
        println!("configuration {} is valid", cli.config.display());
        return Ok(());
    }
    // Logging is needed before config load (it logs), so bootstrap with defaults
    // and re-read the level from the file afterwards via RUST_LOG if set.
    let (cfg, generated) = match config::load_or_init(&cli.config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rust-dns: configuration error: {e:#}");
            return Err(e);
        }
    };
    logging::init(&cfg.logging)?;
    for (section, p) in [
        ("[web_console]", &cfg.web_console.proxy),
        ("[tcp_dns]", &cfg.tcp_dns),
    ] {
        for e in p.broad_trust_entries() {
            tracing::warn!(entry = %e, "{section}.proxy_trust trusts a whole network: any host on it (e.g. every container on a Docker bridge) can claim to be any client; list only the proxy's own address");
        }
    }
    let cfg = Arc::new(cfg);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), config = %cli.config.display(), "starting rust-dns");

    // Storage, root user, catalog.
    let storage = Arc::new(storage::Storage::open(&cfg.database.path)?);
    backup::spawn(storage.clone(), cfg.backup.clone());
    let accounts = Arc::new(mutation::accounts::Accounts::new(storage.clone()));
    let root = accounts.sync_root(
        &cfg.root.username,
        &cfg.root.password,
        cfg.root.mfa_required,
    )?;
    if let Some(pw) = generated {
        // stderr only: the plaintext must never reach the log files.
        tracing::warn!(username = %root.username, config = %cli.config.display(), "generated a new configuration with a random root password (printed once on stderr, not logged)");
        eprintln!("\n  Root login: {}  /  {}\n  (the plaintext is only shown once; the config now holds a hash)\n", root.username, pw);
    }
    let cache = Arc::new(cache::Cache::new(cache::Catalog::empty()));
    let bus = Arc::new(events::Bus::new(1024, 4096));
    let mutator = Arc::new(mutation::Mutator::new(
        storage.clone(),
        cache.clone(),
        bus.clone(),
        &cfg.server.default_primary_ns,
        &cfg.server.default_hostmaster,
    ));
    mutator.rebuild()?;
    let (zc, rc) = storage.counts()?;
    tracing::info!(zones = zc, records = rc, "catalog loaded");

    // DNS.
    let limiter = Arc::new(ratelimit::RateLimiter::new(
        cfg.rate_limit.max_resolutions_per_second_per_address,
        Duration::from_secs(1),
        cfg.rate_limit.max_tracked_addresses,
    ));
    limiter.set_slip(cfg.rate_limit.slip);
    let dns = Arc::new(dns::DnsServer::new(
        cache.clone(),
        bus.clone(),
        limiter.clone(),
        &cfg,
    ));
    // Forwarding settings saved from the console/API override the config file.
    match mutation::settings::load_forwarding(&storage) {
        Ok(Some((f, by, at))) => {
            tracing::info!(upstreams = ?f.upstreams, set_by = %by, set_at = %at, "forwarding settings from the console override the config file");
            dns.set_forwarding_override(Some(f), &cfg);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "stored forwarding settings are unreadable; using the config file")
        }
    }
    // TSIG keys for zone transfers and NOTIFY.
    dns.reload_tsig_keys(&storage)?;
    for w in dns.transfer_warnings() {
        tracing::warn!("{w}");
    }
    let dns_task = tokio::spawn(dns::serve(dns.clone()));
    tokio::spawn(dns::notify::run(dns.clone()));

    let reloader = Arc::new(reload::Reloader {
        path: cli.config.clone(),
        current: arc_swap::ArcSwap::from(cfg.clone()),
        dns: dns.clone(),
        mutator: mutator.clone(),
        accounts: accounts.clone(),
    });
    // Record expiry: stop serving at expires_at, delete after [expiry].retention_days.
    {
        let r = reloader.clone();
        mutator.spawn_expiry_sweeper(move || r.current.load().expiry.clone());
    }
    #[cfg(unix)]
    {
        let r = reloader.clone();
        tokio::spawn(async move {
            let Ok(mut hup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while hup.recv().await.is_some() {
                match r.reload() {
                    Ok(notes) => tracing::info!(?notes, "SIGHUP: configuration reloaded"),
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP: reload failed; keeping the running configuration")
                    }
                }
            }
        });
    }

    // Web.
    let state = Arc::new(api::AppState {
        cfg: cfg.clone(),
        storage: storage.clone(),
        cache: cache.clone(),
        mutator: mutator.clone(),
        accounts: accounts.clone(),
        bus: bus.clone(),
        dns: dns.clone(),
        reloader: reloader.clone(),
        limiter: limiter.clone(),
        login_limiter: ratelimit::RateLimiter::new(
            cfg.web_console.login_attempts_per_minute,
            Duration::from_secs(60),
            10_000,
        ),
        guard: api::guard::AttemptGuard::new(cfg.web_console.login_backoff_after),
        clock: auth::system_clock(),
        trusted: cfg.web_console.proxy.trusted_cidrs(),
        started: std::time::Instant::now(),
    });
    let web_task = tokio::spawn(api::serve(state.clone()));

    // Query logging subscriber.
    if cfg.logging.log_queries {
        if let Some(rx) = bus.subscribe_queries() {
            tokio::spawn(async move {
                while let Ok(q) = rx.recv_async().await {
                    tracing::info!(target: logging::QUERY_TARGET, client = %q.client, proto = q.proto, name = %q.name, qtype = %q.qtype, rcode = %q.rcode, answers = q.answers, result = %q.result.join(" | "), source = q.source, us = q.duration_us, "query");
                }
            });
        }
    }

    // Retention: prune changelog and expired sessions.
    {
        let storage = storage.clone();
        let days = cfg.changelog.retention_days;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                let cutoff = chrono::Utc::now() - chrono::Duration::days(days.max(1) as i64);
                match storage.prune_changelog(cutoff) {
                    Ok(n) if n > 0 => tracing::info!(pruned = n, "changelog retention applied"),
                    Err(e) => tracing::warn!(error = %e, "changelog prune failed"),
                    _ => {}
                }
                match storage.prune_audit(cutoff) {
                    Ok(n) if n > 0 => tracing::info!(pruned = n, "audit log retention applied"),
                    Err(e) => tracing::warn!(error = %e, "audit log prune failed"),
                    _ => {}
                }
                let _ = storage.prune_sessions();
            }
        });
    }

    tokio::select! {
        r = dns_task => { r??; }
        r = web_task => { r??; }
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); bus.shutdown(); }
    }
    Ok(())
}
