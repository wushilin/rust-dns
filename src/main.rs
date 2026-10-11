mod api;
mod auth;
mod backup;
mod blocklist;
mod cache;
mod config;
mod dns;
mod dnssec;
mod events;
mod logging;
mod model;
mod mutation;
mod ratelimit;
mod reload;
mod replication;
mod rrtext;
mod secondary;
mod storage;
mod ui;
#[cfg(windows)]
mod winsvc;
mod zones;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// O13a: the static musl builds (the Linux release binaries) allocate with
/// mimalloc. With musl's own allocator (mallocng) the resident memory grew
/// steadily under sustained queries plus record changes while the live heap
/// stayed flat (fragmentation, not a leak; plan.md O13a has the numbers).
/// Every other target keeps the system allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The allocator this build uses (`rustdns_build_info` in `/rust-dns/metrics`).
pub const ALLOCATOR: &str = if cfg!(target_env = "musl") {
    "mimalloc"
} else {
    "system"
};

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
    /// Promote this standby to primary while the server is stopped: removes
    /// [follow] from the config file and records a new history in the
    /// database. (A running standby: the console or POST /rust-dns/api/replication/promote.)
    #[arg(long)]
    promote: bool,
    /// Make this server fresh so it can follow its [follow] primary (server
    /// stopped): backs the database up next to it, writes a report of the
    /// changes the primary does not have, then deletes zones, records,
    /// users (except the config root), tokens, settings, TSIG keys and the
    /// changelog. Without --yes it only prints what would be deleted.
    #[arg(long)]
    prepare_standby: bool,
    /// Confirm --prepare-standby.
    #[arg(long)]
    yes: bool,
    /// Windows: register rust-dns as a service (name `rust-dns`, started
    /// automatically, LocalSystem) that runs with this --config, then exit.
    /// Needs an elevated prompt.
    #[cfg(windows)]
    #[arg(long)]
    install_service: bool,
    /// Windows: stop and remove the `rust-dns` service, then exit.
    #[cfg(windows)]
    #[arg(long)]
    uninstall_service: bool,
    /// Windows: run under the service control manager (set by
    /// --install-service; not for interactive use).
    #[cfg(windows)]
    #[arg(long, hide = true)]
    windows_service: bool,
}

/// O20: a request to stop from outside the console (the Windows service
/// control manager); the server shuts down as on Ctrl-C.
static SHUTDOWN: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn main() -> anyhow::Result<()> {
    exit_with_stdin();
    let cli = Cli::parse();
    #[cfg(windows)]
    {
        if cli.install_service {
            return winsvc::install(&cli.config);
        }
        if cli.uninstall_service {
            return winsvc::uninstall();
        }
        if cli.windows_service {
            return winsvc::run_dispatcher();
        }
    }
    run(cli)
}

/// Supervisor hook (used by the test suites, O0c): with
/// `RUST_DNS_EXIT_WITH_STDIN=1` the process exits as soon as its standard
/// input reaches end of file, i.e. when the process holding the other end
/// of that pipe is gone, however it ended (a panic, SIGKILL). Off unless
/// the variable is set; nothing reads stdin otherwise.
fn exit_with_stdin() {
    if std::env::var_os("RUST_DNS_EXIT_WITH_STDIN").is_some_and(|v| v == "1") {
        std::thread::spawn(|| {
            use std::io::Read;
            let mut buf = [0u8; 256];
            let mut stdin = std::io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => std::process::exit(0),
                    Ok(_) => {}
                }
            }
        });
    }
}

/// Build the runtime and run the server (or the one-shot command) to the end.
fn run(cli: Cli) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
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
        let cfg = config::check(&cli.config)?;
        println!("configuration {} is valid", cli.config.display());
        for w in config::open_resolver_warnings(&cfg.forwarding) {
            println!("WARNING: {w}");
        }
        if let Some(f) = &cfg.follow {
            println!(
                "role: standby of {} (read-only; promote with --promote or from the console)",
                f.primary
            );
        } else if let Some(p) = &cfg.peer {
            println!("role: primary; [peer] {} is checked so this server stays read-only if it was promoted", p.url);
        }
        if let Some(note) = replication_note(&cfg) {
            println!("{note}");
        }
        return Ok(());
    }
    if cli.prepare_standby {
        match replication::prepare_standby_offline(&cli.config, cli.yes).await {
            Ok(true) => return Ok(()),
            Ok(false) => std::process::exit(2),
            Err(e) => {
                eprintln!("rust-dns: --prepare-standby failed: {e:#}");
                std::process::exit(1);
            }
        }
    }
    if cli.promote {
        match replication::promote_offline(&cli.config).await {
            Ok(h) => {
                println!("promoted: {} is now a primary", cli.config.display());
                println!(
                    "new history id {} (parent {}, forked at offset {})",
                    h.history_id,
                    h.parent_history_id.unwrap_or_default(),
                    h.fork_offset.unwrap_or(0)
                );
                println!("[follow] was removed from the config file; start the server normally.");
                println!("Keep the old primary from accepting writes (stop it, or give it [peer] url = <this server>), then make it a standby of this server.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("rust-dns: promotion failed: {e:#}");
                std::process::exit(1);
            }
        }
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
    // TLS for the standby's client: rustls with the ring provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = Arc::new(cfg);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), config = %cli.config.display(), "starting rust-dns");

    // Storage, root user, catalog.
    let storage = Arc::new(storage::Storage::open(&cfg.database.path)?);
    backup::spawn(storage.clone(), cfg.backup.clone());
    let accounts = Arc::new(mutation::accounts::Accounts::new(storage.clone()));
    let cache = Arc::new(cache::Cache::new(cache::Catalog::empty()));
    let bus = Arc::new(events::Bus::new(1024, 4096));
    let mutator = Arc::new(mutation::Mutator::new(
        storage.clone(),
        cache.clone(),
        bus.clone(),
        &cfg.server.default_primary_ns,
        &cfg.server.default_hostmaster,
    ));
    // Account changes on a standby stay local (its changelog mirrors the
    // primary's offsets): close the write gate before the root sync.
    accounts.set_gate(mutator.gate());
    accounts.set_bus(bus.clone());
    if let Some(f) = &cfg.follow {
        mutator.gate().close(format!(
            "this server is a read-only standby of {}; make changes on the primary",
            f.primary.trim().trim_end_matches('/')
        ));
    }
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
    mutator.set_dnssec_config(cfg.dnssec.clone());
    // O27: secondary zones serve their last transfer until it expires.
    match mutator.signer().secondaries.load(&storage) {
        Ok(0) => {}
        Ok(n) => tracing::info!(zones = n, "secondary zone data loaded"),
        Err(e) => {
            tracing::warn!(error = %e, "secondary zone data could not be loaded; transferring again")
        }
    }
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
    if let Ok(Some((f, by, at))) = mutation::settings::load_forwarding(&storage) {
        tracing::info!(upstreams = ?f.upstreams, set_by = %by, set_at = %at, "forwarding settings from the console override the config file");
    }
    // Forwarding override, resolver settings and blocklists (an unreadable
    // one is logged; the config file / defaults apply).
    dns.load_console_settings(&storage, &cfg);
    tokio::spawn(dns.blocklists.clone().run(blocklist::http_client()));
    for w in dns.open_resolver_warnings() {
        tracing::warn!("{w}");
    }
    // TSIG keys for zone transfers and NOTIFY.
    dns.reload_tsig_keys(&storage)?;
    for w in dns.transfer_warnings() {
        tracing::warn!("{w}");
    }
    let dns_task = tokio::spawn(dns::serve(dns.clone()));
    tokio::spawn(dns::notify::run(dns.clone()));
    // O27: secondary zones (every server transfers them itself).
    let _ = dns.secondaries.set(mutator.signer().secondaries.clone());
    tokio::spawn(secondary::run(Arc::new(secondary::Ctx {
        storage: storage.clone(),
        mutator: mutator.clone(),
        cache: cache.clone(),
        dns: dns.clone(),
        store: mutator.signer().secondaries.clone(),
    })));

    let reloader = Arc::new(reload::Reloader {
        path: cli.config.clone(),
        current: arc_swap::ArcSwap::from(cfg.clone()),
        dns: dns.clone(),
        mutator: mutator.clone(),
        accounts: accounts.clone(),
    });
    // Replication role (standby / primary / fenced) before anything can write.
    let repl = replication::Replication::new(
        storage.clone(),
        mutator.clone(),
        dns.clone(),
        reloader.clone(),
        cli.config.clone(),
    );
    {
        let r = repl.clone();
        accounts.set_commit_hook(Box::new(move |_records, logged| {
            if logged > 0 {
                r.changelog_appended();
            }
        }));
    }
    repl.start().await?;
    // Record expiry: stop serving at expires_at, delete after [expiry].retention_days.
    {
        let r = reloader.clone();
        mutator.spawn_expiry_sweeper(move || r.current.load().expiry.clone());
    }
    // DNSSEC: re-sign due zones (primary), refresh signature windows (all).
    mutator.spawn_resigner();
    mutator.spawn_expiry_watch();
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
        repl: repl.clone(),
    });
    // O3: failed sign-in counters survive restarts.
    match state.guard.persist_to(storage.clone()) {
        Ok(n) if n > 0 => {
            tracing::info!(counters = n, "failed sign-in counters restored")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "could not load failed sign-in counters"),
    }
    let web_task = tokio::spawn(api::serve(state.clone()));
    // N1: the key rollover driver (acts only while this server is writable).
    api::rollover::spawn_driver(state.clone());

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
        let account_days = cfg.changelog.account_retention_days;
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
                let acutoff =
                    chrono::Utc::now() - chrono::Duration::days(account_days.max(1) as i64);
                match storage.scrub_account_changes(acutoff) {
                    Ok(n) if n > 0 => tracing::info!(
                        scrubbed = n,
                        "account change payloads scrubbed after [changelog].account_retention_days"
                    ),
                    Err(e) => tracing::warn!(error = %e, "scrubbing account changes failed"),
                    _ => {}
                }
                match storage.prune_audit(cutoff) {
                    Ok(n) if n > 0 => tracing::info!(pruned = n, "audit log retention applied"),
                    Err(e) => tracing::warn!(error = %e, "audit log prune failed"),
                    _ => {}
                }
                let _ = storage.prune_sessions();
                let now_ms = api::guard::unix_ms_now();
                let _ = storage.prune_login_failures(
                    now_ms - api::guard::FORGET_AFTER.as_millis() as i64,
                    now_ms,
                );
            }
        });
    }

    tokio::select! {
        r = dns_task => { r??; }
        r = web_task => { r??; }
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); bus.shutdown(); }
        _ = SHUTDOWN.notified() => { tracing::info!("stop requested; shutting down"); bus.shutdown(); }
    }
    Ok(())
}

/// A connection for `--check`: reads everything committed (also what is
/// still in the WAL of a running server) and cannot change anything.
fn open_for_check(path: &std::path::Path) -> anyhow::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    // No SQLITE_OPEN_CREATE: --check never creates a database.
    let conn = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn read_replication_state(
    conn: &rusqlite::Connection,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let has: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'replication_state')",
        [],
        |r| r.get(0),
    )?;
    if !has {
        return Ok(Default::default());
    }
    let mut stmt = conn.prepare("SELECT key, value FROM replication_state")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// `--check`: what the database says about replication, if it can be read
/// without changing it.
fn replication_note(cfg: &config::Config) -> Option<String> {
    let path = &cfg.database.path;
    if !path.exists() {
        return None;
    }
    // A normal (read-write capable) connection made read-only with
    // `query_only`: a `SQLITE_OPEN_READ_ONLY` handle cannot always read
    // what is still in the WAL (it may not be able to create or map the
    // -shm file), and then a database full of data looked "fresh".
    let conn = match open_for_check(path) {
        Ok(c) => c,
        Err(e) => {
            return Some(format!(
                "database {}: cannot be read ({e:#}); replication state unknown",
                path.display()
            ))
        }
    };
    let st: std::collections::HashMap<String, String> = match read_replication_state(&conn) {
        Ok(st) => st,
        Err(e) => {
            return Some(format!(
                "database {}: replication state cannot be read ({e:#})",
                path.display()
            ))
        }
    };
    let mut out = format!(
        "database history id {}",
        st.get("history_id")
            .map(String::as_str)
            .unwrap_or("(none yet)")
    );
    if let Some(at) = st.get("promoted_at") {
        out.push_str(&format!(
            "; promoted on {at} from {}",
            st.get("promoted_from").map(String::as_str).unwrap_or("?")
        ));
    }
    if let Some(f) = &cfg.follow {
        let url = f.primary.trim().trim_end_matches('/');
        let same = st.get("following").map(|s| s.trim_end_matches('/')) == Some(url);
        // An error is not "fresh": say so instead of guessing.
        let data = match replication::data::fresh_problems(&conn, &cfg.root.username) {
            Ok(d) => d,
            Err(e) => {
                out.push_str(&format!(
                    "\nwarning: could not tell whether the database has data ({e:#})"
                ));
                return Some(out);
            }
        };
        if !same && !data.is_empty() {
            out.push_str(&format!(
                "\nwarning: the database has data ({}) and is not a standby of {url}: following will be refused unless it is a copy of that primary's history. To discard the data on purpose (backed up first), run with the server stopped: rust-dns --prepare-standby --yes --config <this config>",
                data.join(", ")
            ));
        } else if data.is_empty() {
            out.push_str("\nthe database is fresh: the standby will copy the primary");
        }
    }
    if let Some(h) = st.get("halted") {
        let h: serde_json::Value = serde_json::from_str(h).unwrap_or_default();
        out.push_str(&format!(
            "\nREPLICATION HALTED since {}: {} ({}). The standby serves its last state and does not follow; see {}. Rebuild it: rust-dns --prepare-standby --yes --config <this config>",
            h["at"].as_str().unwrap_or("?"),
            h["reason"].as_str().unwrap_or("?"),
            h["detail"].as_str().unwrap_or(""),
            h["report_file"].as_str().unwrap_or("the divergence report next to the database"),
        ));
    }
    match (&cfg.follow, st.get("following")) {
        (None, Some(u)) => out.push_str(&format!(
            "\nnote: the database is a standby of {u} but the config has no [follow]: the next start records a promotion (new history id) and accepts writes"
        )),
        (Some(f), _) if st.get("promoted_from").map(|s| s.trim_end_matches('/')) == Some(f.primary.trim().trim_end_matches('/')) => out.push_str(
            "\nwarning: this server was promoted away from the primary that [follow] names; it will refuse to follow that old primary (remove [follow])",
        ),
        _ => {}
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_for(db: &std::path::Path) -> config::Config {
        toml::from_str(&format!(
            "[database]\npath = {:?}\n[root]\nusername = \"root\"\npassword = \"x\"\n[follow]\nprimary = \"https://primary.test\"\ninstance_id = \"s1\"\ntoken = \"rdns_x\"\n",
            db.to_str().unwrap()
        ))
        .unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rust-dns-check-{name}-{}-{}",
            std::process::id(),
            auth::random_token(4)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// F1: data that is committed but still only in the WAL (a running
    /// server holds the database open) must be seen by `--check`.
    #[test]
    fn check_sees_data_that_is_still_in_the_wal() {
        let d = tmp("wal");
        let db = d.join("rust-dns.db");
        let s = storage::Storage::open(&db).unwrap();
        s.exec_raw(
            "PRAGMA wal_autocheckpoint = 0;
             INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at) VALUES ('a.test','n.','h.','t','t');",
        )
        .unwrap();
        assert!(db.with_extension("db-wal").metadata().unwrap().len() > 0);
        // The server (`s`) is still running: nothing is checkpointed.
        let note = replication_note(&cfg_for(&db)).unwrap();
        assert!(note.contains("1 zone"), "{note}");
        assert!(!note.contains("is fresh"), "{note}");
        // `--check` changed nothing and a really fresh database says so.
        drop(s);
        let fresh = d.join("fresh.db");
        drop(storage::Storage::open(&fresh).unwrap());
        let note = replication_note(&cfg_for(&fresh)).unwrap();
        assert!(note.contains("is fresh"), "{note}");
        std::fs::remove_dir_all(d).unwrap();
    }

    /// F1: a database that cannot be read is never reported as fresh.
    #[test]
    fn check_does_not_call_an_unreadable_database_fresh() {
        let d = tmp("bad");
        let db = d.join("rust-dns.db");
        std::fs::write(&db, b"this is not a sqlite database, not at all........").unwrap();
        let note = replication_note(&cfg_for(&db)).unwrap();
        assert!(!note.contains("is fresh"), "{note}");
        assert!(note.contains("cannot be read"), "{note}");
        std::fs::remove_dir_all(d).unwrap();
    }
}
