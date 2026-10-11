//! A node process over the demo schema.
//!
//!   cdcnode --db l.db --listen 127.0.0.1:7001 --token t --leader
//!   cdcnode --db f.db --listen 127.0.0.1:7002 --token t --follow http://127.0.0.1:7001 --mode stream

#[path = "../tests/common/demo.rs"]
#[allow(dead_code)]
mod demo;

use std::sync::Arc;
use std::time::Duration;

use axum::response::IntoResponse;
use clap::Parser;
use sqlite_cdc::client::PollOpts;
use sqlite_cdc::node::{FollowMode, Node, NodeConfig};
use sqlite_cdc::store::Store;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    db: std::path::PathBuf,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// Bearer token (for the API it serves and for its upstream).
    #[arg(long, default_value = "")]
    token: String,
    /// Read the token from this file instead (keeps it off the command line).
    #[arg(long)]
    token_file: Option<std::path::PathBuf>,
    /// Follow any leader: create the tables from the upstream's
    /// `GET <api>/schema` instead of the demo schema.
    #[arg(long)]
    schema_from_upstream: bool,
    /// The name this node reports to its upstream.
    #[arg(long)]
    name: Option<String>,
    /// Start a new history if the database is fresh.
    #[arg(long)]
    leader: bool,
    /// Upstream to follow.
    #[arg(long)]
    follow: Option<String>,
    /// poll or stream.
    #[arg(long, default_value = "poll")]
    mode: String,
    #[arg(long, default_value_t = 1)]
    min_bytes: usize,
    #[arg(long, default_value_t = 25_000)]
    max_wait_ms: u64,
    /// Other nodes, for the fence check at start.
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,
    #[arg(long)]
    verify_every_secs: Option<u64>,
    /// Keep row images of this many transactions (prune every 10 s).
    #[arg(long)]
    keep_txns: Option<u64>,
    #[arg(long)]
    no_auto_snapshot: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut a = Args::parse();
    if let Some(f) = &a.token_file {
        a.token = std::fs::read_to_string(f)?.trim().to_string();
    }
    let store = if a.schema_from_upstream {
        let up = a
            .follow
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--schema-from-upstream needs --follow"))?;
        let specs = sqlite_cdc::client::Client::new(&up, &a.token)
            .schema()
            .await
            .map_err(|e| anyhow::anyhow!("reading the upstream schema: {e}"))?;
        eprintln!("upstream schema: {} tables", specs.len());
        let cfg = sqlite_cdc::store::Config::new(
            specs
                .iter()
                .map(|t| sqlite_cdc::schema::TableConfig::new(&t.name))
                .collect(),
        );
        Arc::new(Store::open(&a.db, cfg, |c| {
            sqlite_cdc::schema::create_tables(c, &specs)
        })?)
    } else {
        Arc::new(Store::open(&a.db, demo::config(), demo::migrate)?)
    };
    if a.leader {
        store.init_leader()?;
    }
    let mut cfg = NodeConfig::new(&a.token);
    cfg.name = a.name.clone();
    cfg.mode = match a.mode.as_str() {
        "stream" => FollowMode::Stream,
        _ => FollowMode::Poll(PollOpts {
            min_bytes: a.min_bytes,
            max_wait_ms: a.max_wait_ms,
            max_bytes: 1 << 20,
        }),
    };
    cfg.auto_snapshot_on_gap = !a.no_auto_snapshot;
    cfg.verify_every = a.verify_every_secs.map(Duration::from_secs);
    let node = Node::new(store.clone(), cfg);
    node.fence_check(&a.peers).await?;
    let n2 = node.clone();
    let exec = axum::Router::new().route(
        "/admin/exec",
        axum::routing::post(move |axum::Json(b): axum::Json<serde_json::Value>| {
            let store = n2.store.clone();
            async move {
                let sql: Vec<String> = serde_json::from_value(b["sql"].clone()).unwrap_or_default();
                let r = tokio::task::spawn_blocking(move || {
                    store.write(b["meta"].clone(), |tx| {
                        for s in &sql {
                            tx.execute_batch(s)?;
                        }
                        Ok(())
                    })
                })
                .await
                .expect("join");
                match r {
                    Ok((_, id)) => axum::Json(serde_json::json!({"txn_id": id})).into_response(),
                    Err(e) => (
                        axum::http::StatusCode::CONFLICT,
                        axum::Json(
                            serde_json::json!({"error": e.kind.as_str(), "detail": e.detail}),
                        ),
                    )
                        .into_response(),
                }
            }
        }),
    );
    let (addr, server) = node.serve_with(&a.listen, exec).await?;
    println!("listening http://{addr}");
    if let Some(up) = &a.follow {
        node.start_follow(up).await?;
    } else if let Some(up) = store.state()?.upstream {
        node.start_follow(&up).await?;
    }
    if let Some(keep) = a.keep_txns {
        let s = store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let s = s.clone();
                let _ = tokio::task::spawn_blocking(move || s.prune(keep)).await;
            }
        });
    }
    server.await?;
    Ok(())
}
