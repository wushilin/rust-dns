//! kill -9 of real processes: a follower killed repeatedly while applying,
//! and a leader killed under concurrent writes.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::*;
use rand::Rng;
use serde_json::json;
use sqlite_cdc::client::Client;
use sqlite_cdc::node::{Node, NodeConfig};

const TOKEN: &str = "t";

fn spawn(args: &[&str]) -> (Child, String) {
    let mut child = Command::new(cdcnode_bin())
        .args(args)
        .args(["--token", TOKEN])
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn cdcnode");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let url = line
        .trim()
        .strip_prefix("listening ")
        .expect("listening line")
        .to_string();
    (child, url)
}

/// The `cdcnode` example: `cargo test` builds examples before running tests.
fn cdcnode_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // the test binary's name
    p.pop(); // deps/
    p.push("examples/cdcnode");
    assert!(
        p.exists(),
        "{} missing: run the tests with `cargo test` (it builds examples)",
        p.display()
    );
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn follower_killed_repeatedly_while_applying_converges() {
    let d = tempfile::tempdir().unwrap();
    let leader = leader(d.path(), "l.db");
    workload(&leader, 1, 200, 5);
    let node = Node::new(leader.clone(), NodeConfig::new(TOKEN));
    let (addr, _s) = node.serve("127.0.0.1:0").await.unwrap();
    let lurl = format!("http://{addr}");

    // A writer that never stops while the follower dies and restarts.
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, l2) = (stop.clone(), leader.clone());
    let writer = std::thread::spawn(move || {
        let mut seed = 100;
        while !s2.load(Ordering::Relaxed) {
            workload(&l2, seed, 5, 8);
            seed += 1;
        }
    });

    let fdb = d.path().join("f.db");
    let fdb = fdb.to_str().unwrap();
    let mut rng = rand::rng();
    for i in 0..15 {
        let mode = if i % 2 == 0 { "stream" } else { "poll" };
        let (mut child, _url) = spawn(&[
            "--db",
            fdb,
            "--follow",
            &lurl,
            "--mode",
            mode,
            "--max-wait-ms",
            "200",
        ]);
        std::thread::sleep(Duration::from_millis(rng.random_range(100..700)));
        child.kill().unwrap(); // SIGKILL
        child.wait().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();

    let (mut child, furl) = spawn(&["--db", fdb, "--follow", &lurl, "--mode", "stream"]);
    let want = leader.state().unwrap().last_txn;
    let c = Client::new(&furl, TOKEN);
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        let s = c.status().await.unwrap();
        assert!(s.halted.is_none(), "halted: {:?}", s.halted);
        if s.last_txn == want {
            break;
        }
        assert!(
            Instant::now() < end,
            "follower stuck at {} of {want}",
            s.last_txn
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let r = c.verify(256).await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
    child.kill().unwrap();
    child.wait().unwrap();
    let f = open(std::path::Path::new(fdb));
    assert_eq!(dump(&leader), dump(&f));
    assert!(f.health().unwrap().is_empty());
    println!("leader at txn {want}");
}

#[tokio::test(flavor = "multi_thread")]
async fn leader_killed_under_concurrent_writes_keeps_every_acknowledged_txn() {
    let d = tempfile::tempdir().unwrap();
    let ldb = d.path().join("l.db");
    let ldb = ldb.to_str().unwrap().to_string();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let (mut child, lurl) = spawn(&["--db", &ldb, "--listen", &listen, "--leader"]);

    // A follower in this process, following the leader across its restarts.
    let fstore = open(&d.path().join("f.db"));
    let mut cfg = NodeConfig::new(TOKEN);
    cfg.mode = sqlite_cdc::node::FollowMode::Stream;
    let f = Node::new(fstore.clone(), cfg);
    f.start_follow(&lurl).await.unwrap();

    let acked = Arc::new(std::sync::Mutex::new(Vec::<(String, u64)>::new()));
    for round in 0..4 {
        let stop = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        for w in 0..8 {
            let (c, stop, acked) = (Client::new(&lurl, TOKEN), stop.clone(), acked.clone());
            tasks.push(tokio::spawn(async move {
                let mut i = 0;
                while !stop.load(Ordering::Relaxed) {
                    let key = format!("r{round}w{w}i{i}");
                    i += 1;
                    let sql = format!("INSERT INTO settings(key, value) VALUES ('{key}', 'v')");
                    if let Ok(r) = c.exec(&[&sql]).await
                        && let Some(id) = r["txn_id"].as_u64()
                    {
                        acked.lock().unwrap().push((key, id));
                    }
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        child.kill().unwrap(); // SIGKILL mid-load
        child.wait().unwrap();
        stop.store(true, Ordering::Relaxed);
        for t in tasks {
            t.await.unwrap();
        }
        (child, _) = spawn(&["--db", &ldb, "--listen", &listen, "--leader"]);
    }

    // Every acknowledged write survived, under the txn id it was acknowledged with.
    let leader = open(std::path::Path::new(&ldb));
    let c = leader.reader().unwrap();
    let acked = acked.lock().unwrap().clone();
    assert!(
        acked.len() > 100,
        "only {} writes acknowledged",
        acked.len()
    );
    for (key, id) in &acked {
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM _cdc WHERE txn_id = ?1 AND tbl = 'settings' AND pk = json_object('key', ?2)",
                rusqlite::params![id, key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "acknowledged {key} at txn {id} is missing");
    }
    // The follower followed across the leader's crashes without halting.
    let want = leader.state().unwrap().last_txn;
    let end = Instant::now() + Duration::from_secs(30);
    while fstore.state().unwrap().last_txn < want {
        assert!(
            fstore.state().unwrap().halted.is_none(),
            "{:?}",
            fstore.state().unwrap().halted
        );
        assert!(Instant::now() < end, "follower stuck");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(dump(&leader), dump(&fstore));
    child.kill().unwrap();
    child.wait().unwrap();
    let _ = json!({});
    println!("{} acknowledged writes over 4 leader crashes", acked.len());
}
