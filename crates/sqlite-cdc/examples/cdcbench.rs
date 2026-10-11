//! Benchmark: write overhead of capture, replication throughput and bytes,
//! live latency (poll and stream), snapshot and verify. Run with --release.

#[path = "../tests/common/demo.rs"]
#[allow(dead_code)]
mod demo;

use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};
use serde_json::json;
use sqlite_cdc::client::PollOpts;
use sqlite_cdc::node::{FollowMode, Node, NodeConfig};
use sqlite_cdc::store::Store;

const T: &str = "t";

fn plain(path: &std::path::Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
    )
    .unwrap();
    demo::migrate(&c).unwrap();
    c.execute(
        "INSERT INTO zones(name, serial) VALUES ('bench.example', 1)",
        [],
    )
    .unwrap();
    c
}

fn store(path: &std::path::Path) -> Arc<Store> {
    let s = Arc::new(Store::open(path, demo::config(), demo::migrate).unwrap());
    s.init_leader().unwrap();
    s.write(json!({}), |tx| {
        Ok(tx.execute(
            "INSERT INTO zones(name, serial) VALUES ('bench.example', 1)",
            [],
        )?)
    })
    .unwrap();
    s
}

fn per(d: Duration, n: usize) -> String {
    format!("{:.1} µs", d.as_secs_f64() * 1e6 / n as f64)
}

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 - 1.0) * p) as usize]
}

async fn follower(dir: &std::path::Path, name: &str, mode: FollowMode, up: &str) -> Arc<Node> {
    let s = Arc::new(Store::open(&dir.join(name), demo::config(), demo::migrate).unwrap());
    let mut cfg = NodeConfig::new(T);
    cfg.mode = mode;
    cfg.verify_every = None;
    let n = Node::new(s, cfg);
    n.start_follow(up).await.unwrap();
    n
}

async fn wait_txn(n: &Node, id: u64) {
    let mut rx = n.store.subscribe();
    while *rx.borrow_and_update() < id {
        rx.changed().await.unwrap();
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let d = tempfile_dir();
    let dir = d.as_path();
    let n_small = 3000;
    let n_bulk = 50_000;

    println!("## 1. Leader write cost (WAL, synchronous=FULL)\n");
    println!("| workload | plain SQLite | with capture | overhead |");
    println!("|---|---|---|---|");
    let pc = plain(&dir.join("plain.db"));
    let s = store(&dir.join("leader.db"));
    // single-row inserts, one txn each
    let t0 = Instant::now();
    for i in 0..n_small {
        let tx = pc.unchecked_transaction().unwrap();
        tx.execute("INSERT INTO records(zone_id, name, rtype, value, ttl) VALUES (1, ?1, 'A', '10.0.0.1', 300)", [format!("h{i}")]).unwrap();
        tx.commit().unwrap();
    }
    let a = t0.elapsed();
    let t0 = Instant::now();
    for i in 0..n_small {
        s.write(json!({"actor": "bench"}), |tx| {
            Ok(tx.execute("INSERT INTO records(zone_id, name, rtype, value, ttl) VALUES (1, ?1, 'A', '10.0.0.1', 300)", [format!("h{i}")])?)
        })
        .unwrap();
    }
    let b = t0.elapsed();
    println!(
        "| {n_small} txns × 1 insert | {} /txn | {} /txn | {:.0}% |",
        per(a, n_small),
        per(b, n_small),
        (b.as_secs_f64() / a.as_secs_f64() - 1.0) * 100.0
    );
    // single-row updates
    let t0 = Instant::now();
    for i in 0..n_small {
        let tx = pc.unchecked_transaction().unwrap();
        tx.execute(
            "UPDATE records SET ttl = ttl + 1 WHERE id = ?1",
            [(i % 1000 + 1) as i64],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let a = t0.elapsed();
    let t0 = Instant::now();
    for i in 0..n_small {
        s.write(json!({"actor": "bench"}), |tx| {
            Ok(tx.execute(
                "UPDATE records SET ttl = ttl + 1 WHERE id = ?1",
                [(i % 1000 + 1) as i64],
            )?)
        })
        .unwrap();
    }
    let b = t0.elapsed();
    println!(
        "| {n_small} txns × 1 update | {} /txn | {} /txn | {:.0}% |",
        per(a, n_small),
        per(b, n_small),
        (b.as_secs_f64() / a.as_secs_f64() - 1.0) * 100.0
    );
    // one bulk transaction
    let t0 = Instant::now();
    {
        let tx = pc.unchecked_transaction().unwrap();
        for i in 0..n_bulk {
            tx.execute("INSERT INTO records(zone_id, name, rtype, value, ttl) VALUES (1, ?1, 'A', ?2, NULL)", params![format!("bulk{i}"), format!("10.1.{}.{}", i / 250, i % 250)]).unwrap();
        }
        tx.commit().unwrap();
    }
    let a = t0.elapsed();
    let t0 = Instant::now();
    s.write(json!({"actor": "bench"}), |tx| {
        for i in 0..n_bulk {
            tx.execute("INSERT INTO records(zone_id, name, rtype, value, ttl) VALUES (1, ?1, 'A', ?2, NULL)", params![format!("bulk{i}"), format!("10.1.{}.{}", i / 250, i % 250)])?;
        }
        Ok(())
    })
    .unwrap();
    let b = t0.elapsed();
    println!(
        "| 1 txn × {n_bulk} inserts | {:.0} ms | {:.0} ms | {:.0}% |",
        a.as_secs_f64() * 1e3,
        b.as_secs_f64() * 1e3,
        (b.as_secs_f64() / a.as_secs_f64() - 1.0) * 100.0
    );
    // cascade: delete the zone with all its records
    let t0 = Instant::now();
    pc.execute("DELETE FROM zones WHERE id = 1", []).unwrap();
    let a = t0.elapsed();
    let backlog_before_delete = s.state().unwrap().last_txn;
    let t0 = Instant::now();
    s.write(json!({"actor": "bench"}), |tx| {
        Ok(tx.execute("DELETE FROM zones WHERE id = 1", [])?)
    })
    .unwrap();
    let b = t0.elapsed();
    println!(
        "| cascade delete of {} records | {:.0} ms | {:.0} ms | {:.0}% |",
        n_bulk + n_small,
        a.as_secs_f64() * 1e3,
        b.as_secs_f64() * 1e3,
        (b.as_secs_f64() / a.as_secs_f64() - 1.0) * 100.0
    );
    let last = s.state().unwrap().last_txn;
    let _ = backlog_before_delete;

    let node = Node::new(s.clone(), NodeConfig::new(T));
    let (addr, _srv) = node.serve("127.0.0.1:0").await.unwrap();
    let url = format!("http://{addr}");

    println!(
        "\n## 2. Catch-up: a fresh follower replays the whole log ({last} txns, incl. two of {n_bulk}+ rows)\n"
    );
    println!("| mode | time | txns/s | rows/s | raw bytes | on the wire (gzip) |");
    println!("|---|---|---|---|---|---|");
    let rows: u64 = s
        .reader()
        .unwrap()
        .query_row("SELECT count(*) FROM _cdc", [], |r| r.get(0))
        .unwrap();
    for (name, mode) in [
        (
            "poll",
            FollowMode::Poll(PollOpts {
                min_bytes: 1,
                max_wait_ms: 25_000,
                max_bytes: 4 << 20,
            }),
        ),
        ("stream", FollowMode::Stream),
    ] {
        // Follow from the genesis: snapshot an empty copy is not possible
        // once data exists, so replay through a rewind of a copy instead:
        // a fresh node snapshots (state at `last`), which we measure in §4.
        // Here: a follower started before the history, i.e. from txn 0.
        let fs = Arc::new(
            Store::open(
                &dir.join(format!("replay-{name}.db")),
                demo::config(),
                demo::migrate,
            )
            .unwrap(),
        );
        bootstrap_empty(&s, &fs);
        let before = node.metrics.json();
        let mut cfg = NodeConfig::new(T);
        cfg.mode = mode;
        cfg.verify_every = None;
        let f = Node::new(fs, cfg);
        let t0 = Instant::now();
        f.start_follow(&url).await.unwrap();
        wait_txn(&f, last).await;
        let el = t0.elapsed();
        f.stop_follow().await;
        let after = node.metrics.json();
        let raw = after["changes_raw"].as_u64().unwrap() - before["changes_raw"].as_u64().unwrap();
        let wire =
            after["changes_wire"].as_u64().unwrap() - before["changes_wire"].as_u64().unwrap();
        println!(
            "| {name} | {:.2} s | {:.0} | {:.0} | {:.1} MB | {:.1} MB ({:.1}×) |",
            el.as_secs_f64(),
            last as f64 / el.as_secs_f64(),
            rows as f64 / el.as_secs_f64(),
            raw as f64 / 1e6,
            wire as f64 / 1e6,
            raw as f64 / wire as f64
        );
    }

    println!(
        "\n## 3. Live latency: commit on the leader → applied on the follower (500 single-row txns)\n"
    );
    println!("| mode | p50 | p99 | max |");
    println!("|---|---|---|---|");
    for (name, mode) in [
        (
            "poll (long poll, min_bytes=1)",
            FollowMode::Poll(PollOpts {
                min_bytes: 1,
                max_wait_ms: 25_000,
                max_bytes: 1 << 20,
            }),
        ),
        ("stream", FollowMode::Stream),
    ] {
        let f = follower(dir, &format!("live-{}.db", name.len()), mode, &url).await;
        wait_txn(&f, s.state().unwrap().last_txn).await;
        let mut lat = Vec::new();
        for i in 0..500 {
            let s2 = s.clone();
            let t0 = Instant::now();
            let id = tokio::task::spawn_blocking(move || {
                s2.write(json!({}), |tx| Ok(tx.execute("INSERT INTO settings VALUES (?1, 'v') ON CONFLICT(key) DO UPDATE SET value = excluded.value || 'v'", [format!("k{}", i % 20)])?))
                    .unwrap()
                    .1
                    .unwrap()
            })
            .await
            .unwrap();
            wait_txn(&f, id).await;
            lat.push(t0.elapsed());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        f.stop_follow().await;
        println!(
            "| {name} | {:.2} ms | {:.2} ms | {:.2} ms |",
            pct(&mut lat, 0.5).as_secs_f64() * 1e3,
            pct(&mut lat, 0.99).as_secs_f64() * 1e3,
            pct(&mut lat, 1.0).as_secs_f64() * 1e3
        );
    }

    println!("\n## 4. Snapshot and verify (100k records)\n");
    s.write(json!({}), |tx| {
        tx.execute("INSERT INTO zones(name, serial) VALUES ('big.example', 1)", [])?;
        let z = tx.last_insert_rowid();
        for i in 0..100_000 {
            tx.execute("INSERT INTO records(zone_id, name, rtype, value, ttl) VALUES (?1, ?2, 'A', ?3, 3600)", params![z, format!("host{i}"), format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)])?;
        }
        Ok(())
    })
    .unwrap();
    let before = node.metrics.json();
    let t0 = Instant::now();
    let f = follower(dir, "snap.db", FollowMode::Stream, &url).await;
    wait_txn(&f, s.state().unwrap().last_txn).await;
    let el = t0.elapsed();
    let after = node.metrics.json();
    let raw = after["snapshot_raw"].as_u64().unwrap() - before["snapshot_raw"].as_u64().unwrap();
    let wire = after["snapshot_wire"].as_u64().unwrap() - before["snapshot_wire"].as_u64().unwrap();
    while f.follow_status().snapshots == 0 || f.follow_status().last_verify.is_none() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let el = t0.elapsed().max(el);
    let fs = f.follow_status();
    println!(
        "- snapshot + load + verify-after-load: {:.2} s; {:.1} MB raw, {:.1} MB gzip ({:.1}×); snapshots taken: {}",
        el.as_secs_f64(),
        raw as f64 / 1e6,
        wire as f64 / 1e6,
        raw as f64 / wire as f64,
        fs.snapshots
    );
    let t0 = Instant::now();
    let r = f.verify(256).await.unwrap();
    println!(
        "- client verify of all tables vs leader (256 buckets): {:.0} ms, ok = {}",
        t0.elapsed().as_secs_f64() * 1e3,
        r["ok"]
    );
    // verify as of an older txn: the leader undoes 500 later txns in memory
    f.stop_follow().await;
    for i in 0..500 {
        s.write(json!({}), |tx| {
            Ok(tx.execute("UPDATE records SET ttl = ttl + 1 WHERE id = ?1", [i + 1])?)
        })
        .unwrap();
    }
    let t0 = Instant::now();
    let r = f.verify(256).await.unwrap();
    println!(
        "- the same, with the leader 500 txns ahead (undone in memory): {:.0} ms, ok = {}",
        t0.elapsed().as_secs_f64() * 1e3,
        r["ok"]
    );
    let size = |p: &str| std::fs::metadata(dir.join(p)).map(|m| m.len()).unwrap_or(0);
    let cdc_rows: u64 = s
        .reader()
        .unwrap()
        .query_row("SELECT count(*) FROM _cdc", [], |r| r.get(0))
        .unwrap();
    println!(
        "- leader file {:.1} MB (+ WAL {:.1} MB), change log rows {cdc_rows}; plain SQLite file {:.1} MB",
        size("leader.db") as f64 / 1e6,
        size("leader.db-wal") as f64 / 1e6,
        size("plain.db") as f64 / 1e6
    );
}

/// A follower at txn 0 of the leader's history (as if it had joined at the
/// start), so the whole log is replayed through the protocol.
fn bootstrap_empty(leader: &Store, f: &Store) {
    let mut lines = Vec::new();
    leader
        .snapshot(|mut b| {
            b.pop();
            lines.push(b);
            Ok(())
        })
        .unwrap();
    // Rewrite the snapshot to "empty at txn 0".
    let mut out = Vec::new();
    for l in lines {
        let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
        if let Some(h) = v.get_mut("header") {
            h["txn_id"] = json!(0);
            h["end_seq"] = json!(0);
            h["hash"] = json!(sqlite_cdc::hash::genesis(h["history"].as_str().unwrap()));
            h["row_counts"] = json!(
                h["row_counts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|_| 0)
                    .collect::<Vec<_>>()
            );
            h["chain_entries"] = json!(0);
            out.push(serde_json::to_vec(&v).unwrap());
        }
    }
    let mut digest = blake3::Hasher::new();
    for l in &out {
        digest.update(l);
        digest.update(b"\n");
    }
    out.push(
        serde_json::to_vec(
            &json!({"footer": {"digest": digest.finalize().to_hex().to_string(), "lines": 1}}),
        )
        .unwrap(),
    );
    f.load_snapshot(out.into_iter().map(Ok), None, &Default::default())
        .unwrap();
}

fn tempfile_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("cdcbench-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}
