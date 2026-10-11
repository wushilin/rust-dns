//! Nodes talking HTTP on loopback: snapshot and follow (poll and stream),
//! compression, gaps, divergence, verify, reset, repoint, failover.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::demo;
use common::*;
use serde_json::json;
use sqlite_cdc::client::{Client, PollOpts};
use sqlite_cdc::node::{FollowMode, Node, NodeConfig};
use sqlite_cdc::store::Kind;

const TOKEN: &str = "s3cret";

struct N {
    node: Arc<Node>,
    url: String,
    server: tokio::task::JoinHandle<()>,
}

impl N {
    fn client(&self) -> Client {
        Client::new(&self.url, TOKEN)
    }
    fn last(&self) -> u64 {
        self.node.store.state().unwrap().last_txn
    }
}

fn poll_cfg() -> NodeConfig {
    let mut c = NodeConfig::new(TOKEN);
    c.mode = FollowMode::Poll(PollOpts {
        min_bytes: 1,
        max_wait_ms: 2_000,
        max_bytes: 1 << 20,
    });
    c
}

fn stream_cfg() -> NodeConfig {
    let mut c = NodeConfig::new(TOKEN);
    c.mode = FollowMode::Stream;
    c
}

async fn start(dir: &std::path::Path, name: &str, leader: bool, cfg: NodeConfig) -> N {
    common::tls();
    let store = open(&dir.join(name));
    if leader {
        store.init_leader().unwrap();
    }
    let node = Node::new(store, cfg);
    let (addr, server) = node.serve("127.0.0.1:0").await.unwrap();
    N {
        node,
        url: format!("http://{addr}"),
        server,
    }
}

async fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn caught_up(a: &N, b: &N) {
    let want = a.last();
    let end = Instant::now() + Duration::from_secs(20);
    while b.last() < want {
        assert!(
            Instant::now() < end,
            "timed out waiting for catch up: {:?}",
            b.node.follow_status()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn work(n: &N, seed: u64, txns: usize) {
    let s = n.node.store.clone();
    tokio::task::spawn_blocking(move || workload(&s, seed, txns, 6))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn poll_follow_snapshot_then_tail_with_gzip() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 1, 300).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    assert_eq!(dump(&l.node.store), dump(&f.node.store));
    work(&l, 2, 500).await;
    caught_up(&l, &f).await;
    assert_eq!(dump(&l.node.store), dump(&f.node.store));
    let m = l.node.metrics.json();
    let (raw, wire) = (
        m["changes_raw"].as_u64().unwrap(),
        m["changes_wire"].as_u64().unwrap(),
    );
    assert!(
        wire * 3 < raw,
        "gzip should shrink changes: raw {raw}, wire {wire}"
    );
    let s = f.client().status().await.unwrap();
    let fs = s.follow.unwrap();
    assert_eq!(
        fs["snapshot_progress"]["loaded"],
        fs["snapshot_progress"]["total"]
    );
    assert_eq!(fs["lag_txns"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_follow_is_live_and_chains() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 3, 50).await;
    let f = start(d.path(), "f.db", false, stream_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    let g = start(d.path(), "g.db", false, stream_cfg()).await; // follows the follower
    g.node.start_follow(&f.url).await.unwrap();
    caught_up(&l, &g).await;
    // Live latency of single small commits through two hops.
    let mut worst = Duration::ZERO;
    for i in 0..50 {
        let t0 = Instant::now();
        let s = l.node.store.clone();
        let id = tokio::task::spawn_blocking(move || {
            s.write(json!({}), |tx| Ok(tx.execute("INSERT INTO settings VALUES (?1, 'v') ON CONFLICT(key) DO UPDATE SET value = value || 'v'", [format!("live{}", i % 5)])?))
                .unwrap()
                .1
                .unwrap()
        })
        .await
        .unwrap();
        wait_for("live txn", 5, || g.last() >= id).await;
        worst = worst.max(t0.elapsed());
    }
    assert!(
        worst < Duration::from_millis(500),
        "worst two-hop latency {worst:?}"
    );
    work(&l, 4, 400).await;
    caught_up(&l, &g).await;
    assert_eq!(dump(&l.node.store), dump(&g.node.store));
}

#[tokio::test(flavor = "multi_thread")]
async fn long_poll_waits_for_min_bytes_or_deadline() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 5, 5).await;
    let pos = l.node.store.state().unwrap().position().unwrap();
    let c = l.client();
    // Nothing new: returns empty at the deadline.
    let t0 = Instant::now();
    let r = c
        .changes(
            &pos,
            l.node.store.schema_fp(),
            &PollOpts {
                min_bytes: 1,
                max_wait_ms: 300,
                max_bytes: 1 << 20,
            },
        )
        .await
        .unwrap();
    assert!(r.txns.is_empty());
    assert!(
        t0.elapsed() >= Duration::from_millis(280),
        "{:?}",
        t0.elapsed()
    );
    // A commit arrives while waiting: returns early with it.
    let s = l.node.store.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::task::spawn_blocking(move || {
            s.write(json!({}), |tx| {
                Ok(tx.execute("INSERT INTO settings VALUES ('lp', 'x')", [])?)
            })
            .unwrap()
        })
        .await
        .unwrap();
    });
    let t0 = Instant::now();
    let r = c
        .changes(
            &pos,
            l.node.store.schema_fp(),
            &PollOpts {
                min_bytes: 1,
                max_wait_ms: 5_000,
                max_bytes: 1 << 20,
            },
        )
        .await
        .unwrap();
    assert_eq!(r.txns.len(), 1);
    assert!(t0.elapsed() < Duration::from_millis(1_000));
    // min_bytes not reached: waits the whole deadline, then returns what there is.
    let t0 = Instant::now();
    let r = c
        .changes(
            &pos,
            l.node.store.schema_fp(),
            &PollOpts {
                min_bytes: 10 << 20,
                max_wait_ms: 400,
                max_bytes: 1 << 20,
            },
        )
        .await
        .unwrap();
    assert_eq!(r.txns.len(), 1);
    assert!(t0.elapsed() >= Duration::from_millis(380));
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_is_required() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    let e = Client::new(&l.url, "wrong").status().await.unwrap_err();
    assert!(e.detail.contains("bearer token required"), "{e}");
    let r = reqwest::get(format!("{}/snapshot", l.url)).await.unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn pruned_history_gap_takes_a_new_snapshot_or_halts() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 6, 20).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    f.node.stop_follow().await;
    work(&l, 7, 200).await;
    l.node.store.prune(10).unwrap();
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    assert_eq!(f.node.follow_status().snapshots, 2);
    assert_eq!(dump(&l.node.store), dump(&f.node.store));

    // The same with automatic snapshots off: the follower halts instead.
    let mut cfg = poll_cfg();
    cfg.auto_snapshot_on_gap = false;
    let g = start(d.path(), "g.db", false, cfg).await;
    g.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &g).await;
    g.node.stop_follow().await;
    work(&l, 8, 50).await;
    l.node.store.prune(5).unwrap();
    g.node.start_follow(&l.url).await.unwrap();
    wait_for("halt", 10, || {
        g.node.store.state().unwrap().halted.is_some()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn divergence_halts_and_reset_refollows() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    l.node
        .store
        .write(json!({}), |tx| {
            Ok(tx.execute("INSERT INTO settings VALUES ('a', '1')", [])?)
        })
        .unwrap();
    work(&l, 9, 30).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    // Corrupt the follower behind its back.
    f.node
        .store
        .corrupt_for_test("UPDATE settings SET value = 'X' WHERE key = 'a'")
        .unwrap();
    let before = f.last();
    l.node
        .store
        .write(json!({}), |tx| {
            Ok(tx.execute("UPDATE settings SET value = '2' WHERE key = 'a'", [])?)
        })
        .unwrap();
    wait_for("halt", 10, || {
        f.node.store.state().unwrap().halted.is_some()
    })
    .await;
    let st = f.client().status().await.unwrap();
    let h = st.halted.unwrap();
    assert_eq!(h["kind"], "diverged");
    assert!(h["detail"].as_str().unwrap().contains("settings"), "{h}");
    assert_eq!(st.last_txn, before, "nothing of the bad batch applied");
    // The halted node keeps serving reads and refuses to be a snapshot source.
    assert_eq!(
        Client::new(&f.url, TOKEN)
            .snapshot()
            .await
            .err()
            .unwrap()
            .kind,
        Kind::Halted
    );
    // Operator: reset and refollow.
    f.client().reset().await.unwrap();
    caught_up(&l, &f).await;
    assert!(f.node.store.state().unwrap().halted.is_none());
    assert_eq!(dump(&l.node.store), dump(&f.node.store));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_upstream_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let a = start(d.path(), "a.db", true, poll_cfg()).await;
    let b = start(d.path(), "b.db", true, poll_cfg()).await;
    work(&a, 10, 20).await;
    work(&b, 10, 20).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&a.url).await.unwrap();
    caught_up(&a, &f).await;
    // Repoint to a leader of another history (same data, same txn ids).
    f.node.start_follow(&b.url).await.unwrap();
    wait_for("halt", 10, || {
        f.node.store.state().unwrap().halted.is_some()
    })
    .await;
    let h = f.node.store.state().unwrap().halted.unwrap();
    assert_eq!(h["kind"], "history");
    assert!(
        h["options"][0]
            .as_str()
            .unwrap()
            .contains("/admin/rebootstrap"),
        "{h}"
    );
    assert_eq!(dump(&a.node.store), dump(&f.node.store), "data untouched");
    // The operator chooses: rebootstrap from the new upstream.
    f.client().rebootstrap(Some(&b.url)).await.unwrap();
    caught_up(&b, &f).await;
    assert!(f.node.store.state().unwrap().halted.is_none());
    assert_eq!(dump(&b.node.store), dump(&f.node.store));
    assert_eq!(
        f.node.store.state().unwrap().history,
        b.node.store.state().unwrap().history
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_initiated_verify_finds_silent_corruption() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 11, 400).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    let r = f.client().verify(256).await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
    work(&l, 12, 100).await; // the leader moves on; verify is as of the follower's txn
    f.node.stop_follow().await;
    f.node
        .store
        .corrupt_for_test("DELETE FROM records WHERE id = (SELECT max(id) FROM records)")
        .unwrap();
    let r = f.client().verify(256).await.unwrap();
    assert_eq!(r["ok"], false);
    let rec = r["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["table"] == "records")
        .unwrap();
    assert_eq!(rec["diffs"][0]["problem"], "missing on this node", "{rec}");
    assert!(f.node.store.state().unwrap().halted.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_promote_repoint_and_rejoin_the_old_leader() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, stream_cfg()).await;
    work(&l, 13, 100).await;
    let f1 = start(d.path(), "f1.db", false, stream_cfg()).await;
    let f2 = start(d.path(), "f2.db", false, poll_cfg()).await;
    f1.node.start_follow(&l.url).await.unwrap();
    f2.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f2).await;
    f2.node.stop_follow().await; // f2 falls behind
    work(&l, 14, 50).await;
    caught_up(&l, &f1).await;
    f1.node.stop_follow().await; // the leader's last commits never reach anyone
    work(&l, 15, 7).await;
    let l_last = l.last();
    let f1_last = f1.last();
    assert!(l_last > f1_last);

    // Promotion is refused while the leader is reachable.
    let e = f1.client().promote(&[&f2.url], false).await.unwrap_err();
    assert!(
        e.detail.contains("leader of this history is reachable"),
        "{e}"
    );

    l.server.abort(); // the leader dies
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The lagging follower is not the one to promote.
    let e = f2
        .client()
        .promote(&[&f1.url, &l.url], false)
        .await
        .unwrap_err();
    assert!(e.detail.contains("most advanced"), "{e}");
    let r = f1
        .client()
        .promote(&[&f2.url, &l.url], false)
        .await
        .unwrap();
    assert_eq!(r["promoted"], true, "{r}");
    f1.node
        .store
        .write(json!({"actor": "after failover"}), |tx| {
            Ok(tx.execute("INSERT INTO settings VALUES ('new', 'leader')", [])?)
        })
        .unwrap();
    work(&f1, 16, 30).await;

    // The other follower repoints to the new leader and continues.
    f2.client().follow(&f1.url).await.unwrap();
    caught_up(&f1, &f2).await;
    assert_eq!(dump(&f1.node.store), dump(&f2.node.store));
    assert_eq!(
        f2.node.follow_status().snapshots,
        1,
        "repoint must not need a snapshot"
    );

    // The old leader comes back: it fences itself, then rejoins.
    let (addr, _server) = l.node.serve("127.0.0.1:0").await.unwrap();
    let lc = Client::new(&format!("http://{addr}"), TOKEN);
    assert!(
        l.node
            .fence_check(std::slice::from_ref(&f1.url))
            .await
            .unwrap()
    );
    let e = l
        .node
        .store
        .write(json!({}), |tx| Ok(tx.execute("DELETE FROM settings", [])?))
        .unwrap_err();
    assert_eq!(e.kind, Kind::NotLeader);
    let e = lc.rejoin(&f1.url, false).await.unwrap_err();
    assert!(e.detail.contains("accept_loss"), "{e}");
    let r = lc.rejoin(&f1.url, true).await.unwrap();
    assert_eq!(r["fork"], f1_last, "{r}");
    assert_eq!(r["discarded_txns"].as_u64().unwrap(), l_last - f1_last);
    assert!(std::path::Path::new(r["file"].as_str().unwrap()).exists());
    caught_up(&f1, &l).await;
    assert_eq!(dump(&f1.node.store), dump(&l.node.store));
    assert_eq!(
        l.node.follow_status().snapshots,
        0,
        "rejoin must not need a snapshot"
    );
    // Everything agrees, checked by the verify protocol as well.
    let r = lc.verify(64).await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_schema_mismatch_blocks_loudly_and_resumes_after_the_upgrade() {
    let d = tempfile::tempdir().unwrap();
    let l = start(d.path(), "l.db", true, poll_cfg()).await;
    work(&l, 17, 20).await;
    let f = start(d.path(), "f.db", false, poll_cfg()).await;
    f.node.start_follow(&l.url).await.unwrap();
    caught_up(&l, &f).await;
    let upgrade = |c: &rusqlite::Connection| -> anyhow::Result<()> {
        demo::migrate(c)?;
        if c.prepare("SELECT notes FROM zones").is_err() {
            c.execute_batch("ALTER TABLE zones ADD COLUMN notes TEXT")?;
        }
        Ok(())
    };
    // The leader is upgraded with a new column; the follower is not yet.
    l.server.abort();
    let lp = d.path().join("l.db");
    let l2 = Node::new(
        Arc::new(sqlite_cdc::store::Store::open(&lp, demo::config(), upgrade).unwrap()),
        poll_cfg(),
    );
    let (addr, _s) = l2.serve("127.0.0.1:0").await.unwrap();
    let lurl = format!("http://{addr}");
    l2.store
        .write(json!({}), |tx| {
            Ok(tx.execute("UPDATE zones SET notes = 'n'", [])?)
        })
        .unwrap();
    f.node.start_follow(&lurl).await.unwrap();
    wait_for("blocked", 10, || {
        f.node.follow_status().state.starts_with("blocked")
    })
    .await;
    let fs = f.node.follow_status();
    let msg = fs.last_error.unwrap();
    assert!(
        msg.contains("table zones") && msg.contains("notes"),
        "{msg}"
    );
    assert!(
        f.node.store.state().unwrap().halted.is_none(),
        "a schema mismatch is not a divergence"
    );
    // Upgrade the follower: it resumes on its own, nothing to rebuild.
    f.node.stop_follow().await;
    f.server.abort();
    let fp = d.path().join("f.db");
    drop(f);
    let f2 = Node::new(
        Arc::new(sqlite_cdc::store::Store::open(&fp, demo::config(), upgrade).unwrap()),
        poll_cfg(),
    );
    f2.start_follow(&lurl).await.unwrap();
    let want = l2.store.state().unwrap().last_txn;
    wait_for("resume", 10, || f2.store.state().unwrap().last_txn >= want).await;
    assert_eq!(dump(&l2.store), dump(&f2.store));
}
