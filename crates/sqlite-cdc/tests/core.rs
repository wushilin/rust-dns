//! The store without the network: capture, apply, chain, divergence,
//! rewind and verification.

mod common;

use common::*;
use rusqlite::Connection;
use serde_json::json;
use sqlite_cdc::store::Kind;

#[test]
fn random_workload_replays_to_identical_tables() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 1, 50, 5);
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    assert_eq!(dump(&l), dump(&f));
    workload(&l, 2, 1500, 8);
    catch_up(&l, &f).unwrap();
    assert_eq!(dump(&l), dump(&f));
    assert_eq!(l.state().unwrap().last_hash, f.state().unwrap().last_hash);
    // A follower serves its own followers byte-identical changes.
    let g = open(&d.path().join("g.db"));
    bootstrap(&f, &g);
    workload(&l, 3, 200, 8);
    catch_up(&l, &f).unwrap();
    catch_up(&f, &g).unwrap();
    assert_eq!(dump(&l), dump(&g));
}

#[test]
fn every_kind_of_write_is_captured_including_cascades() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    l.write(json!({}), |tx| {
        tx.execute_batch(
            "INSERT INTO zones(name, serial) VALUES ('a.example', 1);
             INSERT INTO records(zone_id, name, rtype, value) VALUES (1, 'www', 'A', '1.2.3.4');
             INSERT INTO records(zone_id, name, rtype, value) VALUES (1, 'mail', 'A', '1.2.3.5');
             INSERT INTO users(username, pw_hash, weight) VALUES ('bob', x'00ff10', 0.1);
             INSERT INTO members(zone_id, user_id, role) VALUES (1, 1, 'admin');",
        )?;
        Ok(())
    })
    .unwrap();
    let (_, id) = l
        .write(json!({}), |tx| {
            Ok(tx.execute("DELETE FROM zones WHERE id = 1", [])?)
        })
        .unwrap();
    let pos = sqlite_cdc::wire::Position {
        history: l.state().unwrap().history.unwrap(),
        txn_id: id.unwrap() - 1,
        hash: l.hashes(id.unwrap() - 1, id.unwrap() - 1).unwrap()[0]
            .1
            .clone(),
    };
    let (txns, _) = l.changes(&pos, usize::MAX, 10).unwrap();
    let ops: Vec<(String, String)> = txns[0]
        .rows
        .iter()
        .map(|r| (r.op.clone(), r.tbl.clone()))
        .collect();
    // The zone delete cascaded to two records and one membership; all captured.
    assert_eq!(
        ops.iter()
            .filter(|(o, t)| o == "D" && t == "records")
            .count(),
        2,
        "{ops:?}"
    );
    assert_eq!(
        ops.iter()
            .filter(|(o, t)| o == "D" && t == "members")
            .count(),
        1,
        "{ops:?}"
    );
    assert_eq!(
        ops.iter().filter(|(o, t)| o == "D" && t == "zones").count(),
        1,
        "{ops:?}"
    );
}

#[test]
fn blobs_reals_nulls_and_text_round_trip_exactly() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    let weights = [
        0.1f64,
        1.0 / 3.0,
        1e-300,
        123_456_789.123_456_79,
        f64::MAX,
        -0.0,
    ];
    l.write(json!({}), |tx| {
        for (i, w) in weights.iter().enumerate() {
            tx.execute(
                "INSERT INTO users(username, pw_hash, weight) VALUES (?1, ?2, ?3)",
                rusqlite::params![format!("u{i}"), vec![0u8, 255, i as u8, 0], w],
            )?;
        }
        tx.execute(
            "INSERT INTO users(username, pw_hash, weight) VALUES ('n', NULL, NULL)",
            [],
        )?;
        tx.execute(
            "INSERT INTO settings VALUES ('j', '{\"a\":1}'), ('q', 'it''s \"x\" \\ é ✓')",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    workload(&l, 9, 1, 1);
    catch_up(&l, &f).unwrap();
    let read = |s: &sqlite_cdc::store::Store| -> Vec<(String, Option<Vec<u8>>, Option<f64>)> {
        let c = s.reader().unwrap();
        c.prepare("SELECT username, pw_hash, weight FROM users ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let (a, b) = (read(&l), read(&f));
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x.0, y.0);
        assert_eq!(x.1, y.1);
        assert_eq!(
            x.2.map(f64::to_bits),
            y.2.map(f64::to_bits),
            "REAL bits for {}",
            x.0
        );
    }
    assert_eq!(dump(&l), dump(&f));
}

#[test]
fn writes_outside_a_replicated_transaction_fail() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.db");
    let l = leader(d.path(), "l.db");
    // Another connection: the trigger's function does not exist there.
    let other = Connection::open(&path).unwrap();
    let e = other
        .execute("INSERT INTO zones(name, serial) VALUES ('x', 1)", [])
        .unwrap_err();
    assert!(e.to_string().contains("_cdc_capture"), "{e}");
    // Local tables are writable from anywhere.
    other
        .execute("INSERT INTO sessions VALUES ('s', 1, 'now')", [])
        .unwrap();
    // A follower's application cannot write at all.
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    let e = f
        .write(json!({}), |tx| Ok(tx.execute("DELETE FROM zones", [])?))
        .unwrap_err();
    assert_eq!(e.kind, Kind::NotLeader);
    // A primary key change is refused (it would break row identity).
    l.write(json!({}), |tx| {
        Ok(tx.execute("INSERT INTO zones(name, serial) VALUES ('a', 1)", [])?)
    })
    .unwrap();
    let e = l
        .write(json!({}), |tx| {
            Ok(tx.execute("UPDATE zones SET id = 99", [])?)
        })
        .unwrap_err();
    assert!(e.detail.contains("primary key"), "{e}");
}

#[test]
fn a_tampered_follower_row_halts_at_the_next_change_to_it() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    l.write(json!({}), |tx| {
        Ok(tx.execute("INSERT INTO settings VALUES ('a', '1'), ('b', '1')", [])?)
    })
    .unwrap();
    let fp = d.path().join("f.db");
    let f = open(&fp);
    bootstrap(&l, &f);
    // Simulate corruption: edit the follower's row bypassing the triggers.
    {
        let c = Connection::open(&fp).unwrap();
        c.execute_batch(
            "DROP TRIGGER _cdc_u_settings; UPDATE settings SET value = 'X' WHERE key = 'a';",
        )
        .unwrap();
    }
    let f = open(&fp); // reopening recreates the trigger
    l.write(json!({}), |tx| {
        Ok(tx.execute("UPDATE settings SET value = '2' WHERE key = 'a'", [])?)
    })
    .unwrap();
    let e = catch_up(&l, &f).unwrap_err();
    assert_eq!(e.kind, Kind::Diverged);
    assert!(e.detail.contains("settings"), "{e}");
    // Nothing of the failed batch was applied.
    assert_eq!(f.state().unwrap().last_txn, 1);
}

#[test]
fn a_tampered_change_log_fails_the_chain() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 4, 20, 3);
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    workload(&l, 5, 5, 3);
    let pos = f.state().unwrap().position().unwrap();
    let (mut txns, _) = l.changes(&pos, usize::MAX, 100).unwrap();
    let r = txns
        .iter_mut()
        .flat_map(|t| t.rows.iter_mut())
        .find(|r| r.after.is_some())
        .unwrap();
    let edited = r.after.as_ref().unwrap().get().replacen('1', "2", 1);
    r.after = Some(sqlite_cdc::wire::raw(edited));
    let e = f.apply(&txns).unwrap_err();
    assert_eq!(e.kind, Kind::Diverged);
    assert!(e.detail.contains("chain hash"), "{e}");
}

#[test]
fn positions_from_another_history_or_fork_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let a = leader(d.path(), "a.db");
    let b = leader(d.path(), "b.db");
    workload(&a, 6, 10, 2);
    workload(&b, 6, 10, 2); // identical content, different history
    let pa = a.state().unwrap().position().unwrap();
    assert_eq!(b.changes(&pa, 1, 1).unwrap_err().kind, Kind::History);

    // Same history, split after a promotion: same txn id, different hash.
    let f = open(&d.path().join("f.db"));
    bootstrap(&a, &f);
    f.promote(false).unwrap();
    f.write(json!({}), |tx| {
        Ok(tx.execute("INSERT INTO settings VALUES ('f', '1')", [])?)
    })
    .unwrap();
    a.write(json!({}), |tx| {
        Ok(tx.execute("INSERT INTO settings VALUES ('f', '1')", [])?)
    })
    .unwrap();
    a.write(json!({}), |tx| {
        Ok(tx.execute("INSERT INTO settings VALUES ('g', '1')", [])?)
    })
    .unwrap();
    let pa = a.state().unwrap().position().unwrap();
    let pf = f.state().unwrap().position().unwrap();
    assert_eq!(pa.txn_id, pf.txn_id);
    assert_ne!(pa.hash, pf.hash);
    assert_eq!(f.changes(&pa, 1, 1).unwrap_err().kind, Kind::Diverged);
}

#[test]
fn rewind_undoes_divergent_transactions_exactly() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 7, 100, 6);
    let fork = l.state().unwrap().last_txn;
    let before = dump(&l);
    let hash_before = l.state().unwrap().last_hash;
    workload(&l, 8, 100, 6); // these will be discarded
    let last = l.state().unwrap().last_txn;
    let discarded = l.rewind_to(fork).unwrap();
    assert_eq!(discarded.len() as u64, last - fork);
    assert!(discarded.len() > 90);
    assert_eq!(dump(&l), before);
    let st = l.state().unwrap();
    assert_eq!((st.last_txn, st.last_hash), (fork, hash_before));
    assert_eq!(st.role.as_str(), "follower");
}

#[test]
fn rewind_needs_the_row_images() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 10, 50, 3);
    l.prune(10).unwrap();
    assert_eq!(l.rewind_to(20).unwrap_err().kind, Kind::NeedsReset);
    assert!(l.rewind_to(45).is_ok());
}

#[test]
fn pruned_history_is_a_gap_not_a_divergence() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 11, 10, 3);
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    workload(&l, 12, 100, 3);
    l.prune(20).unwrap();
    assert_eq!(catch_up(&l, &f).unwrap_err().kind, Kind::Gap);
    // A wrong hash at the same position is still a divergence, not a gap.
    let mut pos = f.state().unwrap().position().unwrap();
    pos.hash = "00".repeat(32);
    assert_eq!(l.changes(&pos, 1, 1).unwrap_err().kind, Kind::Diverged);
}

#[test]
fn verification_as_of_a_past_transaction() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 13, 200, 6);
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    let at = f.state().unwrap().last_txn;
    workload(&l, 14, 200, 6); // the leader moved on
    for t in ["zones", "records", "users", "members", "settings"] {
        let a = l.bucket_hashes(t, at, 64).unwrap();
        let b = f.bucket_hashes(t, at, 64).unwrap();
        assert_eq!(a.buckets, b.buckets, "{t} at {at}");
    }
    // A silent corruption on the follower is found and pinpointed.
    let fp = d.path().join("f.db");
    {
        let c = Connection::open(&fp).unwrap();
        c.execute_batch("DROP TRIGGER _cdc_u_records; UPDATE records SET ttl = 7 WHERE id = (SELECT min(id) FROM records);")
            .unwrap();
    }
    let f = open(&fp);
    let a = l.bucket_hashes("records", at, 64).unwrap();
    let b = f.bucket_hashes("records", at, 64).unwrap();
    let bad: Vec<usize> = (0..64).filter(|&i| a.buckets[i] != b.buckets[i]).collect();
    assert_eq!(bad.len(), 1);
    let ra = l.bucket_rows("records", at, 64, bad[0]).unwrap();
    let rb = f.bucket_rows("records", at, 64, bad[0]).unwrap();
    let diff: Vec<_> = ra
        .iter()
        .zip(&rb)
        .filter(|(x, y)| x.hash != y.hash)
        .map(|(x, _)| x.pk.clone())
        .collect();
    assert_eq!(diff.len(), 1, "{diff:?}");
}

#[test]
fn a_dropped_trigger_or_altered_table_stops_writes_loudly() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.db");
    let l = leader(d.path(), "l.db");
    workload(&l, 20, 5, 2);
    assert!(l.health().unwrap().is_empty());
    let other = Connection::open(&path).unwrap();
    other.execute_batch("DROP TRIGGER _cdc_u_records").unwrap();
    let e = l
        .write(json!({}), |tx| {
            Ok(tx.execute("UPDATE records SET ttl = 1", [])?)
        })
        .unwrap_err();
    assert_eq!(e.kind, Kind::Schema);
    assert!(e.detail.contains("_cdc_u_records is missing"), "{e}");
    assert!(!l.health().unwrap().is_empty());
    // Reopening regenerates the triggers.
    drop(l);
    let l = open(&path);
    assert!(l.health().unwrap().is_empty());
    l.write(json!({}), |tx| {
        Ok(tx.execute("UPDATE records SET ttl = 1", [])?)
    })
    .unwrap();

    // A column added behind the node's back.
    other
        .execute_batch("ALTER TABLE users ADD COLUMN email TEXT")
        .unwrap();
    let e = l
        .write(json!({}), |tx| {
            Ok(tx.execute("UPDATE users SET weight = 1", [])?)
        })
        .unwrap_err();
    assert_eq!(e.kind, Kind::Schema);
    assert!(e.detail.contains("table users columns changed"), "{e}");

    // A schema change inside a replicated transaction is refused.
    drop(l);
    let l = open(&path);
    let e = l
        .write(json!({}), |tx| {
            Ok(tx.execute_batch("ALTER TABLE settings ADD COLUMN x TEXT")?)
        })
        .unwrap_err();
    assert_eq!(e.kind, Kind::Schema);
    assert!(e.detail.contains("changed the schema"), "{e}");
}

#[test]
fn a_follower_halts_on_a_stale_trigger_too() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 21, 10, 3);
    let fp = d.path().join("f.db");
    let f = open(&fp);
    bootstrap(&l, &f);
    Connection::open(&fp)
        .unwrap()
        .execute_batch("DROP TRIGGER _cdc_i_settings")
        .unwrap();
    workload(&l, 22, 10, 3);
    let e = catch_up(&l, &f).unwrap_err();
    assert_eq!(e.kind, Kind::Schema, "{e}");
}

#[test]
fn temp_triggers_capture_the_same_and_leave_nothing_in_the_file() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.db");
    let mut cfg = common::demo::config();
    cfg.temp_triggers = true;
    let l = std::sync::Arc::new(
        sqlite_cdc::store::Store::open(&path, cfg.clone(), common::demo::migrate).unwrap(),
    );
    l.init_leader().unwrap();
    assert!(l.health().unwrap().is_empty(), "{:?}", l.health());
    workload(&l, 30, 300, 6);
    let f = open(&d.path().join("f.db"));
    bootstrap(&l, &f);
    workload(&l, 31, 300, 6);
    catch_up(&l, &f).unwrap();
    assert_eq!(dump(&l), dump(&f));
    // Nothing is stored in the file: another connection sees no triggers
    // and can write freely (an older binary after a rollback).
    let other = Connection::open(&path).unwrap();
    let n: i64 = other
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
    other
        .execute("INSERT INTO settings VALUES ('other', 'conn')", [])
        .unwrap();
}

#[test]
fn self_check_finds_rows_changed_behind_the_log() {
    let d = tempfile::tempdir().unwrap();
    let l = leader(d.path(), "l.db");
    workload(&l, 40, 200, 5);
    let r = l.self_check().unwrap();
    assert_eq!(r["ok"], true, "{r}");
    l.corrupt_for_test("UPDATE records SET ttl = 4242 WHERE id = (SELECT max(id) FROM records)")
        .unwrap();
    let r = l.self_check().unwrap();
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["problems"][0]["table"], "records", "{r}");
}
