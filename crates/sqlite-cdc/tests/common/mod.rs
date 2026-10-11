#![allow(dead_code)]

pub mod demo;

use std::path::Path;
use std::sync::Arc;

use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::json;
use sqlite_cdc::store::{Progress, Store};

/// A rustls crypto provider for the HTTP client (see Cargo.toml).
pub fn tls() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn open(path: &Path) -> Arc<Store> {
    tls();
    Arc::new(Store::open(path, demo::config(), demo::migrate).expect("open"))
}

pub fn leader(dir: &Path, name: &str) -> Arc<Store> {
    let s = open(&dir.join(name));
    s.init_leader().unwrap();
    s
}

/// Random transactions of 1..=ops operations each.
pub fn workload(s: &Store, seed: u64, txns: usize, ops: usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    for _ in 0..txns {
        let k = rand::Rng::random_range(&mut rng, 1..=ops);
        s.write(json!({"actor": "test"}), |tx| {
            for _ in 0..k {
                demo::random_op(tx, &mut rng)?;
            }
            Ok(())
        })
        .unwrap();
    }
}

/// Every replicated table, as canonical row JSON in key order.
pub fn dump(s: &Store) -> Vec<(String, Vec<String>)> {
    let c = s.reader().unwrap();
    s.tables()
        .iter()
        .map(|t| {
            let rows = c
                .prepare(&t.scan_sql())
                .unwrap()
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (t.name.clone(), rows)
        })
        .collect()
}

/// Copy a snapshot of `from` into fresh `to`, in memory.
pub fn bootstrap(from: &Store, to: &Store) {
    let mut lines = Vec::new();
    from.snapshot(|b| {
        let mut b = b;
        b.pop();
        lines.push(b);
        Ok(())
    })
    .unwrap();
    to.load_snapshot(lines.into_iter().map(Ok), None, &Progress::default())
        .unwrap();
}

/// Pull everything `to` is missing from `from` and apply it.
pub fn catch_up(from: &Store, to: &Store) -> Result<u64, sqlite_cdc::store::CdcError> {
    loop {
        let pos = to.state().unwrap().position().unwrap();
        let (txns, last) = from.changes(&pos, 256 * 1024, 1000)?;
        if txns.is_empty() {
            return Ok(last);
        }
        to.apply(&txns)?;
    }
}
