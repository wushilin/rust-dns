//! The hash chain. Each transaction's hash covers the previous hash and the
//! exact bytes of the transaction, so a matching `(txn_id, hash)` proves the
//! whole history up to it matches.

use crate::wire::Row;

pub fn genesis(history: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"sqlite-cdc/genesis\0");
    h.update(history.as_bytes());
    h.finalize().to_hex().to_string()
}

fn field(h: &mut blake3::Hasher, b: &[u8]) {
    h.update(&(b.len() as u64).to_le_bytes());
    h.update(b);
}

fn opt(h: &mut blake3::Hasher, b: Option<&str>) {
    match b {
        None => {
            h.update(&[0]);
        }
        Some(s) => {
            h.update(&[1]);
            field(h, s.as_bytes());
        }
    }
}

pub fn txn_hash(prev: &str, txn_id: u64, ts: &str, meta: &str, rows: &[Row]) -> String {
    let mut h = blake3::Hasher::new();
    field(&mut h, prev.as_bytes());
    h.update(&txn_id.to_le_bytes());
    field(&mut h, ts.as_bytes());
    field(&mut h, meta.as_bytes());
    h.update(&(rows.len() as u64).to_le_bytes());
    for r in rows {
        h.update(&r.seq.to_le_bytes());
        field(&mut h, r.op.as_bytes());
        field(&mut h, r.tbl.as_bytes());
        field(&mut h, r.pk.get().as_bytes());
        opt(&mut h, r.before.as_ref().map(|b| b.get()));
        opt(&mut h, r.after.as_ref().map(|a| a.get()));
    }
    h.finalize().to_hex().to_string()
}

/// Row hash used by verification: `(bucket, 128-bit value)`.
pub fn row_hash(tbl: &str, pk: &str, row: &str, buckets: u64) -> (usize, u128) {
    let b = blake3::hash(pk.as_bytes());
    let bucket = (u64::from_le_bytes(b.as_bytes()[..8].try_into().unwrap()) % buckets) as usize;
    let mut h = blake3::Hasher::new();
    field(&mut h, tbl.as_bytes());
    field(&mut h, pk.as_bytes());
    field(&mut h, row.as_bytes());
    let v = u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap());
    (bucket, v)
}
