//! Helpers shared by the mutation tests (and `replica`'s).

use super::accounts::Accounts;
use super::*;
use rand::rngs::StdRng;
use rand::Rng;

pub(crate) fn setup() -> (Arc<Storage>, Mutator, Accounts) {
    let storage = Arc::new(Storage::open_memory().unwrap());
    let cache = Arc::new(Cache::new(Catalog::empty()));
    let bus = Arc::new(Bus::new(64, 64));
    let m = Mutator::new(storage.clone(), cache, bus, "", "");
    let a = Accounts::new(storage.clone());
    (storage, m, a)
}

pub(crate) fn actor() -> Actor {
    Actor {
        name: "tester".into(),
        ip: "127.0.0.1".into(),
    }
}

pub(crate) fn rec(name: &str, t: RecordType, v: &str) -> RecordInput {
    RecordInput {
        name: Some(name.into()),
        rtype: Some(t),
        value: Some(v.into()),
        ..Default::default()
    }
}

pub(crate) fn zone_input(name: &str) -> ZoneInput {
    ZoneInput {
        name: Some(name.into()),
        ..Default::default()
    }
}

pub(crate) fn log(s: &Storage) -> Vec<ChangeEvent> {
    s.changelog_after(0, 1_000_000).unwrap()
}

pub(crate) fn expiring(name: &str, v: &str, secs: u64) -> RecordInput {
    RecordInput {
        expires_in: Some(secs),
        ..rec(name, RecordType::A, v)
    }
}

/// A full build of what `s` holds now, with a signer of its own (no
/// shared cache), configured like `m`'s.
pub(crate) fn full_build(s: &Storage, m: &Mutator) -> Catalog {
    let signer = crate::dnssec::Signer::default();
    signer.set_config(m.signer().config());
    let (zones, records, keys) = s.catalog_inputs().unwrap();
    Catalog::build_signed(zones, records, &keys, &signer, chrono::Utc::now())
}

/// The served catalog must equal a full build of the database, and
/// every signature in it must verify.
pub(crate) fn assert_catalog_is_current(s: &Storage, m: &Mutator, what: &str) {
    let served = m.cache.load();
    let full = full_build(s, m);
    let (a, b) = (served.describe(), full.describe());
    if a != b {
        for (k, v) in a["zones"].as_object().unwrap() {
            if b["zones"].get(k) != Some(v) {
                panic!(
                    "{what}: zone {k} differs\nincremental: {v:#}\nfull: {:#}",
                    b["zones"][k]
                );
            }
        }
        panic!("{what}: catalogs differ\nincremental: {a:#}\nfull: {b:#}");
    }
    served.verify_signatures();
    full.verify_signatures();
}

/// One random DNS operation (zones incl. a parent/child pair, records
/// incl. delegations, DS, wildcards, DNAME, addresses shared between
/// zones for the reverse index, expiry, import, DNSSEC on/off/new
/// key/re-sign). Used by the catalog equality tests here and in
/// `replica`.
pub(crate) async fn random_dns_op(
    rng: &mut StdRng,
    s: &Storage,
    m: &Mutator,
    step: usize,
) -> MResult<()> {
    let zones = ["eq.test", "sub.eq.test", "other.test", "10.in-addr.arpa"];
    let z = zones[rng.random_range(0..zones.len())];
    let names = [
        "@", "www", "a.b", "*.w", "x.w", "deleg", "ns.deleg", "old", "y.old", "sub",
    ];
    let pick = |rng: &mut StdRng| names[rng.random_range(0..names.len())];
    match rng.random_range(0..100) {
        0..=7 => m
            .create_zone(actor(), zone_input(z), None)
            .await
            .map(|_| ()),
        8..=9 => m.delete_zone(actor(), z).await.map(|_| ()),
        10..=14 => m
            .update_zone(
                actor(),
                z,
                ZoneInput {
                    refresh: Some(rng.random_range(60..9000)),
                    default_ttl: Some(rng.random_range(30..600)),
                    minimum: Some(rng.random_range(30..600)),
                    ..Default::default()
                },
                None,
            )
            .await
            .map(|_| ()),
        15..=54 => {
            let name = pick(rng);
            // Few addresses: several zones share them (reverse index).
            let n = rng.random_range(1..6);
            let (t, v) = match rng.random_range(0..12) {
                0..=3 => (RecordType::A, format!("10.0.0.{n}")),
                4 => (RecordType::AAAA, format!("2001:db8::{n}")),
                5 => (RecordType::TXT, format!("text {n}")),
                6 => (RecordType::CNAME, format!("host{n}.example.com.")),
                7 => (RecordType::NS, format!("ns{n}.example.org.")),
                8 => (RecordType::MX, format!("10 mx{n}.eq.test.")),
                9 => (RecordType::DS, format!("{n} 13 2 {}", "ab".repeat(32))),
                10 => (RecordType::DNAME, format!("target{n}.example.net.")),
                _ => (RecordType::PTR, format!("host{n}.eq.test.")),
            };
            let mut input = rec(name, t, &v);
            match rng.random_range(0..10) {
                0 => input.ttl = Some(Some(rng.random_range(10..900))),
                1 => input.expires_in = Some(rng.random_range(3600..7200)),
                _ => {}
            }
            m.create_record(actor(), z, input).await.map(|_| ())
        }
        55..=69 => match s
            .get_zone(z)
            .unwrap()
            .map(|zz| s.list_records(zz.id).unwrap())
        {
            Some(rs) if !rs.is_empty() => {
                let r = &rs[rng.random_range(0..rs.len())];
                let input = if r.rtype == RecordType::A {
                    RecordInput {
                        value: Some(format!("10.0.0.{}", rng.random_range(1..6))),
                        ..Default::default()
                    }
                } else {
                    RecordInput {
                        ttl: Some(Some(rng.random_range(10..900))),
                        ..Default::default()
                    }
                };
                m.update_record(actor(), z, r.id, input).await.map(|_| ())
            }
            _ => Ok(()),
        },
        70..=79 => match s
            .get_zone(z)
            .unwrap()
            .map(|zz| s.list_records(zz.id).unwrap())
        {
            Some(rs) if !rs.is_empty() => {
                let r = &rs[rng.random_range(0..rs.len())];
                m.delete_record(actor(), z, r.id).await.map(|_| ())
            }
            _ => Ok(()),
        },
        // O24: NSEC3 on, off or unchanged with it.
        80..=85 => m
            .set_dnssec_with(
                actor(),
                z,
                true,
                step.is_multiple_of(5),
                [None, Some(true), Some(false)][step % 3],
            )
            .await
            .map(|_| ()),
        86..=88 => m.set_dnssec(actor(), z, false, false).await.map(|_| ()),
        89..=90 => m
            .resign_due(chrono::Utc::now() + chrono::Duration::days(8))
            .await
            .map(|_| ()),
        // Marks the records with an expiry as expired (they stay in
        // the catalog until their time really passes) / reaps nothing.
        91..=92 => m
            .expire_due(chrono::Utc::now() + chrono::Duration::hours(3))
            .await
            .map(|_| ()),
        93 => m
            .reap_due(chrono::Utc::now() - chrono::Duration::days(30))
            .await
            .map(|_| ()),
        _ => {
            let recs = (0..rng.random_range(0..5))
                .map(|i| ExportRecord {
                    name: format!("imp{i}"),
                    rtype: RecordType::A,
                    value: format!("10.0.1.{}", rng.random_range(1..4)),
                    ttl: None,
                    expires_at: None,
                })
                .collect();
            let doc = ExportDoc {
                version: 1,
                exported_at: String::new(),
                zones: vec![ExportZone {
                    name: z.into(),
                    serial: None,
                    soa_mname: None,
                    soa_rname: None,
                    refresh: None,
                    retry: None,
                    expire: None,
                    minimum: None,
                    default_ttl: None,
                    owner: None,
                    overrides: None,
                    record_policy: None,
                    records: recs,
                }],
            };
            let mode = if rng.random_bool(0.4) {
                ImportMode::Replace
            } else {
                ImportMode::Merge
            };
            m.import(actor(), doc, mode, None, None).await.map(|_| ())
        }
    }
}

pub(crate) fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/changelog_payloads.jsonl")
}

pub(crate) fn dump(s: &Storage) -> serde_json::Value {
    s.read_tx(|c| {
        let mut v = serde_json::Map::new();
        for t in crate::replication::tables::replicated_tables() {
            v.insert(
                t.name.into(),
                crate::replication::tables::dump(c, t, &["last_used_at", "last_used_ip"], None)?
                    .into(),
            );
        }
        Ok(serde_json::Value::Object(v))
    })
    .unwrap()
}
