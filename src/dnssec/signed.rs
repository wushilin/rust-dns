//! The signed view of one zone, computed when the catalog is built.
//!
//! What is signed (RFC 4035 §2): every authoritative RRset, including the
//! apex SOA, NS and DNSKEY and every NSEC. Not signed: the NS RRset at a
//! delegation point and anything below a zone cut (glue), nor names below
//! a DNAME (occluded; DNAME answers synthesize them). A DS RRset at a
//! delegation point is authoritative parent-side data and is signed.
//!
//! The NSEC chain links every authoritative owner name in canonical order:
//! the apex, every name holding records (wildcard owners such as
//! `*.gate.example.net.` included, `*` sorting before other labels) and
//! every delegation point. Empty non-terminals have no NSEC of their own
//! (RFC 4035 §2.3): the NSEC of the previous name, whose next name is a
//! descendant of the empty non-terminal, proves it exists without data.
//! Names below a cut or a DNAME are not in the chain.
//!
//! Every record is converted with the same function the query path uses
//! (`zones::to_rr`), so what is signed is exactly what is served.

use super::wire::{self, CanonKey, RrsigFields, T_DNSKEY, T_DS, T_NSEC, T_RRSIG};
use super::{Window, ZoneKey, ALGORITHM};
use crate::cache::ZoneData;
use crate::model::RecordType as Rt;
use crate::replication::types::ReplDnssecKey;
use crate::zones::{apex_ns, soa_record, to_rr};
use anyhow::{anyhow, Result};
use hickory_proto::rr::{Name, Record, RecordType};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// Bumped when the signing code changes what it produces (cache key).
const SIGNER_VERSION: u32 = 1;

/// One link of the NSEC chain.
pub struct NsecEntry {
    /// Lower-case owner (as in `ZoneData::names`).
    pub owner: String,
    key: CanonKey,
    pub record: Record,
    pub types: Vec<u16>,
}

pub struct SignedZone {
    pub fingerprint: String,
    pub key_tag: u16,
    pub inception: u32,
    pub expiration: u32,
    /// The apex DNSKEY RRset (one key).
    pub dnskey: Record,
    /// RRsets signed, NSEC RRsets included.
    pub signed_rrsets: usize,
    /// RRSIG per (owner, covered type); the owner as stored (lower case).
    sigs: HashMap<(String, u16), Record>,
    chain: Vec<NsecEntry>,
    index: HashMap<String, usize>,
}

/// Where a name stands in the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Authoritative,
    /// A delegation point: NS (unsigned) and DS (signed) are parent-side.
    Cut,
    /// Below a cut (glue) or below a DNAME: not authoritative here.
    Occluded,
}

fn parent(name: &str) -> Option<&str> {
    match name.split_once('.') {
        Some((_, rest)) if !rest.is_empty() => Some(rest),
        Some(_) if name != "." => Some("."),
        _ => None,
    }
}

pub fn is_below(name: &str, ancestor: &str) -> bool {
    if ancestor == "." {
        return name != ".";
    }
    name.len() > ancestor.len()
        && name.ends_with(ancestor)
        && name.as_bytes()[name.len() - ancestor.len() - 1] == b'.'
}

pub fn position(z: &ZoneData, owner: &str) -> Position {
    if owner == z.apex {
        return Position::Authoritative;
    }
    if z.delegations
        .iter()
        .any(|d| d != owner && is_below(owner, d))
    {
        return Position::Occluded;
    }
    let mut cur = owner;
    while let Some(p) = parent(cur) {
        if z.records_at(p)
            .is_some_and(|rs| rs.iter().any(|r| r.rtype == Rt::DNAME))
        {
            return Position::Occluded;
        }
        if p == z.apex {
            break;
        }
        cur = p;
    }
    if z.delegations.iter().any(|d| d == owner) {
        Position::Cut
    } else {
        Position::Authoritative
    }
}

/// Cache key: everything the signed view depends on.
pub fn fingerprint(z: &ZoneData, key: &ReplDnssecKey, w: &Window) -> String {
    let mut records: Vec<&crate::model::Record> = z.names.values().flatten().collect();
    records.sort_by_key(|r| r.id);
    let recs: Vec<(i64, &str, &str, &str, Option<u32>)> = records
        .iter()
        .map(|r| {
            (
                r.id,
                r.name.as_str(),
                r.rtype.as_str(),
                r.value.as_str(),
                r.ttl,
            )
        })
        .collect();
    let v = serde_json::json!({
        "v": SIGNER_VERSION,
        "zone": z.zone,
        "records": recs,
        "key": [key.key_tag.to_string(), key.public_key.clone(), key.algorithm.to_string()],
        "window": [w.inception, w.expiration],
    });
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

struct OwnerSets {
    owner: String,
    name: Name,
    position: Position,
    rrsets: BTreeMap<u16, Vec<Record>>,
}

fn code(r: &Record) -> u16 {
    u16::from(r.record_type())
}

impl SignedZone {
    pub fn build(z: &ZoneData, key: &ZoneKey, w: Window, fingerprint: String) -> Result<Self> {
        let zone = &z.zone;
        let apex = Name::from_ascii(&z.apex).map_err(|e| anyhow!("apex: {e}"))?;
        // NSEC TTL: as the SOA of negative answers (RFC 9077).
        let nsec_ttl = zone.minimum.min(zone.default_ttl);
        let dnskey = wire::raw_record(apex.clone(), zone.default_ttl, T_DNSKEY, key.dnskey_rdata());

        let mut owners: BTreeMap<CanonKey, OwnerSets> = BTreeMap::new();
        // Apex: SOA, NS (explicit or synthesized), DNSKEY, then its records.
        let mut apex_sets: BTreeMap<u16, Vec<Record>> = BTreeMap::new();
        let soa = soa_record(z, zone.default_ttl).ok_or_else(|| anyhow!("SOA does not encode"))?;
        apex_sets.entry(code(&soa)).or_default().push(soa);
        for ns in apex_ns(z) {
            apex_sets.entry(code(&ns)).or_default().push(ns);
        }
        apex_sets.entry(T_DNSKEY).or_default().push(dnskey.clone());
        owners.insert(
            wire::canon_key(&apex),
            OwnerSets {
                owner: z.apex.clone(),
                name: apex.clone(),
                position: Position::Authoritative,
                rrsets: apex_sets,
            },
        );
        let mut names: Vec<&String> = z.names.keys().collect();
        names.sort();
        for owner in names {
            let pos = position(z, owner);
            if pos == Position::Occluded {
                continue;
            }
            // A name that does not parse is not served either (queries and
            // AXFR skip it), so it is left out of the signed view too.
            let Ok(name) = Name::from_ascii(owner) else {
                tracing::warn!(zone = %zone.name, owner = %owner, "DNSSEC: owner name does not parse; not signed");
                continue;
            };
            let key_ = wire::canon_key(&name);
            let entry = owners.entry(key_).or_insert_with(|| OwnerSets {
                owner: owner.clone(),
                name: name.clone(),
                position: pos,
                rrsets: BTreeMap::new(),
            });
            for r in &z.names[owner] {
                if owner == &z.apex && r.rtype == Rt::NS {
                    continue; // apex NS came from apex_ns
                }
                if pos == Position::Cut && !matches!(r.rtype, Rt::NS | Rt::DS) {
                    continue; // glue at the cut is not authoritative
                }
                if let Some(rr) = to_rr(zone, r, &name) {
                    let set = entry.rrsets.entry(code(&rr)).or_default();
                    if !set.contains(&rr) {
                        set.push(rr);
                    }
                }
            }
        }

        let inception = w.inception as u32;
        let expiration = w.expiration as u32;
        let mut sigs = HashMap::new();
        let mut signed_rrsets = 0usize;
        let mut sign = |owner: &str, name: &Name, t: u16, set: &[Record]| -> Result<Record> {
            let original_ttl = set.iter().map(|r| r.ttl).min().unwrap_or(0);
            let fields = RrsigFields {
                type_covered: t,
                algorithm: ALGORITHM,
                labels: wire::rrsig_labels(name),
                original_ttl,
                expiration,
                inception,
                key_tag: key.key_tag,
                signer: apex.clone(),
            };
            let rdatas = set
                .iter()
                .map(|r| wire::canonical_rdata(&r.data))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow!("{owner} {}: RDATA does not encode", RecordType::from(t)))?;
            let data = wire::signed_data(&fields, name, &rdatas);
            let sig = key.sign(&data)?;
            signed_rrsets += 1;
            Ok(wire::raw_record(
                name.clone(),
                original_ttl,
                T_RRSIG,
                fields.rdata(&sig),
            ))
        };

        let list: Vec<&OwnerSets> = owners.values().collect();
        let mut chain = Vec::with_capacity(list.len());
        for (i, o) in list.iter().enumerate() {
            for (t, set) in &o.rrsets {
                if o.position == Position::Cut && *t != T_DS {
                    continue; // delegation NS: not signed
                }
                sigs.insert((o.owner.clone(), *t), sign(&o.owner, &o.name, *t, set)?);
            }
            let next = &list[(i + 1) % list.len()].name;
            let mut types: Vec<u16> = o.rrsets.keys().copied().collect();
            types.push(T_NSEC);
            types.push(T_RRSIG);
            types.sort_unstable();
            types.dedup();
            let nsec = wire::raw_record(
                o.name.clone(),
                nsec_ttl,
                T_NSEC,
                wire::nsec_rdata(&next.to_lowercase(), &types),
            );
            sigs.insert(
                (o.owner.clone(), T_NSEC),
                sign(&o.owner, &o.name, T_NSEC, std::slice::from_ref(&nsec))?,
            );
            chain.push(NsecEntry {
                owner: o.owner.clone(),
                key: wire::canon_key(&o.name),
                record: nsec,
                types,
            });
        }
        let index = chain
            .iter()
            .enumerate()
            .map(|(i, e)| (e.owner.clone(), i))
            .collect();
        Ok(SignedZone {
            fingerprint,
            key_tag: key.key_tag,
            inception,
            expiration,
            dnskey,
            signed_rrsets,
            sigs,
            chain,
            index,
        })
    }

    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// The RRSIG over the RRset of type `t` at `owner` (stored owner name:
    /// the wildcard owner for a wildcard RRset).
    pub fn sig(&self, owner: &str, t: u16) -> Option<&Record> {
        self.sigs.get(&(owner.to_string(), t))
    }

    /// That RRSIG as served with an RRset named `name` with `ttl`.
    pub fn sig_as(&self, owner: &str, t: u16, name: &Name, ttl: u32) -> Option<Record> {
        let mut r = self.sig(owner, t)?.clone();
        r.name = name.clone();
        r.ttl = ttl;
        Some(r)
    }

    pub fn nsec_at(&self, owner: &str) -> Option<&NsecEntry> {
        self.index.get(owner).map(|i| &self.chain[*i])
    }

    /// The NSEC whose owner precedes `name` in canonical order and whose
    /// next name follows it (proof that `name` does not exist, or, when the
    /// next name is below `name`, that it is an empty non-terminal).
    pub fn nsec_covering(&self, name: &str) -> Option<&NsecEntry> {
        let k = wire::canon_key_str(name)?;
        let pp = self.chain.partition_point(|e| e.key < k);
        if pp < self.chain.len() && self.chain[pp].key == k {
            return None; // the name is an owner: nothing covers it
        }
        pp.checked_sub(1).map(|i| &self.chain[i])
    }

    /// An NSEC and its RRSIG.
    pub fn proof(&self, e: &NsecEntry) -> Vec<Record> {
        let mut out = vec![e.record.clone()];
        if let Some(s) = self.sig(&e.owner, T_NSEC) {
            out.push(s.clone());
        }
        out
    }

    /// Every RRSIG at `owner` (qtype RRSIG).
    pub fn sigs_at(&self, owner: &str) -> Vec<Record> {
        match self.nsec_at(owner) {
            Some(e) => e
                .types
                .iter()
                .filter_map(|t| self.sig(owner, *t).cloned())
                .collect(),
            None => vec![],
        }
    }

    /// DNSSEC records a zone transfer adds: DNSKEY, every RRSIG and NSEC.
    pub fn transfer_records(&self) -> Vec<Record> {
        let mut out = vec![self.dnskey.clone()];
        for e in &self.chain {
            out.push(e.record.clone());
            for t in &e.types {
                if let Some(s) = self.sig(&e.owner, *t) {
                    out.push(s.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Catalog;
    use crate::model::{Record as StoredRecord, Zone};

    fn zone(id: i64, name: &str) -> Zone {
        Zone {
            id,
            name: name.into(),
            serial: 7,
            soa_mname: format!("ns1.{name}."),
            soa_rname: format!("hostmaster.{name}."),
            refresh: 3600,
            retry: 600,
            expire: 1209600,
            minimum: 300,
            default_ttl: 3600,
            created_at: String::new(),
            updated_at: "2026-09-01T00:00:00.000Z".into(),
            owner_id: None,
            dnssec: true,
        }
    }

    fn rec(id: i64, name: &str, t: Rt, v: &str) -> StoredRecord {
        StoredRecord {
            id,
            zone_id: 1,
            name: name.into(),
            rtype: t,
            value: v.into(),
            ttl: None,
            created_at: String::new(),
            updated_at: String::new(),
            expires_at: None,
        }
    }

    pub(crate) fn test_key() -> (ReplDnssecKey, ZoneKey) {
        let k = super::super::generate_key().unwrap();
        let rd = wire::dnskey_rdata(257, 13, &k.public_key);
        let stored = ReplDnssecKey {
            zone_id: 1,
            zone: "example.net".into(),
            algorithm: 13,
            flags: 257,
            key_tag: wire::key_tag(&rd),
            public_key: data_encoding::BASE64.encode(&k.public_key),
            private_key: crate::replication::types::Hidden(data_encoding::BASE64.encode(&k.pkcs8)),
            created_at: "t".into(),
        };
        let zk = ZoneKey::load(&stored).unwrap();
        (stored, zk)
    }

    fn sample() -> Catalog {
        Catalog::build(
            vec![zone(1, "example.net")],
            vec![
                rec(1, "@", Rt::NS, "ns1.example.net."),
                rec(2, "ns1", Rt::A, "192.0.2.53"),
                rec(3, "*.gate", Rt::A, "192.0.2.1"),
                rec(4, "gate", Rt::A, "192.0.2.2"),
                rec(5, "a.b.c", Rt::TXT, "deep"),
                rec(6, "sub", Rt::NS, "ns.sub.example.net."),
                rec(7, "ns.sub", Rt::A, "192.0.2.54"),
                rec(
                    8,
                    "sub",
                    Rt::DS,
                    "1 13 2 0000000000000000000000000000000000000000000000000000000000000000",
                ),
                rec(9, "old", Rt::DNAME, "example.org."),
                rec(10, "x.old", Rt::A, "192.0.2.9"),
                rec(11, "sub", Rt::A, "192.0.2.99"),
            ],
        )
    }

    #[test]
    fn chain_order_positions_and_bitmaps() {
        let c = sample();
        let z = c.zones.get("example.net.").unwrap();
        let (_, key) = test_key();
        let w = Window {
            inception: 1000,
            expiration: 2000,
        };
        let s = SignedZone::build(z, &key, w, String::new()).unwrap();
        let owners: Vec<&str> = s.chain.iter().map(|e| e.owner.as_str()).collect();
        assert_eq!(
            owners,
            vec![
                "example.net.",
                "a.b.c.example.net.",
                "gate.example.net.",
                "*.gate.example.net.",
                "ns1.example.net.",
                "old.example.net.",
                "sub.example.net.",
            ],
            "ENTs (b.c, c) and occluded names (ns.sub, x.old) have no NSEC"
        );
        let apex = s.nsec_at("example.net.").unwrap();
        assert_eq!(
            apex.types,
            vec![2, 6, 46, 47, 48],
            "NS SOA RRSIG NSEC DNSKEY"
        );
        let cut = s.nsec_at("sub.example.net.").unwrap();
        assert_eq!(
            cut.types,
            vec![2, 43, 46, 47],
            "cut: NS DS RRSIG NSEC, no glue A"
        );
        assert!(
            s.sig("sub.example.net.", 2).is_none(),
            "delegation NS unsigned"
        );
        assert!(s.sig("sub.example.net.", 43).is_some(), "DS signed");
        assert!(s.sig("ns.sub.example.net.", 1).is_none(), "glue unsigned");
        assert!(
            s.sig("x.old.example.net.", 1).is_none(),
            "below DNAME occluded"
        );
        // Wildcard RRSIG: labels exclude the '*'.
        let wsig = s.sig("*.gate.example.net.", 1).unwrap();
        let (f, _) = wire::parse_rrsig(wire::raw_rdata(wsig).unwrap()).unwrap();
        assert_eq!(f.labels, 3);
        // Last NSEC wraps to the apex.
        let last = s.nsec_at("sub.example.net.").unwrap();
        let (next, _) = wire::parse_nsec(wire::raw_rdata(&last.record).unwrap()).unwrap();
        assert_eq!(next.to_ascii(), "example.net.");
        // Covering: an ENT is covered by the NSEC before it (next is below it).
        let cov = s.nsec_covering("b.c.example.net.").unwrap();
        assert_eq!(cov.owner, "example.net.");
        let cov = s.nsec_covering("zzz.example.net.").unwrap();
        assert_eq!(cov.owner, "sub.example.net.");
        let cov = s.nsec_covering("*.example.net.").unwrap();
        assert_eq!(cov.owner, "example.net.");
        let cov = s.nsec_covering("x.gate.example.net.").unwrap();
        assert_eq!(cov.owner, "*.gate.example.net.");
        assert!(s.nsec_covering("gate.example.net.").is_none());
    }

    #[test]
    fn signatures_verify_with_the_public_key() {
        let c = sample();
        let z = c.zones.get("example.net.").unwrap();
        let (_, key) = test_key();
        let w = Window {
            inception: 1000,
            expiration: 2000,
        };
        let s = SignedZone::build(z, &key, w, String::new()).unwrap();
        let mut pk = vec![4u8];
        pk.extend(&key.public_key);
        let verifier =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pk);
        // Re-derive the signed data for the apex SOA independently of `build`.
        let soa = soa_record(z, z.zone.default_ttl).unwrap();
        let sig = s.sig("example.net.", 6).unwrap();
        let (f, sigbytes) = wire::parse_rrsig(wire::raw_rdata(sig).unwrap()).unwrap();
        let data = wire::signed_data(
            &f,
            &Name::from_ascii("EXAMPLE.net.").unwrap(),
            &[wire::canonical_rdata(&soa.data).unwrap()],
        );
        verifier.verify(&data, &sigbytes).unwrap();
        assert_eq!((f.inception, f.expiration), (1000, 2000));
        assert_eq!(s.signed_rrsets, s.sigs.len());
    }
}
