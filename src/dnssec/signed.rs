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
//! O24: a zone with `nsec3` gets an NSEC3 chain instead (RFC 5155, with the
//! RFC 9276 parameters: SHA-1, no extra iterations, no salt, flags 0 (no
//! opt-out)) and an NSEC3PARAM RRset at the apex. Every name of the NSEC
//! chain has an NSEC3, and so does every empty non-terminal (RFC 5155
//! §7.1); the bitmap lists the types at the original name (RRSIG when
//! something there is signed; no NSEC3 type). The NSEC3 records live at
//! `<base32hex hash>.<apex>` and are ordered by hash.
//!
//! Every record is the wire record the catalog prepared (`cache::Rec`), the
//! same one the query path serves, so what is signed is exactly what is
//! served.
//!
//! Signatures are reused across builds, per RRset: a signature is kept
//! under the SHA-256 of the public key and of the exact octets it signs
//! (RFC 4034 §3.1.8.1: the RRSIG fields with the key tag, signer name,
//! inception and expiration, and the RRset in canonical form with its
//! owner, type and TTL). A build looks every RRset up in the previous
//! signed view of the zone and signs only what is not there, so a change
//! signs the changed RRsets, the SOA, and the NSECs whose next name or
//! type list changed. Anything that alters the signed octets (a record, a
//! TTL, the key, the window) misses the lookup and is signed afresh; an
//! entry can never be used for other octets or another key.

use super::wire::{
    self, CanonKey, RrsigFields, T_DNSKEY, T_DS, T_NSEC, T_NSEC3, T_NSEC3PARAM, T_RRSIG,
};
use super::{Window, ZoneKey};
use crate::cache::ZoneData;
use crate::model::RecordType as Rt;
use crate::replication::types::ReplDnssecKey;
use crate::zones::{apex_ns, soa_record};
use anyhow::{anyhow, Result};
use hickory_proto::rr::{Name, Record, RecordType};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// O24: the NSEC3 iterations and salt this server signs with (RFC 9276
/// §3.1: no extra iteration, no salt).
pub const NSEC3_ITERATIONS: u16 = 0;
pub const NSEC3_SALT: &[u8] = &[];

/// One link of the NSEC3 chain (O24).
pub struct Nsec3Entry {
    /// The original owner name (lower case, as in `ZoneData::names`), or
    /// an empty non-terminal.
    pub owner: String,
    hash: [u8; 20],
    /// The NSEC3 owner name, `<hash>.<apex>` (lower case).
    pub hashed: String,
    pub record: Record,
    /// Types at the original owner name (the NSEC3 bitmap).
    pub types: Vec<u16>,
}

pub struct SignedZone {
    pub fingerprint: String,
    pub key_tag: u16,
    pub inception: u32,
    pub expiration: u32,
    /// The signing key's DNSKEY.
    #[cfg_attr(not(test), allow(dead_code))]
    pub dnskey: Record,
    /// The apex DNSKEY RRset: the signing key, plus the other key of a
    /// rollover in progress (N1).
    pub dnskey_set: Vec<Record>,
    /// RRsets signed, NSEC RRsets included.
    pub signed_rrsets: usize,
    /// Of those, signatures computed by this build ...
    pub fresh_signatures: usize,
    /// ... and signatures taken from the previous build of the zone.
    pub reused_signatures: usize,
    /// Signature per digest of (public key, signed octets): what the next
    /// build reuses.
    sig_cache: HashMap<[u8; 32], Vec<u8>>,
    /// RRSIG per (owner, covered type); the owner as stored (lower case).
    sigs: HashMap<(String, u16), Record>,
    chain: Vec<NsecEntry>,
    index: HashMap<String, usize>,
    /// O24: the NSEC3 chain, by hash (empty for an NSEC zone) ...
    nsec3: Vec<Nsec3Entry>,
    /// ... and the position of each original owner name in it.
    nsec3_index: HashMap<String, usize>,
    /// The apex NSEC3PARAM record (NSEC3 zones only).
    pub nsec3param: Option<Record>,
    /// O27: the NSEC3 hash parameters (ours: RFC 9276; a transferred
    /// zone's: its NSEC3PARAM's).
    nsec3_salt: Vec<u8>,
    nsec3_iterations: u16,
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
    let mut records: Vec<&crate::model::Record> =
        z.names.values().flatten().map(|r| &**r).collect();
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
        "also_published": key.rollover.as_ref().map(|r| r.key.public_key.clone()),
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
    /// Sign `z`. `prev`: the zone's previous signed view, whose signatures
    /// are reused for RRsets that are signed over the same octets.
    #[cfg(test)]
    pub fn build(
        z: &ZoneData,
        key: &ZoneKey,
        w: Window,
        fingerprint: String,
        prev: Option<&SignedZone>,
    ) -> Result<Self> {
        Self::build_with(z, key, None, w, fingerprint, prev)
    }

    /// [`Self::build`] with another DNSKEY published next to the signing
    /// key's (`also_published`: its RDATA; a rollover, N1). The DNSKEY
    /// RRset holds both and is signed, like everything else, by `key`.
    pub fn build_with(
        z: &ZoneData,
        key: &ZoneKey,
        also_published: Option<Vec<u8>>,
        w: Window,
        fingerprint: String,
        prev: Option<&SignedZone>,
    ) -> Result<Self> {
        let zone = &z.zone;
        let apex = Name::from_ascii(&z.apex).map_err(|e| anyhow!("apex: {e}"))?;
        // NSEC TTL: as the SOA of negative answers (RFC 9077).
        let nsec_ttl = zone.minimum.min(zone.default_ttl);
        let dnskey = wire::raw_record(apex.clone(), zone.default_ttl, T_DNSKEY, key.dnskey_rdata());
        let mut dnskey_set = vec![dnskey.clone()];
        if let Some(rd) = also_published.filter(|rd| *rd != key.dnskey_rdata()) {
            dnskey_set.push(wire::raw_record(
                apex.clone(),
                zone.default_ttl,
                T_DNSKEY,
                rd,
            ));
        }

        let mut owners: BTreeMap<CanonKey, OwnerSets> = BTreeMap::new();
        // Apex: SOA, NS (explicit or synthesized), DNSKEY, then its records.
        let mut apex_sets: BTreeMap<u16, Vec<Record>> = BTreeMap::new();
        let soa = soa_record(z, zone.default_ttl).ok_or_else(|| anyhow!("SOA does not encode"))?;
        apex_sets.entry(code(&soa)).or_default().push(soa);
        for ns in apex_ns(z) {
            apex_sets.entry(code(&ns)).or_default().push(ns);
        }
        apex_sets
            .entry(T_DNSKEY)
            .or_default()
            .extend(dnskey_set.iter().cloned());
        let use_nsec3 = zone.nsec3;
        let nsec3param = use_nsec3.then(|| {
            wire::raw_record(
                apex.clone(),
                nsec_ttl,
                T_NSEC3PARAM,
                wire::nsec3param_rdata(NSEC3_ITERATIONS, NSEC3_SALT),
            )
        });
        if let Some(p) = &nsec3param {
            apex_sets.insert(T_NSEC3PARAM, vec![p.clone()]);
        }
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
                if let Some(rr) = r.rr(&name) {
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
        let (mut fresh, mut reused) = (0usize, 0usize);
        let mut sig_cache: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let key_digest = Sha256::digest(key.dnskey_rdata());
        let mut sign = |owner: &str, name: &Name, t: u16, set: &[Record]| -> Result<Record> {
            let original_ttl = set.iter().map(|r| r.ttl).min().unwrap_or(0);
            let fields = RrsigFields {
                type_covered: t,
                algorithm: key.algorithm,
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
            let mut h = Sha256::new();
            h.update(key_digest);
            h.update(&data);
            let digest: [u8; 32] = h.finalize().into();
            let sig = match prev.and_then(|p| p.sig_cache.get(&digest)) {
                Some(sig) => {
                    reused += 1;
                    sig.clone()
                }
                None => {
                    fresh += 1;
                    key.sign(&data)?
                }
            };
            sig_cache.insert(digest, sig.clone());
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
            if use_nsec3 {
                continue;
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

        // O24: the NSEC3 chain over the same names plus the empty
        // non-terminals between them and the apex.
        let mut nsec3 = Vec::new();
        if use_nsec3 {
            let mut items: Vec<(String, Name, Vec<u16>)> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for o in &list {
                let mut types: Vec<u16> = o.rrsets.keys().copied().collect();
                let signed_here = o.position != Position::Cut || o.rrsets.contains_key(&T_DS);
                if signed_here && !types.is_empty() {
                    types.push(T_RRSIG);
                }
                types.sort_unstable();
                types.dedup();
                seen.insert(o.owner.clone());
                items.push((o.owner.clone(), o.name.clone(), types));
            }
            for o in &list {
                let mut cur = o.name.clone();
                while cur.num_labels() > apex.num_labels() {
                    cur = cur.base_name();
                    let owner = cur.to_lowercase().to_ascii();
                    if seen.insert(owner.clone()) {
                        items.push((owner, cur.clone(), vec![]));
                    }
                }
            }
            let mut hashed: Vec<([u8; 20], String, Vec<u16>)> = items
                .into_iter()
                .map(|(owner, name, types)| {
                    (
                        wire::nsec3_hash(&name, NSEC3_SALT, NSEC3_ITERATIONS),
                        owner,
                        types,
                    )
                })
                .collect();
            hashed.sort_by_key(|a| a.0);
            for (i, (hash, owner, types)) in hashed.iter().enumerate() {
                let next = &hashed[(i + 1) % hashed.len()].0;
                let hname = format!("{}.{}", wire::nsec3_label(hash), z.apex);
                let hn = Name::from_ascii(&hname).map_err(|e| anyhow!("NSEC3 owner: {e}"))?;
                let rec = wire::raw_record(
                    hn.clone(),
                    nsec_ttl,
                    T_NSEC3,
                    wire::nsec3_rdata(0, NSEC3_ITERATIONS, NSEC3_SALT, next, types),
                );
                sigs.insert(
                    (hname.clone(), T_NSEC3),
                    sign(&hname, &hn, T_NSEC3, std::slice::from_ref(&rec))?,
                );
                nsec3.push(Nsec3Entry {
                    owner: owner.clone(),
                    hash: *hash,
                    hashed: hname,
                    record: rec,
                    types: types.clone(),
                });
            }
        }
        let nsec3_index = nsec3
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
            dnskey_set,
            signed_rrsets,
            fresh_signatures: fresh,
            reused_signatures: reused,
            sig_cache,
            sigs,
            chain,
            index,
            nsec3,
            nsec3_index,
            nsec3param,
            nsec3_salt: NSEC3_SALT.to_vec(),
            nsec3_iterations: NSEC3_ITERATIONS,
        })
    }

    /// O27: the signed view of a secondary zone whose primary signed it:
    /// its DNSKEY RRset, RRSIGs and NSEC or NSEC3 chain exactly as
    /// transferred (nothing is signed here). `existing`: the zone's names
    /// (owners and empty non-terminals, as `ZoneData::existing`), to map
    /// NSEC3 hashes back to names. `None`: the zone is not signed (no
    /// DNSKEY at the apex). One RRSIG is kept per RRset: for the DNSKEY
    /// RRset one made by a SEP key (flags 257, the key a DS points to),
    /// for others one made by a non-SEP key when there is one (KSK / ZSK
    /// split); with a single CSK both are the same. NSEC3 opt-out
    /// delegations have no NSEC3 and are answered without a proof.
    pub fn from_transfer<'a>(
        apex: &str,
        existing: impl IntoIterator<Item = &'a String>,
        recs: &[Record],
    ) -> Option<SignedZone> {
        let mut dnskey_set: Vec<Record> = Vec::new();
        let mut rrsigs: Vec<(String, RrsigFields, &Record)> = Vec::new();
        let mut chain: Vec<NsecEntry> = Vec::new();
        let mut nsec3_raw: Vec<(String, [u8; 20], &Record, Vec<u16>)> = Vec::new();
        let mut nsec3param: Option<(Record, u16, Vec<u8>)> = None;
        for r in recs {
            // A malformed record is skipped (it is never served then).
            let _ = (|| -> Option<()> {
                let owner = r.name.to_lowercase().to_ascii();
                let raw = wire::raw_rdata(r)?;
                match u16::from(r.record_type()) {
                    T_DNSKEY if owner == apex => dnskey_set.push(r.clone()),
                    T_RRSIG => {
                        let (f, _) = wire::parse_rrsig(raw)?;
                        rrsigs.push((owner, f, r));
                    }
                    T_NSEC => {
                        let (_, types) = wire::parse_nsec(raw)?;
                        chain.push(NsecEntry {
                            key: wire::canon_key(&r.name),
                            owner,
                            record: r.clone(),
                            types,
                        });
                    }
                    T_NSEC3 => {
                        let (_, _, _, _, _, types) = wire::parse_nsec3(raw)?;
                        let label = owner.split('.').next().unwrap_or("");
                        let h = data_encoding::BASE32HEX_NOPAD
                            .decode(label.to_ascii_uppercase().as_bytes())
                            .ok()?;
                        let hash: [u8; 20] = h.try_into().ok()?;
                        nsec3_raw.push((owner, hash, r, types));
                    }
                    T_NSEC3PARAM if owner == apex => {
                        let (iter, slen) = (
                            u16::from_be_bytes([*raw.get(2)?, *raw.get(3)?]),
                            *raw.get(4)? as usize,
                        );
                        let salt = raw.get(5..5 + slen)?.to_vec();
                        nsec3param = Some((r.clone(), iter, salt));
                    }
                    _ => {}
                }
                Some(())
            })();
        }
        if dnskey_set.is_empty() {
            return None;
        }
        // Key tags of the SEP keys (flags 257).
        let sep: Vec<u16> = dnskey_set
            .iter()
            .filter_map(|k| wire::raw_rdata(k))
            .filter(|d| d.len() > 4 && u16::from_be_bytes([d[0], d[1]]) & 1 == 1)
            .map(wire::key_tag)
            .collect();
        let mut sigs: HashMap<(String, u16), Record> = HashMap::new();
        for (owner, f, r) in rrsigs {
            let by_sep = sep.contains(&f.key_tag);
            let want_sep = f.type_covered == T_DNSKEY;
            let k = (owner, f.type_covered);
            let better = match sigs.get(&k) {
                None => true,
                Some(old) => {
                    let old_sep = wire::raw_rdata(old)
                        .and_then(wire::parse_rrsig)
                        .is_some_and(|(o, _)| sep.contains(&o.key_tag));
                    old_sep != want_sep && by_sep == want_sep
                }
            };
            if better {
                sigs.insert(k, r.clone());
            }
        }
        chain.sort_by(|a, b| a.key.cmp(&b.key));
        let index = chain
            .iter()
            .enumerate()
            .map(|(i, e)| (e.owner.clone(), i))
            .collect();
        let (param, iterations, salt) = match nsec3param {
            Some((r, i, s)) if !nsec3_raw.is_empty() => (Some(r), i, s),
            _ => (None, NSEC3_ITERATIONS, NSEC3_SALT.to_vec()),
        };
        let mut by_hash: HashMap<[u8; 20], String> = HashMap::new();
        if param.is_some() {
            for n in existing {
                if let Ok(name) = Name::from_ascii(n) {
                    by_hash.insert(wire::nsec3_hash(&name, &salt, iterations), n.clone());
                }
            }
        }
        let mut nsec3: Vec<Nsec3Entry> = nsec3_raw
            .into_iter()
            .map(|(hashed, hash, r, types)| Nsec3Entry {
                owner: by_hash.get(&hash).cloned().unwrap_or_default(),
                hash,
                hashed,
                record: r.clone(),
                types,
            })
            .collect();
        nsec3.sort_by_key(|e| e.hash);
        let nsec3_index = nsec3
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.owner.is_empty())
            .map(|(i, e)| (e.owner.clone(), i))
            .collect();
        let (inception, expiration) = sigs
            .get(&(apex.to_string(), 6))
            .and_then(|r| wire::raw_rdata(r))
            .and_then(wire::parse_rrsig)
            .map(|(f, _)| (f.inception, f.expiration))
            .unwrap_or((0, 0));
        let dnskey = dnskey_set[0].clone();
        let key_tag = wire::raw_rdata(&dnskey).map(wire::key_tag).unwrap_or(0);
        Some(SignedZone {
            fingerprint: "transferred".into(),
            key_tag,
            inception,
            expiration,
            dnskey,
            dnskey_set,
            signed_rrsets: sigs.len(),
            fresh_signatures: 0,
            reused_signatures: 0,
            sig_cache: HashMap::new(),
            sigs,
            chain: if param.is_some() { Vec::new() } else { chain },
            index: if param.is_some() {
                HashMap::new()
            } else {
                index
            },
            nsec3,
            nsec3_index,
            nsec3param: param,
            nsec3_salt: salt,
            nsec3_iterations: iterations,
        })
    }

    /// Names in the denial chain (NSEC, or NSEC3 with the empty
    /// non-terminals).
    pub fn chain_len(&self) -> usize {
        if self.uses_nsec3() {
            self.nsec3.len()
        } else {
            self.chain.len()
        }
    }

    /// O24: denial of existence with NSEC3 instead of NSEC.
    pub fn uses_nsec3(&self) -> bool {
        self.nsec3param.is_some()
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
        let types = match (self.nsec_at(owner), self.nsec3_at(owner)) {
            (Some(e), _) => &e.types,
            (None, Some(e)) => &e.types,
            (None, None) => return vec![],
        };
        types
            .iter()
            .filter_map(|t| self.sig(owner, *t).cloned())
            .collect()
    }

    /// DNSSEC records a zone transfer adds: DNSKEY, every RRSIG and NSEC.
    pub fn transfer_records(&self) -> Vec<Record> {
        let mut out = self.dnskey_set.clone();
        out.extend(self.nsec3param.iter().cloned());
        for e in &self.nsec3 {
            for t in &e.types {
                if let Some(s) = self.sig(&e.owner, *t) {
                    out.push(s.clone());
                }
            }
            out.push(e.record.clone());
            if let Some(s) = self.sig(&e.hashed, T_NSEC3) {
                out.push(s.clone());
            }
        }
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

/// Denial of existence (RFC 4035 §3.1.3, RFC 5155 §7.2): the proof
/// records (each NSEC or NSEC3 with its RRSIG, no duplicates) for each kind
/// of answer, from the NSEC or the NSEC3 chain as the zone is signed.
impl SignedZone {
    fn nsec_records(&self, entries: Vec<&NsecEntry>) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for e in entries {
            if seen.contains(&e.owner.as_str()) {
                continue;
            }
            seen.push(&e.owner);
            for r in self.proof(e) {
                if !out.contains(&r) {
                    out.push(r);
                }
            }
        }
        out
    }

    fn nsec3_records(&self, entries: Vec<&Nsec3Entry>) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for e in entries {
            if seen.contains(&e.hashed.as_str()) {
                continue;
            }
            seen.push(&e.hashed);
            out.push(e.record.clone());
            if let Some(s) = self.sig(&e.hashed, T_NSEC3) {
                out.push(s.clone());
            }
        }
        out
    }

    /// The NSEC3 of an original owner name (an existing name or an empty
    /// non-terminal).
    pub fn nsec3_at(&self, owner: &str) -> Option<&Nsec3Entry> {
        self.nsec3_index.get(owner).map(|i| &self.nsec3[*i])
    }

    /// The NSEC3 whose hash precedes the hash of `name` and whose next hash
    /// follows it (wrapping around the end of the chain): proof that no
    /// name with that hash exists. None when `name` has an NSEC3 itself.
    pub fn nsec3_covering(&self, name: &str) -> Option<&Nsec3Entry> {
        if self.nsec3.is_empty() {
            return None;
        }
        let n = Name::from_ascii(name).ok()?;
        let h = wire::nsec3_hash(&n, &self.nsec3_salt, self.nsec3_iterations);
        let pp = self.nsec3.partition_point(|e| e.hash < h);
        if pp < self.nsec3.len() && self.nsec3[pp].hash == h {
            return None;
        }
        Some(&self.nsec3[pp.checked_sub(1).unwrap_or(self.nsec3.len() - 1)])
    }

    /// The closest encloser of a name without an NSEC3 (its longest
    /// ancestor that has one) and the next closer name (the ancestor-or-
    /// self of `name` one label longer), RFC 5155 §7.2.1.
    fn nsec3_encloser(&self, name: &str) -> Option<(String, String)> {
        let mut child = name;
        loop {
            let (_, parent) = child.split_once('.')?;
            let parent = if parent.is_empty() { "." } else { parent };
            if self.nsec3_index.contains_key(parent) {
                return Some((parent.to_string(), child.to_string()));
            }
            if parent == "." {
                return None;
            }
            child = parent;
        }
    }

    fn wildcard_of(ce: &str) -> String {
        if ce == "." {
            "*.".to_string()
        } else {
            format!("*.{ce}")
        }
    }

    /// NODATA at a name that exists (or an empty non-terminal): the NSEC at
    /// it (the one whose next name is below it for an empty non-terminal
    /// with NSEC), or the matching NSEC3 (RFC 5155 §7.2.3).
    pub fn deny_nodata(&self, key: &str) -> Vec<Record> {
        if self.uses_nsec3() {
            return match self.nsec3_at(key) {
                Some(e) => self.nsec3_records(vec![e]),
                None => self.deny_nxdomain(key, ""),
            };
        }
        self.nsec_records(match self.nsec_at(key) {
            Some(e) => vec![e],
            None => self.nsec_covering(key).into_iter().collect(),
        })
    }

    /// NXDOMAIN. NSEC: the name and the wildcard at its closest encloser
    /// `ce` (as the zone data knows it) are covered. NSEC3 (RFC 5155
    /// §7.2.2): the closest encloser proof (the NSEC3 matching the closest
    /// encloser and the one covering the next closer name) and the NSEC3
    /// covering the wildcard at the closest encloser.
    pub fn deny_nxdomain(&self, key: &str, ce: &str) -> Vec<Record> {
        if self.uses_nsec3() {
            let Some((ce, next_closer)) = self.nsec3_encloser(key) else {
                return vec![];
            };
            let wc = Self::wildcard_of(&ce);
            return self.nsec3_records(
                self.nsec3_at(&ce)
                    .into_iter()
                    .chain(self.nsec3_covering(&next_closer))
                    .chain(self.nsec3_covering(&wc))
                    .collect(),
            );
        }
        let wc = Self::wildcard_of(ce);
        self.nsec_records(
            self.nsec_covering(key)
                .into_iter()
                .chain(self.nsec_covering(&wc))
                .collect(),
        )
    }

    /// An answer synthesized from the wildcard `wc`: no closer name exists.
    /// NSEC: the NSEC covering the query name. NSEC3 (RFC 5155 §7.2.6): the
    /// NSEC3 covering the next closer name (the closest encloser is the
    /// wildcard's parent).
    pub fn prove_wildcard_answer(&self, key: &str, wc: &str) -> Vec<Record> {
        if self.uses_nsec3() {
            return self.nsec3_records(
                Self::next_closer_below(key, wc)
                    .and_then(|nc| self.nsec3_covering(&nc))
                    .into_iter()
                    .collect(),
            );
        }
        self.nsec_records(self.nsec_covering(key).into_iter().collect())
    }

    /// Wildcard NODATA: no closer name, and the wildcard lacks the type.
    /// NSEC: the NSEC covering the name and the wildcard's NSEC. NSEC3
    /// (RFC 5155 §7.2.5): the closest encloser proof and the NSEC3 matching
    /// the wildcard.
    pub fn deny_wildcard_nodata(&self, key: &str, wc: &str) -> Vec<Record> {
        if self.uses_nsec3() {
            let ce = wc.strip_prefix("*.").unwrap_or(".");
            let ce = if ce.is_empty() { "." } else { ce };
            return self.nsec3_records(
                self.nsec3_at(ce)
                    .into_iter()
                    .chain(Self::next_closer_below(key, wc).and_then(|nc| self.nsec3_covering(&nc)))
                    .chain(self.nsec3_at(wc))
                    .collect(),
            );
        }
        self.nsec_records(
            self.nsec_covering(key)
                .into_iter()
                .chain(self.nsec_at(wc))
                .collect(),
        )
    }

    /// No DS at a delegation point (a referral, or a DS query at the cut):
    /// the NSEC, or the matching NSEC3 (no opt-out: every delegation has
    /// one; RFC 5155 §7.2.4 / §7.2.7), showing NS without DS.
    pub fn deny_ds(&self, deleg: &str) -> Vec<Record> {
        if self.uses_nsec3() {
            return self.nsec3_records(self.nsec3_at(deleg).into_iter().collect());
        }
        self.nsec_records(self.nsec_at(deleg).into_iter().collect())
    }

    /// The next closer name of `key` under the wildcard `wc`'s parent.
    fn next_closer_below(key: &str, wc: &str) -> Option<String> {
        let ce = wc.strip_prefix("*.")?;
        let prefix = if ce == "." || ce.is_empty() {
            key.strip_suffix('.')?
        } else {
            key.strip_suffix(ce)?.strip_suffix('.')?
        };
        let label = prefix.rsplit('.').next()?;
        Some(if ce == "." || ce.is_empty() {
            format!("{label}.")
        } else {
            format!("{label}.{ce}")
        })
    }
}

/// Test support (used by the cache, mutation and replica tests).
#[cfg(test)]
impl SignedZone {
    /// Verify every RRSIG of the zone against the RRset it covers, with the
    /// zone's DNSKEY: the signed octets are derived again from `z` (not
    /// from what `build` kept), and checked with ring. ECDSA signatures
    /// are randomised, so signatures are validated, never compared.
    /// Also checks that every authoritative RRset has a signature with
    /// this view's window and key tag. Returns the number verified.
    pub(crate) fn verify_all(&self, z: &ZoneData) -> usize {
        let key = wire::raw_rdata(&self.dnskey).expect("DNSKEY rdata");
        let (alg, pk) = (key[3], key[4..].to_vec());
        let apex = Name::from_ascii(&z.apex).unwrap();
        let mut verified = 0;
        for ((owner, t), sig) in &self.sigs {
            let name = Name::from_ascii(owner).unwrap();
            let (f, sigbytes) = wire::parse_rrsig(wire::raw_rdata(sig).unwrap()).unwrap();
            let set: Vec<Record> = if *t == T_NSEC3 {
                vec![self
                    .nsec3
                    .iter()
                    .find(|e| &e.hashed == owner)
                    .expect("NSEC3 for the RRSIG")
                    .record
                    .clone()]
            } else if *t == T_NSEC3PARAM {
                vec![self.nsec3param.clone().expect("NSEC3PARAM")]
            } else if *t == T_NSEC {
                vec![self
                    .nsec_at(owner)
                    .expect("NSEC for the RRSIG")
                    .record
                    .clone()]
            } else if *t == T_DNSKEY {
                self.dnskey_set.clone()
            } else if owner == &z.apex && *t == 6 {
                vec![soa_record(z, z.zone.default_ttl).unwrap()]
            } else if owner == &z.apex && *t == 2 {
                apex_ns(z)
            } else {
                z.names[owner]
                    .iter()
                    .filter_map(|r| r.rr(&name))
                    .filter(|rr| code(rr) == *t)
                    .collect()
            };
            assert!(!set.is_empty(), "{owner} type {t}: RRSIG without an RRset");
            assert_eq!(f.type_covered, *t);
            assert_eq!(
                (f.inception, f.expiration, f.key_tag),
                (self.inception, self.expiration, self.key_tag),
                "{owner} type {t}"
            );
            assert_eq!(f.signer, apex);
            assert_eq!(f.original_ttl, set.iter().map(|r| r.ttl).min().unwrap());
            let rdatas: Vec<Vec<u8>> = set
                .iter()
                .map(|r| wire::canonical_rdata(&r.data).unwrap())
                .collect();
            let data = wire::signed_data(&f, &name, &rdatas);
            assert_eq!(f.algorithm, alg, "{owner} type {t}");
            assert!(
                crate::dnssec::verify(alg, &pk, &data, &sigbytes),
                "{owner} type {t}: signature does not verify"
            );
            verified += 1;
        }
        // Completeness: every owner of the chain has its NSEC signed, and
        // every type in its bitmap except RRSIG (and the NS of a cut).
        for e in &self.chain {
            let cut = position(z, &e.owner) == Position::Cut;
            for t in &e.types {
                if *t == T_RRSIG || (cut && *t != T_DS && *t != T_NSEC) {
                    continue;
                }
                assert!(
                    self.sigs.contains_key(&(e.owner.clone(), *t)),
                    "{} type {t} is not signed",
                    e.owner
                );
            }
        }
        for e in &self.nsec3 {
            assert!(self.sigs.contains_key(&(e.hashed.clone(), T_NSEC3)));
            let cut = position(z, &e.owner) == Position::Cut;
            for t in &e.types {
                if *t == T_RRSIG || (cut && *t != T_DS) {
                    continue;
                }
                assert!(
                    self.sigs.contains_key(&(e.owner.clone(), *t)),
                    "{} type {t} is not signed",
                    e.owner
                );
            }
        }
        assert_eq!(verified, self.signed_rrsets);
        verified
    }

    /// The signed view without the signature bytes (they are randomised):
    /// window, key, chain and which RRsets are signed with which fields.
    pub(crate) fn describe(&self) -> serde_json::Value {
        let mut sigs: Vec<(String, u16, u8, u32)> = self
            .sigs
            .iter()
            .map(|((o, t), r)| {
                let (f, _) = wire::parse_rrsig(wire::raw_rdata(r).unwrap()).unwrap();
                (o.clone(), *t, f.labels, f.original_ttl)
            })
            .collect();
        sigs.sort();
        serde_json::json!({
            "key_tag": self.key_tag,
            "inception": self.inception,
            "expiration": self.expiration,
            "dnskey": hex::encode(wire::raw_rdata(&self.dnskey).unwrap()),
            "chain": self.chain.iter().map(|e| serde_json::json!([
                e.owner, e.types, e.record.ttl, hex::encode(wire::raw_rdata(&e.record).unwrap())
            ])).collect::<Vec<_>>(),
            "nsec3": self.nsec3.iter().map(|e| serde_json::json!([
                e.owner, e.hashed, e.types, e.record.ttl, hex::encode(wire::raw_rdata(&e.record).unwrap())
            ])).collect::<Vec<_>>(),
            "sigs": sigs,
        })
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
            signed_at: None,
            overrides: None,
            record_policy: None,
            nsec3: false,
            secondary: None,
            settings: None,
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
        test_key_for(13)
    }

    pub(crate) fn test_key_for(algorithm: u8) -> (ReplDnssecKey, ZoneKey) {
        let k = super::super::generate_key_for(algorithm).unwrap();
        let rd = wire::dnskey_rdata(257, algorithm, &k.public_key);
        let stored = ReplDnssecKey {
            zone_id: 1,
            zone: "example.net".into(),
            algorithm,
            flags: 257,
            key_tag: wire::key_tag(&rd),
            public_key: data_encoding::BASE64.encode(&k.public_key),
            private_key: crate::replication::types::Hidden(data_encoding::BASE64.encode(&k.pkcs8)),
            created_at: "t".into(),
            rollover: None,
        };
        let zk = ZoneKey::load(&stored).unwrap();
        (stored, zk)
    }

    fn sample() -> Catalog {
        sample_with(false)
    }

    fn sample_with(nsec3: bool) -> Catalog {
        Catalog::build(
            vec![Zone {
                nsec3,
                ..zone(1, "example.net")
            }],
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
        let s = SignedZone::build(z, &key, w, String::new(), None).unwrap();
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

    /// O24: the NSEC3 chain of the sample zone: every authoritative name,
    /// the empty non-terminals, no occluded name; hashes ordered and
    /// linked; bitmaps of the original names; and the records each kind of
    /// negative or wildcard answer carries (RFC 5155 §7.2), checked by
    /// hash relations, not by the code that picks them.
    #[test]
    fn nsec3_chain_and_proofs() {
        let c = sample_with(true);
        let zd = c.zones.get("example.net.").unwrap().clone();
        let (_, key) = test_key();
        let w = Window {
            inception: 1000,
            expiration: 2000,
        };
        let s = SignedZone::build(&zd, &key, w, String::new(), None).unwrap();
        assert!(s.uses_nsec3());
        assert!(s.chain.is_empty() && s.nsec_at("example.net.").is_none());
        let mut owners: Vec<&str> = s.nsec3.iter().map(|e| e.owner.as_str()).collect();
        owners.sort();
        assert_eq!(
            owners,
            vec![
                "*.gate.example.net.",
                "a.b.c.example.net.",
                "b.c.example.net.",
                "c.example.net.",
                "example.net.",
                "gate.example.net.",
                "ns1.example.net.",
                "old.example.net.",
                "sub.example.net.",
            ],
            "ENTs b.c and c have an NSEC3; ns.sub and x.old (occluded) do not"
        );
        assert_eq!(s.chain_len(), 9);
        let h = |n: &str| wire::nsec3_hash(&Name::from_ascii(n).unwrap(), &[], 0);
        for (i, e) in s.nsec3.iter().enumerate() {
            assert_eq!(e.hash, h(&e.owner));
            assert_eq!(
                e.hashed,
                format!("{}.example.net.", wire::nsec3_label(&e.hash))
            );
            let (alg, flags, it, salt, next, types) =
                wire::parse_nsec3(wire::raw_rdata(&e.record).unwrap()).unwrap();
            assert_eq!(
                (alg, flags, it, salt.len()),
                (1, 0, 0, 0),
                "RFC 9276 parameters"
            );
            assert_eq!(next, s.nsec3[(i + 1) % s.nsec3.len()].hash.to_vec());
            assert_eq!(types, e.types);
            assert_eq!(e.record.ttl, 300, "min(SOA minimum, zone TTL) as NSEC");
            if i > 0 {
                assert!(s.nsec3[i - 1].hash < e.hash, "ordered by hash");
            }
        }
        assert_eq!(
            s.nsec3_at("example.net.").unwrap().types,
            vec![2, 6, 46, 48, 51]
        );
        assert_eq!(
            s.nsec3_at("sub.example.net.").unwrap().types,
            vec![2, 43, 46]
        );
        assert!(s.nsec3_at("c.example.net.").unwrap().types.is_empty());
        assert_eq!(s.nsec3_at("gate.example.net.").unwrap().types, vec![1, 46]);
        let p = s.nsec3param.as_ref().unwrap();
        assert_eq!(wire::raw_rdata(p).unwrap(), &[1, 0, 0, 0, 0]);
        assert!(s.sig("example.net.", T_NSEC3PARAM).is_some());
        assert_eq!(s.verify_all(&zd), s.signed_rrsets);

        // Which NSEC3 matches (same hash) or covers (hash strictly between
        // owner and next, wrapping) a name.
        let rel = |recs: &[Record], name: &str| -> (bool, bool) {
            let hn = h(name);
            let mut m = false;
            let mut cv = false;
            for r in recs
                .iter()
                .filter(|r| u16::from(r.record_type()) == T_NSEC3)
            {
                let own = r.name.iter().next().unwrap().to_vec();
                let own = data_encoding::BASE32HEX_NOPAD
                    .decode(&own.to_ascii_uppercase())
                    .unwrap();
                let (_, _, _, _, next, _) = wire::parse_nsec3(wire::raw_rdata(r).unwrap()).unwrap();
                let hn = hn.to_vec();
                if own == hn {
                    m = true;
                } else if (own < next && own < hn && hn < next)
                    || (own >= next && (hn > own || hn < next))
                {
                    cv = true;
                }
            }
            (m, cv)
        };
        let n3 = |recs: &[Record]| {
            let k = recs
                .iter()
                .filter(|r| u16::from(r.record_type()) == T_NSEC3)
                .count();
            assert_eq!(recs.len(), 2 * k, "each NSEC3 with its RRSIG");
            k
        };
        // NXDOMAIN: closest encloser matched, next closer and wildcard covered.
        let p = s.deny_nxdomain("zzz.example.net.", "example.net.");
        assert!(rel(&p, "example.net.").0);
        assert!(rel(&p, "zzz.example.net.").1);
        assert!(rel(&p, "*.example.net.").1);
        assert!(n3(&p) <= 3);
        let p = s.deny_nxdomain("x.y.a.b.c.example.net.", "a.b.c.example.net.");
        assert!(rel(&p, "a.b.c.example.net.").0);
        assert!(rel(&p, "y.a.b.c.example.net.").1, "next closer");
        assert!(rel(&p, "*.a.b.c.example.net.").1);
        // NODATA at a name and at an empty non-terminal: the matching NSEC3.
        let p = s.deny_nodata("b.c.example.net.");
        assert_eq!((n3(&p), rel(&p, "b.c.example.net.").0), (1, true));
        let p = s.deny_nodata("gate.example.net.");
        assert_eq!((n3(&p), rel(&p, "gate.example.net.").0), (1, true));
        // Wildcard answer: the next closer name is covered.
        let p = s.prove_wildcard_answer("q.r.gate.example.net.", "*.gate.example.net.");
        assert_eq!((n3(&p), rel(&p, "r.gate.example.net.").1), (1, true));
        // Wildcard NODATA: closest encloser, next closer, the wildcard.
        let p = s.deny_wildcard_nodata("q.gate.example.net.", "*.gate.example.net.");
        assert!(rel(&p, "gate.example.net.").0);
        assert!(rel(&p, "q.gate.example.net.").1);
        assert!(rel(&p, "*.gate.example.net.").0);
        // No DS at a delegation: its matching NSEC3.
        let p = s.deny_ds("sub.example.net.");
        assert_eq!((n3(&p), rel(&p, "sub.example.net.").0), (1, true));
        // AXFR: NSEC3PARAM, every NSEC3 with its RRSIG, no NSEC.
        let t = s.transfer_records();
        assert!(t.iter().all(|r| u16::from(r.record_type()) != T_NSEC));
        assert_eq!(
            t.iter()
                .filter(|r| u16::from(r.record_type()) == T_NSEC3)
                .count(),
            9
        );
        assert_eq!(
            t.iter()
                .filter(|r| u16::from(r.record_type()) == T_NSEC3PARAM)
                .count(),
            1
        );
    }

    /// D2: signatures are reused per RRset; the lookup key is the public
    /// key plus the exact signed octets, so anything that changes them
    /// (record data, a TTL, the window, the key) is signed afresh.
    #[test]
    fn signatures_are_reused_only_for_identical_signed_octets() {
        let (_, key) = test_key();
        let w = Window {
            inception: 1000,
            expiration: 2000,
        };
        let records = |extra: Option<StoredRecord>| {
            let mut v = vec![
                rec(1, "@", Rt::NS, "ns1.example.net."),
                rec(2, "ns1", Rt::A, "192.0.2.53"),
                rec(3, "www", Rt::A, "192.0.2.1"),
                rec(4, "www", Rt::A, "192.0.2.2"),
                rec(5, "mail", Rt::MX, "10 mx.example.net."),
            ];
            v.extend(extra);
            v
        };
        let build = |z: Zone,
                     recs: Vec<StoredRecord>,
                     key: &ZoneKey,
                     w: Window,
                     prev: Option<&SignedZone>| {
            let c = Catalog::build(vec![z], recs);
            let zd = c.zones.get("example.net.").unwrap().clone();
            let s = SignedZone::build(&zd, key, w, String::new(), prev).unwrap();
            s.verify_all(&zd);
            s
        };
        let first = build(zone(1, "example.net"), records(None), &key, w, None);
        assert_eq!(first.reused_signatures, 0);
        // 4 owners (apex, mail, ns1, www): apex SOA NS DNSKEY, 3 RRsets, 4 NSEC.
        assert_eq!((first.fresh_signatures, first.signed_rrsets), (10, 10));
        // Nothing changed: nothing is signed.
        let same = build(zone(1, "example.net"), records(None), &key, w, Some(&first));
        assert_eq!((same.fresh_signatures, same.reused_signatures), (0, 10));
        // A serial bump (every ordinary change): only the SOA.
        let mut z2 = zone(1, "example.net");
        z2.serial += 1;
        let bumped = build(z2.clone(), records(None), &key, w, Some(&first));
        assert_eq!((bumped.fresh_signatures, bumped.reused_signatures), (1, 9));
        // A record added to an existing RRset: that RRset (and the SOA).
        let more = build(
            z2.clone(),
            records(Some(rec(6, "www", Rt::A, "192.0.2.3"))),
            &key,
            w,
            Some(&first),
        );
        assert_eq!((more.fresh_signatures, more.reused_signatures), (2, 8));
        // A new type at an existing name: the RRset and that name's NSEC.
        let typed = build(
            z2.clone(),
            records(Some(rec(6, "www", Rt::TXT, "hello"))),
            &key,
            w,
            Some(&first),
        );
        assert_eq!((typed.fresh_signatures, typed.reused_signatures), (3, 8));
        // A new name: its RRset, its NSEC, the NSEC before it (next name
        // changed), the SOA. O(1), whatever the size of the zone.
        let named = build(
            z2.clone(),
            records(Some(rec(6, "new", Rt::A, "192.0.2.9"))),
            &key,
            w,
            Some(&first),
        );
        assert_eq!((named.fresh_signatures, named.reused_signatures), (4, 8));
        // A TTL change alone re-signs the RRset (the TTL is signed).
        let mut ttl = records(None);
        ttl[4].ttl = Some(77);
        let t = build(zone(1, "example.net"), ttl, &key, w, Some(&first));
        assert_eq!((t.fresh_signatures, t.reused_signatures), (1, 9));
        // The zone's default TTL: every RRset that takes it. The 4 NSECs
        // keep theirs (min(SOA minimum, default TTL) = 300 as before).
        let mut z3 = zone(1, "example.net");
        z3.default_ttl = 1234;
        let d = build(z3, records(None), &key, w, Some(&first));
        assert_eq!((d.fresh_signatures, d.reused_signatures), (6, 4));
        // Another window: nothing is reused.
        let w2 = Window {
            inception: 1001,
            expiration: 2000,
        };
        let moved = build(
            zone(1, "example.net"),
            records(None),
            &key,
            w2,
            Some(&first),
        );
        assert_eq!((moved.fresh_signatures, moved.reused_signatures), (10, 0));
        let w3 = Window {
            inception: 1000,
            expiration: 2001,
        };
        let moved = build(
            zone(1, "example.net"),
            records(None),
            &key,
            w3,
            Some(&first),
        );
        assert_eq!(moved.reused_signatures, 0);
        // Another key: nothing is reused (also if the key tag were the same:
        // the public key is part of the lookup).
        let (_, other) = test_key();
        let rekeyed = build(
            zone(1, "example.net"),
            records(None),
            &other,
            w,
            Some(&first),
        );
        assert_eq!(
            (rekeyed.fresh_signatures, rekeyed.reused_signatures),
            (10, 0)
        );
        // Reuse is per build chain: entries no longer used are dropped.
        let back = build(zone(1, "example.net"), records(None), &key, w, Some(&more));
        assert_eq!(back.fresh_signatures, 2, "SOA (serial) and the www RRset");
        assert_eq!(back.sig_cache.len(), back.signed_rrsets);
    }

    /// O13a: a signed zone rebuilt after every change (the soak's pattern:
    /// names created, changed and deleted, the serial bumped each time)
    /// holds exactly one signature, one cache entry and one NSEC per current
    /// RRset / name: nothing from earlier builds survives in the chain.
    #[test]
    fn rebuilt_signed_zones_hold_only_the_current_rrsets() {
        let (_, key) = test_key();
        let w = Window {
            inception: 1000,
            expiration: 2000,
        };
        let mut live: std::collections::BTreeMap<String, String> = Default::default();
        let mut prev: Option<SignedZone> = None;
        let mut z = zone(1, "example.net");
        for n in 0..300u32 {
            match n % 5 {
                0 | 1 => {
                    live.insert(format!("h{n}"), format!("10.0.{}.{}", n / 250, n % 250));
                }
                2 => {
                    if let Some(k) = live.keys().next().cloned() {
                        live.insert(k, format!("10.1.{}.{}", n / 250, n % 250));
                    }
                }
                _ => {
                    if live.len() > 20 {
                        let k = live.keys().nth(n as usize % live.len()).cloned().unwrap();
                        live.remove(&k);
                    }
                }
            }
            z.serial += 1;
            let mut recs = vec![
                rec(1, "@", Rt::NS, "ns1.example.net."),
                rec(2, "ns1", Rt::A, "192.0.2.53"),
            ];
            for (i, (name, v)) in live.iter().enumerate() {
                recs.push(rec(10 + i as i64, name, Rt::A, v));
            }
            let c = Catalog::build(vec![z.clone()], recs);
            let zd = c.zones.get("example.net.").unwrap().clone();
            let s = SignedZone::build(&zd, &key, w, String::new(), prev.as_ref()).unwrap();
            // apex (SOA, NS, DNSKEY, NSEC), ns1 (A, NSEC), each name (A, NSEC).
            let rrsets = 4 + 2 + 2 * live.len();
            assert_eq!(s.signed_rrsets, rrsets, "build {n}");
            assert_eq!(s.sig_cache.len(), rrsets, "signature cache after build {n}");
            assert_eq!(s.sigs.len(), rrsets, "signatures after build {n}");
            assert_eq!(s.chain.len(), 2 + live.len(), "NSEC chain after build {n}");
            assert_eq!(s.index.len(), s.chain.len(), "chain index after build {n}");
            prev = Some(s);
        }
        let last = prev.unwrap();
        assert!(last.reused_signatures > 0, "unchanged RRsets are reused");
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
        let s = SignedZone::build(z, &key, w, String::new(), None).unwrap();
        // Re-derive the signed data for the apex SOA independently of `build`.
        let soa = soa_record(z, z.zone.default_ttl).unwrap();
        let sig = s.sig("example.net.", 6).unwrap();
        let (f, sigbytes) = wire::parse_rrsig(wire::raw_rdata(sig).unwrap()).unwrap();
        let data = wire::signed_data(
            &f,
            &Name::from_ascii("EXAMPLE.net.").unwrap(),
            &[wire::canonical_rdata(&soa.data).unwrap()],
        );
        assert!(crate::dnssec::verify(13, &key.public_key, &data, &sigbytes));
        assert_eq!((f.inception, f.expiration), (1000, 2000));
        assert_eq!(s.signed_rrsets, s.sigs.len());
    }

    /// O25: an Ed25519 (algorithm 15) zone, NSEC and NSEC3: every RRSIG
    /// verifies and carries algorithm 15, and two independent builds
    /// (another process, a standby) produce byte-identical signatures:
    /// Ed25519 is deterministic.
    #[test]
    fn ed25519_zone_signs_deterministically() {
        for nsec3 in [false, true] {
            let c = sample_with(nsec3);
            let zd = c.zones.get("example.net.").unwrap().clone();
            let (stored, key) = test_key_for(15);
            assert_eq!(key.public_key.len(), 32);
            let w = Window {
                inception: 1000,
                expiration: 2000,
            };
            let a = SignedZone::build(&zd, &key, w, String::new(), None).unwrap();
            assert_eq!(a.verify_all(&zd), a.signed_rrsets, "nsec3={nsec3}");
            let again = ZoneKey::load(&stored).unwrap();
            let b = SignedZone::build(&zd, &again, w, String::new(), None).unwrap();
            assert_eq!(a.sigs.len(), b.sigs.len());
            for (k, sig) in &a.sigs {
                let (f, _) = wire::parse_rrsig(wire::raw_rdata(sig).unwrap()).unwrap();
                assert_eq!(f.algorithm, 15);
                assert_eq!(
                    wire::raw_rdata(sig),
                    wire::raw_rdata(&b.sigs[k]),
                    "{k:?}: same key, same window, same RRSIG"
                );
            }
        }
    }
}
