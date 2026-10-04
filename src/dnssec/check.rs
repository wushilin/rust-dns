//! Verification of signed answers with a zone's public key: the console's
//! "check before adding DS" (this server's own answers, validated as a
//! resolver would) and the comparison of the parent's DS with our key.
//!
//! This is a sanity check of what is served, not a second implementation:
//! the canonical form comes from [`super::wire`]. The independent proof is
//! BIND (`dnssec-verify`, `delv`, a validating `named`) and dnspython in the
//! test suite.

use super::wire::{self, T_NSEC, T_NSEC3, T_RRSIG};
use super::KeyInfo;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

/// Same DNS name, ignoring letter case.
pub fn same_name(a: &Name, b: &Name) -> bool {
    wire::canon_key(a) == wire::canon_key(b)
}

/// A query with EDNS (4096) and DO=1; `cd` sets Checking Disabled, `rd`
/// Recursion Desired.
pub fn query_bytes(name: &Name, t: RecordType, rd: bool, cd: bool) -> Vec<u8> {
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = rd;
    m.metadata.checking_disabled = cd;
    m.add_query(Query::query(name.clone(), t));
    let mut e = Edns::new();
    e.set_max_payload(4096).set_version(0).set_dnssec_ok(true);
    m.set_edns(e);
    m.to_vec().unwrap_or_default()
}

/// Verify one RRset against one RRSIG record with `key`. `records` are the
/// RRset as received (owner as served); the owner used for the signature is
/// rebuilt from the RRSIG labels field (wildcards, RFC 4035 §5.3.2).
pub fn verify_rrset(
    records: &[&Record],
    rrsig: &Record,
    apex: &Name,
    key: &KeyInfo,
    now: u32,
) -> Result<(), String> {
    let first = records.first().ok_or("empty RRset")?;
    let raw = wire::raw_rdata(rrsig).ok_or("RRSIG is not raw data")?;
    let (f, sig) = wire::parse_rrsig(raw).ok_or("malformed RRSIG")?;
    let t = u16::from(first.record_type());
    if f.type_covered != t {
        return Err(format!("RRSIG covers type {} not {t}", f.type_covered));
    }
    if f.algorithm != key.algorithm || f.key_tag != key.key_tag {
        return Err(format!(
            "RRSIG by key {} algorithm {}, not the zone key {} algorithm {}",
            f.key_tag, f.algorithm, key.key_tag, key.algorithm
        ));
    }
    if !same_name(&f.signer, apex) {
        return Err(format!("signer {} is not the zone apex", f.signer));
    }
    if now < f.inception || now > f.expiration {
        return Err(format!(
            "outside its validity ({} .. {})",
            wire::sig_time(f.inception),
            wire::sig_time(f.expiration)
        ));
    }
    let owner_labels = wire::rrsig_labels(&first.name);
    let owner = if f.labels < owner_labels {
        // Wildcard expansion: "*." + the rightmost `labels` labels.
        let labels: Vec<&[u8]> = first.name.iter().collect();
        let keep = &labels[labels.len() - f.labels as usize..];
        let mut v: Vec<&[u8]> = vec![b"*"];
        v.extend_from_slice(keep);
        let mut n = Name::from_labels(v).map_err(|e| e.to_string())?;
        n.set_fqdn(true);
        n
    } else if f.labels == owner_labels {
        first.name.clone()
    } else {
        return Err("RRSIG labels exceed the owner's".into());
    };
    let rdatas = records
        .iter()
        .map(|r| wire::canonical_rdata(&r.data))
        .collect::<Option<Vec<_>>>()
        .ok_or("RDATA does not encode")?;
    let data = wire::signed_data(&f, &owner, &rdatas);
    if super::verify(key.algorithm, &key.public_key, &data, &sig) {
        Ok(())
    } else {
        Err("signature does not verify".to_string())
    }
}

/// Every RRset of `section` (except RRSIGs and, when `skip_ns`, an
/// unsigned delegation NS set) verified with its RRSIG. Returns the number
/// of RRsets verified, or the first problem.
fn verify_section(
    section: &[Record],
    apex: &Name,
    key: &KeyInfo,
    now: u32,
    skip_ns: bool,
) -> Result<usize, String> {
    let mut groups: Vec<(String, u16, Vec<&Record>)> = Vec::new();
    for r in section {
        let t = u16::from(r.record_type());
        if t == T_RRSIG || (skip_ns && t == 2) {
            continue;
        }
        let owner = r.name.to_ascii().to_ascii_lowercase();
        match groups.iter_mut().find(|g| g.0 == owner && g.1 == t) {
            Some(g) => g.2.push(r),
            None => groups.push((owner, t, vec![r])),
        }
    }
    for (owner, t, set) in &groups {
        let sigs: Vec<&Record> = section
            .iter()
            .filter(|r| u16::from(r.record_type()) == T_RRSIG)
            .filter(|r| r.name.to_ascii().to_ascii_lowercase() == *owner)
            .filter(|r| {
                wire::raw_rdata(r)
                    .and_then(|b| b.get(..2))
                    .is_some_and(|c| u16::from_be_bytes([c[0], c[1]]) == *t)
            })
            .collect();
        if sigs.is_empty() {
            return Err(format!("{owner} {} has no RRSIG", RecordType::from(*t)));
        }
        let mut last = String::new();
        if !sigs
            .iter()
            .any(|s| match verify_rrset(set, s, apex, key, now) {
                Ok(()) => true,
                Err(e) => {
                    last = e;
                    false
                }
            })
        {
            return Err(format!("{owner} {}: {last}", RecordType::from(*t)));
        }
    }
    Ok(groups.len())
}

/// Does the NSEC record cover `name` (owner < name < next, canonical order,
/// with the last NSEC wrapping to the apex)?
pub fn nsec_covers(nsec: &Record, name: &Name) -> bool {
    let Some((next, _)) = wire::raw_rdata(nsec).and_then(wire::parse_nsec) else {
        return false;
    };
    let o = wire::canon_key(&nsec.name);
    let n = wire::canon_key(name);
    let x = wire::canon_key(&next);
    if o < x {
        o < n && n < x
    } else {
        o < n || n < x // wraps around
    }
}

/// O24: the hash an NSEC3 record stands for (its first label) and the
/// hash of `name` with that record's parameters.
fn nsec3_hashes(nsec3: &Record, name: &Name) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (_, _, iterations, salt, next, _) = wire::parse_nsec3(wire::raw_rdata(nsec3)?)?;
    let label = nsec3.name.iter().next()?.to_ascii_uppercase();
    let owner = data_encoding::BASE32HEX_NOPAD.decode(&label).ok()?;
    let h = wire::nsec3_hash(name, &salt, iterations).to_vec();
    Some((owner, next, h))
}

/// The NSEC3 record stands for `name` (RFC 5155 §8.3).
pub fn nsec3_matches(nsec3: &Record, name: &Name) -> bool {
    nsec3_hashes(nsec3, name).is_some_and(|(o, _, h)| o == h)
}

/// The NSEC3 record covers the hash of `name` (RFC 5155 §8.3), wrapping
/// around the end of the chain.
pub fn nsec3_covers(nsec3: &Record, name: &Name) -> bool {
    let Some((o, x, h)) = nsec3_hashes(nsec3, name) else {
        return false;
    };
    if o < x {
        o < h && h < x
    } else {
        o < h || h < x
    }
}

/// RFC 5155 §8.3-8.4: a closest encloser of `qname` (an ancestor matched
/// by an NSEC3) whose next closer name is covered, and the wildcard at it
/// covered.
fn nsec3_nxdomain_proven(nsec3s: &[&Record], qname: &Name) -> bool {
    let mut child = qname.clone();
    while child.num_labels() > 0 {
        let ce = child.base_name();
        if nsec3s.iter().any(|r| nsec3_matches(r, &ce)) {
            let wildcard = Name::from_ascii("*")
                .ok()
                .and_then(|w| w.append_domain(&ce).ok());
            return nsec3s.iter().any(|r| nsec3_covers(r, &child))
                && wildcard.is_some_and(|w| nsec3s.iter().any(|r| nsec3_covers(r, &w)));
        }
        child = ce;
    }
    false
}

/// What a probe expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// An answer of the query type.
    Answer,
    /// NXDOMAIN with an NSEC covering the name.
    NxDomain,
    /// NOERROR, no answer, an NSEC for the name.
    NoData,
}

/// Validate one response as a validating resolver would, for a zone whose
/// DNSKEY is `key`. Returns a one-line summary or the problem.
pub fn validate_response(
    resp: &[u8],
    qname: &Name,
    qtype: RecordType,
    apex: &Name,
    key: &KeyInfo,
    now: u32,
    expect: Expect,
) -> Result<String, String> {
    let m = Message::from_bytes(resp).map_err(|e| format!("unparsable response: {e}"))?;
    if m.metadata.truncation {
        return Err("truncated".into());
    }
    if !m.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok) {
        return Err("the response does not echo the DO bit".into());
    }
    let rcode = m.metadata.response_code;
    match expect {
        Expect::Answer => {
            if rcode != ResponseCode::NoError {
                return Err(format!("rcode {rcode}"));
            }
            let has = m.answers.iter().any(|r| {
                r.record_type() == qtype
                    || (r.record_type() == RecordType::CNAME && qtype != RecordType::CNAME)
            });
            if !has {
                return Err(format!("no {qtype} answer"));
            }
        }
        Expect::NxDomain if rcode != ResponseCode::NXDomain => {
            return Err(format!("expected NXDOMAIN, got {rcode}"));
        }
        Expect::NoData if rcode != ResponseCode::NoError || !m.answers.is_empty() => {
            return Err(format!(
                "expected NODATA, got {rcode} with {} answers",
                m.answers.len()
            ));
        }
        _ => {}
    }
    // Only this zone's records can be checked with its key (a CNAME may
    // lead elsewhere).
    let in_zone = |r: &Record| apex.zone_of(&r.name);
    let answers: Vec<Record> = m.answers.iter().filter(|r| in_zone(r)).cloned().collect();
    let authority: Vec<Record> = m
        .authorities
        .iter()
        .filter(|r| in_zone(r))
        .cloned()
        .collect();
    let a = verify_section(&answers, apex, key, now, false)?;
    let n = verify_section(&authority, apex, key, now, !m.metadata.authoritative)?;
    let nsecs: Vec<&Record> = m
        .authorities
        .iter()
        .filter(|r| u16::from(r.record_type()) == T_NSEC)
        .collect();
    let nsec3s: Vec<&Record> = m
        .authorities
        .iter()
        .filter(|r| u16::from(r.record_type()) == T_NSEC3)
        .collect();
    match expect {
        Expect::NxDomain if !nsec3s.is_empty() => {
            if !nsec3_nxdomain_proven(&nsec3s, qname) {
                return Err("no NSEC3 closest encloser proof shows the name does not exist".into());
            }
        }
        Expect::NoData if !nsec3s.is_empty() => {
            let ok = nsec3s.iter().any(|r| {
                nsec3_matches(r, qname)
                    && wire::raw_rdata(r)
                        .and_then(wire::parse_nsec3)
                        .is_some_and(|(.., types)| !types.contains(&u16::from(qtype)))
            });
            if !ok {
                return Err(format!("no NSEC3 proves the absence of {qtype}"));
            }
        }
        Expect::NxDomain => {
            if !nsecs.iter().any(|r| nsec_covers(r, qname)) {
                return Err("no NSEC proves the name does not exist".into());
            }
        }
        Expect::NoData => {
            let ok = nsecs.iter().any(|r| {
                (same_name(&r.name, qname)
                    && wire::raw_rdata(r)
                        .and_then(wire::parse_nsec)
                        .is_some_and(|(_, types)| !types.contains(&u16::from(qtype))))
                    || nsec_covers(r, qname)
            });
            if !ok {
                return Err(format!("no NSEC proves the absence of {qtype}"));
            }
        }
        Expect::Answer => {}
    }
    Ok(format!(
        "{rcode}, {a} answer and {n} authority RRset{} verified",
        if a + n == 1 { "" } else { "s" }
    ))
}

/// The parent's DS records compared with our key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentDs {
    /// No DS at the parent (the zone is not secured by its parent).
    Absent,
    /// A DS matches our key (validating resolvers check the zone).
    Present(Vec<String>),
    /// DS records exist but none matches our key.
    Mismatch(Vec<String>),
}

/// Compare the DS records of a response (for `apex`) with `key`.
pub fn compare_parent_ds(m: &Message, apex: &Name, key: Option<&KeyInfo>) -> ParentDs {
    let ds: Vec<(u16, u8, u8, Vec<u8>)> = m
        .answers
        .iter()
        .filter(|r| u16::from(r.record_type()) == wire::T_DS && same_name(&r.name, apex))
        .filter_map(|r| wire::raw_rdata(r).and_then(wire::parse_ds))
        .collect();
    if ds.is_empty() {
        return ParentDs::Absent;
    }
    let texts: Vec<String> = ds
        .iter()
        .map(|(t, a, d, g)| wire::ds_text(*t, *a, *d, g))
        .collect();
    let matches = key.is_some_and(|k| {
        let rd = k.dnskey_rdata();
        ds.iter().any(|(tag, alg, dt, digest)| {
            *tag == k.key_tag
                && *alg == k.algorithm
                && wire::ds_digest(apex, &rd, *dt).as_deref() == Some(digest.as_slice())
        })
    });
    if matches {
        ParentDs::Present(texts)
    } else {
        ParentDs::Mismatch(texts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsec_cover_and_wrap() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let nsec = wire::raw_record(
            n("a.example."),
            300,
            T_NSEC,
            wire::nsec_rdata(&n("d.example."), &[1, 46, 47]),
        );
        assert!(nsec_covers(&nsec, &n("b.example.")));
        assert!(nsec_covers(&nsec, &n("x.a.example.")));
        assert!(!nsec_covers(&nsec, &n("a.example.")));
        assert!(!nsec_covers(&nsec, &n("d.example.")));
        assert!(!nsec_covers(&nsec, &n("e.example.")));
        let last = wire::raw_record(
            n("z.example."),
            300,
            T_NSEC,
            wire::nsec_rdata(&n("example."), &[1, 46, 47]),
        );
        assert!(nsec_covers(&last, &n("zz.example.")));
        assert!(!nsec_covers(&last, &n("b.example.")));
    }
}
