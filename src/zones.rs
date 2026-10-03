//! Pure authoritative lookup logic over a [`Catalog`]. No I/O.

use crate::cache::{Catalog, ZoneData};
use crate::model::{txt_chunks, Record as StoredRecord, RecordType as Rt, Zone};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, NULL, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use crate::dnssec::signed::NsecEntry;
use crate::dnssec::wire;
use crate::dnssec::SignedZone;

/// DNAME is not modelled by hickory; it is carried as an unknown type 39
/// whose RDATA is the uncompressed target name (RFC 6672 §2.1).
pub const DNAME_TYPE: RecordType = RecordType::Unknown(39);

fn dname_rdata(target: &Name) -> Option<RData> {
    let mut bytes = Vec::with_capacity(target.len() + 2);
    let mut enc = BinEncoder::new(&mut bytes);
    enc.set_canonical_form(true);
    target.emit(&mut enc).ok()?;
    Some(RData::Unknown {
        code: DNAME_TYPE,
        rdata: NULL::with(bytes),
    })
}
use std::sync::Arc;

const MAX_CNAME_HOPS: usize = 8;

#[derive(Debug)]
pub struct Answer {
    pub rcode: ResponseCode,
    pub authoritative: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    /// NSEC proofs a positive answer needs (wildcard expansion), collected
    /// through CNAME/DNAME chains and moved into `authority` by `lookup`.
    proofs: Vec<Record>,
}

impl Answer {
    fn new(rcode: ResponseCode) -> Self {
        Answer {
            rcode,
            authoritative: true,
            answers: vec![],
            authority: vec![],
            additional: vec![],
            proofs: vec![],
        }
    }

    /// RFC 8482 for a signed zone: keep only the first RRset of the answer
    /// and its RRSIG (a real, validatable RRset rather than a synthesized
    /// HINFO), drop the additional section.
    pub fn keep_first_rrset(&mut self) {
        let Some(first) = self.answers.first() else {
            return;
        };
        let owner = key_of(&first.name);
        let t = u16::from(first.record_type());
        self.answers.retain(|r| {
            key_of(&r.name) == owner
                && match u16::from(r.record_type()) {
                    wire::T_RRSIG => wire::raw_rdata(r)
                        .and_then(|b| b.get(..2))
                        .is_some_and(|c| u16::from_be_bytes([c[0], c[1]]) == t),
                    x => x == t,
                }
        });
        self.additional.clear();
    }
}

pub enum Lookup {
    /// We are authoritative for this name (possibly negative).
    Answer(Answer),
    /// No zone matches and no auto-PTR hit: caller may forward or refuse.
    NotOurs,
}

fn name_of(s: &str) -> Option<Name> {
    Name::from_ascii(s).ok()
}

/// Convert a stored record to a wire record with the given owner. Text is
/// parsed here: the catalog does it once per record when it is built
/// ([`crate::cache::Rec`]); the query path uses the prepared record.
pub fn to_rr(zone: &Zone, r: &StoredRecord, owner: &Name) -> Option<Record> {
    let ttl = r.ttl.unwrap_or(zone.default_ttl);
    let rdata = match r.rtype {
        Rt::A => RData::A(A(r.value.parse().ok()?)),
        Rt::AAAA => RData::AAAA(AAAA(r.value.parse().ok()?)),
        Rt::CNAME => RData::CNAME(CNAME(name_of(&r.value)?)),
        Rt::PTR => RData::PTR(PTR(name_of(&r.value)?)),
        Rt::NS => RData::NS(NS(name_of(&r.value)?)),
        Rt::MX => {
            let (p, h) = r.value.split_once(' ')?;
            RData::MX(MX::new(p.parse().ok()?, name_of(h)?))
        }
        Rt::SRV => {
            let parts: Vec<&str> = r.value.split(' ').collect();
            if parts.len() != 4 {
                return None;
            }
            RData::SRV(SRV::new(
                parts[0].parse().ok()?,
                parts[1].parse().ok()?,
                parts[2].parse().ok()?,
                name_of(parts[3])?,
            ))
        }
        Rt::TXT => RData::TXT(TXT::new(txt_chunks(&r.value))),
        Rt::DNAME => dname_rdata(&name_of(&r.value)?)?,
        Rt::CAA | Rt::HTTPS | Rt::SVCB | Rt::TLSA | Rt::SSHFP | Rt::NAPTR | Rt::HINFO => {
            RData::try_from_str(r.rtype.to_hickory(), &r.value).ok()?
        }
        Rt::DS => {
            let (tag, alg, dt, digest) = wire::parse_ds_text(&r.value).ok()?;
            return Some(wire::raw_record(
                owner.clone(),
                ttl,
                wire::T_DS,
                wire::ds_rdata(tag, alg, dt, &digest),
            ));
        }
    };
    Some(Record::from_rdata(owner.clone(), ttl, rdata))
}

/// The zone's SOA record with TTL `ttl` (prepared when the catalog is built).
pub fn soa_record(z: &ZoneData, ttl: u32) -> Option<Record> {
    let mut r = z.soa.clone()?;
    r.ttl = ttl;
    Some(r)
}

/// Build the SOA record (TTL = the zone default) for the catalog.
pub fn build_soa(z: &ZoneData) -> Option<Record> {
    let zone = &z.zone;
    let apex = name_of(&z.apex)?;
    let mname = name_of(&zone.soa_mname)?;
    let rname = name_of(&zone.soa_rname)?;
    Some(Record::from_rdata(
        apex,
        zone.default_ttl,
        RData::SOA(SOA::new(
            mname,
            rname,
            zone.serial,
            zone.refresh as i32,
            zone.retry as i32,
            zone.expire as i32,
            zone.minimum,
        )),
    ))
}

/// NS records at the apex: explicit ones, else a single synthesized one
/// from the SOA MNAME (prepared when the catalog is built).
pub fn apex_ns(z: &ZoneData) -> Vec<Record> {
    z.apex_ns.clone()
}

/// Build the apex NS RRset for the catalog.
pub fn build_apex_ns(z: &ZoneData) -> Vec<Record> {
    let apex = match name_of(&z.apex) {
        Some(a) => a,
        None => return vec![],
    };
    let explicit: Vec<Record> = z
        .records_at(&z.apex)
        .map(|rs| {
            rs.iter()
                .filter(|r| r.rtype == Rt::NS)
                .filter_map(|r| r.rr(&apex))
                .collect()
        })
        .unwrap_or_default();
    if !explicit.is_empty() {
        return explicit;
    }
    match name_of(&z.zone.soa_mname) {
        Some(m) => vec![Record::from_rdata(
            apex,
            z.zone.default_ttl,
            RData::NS(NS(m)),
        )],
        None => vec![],
    }
}

/// Glue: A/AAAA for names referenced by NS/MX/SRV answers when we hold them.
fn add_glue(catalog: &Catalog, records: &[Record], out: &mut Vec<Record>) {
    for r in records {
        let target = match &r.data {
            RData::NS(ns) => &ns.0,
            RData::MX(mx) => &mx.exchange,
            RData::SRV(srv) => &srv.target,
            _ => continue,
        };
        let key = key_of(target);
        if let Some((_, recs)) = catalog.records_anywhere(&key) {
            for sr in recs.iter().filter(|x| matches!(x.rtype, Rt::A | Rt::AAAA)) {
                if let Some(rr) = sr.rr(target) {
                    if !out.iter().any(|o| o == &rr) {
                        out.push(rr);
                    }
                }
            }
        }
    }
}

/// Lower-case fqdn string key for a wire name.
pub fn key_of(n: &Name) -> String {
    let mut s = n.to_ascii().to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn wants(qtype: RecordType, rt: Rt) -> bool {
    qtype == RecordType::ANY || rt.to_hickory() == qtype
}

/// Find the record set at `owner` in zone `z`, falling back to wildcard
/// synthesis. Returns `(records, owner_exists, wildcard owner if synthesized)`.
fn find_rrset<'a>(
    z: &'a ZoneData,
    owner: &str,
) -> (Option<&'a Vec<crate::cache::Rec>>, bool, Option<String>) {
    if let Some(rs) = z.records_at(owner) {
        return (Some(rs), true, None);
    }
    if z.existing.contains(owner) {
        return (None, true, None); // empty non-terminal
    }
    // Wildcard (RFC 4592): walk up to the closest encloser, the first ancestor
    // that exists in the zone, and only a `*` directly beneath it may match.
    let mut cur = owner;
    while cur != z.apex {
        cur = match cur.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => rest,
            _ => break,
        };
        let wc = if cur == "." {
            "*.".to_string()
        } else {
            format!("*.{cur}")
        };
        if let Some(rs) = z.records_at(&wc) {
            return (Some(rs), false, Some(wc));
        }
        if z.existing.contains(cur) {
            break; // closest encloser found and it has no wildcard child
        }
        if cur == "." {
            break;
        }
    }
    (None, false, None)
}

/// Find a DNAME at a strict ancestor of `key` (below or at the apex). Returns (owner, target).
fn find_dname(z: &ZoneData, key: &str) -> Option<(String, String)> {
    let mut cur = key;
    loop {
        cur = match cur.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => rest,
            _ => return None,
        };
        if let Some(rs) = z.records_at(cur) {
            if let Some(d) = rs.iter().find(|r| r.rtype == Rt::DNAME) {
                return Some((cur.to_string(), d.value.clone()));
            }
        }
        if cur == z.apex {
            return None;
        }
    }
}

pub fn lookup(catalog: &Catalog, qname: &Name, qtype: RecordType, auto_ptr: bool) -> Lookup {
    lookup_dnssec(catalog, qname, qtype, auto_ptr, false)
}

/// [`lookup`] for a query with the DO bit: in a signed zone the answer
/// carries RRSIGs and NSEC proofs (RFC 4035 §3.1). Without DO the answer is
/// the same as for an unsigned zone.
pub fn lookup_dnssec(
    catalog: &Catalog,
    qname: &Name,
    qtype: RecordType,
    auto_ptr: bool,
    dnssec_ok: bool,
) -> Lookup {
    let key = key_of(qname);
    let zone = match catalog.find_zone(&key) {
        Some(z) => z.clone(),
        None => {
            if auto_ptr && (qtype == RecordType::PTR || qtype == RecordType::ANY) {
                if let Some(a) = auto_ptr_answer(catalog, qname, &key) {
                    return Lookup::Answer(a);
                }
            }
            return Lookup::NotOurs;
        }
    };
    let zone = ds_parent_side(catalog, &zone, &key, qtype).unwrap_or(zone);
    let mut ans = Answer::new(ResponseCode::NoError);
    resolve_into(
        catalog, &zone, qname, &key, qtype, auto_ptr, &mut ans, 0, dnssec_ok,
    );
    for r in std::mem::take(&mut ans.proofs) {
        if !ans.authority.contains(&r) {
            ans.authority.push(r);
        }
    }
    Lookup::Answer(ans)
}

/// RFC 4035 §3.1.4.1: a DS query for the apex of a zone whose parent zone
/// is also here is answered from the parent (DS is parent-side data), when
/// the parent is signed or holds DS records for it.
fn ds_parent_side(
    catalog: &Catalog,
    z: &Arc<ZoneData>,
    key: &str,
    qtype: RecordType,
) -> Option<Arc<ZoneData>> {
    if qtype != RecordType::DS || key != z.apex || key == "." {
        return None;
    }
    let parent = match key.split_once('.') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => ".",
    };
    let p = catalog.find_zone(parent)?;
    if p.cut_for(key) != Some(key) {
        return None;
    }
    let has_ds = p
        .records_at(key)
        .is_some_and(|rs| rs.iter().any(|r| r.rtype == Rt::DS));
    (p.signed.is_some() || has_ds).then(|| p.clone())
}

fn auto_ptr_answer(catalog: &Catalog, qname: &Name, key: &str) -> Option<Answer> {
    let targets = catalog.reverse.get(key)?;
    let mut ans = Answer::new(ResponseCode::NoError);
    for t in targets {
        if let Some(n) = name_of(t) {
            let ttl = catalog
                .find_zone(t)
                .map(|z| z.zone.default_ttl)
                .unwrap_or(300);
            ans.answers
                .push(Record::from_rdata(qname.clone(), ttl, RData::PTR(PTR(n))));
        }
    }
    Some(ans)
}

/// Append the RRSIG of every RRset in `section[from..]` (records owned by
/// one name, signed under `owner`: the wildcard owner for a synthesized
/// answer). The RRSIG carries the name and the TTL the RRset is served with.
fn sign_section(sec: &SignedZone, section: &mut Vec<Record>, from: usize, owner: &str) {
    let mut types: Vec<RecordType> = Vec::new();
    let mut sigs = Vec::new();
    for r in &section[from..] {
        let t = r.record_type();
        if types.contains(&t) {
            continue;
        }
        types.push(t);
        let ttl = section[from..]
            .iter()
            .filter(|x| x.record_type() == t)
            .map(|x| x.ttl)
            .min()
            .unwrap_or(r.ttl);
        if let Some(s) = sec.sig_as(owner, u16::from(t), &r.name, ttl) {
            sigs.push(s);
        }
    }
    section.extend(sigs);
}

/// The closest encloser of a name that does not exist: its longest
/// existing ancestor (RFC 5155 terminology; RFC 4592 §3.3.1).
fn closest_encloser(z: &ZoneData, key: &str) -> String {
    let mut cur = key;
    while cur != z.apex {
        cur = match cur.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => rest,
            _ => return z.apex.clone(),
        };
        if z.existing.contains(cur) {
            return cur.to_string();
        }
    }
    z.apex.clone()
}

fn push_proofs(sec: &SignedZone, entries: Vec<&NsecEntry>, out: &mut Vec<Record>) {
    let mut seen: Vec<&str> = Vec::new();
    for e in entries {
        if seen.contains(&e.owner.as_str()) {
            continue;
        }
        seen.push(&e.owner);
        for r in sec.proof(e) {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_into(
    catalog: &Catalog,
    z: &Arc<ZoneData>,
    qname: &Name,
    key: &str,
    qtype: RecordType,
    auto_ptr: bool,
    ans: &mut Answer,
    depth: usize,
    dnssec_ok: bool,
) {
    let zone = &z.zone;
    let is_apex = key == z.apex;
    let signed = z.signed.as_deref();
    // RRSIGs and NSEC proofs only for a DO query to a signed zone.
    let sec = if dnssec_ok { signed } else { None };

    // Referral: name is at or below a delegation point inside this zone.
    if !is_apex {
        let cut = if signed.is_some() {
            z.cut_for(key)
        } else {
            z.delegation_for(key)
        };
        if let Some(deleg) = cut {
            // A query for the NS set exactly at the cut is still a referral (not authoritative).
            let owner = match name_of(deleg) {
                Some(o) => o,
                None => return,
            };
            let ds_at = |n: &Name| -> Vec<Record> {
                z.records_at(deleg)
                    .map(|rs| {
                        rs.iter()
                            .filter(|r| r.rtype == Rt::DS)
                            .filter_map(|r| r.rr(n))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let ds = ds_at(&owner);
            // RFC 4035 §3.1.4.1: DS at the cut is parent-side data, answered
            // authoritatively (only for a signed zone or when DS records
            // exist; otherwise the referral as before).
            if qtype == RecordType::DS && key == deleg && (signed.is_some() || !ds.is_empty()) {
                if ds.is_empty() {
                    if depth == 0 {
                        ans.rcode = ResponseCode::NoError;
                    }
                    negative_soa(z, sec, ans);
                    if let Some(sec) = sec {
                        let proof: Vec<&NsecEntry> = sec.nsec_at(deleg).into_iter().collect();
                        push_proofs(sec, proof, &mut ans.authority);
                    }
                } else {
                    let from = ans.answers.len();
                    ans.answers.extend(ds_at(qname));
                    if let Some(sec) = sec {
                        sign_section(sec, &mut ans.answers, from, deleg);
                    }
                }
                return;
            }
            let ns: Vec<Record> = z
                .records_at(deleg)
                .map(|rs| {
                    rs.iter()
                        .filter(|r| r.rtype == Rt::NS)
                        .filter_map(|r| r.rr(&owner))
                        .collect()
                })
                .unwrap_or_default();
            ans.authoritative = false;
            ans.authority.extend(ns.iter().cloned());
            add_glue(catalog, &ns, &mut ans.additional);
            // RFC 4035 §3.1.4: the DS RRset (signed) or an NSEC proving there is none.
            if let Some(sec) = sec {
                if ds.is_empty() {
                    let proof: Vec<&NsecEntry> = sec.nsec_at(deleg).into_iter().collect();
                    push_proofs(sec, proof, &mut ans.authority);
                } else {
                    let from = ans.authority.len();
                    ans.authority.extend(ds);
                    sign_section(sec, &mut ans.authority, from, deleg);
                }
            }
            return;
        }
    }

    // DNAME (RFC 6672): a DNAME at an ancestor redirects the whole subtree.
    if let Some((owner, target)) = find_dname(z, key) {
        if let (Some(owner_n), Some(target_n)) = (name_of(&owner), name_of(&target)) {
            if let Some(dr) = z
                .records_at(&owner)
                .and_then(|rs| rs.iter().find(|r| r.rtype == Rt::DNAME))
                .and_then(|r| r.rr(&owner_n))
            {
                let from = ans.answers.len();
                ans.answers.push(dr);
                if let Some(sec) = sec {
                    sign_section(sec, &mut ans.answers, from, &owner);
                }
            }
            // Substitute the suffix: qname = <prefix>.<owner> -> <prefix>.<target>
            // The synthesized CNAME is not signed (RFC 6672 §5.3.1).
            let prefix = &key[..key.len() - owner.len()];
            let new_key = format!("{prefix}{target}");
            if let Some(new_name) = name_of(&new_key) {
                let cname = Record::from_rdata(
                    qname.clone(),
                    zone.default_ttl,
                    RData::CNAME(CNAME(new_name.clone())),
                );
                ans.answers.push(cname);
                if qtype != RecordType::CNAME && depth < MAX_CNAME_HOPS {
                    if let Some(tz) = catalog.find_zone(&new_key) {
                        let tz = tz.clone();
                        let mut sub = Answer::new(ResponseCode::NoError);
                        resolve_into(
                            catalog,
                            &tz,
                            &new_name,
                            &new_key,
                            qtype,
                            auto_ptr,
                            &mut sub,
                            depth + 1,
                            dnssec_ok,
                        );
                        ans.answers.extend(sub.answers);
                        ans.additional.extend(sub.additional);
                        ans.proofs.extend(sub.proofs);
                    }
                }
            }
            let _ = target_n;
            return;
        }
    }

    let (rrset, exists, wildcard) = find_rrset(z, key);
    // The owner the served RRsets are signed under.
    let sig_owner: &str = wildcard.as_deref().unwrap_or(key);
    let start = ans.answers.len();

    // Synthesised apex records.
    if is_apex && (qtype == RecordType::SOA || qtype == RecordType::ANY) {
        if let Some(soa) = soa_record(z, zone.default_ttl) {
            ans.answers.push(soa);
        }
    }
    if is_apex && (qtype == RecordType::NS || qtype == RecordType::ANY) {
        let ns = apex_ns(z);
        add_glue(catalog, &ns, &mut ans.additional);
        for r in ns {
            if !ans.answers.contains(&r) {
                ans.answers.push(r);
            }
        }
    }
    // A signed zone also holds DNSKEY at the apex and NSEC / RRSIG at each
    // name of its chain.
    if let Some(s) = signed {
        if is_apex && (qtype == RecordType::DNSKEY || qtype == RecordType::ANY) {
            let mut r = s.dnskey.clone();
            r.name = qname.clone();
            ans.answers.push(r);
        }
        if wildcard.is_none() && qtype == RecordType::NSEC {
            if let Some(e) = s.nsec_at(key) {
                let mut r = e.record.clone();
                r.name = qname.clone();
                ans.answers.push(r);
            }
        }
        if wildcard.is_none() && qtype == RecordType::RRSIG {
            for mut r in s.sigs_at(key) {
                r.name = qname.clone();
                ans.answers.push(r);
            }
        }
    }

    let mut matched = ans.answers.len() > start;
    let mut cname_target: Option<Name> = None;

    if let Some(rs) = rrset {
        // If a CNAME lives here and the query is not for CNAME/ANY, follow it.
        if let Some(c) = rs.iter().find(|r| r.rtype == Rt::CNAME) {
            if qtype != RecordType::CNAME && qtype != RecordType::ANY {
                if let Some(rr) = c.rr(qname) {
                    if let RData::CNAME(t) = &rr.data {
                        cname_target = Some(t.0.clone());
                    }
                    ans.answers.push(rr);
                    matched = true;
                }
            }
        }
        if cname_target.is_none() {
            for r in rs.iter().filter(|r| wants(qtype, r.rtype)) {
                // NS at the apex is already handled above (explicit or synthesized).
                if is_apex && r.rtype == Rt::NS {
                    continue;
                }
                if let Some(rr) = r.rr(qname) {
                    if !ans.answers.contains(&rr) {
                        ans.answers.push(rr);
                    }
                    matched = true;
                }
            }
        }
    }

    if let Some(sec) = sec {
        if matched {
            if qtype != RecordType::RRSIG {
                sign_section(sec, &mut ans.answers, start, sig_owner);
            }
            // RFC 4035 §3.1.3.3: a wildcard answer proves that no closer
            // name (the next closer name) exists.
            if wildcard.is_some() {
                let proof: Vec<&NsecEntry> = sec.nsec_covering(key).into_iter().collect();
                push_proofs(sec, proof, &mut ans.proofs);
            }
        }
    }

    if let Some(target) = cname_target {
        if depth < MAX_CNAME_HOPS {
            let tkey = key_of(&target);
            if let Some(tz) = catalog.find_zone(&tkey) {
                let tz = tz.clone();
                let mut sub = Answer::new(ResponseCode::NoError);
                resolve_into(
                    catalog,
                    &tz,
                    &target,
                    &tkey,
                    qtype,
                    auto_ptr,
                    &mut sub,
                    depth + 1,
                    dnssec_ok,
                );
                ans.answers.extend(sub.answers);
                ans.additional.extend(sub.additional);
                ans.proofs.extend(sub.proofs);
                // rcode from the chase is not propagated (RFC 6604): NOERROR with the CNAME.
            }
        }
        add_glue(catalog, &ans.answers.clone(), &mut ans.additional);
        return;
    }

    if matched {
        add_glue(catalog, &ans.answers.clone(), &mut ans.additional);
        return;
    }

    // Nothing found: try auto PTR before going negative. Not in a signed
    // zone: a synthesized PTR could not be signed (and would contradict
    // the zone's NSEC chain).
    if auto_ptr && signed.is_none() && (qtype == RecordType::PTR || qtype == RecordType::ANY) {
        if let Some(a) = auto_ptr_answer(catalog, qname, key) {
            ans.answers.extend(a.answers);
            return;
        }
    }

    // Negative answer with SOA in authority (RFC 2308): NODATA if the name exists, else NXDOMAIN.
    if depth == 0 {
        ans.rcode = if exists || rrset.is_some() {
            ResponseCode::NoError
        } else {
            ResponseCode::NXDomain
        };
    }
    negative_soa(z, sec, ans);
    if let Some(sec) = sec {
        // RFC 4035 §3.1.3.
        let proofs: Vec<&NsecEntry> = if exists {
            // NODATA: the NSEC at the name shows the type is absent; an empty
            // non-terminal is proven by the NSEC whose next name is below it.
            match sec.nsec_at(key) {
                Some(e) => vec![e],
                None => sec.nsec_covering(key).into_iter().collect(),
            }
        } else if let Some(wc) = &wildcard {
            // Wildcard NODATA: no closer match, and the wildcard lacks the type.
            sec.nsec_covering(key)
                .into_iter()
                .chain(sec.nsec_at(wc))
                .collect()
        } else {
            // NXDOMAIN: the name does not exist, nor the wildcard at its
            // closest encloser.
            let ce = closest_encloser(z, key);
            let wc = if ce == "." {
                "*.".to_string()
            } else {
                format!("*.{ce}")
            };
            sec.nsec_covering(key)
                .into_iter()
                .chain(sec.nsec_covering(&wc))
                .collect()
        };
        push_proofs(sec, proofs, &mut ans.authority);
    }
}

/// The SOA of a negative answer (TTL min(SOA minimum, zone TTL), RFC 2308 /
/// RFC 9077) and, for a DO query to a signed zone, its RRSIG.
fn negative_soa(z: &ZoneData, sec: Option<&SignedZone>, ans: &mut Answer) {
    let ttl = z.zone.minimum.min(z.zone.default_ttl);
    if let Some(soa) = soa_record(z, ttl) {
        let name = soa.name.clone();
        ans.authority.push(soa);
        if let Some(s) = sec.and_then(|sec| sec.sig_as(&z.apex, 6, &name, ttl)) {
            ans.authority.push(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RecordType as Rt;

    fn zone(id: i64, name: &str) -> Zone {
        Zone {
            id,
            name: name.into(),
            serial: 2024010101,
            soa_mname: format!("ns1.{name}."),
            soa_rname: format!("hostmaster.{name}."),
            refresh: 3600,
            retry: 600,
            expire: 1209600,
            minimum: 300,
            default_ttl: 60,
            created_at: String::new(),
            updated_at: String::new(),
            owner_id: None,
            dnssec: false,
            signed_at: None,
        }
    }
    fn rec(id: i64, zone_id: i64, name: &str, t: Rt, v: &str) -> StoredRecord {
        StoredRecord {
            id,
            zone_id,
            name: name.into(),
            rtype: t,
            value: v.into(),
            ttl: None,
            created_at: String::new(),
            updated_at: String::new(),
            expires_at: None,
        }
    }
    fn catalog() -> Catalog {
        Catalog::build(
            vec![zone(1, "example.com"), zone(2, "0.0.10.in-addr.arpa")],
            vec![
                rec(1, 1, "@", Rt::NS, "ns1.example.com."),
                rec(2, 1, "ns1", Rt::A, "10.0.0.53"),
                rec(3, 1, "www", Rt::A, "10.0.0.1"),
                rec(4, 1, "www", Rt::AAAA, "2001:db8::1"),
                rec(5, 1, "alias", Rt::CNAME, "www.example.com."),
                rec(6, 1, "ext", Rt::CNAME, "www.other.org."),
                rec(7, 1, "*.apps", Rt::A, "10.0.0.9"),
                rec(8, 1, "@", Rt::MX, "10 mail.example.com."),
                rec(9, 1, "mail", Rt::A, "10.0.0.25"),
                rec(10, 1, "sub", Rt::NS, "ns.sub.example.com."),
                rec(11, 1, "ns.sub", Rt::A, "10.0.0.54"),
                rec(12, 2, "25", Rt::PTR, "mail.example.com."),
                rec(13, 1, "a.b", Rt::TXT, "hello"),
                rec(14, 1, "x.apps", Rt::A, "10.0.0.10"),
                rec(15, 1, "old", Rt::DNAME, "www.example.com."),
                rec(16, 1, "@", Rt::CAA, "0 issue \"letsencrypt.org\""),
                rec(17, 1, "@", Rt::HTTPS, "1 . alpn=h2,h3"),
            ],
        )
    }
    fn q(name: &str, t: RecordType) -> Answer {
        match lookup(&catalog(), &Name::from_ascii(name).unwrap(), t, true) {
            Lookup::Answer(a) => a,
            Lookup::NotOurs => panic!("expected an answer for {name}"),
        }
    }

    #[test]
    fn positive() {
        let a = q("WWW.example.com.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert_eq!(a.answers.len(), 1);
        assert!(a.authoritative);
        assert_eq!(
            a.answers[0].name.to_ascii(),
            "WWW.example.com.",
            "case preserved"
        );
    }

    #[test]
    fn nodata_and_nxdomain() {
        let a = q("www.example.com.", RecordType::MX);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.answers.is_empty());
        assert_eq!(a.authority.len(), 1, "SOA in authority");
        let a = q("nope.example.com.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NXDomain);
        assert_eq!(a.authority.len(), 1);
        let a = q("b.example.com.", RecordType::A);
        assert_eq!(
            a.rcode,
            ResponseCode::NoError,
            "empty non-terminal is NODATA"
        );
    }

    #[test]
    fn cname_chase() {
        let a = q("alias.example.com.", RecordType::A);
        assert_eq!(a.answers.len(), 2);
        assert!(matches!(&a.answers[0].data, RData::CNAME(_)));
        assert!(matches!(&a.answers[1].data, RData::A(_)));
        let a = q("alias.example.com.", RecordType::CNAME);
        assert_eq!(a.answers.len(), 1);
        let a = q("ext.example.com.", RecordType::A);
        assert_eq!(
            a.answers.len(),
            1,
            "external CNAME target left to the resolver"
        );
        assert_eq!(a.rcode, ResponseCode::NoError);
    }

    #[test]
    fn wildcard() {
        let a = q("foo.apps.example.com.", RecordType::A);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].name.to_ascii(), "foo.apps.example.com.");
        let a = q("foo.apps.example.com.", RecordType::AAAA);
        assert_eq!(a.rcode, ResponseCode::NoError, "wildcard NODATA");
        let a = q("apps.example.com.", RecordType::A);
        assert_eq!(
            a.rcode,
            ResponseCode::NoError,
            "wildcard parent exists as ENT"
        );
        let a = q("x.apps.example.com.", RecordType::A);
        assert_eq!(
            &a.answers[0].data.to_string(),
            "10.0.0.10",
            "explicit name beats wildcard"
        );
        let a = q("y.x.apps.example.com.", RecordType::A);
        assert_eq!(
            a.rcode,
            ResponseCode::NXDomain,
            "RFC 4592: wildcard does not match below an existing closer name"
        );
        let a = q("deep.er.name.apps.example.com.", RecordType::A);
        assert_eq!(
            a.answers.len(),
            1,
            "wildcard matches multiple labels when no closer name exists"
        );
    }

    #[test]
    fn apex_soa_ns_mx_glue() {
        let a = q("example.com.", RecordType::SOA);
        assert_eq!(a.answers.len(), 1);
        let a = q("example.com.", RecordType::NS);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.additional.len(), 1, "glue for ns1");
        let a = q("example.com.", RecordType::MX);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.additional.len(), 1, "glue for mail");
        let a = q("example.com.", RecordType::ANY);
        assert!(a.answers.len() >= 3);
    }

    #[test]
    fn referral() {
        let a = q("host.sub.example.com.", RecordType::A);
        assert!(!a.authoritative);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.answers.is_empty());
        assert_eq!(a.authority.len(), 1);
        assert_eq!(a.additional.len(), 1, "glue for ns.sub");
    }

    #[test]
    fn ptr_explicit_and_auto() {
        let a = q("25.0.0.10.in-addr.arpa.", RecordType::PTR);
        assert_eq!(a.answers.len(), 1);
        let a = q("1.0.0.10.in-addr.arpa.", RecordType::PTR);
        assert_eq!(a.answers.len(), 1, "auto PTR inside our reverse zone");
        match lookup(
            &catalog(),
            &Name::from_ascii(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            )
            .unwrap(),
            RecordType::PTR,
            true,
        ) {
            Lookup::Answer(a) => assert_eq!(a.answers.len(), 1, "auto PTR without a reverse zone"),
            Lookup::NotOurs => panic!(),
        }
        assert!(matches!(
            lookup(
                &catalog(),
                &Name::from_ascii("example.org.").unwrap(),
                RecordType::A,
                true
            ),
            Lookup::NotOurs
        ));
    }

    #[test]
    fn dname_and_new_types() {
        let a = q("example.com.", RecordType::CAA);
        assert_eq!(a.answers.len(), 1);
        assert!(matches!(&a.answers[0].data, RData::CAA(_)));
        let a = q("example.com.", RecordType::HTTPS);
        assert_eq!(a.answers.len(), 1);
        // DNAME at old.example.com -> www.example.com: host.old.example.com resolves to host.www.example.com (NXDOMAIN target here)
        let a = q("old.example.com.", DNAME_TYPE);
        assert_eq!(a.answers.len(), 1, "DNAME itself is answered at its owner");
        let a = q("a.old.example.com.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(
            matches!(&a.answers[0].data, RData::Unknown { code, .. } if *code == DNAME_TYPE),
            "DNAME first"
        );
        assert!(
            matches!(&a.answers[1].data, RData::CNAME(c) if c.0.to_ascii() == "a.www.example.com."),
            "synthesized CNAME"
        );
    }
}
