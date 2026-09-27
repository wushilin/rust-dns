//! Pure authoritative lookup logic over a [`Catalog`]. No I/O.

use crate::cache::{Catalog, ZoneData};
use crate::model::{txt_chunks, Record as StoredRecord, RecordType as Rt, Zone};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, NULL, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_proto::serialize::txt::RDataParser;

/// DNAME is not modelled by hickory 0.25; it is carried as an unknown type 39
/// whose RDATA is the uncompressed target name (RFC 6672 §2.1).
pub const DNAME_TYPE: RecordType = RecordType::Unknown(39);

fn dname_rdata(target: &Name) -> Option<RData> {
    let mut bytes = Vec::with_capacity(target.len() + 2);
    let mut enc = BinEncoder::new(&mut bytes);
    enc.set_canonical_names(true);
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
}

impl Answer {
    fn new(rcode: ResponseCode) -> Self {
        Answer {
            rcode,
            authoritative: true,
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
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

/// Convert a stored record to a wire record with the given owner.
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
    };
    Some(Record::from_rdata(owner.clone(), ttl, rdata))
}

pub fn soa_record(z: &ZoneData, ttl: u32) -> Option<Record> {
    let zone = &z.zone;
    let apex = name_of(&z.apex)?;
    let mname = name_of(&zone.soa_mname)?;
    let rname = name_of(&zone.soa_rname)?;
    Some(Record::from_rdata(
        apex,
        ttl,
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

/// NS records at the apex: explicit ones, else a single synthesized one from the SOA MNAME.
pub fn apex_ns(z: &ZoneData) -> Vec<Record> {
    let apex = match name_of(&z.apex) {
        Some(a) => a,
        None => return vec![],
    };
    let explicit: Vec<Record> = z
        .records_at(&z.apex)
        .map(|rs| {
            rs.iter()
                .filter(|r| r.rtype == Rt::NS)
                .filter_map(|r| to_rr(&z.zone, r, &apex))
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
        let target = match r.data() {
            RData::NS(ns) => &ns.0,
            RData::MX(mx) => mx.exchange(),
            RData::SRV(srv) => srv.target(),
            _ => continue,
        };
        let key = key_of(target);
        if let Some((z, recs)) = catalog.records_anywhere(&key) {
            for sr in recs.iter().filter(|x| matches!(x.rtype, Rt::A | Rt::AAAA)) {
                if let Some(rr) = to_rr(&z.zone, sr, target) {
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
/// synthesis. Returns `(records, owner_exists)`.
fn find_rrset<'a>(z: &'a ZoneData, owner: &str) -> (Option<&'a Vec<StoredRecord>>, bool) {
    if let Some(rs) = z.records_at(owner) {
        return (Some(rs), true);
    }
    if z.existing.contains(owner) {
        return (None, true); // empty non-terminal
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
            return (Some(rs), false);
        }
        if z.existing.contains(cur) {
            break; // closest encloser found and it has no wildcard child
        }
        if cur == "." {
            break;
        }
    }
    (None, false)
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
    let mut ans = Answer::new(ResponseCode::NoError);
    resolve_into(catalog, &zone, qname, &key, qtype, auto_ptr, &mut ans, 0);
    Lookup::Answer(ans)
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
) {
    let zone = &z.zone;
    let is_apex = key == z.apex;

    // Referral: name is at or below a delegation point inside this zone.
    if !is_apex {
        if let Some(deleg) = z.delegation_for(key) {
            // A query for the NS set exactly at the cut is still a referral (not authoritative).
            let owner = match name_of(deleg) {
                Some(o) => o,
                None => return,
            };
            let ns: Vec<Record> = z
                .records_at(deleg)
                .map(|rs| {
                    rs.iter()
                        .filter(|r| r.rtype == Rt::NS)
                        .filter_map(|r| to_rr(zone, r, &owner))
                        .collect()
                })
                .unwrap_or_default();
            ans.authoritative = false;
            ans.authority.extend(ns.iter().cloned());
            add_glue(catalog, &ns, &mut ans.additional);
            return;
        }
    }

    // DNAME (RFC 6672): a DNAME at an ancestor redirects the whole subtree.
    if let Some((owner, target)) = find_dname(z, key) {
        if let (Some(owner_n), Some(target_n)) = (name_of(&owner), name_of(&target)) {
            if let Some(dr) = z
                .records_at(&owner)
                .and_then(|rs| rs.iter().find(|r| r.rtype == Rt::DNAME))
                .and_then(|r| to_rr(zone, r, &owner_n))
            {
                ans.answers.push(dr);
            }
            // Substitute the suffix: qname = <prefix>.<owner> -> <prefix>.<target>
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
                        );
                        ans.answers.extend(sub.answers);
                        ans.additional.extend(sub.additional);
                    }
                }
            }
            let _ = target_n;
            return;
        }
    }

    let (rrset, exists) = find_rrset(z, key);

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

    let mut matched = !ans.answers.is_empty();
    let mut cname_target: Option<Name> = None;

    if let Some(rs) = rrset {
        // If a CNAME lives here and the query is not for CNAME/ANY, follow it.
        if let Some(c) = rs.iter().find(|r| r.rtype == Rt::CNAME) {
            if qtype != RecordType::CNAME && qtype != RecordType::ANY {
                if let Some(rr) = to_rr(zone, c, qname) {
                    if let RData::CNAME(t) = rr.data() {
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
                if let Some(rr) = to_rr(zone, r, qname) {
                    if !ans.answers.contains(&rr) {
                        ans.answers.push(rr);
                    }
                    matched = true;
                }
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
                );
                ans.answers.extend(sub.answers);
                ans.additional.extend(sub.additional);
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

    // Nothing found: try auto PTR before going negative.
    if auto_ptr && (qtype == RecordType::PTR || qtype == RecordType::ANY) {
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
    if let Some(soa) = soa_record(z, zone.minimum.min(zone.default_ttl)) {
        ans.authority.push(soa);
    }
}

/// BIND-style zone file text for export.
pub fn to_zone_file(z: &ZoneData) -> String {
    use std::fmt::Write;
    let zone = &z.zone;
    let mut s = String::new();
    let _ = writeln!(s, "$ORIGIN {}", z.apex);
    let _ = writeln!(s, "$TTL {}", zone.default_ttl);
    let _ = writeln!(
        s,
        "@\t{}\tIN\tSOA\t{} {} {} {} {} {} {}",
        zone.default_ttl,
        zone.soa_mname,
        zone.soa_rname,
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum
    );
    let has_ns = z
        .records_at(&z.apex)
        .map(|rs| rs.iter().any(|r| r.rtype == Rt::NS))
        .unwrap_or(false);
    if !has_ns {
        let _ = writeln!(s, "@\t{}\tIN\tNS\t{}", zone.default_ttl, zone.soa_mname);
    }
    let mut owners: Vec<&String> = z.names.keys().collect();
    owners.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
    for owner in owners {
        let mut recs: Vec<&StoredRecord> = z.names[owner].iter().collect();
        recs.sort_by_key(|r| (r.rtype, r.value.clone()));
        for r in recs {
            let ttl = r.ttl.unwrap_or(zone.default_ttl);
            let value = match r.rtype {
                Rt::TXT => txt_chunks(&r.value)
                    .iter()
                    .map(|c| format!("\"{}\"", c.replace('\\', "\\\\").replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(" "),
                _ => r.value.clone(),
            };
            let _ = writeln!(s, "{}\t{}\tIN\t{}\t{}", r.name, ttl, r.rtype, value);
        }
    }
    s
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
            a.answers[0].name().to_ascii(),
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
        assert!(matches!(a.answers[0].data(), RData::CNAME(_)));
        assert!(matches!(a.answers[1].data(), RData::A(_)));
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
        assert_eq!(a.answers[0].name().to_ascii(), "foo.apps.example.com.");
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
            a.answers[0].data().to_string(),
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
        assert!(matches!(a.answers[0].data(), RData::CAA(_)));
        let a = q("example.com.", RecordType::HTTPS);
        assert_eq!(a.answers.len(), 1);
        // DNAME at old.example.com -> www.example.com: host.old.example.com resolves to host.www.example.com (NXDOMAIN target here)
        let a = q("old.example.com.", DNAME_TYPE);
        assert_eq!(a.answers.len(), 1, "DNAME itself is answered at its owner");
        let a = q("a.old.example.com.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(
            matches!(a.answers[0].data(), RData::Unknown { code, .. } if *code == DNAME_TYPE),
            "DNAME first"
        );
        assert!(
            matches!(a.answers[1].data(), RData::CNAME(c) if c.0.to_ascii() == "a.www.example.com."),
            "synthesized CNAME"
        );
    }

    #[test]
    fn zone_file() {
        let c = catalog();
        let text = to_zone_file(&c.zones["example.com."]);
        assert!(text.contains("$ORIGIN example.com."));
        assert!(text.contains("IN\tSOA"));
        assert!(text.contains("a.b\t60\tIN\tTXT\t\"hello\""));
    }
}
