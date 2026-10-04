//! DNSSEC wire formats (RFC 4034) implemented by hand: canonical names and
//! RDATA, canonical RRset ordering, the data an RRSIG signs, and the RDATA of
//! RRSIG, NSEC, DNSKEY and DS records.
//!
//! hickory-proto is used without its DNSSEC features (they would pull in a
//! second crypto stack), so these types travel as `RData::Unknown`, exactly
//! like DNAME does elsewhere in this server.

use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use sha2::Digest;

pub const T_DNAME: u16 = 39;
pub const T_DS: u16 = 43;
pub const T_RRSIG: u16 = 46;
pub const T_NSEC: u16 = 47;
pub const T_DNSKEY: u16 = 48;
pub const T_NSEC3: u16 = 50;
pub const T_NSEC3PARAM: u16 = 51;
pub const CLASS_IN: u16 = 1;

/// Lower-case, uncompressed wire form of a name (RFC 4034 §6.2).
pub fn name_wire(n: &Name) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.len() + 2);
    for l in n.iter() {
        out.push(l.len() as u8);
        out.extend(l.iter().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

/// Parse an uncompressed wire name starting at `pos`; returns the name and
/// the position after it.
pub fn read_name(b: &[u8], mut pos: usize) -> Option<(Name, usize)> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    loop {
        let len = *b.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointers are not allowed here
        }
        labels.push(b.get(pos..pos + len)?.to_vec());
        pos += len;
    }
    let mut n = Name::from_labels(labels).ok()?;
    n.set_fqdn(true);
    Some((n, pos))
}

/// The RRSIG Labels field: labels of the owner, not counting the root or a
/// leading `*` (RFC 4034 §3.1.3).
pub fn rrsig_labels(n: &Name) -> u8 {
    let mut count = n.iter().count();
    if n.iter().next() == Some(b"*".as_slice()) {
        count -= 1;
    }
    count as u8
}

/// Sort key giving the canonical DNS name order (RFC 4034 §6.1): labels
/// compared from the right, each as lower-cased octets, a name sorting
/// before its descendants.
pub type CanonKey = Vec<Vec<u8>>;

pub fn canon_key(n: &Name) -> CanonKey {
    let mut v: Vec<Vec<u8>> = n.iter().map(|l| l.to_ascii_lowercase()).collect();
    v.reverse();
    v
}

pub fn canon_key_str(s: &str) -> Option<CanonKey> {
    Name::from_ascii(s).ok().map(|n| canon_key(&n))
}

/// Canonical RDATA of a record as this server serves it (RFC 4034 §6.2):
/// no name compression; names lower-cased for the types listed there
/// (hickory's canonical encoder applies the per-type rules; DNAME, carried
/// as an unknown type, is lower-cased here).
pub fn canonical_rdata(r: &RData) -> Option<Vec<u8>> {
    match r {
        RData::Unknown { code, rdata } if u16::from(*code) == T_DNAME => {
            let (n, end) = read_name(&rdata.anything, 0)?;
            (end == rdata.anything.len()).then(|| name_wire(&n))
        }
        RData::Unknown { rdata, .. } => Some(rdata.anything.clone()),
        _ => {
            let mut buf = Vec::new();
            let mut enc = BinEncoder::new(&mut buf);
            enc.set_canonical_form(true);
            r.emit(&mut enc).ok()?;
            Some(buf)
        }
    }
}

/// A record with raw RDATA of a type hickory handles as unknown here.
pub fn raw_record(name: Name, ttl: u32, code: u16, rdata: Vec<u8>) -> Record {
    Record::from_rdata(
        name,
        ttl,
        RData::Unknown {
            code: RecordType::from(code),
            rdata: NULL::with(rdata),
        },
    )
}

/// Raw RDATA of a record carried as an unknown type (`None` otherwise).
pub fn raw_rdata(r: &Record) -> Option<&[u8]> {
    match &r.data {
        RData::Unknown { rdata, .. } => Some(&rdata.anything),
        _ => None,
    }
}

/// The fixed fields of an RRSIG (everything before the signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigFields {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: Name,
}

impl RrsigFields {
    /// RDATA up to (not including) the signature, signer in canonical form.
    pub fn prefix(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(18 + self.signer.len() + 2);
        d.extend(self.type_covered.to_be_bytes());
        d.push(self.algorithm);
        d.push(self.labels);
        d.extend(self.original_ttl.to_be_bytes());
        d.extend(self.expiration.to_be_bytes());
        d.extend(self.inception.to_be_bytes());
        d.extend(self.key_tag.to_be_bytes());
        d.extend(name_wire(&self.signer));
        d
    }

    pub fn rdata(&self, signature: &[u8]) -> Vec<u8> {
        let mut d = self.prefix();
        d.extend_from_slice(signature);
        d
    }
}

/// Split RRSIG RDATA into its fields and the signature.
pub fn parse_rrsig(b: &[u8]) -> Option<(RrsigFields, Vec<u8>)> {
    if b.len() < 19 {
        return None;
    }
    let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let (signer, end) = read_name(b, 18)?;
    Some((
        RrsigFields {
            type_covered: u16_at(0),
            algorithm: b[2],
            labels: b[3],
            original_ttl: u32_at(4),
            expiration: u32_at(8),
            inception: u32_at(12),
            key_tag: u16_at(16),
            signer,
        },
        b[end..].to_vec(),
    ))
}

/// The octets an RRSIG signs (RFC 4034 §3.1.8.1): the RRSIG RDATA without
/// the signature, then every RR of the set in canonical form and order
/// (duplicates removed), each with the original TTL. `owner` is the owner
/// as signed (the wildcard name for a wildcard RRset).
pub fn signed_data(fields: &RrsigFields, owner: &Name, rdatas: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted: Vec<&Vec<u8>> = rdatas.iter().collect();
    sorted.sort();
    sorted.dedup();
    let owner = name_wire(owner);
    let mut d = fields.prefix();
    for rd in sorted {
        d.extend_from_slice(&owner);
        d.extend(fields.type_covered.to_be_bytes());
        d.extend(CLASS_IN.to_be_bytes());
        d.extend(fields.original_ttl.to_be_bytes());
        d.extend((rd.len() as u16).to_be_bytes());
        d.extend_from_slice(rd);
    }
    d
}

/// Type bit maps field of an NSEC record (RFC 4034 §4.1.2).
pub fn type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut sorted: Vec<u16> = types.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let window = (sorted[i] >> 8) as u8;
        let mut bits = [0u8; 32];
        let mut len = 0usize;
        while i < sorted.len() && (sorted[i] >> 8) as u8 == window {
            let low = (sorted[i] & 0xff) as usize;
            bits[low / 8] |= 0x80 >> (low % 8);
            len = len.max(low / 8 + 1);
            i += 1;
        }
        out.push(window);
        out.push(len as u8);
        out.extend_from_slice(&bits[..len]);
    }
    out
}

pub fn parse_bitmap(mut b: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let window = *b.first()? as u16;
        let len = *b.get(1)? as usize;
        if len == 0 || len > 32 {
            return None;
        }
        let bits = b.get(2..2 + len)?;
        for (i, byte) in bits.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    out.push((window << 8) | (i * 8 + bit) as u16);
                }
            }
        }
        b = &b[2 + len..];
    }
    Some(out)
}

pub fn nsec_rdata(next: &Name, types: &[u16]) -> Vec<u8> {
    let mut d = name_wire(next);
    d.extend(type_bitmap(types));
    d
}

pub fn parse_nsec(b: &[u8]) -> Option<(Name, Vec<u16>)> {
    let (next, end) = read_name(b, 0)?;
    Some((next, parse_bitmap(&b[end..])?))
}

/// NSEC3 hash algorithm 1 (SHA-1), the only one defined (RFC 5155 §11).
pub const NSEC3_SHA1: u8 = 1;

/// The NSEC3 hash of an owner name (RFC 5155 §5): SHA-1 over the
/// canonical (lower-case) wire name and the salt, then `iterations` more
/// times over the previous digest and the salt.
pub fn nsec3_hash(owner: &Name, salt: &[u8], iterations: u16) -> [u8; 20] {
    let mut h = sha1::Sha1::new();
    h.update(name_wire(owner));
    h.update(salt);
    let mut d: [u8; 20] = h.finalize().into();
    for _ in 0..iterations {
        let mut h = sha1::Sha1::new();
        h.update(d);
        h.update(salt);
        d = h.finalize().into();
    }
    d
}

/// The owner label of an NSEC3 record: the hash in lower-case Base32hex
/// without padding (RFC 5155 §3.3, RFC 4648 §7).
pub fn nsec3_label(hash: &[u8]) -> String {
    data_encoding::BASE32HEX_NOPAD
        .encode(hash)
        .to_ascii_lowercase()
}

/// NSEC3 RDATA (RFC 5155 §3.2): hash algorithm, flags, iterations, salt,
/// next hashed owner name (raw hash), type bit maps.
pub fn nsec3_rdata(flags: u8, iterations: u16, salt: &[u8], next: &[u8], types: &[u16]) -> Vec<u8> {
    let mut d = vec![NSEC3_SHA1, flags];
    d.extend(iterations.to_be_bytes());
    d.push(salt.len() as u8);
    d.extend_from_slice(salt);
    d.push(next.len() as u8);
    d.extend_from_slice(next);
    d.extend(type_bitmap(types));
    d
}

/// The fields of an NSEC3 RDATA: (hash algorithm, flags, iterations,
/// salt, next hashed owner, types).
pub type Nsec3Fields = (u8, u8, u16, Vec<u8>, Vec<u8>, Vec<u16>);

pub fn parse_nsec3(b: &[u8]) -> Option<Nsec3Fields> {
    let (alg, flags) = (*b.first()?, *b.get(1)?);
    let iterations = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
    let slen = *b.get(4)? as usize;
    let salt = b.get(5..5 + slen)?.to_vec();
    let hlen = *b.get(5 + slen)? as usize;
    let next = b.get(6 + slen..6 + slen + hlen)?.to_vec();
    let types = parse_bitmap(&b[6 + slen + hlen..])?;
    Some((alg, flags, iterations, salt, next, types))
}

/// NSEC3PARAM RDATA (RFC 5155 §4.2): hash algorithm, flags (0), iterations,
/// salt.
pub fn nsec3param_rdata(iterations: u16, salt: &[u8]) -> Vec<u8> {
    let mut d = vec![NSEC3_SHA1, 0];
    d.extend(iterations.to_be_bytes());
    d.push(salt.len() as u8);
    d.extend_from_slice(salt);
    d
}

fn salt_text(salt: &[u8]) -> String {
    if salt.is_empty() {
        "-".into()
    } else {
        hex::encode_upper(salt)
    }
}

pub fn dnskey_rdata(flags: u16, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(4 + public_key.len());
    d.extend(flags.to_be_bytes());
    d.push(3); // protocol
    d.push(algorithm);
    d.extend_from_slice(public_key);
    d
}

/// Key tag of a DNSKEY RDATA (RFC 4034 Appendix B; not for algorithm 1).
pub fn key_tag(dnskey: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, b) in dnskey.iter().enumerate() {
        ac += if i & 1 == 1 {
            *b as u32
        } else {
            (*b as u32) << 8
        };
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

/// DS digest over the owner and DNSKEY RDATA (RFC 4034 §5.1.4; digest
/// types 1 SHA-1, 2 SHA-256, 4 SHA-384).
pub fn ds_digest(owner: &Name, dnskey: &[u8], digest_type: u8) -> Option<Vec<u8>> {
    let mut data = name_wire(owner);
    data.extend_from_slice(dnskey);
    Some(match digest_type {
        1 => {
            use sha1::Digest as _;
            sha1::Sha1::digest(&data).to_vec()
        }
        2 => sha2::Sha256::digest(&data).to_vec(),
        4 => sha2::Sha384::digest(&data).to_vec(),
        _ => return None,
    })
}

pub fn ds_rdata(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(4 + digest.len());
    d.extend(key_tag.to_be_bytes());
    d.push(algorithm);
    d.push(digest_type);
    d.extend_from_slice(digest);
    d
}

/// A DS RDATA: (key tag, algorithm, digest type, digest).
pub fn parse_ds(b: &[u8]) -> Option<(u16, u8, u8, Vec<u8>)> {
    if b.len() < 5 {
        return None;
    }
    Some((
        u16::from_be_bytes([b[0], b[1]]),
        b[2],
        b[3],
        b[4..].to_vec(),
    ))
}

/// Parse the presentation form `<key tag> <algorithm> <digest type> <hex>`
/// (hex may contain spaces). Only digest types 1, 2 and 4 with their exact
/// digest lengths are accepted.
pub fn parse_ds_text(s: &str) -> Result<(u16, u8, u8, Vec<u8>), String> {
    let mut parts = s.split_whitespace();
    let usage = "DS value must be '<key tag> <algorithm> <digest type> <digest hex>', e.g. 12345 13 2 <64 hex digits>";
    let tag: u16 = parts.next().and_then(|p| p.parse().ok()).ok_or(usage)?;
    let alg: u8 = parts.next().and_then(|p| p.parse().ok()).ok_or(usage)?;
    let dt: u8 = parts.next().and_then(|p| p.parse().ok()).ok_or(usage)?;
    let hex_digits: String = parts.collect::<Vec<_>>().join("");
    if hex_digits.is_empty() {
        return Err(usage.into());
    }
    let digest =
        hex::decode(&hex_digits).map_err(|_| "DS digest must be hexadecimal".to_string())?;
    let want = match dt {
        1 => 20,
        2 => 32,
        4 => 48,
        _ => {
            return Err(format!(
                "DS digest type {dt} is not supported (use 2 = SHA-256, 4 = SHA-384 or 1 = SHA-1)"
            ))
        }
    };
    if digest.len() != want {
        return Err(format!(
            "a digest of type {dt} is {want} bytes ({} hex digits), got {}",
            want * 2,
            digest.len()
        ));
    }
    if alg == 0 {
        return Err("DS algorithm must not be 0".into());
    }
    Ok((tag, alg, dt, digest))
}

/// Presentation form of a DS RDATA (hex upper-case, as BIND prints it).
pub fn ds_text(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> String {
    format!(
        "{key_tag} {algorithm} {digest_type} {}",
        hex::encode_upper(digest)
    )
}

fn type_name(t: u16) -> String {
    match t {
        T_DNAME => "DNAME".into(),
        _ => RecordType::from(t).to_string(),
    }
}

/// UTC `YYYYMMDDHHmmSS` as in RRSIG presentation form.
pub fn sig_time(t: u32) -> String {
    chrono::DateTime::from_timestamp(t as i64, 0)
        .map(|d| d.format("%Y%m%d%H%M%S").to_string())
        .unwrap_or_else(|| t.to_string())
}

/// Presentation form of the DNSSEC types carried as unknown RDATA (query
/// log, live feed, self-check details); `None` for other types.
pub fn display_rdata(code: u16, b: &[u8]) -> Option<String> {
    match code {
        T_RRSIG => {
            let (f, sig) = parse_rrsig(b)?;
            Some(format!(
                "{} {} {} {} {} {} {} {} {}",
                type_name(f.type_covered),
                f.algorithm,
                f.labels,
                f.original_ttl,
                sig_time(f.expiration),
                sig_time(f.inception),
                f.key_tag,
                f.signer,
                data_encoding::BASE64.encode(&sig)
            ))
        }
        T_NSEC => {
            let (next, types) = parse_nsec(b)?;
            let names: Vec<String> = types.iter().map(|t| type_name(*t)).collect();
            Some(format!("{next} {}", names.join(" ")))
        }
        T_NSEC3 => {
            let (alg, flags, it, salt, next, types) = parse_nsec3(b)?;
            let names: Vec<String> = types.iter().map(|t| type_name(*t)).collect();
            Some(
                format!(
                    "{alg} {flags} {it} {} {} {}",
                    salt_text(&salt),
                    data_encoding::BASE32HEX_NOPAD.encode(&next),
                    names.join(" ")
                )
                .trim_end()
                .to_string(),
            )
        }
        T_NSEC3PARAM if b.len() >= 5 => {
            let salt = b.get(5..5 + b[4] as usize)?;
            Some(format!(
                "{} {} {} {}",
                b[0],
                b[1],
                u16::from_be_bytes([b[2], b[3]]),
                salt_text(salt)
            ))
        }
        T_DNSKEY if b.len() > 4 => Some(format!(
            "{} {} {} {}",
            u16::from_be_bytes([b[0], b[1]]),
            b[2],
            b[3],
            data_encoding::BASE64.encode(&b[4..])
        )),
        T_DS => {
            let (tag, alg, dt, digest) = parse_ds(b)?;
            Some(ds_text(tag, alg, dt, &digest))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    /// O24: RFC 5155 Appendix A (salt aabbccdd, 12 extra iterations), the
    /// same values BIND's `nsec3hash` prints, and the RFC 9276 parameters
    /// (no salt, no extra iteration) for example.net. (`nsec3hash - 1 0
    /// example.net.`).
    #[test]
    fn nsec3_hashes_match_rfc5155_and_bind() {
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (name, want) in [
            ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi"),
            ("NS1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
            ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
            ("x.y.w.example.", "2vptu5timamqttgl4luu9kg21e0aor3s"),
            ("xx.example.", "t644ebqk9bibcna874givr6joj62mlhv"),
        ] {
            let h = nsec3_hash(&Name::from_ascii(name).unwrap(), &salt, 12);
            assert_eq!(nsec3_label(&h), want, "{name}");
        }
        let h = nsec3_hash(&Name::from_ascii("example.net.").unwrap(), &[], 0);
        assert_eq!(nsec3_label(&h), "93j57bnunnk7b6rcofljbhj4mkp5bpjh");
        // RDATA round trip and presentation form.
        let rd = nsec3_rdata(0, 0, &[], &h, &[1, 16, 46]);
        let (alg, flags, it, s, next, types) = parse_nsec3(&rd).unwrap();
        assert_eq!((alg, flags, it, s.len()), (1, 0, 0, 0));
        assert_eq!((next.as_slice(), types), (&h[..], vec![1, 16, 46]));
        assert_eq!(
            display_rdata(T_NSEC3, &rd).unwrap(),
            "1 0 0 - 93J57BNUNNK7B6RCOFLJBHJ4MKP5BPJH A TXT RRSIG"
        );
        // An empty non-terminal's NSEC3 has no types.
        let ent = nsec3_rdata(0, 0, &[], &h, &[]);
        assert_eq!(ent.len(), 6 + 20);
        assert_eq!(
            display_rdata(T_NSEC3, &ent).unwrap(),
            "1 0 0 - 93J57BNUNNK7B6RCOFLJBHJ4MKP5BPJH"
        );
        assert_eq!(nsec3param_rdata(0, &[]), vec![1, 0, 0, 0, 0]);
        assert_eq!(
            display_rdata(T_NSEC3PARAM, &nsec3param_rdata(0, &[])).unwrap(),
            "1 0 0 -"
        );
    }
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// A name from raw labels (any octets), fully qualified.
    fn raw(labels: &[&[u8]]) -> Name {
        let mut n = Name::from_labels(labels.iter().copied()).unwrap();
        n.set_fqdn(true);
        n
    }

    #[test]
    fn canonical_order_rfc4034_example() {
        // RFC 4034 §6.1 lists these names in canonical order.
        let ordered = [
            raw(&[b"example"]),
            raw(&[b"a", b"example"]),
            raw(&[b"yljkjljk", b"a", b"example"]),
            raw(&[b"Z", b"a", b"example"]),
            raw(&[b"zABC", b"a", b"EXAMPLE"]),
            raw(&[b"z", b"example"]),
            raw(&[&[1u8], b"z", b"example"]),
            raw(&[b"*", b"z", b"example"]),
            raw(&[&[200u8], b"z", b"example"]),
        ];
        let keys: Vec<CanonKey> = ordered.iter().map(canon_key).collect();
        for w in keys.windows(2) {
            assert!(w[0] < w[1], "{:?} < {:?}", w[0], w[1]);
        }
    }

    #[test]
    fn wildcard_sorts_first_among_siblings() {
        let apex = raw(&[b"wushilin", b"net"]);
        let ap = raw(&[b"ap-southeast-1", b"wushilin", b"net"]);
        let wc = raw(&[b"*", b"ap-southeast-1", b"wushilin", b"net"]);
        let dash = raw(&[b"-x", b"ap-southeast-1", b"wushilin", b"net"]);
        let zero = raw(&[b"0", b"ap-southeast-1", b"wushilin", b"net"]);
        let a = raw(&[b"a", b"ap-southeast-1", b"wushilin", b"net"]);
        let dmarc = raw(&[b"_dmarc", b"wushilin", b"net"]);
        let mut v = vec![
            a.clone(),
            dmarc.clone(),
            zero.clone(),
            wc.clone(),
            apex.clone(),
            dash.clone(),
            ap.clone(),
        ];
        v.sort_by_key(canon_key);
        // '_' (0x5f) sorts before 'a'; '*' (0x2a) before '-' (0x2d) and digits.
        assert_eq!(v, vec![apex, dmarc, ap, wc, dash, zero, a]);
    }

    #[test]
    fn labels_field() {
        assert_eq!(rrsig_labels(&n("www.example.com.")), 3);
        assert_eq!(rrsig_labels(&n("*.gate.example.com.")), 3);
        assert_eq!(rrsig_labels(&n("example.com.")), 2);
        assert_eq!(rrsig_labels(&Name::root()), 0);
    }

    #[test]
    fn bitmap_round_trip_and_rfc_example() {
        // RFC 4034 §4.3: A MX RRSIG NSEC TYPE1234.
        let bm = type_bitmap(&[1, 15, 46, 47, 1234]);
        assert_eq!(
            hex::encode(&bm),
            "0006400100000003041b000000000000000000000000000000000000000000000000000020"
        );
        assert_eq!(parse_bitmap(&bm).unwrap(), vec![1, 15, 46, 47, 1234]);
    }

    #[test]
    fn key_tag_and_ds_rfc_example() {
        // RFC 4034 §5.4: dskey.example.com. DNSKEY 256 3 5 ..., key id 60485,
        // and its SHA-1 DS.
        let pk = data_encoding::BASE64
            .decode(b"AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==")
            .unwrap();
        let rd = dnskey_rdata(256, 5, &pk);
        assert_eq!(key_tag(&rd), 60485);
        let d = ds_digest(&n("dskey.example.com."), &rd, 1).unwrap();
        assert_eq!(
            hex::encode_upper(d),
            "2BB183AF5F22588179A53B0A98631FAD1A292118"
        );
    }

    #[test]
    fn rrsig_round_trip() {
        let f = RrsigFields {
            type_covered: 1,
            algorithm: 13,
            labels: 3,
            original_ttl: 300,
            expiration: 2000,
            inception: 1000,
            key_tag: 4242,
            signer: n("Example.COM."),
        };
        let rd = f.rdata(&[7u8; 64]);
        let (g, sig) = parse_rrsig(&rd).unwrap();
        assert_eq!(sig, vec![7u8; 64]);
        assert_eq!(g.signer.to_ascii(), "example.com.", "signer is canonical");
        assert_eq!(
            display_rdata(T_RRSIG, &rd)
                .unwrap()
                .split(' ')
                .take(3)
                .collect::<Vec<_>>(),
            vec!["A", "13", "3"]
        );
    }

    #[test]
    fn signed_data_sorts_and_dedups() {
        let f = RrsigFields {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 60,
            expiration: 2,
            inception: 1,
            key_tag: 1,
            signer: n("example.com."),
        };
        let a = signed_data(
            &f,
            &n("WWW.example.com."),
            &[vec![10, 0, 0, 2], vec![10, 0, 0, 1], vec![10, 0, 0, 2]],
        );
        let b = signed_data(
            &f,
            &n("www.example.com."),
            &[vec![10, 0, 0, 1], vec![10, 0, 0, 2]],
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), f.prefix().len() + 2 * (17 + 10 + 4));
    }

    #[test]
    fn ds_text_parse() {
        let (t, a, d, dg) =
            parse_ds_text("60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118").unwrap();
        assert_eq!((t, a, d, dg.len()), (60485, 5, 1, 20));
        assert!(parse_ds_text("1 13 2 abcd").is_err(), "wrong length");
        assert!(
            parse_ds_text("1 13 3 abcd").is_err(),
            "unsupported digest type"
        );
        assert!(parse_ds_text("x 13 2 ab").is_err());
    }

    #[test]
    fn canonical_rdata_lowercases_listed_types_only() {
        use hickory_proto::rr::rdata::{CNAME, MX};
        let mx = RData::MX(MX::new(10, n("Mail.Example.COM.")));
        let c = canonical_rdata(&mx).unwrap();
        assert_eq!(&c[2..], name_wire(&n("mail.example.com.")).as_slice());
        let cn = RData::CNAME(CNAME(n("WWW.example.com.")));
        assert_eq!(
            canonical_rdata(&cn).unwrap(),
            name_wire(&n("www.example.com."))
        );
        // SVCB/HTTPS (RFC 9460): the target is not lower-cased.
        // Served and signed forms must be the same bytes.
        let h = RData::try_from_str(RecordType::HTTPS, "1 Svc.Example.com. alpn=h2").unwrap();
        let c = canonical_rdata(&h).unwrap();
        let mut served = Vec::new();
        let mut enc = BinEncoder::new(&mut served);
        h.emit(&mut enc).unwrap();
        assert_eq!(c, served, "HTTPS: canonical form equals the served form");
    }
}
