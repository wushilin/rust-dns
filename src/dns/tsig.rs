//! TSIG (RFC 8945): secret-key transaction signatures for DNS messages.
//!
//! Works on wire-format bytes, because the MAC covers the exact bytes that
//! were sent: the message without its TSIG record (ARCOUNT decremented, the
//! original ID restored) followed by the TSIG variables in canonical form.
//!
//! * Requests: `MAC = HMAC(message || variables)`.
//! * Responses: `MAC = HMAC(len(request MAC) || request MAC || message || variables)`.
//! * Later messages of a multi-message response (AXFR over TCP, §5.3.1):
//!   `MAC = HMAC(len(prior MAC) || prior MAC || message || timers)`.
//!
//! This module is self-contained (std, `hmac`, `sha1`, `sha2`) so the
//! end-to-end tests can include it verbatim and act as a TSIG client.

use hmac::{Hmac, Mac};

/// RR type code of TSIG.
pub const TYPE_TSIG: u16 = 250;
/// Class ANY, which TSIG records carry.
pub const CLASS_ANY: u16 = 255;
/// Largest clock skew we accept, whatever fudge the peer asks for (seconds).
pub const MAX_FUDGE: u16 = 300;

/// TSIG error codes (RFC 8945 §4.3 / RFC 2845).
pub const BADSIG: u16 = 16;
pub const BADKEY: u16 = 17;
pub const BADTIME: u16 = 18;
pub const BADTRUNC: u16 = 22;

/// Supported MAC algorithms. `HmacSha1` is legacy (RFC 8945 §6: SHOULD NOT
/// be used for new deployments) and is only here for older secondaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Algorithm {
    pub const ALL: [Algorithm; 4] = [
        Algorithm::HmacSha256,
        Algorithm::HmacSha384,
        Algorithm::HmacSha512,
        Algorithm::HmacSha1,
    ];

    /// Name as used in BIND configuration and `dig -y`, e.g. `hmac-sha256`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::HmacSha1 => "hmac-sha1",
            Algorithm::HmacSha256 => "hmac-sha256",
            Algorithm::HmacSha384 => "hmac-sha384",
            Algorithm::HmacSha512 => "hmac-sha512",
        }
    }

    /// Accepts `hmac-sha256` or the absolute form `hmac-sha256.`, any case.
    pub fn from_name(s: &str) -> Option<Algorithm> {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        Algorithm::ALL.into_iter().find(|a| a.name() == s)
    }

    /// Hash output length in bytes (the full MAC size).
    pub fn mac_len(self) -> usize {
        match self {
            Algorithm::HmacSha1 => 20,
            Algorithm::HmacSha256 => 32,
            Algorithm::HmacSha384 => 48,
            Algorithm::HmacSha512 => 64,
        }
    }

    /// Canonical (lowercase, uncompressed) wire form of the algorithm name.
    pub fn wire_name(self) -> Vec<u8> {
        name_to_wire(self.name()).expect("static algorithm names are valid")
    }

    /// HMAC over the concatenation of `parts`.
    pub fn mac(self, secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut m =
                <M as Mac>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
        match self {
            Algorithm::HmacSha1 => run::<Hmac<sha1::Sha1>>(secret, parts),
            Algorithm::HmacSha256 => run::<Hmac<sha2::Sha256>>(secret, parts),
            Algorithm::HmacSha384 => run::<Hmac<sha2::Sha384>>(secret, parts),
            Algorithm::HmacSha512 => run::<Hmac<sha2::Sha512>>(secret, parts),
        }
    }
}

/// A key as used for signing and verifying.
#[derive(Clone)]
pub struct Key {
    /// Lowercase, absolute (`hn-secondary.`).
    pub name: String,
    pub algorithm: Algorithm,
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for Key {
    // Never print the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A parsed TSIG record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsigRecord {
    /// Key name, lowercase and absolute (`hn-secondary.`).
    pub key_name: String,
    /// Algorithm name, lowercase and absolute (`hmac-sha256.`).
    pub algorithm_name: String,
    /// Seconds since the epoch (48 bits on the wire).
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: u16,
    pub other: Vec<u8>,
}

impl TsigRecord {
    pub fn algorithm(&self) -> Option<Algorithm> {
        Algorithm::from_name(&self.algorithm_name)
    }
}

/// A message carrying a TSIG record.
#[derive(Clone, Debug)]
pub struct Signed {
    pub tsig: TsigRecord,
    /// Offset where the TSIG record starts; `msg[..offset]` with ARCOUNT
    /// decremented is the message the MAC covers.
    pub offset: usize,
}

/// Why a message could not be parsed for TSIG. Always answered with FORMERR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormErr(pub &'static str);

// ---------------------------------------------------------------------------
// wire helpers
// ---------------------------------------------------------------------------

pub(super) fn u16_at(b: &[u8], i: usize) -> Result<u16, FormErr> {
    b.get(i..i + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .ok_or(FormErr("message truncated"))
}

/// Skip a (possibly compressed) name starting at `i`; returns the offset after it.
pub(super) fn skip_name(b: &[u8], mut i: usize) -> Result<usize, FormErr> {
    loop {
        let len = *b.get(i).ok_or(FormErr("name runs past the end"))? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(i + 1),
            0x00 => i += 1 + len,
            0xC0 => {
                b.get(i + 1).ok_or(FormErr("name runs past the end"))?;
                return Ok(i + 2);
            }
            _ => return Err(FormErr("unsupported label type")),
        }
    }
}

/// Read a (possibly compressed) name at `i`. Returns the canonical wire form
/// (lowercase, uncompressed), the text form (lowercase, absolute) and the
/// offset after the name as it appears at `i`.
fn read_name(b: &[u8], start: usize) -> Result<(Vec<u8>, String, usize), FormErr> {
    let mut wire = Vec::new();
    let mut text = String::new();
    let mut i = start;
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(i).ok_or(FormErr("name runs past the end"))? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => {
                wire.push(0);
                if end.is_none() {
                    end = Some(i + 1);
                }
                break;
            }
            0x00 => {
                let label = b
                    .get(i + 1..i + 1 + len)
                    .ok_or(FormErr("label runs past the end"))?;
                wire.push(len as u8);
                for &c in label {
                    let c = c.to_ascii_lowercase();
                    wire.push(c);
                    if c == b'.' || c == b'\\' || !(0x21..0x7f).contains(&c) {
                        text.push_str(&format!("\\{c:03}"));
                    } else {
                        text.push(c as char);
                    }
                }
                text.push('.');
                i += 1 + len;
            }
            0xC0 => {
                let lo = *b.get(i + 1).ok_or(FormErr("name runs past the end"))? as usize;
                if end.is_none() {
                    end = Some(i + 2);
                }
                jumps += 1;
                if jumps > 64 {
                    return Err(FormErr("compression loop"));
                }
                i = ((len & 0x3F) << 8) | lo;
            }
            _ => return Err(FormErr("unsupported label type")),
        }
        if wire.len() > 255 {
            return Err(FormErr("name too long"));
        }
    }
    if text.is_empty() {
        text.push('.');
    }
    Ok((wire, text, end.expect("set when the name ends")))
}

/// Uncompressed, lowercase wire form of a presentation name (`a.b.` or `a.b`).
pub fn name_to_wire(name: &str) -> Option<Vec<u8>> {
    let n = name.trim_end_matches('.');
    let mut out = Vec::with_capacity(n.len() + 2);
    if !n.is_empty() {
        for label in n.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend(label.bytes().map(|c| c.to_ascii_lowercase()));
        }
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

/// Find the TSIG record of a message, if any. A TSIG that is not the last
/// record of the additional section, a second TSIG, a TSIG with the wrong
/// class or TTL, or bytes after it are format errors (RFC 8945 §5.1).
pub fn find(msg: &[u8]) -> Result<Option<Signed>, FormErr> {
    let mut saw_tsig = false;
    match walk(msg, &mut saw_tsig) {
        Ok(found) => Ok(found),
        // A malformed message without a TSIG is left to the DNS parser.
        Err(_) if !saw_tsig => Ok(None),
        Err(e) => Err(e),
    }
}

fn walk(msg: &[u8], saw_tsig: &mut bool) -> Result<Option<Signed>, FormErr> {
    if msg.len() < 12 {
        return Err(FormErr("shorter than a header"));
    }
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)? as usize;
    let ns = u16_at(msg, 8)? as usize;
    let ar = u16_at(msg, 10)? as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(msg, i)? + 4;
    }
    let total = an + ns + ar;
    let mut found: Option<Signed> = None;
    for n in 0..total {
        let rr_start = i;
        let after_name = skip_name(msg, i)?;
        let rtype = u16_at(msg, after_name)?;
        if rtype == TYPE_TSIG {
            *saw_tsig = true;
        }
        let rdlen = u16_at(msg, after_name + 8)? as usize;
        let rdata = after_name + 10;
        let next = rdata + rdlen;
        if next > msg.len() {
            return Err(FormErr("record runs past the end"));
        }
        if rtype == TYPE_TSIG {
            if n < an + ns {
                return Err(FormErr("TSIG outside the additional section"));
            }
            if n != total - 1 {
                return Err(FormErr("TSIG is not the last record"));
            }
            if u16_at(msg, after_name + 2)? != CLASS_ANY {
                return Err(FormErr("TSIG class is not ANY"));
            }
            if msg[after_name + 4..after_name + 8] != [0, 0, 0, 0] {
                return Err(FormErr("TSIG TTL is not 0"));
            }
            let (_, key_name, _) = read_name(msg, rr_start)?;
            let tsig = parse_rdata(msg, rdata, next, key_name)?;
            found = Some(Signed {
                tsig,
                offset: rr_start,
            });
        }
        i = next;
    }
    if found.is_some() && i != msg.len() {
        return Err(FormErr("trailing bytes after the TSIG record"));
    }
    Ok(found)
}

fn parse_rdata(
    msg: &[u8],
    start: usize,
    end: usize,
    key_name: String,
) -> Result<TsigRecord, FormErr> {
    let (_, algorithm_name, mut i) = read_name(msg, start)?;
    let need = |i: usize, n: usize| {
        if i + n > end {
            Err(FormErr("TSIG rdata too short"))
        } else {
            Ok(())
        }
    };
    need(i, 10)?;
    let time_signed = u64::from_be_bytes([
        0,
        0,
        msg[i],
        msg[i + 1],
        msg[i + 2],
        msg[i + 3],
        msg[i + 4],
        msg[i + 5],
    ]);
    let fudge = u16_at(msg, i + 6)?;
    let mac_size = u16_at(msg, i + 8)? as usize;
    i += 10;
    need(i, mac_size + 6)?;
    let mac = msg[i..i + mac_size].to_vec();
    i += mac_size;
    let original_id = u16_at(msg, i)?;
    let error = u16_at(msg, i + 2)?;
    let other_len = u16_at(msg, i + 4)? as usize;
    i += 6;
    need(i, other_len)?;
    let other = msg[i..i + other_len].to_vec();
    if i + other_len != end {
        return Err(FormErr("TSIG rdata length mismatch"));
    }
    Ok(TsigRecord {
        key_name,
        algorithm_name,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
    })
}

/// The message the MAC covers: without the TSIG record, ARCOUNT decremented,
/// the original ID in place of the message ID.
fn covered(msg: &[u8], signed: &Signed) -> Vec<u8> {
    let mut m = strip(msg, signed);
    m[0..2].copy_from_slice(&signed.tsig.original_id.to_be_bytes());
    m
}

/// 48-bit big-endian time, as in Time Signed and the BADTIME Other Data.
pub fn time48(t: u64) -> [u8; 6] {
    let b = t.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// TSIG variables (RFC 8945 §4.3.3) in canonical wire form.
fn variables(
    key_wire: &[u8],
    alg_wire: &[u8],
    time: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(key_wire.len() + alg_wire.len() + 24 + other.len());
    v.extend_from_slice(key_wire);
    v.extend_from_slice(&CLASS_ANY.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(alg_wire);
    v.extend_from_slice(&time48(time));
    v.extend_from_slice(&fudge.to_be_bytes());
    v.extend_from_slice(&error.to_be_bytes());
    v.extend_from_slice(&(other.len() as u16).to_be_bytes());
    v.extend_from_slice(other);
    v
}

/// TSIG timers (§4.3.3.1): time signed and fudge only.
fn timers(time: u64, fudge: u16) -> Vec<u8> {
    let mut v = time48(time).to_vec();
    v.extend_from_slice(&fudge.to_be_bytes());
    v
}

/// What precedes the message in the digest.
#[derive(Clone, Copy, Debug)]
pub enum Chain<'a> {
    /// A request: nothing.
    Request,
    /// The first (or only) response to a request with this MAC; full variables.
    Response(&'a [u8]),
    /// A later message of a multi-message response: the previous message's
    /// MAC, and only the timers.
    Continuation(&'a [u8]),
}

fn digest(key: &Key, chain: Chain, message: &[u8], vars: &[u8]) -> Vec<u8> {
    let prefix: Vec<u8> = match chain {
        Chain::Request => Vec::new(),
        Chain::Response(m) | Chain::Continuation(m) => {
            let mut p = (m.len() as u16).to_be_bytes().to_vec();
            p.extend_from_slice(m);
            p
        }
    };
    key.algorithm.mac(&key.secret, &[&prefix, message, vars])
}

/// Parameters of a TSIG record to add.
#[derive(Clone, Debug)]
pub struct SignParams {
    pub time: u64,
    pub fudge: u16,
    pub original_id: u16,
    pub error: u16,
    pub other: Vec<u8>,
}

/// Append a TSIG record signed with `key` to `msg` (which must not carry
/// one). Returns the new message and its MAC.
pub fn sign(msg: &[u8], key: &Key, chain: Chain, p: &SignParams) -> (Vec<u8>, Vec<u8>) {
    let key_wire = name_to_wire(&key.name).unwrap_or_else(|| vec![0]);
    let alg_wire = key.algorithm.wire_name();
    let mut covered = msg.to_vec();
    covered[0..2].copy_from_slice(&p.original_id.to_be_bytes());
    let vars = match chain {
        Chain::Continuation(_) => timers(p.time, p.fudge),
        _ => variables(&key_wire, &alg_wire, p.time, p.fudge, p.error, &p.other),
    };
    let mac = digest(key, chain, &covered, &vars);
    (append(msg, &key_wire, &alg_wire, &mac, p), mac)
}

/// Append an unsigned TSIG record (empty MAC) carrying `p.error`: the reply
/// to a request with an unknown key or a bad MAC (RFC 8945 §5.3.2). The key
/// and algorithm names are echoed from the request.
pub fn unsigned(msg: &[u8], key_name: &str, algorithm_name: &str, p: &SignParams) -> Vec<u8> {
    let key_wire = name_to_wire(key_name).unwrap_or_else(|| vec![0]);
    let alg_wire = name_to_wire(algorithm_name).unwrap_or_else(|| vec![0]);
    append(msg, &key_wire, &alg_wire, &[], p)
}

fn append(msg: &[u8], key_wire: &[u8], alg_wire: &[u8], mac: &[u8], p: &SignParams) -> Vec<u8> {
    let mut rdata = alg_wire.to_vec();
    rdata.extend_from_slice(&time48(p.time));
    rdata.extend_from_slice(&p.fudge.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&p.original_id.to_be_bytes());
    rdata.extend_from_slice(&p.error.to_be_bytes());
    rdata.extend_from_slice(&(p.other.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&p.other);

    let mut out = Vec::with_capacity(msg.len() + key_wire.len() + 10 + rdata.len());
    out.extend_from_slice(msg);
    let ar = u16::from_be_bytes([out[10], out[11]]).wrapping_add(1);
    out[10..12].copy_from_slice(&ar.to_be_bytes());
    out.extend_from_slice(key_wire);
    out.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

/// Strip the TSIG record: the message as it was before signing (ARCOUNT
/// decremented; the message ID is left as received).
pub fn strip(msg: &[u8], signed: &Signed) -> Vec<u8> {
    let mut m = msg[..signed.offset].to_vec();
    let ar = u16::from_be_bytes([m[10], m[11]]).saturating_sub(1);
    m[10..12].copy_from_slice(&ar.to_be_bytes());
    m
}

/// Size of the TSIG record `sign` would append for this key.
pub fn record_len(key_name: &str, algorithm: Algorithm, other_len: usize) -> usize {
    let key = name_to_wire(key_name).map(|w| w.len()).unwrap_or(1);
    key + 10 + algorithm.wire_name().len() + 16 + algorithm.mac_len() + other_len
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // Keep the comparison from being turned into an early exit.
    std::hint::black_box(d) == 0
}

/// Outcome of checking a signed message. Everything except `FormErr` is
/// answered with NOTAUTH and the TSIG error in the TSIG record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    FormErr(&'static str),
    /// Unknown key, or the key has a different algorithm.
    BadKey,
    BadSig,
    /// Signature fine, clock outside `time signed ± fudge`.
    BadTime,
    /// Signature fine, but truncated below what we accept (full length).
    BadTrunc,
}

impl VerifyError {
    pub fn code(&self) -> u16 {
        match self {
            VerifyError::FormErr(_) => 0,
            VerifyError::BadKey => BADKEY,
            VerifyError::BadSig => BADSIG,
            VerifyError::BadTime => BADTIME,
            VerifyError::BadTrunc => BADTRUNC,
        }
    }

    /// Whether the error response is signed (§5.3.2: BADTIME and BADTRUNC
    /// are, errors about the key or the MAC are not).
    pub fn signed_reply(&self) -> bool {
        matches!(self, VerifyError::BadTime | VerifyError::BadTrunc)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            VerifyError::FormErr(w) => w,
            VerifyError::BadKey => "BADKEY",
            VerifyError::BadSig => "BADSIG",
            VerifyError::BadTime => "BADTIME",
            VerifyError::BadTrunc => "BADTRUNC",
        }
    }
}

/// Verify a signed message with `key` (already looked up by name; `None`
/// when the name is unknown). Order per RFC 8945 §5.2: key, MAC (§5.2.2,
/// with the truncation rules of §5.2.2.1), time (§5.2.3), truncation policy
/// (§5.2.4). The accepted clock skew is the signer's fudge capped at
/// [`MAX_FUDGE`].
pub fn verify(
    msg: &[u8],
    signed: &Signed,
    key: Option<&Key>,
    chain: Chain,
    now: u64,
) -> Result<(), VerifyError> {
    let t = &signed.tsig;
    let key = key.ok_or(VerifyError::BadKey)?;
    if t.algorithm() != Some(key.algorithm) || !t.key_name.eq_ignore_ascii_case(&key.name) {
        return Err(VerifyError::BadKey);
    }
    let full = key.algorithm.mac_len();
    let min = std::cmp::max(10, full / 2);
    if t.mac.len() > full || t.mac.len() < min {
        return Err(VerifyError::FormErr("MAC size out of range"));
    }
    let key_wire = name_to_wire(&key.name).ok_or(VerifyError::BadKey)?;
    let vars = match chain {
        Chain::Continuation(_) => timers(t.time_signed, t.fudge),
        _ => variables(
            &key_wire,
            &key.algorithm.wire_name(),
            t.time_signed,
            t.fudge,
            t.error,
            &t.other,
        ),
    };
    let expected = digest(key, chain, &covered(msg, signed), &vars);
    if !ct_eq(&expected[..t.mac.len()], &t.mac) {
        return Err(VerifyError::BadSig);
    }
    let fudge = t.fudge.min(MAX_FUDGE) as u64;
    if now.abs_diff(t.time_signed) > fudge {
        return Err(VerifyError::BadTime);
    }
    if t.mac.len() < full {
        return Err(VerifyError::BadTrunc);
    }
    Ok(())
}

/// Replay protection for signed requests (RFC 8945 §5.2.3), in memory,
/// per server: per key the Time Signed of the newest verified request and
/// the MACs seen at that second. A request is refused (BADTIME) when its
/// Time Signed is older than that, or equal with a MAC already seen (the
/// same message again). Several different requests signed in the same
/// second all pass (a secondary's SOA query followed by its transfer, an
/// `nsupdate` batch). Anything outside the fudge window was already
/// refused by the time check, so this only has to remember one second
/// per key.
#[derive(Default)]
pub struct ReplayGuard {
    last: std::sync::Mutex<std::collections::HashMap<String, Newest>>,
}

/// Per key: the newest Time Signed and the MACs seen in that second.
type Newest = (u64, Vec<Vec<u8>>);

/// MACs remembered for one key and second (more requests than this in one
/// second: the oldest are forgotten).
const REPLAY_MACS: usize = 1024;

impl ReplayGuard {
    /// Accept a request that verified with `key` (a fresh one is recorded),
    /// or `false` for a replay.
    pub fn accept(&self, key: &str, time_signed: u64, mac: &[u8]) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let e = last
            .entry(key.to_ascii_lowercase())
            .or_insert_with(|| (0, Vec::new()));
        if time_signed < e.0 {
            return false;
        }
        if time_signed > e.0 {
            *e = (time_signed, Vec::new());
        } else if e.1.iter().any(|m| m == mac) {
            return false;
        }
        if e.1.len() >= REPLAY_MACS {
            e.1.remove(0);
        }
        e.1.push(mac.to_vec());
        true
    }
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Client-side verifier for the response(s) to a request we signed: the
/// first response is checked against the request MAC, every later one
/// (multi-message AXFR) is chained to the previous MAC. Every message must
/// be signed (this server signs all of them).
pub struct ResponseVerifier {
    key: Key,
    prior: Vec<u8>,
    first: bool,
}

/// Why a response failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    Unsigned,
    Malformed(&'static str),
    /// The peer reported a TSIG error (BADKEY, BADSIG, BADTIME, ...).
    Peer(u16),
    Invalid(VerifyError),
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseError::Unsigned => write!(f, "response is not signed"),
            ResponseError::Malformed(w) => write!(f, "malformed TSIG: {w}"),
            ResponseError::Peer(BADSIG) => write!(f, "peer reports BADSIG (wrong secret?)"),
            ResponseError::Peer(BADKEY) => write!(
                f,
                "peer reports BADKEY (key unknown to the peer or different algorithm)"
            ),
            ResponseError::Peer(BADTIME) => write!(
                f,
                "peer reports BADTIME (clocks differ by more than the fudge)"
            ),
            ResponseError::Peer(e) => write!(f, "peer reports TSIG error {e}"),
            ResponseError::Invalid(e) => write!(f, "response signature invalid: {}", e.as_str()),
        }
    }
}

impl ResponseVerifier {
    pub fn new(key: Key, request_mac: &[u8]) -> Self {
        ResponseVerifier {
            key,
            prior: request_mac.to_vec(),
            first: true,
        }
    }

    pub fn verify(&mut self, msg: &[u8], now: u64) -> Result<(), ResponseError> {
        let signed = find(msg)
            .map_err(|e| ResponseError::Malformed(e.0))?
            .ok_or(ResponseError::Unsigned)?;
        if signed.tsig.error != 0 {
            return Err(ResponseError::Peer(signed.tsig.error));
        }
        let chain = if self.first {
            Chain::Response(&self.prior)
        } else {
            Chain::Continuation(&self.prior)
        };
        verify(msg, &signed, Some(&self.key), chain, now).map_err(ResponseError::Invalid)?;
        self.prior = signed.tsig.mac;
        self.first = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// M3: per key, older than the newest refused; the same MAC in the same
    /// second refused; other messages in the same second and other keys fine.
    #[test]
    fn replay_guard_refuses_old_and_repeated_requests() {
        let g = ReplayGuard::default();
        assert!(g.accept("k.", 100, b"a"));
        assert!(
            !g.accept("K.", 100, b"a"),
            "same message (key name case-insensitive)"
        );
        assert!(g.accept("k.", 100, b"b"), "another message, same second");
        assert!(!g.accept("k.", 99, b"c"), "older");
        assert!(g.accept("other.", 50, b"a"), "keys are separate");
        assert!(
            g.accept("k.", 101, b"a"),
            "newer: the old MAC no longer matters"
        );
        assert!(!g.accept("k.", 100, b"z"));
        for i in 0..2000u32 {
            assert!(g.accept("k.", 102, &i.to_be_bytes()));
        }
        assert!(
            g.accept("k.", 102, &0u32.to_be_bytes()),
            "forgotten beyond the cap"
        );
        assert!(!g.accept("k.", 102, &1999u32.to_be_bytes()));
    }
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const T: u64 = 1_700_000_000;

    /// Known answers generated with dnspython 2.8 (dns.tsig), key name
    /// `test-key.`, secret = bytes 0..hash length, time signed 1700000000,
    /// fudge 300: an `example.com. AXFR` query (id 0x1234), and a two-message
    /// response (SOA, then `www A 192.0.2.1`) signed with MAC chaining.
    const KAT: &[(&str, &str, &str, &str)] = &[
        ("hmac-sha256", "123400000001000000000001076578616d706c6503636f6d0000fc000108746573742d6b65790000fa00ff00000000003d0b686d61632d7368613235360000006553f100012c0020bb5ec753c3499c77e7c40d287d4710f2b081ddd8bc4e0880a4e3ced441fd05ae123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc0001c00c000600010000012c0027036e7331c00c0a686f73746d6173746572c00c0000000100000e1000000258001275000000012c08746573742d6b65790000fa00ff00000000003d0b686d61632d7368613235360000006553f100012c00201820b8cab3ab7605648bef203b5a85e46c461a4c71ea3ac475dfa190fdd630a8123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc000103777777c00c000100010000012c0004c000020108746573742d6b65790000fa00ff00000000003d0b686d61632d7368613235360000006553f100012c0020517ec335d0c319c8efe2a4a5c1179024f0a64400c28b07d0b3d257158a8b3085123400000000"),
        ("hmac-sha384", "123400000001000000000001076578616d706c6503636f6d0000fc000108746573742d6b65790000fa00ff00000000004d0b686d61632d7368613338340000006553f100012c00301246544fb71daab829960a39415a284b6ca397a5fcf59fc497c946f49efa51f05e34c12c08258ce34a162b1baef71f66123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc0001c00c000600010000012c0027036e7331c00c0a686f73746d6173746572c00c0000000100000e1000000258001275000000012c08746573742d6b65790000fa00ff00000000004d0b686d61632d7368613338340000006553f100012c00306ed08981e82e2037234885e77967257ab0ed1ae1cbc4bb3cd73451aac13bfdc3b468dc71d2271cdf9d4ceeb74b04bfd6123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc000103777777c00c000100010000012c0004c000020108746573742d6b65790000fa00ff00000000004d0b686d61632d7368613338340000006553f100012c00307322d6ca0e91950b5a37a9c40f1c22b4a5f4512e8beac55ecddf29de67997bda712839ef58cc4a3313d5db56a5855c86123400000000"),
        ("hmac-sha512", "123400000001000000000001076578616d706c6503636f6d0000fc000108746573742d6b65790000fa00ff00000000005d0b686d61632d7368613531320000006553f100012c004023920480fa1d9b116a16566ff3fe797de1a7440a70f3d61990d0247ac245d4993683958bec6b03c32fb936e0b681ac2dca893a60f8c8824fe6e96bbd23edcc4a123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc0001c00c000600010000012c0027036e7331c00c0a686f73746d6173746572c00c0000000100000e1000000258001275000000012c08746573742d6b65790000fa00ff00000000005d0b686d61632d7368613531320000006553f100012c004018d9292d0e428e041c91519c598b21b9c8876b102e93cac168b41ff4dd5df41522895570bba3514aa336d23bcab106d0c66e21158e794b8bac5549ff3afc5148123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc000103777777c00c000100010000012c0004c000020108746573742d6b65790000fa00ff00000000005d0b686d61632d7368613531320000006553f100012c00400ab2effc60c2ce4466ab52b32b2b3a72f3730fe0bfcac6efd494a8a0eb5ef3908eb64d86a56739e9a731529eabd9532565aec80e7db8c7f9cb84e4e1adf47b85123400000000"),
        ("hmac-sha1", "123400000001000000000001076578616d706c6503636f6d0000fc000108746573742d6b65790000fa00ff00000000002f09686d61632d736861310000006553f100012c0014d0993e6d843665f2bb1b55d920122e5fd92712fb123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc0001c00c000600010000012c0027036e7331c00c0a686f73746d6173746572c00c0000000100000e1000000258001275000000012c08746573742d6b65790000fa00ff00000000002f09686d61632d736861310000006553f100012c0014d7cd1afdcdace9d0753cba7f6244714904a334e7123400000000",
         "123480000001000100000001076578616d706c6503636f6d0000fc000103777777c00c000100010000012c0004c000020108746573742d6b65790000fa00ff00000000002f09686d61632d736861310000006553f100012c0014f5d1bb73e3f9f7c19e3561a0ac6e13463ef6aae0123400000000"),
    ];

    fn kat_key(alg: Algorithm) -> Key {
        Key {
            name: "test-key.".into(),
            algorithm: alg,
            secret: (0..alg.mac_len() as u8).collect(),
        }
    }

    fn params(t: &TsigRecord) -> SignParams {
        SignParams {
            time: t.time_signed,
            fudge: t.fudge,
            original_id: t.original_id,
            error: t.error,
            other: t.other.clone(),
        }
    }

    #[test]
    fn known_answers_from_dnspython() {
        for (alg, q, r1, r2) in KAT {
            let alg = Algorithm::from_name(alg).unwrap();
            let key = kat_key(alg);
            let (q, r1, r2) = (h(q), h(r1), h(r2));

            // Verify the request dnspython signed.
            let sq = find(&q).unwrap().unwrap();
            assert_eq!(sq.tsig.key_name, "test-key.");
            assert_eq!(sq.tsig.time_signed, T);
            assert_eq!(sq.tsig.mac.len(), alg.mac_len());
            verify(&q, &sq, Some(&key), Chain::Request, T).unwrap();

            // Re-sign it ourselves: byte-identical.
            let mut unsigned = q[..sq.offset].to_vec();
            unsigned[11] -= 1;
            let (mine2, mac2) = sign(&unsigned, &key, Chain::Request, &params(&sq.tsig));
            assert_eq!(mine2, q, "{alg:?} request");
            assert_eq!(mac2, sq.tsig.mac);

            // The two-message response: first chained to the request MAC,
            // the second to the first (timers only).
            let s1 = find(&r1).unwrap().unwrap();
            let s2 = find(&r2).unwrap().unwrap();
            let (o1, m1) = sign(
                &strip(&r1, &s1),
                &key,
                Chain::Response(&sq.tsig.mac),
                &params(&s1.tsig),
            );
            assert_eq!(o1, r1, "{alg:?} first response");
            let (o2, _) = sign(
                &strip(&r2, &s2),
                &key,
                Chain::Continuation(&m1),
                &params(&s2.tsig),
            );
            assert_eq!(o2, r2, "{alg:?} second response");

            let mut v = ResponseVerifier::new(key.clone(), &sq.tsig.mac);
            v.verify(&r1, T).unwrap();
            v.verify(&r2, T).unwrap();
            // Out of order: the chain breaks.
            let mut v = ResponseVerifier::new(key.clone(), &sq.tsig.mac);
            assert_eq!(
                v.verify(&r2, T),
                Err(ResponseError::Invalid(VerifyError::BadSig))
            );
            // Second message verified as a first one: not valid either.
            let mut v = ResponseVerifier::new(key.clone(), &s1.tsig.mac);
            assert!(v.verify(&r2, T).is_err());
        }
    }

    fn sample_query() -> Vec<u8> {
        h(&KAT[0].1[..KAT[0].1.find("08746573742d6b6579").unwrap()])
            .into_iter()
            .enumerate()
            .map(|(i, b)| if i == 11 { 0 } else { b })
            .collect()
    }

    #[test]
    fn errors_badkey_badsig_badtime_trunc() {
        let key = kat_key(Algorithm::HmacSha256);
        let q = sample_query();
        let p = SignParams {
            time: T,
            fudge: 300,
            original_id: 0x1234,
            error: 0,
            other: vec![],
        };
        let (signed, _) = sign(&q, &key, Chain::Request, &p);
        let s = find(&signed).unwrap().unwrap();
        verify(&signed, &s, Some(&key), Chain::Request, T).unwrap();

        // Unknown key, and a known name with another algorithm.
        assert_eq!(
            verify(&signed, &s, None, Chain::Request, T),
            Err(VerifyError::BadKey)
        );
        let other_alg = Key {
            algorithm: Algorithm::HmacSha512,
            ..key.clone()
        };
        assert_eq!(
            verify(&signed, &s, Some(&other_alg), Chain::Request, T),
            Err(VerifyError::BadKey)
        );
        // Wrong secret.
        let wrong = Key {
            secret: vec![7; 32],
            ..key.clone()
        };
        assert_eq!(
            verify(&signed, &s, Some(&wrong), Chain::Request, T),
            Err(VerifyError::BadSig)
        );
        // Any flipped bit in the covered message.
        // (byte 0-1, the ID, is replaced by the original ID in the digest)
        for i in [2usize, 3, 13, 18, s.offset - 1] {
            let mut t = signed.clone();
            t[i] ^= 0x01;
            let st = find(&t).unwrap().unwrap();
            assert_eq!(
                verify(&t, &st, Some(&key), Chain::Request, T),
                Err(VerifyError::BadSig),
                "byte {i}"
            );
        }
        // Time: inside fudge ok, outside BADTIME (after the MAC check).
        verify(&signed, &s, Some(&key), Chain::Request, T + 300).unwrap();
        verify(&signed, &s, Some(&key), Chain::Request, T - 300).unwrap();
        assert_eq!(
            verify(&signed, &s, Some(&key), Chain::Request, T + 301),
            Err(VerifyError::BadTime)
        );
        assert_eq!(
            verify(&signed, &s, Some(&key), Chain::Request, T - 301),
            Err(VerifyError::BadTime)
        );
        assert_eq!(
            verify(&signed, &s, Some(&wrong), Chain::Request, T + 9999),
            Err(VerifyError::BadSig),
            "bad MAC wins over bad time"
        );
        // A signer asking for a huge fudge still gets at most MAX_FUDGE.
        let wide = SignParams {
            fudge: 3600,
            ..p.clone()
        };
        let (w, _) = sign(&q, &key, Chain::Request, &wide);
        let sw = find(&w).unwrap().unwrap();
        assert_eq!(
            verify(&w, &sw, Some(&key), Chain::Request, T + 1000),
            Err(VerifyError::BadTime)
        );

        // Truncated MACs: valid but short -> BADTRUNC; too short/long -> FORMERR.
        let truncate = |n: usize| {
            let mut t = signed.clone();
            // owner (10) + type/class/ttl/rdlength (10) + algorithm + time/fudge/mac size (10)
            let mac_at = s.offset + 20 + Algorithm::HmacSha256.wire_name().len() + 10;
            t[mac_at - 2..mac_at].copy_from_slice(&(n as u16).to_be_bytes());
            t.drain(mac_at + n..mac_at + 32);
            let rdlen_at = s.offset + 10 + 8;
            let rdlen = u16::from_be_bytes([t[rdlen_at], t[rdlen_at + 1]]) - (32 - n as u16);
            t[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
            t
        };
        let t16 = truncate(16);
        let st = find(&t16).unwrap().unwrap();
        assert_eq!(st.tsig.mac.len(), 16);
        assert_eq!(
            verify(&t16, &st, Some(&key), Chain::Request, T),
            Err(VerifyError::BadTrunc)
        );
        let t8 = truncate(8);
        let st = find(&t8).unwrap().unwrap();
        assert!(matches!(
            verify(&t8, &st, Some(&key), Chain::Request, T),
            Err(VerifyError::FormErr(_))
        ));
        let mut t16bad = t16.clone();
        let l = t16bad.len();
        t16bad[l - 8] ^= 1; // inside the MAC
        let st = find(&t16bad).unwrap().unwrap();
        assert_eq!(
            verify(&t16bad, &st, Some(&key), Chain::Request, T),
            Err(VerifyError::BadSig)
        );
    }

    #[test]
    fn find_rejects_misplaced_tsig() {
        let key = kat_key(Algorithm::HmacSha256);
        let q = sample_query();
        assert!(find(&q).unwrap().is_none());
        let p = SignParams {
            time: T,
            fudge: 300,
            original_id: 0x1234,
            error: 0,
            other: vec![],
        };
        let (signed, _) = sign(&q, &key, Chain::Request, &p);
        // Trailing garbage.
        let mut t = signed.clone();
        t.push(0);
        assert!(find(&t).is_err());
        // Malformed but unsigned: left to the DNS parser.
        let mut t = q.clone();
        t.push(0);
        assert!(find(&t).unwrap().is_none());
        assert!(find(&q[..q.len() - 2]).unwrap().is_none());
        // Two TSIG records.
        let (twice, _) = sign(&signed, &key, Chain::Request, &p);
        assert!(find(&twice).is_err());
        // TSIG counted in the answer section.
        let mut t = signed.clone();
        t[7] = 1;
        t[11] = 0;
        assert!(find(&t).is_err());
        // Cut short.
        assert!(find(&signed[..signed.len() - 3]).is_err());
    }

    #[test]
    fn compressed_owner_name_is_read() {
        // Owner name of the TSIG record given as a pointer to the question name.
        let key = Key {
            name: "example.com.".into(),
            algorithm: Algorithm::HmacSha256,
            secret: vec![1; 32],
        };
        let q = sample_query();
        let p = SignParams {
            time: T,
            fudge: 300,
            original_id: 0x1234,
            error: 0,
            other: vec![],
        };
        let (signed, _) = sign(&q, &key, Chain::Request, &p);
        let owner = name_to_wire("example.com.").unwrap();
        let mut c = signed[..q.len()].to_vec();
        c.extend_from_slice(&[0xC0, 12]);
        c.extend_from_slice(&signed[q.len() + owner.len()..]);
        let s = find(&c).unwrap().unwrap();
        assert_eq!(s.tsig.key_name, "example.com.");
        verify(&c, &s, Some(&key), Chain::Request, T).unwrap();
    }

    #[test]
    fn unsigned_error_and_badtime_reply() {
        let key = kat_key(Algorithm::HmacSha256);
        let q = sample_query();
        let p = SignParams {
            time: T,
            fudge: 300,
            original_id: 0x1234,
            error: BADKEY,
            other: vec![],
        };
        let m = unsigned(&q, "test-key.", "hmac-sha256.", &p);
        let s = find(&m).unwrap().unwrap();
        assert_eq!(s.tsig.error, BADKEY);
        assert!(s.tsig.mac.is_empty());
        let mut v = ResponseVerifier::new(key.clone(), &[1, 2, 3]);
        assert_eq!(v.verify(&m, T), Err(ResponseError::Peer(BADKEY)));

        // BADTIME is signed and carries the server time in Other Data.
        let req_mac = vec![9u8; 32];
        let p = SignParams {
            time: T,
            fudge: 300,
            original_id: 0x1234,
            error: BADTIME,
            other: time48(T + 1000).to_vec(),
        };
        let (m, mac) = sign(&q, &key, Chain::Response(&req_mac), &p);
        assert_eq!(mac.len(), 32);
        let s = find(&m).unwrap().unwrap();
        assert_eq!(s.tsig.other, time48(T + 1000).to_vec());
        verify(&m, &s, Some(&key), Chain::Response(&req_mac), T).unwrap();
        assert_eq!(
            record_len("test-key.", Algorithm::HmacSha256, 6),
            m.len() - q.len()
        );
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(
            Algorithm::from_name("HMAC-SHA256."),
            Some(Algorithm::HmacSha256)
        );
        assert_eq!(Algorithm::from_name("hmac-md5.sig-alg.reg.int."), None);
        assert_eq!(Algorithm::HmacSha384.mac_len(), 48);
        assert_eq!(name_to_wire("A.b."), Some(b"\x01a\x01b\x00".to_vec()));
        assert_eq!(name_to_wire("."), Some(vec![0]));
        let dbg = format!("{:?}", kat_key(Algorithm::HmacSha256));
        assert!(!dbg.contains("secret"), "{dbg}");
    }
}
