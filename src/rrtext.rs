//! O28: presentation format <-> wire RDATA for record types hickory's text
//! parser does not handle: LOC (RFC 1876), RP and AFSDB (RFC 1183), URI
//! (RFC 7553), SPF (RFC 7208 §3.1, TXT syntax), EUI48 and EUI64 (RFC 7043).
//! Records of these types are served as raw RDATA (hickory carries them as
//! unknown types); [`parse`] validates and encodes the stored value and
//! [`format`] gives its canonical text, which is what is stored (so a value
//! entered in any accepted form reads back the same way).

use crate::model::{normalize_domain, RecordType};

/// The record types handled here.
pub fn handles(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::LOC
            | RecordType::RP
            | RecordType::AFSDB
            | RecordType::URI
            | RecordType::SPF
            | RecordType::EUI48
            | RecordType::EUI64
    )
}

fn name_wire(s: &str) -> Result<Vec<u8>, String> {
    let n = if s == "." {
        String::new()
    } else {
        normalize_domain(s, true).map_err(|e| e.0)?
    };
    let mut out = Vec::new();
    for l in n.split('.').filter(|l| !l.is_empty()) {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// An uncompressed name at `pos`: (text with trailing dot, next position).
fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *b.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression is not allowed in these RDATA
        }
        let l = b.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(l).to_ascii_lowercase());
        pos += len;
    }
    Some((
        if labels.is_empty() {
            ".".into()
        } else {
            format!("{}.", labels.join("."))
        },
        pos,
    ))
}

/// Character-strings of a TXT-style value: quoted strings (with `\"`, `\\`
/// and `\DDD` escapes) or, unquoted, the whole value as one text split
/// into 255-byte strings.
fn char_strings(v: &str) -> Result<Vec<Vec<u8>>, String> {
    let v = v.trim();
    if !v.starts_with('"') {
        return Ok(v.as_bytes().chunks(255).map(|c| c.to_vec()).collect());
    }
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] != b'"' {
            return Err("strings must be quoted".into());
        }
        i += 1;
        let mut cur = Vec::new();
        loop {
            let c = *b.get(i).ok_or("unterminated string")?;
            i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let d = b.get(i..i + 3).filter(|d| d.iter().all(u8::is_ascii_digit));
                    if let Some(d) = d {
                        let n: u16 = std::str::from_utf8(d).unwrap().parse().unwrap();
                        cur.push(u8::try_from(n).map_err(|_| "escape over 255")?);
                        i += 3;
                    } else {
                        cur.push(*b.get(i).ok_or("dangling escape")?);
                        i += 1;
                    }
                }
                c => cur.push(c),
            }
        }
        if cur.len() > 255 {
            return Err("a string is longer than 255 bytes".into());
        }
        out.push(cur);
    }
    Ok(out)
}

fn quote(s: &[u8]) -> String {
    let mut o = String::from("\"");
    for &c in s {
        match c {
            b'"' | b'\\' => {
                o.push('\\');
                o.push(c as char);
            }
            0x20..=0x7e => o.push(c as char),
            _ => o.push_str(&format!("\\{c:03}")),
        }
    }
    o.push('"');
    o
}

// ---- LOC (RFC 1876) -------------------------------------------------------

/// Centimetres to the precision byte (mantissa << 4 | exponent).
fn loc_prec(cm: u64) -> Result<u8, String> {
    // m * 10^e (truncated, as BIND and dnspython do).
    let mut e = 0u8;
    let mut v = cm;
    while v > 9 {
        v /= 10;
        e += 1;
    }
    if e > 9 {
        return Err("size / precision out of range (at most 90000000.00m)".into());
    }
    Ok(((v as u8) << 4) | e)
}

fn loc_prec_cm(b: u8) -> Option<u64> {
    let (m, e) = ((b >> 4) as u64, (b & 0x0f) as u32);
    (m <= 9 && e <= 9).then(|| m * 10u64.pow(e))
}

/// Metres with up to 2 decimals and an optional `m`, to centimetres.
fn metres_cm(s: &str) -> Result<i64, String> {
    let s = s.trim_end_matches(['m', 'M']);
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (i, f) = s.split_once('.').unwrap_or((s, ""));
    if i.is_empty()
        || f.len() > 2
        || !i.bytes().all(|c| c.is_ascii_digit())
        || !f.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(format!(
            "'{s}' is not a distance in metres (e.g. 10m or -2.50m)"
        ));
    }
    let cm = i.parse::<i64>().map_err(|e| e.to_string())? * 100
        + format!("{f:0<2}").parse::<i64>().unwrap_or(0);
    Ok(if neg { -cm } else { cm })
}

fn loc_parse(v: &str) -> Result<Vec<u8>, String> {
    let t: Vec<&str> = v.split_whitespace().collect();
    let mut i = 0;
    let mut angle = |hemis: [&str; 2], max: u32| -> Result<u32, String> {
        let d: u32 = t
            .get(i)
            .and_then(|x| x.parse().ok())
            .ok_or("degrees expected")?;
        i += 1;
        let (mut m, mut sec_thou) = (0u32, 0u32);
        if let Some(x) = t.get(i).filter(|x| x.bytes().all(|c| c.is_ascii_digit())) {
            m = x.parse().map_err(|_| "minutes")?;
            i += 1;
            if let Some(x) = t
                .get(i)
                .filter(|x| x.bytes().next().is_some_and(|c| c.is_ascii_digit()))
            {
                let (s, f) = x.split_once('.').unwrap_or((x, ""));
                if f.len() > 3 || !f.bytes().all(|c| c.is_ascii_digit()) {
                    return Err("seconds have at most 3 decimals".into());
                }
                sec_thou = s.parse::<u32>().map_err(|_| "seconds")? * 1000
                    + format!("{f:0<3}").parse::<u32>().unwrap_or(0);
                i += 1;
            }
        }
        if d > max || m > 59 || sec_thou >= 60_000 || (d == max && (m > 0 || sec_thou > 0)) {
            return Err("angle out of range".into());
        }
        let h = t
            .get(i)
            .map(|x| x.to_ascii_uppercase())
            .ok_or("hemisphere expected")?;
        i += 1;
        let val = ((d * 60 + m) * 60) * 1000 + sec_thou;
        if h == hemis[0] {
            Ok((1u32 << 31) + val)
        } else if h == hemis[1] {
            Ok((1u32 << 31) - val)
        } else {
            Err(format!("hemisphere must be {} or {}", hemis[0], hemis[1]))
        }
    };
    let lat = angle(["N", "S"], 90)?;
    let lon = angle(["E", "W"], 180)?;
    let alt_cm = metres_cm(t.get(i).ok_or("altitude expected")?)?;
    i += 1;
    let alt = u32::try_from(alt_cm + 10_000_000)
        .map_err(|_| "altitude out of range (-100000.00m to 42849672.95m)")?;
    let mut prec = [100i64, 1_000_000, 1000]; // size 1m, horizontal 10000m, vertical 10m
    for p in prec.iter_mut() {
        if let Some(x) = t.get(i) {
            *p = metres_cm(x)?;
            if *p < 0 {
                return Err("size and precision must not be negative".into());
            }
            i += 1;
        }
    }
    if i != t.len() {
        return Err("too many fields".into());
    }
    let mut out = vec![0];
    for p in prec {
        out.push(loc_prec(p as u64)?);
    }
    out.extend_from_slice(&lat.to_be_bytes());
    out.extend_from_slice(&lon.to_be_bytes());
    out.extend_from_slice(&alt.to_be_bytes());
    Ok(out)
}

fn loc_format(b: &[u8]) -> Option<String> {
    if b.len() != 16 || b[0] != 0 {
        return None;
    }
    let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let angle = |raw: u32, pos: char, neg: char| {
        let (h, v) = if raw >= 1 << 31 {
            (pos, raw - (1 << 31))
        } else {
            (neg, (1 << 31) - raw)
        };
        let (thou, secs) = (v % 1000, v / 1000);
        format!(
            "{} {} {}.{thou:03} {h}",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        )
    };
    let m = |cm: i64| {
        let s = if cm < 0 { "-" } else { "" };
        format!("{s}{}.{:02}m", cm.abs() / 100, cm.abs() % 100)
    };
    let [size, hp, vp] = [b[1], b[2], b[3]].map(loc_prec_cm);
    Some(format!(
        "{} {} {} {} {} {}",
        angle(u(4), 'N', 'S'),
        angle(u(8), 'E', 'W'),
        m(u(12) as i64 - 10_000_000),
        m(size? as i64),
        m(hp? as i64),
        m(vp? as i64)
    ))
}

// ---- the others ------------------------------------------------------------

fn eui(v: &str, n: usize) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() != n || parts.iter().any(|p| p.len() != 2) {
        return Err(format!(
            "EUI{} is {n} hexadecimal pairs joined by '-', e.g. 00-00-5e-00-53-2a",
            n * 8
        ));
    }
    parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).map_err(|_| format!("'{p}' is not hexadecimal")))
        .collect()
}

/// The wire RDATA of `value` for a type [`handles`] covers.
pub fn parse(t: RecordType, value: &str) -> Result<Vec<u8>, String> {
    let v = value.trim();
    let f: Vec<&str> = v.split_whitespace().collect();
    match t {
        RecordType::LOC => loc_parse(v),
        RecordType::RP => {
            if f.len() != 2 {
                return Err("RP value must be '<mailbox name> <TXT name>' (use . for none)".into());
            }
            let mut o = name_wire(f[0])?;
            o.extend(name_wire(f[1])?);
            Ok(o)
        }
        RecordType::AFSDB => {
            let sub: u16 = f
                .first()
                .and_then(|x| x.parse().ok())
                .filter(|_| f.len() == 2)
                .ok_or("AFSDB value must be '<subtype> <hostname>'")?;
            let mut o = sub.to_be_bytes().to_vec();
            o.extend(name_wire(f[1])?);
            Ok(o)
        }
        RecordType::URI => {
            let (p, rest) = v
                .split_once(char::is_whitespace)
                .ok_or("URI value must be '<priority> <weight> \"<target>\"'")?;
            let (w, target) = rest
                .trim()
                .split_once(char::is_whitespace)
                .ok_or("URI value must be '<priority> <weight> \"<target>\"'")?;
            let (p, w): (u16, u16) = (
                p.parse().map_err(|_| "URI priority must be 0-65535")?,
                w.parse().map_err(|_| "URI weight must be 0-65535")?,
            );
            let target = target.trim();
            if !(target.len() >= 2 && target.starts_with('"') && target.ends_with('"')) {
                return Err("the URI target must be quoted".into());
            }
            let s = char_strings(target)?;
            if s.len() != 1 || s[0].is_empty() {
                return Err("the URI target must be one non-empty quoted string".into());
            }
            let mut o = p.to_be_bytes().to_vec();
            o.extend(w.to_be_bytes());
            o.extend(&s[0]);
            Ok(o)
        }
        RecordType::SPF => {
            let s = char_strings(v)?;
            if s.is_empty() {
                return Err("SPF value must not be empty".into());
            }
            let mut o = Vec::new();
            for x in s {
                o.push(x.len() as u8);
                o.extend(x);
            }
            Ok(o)
        }
        RecordType::EUI48 => eui(v, 6),
        RecordType::EUI64 => eui(v, 8),
        _ => Err(format!("{} is not handled here", t.as_str())),
    }
}

/// The canonical presentation of wire RDATA (`None`: malformed).
pub fn format(t: RecordType, b: &[u8]) -> Option<String> {
    match t {
        RecordType::LOC => loc_format(b),
        RecordType::RP => {
            let (a, p) = read_name(b, 0)?;
            let (c, p) = read_name(b, p)?;
            (p == b.len()).then(|| format!("{a} {c}"))
        }
        RecordType::AFSDB => {
            let sub = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
            let (h, p) = read_name(b, 2)?;
            (p == b.len()).then(|| format!("{sub} {h}"))
        }
        RecordType::URI => {
            let p = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
            let w = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
            (b.len() > 4).then(|| format!("{p} {w} {}", quote(&b[4..])))
        }
        RecordType::SPF => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                let n = b[i] as usize;
                out.push(quote(b.get(i + 1..i + 1 + n)?));
                i += 1 + n;
            }
            (!out.is_empty()).then(|| out.join(" "))
        }
        RecordType::EUI48 | RecordType::EUI64 => {
            let n = if t == RecordType::EUI48 { 6 } else { 8 };
            (b.len() == n).then(|| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join("-")
            })
        }
        _ => None,
    }
}

/// Validate `value` and return its canonical form (what is stored).
pub fn normalize(t: RecordType, value: &str) -> Result<String, String> {
    let wire = parse(t, value)?;
    format(t, &wire).ok_or_else(|| "value does not encode".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire forms from dnspython 2.8 (`dns.rdata.from_text(...).to_wire()`),
    /// an independent implementation.
    #[test]
    fn wire_forms_match_dnspython() {
        for (t, text, hex) in [
            (
                RecordType::LOC,
                "42 21 54 N 71 06 18 W -24m 30m",
                "0033161389172dd070be15f000988d20",
            ),
            (
                RecordType::LOC,
                "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
                "000016138b3cf018810cbce0009895b8",
            ),
            (
                RecordType::RP,
                "mbox.example.com. txt.example.com.",
                "046d626f78076578616d706c6503636f6d0003747874076578616d706c6503636f6d00",
            ),
            (
                RecordType::AFSDB,
                "1 afs.example.com.",
                "000103616673076578616d706c6503636f6d00",
            ),
            (
                RecordType::URI,
                "10 1 \"https://example.com/path\"",
                "000a000168747470733a2f2f6578616d706c652e636f6d2f70617468",
            ),
            (
                RecordType::SPF,
                "\"v=spf1 -all\"",
                "0b763d73706631202d616c6c",
            ),
            (RecordType::EUI48, "00-00-5e-00-53-2a", "00005e00532a"),
            (
                RecordType::EUI64,
                "00-00-5e-ef-10-00-00-2a",
                "00005eef1000002a",
            ),
        ] {
            let w = parse(t, text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(hex::encode(&w), hex, "{} {text}", t.as_str());
            // Canonical text round-trips to the same wire.
            let canon = format(t, &w).unwrap();
            assert_eq!(parse(t, &canon).unwrap(), w, "{canon}");
        }
        assert_eq!(
            normalize(RecordType::LOC, "42 21 54 N 71 06 18 W -24m 30m").unwrap(),
            "42 21 54.000 N 71 6 18.000 W -24.00m 30.00m 10000.00m 10.00m",
            "dnspython's text form too"
        );
        assert_eq!(
            normalize(RecordType::EUI48, "00-00-5E-00-53-2A").unwrap(),
            "00-00-5e-00-53-2a"
        );
        assert_eq!(
            normalize(RecordType::SPF, "v=spf1 -all").unwrap(),
            "\"v=spf1 -all\""
        );
        assert_eq!(
            normalize(RecordType::RP, "Mbox.Example.COM . ").unwrap(),
            "mbox.example.com. ."
        );
    }

    #[test]
    fn invalid_values_are_refused() {
        for (t, v) in [
            (RecordType::LOC, "91 0 0 N 0 0 0 E 0m"),
            (RecordType::LOC, "42 21 54 X 71 06 18 W -24m"),
            (RecordType::LOC, "42 21 54 N 71 06 18 W"),
            (RecordType::LOC, "42 21 54 N 71 06 18 W 0m 1m 1m 1m 1m"),
            (RecordType::RP, "only.one."),
            (RecordType::AFSDB, "x host."),
            (RecordType::URI, "10 1 https://unquoted"),
            (RecordType::URI, "10 1 \"\""),
            (RecordType::EUI48, "00-00-5e-00-53"),
            (RecordType::EUI64, "zz-00-5e-ef-10-00-00-2a"),
            (RecordType::SPF, "\"unterminated"),
        ] {
            assert!(parse(t, v).is_err(), "{} {v}", t.as_str());
        }
        // Malformed wire does not format.
        assert!(format(RecordType::LOC, &[1; 16]).is_none());
        assert!(format(RecordType::EUI48, &[1; 5]).is_none());
    }
}
