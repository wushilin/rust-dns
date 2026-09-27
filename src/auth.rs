//! Passwords (Argon2id), TOTP (RFC 6238), random tokens and hashing helpers.

use anyhow::{anyhow, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn is_password_hash(s: &str) -> bool {
    s.starts_with("$argon2")
}

pub fn hash_password(pw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// URL-safe random token of `bytes` random bytes, base64url without padding.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    data_encoding::BASE64URL_NOPAD.encode(&buf)
}

/// Hex SHA-256 used to store session and API tokens.
pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Eight one-time recovery codes in `xxxxx-xxxxx` form (lower-case base32 alphabet).
pub fn recovery_codes() -> Vec<String> {
    (0..8)
        .map(|_| {
            let mut b = [0u8; 8];
            rand::rng().fill_bytes(&mut b);
            let s = data_encoding::BASE32_NOPAD.encode(&b).to_ascii_lowercase();
            format!("{}-{}", &s[..5], &s[5..10])
        })
        .collect()
}

/// Canonical form of a recovery code as typed by a user.
pub fn normalize_recovery_code(s: &str) -> String {
    s.trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

// ---- TOTP ------------------------------------------------------------------

pub fn totp_new_secret() -> String {
    let mut buf = [0u8; 20];
    rand::rng().fill_bytes(&mut buf);
    data_encoding::BASE32_NOPAD.encode(&buf)
}

pub fn totp_uri(issuer: &str, account: &str, secret: &str) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(account),
        secret,
        enc(issuer)
    )
}

fn totp_code(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | h[off + 3] as u32;
    bin % 1_000_000
}

/// Verify a 6-digit code against the secret, allowing one step of skew.
pub fn totp_verify(secret_b32: &str, code: &str) -> bool {
    let code = code.trim();
    let want: u32 = match code.parse() {
        Ok(v) if code.len() == 6 => v,
        _ => return false,
    };
    let secret =
        match data_encoding::BASE32_NOPAD.decode(secret_b32.trim_end_matches('=').as_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let step = now / 30;
    [step.wrapping_sub(1), step, step + 1]
        .iter()
        .any(|c| totp_code(&secret, *c) == want)
}

/// Render an otpauth URI as an inline SVG QR code.
pub fn qr_svg(data: &str) -> Option<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    let w = code.width();
    let colors = code.to_colors();
    let scale = 4;
    let quiet = 4;
    let size = (w + quiet * 2) * scale;
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path fill=\"#000\" d=\""
    );
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let px = (x + quiet) * scale;
                let py = (y + quiet) * scale;
                svg.push_str(&format!("M{px} {py}h{scale}v{scale}h-{scale}z"));
            }
        }
    }
    svg.push_str("\"/></svg>");
    Some(svg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("hunter2").unwrap();
        assert!(is_password_hash(&h));
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
        assert!(!verify_password("hunter2", "garbage"));
    }

    #[test]
    fn totp_rfc6238_vector() {
        // RFC 6238 test secret "12345678901234567890", SHA1, T=59 -> 94287082 (8 digits) => 6 digits 287082
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 1), 287082);
        assert_eq!(totp_code(secret, 1111111109 / 30), 81804);
    }

    #[test]
    fn totp_live() {
        let s = totp_new_secret();
        let secret = data_encoding::BASE32_NOPAD.decode(s.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = format!("{:06}", totp_code(&secret, now / 30));
        assert!(totp_verify(&s, &code));
        assert!(!totp_verify(&s, "000000") || code == "000000");
        assert!(!totp_verify(&s, "12345"));
    }

    #[test]
    fn qr() {
        let svg = qr_svg(&totp_uri("rust-dns", "root", "JBSWY3DPEHPK3PXP")).unwrap();
        assert!(svg.starts_with("<svg"));
    }
}
