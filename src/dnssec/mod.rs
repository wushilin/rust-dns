//! DNSSEC online signing (RFC 4033-4035).
//!
//! Per zone and off by default. A zone with signing on has one Combined
//! Signing Key (flags 257, SEP) of algorithm 13 (ECDSA P-256 / SHA-256, the
//! default) or (O25) 15 (Ed25519, RFC 8080), chosen when the key is
//! generated, and NSEC (or, O24, NSEC3) denial of existence. The key is generated when signing is first
//! turned on, stored in `dnssec_keys` and replicated as an account-class
//! change (the private key never appears in the user-facing changelog, the
//! audit log or the logs).
//!
//! Signing happens in memory when the catalog is built ([`signed`]): every
//! authoritative RRset gets an RRSIG and every authoritative owner an NSEC.
//! Queries with DO=1 and zone transfers serve that signed view; queries
//! without DO are answered exactly as for an unsigned zone.
//!
//! Signature window: inception = one hour before the zone's signing epoch,
//! expiration = inception + validity. The epoch is `zones.signed_at`
//! (replicated: set when signing is turned on and by every re-sign), so the
//! window does not move when the zone's data changes and only the changed
//! RRsets need new signatures ([`signed`] reuses the others); every
//! rebuild, on the primary or a standby, uses the same window. A zone
//! signed before `signed_at` existed has none: its epoch is `updated_at`
//! (the old rule) until its next serial bump, which pins it to that value,
//! so the window served at an upgrade stays. The primary re-signs (a new
//! epoch and a serial bump through a `Tx`) once the signatures expire
//! within `resign_before_days`; a standby never writes, and signs in memory
//! with its own copy of the key (ECDSA signatures are randomised, so its
//! RRSIGs differ from the primary's but verify with the same DNSKEY;
//! Ed25519 signatures are deterministic, so they are byte-identical). If a
//! window gets close to expiry without a re-sign (a stopped primary, a
//! disconnected standby), the node signs from the current hour instead.

pub mod check;
pub mod parent;
pub mod signed;
#[cfg(test)]
mod vectors;
pub mod wire;

use crate::config::DnssecConfig;
use crate::replication::types::ReplDnssecKey;
use anyhow::{anyhow, Context, Result};
use hickory_proto::rr::Name;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ED25519,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

pub use signed::SignedZone;

/// ECDSA Curve P-256 with SHA-256 (RFC 6605): the default algorithm.
pub const ALGORITHM: u8 = 13;
/// O25: Ed25519 (RFC 8080).
pub const ED25519_ALGORITHM: u8 = 15;
/// The algorithms a zone key can be generated with.
pub const ALGORITHMS: [u8; 2] = [ALGORITHM, ED25519_ALGORITHM];

/// The mnemonic of a supported algorithm (RFC 8624 names).
pub fn algorithm_name(alg: u8) -> &'static str {
    match alg {
        ALGORITHM => "ECDSAP256SHA256",
        ED25519_ALGORITHM => "ED25519",
        _ => "unsupported",
    }
}

/// Verify a DNSSEC signature with a DNSKEY public key (its RDATA form:
/// x || y for algorithm 13, the 32-byte key for 15).
pub fn verify(algorithm: u8, public_key: &[u8], data: &[u8], sig: &[u8]) -> bool {
    match algorithm {
        ALGORITHM => {
            let mut pk = Vec::with_capacity(65);
            pk.push(4u8);
            pk.extend_from_slice(public_key);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk)
                .verify(data, sig)
                .is_ok()
        }
        ED25519_ALGORITHM => UnparsedPublicKey::new(&ED25519, public_key)
            .verify(data, sig)
            .is_ok(),
        _ => false,
    }
}
/// Zone Key + Secure Entry Point: one key signs everything (CSK).
pub const CSK_FLAGS: u16 = 257;
/// Signatures start this long before the zone's signing epoch (clock skew).
pub const INCEPTION_MARGIN_SECS: i64 = 3600;
/// DS digest types offered: SHA-256 (use this) and SHA-384.
pub const DS_DIGEST_TYPES: [u8; 2] = [2, 4];

/// A freshly generated key: PKCS#8 private key and the public key in its
/// DNSKEY form (64 bytes x || y for algorithm 13, 32 bytes for 15).
pub struct NewKey {
    pub pkcs8: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl std::fmt::Debug for NewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewKey { .. }")
    }
}

/// A new key of the default algorithm (13).
#[cfg(test)]
pub fn generate_key() -> Result<NewKey> {
    generate_key_for(ALGORITHM)
}

/// A new key of `algorithm` (13 or 15).
pub fn generate_key_for(algorithm: u8) -> Result<NewKey> {
    let rng = SystemRandom::new();
    if algorithm == ED25519_ALGORITHM {
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("Ed25519 key generation failed"))?;
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref())
            .map_err(|_| anyhow!("generated key does not load"))?;
        return Ok(NewKey {
            pkcs8: doc.as_ref().to_vec(),
            public_key: pair.public_key().as_ref().to_vec(),
        });
    }
    if algorithm != ALGORITHM {
        anyhow::bail!("unsupported DNSSEC algorithm {algorithm}");
    }
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| anyhow!("ECDSA P-256 key generation failed"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng)
        .map_err(|_| anyhow!("generated key does not load"))?;
    Ok(NewKey {
        pkcs8: doc.as_ref().to_vec(),
        public_key: pair.public_key().as_ref()[1..].to_vec(),
    })
}

/// A zone's signing key, loaded.
pub struct ZoneKey {
    pub zone_id: i64,
    pub algorithm: u8,
    pub flags: u16,
    pub key_tag: u16,
    /// The DNSKEY form: 64 bytes x || y (13), 32 bytes (15).
    pub public_key: Vec<u8>,
    pair: Pair,
    rng: SystemRandom,
}

enum Pair {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl std::fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneKey")
            .field("zone_id", &self.zone_id)
            .field("key_tag", &self.key_tag)
            .finish_non_exhaustive()
    }
}

impl ZoneKey {
    pub fn load(k: &ReplDnssecKey) -> Result<Self> {
        let pkcs8 = data_encoding::BASE64
            .decode(k.private_key.0.as_bytes())
            .context("private key is not base64")?;
        let rng = SystemRandom::new();
        let (pair, public_key) = match k.algorithm {
            ALGORITHM => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
                    .map_err(|_| anyhow!("private key does not load"))?;
                let pk = pair.public_key().as_ref()[1..].to_vec();
                (Pair::Ecdsa(pair), pk)
            }
            ED25519_ALGORITHM => {
                // v2 documents (what `generate_key_for` writes) are checked
                // against their public key; a v1 document (seed only) loads too.
                let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8)
                    .map_err(|_| anyhow!("private key does not load"))?;
                let pk = pair.public_key().as_ref().to_vec();
                (Pair::Ed25519(pair), pk)
            }
            a => anyhow::bail!("unsupported DNSSEC algorithm {a}"),
        };
        let stored = data_encoding::BASE64
            .decode(k.public_key.as_bytes())
            .context("public key is not base64")?;
        if stored != public_key {
            anyhow::bail!("stored public key does not match the private key");
        }
        let key_tag = wire::key_tag(&wire::dnskey_rdata(k.flags, k.algorithm, &public_key));
        if key_tag != k.key_tag {
            anyhow::bail!(
                "stored key tag {} does not match the key ({key_tag})",
                k.key_tag
            );
        }
        Ok(ZoneKey {
            zone_id: k.zone_id,
            algorithm: k.algorithm,
            flags: k.flags,
            key_tag,
            public_key,
            pair,
            rng,
        })
    }

    pub fn dnskey_rdata(&self) -> Vec<u8> {
        wire::dnskey_rdata(self.flags, self.algorithm, &self.public_key)
    }

    /// The signature field of an RRSIG: 64-byte r || s (RFC 6605 §4) for
    /// algorithm 13 (randomised), the 64-byte Ed25519 signature (RFC 8080
    /// §4, deterministic) for 15.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.pair {
            Pair::Ecdsa(p) => Ok(p
                .sign(&self.rng, data)
                .map_err(|_| anyhow!("ECDSA signing failed"))?
                .as_ref()
                .to_vec()),
            Pair::Ed25519(p) => Ok(p.sign(data).as_ref().to_vec()),
        }
    }
}

/// Public facts about a key: what the API and console show.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_tag: u16,
    pub algorithm: u8,
    pub flags: u16,
    pub public_key: Vec<u8>,
}

impl KeyInfo {
    pub fn from_stored(k: &ReplDnssecKey) -> Result<Self> {
        Ok(KeyInfo {
            key_tag: k.key_tag,
            algorithm: k.algorithm,
            flags: k.flags,
            public_key: data_encoding::BASE64
                .decode(k.public_key.as_bytes())
                .context("public key is not base64")?,
        })
    }

    pub fn dnskey_rdata(&self) -> Vec<u8> {
        wire::dnskey_rdata(self.flags, self.algorithm, &self.public_key)
    }

    /// `<apex> <ttl> IN DNSKEY 257 3 13 <base64>`.
    pub fn dnskey_text(&self, apex: &str, ttl: u32) -> String {
        format!(
            "{apex} {ttl} IN DNSKEY {} 3 {} {}",
            self.flags,
            self.algorithm,
            data_encoding::BASE64.encode(&self.public_key)
        )
    }

    /// (digest type, digest) for the zone apex.
    pub fn ds(&self, apex: &str, digest_type: u8) -> Option<Vec<u8>> {
        let owner = Name::from_ascii(apex).ok()?;
        wire::ds_digest(&owner, &self.dnskey_rdata(), digest_type)
    }
}

/// A signature window in seconds since the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub inception: i64,
    pub expiration: i64,
}

fn parse_ts(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp())
}

fn validity_secs(cfg: &DnssecConfig) -> i64 {
    cfg.signature_validity_days as i64 * 86400
}

fn resign_before_secs(cfg: &DnssecConfig) -> i64 {
    cfg.resign_before_days as i64 * 86400
}

/// The window for a zone with signing epoch `epoch`
/// ([`Zone::signing_epoch`](crate::model::Zone::signing_epoch)), signed at
/// `now`.
pub fn window(epoch: &str, now: i64, cfg: &DnssecConfig) -> Window {
    let validity = validity_secs(cfg);
    if let Some(changed) = parse_ts(epoch) {
        let inception = changed - INCEPTION_MARGIN_SECS;
        let expiration = inception + validity;
        // Deterministic per epoch while it has plenty of time left and is
        // not in the future (clock skew between servers).
        if expiration - now > resign_before_secs(cfg) / 2 && inception <= now - 300 {
            return Window {
                inception,
                expiration,
            };
        }
    }
    // Fallback: sign from the current hour (stable within the hour).
    let inception = now - now.rem_euclid(3600) - INCEPTION_MARGIN_SECS;
    Window {
        inception,
        expiration: inception + validity,
    }
}

/// When the primary must re-sign a zone with signing epoch `epoch`.
pub fn resign_due_at(epoch: &str, cfg: &DnssecConfig) -> Option<i64> {
    let changed = parse_ts(epoch)?;
    Some(changed - INCEPTION_MARGIN_SECS + validity_secs(cfg) - resign_before_secs(cfg))
}

pub fn ts_rfc3339(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Signing state shared by every catalog build: the `[dnssec]` settings,
/// signed zones reused while nothing they depend on changed, and the last
/// signing error per zone.
pub struct Signer {
    cfg: RwLock<DnssecConfig>,
    cache: Mutex<HashMap<i64, Arc<SignedZone>>>,
    errors: Mutex<HashMap<i64, String>>,
    /// Signatures computed since start (not the reused ones).
    signatures_made: std::sync::atomic::AtomicU64,
    /// O27: the transferred data of secondary zones, an input of every
    /// catalog build next to storage (each server transfers it itself).
    pub secondaries: Arc<crate::secondary::Store>,
}

impl Default for Signer {
    fn default() -> Self {
        Signer {
            cfg: RwLock::new(DnssecConfig::default()),
            cache: Mutex::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
            signatures_made: Default::default(),
            secondaries: Default::default(),
        }
    }
}

impl Signer {
    pub fn set_config(&self, cfg: DnssecConfig) {
        *self.cfg.write().unwrap_or_else(|p| p.into_inner()) = cfg;
    }

    pub fn config(&self) -> DnssecConfig {
        self.cfg.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Signatures computed since start.
    pub fn signatures_made(&self) -> u64 {
        self.signatures_made
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The signed view of a zone: the previous one when the fingerprint
    /// (zone row, served records, key, window) is unchanged; else built
    /// again, signing only the RRsets the previous one has no signature
    /// for (see [`signed`]).
    pub fn sign(
        &self,
        z: &crate::cache::ZoneData,
        key: &ReplDnssecKey,
        now: i64,
    ) -> Option<Arc<SignedZone>> {
        let cfg = self.config();
        let w = window(z.zone.signing_epoch(), now, &cfg);
        let fp = signed::fingerprint(z, key, &w);
        let prev = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.get(&z.zone.id).cloned()
        };
        if let Some(s) = &prev {
            if s.fingerprint == fp {
                return Some(s.clone());
            }
        }
        // N1: the other key of a rollover is published too (never signs).
        let also = match &key.rollover {
            Some(r) => match data_encoding::BASE64.decode(r.key.public_key.as_bytes()) {
                Ok(pk) => Some(wire::dnskey_rdata(key.flags, key.algorithm, &pk)),
                Err(_) => {
                    tracing::error!(zone = %z.zone.name, "DNSSEC: the rollover key's public key is not base64");
                    None
                }
            },
            None => None,
        };
        let result = ZoneKey::load(key)
            .and_then(|k| SignedZone::build_with(z, &k, also, w, fp, prev.as_deref()));
        match result {
            Ok(s) => {
                let s = Arc::new(s);
                self.signatures_made.fetch_add(
                    s.fresh_signatures as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                tracing::info!(zone = %z.zone.name, serial = z.zone.serial, key_tag = s.key_tag, rrsets = s.signed_rrsets, signed_now = s.fresh_signatures, reused = s.reused_signatures, names = s.chain_len(), inception = %ts_rfc3339(s.inception as i64), expiration = %ts_rfc3339(s.expiration as i64), "zone signed");
                self.cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(z.zone.id, s.clone());
                self.errors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&z.zone.id);
                Some(s)
            }
            Err(e) => {
                tracing::error!(zone = %z.zone.name, error = %e, "DNSSEC signing failed; the zone is served unsigned");
                self.errors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(z.zone.id, e.to_string());
                None
            }
        }
    }

    /// Forget one zone (deleted, or signing turned off).
    pub fn forget(&self, zone_id: i64) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&zone_id);
        self.errors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&zone_id);
    }

    /// Forget zones that are no longer signed.
    pub fn retain(&self, signed_zone_ids: &[i64]) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|id, _| signed_zone_ids.contains(id));
    }

    pub fn error(&self, zone_id: i64) -> Option<String> {
        self.errors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&zone_id)
            .cloned()
    }

    /// Would a rebuild now sign some zone with a different window than the
    /// one it is served with? (Signatures close to expiry without a serial
    /// bump: a standby cut off from its primary, or a primary that could
    /// not re-sign.)
    pub fn window_stale(&self, catalog: &crate::cache::Catalog, now: i64) -> bool {
        let cfg = self.config();
        catalog.zones.values().any(|z| match &z.signed {
            Some(s) => {
                let w = window(z.zone.signing_epoch(), now, &cfg);
                w.inception != s.inception as i64
                    || s.expiration as i64 - now <= resign_before_secs(&cfg) / 2
            }
            None => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_deterministic_per_change_and_falls_back() {
        let cfg = DnssecConfig::default();
        let changed = "2026-09-01T00:00:00.000Z";
        let t0 = parse_ts(changed).unwrap();
        let w1 = window(changed, t0 + 10, &cfg);
        assert_eq!(w1.inception, t0 - 3600);
        assert_eq!(w1.expiration, t0 - 3600 + 14 * 86400);
        let w2 = window(changed, t0 + 5 * 86400, &cfg);
        assert_eq!(w1, w2, "same serial, same window");
        // Re-sign is due 7 days before expiry.
        assert_eq!(resign_due_at(changed, &cfg).unwrap(), t0 - 3600 + 7 * 86400);
        // 11 days later (3.5 days before expiry) without a bump: fresh window.
        let late = t0 + 11 * 86400;
        let w3 = window(changed, late, &cfg);
        assert!(w3.inception > late - 2 * 3600 && w3.inception <= late - 3600);
        assert_eq!(w3.expiration - w3.inception, 14 * 86400);
        // A change "in the future" (clock skew) never yields a future inception.
        let w4 = window(changed, t0 - 7200, &cfg);
        assert!(w4.inception <= t0 - 7200 - 3600);
    }

    #[test]
    fn generated_key_loads_and_signs() {
        let k = generate_key().unwrap();
        assert_eq!(k.public_key.len(), 64);
        let rd = wire::dnskey_rdata(CSK_FLAGS, ALGORITHM, &k.public_key);
        let stored = ReplDnssecKey {
            zone_id: 1,
            zone: "example.com".into(),
            algorithm: ALGORITHM,
            flags: CSK_FLAGS,
            key_tag: wire::key_tag(&rd),
            public_key: data_encoding::BASE64.encode(&k.public_key),
            private_key: crate::replication::types::Hidden(data_encoding::BASE64.encode(&k.pkcs8)),
            created_at: "t".into(),
            rollover: None,
        };
        let zk = ZoneKey::load(&stored).unwrap();
        let sig = zk.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        let mut pk = vec![4u8];
        pk.extend(&k.public_key);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pk)
            .verify(b"hello", &sig)
            .unwrap();
        assert!(!format!("{zk:?}").contains(&stored.private_key.0));
        let mut bad = stored.clone();
        bad.key_tag ^= 1;
        assert!(ZoneKey::load(&bad).is_err());
    }

    #[test]
    fn generated_ed25519_key_loads_and_signs() {
        let k = generate_key_for(ED25519_ALGORITHM).unwrap();
        assert_eq!(k.public_key.len(), 32);
        let rd = wire::dnskey_rdata(CSK_FLAGS, ED25519_ALGORITHM, &k.public_key);
        let stored = ReplDnssecKey {
            zone_id: 1,
            zone: "example.com".into(),
            algorithm: ED25519_ALGORITHM,
            flags: CSK_FLAGS,
            key_tag: wire::key_tag(&rd),
            public_key: data_encoding::BASE64.encode(&k.public_key),
            private_key: crate::replication::types::Hidden(data_encoding::BASE64.encode(&k.pkcs8)),
            created_at: "t".into(),
            rollover: None,
        };
        let zk = ZoneKey::load(&stored).unwrap();
        let sig = zk.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, zk.sign(b"hello").unwrap(), "deterministic");
        assert!(verify(ED25519_ALGORITHM, &k.public_key, b"hello", &sig));
        assert!(!verify(ALGORITHM, &k.public_key, b"hello", &sig));
        // A key stored under the wrong algorithm does not load.
        let mut wrong = stored.clone();
        wrong.algorithm = ALGORITHM;
        assert!(ZoneKey::load(&wrong).is_err());
        assert!(generate_key_for(8).is_err());
        assert_eq!(algorithm_name(15), "ED25519");
    }
}
