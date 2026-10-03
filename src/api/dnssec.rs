//! DNSSEC per zone: status, turning signing on and off, the DS records to
//! publish at the registrar, a pre-publication self-check and a lookup of
//! the DS the parent publishes.
//!
//! Reading needs the viewer role; turning signing on or off needs the
//! owner role (`edit_settings`). The private key never leaves the server
//! through the API.

use super::error::{ApiError, ApiResult, ErrorCode};
use super::openapi::{BadRequest, Conflict, ConflictOrReadOnly, Forbidden, NotFound, Unauthorized};
use super::routes::ZonePath;
use super::session::Caller;
use super::AppState;
use crate::dnssec::check::{self, Expect, ParentDs};
use crate::dnssec::signed::{position, Position};
use crate::dnssec::{self as sec, KeyInfo};
use crate::model::{Zone, ZonePerm};
use axum::extract::{Path, State};
use axum::Json;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// The zone's signing key (public part only).
#[derive(Debug, Serialize, ToSchema)]
pub struct DnssecKeyView {
    pub key_tag: u16,
    /// 13 = ECDSA Curve P-256 with SHA-256.
    pub algorithm: u8,
    #[schema(example = "ECDSAP256SHA256")]
    pub algorithm_name: String,
    /// 257 = zone key and secure entry point (one combined signing key).
    pub flags: u16,
    /// Base64 public key (64 bytes).
    pub public_key: String,
    /// The DNSKEY record in zone-file form.
    pub dnskey: String,
    #[schema(format = DateTime)]
    pub created_at: String,
}

/// A DS record for the parent zone (the registrar).
#[derive(Debug, Serialize, ToSchema)]
pub struct DsRecordView {
    pub key_tag: u16,
    pub algorithm: u8,
    /// 2 = SHA-256 (publish this one), 4 = SHA-384.
    pub digest_type: u8,
    #[schema(example = "SHA-256")]
    pub digest_name: String,
    /// Hex, upper case.
    pub digest: String,
    /// `example.com. IN DS <key tag> 13 2 <digest>`.
    pub record: String,
    /// The one to publish unless the registrar asks for another digest.
    pub recommended: bool,
}

/// The signatures served now.
#[derive(Debug, Serialize, ToSchema)]
pub struct SignatureInfo {
    /// Zone serial they were computed for.
    #[schema(format = Int64, maximum = 4294967295_u64)]
    pub serial: u32,
    #[schema(format = DateTime)]
    pub inception: String,
    #[schema(format = DateTime)]
    pub expiration: String,
    /// When the primary re-signs (bumps the serial); null on a standby,
    /// which follows the primary's re-signs.
    #[schema(required = true, format = DateTime)]
    pub next_resign: Option<String>,
    /// RRsets signed (NSEC RRsets included).
    pub signed_rrsets: usize,
    /// Names in the NSEC chain.
    pub nsec_names: usize,
}

/// off | signing | error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DnssecState {
    /// Signing is off: answers are unsigned.
    Off,
    /// The zone is signed.
    Signing,
    /// Signing is on but failed (see `error`): answers are unsigned.
    Error,
}

/// DNSSEC status of a zone.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "zone": "example.com", "enabled": true, "state": "signing",
    "key": { "key_tag": 12345, "algorithm": 13, "algorithm_name": "ECDSAP256SHA256", "flags": 257,
             "public_key": "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
             "dnskey": "example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
             "created_at": "2026-01-15T09:30:00.000Z" },
    "ds": [{ "key_tag": 12345, "algorithm": 13, "digest_type": 2, "digest_name": "SHA-256",
             "digest": "3490A6806D47F17A34C29E2CE80E8A999FFBE4BE3A1C5B8BCCDE3CFB5A0BA3B5",
             "record": "example.com. IN DS 12345 13 2 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE3A1C5B8BCCDE3CFB5A0BA3B5", "recommended": true }],
    "signatures": { "serial": 2026011502, "inception": "2026-01-15T08:30:00Z", "expiration": "2026-01-29T08:30:00Z",
                    "next_resign": "2026-01-22T08:30:00Z", "signed_rrsets": 42, "nsec_names": 17 },
    "error": null, "signature_validity_days": 14, "resign_before_days": 7, "standby": false
}))]
pub struct DnssecStatus {
    pub zone: String,
    /// Signing is on for this zone.
    pub enabled: bool,
    pub state: DnssecState,
    /// Present once a key exists (signing was turned on at least once).
    #[schema(required = true)]
    pub key: Option<DnssecKeyView>,
    /// DS records for the registrar (empty without a key).
    pub ds: Vec<DsRecordView>,
    /// The signatures currently served (null when not signing).
    #[schema(required = true)]
    pub signatures: Option<SignatureInfo>,
    /// Why signing failed (state `error`).
    #[schema(required = true)]
    pub error: Option<String>,
    /// `[dnssec].signature_validity_days`.
    pub signature_validity_days: u32,
    /// `[dnssec].resign_before_days`.
    pub resign_before_days: u32,
    /// This server is a read-only standby: it signs in memory with the
    /// replicated key and never re-signs by itself.
    pub standby: bool,
}

/// Turn signing on or off.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DnssecInput {
    /// true: sign the zone (a key is generated the first time); false: stop
    /// signing (the key is kept, turning signing on again reuses it).
    pub enabled: bool,
    /// Turning off: skip the check that the parent publishes no DS. Only
    /// when the DS is already gone from the registrar and its TTL passed but
    /// the check cannot confirm it. With a DS still published, the zone
    /// fails to resolve for every validating resolver.
    #[serde(default)]
    #[schema(nullable = false)]
    pub force: Option<bool>,
    /// Turning on while off: replace the kept key with a new one (a new DS
    /// must then be published at the registrar).
    #[serde(default)]
    #[schema(nullable = false)]
    pub new_key: Option<bool>,
}

/// The DS records of the zone's key.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "zone": "example.com", "key_tag": 12345, "ds": [{ "key_tag": 12345, "algorithm": 13, "digest_type": 2, "digest_name": "SHA-256", "digest": "3490A6806D47F17A34C29E2CE80E8A999FFBE4BE3A1C5B8BCCDE3CFB5A0BA3B5", "record": "example.com. IN DS 12345 13 2 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE3A1C5B8BCCDE3CFB5A0BA3B5", "recommended": true }] }))]
pub struct DsList {
    pub zone: String,
    /// Null when the zone has no key yet.
    #[schema(required = true)]
    pub key_tag: Option<u16>,
    pub ds: Vec<DsRecordView>,
}

/// One query of the self-check.
#[derive(Debug, Serialize, ToSchema)]
pub struct DnssecCheckItem {
    /// e.g. `example.com. DNSKEY`.
    pub query: String,
    pub ok: bool,
    pub detail: String,
}

/// This server's own signed answers, validated with the zone's key.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "zone": "example.com", "ok": true, "key_tag": 12345, "checked_at": "2026-01-15T09:30:00.000Z",
    "checks": [{ "query": "example.com. DNSKEY", "ok": true, "detail": "NOERROR, 1 answer and 0 authority RRsets verified" }],
    "note": "These are this server's answers only; validating resolvers start checking once the DS is published at the parent." }))]
pub struct DnssecCheck {
    pub zone: String,
    /// Every check passed.
    pub ok: bool,
    pub key_tag: u16,
    #[schema(format = DateTime)]
    pub checked_at: String,
    pub checks: Vec<DnssecCheckItem>,
    pub note: String,
}

/// present | absent | mismatch | unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ParentDsState {
    /// The parent publishes a DS matching this zone's key: validating
    /// resolvers check the signatures.
    Present,
    /// The parent publishes no DS: resolvers treat the zone as unsigned.
    Absent,
    /// The parent publishes DS records, none for this zone's key: validating
    /// resolvers fail the zone (SERVFAIL).
    Mismatch,
    /// The lookup failed (no forwarding upstream, timeout, error).
    Unknown,
}

/// What the parent zone publishes, looked up through the forwarding upstream.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({ "zone": "example.com", "state": "absent", "detail": "no DS record for example.com. at the parent", "upstream": "1.1.1.1:53", "parent_ds": [], "expected": ["example.com. IN DS 12345 13 2 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE3A1C5B8BCCDE3CFB5A0BA3B5"] }))]
pub struct ParentDsCheck {
    pub zone: String,
    pub state: ParentDsState,
    pub detail: String,
    /// The resolver asked (the first forwarding upstream).
    #[schema(required = true)]
    pub upstream: Option<String>,
    /// DS records the parent publishes (presentation form).
    pub parent_ds: Vec<String>,
    /// DS records of this zone's key.
    pub expected: Vec<String>,
}

fn key_info(s: &AppState, z: &Zone) -> ApiResult<Option<(KeyInfo, String)>> {
    match s.storage.get_dnssec_key(z.id)? {
        Some(k) => Ok(Some((
            KeyInfo::from_stored(&k).map_err(ApiError::internal)?,
            k.created_at,
        ))),
        None => Ok(None),
    }
}

fn ds_views(apex: &str, k: &KeyInfo) -> Vec<DsRecordView> {
    sec::DS_DIGEST_TYPES
        .iter()
        .filter_map(|dt| {
            let digest = k.ds(apex, *dt)?;
            let text = sec::wire::ds_text(k.key_tag, k.algorithm, *dt, &digest);
            Some(DsRecordView {
                key_tag: k.key_tag,
                algorithm: k.algorithm,
                digest_type: *dt,
                digest_name: if *dt == 2 { "SHA-256" } else { "SHA-384" }.into(),
                digest: hex::encode_upper(&digest),
                record: format!("{apex} IN DS {text}"),
                recommended: *dt == 2,
            })
        })
        .collect()
}

fn status(s: &AppState, z: &Zone) -> ApiResult<DnssecStatus> {
    let apex = z.fqdn();
    let key = key_info(s, z)?;
    let cfg = s.mutator.signer().config();
    let standby = s.repl.read_only_reason().is_some();
    let catalog = s.cache.load();
    let signed = catalog.zones.get(&apex).and_then(|zd| {
        zd.signed.as_ref().map(|sz| SignatureInfo {
            serial: zd.zone.serial,
            inception: sec::ts_rfc3339(sz.inception as i64),
            expiration: sec::ts_rfc3339(sz.expiration as i64),
            next_resign: (!standby)
                .then(|| sec::resign_due_at(zd.zone.signing_epoch(), &cfg).map(sec::ts_rfc3339))
                .flatten(),
            signed_rrsets: sz.signed_rrsets,
            nsec_names: sz.chain_len(),
        })
    });
    let error = if z.dnssec && signed.is_none() {
        Some(
            s.mutator
                .signer()
                .error(z.id)
                .unwrap_or_else(|| "the zone is not signed yet".into()),
        )
    } else {
        None
    };
    let state = match (z.dnssec, &signed) {
        (false, _) => DnssecState::Off,
        (true, Some(_)) => DnssecState::Signing,
        (true, None) => DnssecState::Error,
    };
    Ok(DnssecStatus {
        zone: z.name.clone(),
        enabled: z.dnssec,
        state,
        ds: key
            .as_ref()
            .map(|(k, _)| ds_views(&apex, k))
            .unwrap_or_default(),
        key: key.map(|(k, created_at)| DnssecKeyView {
            key_tag: k.key_tag,
            algorithm: k.algorithm,
            algorithm_name: "ECDSAP256SHA256".into(),
            flags: k.flags,
            public_key: data_encoding::BASE64.encode(&k.public_key),
            dnskey: k.dnskey_text(&apex, z.default_ttl),
            created_at,
        }),
        signatures: signed,
        error,
        signature_validity_days: cfg.signature_validity_days,
        resign_before_days: cfg.resign_before_days,
        standby,
    })
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/dnssec",
    tag = "DNSSEC",
    operation_id = "get_dnssec",
    summary = "DNSSEC status of a zone",
    description = "Signing state, the key (public part), the DS records for the registrar and the signature window. Needs the viewer role.",
    params(ZonePath),
    responses(
        (status = 200, description = "Status.", body = DnssecStatus),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn get_dnssec(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<DnssecStatus>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    Ok(Json(status(&s, &z)?))
}

#[utoipa::path(
    put,
    path = "/zones/{zone}/dnssec",
    tag = "DNSSEC",
    operation_id = "set_dnssec",
    summary = "Turn DNSSEC signing on or off",
    description = "Needs the owner role. **On**: the zone is signed from now on (a key is generated the first time). Nothing changes for resolvers until the DS record is published at the registrar. **Off**: refused with 409 `ds_published` while the parent publishes a DS for the zone (or when that cannot be checked): remove the DS at the registrar first and wait for its TTL. `force: true` skips that check.",
    params(ZonePath),
    request_body(content = DnssecInput, example = json!({ "enabled": true })),
    responses(
        (status = 200, description = "New status.", body = DnssecStatus),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = ConflictOrReadOnly),
    ),
)]
pub async fn set_dnssec(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
    Json(input): Json<DnssecInput>,
) -> ApiResult<Json<DnssecStatus>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    let force = input.force.unwrap_or(false);
    if !input.enabled && z.dnssec {
        if force {
            tracing::warn!(zone = %z.name, actor = %caller.user.username, "DNSSEC: turning signing off with force (parent DS check skipped)");
        } else {
            let p = parent_check(&s, &z).await;
            let apex = z.fqdn();
            let why = match p.state {
                ParentDsState::Absent => None,
                ParentDsState::Present | ParentDsState::Mismatch => Some(format!(
                    "the parent zone publishes a DS record for {apex} ({}). Turning signing off now would make {apex} fail to resolve (SERVFAIL) for every validating resolver. Remove the DS record at your registrar first, wait until the parent's DS TTL has passed (often 1 to 2 days), then turn signing off",
                    p.parent_ds.join("; ")
                )),
                ParentDsState::Unknown => Some(format!(
                    "could not confirm that the parent zone publishes no DS record for {apex} ({}). If a DS is published, turning signing off makes {apex} fail for every validating resolver. Check at your registrar that no DS record is left and that its TTL has passed; the API accepts force: true to skip this check",
                    p.detail
                )),
            };
            if let Some(msg) = why {
                return Err(ApiError::conflict(msg).with_code(ErrorCode::DsPublished));
            }
        }
    }
    let out = s
        .mutator
        .set_dnssec(
            caller.actor(),
            &z.name,
            input.enabled,
            input.new_key.unwrap_or(false),
        )
        .await?;
    if out.changed || out.key_generated {
        tracing::info!(zone = %z.name, enabled = input.enabled, key_generated = out.key_generated, actor = %caller.user.username, "DNSSEC setting changed");
    }
    Ok(Json(status(&s, &out.zone)?))
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/dnssec/ds",
    tag = "DNSSEC",
    operation_id = "get_ds",
    summary = "DS records to publish at the registrar",
    description = "SHA-256 (digest type 2, publish this one) and SHA-384 (4) DS records of the zone's key. Empty before signing was ever turned on. Needs the viewer role.",
    params(ZonePath),
    responses(
        (status = 200, description = "DS records.", body = DsList),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn get_ds(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<DsList>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    let key = key_info(&s, &z)?;
    Ok(Json(DsList {
        zone: z.name.clone(),
        key_tag: key.as_ref().map(|(k, _)| k.key_tag),
        ds: key
            .map(|(k, _)| ds_views(&z.fqdn(), &k))
            .unwrap_or_default(),
    }))
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/dnssec/check",
    tag = "DNSSEC",
    operation_id = "check_dnssec",
    summary = "Check this server's signed answers (before adding the DS)",
    description = "Queries this server's own answers with the DO bit (DNSKEY, SOA, NS, a sample of names, a name that does not exist, a missing type) and validates every signature and denial-of-existence proof with the zone's key. Only this server is checked: other name servers of the zone are not. Needs the viewer role; 409 while signing is off.",
    params(ZonePath),
    responses(
        (status = 200, description = "Results.", body = DnssecCheck),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
        (status = 409, response = Conflict),
    ),
)]
pub async fn check_dnssec(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<DnssecCheck>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    if !z.dnssec {
        return Err(ApiError::conflict("signing is off for this zone"));
    }
    let Some((key, _)) = key_info(&s, &z)? else {
        return Err(ApiError::conflict("the zone has no DNSSEC key"));
    };
    let apex_s = z.fqdn();
    let apex = Name::from_ascii(&apex_s).map_err(ApiError::internal)?;
    let n = |s: &str| Name::from_ascii(s).ok();
    let mut probes: Vec<(Name, RecordType, Expect)> = vec![
        (apex.clone(), RecordType::DNSKEY, Expect::Answer),
        (apex.clone(), RecordType::SOA, Expect::Answer),
        (apex.clone(), RecordType::NS, Expect::Answer),
        (apex.clone(), RecordType::NULL, Expect::NoData),
    ];
    let catalog = s.cache.load();
    let mut note = "Only this server's answers are checked. Validating resolvers start checking the signatures once the DS record is published at the parent (registrar); other name servers of the zone must serve the same signed data (secondaries: zone transfer).".to_string();
    if let Some(zd) = catalog.zones.get(&apex_s) {
        let mut owners: Vec<&String> = zd.names.keys().filter(|o| **o != apex_s).collect();
        owners.sort();
        let mut sampled = 0;
        for owner in owners {
            if sampled >= 12 {
                break;
            }
            let pos = position(zd, owner);
            let first = zd.names[owner].first().map(|r| r.rtype);
            match (pos, first) {
                (Position::Authoritative, Some(t)) => {
                    let name = match owner.strip_prefix("*.") {
                        Some(rest) => n(&format!("rust-dns-check.{rest}")),
                        None => n(owner),
                    };
                    if let Some(name) = name {
                        probes.push((name, t.to_hickory(), Expect::Answer));
                        sampled += 1;
                    }
                }
                (Position::Cut, _) => {
                    let has_ds = zd.names[owner]
                        .iter()
                        .any(|r| r.rtype == crate::model::RecordType::DS);
                    if let Some(name) = n(owner) {
                        probes.push((
                            name,
                            RecordType::DS,
                            if has_ds {
                                Expect::Answer
                            } else {
                                Expect::NoData
                            },
                        ));
                        sampled += 1;
                    }
                }
                _ => {}
            }
        }
        if zd.records_at(&format!("*.{apex_s}")).is_none() {
            let label = format!("rust-dns-check-{:08x}", rand::random::<u32>());
            if let Some(name) = n(&format!("{label}.{apex_s}")) {
                probes.push((name, RecordType::A, Expect::NxDomain));
            }
        } else {
            note.push_str(" The zone has a wildcard at the apex, so no name is missing there: the NXDOMAIN proof was not checked.");
        }
    }
    let now = chrono::Utc::now().timestamp() as u32;
    let mut checks = Vec::new();
    for (name, t, expect) in probes {
        let q = check::query_bytes(&name, t, false, false);
        let result = match s.dns.answer_internal(&q).await {
            Some(resp) => check::validate_response(&resp, &name, t, &apex, &key, now, expect),
            None => Err("no answer".into()),
        };
        checks.push(DnssecCheckItem {
            query: format!("{name} {t}"),
            ok: result.is_ok(),
            detail: result.unwrap_or_else(|e| e),
        });
    }
    Ok(Json(DnssecCheck {
        zone: z.name.clone(),
        ok: checks.iter().all(|c| c.ok),
        key_tag: key.key_tag,
        checked_at: crate::model::now_rfc3339(),
        checks,
        note,
    }))
}

/// Ask the first forwarding upstream for the zone's DS (RD, CD, DO).
pub async fn parent_check(s: &AppState, z: &Zone) -> ParentDsCheck {
    let apex_s = z.fqdn();
    let key = key_info(s, z).ok().flatten().map(|(k, _)| k);
    let expected = key
        .as_ref()
        .map(|k| ds_views(&apex_s, k).into_iter().map(|d| d.record).collect())
        .unwrap_or_default();
    let mut out = ParentDsCheck {
        zone: z.name.clone(),
        state: ParentDsState::Unknown,
        detail: String::new(),
        upstream: None,
        parent_ds: vec![],
        expected,
    };
    let rt = s.dns.runtime.load_full();
    let Some(first) = rt.forwarding.upstreams.first() else {
        out.detail = format!("no forwarding upstream is configured to look it up (Server settings > Forwarding); check at the registrar, or run: dig +short DS {apex_s}");
        return out;
    };
    out.upstream = Some(first.to_string());
    let Ok(apex) = Name::from_ascii(&apex_s) else {
        out.detail = "invalid zone name".into();
        return out;
    };
    let q = check::query_bytes(&apex, RecordType::DS, true, true);
    let reply = crate::dns::forward::forward(&rt.forwarding, &q, crate::dns::Proto::Udp).await;
    let m = match reply.map(|b| Message::from_bytes(&b)) {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            out.detail = format!("unparsable answer from the upstream: {e}");
            return out;
        }
        Err(e) => {
            out.detail = format!("the upstream did not answer: {e}");
            return out;
        }
    };
    match m.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            out.state = ParentDsState::Absent;
            out.detail = format!(
                "the parent says {apex_s} does not exist (NXDOMAIN), so it publishes no DS for it"
            );
            return out;
        }
        rc => {
            out.detail = format!("the upstream answered {rc}");
            return out;
        }
    }
    match check::compare_parent_ds(&m, &apex, key.as_ref()) {
        ParentDs::Absent => {
            out.state = ParentDsState::Absent;
            out.detail = format!("no DS record for {apex_s} at the parent");
        }
        ParentDs::Present(ds) => {
            out.state = ParentDsState::Present;
            out.detail = format!("the parent publishes a DS for {apex_s} that matches this zone's key: validating resolvers check the signatures");
            out.parent_ds = ds;
        }
        ParentDs::Mismatch(ds) => {
            out.state = ParentDsState::Mismatch;
            out.detail = format!("the parent publishes DS records for {apex_s} but none matches this zone's key: validating resolvers fail the zone (SERVFAIL)");
            out.parent_ds = ds;
        }
    }
    out
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/dnssec/parent",
    tag = "DNSSEC",
    operation_id = "get_parent_ds",
    summary = "Is the DS published at the parent?",
    description = "Looks up the zone's DS record through the first forwarding upstream (a recursive resolver) and compares it with the zone's key: `present` (matches), `absent`, `mismatch` (a DS for another key: validating resolvers fail the zone) or `unknown` (no upstream configured, or the lookup failed). Needs the viewer role.",
    params(ZonePath),
    responses(
        (status = 200, description = "What the parent publishes.", body = ParentDsCheck),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn get_parent_ds(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<ParentDsCheck>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    Ok(Json(parent_check(&s, &z).await))
}
