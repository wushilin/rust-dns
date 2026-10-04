//! N1: DNSSEC key rollover wizard (CSK, manual DS steps at the registrar).
//!
//! Stages (state in the zone's key row, replicated; see
//! `replication::types::Rollover`):
//! 1. `prepublish`: a new key is published next to the old one, which keeps
//!    signing. After the DNSKEY TTL the console shows the new DS to add at
//!    the registrar NEXT TO the old one; the owner confirms ("ds-added").
//! 2. `ds_check`: the primary asks every parent server (RD=0) until all
//!    return the new DS, then waits the parent's DS TTL and switches.
//! 3. `switched`: the new key signs, the old DNSKEY stays published; the
//!    console names the old DS to delete. Once no parent server returns it
//!    and the DS TTL passed, the old key is unpublished: done.
//!
//! Cancel is allowed before the switch. Only the primary moves stages on
//! (its driver writes through the mutation layer, which a standby refuses);
//! a standby signs with the replicated key set. Starting is refused while a
//! following standby cannot represent a rollover (an older version).

use super::dnssec::{ds_views, self_check, DnssecCheck, DsRecordView};
use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, ConflictOrReadOnly, Forbidden, NotFound, Unauthorized};
use super::routes::ZonePath;
use super::session::Caller;
use super::AppState;
use crate::dnssec::parent::{self, ParentProbe};
use crate::dnssec::KeyInfo;
use crate::model::{Zone, ZonePerm};
use crate::mutation::RolloverStep;
use crate::replication::types::{ReplDnssecKey, RolloverStage};
use axum::extract::{Path, State};
use axum::Json;
use hickory_proto::rr::Name;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// What this server last learned while driving a rollover (memory only:
/// asked again after a restart).
#[derive(Default, Clone)]
struct Observed {
    probe: Option<ParentProbe>,
    probe_error: Option<String>,
    self_check: Option<DnssecCheck>,
}

fn observed() -> &'static Mutex<HashMap<String, Observed>> {
    static M: OnceLock<Mutex<HashMap<String, Observed>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

fn observe(zone: &str, f: impl FnOnce(&mut Observed)) {
    let mut m = observed().lock().unwrap_or_else(|p| p.into_inner());
    f(m.entry(zone.to_string()).or_default());
}

/// One key of a rollover with the DS records it needs at the parent.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloverKeyView {
    pub key_tag: u16,
    pub algorithm: u8,
    /// The DNSKEY record in zone-file form.
    pub dnskey: String,
    /// The DS records for this key (publish the SHA-256 one).
    pub ds: Vec<DsRecordView>,
}

/// A rollover's state and exactly what to do next.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloverView {
    pub zone: String,
    /// A rollover is in progress.
    pub active: bool,
    #[schema(required = true)]
    pub stage: Option<RolloverStage>,
    /// What happens next: `start`, `wait_dnskey_ttl`, `add_new_ds`,
    /// `wait_parent_new_ds`, `wait_ds_ttl_then_switch`, `remove_old_ds`,
    /// `wait_ds_ttl_then_retire`.
    pub next: String,
    /// Step-by-step instructions for the owner, in order.
    pub instructions: Vec<String>,
    #[schema(required = true, format = DateTime)]
    pub started_at: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub stage_at: Option<String>,
    /// End of the current wait.
    #[schema(required = true, format = DateTime)]
    pub wait_until: Option<String>,
    /// Seconds left of the current wait (0 when over).
    #[schema(required = true)]
    pub wait_remaining_secs: Option<i64>,
    #[schema(required = true)]
    pub dnskey_ttl: Option<u32>,
    #[schema(required = true)]
    pub ds_ttl: Option<u32>,
    /// When every parent server first showed what the stage waits for.
    #[schema(required = true, format = DateTime)]
    pub parent_ok_at: Option<String>,
    /// The key that signs now.
    #[schema(required = true)]
    pub signing_key_tag: Option<u16>,
    /// The new key (before the switch): its DS goes to the registrar.
    #[schema(required = true)]
    pub new_key: Option<RolloverKeyView>,
    /// The old key (after the switch): its DS must be removed.
    #[schema(required = true)]
    pub old_key: Option<RolloverKeyView>,
    /// Cancelling is possible (before the switch).
    pub can_cancel: bool,
    /// The last answer of every parent server (this server's memory; the
    /// primary asks every `[dnssec].rollover_check_secs` while waiting).
    #[schema(required = true)]
    pub parent: Option<ParentProbe>,
    #[schema(required = true)]
    pub parent_error: Option<String>,
    /// The self-check run after the switch (every RRset validates with the
    /// new key).
    #[schema(required = true)]
    pub self_check: Option<DnssecCheck>,
    /// Standbys that cannot follow a rollover (older versions): starting
    /// is refused until they are upgraded (or removed from the list).
    pub blocked_by: Vec<String>,
}

fn key_view(apex: &str, k: &KeyInfo) -> RolloverKeyView {
    RolloverKeyView {
        key_tag: k.key_tag,
        algorithm: k.algorithm,
        dnskey: k.dnskey_text(apex, 0).replacen(" 0 IN ", " IN ", 1),
        ds: ds_views(apex, k),
    }
}

fn other_key(k: &ReplDnssecKey) -> Option<KeyInfo> {
    let r = k.rollover.as_ref()?;
    Some(KeyInfo {
        key_tag: r.key.key_tag,
        algorithm: k.algorithm,
        flags: k.flags,
        public_key: data_encoding::BASE64
            .decode(r.key.public_key.as_bytes())
            .ok()?,
    })
}

/// Standbys known to this primary that cannot follow a rollover.
fn blocked_by(s: &AppState) -> Vec<String> {
    s.repl
        .replica_list()
        .into_iter()
        .filter(|r| !crate::replication::replicas::has_feature(&r.version, "dnssec-rollover"))
        .map(|r| {
            format!(
                "{} (version {})",
                r.instance,
                if r.version.is_empty() {
                    "unknown"
                } else {
                    &r.version
                }
            )
        })
        .collect()
}

/// Whole seconds until `t`, rounded up (0 only once it has passed).
fn secs_left(t: &chrono::DateTime<chrono::FixedOffset>) -> i64 {
    let ms = t.timestamp_millis() - chrono::Utc::now().timestamp_millis();
    if ms <= 0 {
        0
    } else {
        (ms + 999) / 1000
    }
}

fn fmt_secs(s: i64) -> String {
    if s >= 86400 {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    } else if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

fn view(s: &AppState, z: &Zone) -> ApiResult<RolloverView> {
    let apex = z.fqdn();
    let key = s.storage.get_dnssec_key(z.id)?;
    let obs = observed()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&z.name)
        .cloned()
        .unwrap_or_default();
    let mut v = RolloverView {
        zone: z.name.clone(),
        active: false,
        stage: None,
        next: "start".into(),
        instructions: vec![],
        started_at: None,
        stage_at: None,
        wait_until: None,
        wait_remaining_secs: None,
        dnskey_ttl: None,
        ds_ttl: None,
        parent_ok_at: None,
        signing_key_tag: key.as_ref().map(|k| k.key_tag),
        new_key: None,
        old_key: None,
        can_cancel: false,
        parent: None,
        parent_error: None,
        self_check: None,
        blocked_by: blocked_by(s),
    };
    let Some(k) = key else {
        v.instructions
            .push("Turn signing on first: a rollover replaces an existing key.".into());
        return Ok(v);
    };
    let Some(r) = k.rollover.clone() else {
        v.instructions.push(format!(
            "Start a rollover to replace key {} with a new key of the same algorithm. Nothing changes for resolvers until you change the DS at your registrar, and the wizard tells you exactly when and what.",
            k.key_tag
        ));
        if !v.blocked_by.is_empty() {
            v.instructions.push(format!(
                "Blocked: upgrade these standbys first (they cannot follow a rollover): {}.",
                v.blocked_by.join(", ")
            ));
        }
        return Ok(v);
    };
    let me = KeyInfo::from_stored(&k).map_err(ApiError::internal)?;
    let other = other_key(&k).ok_or_else(|| ApiError::internal("rollover key does not decode"))?;
    let remaining = r.wait_until.as_deref().and_then(|w| {
        chrono::DateTime::parse_from_rfc3339(w)
            .ok()
            .map(|t| secs_left(&t))
    });
    v.active = true;
    v.stage = Some(r.stage);
    v.started_at = Some(r.started_at.clone());
    v.stage_at = Some(r.stage_at.clone());
    v.wait_until = r.wait_until.clone();
    v.wait_remaining_secs = remaining;
    v.dnskey_ttl = Some(r.dnskey_ttl);
    v.ds_ttl = r.ds_ttl;
    v.parent_ok_at = r.parent_ok_at.clone();
    v.parent = obs.probe;
    v.parent_error = obs.probe_error;
    v.self_check = obs.self_check;
    let ds_line = |kv: &RolloverKeyView| {
        kv.ds
            .iter()
            .find(|d| d.recommended)
            .map(|d| {
                format!(
                    "key tag {}, algorithm {} (ECDSAP256SHA256), digest type {} ({}), digest {}  —  as one record: {}",
                    d.key_tag, d.algorithm, d.digest_type, d.digest_name, d.digest, d.record
                )
            })
            .unwrap_or_default()
    };
    match r.stage {
        RolloverStage::Prepublish | RolloverStage::DsCheck => {
            let new = key_view(&apex, &other);
            v.can_cancel = true;
            if r.stage == RolloverStage::Prepublish {
                if remaining.unwrap_or(0) > 0 {
                    v.next = "wait_dnskey_ttl".into();
                    v.instructions.push(format!(
                        "1. Both keys are published; key {} still signs. Wait {} (the DNSKEY TTL, {} s) so every resolver has the new key before its DS appears. Do not change anything at the registrar yet.",
                        me.key_tag,
                        fmt_secs(remaining.unwrap_or(0)),
                        r.dnskey_ttl
                    ));
                } else {
                    v.next = "add_new_ds".into();
                    v.instructions.push(format!(
                        "2. At your registrar, ADD this DS record for {apex} next to the existing one: {}",
                        ds_line(&new)
                    ));
                    v.instructions.push(format!(
                        "Do NOT remove the old DS (key tag {}) yet. When the new one is saved, press \"I've added it\".",
                        me.key_tag
                    ));
                }
            } else if r.parent_ok_at.is_none() {
                v.next = "wait_parent_new_ds".into();
                v.instructions.push(format!(
                    "3. Waiting until every server of the parent zone returns the new DS (key tag {}). This can take from minutes to an hour after you saved it at the registrar. If a server shows a DS that matches neither key, the field that differs is shown below: correct it at the registrar.",
                    other.key_tag
                ));
            } else {
                v.next = "wait_ds_ttl_then_switch".into();
                v.instructions.push(format!(
                    "3. Every parent server returns the new DS. Waiting {} (the parent's DS TTL) so no resolver still holds a DS set without it; then key {} starts signing automatically.",
                    fmt_secs(remaining.unwrap_or(0)),
                    other.key_tag
                ));
            }
            v.new_key = Some(new);
        }
        RolloverStage::Switched => {
            let old = key_view(&apex, &other);
            if r.parent_ok_at.is_none() {
                v.next = "remove_old_ds".into();
                v.instructions.push(format!(
                    "4. The new key {} signs the zone now (the old key stays published). At your registrar, DELETE this DS record for {apex} (the old key): {}",
                    me.key_tag,
                    ds_line(&old)
                ));
                v.instructions.push(format!(
                    "Keep the new DS (key tag {}). The wizard checks the parent until no server returns the old DS.",
                    me.key_tag
                ));
            } else {
                v.next = "wait_ds_ttl_then_retire".into();
                v.instructions.push(format!(
                    "5. No parent server returns the old DS any more. Waiting {} (the DS TTL); then the old key {} is unpublished and the rollover is done.",
                    fmt_secs(remaining.unwrap_or(0)),
                    other.key_tag
                ));
            }
            v.old_key = Some(old);
        }
    }
    Ok(v)
}

#[utoipa::path(
    get,
    path = "/zones/{zone}/dnssec/rollover",
    tag = "DNSSEC",
    operation_id = "get_key_rollover",
    summary = "Key rollover state and next step",
    description = "The rollover wizard's state: stage, timers (from the real DNSKEY and DS TTLs), the new or old DS with every field, what every parent server returned, and exactly what to do next. Needs the viewer role.",
    params(ZonePath),
    responses(
        (status = 200, description = "State.", body = RolloverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 404, response = NotFound),
    ),
)]
pub async fn get_rollover(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<RolloverView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::View)?;
    Ok(Json(view(&s, &z)?))
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/dnssec/rollover",
    tag = "DNSSEC",
    operation_id = "start_key_rollover",
    summary = "Start a key rollover",
    description = "Generates a new key of the same algorithm and publishes it next to the current one, which keeps signing (a serial bump). Then follow `GET .../rollover`. Refused (409) when signing is off, a rollover runs already, or a following standby is too old to represent it. Needs the owner role.",
    params(ZonePath),
    responses(
        (status = 200, description = "Started.", body = RolloverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = ConflictOrReadOnly),
    ),
)]
pub async fn start_rollover(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<RolloverView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    let blocked = blocked_by(&s);
    if !blocked.is_empty() {
        return Err(ApiError::conflict(format!(
            "these standbys cannot follow a key rollover (older versions): {}. Upgrade them first (or remove a standby that is gone from Replication > Standbys)",
            blocked.join(", ")
        )));
    }
    s.mutator.rollover_start(caller.actor(), &z.name).await?;
    observe(&z.name, |o| *o = Observed::default());
    let z = s.storage.get_zone(&z.name)?.unwrap_or(z);
    Ok(Json(view(&s, &z)?))
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/dnssec/rollover/ds-added",
    tag = "DNSSEC",
    operation_id = "key_rollover_ds_added",
    summary = "The new DS is added at the registrar",
    description = "Confirms that the new DS was added next to the old one (allowed once the DNSKEY TTL wait is over). The primary then checks every parent server until all return it. Needs the owner role.",
    params(ZonePath),
    responses(
        (status = 200, description = "Checking the parent.", body = RolloverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = ConflictOrReadOnly),
    ),
)]
pub async fn rollover_ds_added(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<RolloverView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    s.mutator.rollover_ds_added(caller.actor(), &z.name).await?;
    // Ask the parent at once (not only at the next driver round), without
    // making the caller wait for the parent's servers.
    let (st, name) = (s.clone(), z.name.clone());
    tokio::spawn(async move {
        drive_zone(&st, &name).await;
    });
    Ok(Json(view(&s, &z)?))
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/dnssec/rollover/cancel",
    tag = "DNSSEC",
    operation_id = "cancel_key_rollover",
    summary = "Cancel a key rollover (before the switch)",
    description = "Drops the new key (the old one never stopped signing; a serial bump). If the new DS was already added at the registrar, remove it there. Refused (409) after the switch to the new key. Needs the owner role.",
    params(ZonePath),
    responses(
        (status = 200, description = "Cancelled.", body = RolloverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = ConflictOrReadOnly),
    ),
)]
pub async fn cancel_rollover(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<RolloverView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    s.mutator.rollover_cancel(caller.actor(), &z.name).await?;
    observe(&z.name, |o| *o = Observed::default());
    Ok(Json(view(&s, &z)?))
}

#[utoipa::path(
    post,
    path = "/zones/{zone}/dnssec/rollover/check",
    tag = "DNSSEC",
    operation_id = "check_key_rollover",
    summary = "Ask the parent's servers now",
    description = "Runs the rollover's parent check at once instead of waiting for the next round (`[dnssec].rollover_check_secs`), and moves the rollover on when it can. Primary only. Needs the owner role.",
    params(ZonePath),
    responses(
        (status = 200, description = "State after the check.", body = RolloverView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = ConflictOrReadOnly),
    ),
)]
pub async fn check_rollover(
    State(s): St,
    caller: Caller,
    Path(ZonePath { zone }): Path<ZonePath>,
) -> ApiResult<Json<RolloverView>> {
    let (z, _) = s.require_zone(&caller, &zone, ZonePerm::EditSettings)?;
    if s.mutator.gate().read_only() {
        return Err(ApiError::read_only(
            "only the primary checks the parent and moves a rollover on".to_string(),
        ));
    }
    if tokio::time::timeout(Duration::from_secs(20), drive_zone(&s, &z.name))
        .await
        .is_err()
    {
        observe(&z.name, |o| {
            o.probe_error = Some("the parent's servers did not all answer within 20 s".into())
        });
    }
    let z = s.storage.get_zone(&z.name)?.unwrap_or(z);
    Ok(Json(view(&s, &z)?))
}

/// One round for one zone: ask the parent when the stage waits for it,
/// and move on when the parent and the clock allow. Returns when the next
/// round is due at the latest (a wait ending sooner than the check
/// interval).
async fn drive_zone(s: &AppState, zone: &str) -> Option<Duration> {
    let z = s.storage.get_zone(zone).ok().flatten()?;
    let key = s.storage.get_dnssec_key(z.id).ok().flatten()?;
    let r = key.rollover.clone()?;
    let cfg = s.reloader.current.load().dnssec.clone();
    let until_wait = |w: &Option<String>| {
        w.as_deref()
            .and_then(|w| chrono::DateTime::parse_from_rfc3339(w).ok())
            .map(|t| secs_left(&t) as u64)
    };
    let which = match r.stage {
        RolloverStage::Prepublish => return until_wait(&r.wait_until).map(Duration::from_secs),
        RolloverStage::DsCheck => "new",
        RolloverStage::Switched => "old",
    };
    let me = KeyInfo::from_stored(&key).ok()?;
    let other = other_key(&key)?;
    let (new, old) = if r.stage == RolloverStage::DsCheck {
        (other, Some(me))
    } else {
        (me, Some(other))
    };
    let apex = Name::from_ascii(z.fqdn()).ok()?;
    let fwd = s.dns.runtime.load_full().forwarding.clone();
    let probe = parent::probe(&fwd, &apex, cfg.parent_port, &new, old.as_ref()).await;
    let ok = match &probe {
        Ok(p) => {
            if which == "new" {
                p.all_have("new")
            } else {
                p.none_has("old")
            }
        }
        Err(_) => false,
    };
    let ds_ttl = probe
        .as_ref()
        .ok()
        .and_then(|p| p.ds_ttl())
        .or(r.ds_ttl)
        .unwrap_or(86_400);
    match probe {
        Ok(p) => observe(zone, |o| {
            o.probe = Some(p);
            o.probe_error = None;
        }),
        Err(e) => observe(zone, |o| o.probe_error = Some(e.to_string())),
    }
    let step = if ok {
        RolloverStep::ParentOk { ds_ttl }
    } else {
        RolloverStep::ParentNotOk
    };
    if let Err(e) = s.mutator.rollover_step(zone, step).await {
        tracing::warn!(zone, error = %e, "DNSSEC rollover: could not record the parent check");
        return None;
    }
    if ok {
        let last = match r.stage {
            RolloverStage::DsCheck => RolloverStep::Switch,
            _ => RolloverStep::Finish,
        };
        match s.mutator.rollover_step(zone, last).await {
            Ok(true) if last == RolloverStep::Switch => {
                tracing::info!(zone, "DNSSEC rollover: switched to the new key");
                // The catalog is rebuilt at commit; validate every sampled
                // RRset with the new key.
                let z = s.storage.get_zone(zone).ok().flatten()?;
                let check = self_check(s, &z).await.ok();
                if let Some(c) = &check {
                    if !c.ok {
                        tracing::error!(zone, "DNSSEC rollover: the self-check after the switch failed; see the zone's DNSSEC tab");
                    }
                }
                observe(zone, |o| {
                    o.self_check = check;
                    o.probe = None;
                });
                return Some(Duration::from_secs(1));
            }
            Ok(true) => {
                tracing::info!(zone, "DNSSEC rollover: done, the old key is retired");
                observe(zone, |o| *o = Observed::default());
                return None;
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(zone, error = %e, "DNSSEC rollover: could not move on"),
        }
    }
    let key = s.storage.get_dnssec_key(z.id).ok().flatten()?;
    let r = key.rollover?;
    until_wait(&r.wait_until).map(|w| Duration::from_secs(w.max(1)))
}

/// The primary's rollover driver: every `[dnssec].rollover_check_secs`
/// (sooner when a wait ends), one round per zone with a rollover. Does
/// nothing on a read-only server.
pub fn spawn_driver(s: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            let every =
                Duration::from_secs(s.reloader.current.load().dnssec.rollover_check_secs.max(1));
            let mut next = every;
            if !s.mutator.gate().read_only() {
                let zones: Vec<String> = s.storage.rollover_zones().unwrap_or_default();
                for zone in zones {
                    if let Some(d) = drive_zone(&s, &zone).await {
                        next = next.min(d);
                    }
                }
            }
            tokio::time::sleep(next.max(Duration::from_secs(1))).await;
        }
    });
}
