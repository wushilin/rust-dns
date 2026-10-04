//! Replication API: what a standby pulls from its primary (snapshot,
//! changes, account data, checksums), the status of either side, the
//! public identity used by a returning old primary, and promotion.
//!
//! Everything except `identity` needs [`GlobalPerm::Replicate`]
//! (administrators). Snapshot and account answers carry password hashes,
//! TOTP secrets, token hashes and TSIG secrets: they are sent with
//! `Cache-Control: no-store` and never logged.

use super::error::{ApiError, ApiResult};
use super::openapi::{Conflict, Forbidden, InvalidRequest, NotFound, Unauthorized};
use super::session::Caller;
use super::AppState;
use crate::model::{Actor, GlobalPerm};
use crate::replication::data;
use crate::replication::replicas::{Report, Seen, HEADER_INSTANCE, HEADER_SESSION, HEADER_VERSION};
use crate::replication::types::*;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use utoipa::IntoParams;

type St = State<Arc<AppState>>;

/// Replication sources: writable primaries, and (O21) standbys that hold
/// their primary's data and have not halted. A halted standby answers with
/// the code `replication_halted`: the standbys that follow it halt too.
fn require_source(s: &AppState) -> ApiResult<()> {
    match s.repl.source_refusal() {
        None => Ok(()),
        Some(r) if r.halted => Err(ApiError::conflict(format!(
            "this server does not serve replication: {}",
            r.message
        ))
        .with_code(super::error::ErrorCode::ReplicationHalted)),
        Some(r) => Err(ApiError::read_only(format!(
            "this server does not serve replication: {}",
            r.message
        ))),
    }
}

/// The standby's identity headers (required on the data endpoints).
struct ReplicaHeaders {
    instance: String,
    version: String,
    session: String,
}

fn replica_headers(h: &HeaderMap, required: bool) -> ApiResult<Option<ReplicaHeaders>> {
    let get = |n: &str| {
        h.get(n)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let Some(instance) = get(HEADER_INSTANCE) else {
        if required {
            return Err(ApiError::bad_request(
                "missing X-Rust-DNS-Instance header: replication requests must name the standby ([follow].instance_id; rust-dns 0.1 standbys older than this version must be upgraded)",
            )
            .with_code(super::error::ErrorCode::InvalidRequest));
        }
        return Ok(None);
    };
    if let Some(p) = crate::replication::replicas::instance_id_problem(&instance) {
        return Err(ApiError::bad_request(format!(
            "X-Rust-DNS-Instance '{instance}' {p}"
        )));
    }
    Ok(Some(ReplicaHeaders {
        instance,
        version: get(HEADER_VERSION).unwrap_or_default(),
        session: get(HEADER_SESSION).unwrap_or_default(),
    }))
}

/// O25 / O27: the zones a standby of this version could not serve
/// correctly, with the reason: Ed25519-signed zones for a standby that does
/// not advertise `ed25519`, secondary zones for one without
/// `secondary-zones`. Read in the same transaction as the answer.
fn unsignable_for(c: &rusqlite::Connection, h: &ReplicaHeaders) -> anyhow::Result<Vec<String>> {
    use crate::replication::replicas::has_feature;
    let mut out = Vec::new();
    if !has_feature(&h.version, "ed25519") {
        out.extend(
            data::ed25519_signed_zones(c)?
                .into_iter()
                .map(|z| format!("{z} (signed with Ed25519, DNSSEC algorithm 15)")),
        );
    }
    if !has_feature(&h.version, "rrtypes-o28") {
        out.extend(
            data::o28_record_zones(c)?
                .into_iter()
                .map(|z| format!("{z} (LOC, RP, AFSDB, URI, SPF or EUI records)")),
        );
    }
    if !has_feature(&h.version, "secondary-zones") {
        out.extend(
            data::secondary_zones(c)?
                .into_iter()
                .map(|z| format!("{z} (a secondary zone)")),
        );
    }
    Ok(out)
}

/// O25 / O27: refuse (409: the standby keeps its data and retries, it does
/// not halt) a standby whose version cannot serve a zone of this server
/// correctly. An older binary would load an Ed25519 zone and serve it
/// unsigned (it logs "unsupported DNSSEC algorithm"; validating resolvers
/// reject it once a DS is published), and would store a secondary zone as
/// an empty zone of its own, answering NXDOMAIN for its names.
fn refuse_unsignable(zones: &[String], h: &ReplicaHeaders) -> ApiResult<()> {
    if zones.is_empty() {
        return Ok(());
    }
    tracing::warn!(standby = %h.instance, version = %h.version, zones = %zones.join(","), "replication refused: the standby cannot serve these zones");
    Err(ApiError::conflict(format!(
        "this server has zones that standby '{}' (version {}) cannot serve correctly: {}; upgrade the standby",
        h.instance,
        if h.version.is_empty() { "unknown" } else { &h.version },
        zones.join(", ")
    )))
}

fn note(s: &AppState, caller: &Caller, h: &ReplicaHeaders, report: Report) {
    let address = caller.ip.to_string();
    s.repl.note_replica(
        &Seen {
            instance: &h.instance,
            address: &address,
            session: &h.session,
            version: &h.version,
            user: &caller.user.username,
        },
        report,
    );
}

#[utoipa::path(
    get,
    path = "/replication/identity",
    tag = "Replication",
    operation_id = "get_replication_identity",
    summary = "Role and history of this server (public)",
    description = "No authentication. A primary with `[peer]` asks its standby this at startup and periodically: if the peer is writable and its `parent_history_id` is the asking server's history id, the peer was promoted and the asking server stays read-only (fenced). Contains no secrets and no data.",
    responses(
        (status = 200, description = "Identity.", body = Identity),
    ),
    security(()),
)]
pub async fn identity(State(s): St) -> Json<Identity> {
    Json(s.repl.identity())
}

#[utoipa::path(
    get,
    path = "/replication/status",
    tag = "Replication",
    operation_id = "get_replication_status",
    params(
        ("X-Rust-DNS-Instance" = Option<String>, Header, description = "Sent by standbys (their `[follow].instance_id`): the call counts as a sign of life.", example = "dns2"),
    ),
    summary = "Replication status (admin)",
    description = "Role (primary, promoted, standby, fenced), history, and on a standby the connection to the primary: applied offset, lag, last error, last snapshot and reconcile. On a primary: its replicas (standbys by instance id, with state and lag). A standby also calls this on its primary to validate its token. Needs `replicate`.",
    responses(
        (status = 200, description = "Status.", body = ReplicationStatus),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn status(
    State(s): St,
    caller: Caller,
    headers: HeaderMap,
) -> ApiResult<Json<ReplicationStatus>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    if let Some(rh) = replica_headers(&headers, false)? {
        note(&s, &caller, &rh, Report::Alive);
    }
    Ok(Json(s.repl.status()))
}

#[utoipa::path(
    get,
    path = "/replication/snapshot",
    tag = "Replication",
    operation_id = "get_replication_snapshot",
    params(
        ("X-Rust-DNS-Instance" = String, Header, description = "The standby's `[follow].instance_id` (a-z, 0-9, '-'; 1-63). Required.", example = "dns2"),
        ("X-Rust-DNS-Version" = Option<String>, Header, description = "The standby's rust-dns version, with what it can follow as build metadata (`+dnssec-rollover`).", example = "0.1.0+dnssec-rollover"),
        ("X-Rust-DNS-Session" = Option<String>, Header, description = "Random per standby process (detects two processes with one instance id).", example = "k3v9x2m1q8p0"),
    ),
    summary = "Consistent copy of all replicated data (admin, contains secrets)",
    description = "Zones, records (with expiry state), zone members, users (password hashes, MFA secrets and last TOTP step, recovery code hashes), API token hashes and tags, console settings, TSIG keys, the history and the changelog offset it corresponds to, all read in one transaction. A standby loads it to start and whenever it cannot continue from the changelog (afterwards every change, account changes included, arrives through `/replication/changes`). Sent gzip-compressed (`Content-Encoding: gzip`) when the request accepts it (`Accept-Encoding: gzip`; standbys of this version do, older ones get plain JSON). Needs `replicate`; refused (409) on a server that is not a writable primary or a standby that serves standbys (O21: one that loaded its primary's data; `replication_halted` when its replication halted).",
    responses(
        (status = 200, description = "Snapshot.", body = Snapshot),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn snapshot(State(s): St, caller: Caller, headers: HeaderMap) -> ApiResult<Response> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_source(&s)?;
    let rh = replica_headers(&headers, true)?.expect("required");
    note(&s, &caller, &rh, Report::Bootstrapping);
    let storage = s.storage.clone();
    let gzip = accepts_gzip(&headers);
    // O22: serialized (and compressed when the standby accepts gzip) off
    // the async workers: a snapshot is the whole database.
    let rh2 = ReplicaHeaders {
        instance: rh.instance.clone(),
        version: rh.version.clone(),
        session: String::new(),
    };
    let (offset, entities, body) = tokio::task::spawn_blocking(move || -> ApiResult<_> {
        let (snap, unsignable) =
            storage.read_tx(|c| Ok((data::snapshot(c)?, unsignable_for(c, &rh2)?)))?;
        refuse_unsignable(&unsignable, &rh2)?;
        let json = serde_json::to_vec(&snap).map_err(ApiError::internal)?;
        let body = if gzip {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(
                Vec::with_capacity(json.len() / 4),
                flate2::Compression::default(),
            );
            enc.write_all(&json).map_err(ApiError::internal)?;
            enc.finish().map_err(ApiError::internal)?
        } else {
            json
        };
        Ok((snap.offset, snap.entities.len(), body))
    })
    .await
    .map_err(ApiError::internal)??;
    tracing::info!(user = %caller.user.username, ip = %caller.ip, offset, entities, bytes = body.len(), gzip, "replication snapshot served");
    let mut resp = (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "application/json"),
            (header::VARY, "accept-encoding"),
        ],
        body,
    )
        .into_response();
    if gzip {
        resp.headers_mut().insert(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_static("gzip"),
        );
    }
    Ok(resp)
}

/// O22: does the request accept a gzip body (`Accept-Encoding`, `q` > 0)?
/// Standbys of this version send it for snapshots; older ones do not and
/// get plain JSON, as before.
fn accepts_gzip(h: &HeaderMap) -> bool {
    h.get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|item| {
            let mut parts = item.split(';').map(str::trim);
            let coding = parts.next().unwrap_or("");
            let q_zero = parts.any(|p| {
                p.strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            coding.eq_ignore_ascii_case("gzip") && !q_zero
        })
}

#[cfg(test)]
mod tests {
    use super::accepts_gzip;
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn gzip_is_negotiated_by_accept_encoding() {
        let h = |v: &[&str]| {
            let mut m = HeaderMap::new();
            for x in v {
                m.append(header::ACCEPT_ENCODING, HeaderValue::from_str(x).unwrap());
            }
            accepts_gzip(&m)
        };
        assert!(!h(&[]), "nothing sent: plain (older standbys)");
        assert!(h(&["gzip"]));
        assert!(h(&["br, GZIP;q=0.8"]));
        assert!(h(&["identity", "gzip"]));
        assert!(!h(&["gzip;q=0"]));
        assert!(!h(&["gzip; q=0.0, identity"]));
        assert!(!h(&["deflate, br"]));
        assert!(!h(&["x-gzip-not"]));
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ChangesQuery {
    /// Return changes after this offset (0: from the start).
    #[param(default = 0, minimum = 0)]
    pub after: Option<i64>,
    /// At most this many changes (extended to the end of the last
    /// transaction), 1-5000.
    #[param(default = 1000, minimum = 1, maximum = 5000)]
    pub limit: Option<usize>,
    /// Health probe of the standby: do not record `after` as its applied offset.
    #[param(default = false)]
    pub probe: Option<bool>,
    /// Seconds to wait for a change (or an account-data change) when there
    /// is none yet, 0-60.
    #[param(default = 0, minimum = 0, maximum = 60)]
    pub wait: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/replication/changes",
    tag = "Replication",
    operation_id = "get_replication_changes",
    summary = "Changes after an offset, long-poll (admin)",
    description = "Committed changelog entries after `after`, DNS and account changes in one sequence (account changes carry password hashes, TOTP and TSIG secrets and appear nowhere else), whole transactions only, with the history id and the latest offset. The `after` of each request is recorded as the standby's applied offset (a standby commits a batch before asking for the next), unless `probe=true`. With `wait`, an answer without changes is held until a change commits or the wait ends. `gap: true`: entries after `after` were pruned or scrubbed; load a snapshot. Needs `replicate`; refused (409) on a server that is not a writable primary or a standby that serves standbys (O21: one that loaded its primary's data; `replication_halted` when its replication halted).",
    params(
        ChangesQuery,
        ("X-Rust-DNS-Instance" = String, Header, description = "The standby's `[follow].instance_id` (a-z, 0-9, '-'; 1-63). Required.", example = "dns2"),
        ("X-Rust-DNS-Version" = Option<String>, Header, description = "The standby's rust-dns version, with what it can follow as build metadata (`+dnssec-rollover`).", example = "0.1.0+dnssec-rollover"),
        ("X-Rust-DNS-Session" = Option<String>, Header, description = "Random per standby process (detects two processes with one instance id).", example = "k3v9x2m1q8p0"),
    ),
    responses(
        (status = 200, description = "Changes.", body = ChangesResponse),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn changes(
    State(s): St,
    caller: Caller,
    headers: HeaderMap,
    Query(q): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_source(&s)?;
    let rh = replica_headers(&headers, true)?.expect("required");
    let after = q.after.unwrap_or(0);
    if after < 0 {
        return Err(ApiError::bad_request("after must be at least 0"));
    }
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(60));
    // A standby commits a batch before it asks for the next one: `after` is
    // the offset it has applied.
    note(
        &s,
        &caller,
        &rh,
        if q.probe.unwrap_or(false) {
            Report::Alive
        } else {
            Report::Applied(after)
        },
    );
    // Subscribe first so a commit between the read and the wait is not missed.
    let changes_rx = s.bus.subscribe_changes();
    let mut tick = s.repl.subscribe_changelog_tick();
    tick.borrow_and_update();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (history_id, head, oldest, mut events, unsignable) = s.storage.read_tx(|c| {
            Ok((
                data::history(c)?.history_id,
                data::changelog_head(c)?,
                data::changelog_oldest(c)?,
                data::changes_after(c, after, limit)?,
                unsignable_for(c, &rh)?,
            ))
        })?;
        refuse_unsignable(&unsignable, &rh)?;
        // A needed account change whose payload was scrubbed after
        // `[changelog].account_retention_days` is gone too.
        let scrubbed = events.iter().any(|e| e.payload["kind"] == "scrubbed");
        let gap = scrubbed
            || match oldest {
                Some(o) => after + 1 < o,
                None => after < head,
            };
        if gap {
            events.clear();
        }
        let done = !events.is_empty() || gap || tokio::time::Instant::now() >= deadline;
        if done {
            return Ok(Json(ChangesResponse {
                protocol: REPLICATION_PROTOCOL,
                history_id,
                head,
                oldest_offset: oldest,
                gap,
                events,
            }));
        }
        let changes_wait = async {
            match &changes_rx {
                Some(rx) => {
                    let _ = rx.recv_async().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = changes_wait => {}
            // Account changes are not on the event bus (they carry secrets).
            _ = tick.changed() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
        // Stop serving if this server stopped being a primary meanwhile.
        require_source(&s)?;
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ChecksumQuery {
    /// Leave this account out (the standby's own config root).
    #[param(example = "root")]
    pub exclude_user: Option<String>,
}

#[utoipa::path(
    get,
    path = "/replication/checksum",
    tag = "Replication",
    operation_id = "get_replication_checksum",
    summary = "Checksums of every replicated table and zone (admin)",
    description = "SHA-256 of every replicated table (per-server columns such as token last use left out, and the rows of the account named `exclude_user`: the standby's own root, which is local there) and serial and SHA-256 of every zone, at one changelog offset. A standby compares them periodically (`[follow].reconcile_interval_secs`) and re-bootstraps on a mismatch. Needs `replicate`; refused (409) on a server that is not a writable primary or a standby that serves standbys (O21: one that loaded its primary's data; `replication_halted` when its replication halted).",
    params(
        ChecksumQuery,
        ("X-Rust-DNS-Instance" = String, Header, description = "The standby's `[follow].instance_id` (a-z, 0-9, '-'; 1-63). Required.", example = "dns2"),
        ("X-Rust-DNS-Version" = Option<String>, Header, description = "The standby's rust-dns version, with what it can follow as build metadata (`+dnssec-rollover`).", example = "0.1.0+dnssec-rollover"),
        ("X-Rust-DNS-Session" = Option<String>, Header, description = "Random per standby process (detects two processes with one instance id).", example = "k3v9x2m1q8p0"),
    ),
    responses(
        (status = 200, description = "Checksums.", body = Checksums),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn checksum(
    State(s): St,
    caller: Caller,
    headers: HeaderMap,
    Query(q): Query<ChecksumQuery>,
) -> ApiResult<Json<Checksums>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_source(&s)?;
    let rh = replica_headers(&headers, true)?.expect("required");
    note(&s, &caller, &rh, Report::Alive);
    let storage = s.storage.clone();
    let root = q.exclude_user.unwrap_or_default();
    let out = tokio::task::spawn_blocking(move || {
        storage.read_tx(|c| {
            Ok(Checksums {
                history_id: data::history(c)?.history_id,
                offset: data::changelog_head(c)?,
                tables: crate::replication::tables::checksums(c, &root)?,
                zones: data::zone_checksums(c)?,
            })
        })
    })
    .await
    .map_err(ApiError::internal)??;
    Ok(Json(out))
}

#[utoipa::path(
    post,
    path = "/replication/promote",
    tag = "Replication",
    operation_id = "promote_standby",
    summary = "Promote this standby to primary (admin)",
    description = "Stops following, removes `[follow]` from the config file, starts a new history (parent: the old one, forked at the current offset), and accepts writes from now on. Refused (409) on a server that is not a standby, and while the primary is reachable unless `force` is true. Needs `replicate`. Audited as `replication.promote`.",
    request_body(content = PromoteBody, example = json!({ "confirm": true, "force": false })),
    responses(
        (status = 200, description = "Promoted.", body = PromoteResult),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn promote(
    State(s): St,
    caller: Caller,
    Json(body): Json<PromoteBody>,
) -> ApiResult<Json<PromoteResult>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    if !body.confirm {
        return Err(ApiError::bad_request(
            "set \"confirm\": true to promote this standby",
        ));
    }
    let actor = Actor {
        name: caller.user.username.clone(),
        ip: caller.ip.to_string(),
    };
    match s.repl.promote(actor, body.force, "api").await {
        Ok(r) => Ok(Json(r)),
        Err((409, m)) => Err(ApiError::conflict(m)),
        Err((_, m)) => {
            tracing::error!(error = %m, "promotion failed");
            Err(ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                m,
            ))
        }
    }
}

#[utoipa::path(
    get,
    path = "/replication/replicas",
    tag = "Replication",
    operation_id = "list_replicas",
    summary = "Standbys following this server (admin)",
    description = "Every standby known by its `[follow].instance_id`: state (`up_to_date`, `catching_up`, `falling_behind`, `offline`, `bootstrapping`; thresholds in `[replication]`), a `conflict` flag when two processes use one id, applied offset (the `after` of its last changes request), lag in changes and in seconds since it was last caught up, last seen, address, version. Kept in a local table across restarts; entries not seen for `[replication].forget_after_days` are dropped. Needs `replicate`.",
    responses(
        (status = 200, description = "Replicas, by instance id.", body = ReplicaList),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn list_replicas(State(s): St, caller: Caller) -> ApiResult<Json<ReplicaList>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    Ok(Json(ReplicaList {
        replicas: s.repl.replica_list(),
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct ReplicaPath {
    /// The standby's instance id.
    #[param(example = "dns2")]
    pub id: String,
}

#[utoipa::path(
    delete,
    path = "/replication/replicas/{id}",
    tag = "Replication",
    operation_id = "forget_replica",
    summary = "Forget a standby (admin)",
    description = "Removes the instance from the replica list (e.g. a decommissioned standby). A standby that is still running reappears at its next request. Local bookkeeping: audited as `replication.replica_forget`, not in the changelog and not replicated. Needs `replicate`.",
    params(ReplicaPath),
    responses(
        (status = 200, description = "Forgotten.", body = super::types::StatusResponse),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn forget_replica(
    State(s): St,
    caller: Caller,
    axum::extract::Path(p): axum::extract::Path<ReplicaPath>,
) -> ApiResult<Json<super::types::StatusResponse>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    let id = p.id.clone();
    let removed = s
        .accounts
        .run(&caller.actor(), "forget_replica", |t| t.forget_replica(&id))?;
    let known = s.repl.forget_replica(&p.id);
    if !removed && !known {
        return Err(ApiError::not_found(format!("no replica '{}'", p.id)));
    }
    Ok(Json(super::types::StatusResponse {
        status: super::types::StatusValue::Deleted,
    }))
}

#[utoipa::path(
    post,
    path = "/replication/replicas/{id}/report",
    tag = "Replication",
    operation_id = "report_replica",
    summary = "A standby reports that it stopped (admin)",
    description = "Sent by a standby whose replication halted (its data diverged from this primary: a bug), once when it halts and once at each start while halted, so the replica list shows it as `halted` with the reason. The `X-Rust-DNS-Instance` header must name the same instance. Local bookkeeping (not audited, not in the changelog). Needs `replicate`.",
    params(
        ReplicaPath,
        ("X-Rust-DNS-Instance" = String, Header, description = "The standby's `[follow].instance_id`; must equal `id`.", example = "dns2"),
        ("X-Rust-DNS-Version" = Option<String>, Header, description = "The standby's rust-dns version, with what it can follow as build metadata (`+dnssec-rollover`).", example = "0.1.0+dnssec-rollover"),
        ("X-Rust-DNS-Session" = Option<String>, Header, description = "Random per standby process.", example = "k3v9x2m1q8p0"),
    ),
    request_body(content = ReplicaReport, example = json!({ "state": "halted", "reason": "diverged", "detail": "reconcile at offset 1834 found data that differs from the primary: table users: differs (3 rows here, 3 on the primary)" })),
    responses(
        (status = 200, description = "Recorded.", body = super::types::StatusResponse),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn report_replica(
    State(s): St,
    caller: Caller,
    headers: HeaderMap,
    axum::extract::Path(p): axum::extract::Path<ReplicaPath>,
    Json(body): Json<ReplicaReport>,
) -> ApiResult<Json<super::types::StatusResponse>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    let rh = replica_headers(&headers, true)?.expect("required");
    if rh.instance != p.id {
        return Err(ApiError::bad_request(
            "X-Rust-DNS-Instance does not match the instance in the path",
        ));
    }
    if body.state != "halted" {
        return Err(ApiError::bad_request("state must be \"halted\""));
    }
    let reason: String = format!("{}: {}", body.reason, body.detail)
        .chars()
        .take(2000)
        .collect();
    tracing::error!(instance = %rh.instance, address = %caller.ip, reason = %reason, "a standby reports that its replication HALTED (its data diverged from this primary)");
    note(&s, &caller, &rh, Report::Halted(reason));
    Ok(Json(super::types::StatusResponse {
        status: super::types::StatusValue::Ok,
    }))
}
