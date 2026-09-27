//! Replication API: what a standby pulls from its primary (snapshot,
//! changes, account data, checksums), the status of either side, the
//! public identity used by a returning old primary, and promotion.
//!
//! Everything except `identity` needs [`GlobalPerm::Replicate`]
//! (administrators). Snapshot and account answers carry password hashes,
//! TOTP secrets, token hashes and TSIG secrets: they are sent with
//! `Cache-Control: no-store` and never logged.

use super::error::{ApiError, ApiResult};
use super::openapi::{Conflict, Forbidden, InvalidRequest, Unauthorized};
use super::session::Caller;
use super::AppState;
use crate::model::{Actor, GlobalPerm};
use crate::replication::data;
use crate::replication::types::*;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use utoipa::IntoParams;

type St = State<Arc<AppState>>;

/// Replication sources must be writable primaries.
fn require_primary(s: &AppState) -> ApiResult<()> {
    match s.repl.read_only_reason() {
        None => Ok(()),
        Some(why) => Err(ApiError::read_only(format!(
            "this server does not serve replication: {why}"
        ))),
    }
}

fn no_store<T: serde::Serialize>(v: T) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response()
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
    summary = "Replication status (admin)",
    description = "Role (primary, promoted, standby, fenced), history, and on a standby the connection to the primary: applied offset, lag, last error, last snapshot and reconcile. On a primary: the standbys that polled it in the last 10 minutes. A standby also calls this on its primary to validate its token. Needs `replicate`.",
    responses(
        (status = 200, description = "Status.", body = ReplicationStatus),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn status(State(s): St, caller: Caller) -> ApiResult<Json<ReplicationStatus>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    Ok(Json(s.repl.status()))
}

#[utoipa::path(
    get,
    path = "/replication/snapshot",
    tag = "Replication",
    operation_id = "get_replication_snapshot",
    summary = "Consistent copy of all replicated data (admin, contains secrets)",
    description = "Zones, records (with expiry state), zone members, users (password hashes, MFA secrets and last TOTP step, recovery code hashes), API token hashes and tags, console settings, TSIG keys, the history and the changelog offset it corresponds to, all read in one transaction. A standby loads it to start and whenever it cannot continue from the changelog. Needs `replicate`; refused (409) on a server that is not a writable primary.",
    responses(
        (status = 200, description = "Snapshot.", body = Snapshot),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn snapshot(State(s): St, caller: Caller) -> ApiResult<Response> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_primary(&s)?;
    let generation = s.repl.generation();
    let storage = s.storage.clone();
    let snap =
        tokio::task::spawn_blocking(move || storage.read_tx(|c| data::snapshot(c, &generation)))
            .await
            .map_err(ApiError::internal)??;
    tracing::info!(user = %caller.user.username, ip = %caller.ip, offset = snap.offset, zones = snap.zones.len(), records = snap.records.len(), "replication snapshot served");
    Ok(no_store(snap))
}

#[utoipa::path(
    get,
    path = "/replication/accounts",
    tag = "Replication",
    operation_id = "get_replication_accounts",
    summary = "Account data, settings and TSIG keys (admin, contains secrets)",
    description = "The replicated data that is not in the DNS changelog. A standby fetches it whenever `accounts_generation` in a changes answer moves. Needs `replicate`; refused (409) on a server that is not a writable primary.",
    responses(
        (status = 200, description = "Account data.", body = AccountsSnapshot),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn accounts(State(s): St, caller: Caller) -> ApiResult<Response> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_primary(&s)?;
    let generation = s.repl.generation();
    let acc = s.storage.read_tx(|c| data::accounts(c, &generation))?;
    Ok(no_store(acc))
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
    description = "Committed changelog entries after `after`, whole transactions only, with the history id, the latest offset, and the account-data generation. With `wait`, an answer without changes is held until a change commits, account data changes, or the wait ends. `gap: true`: the entries after `after` were pruned; load a snapshot. Needs `replicate`; refused (409) on a server that is not a writable primary.",
    params(ChangesQuery),
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
    Query(q): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_primary(&s)?;
    let after = q.after.unwrap_or(0);
    if after < 0 {
        return Err(ApiError::bad_request("after must be at least 0"));
    }
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(60));
    s.repl
        .note_standby(caller.ip.to_string(), caller.user.username.clone(), after);
    // Subscribe first so a commit between the read and the wait is not missed.
    let changes_rx = s.bus.subscribe_changes();
    let mut gen_rx = s.repl.subscribe_generation();
    gen_rx.borrow_and_update();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let generation = s.repl.generation();
        let (history_id, head, oldest, events) = s.storage.read_tx(|c| {
            Ok((
                data::history(c)?.history_id,
                data::changelog_head(c)?,
                data::changelog_oldest(c)?,
                data::changes_after(c, after, limit)?,
            ))
        })?;
        let gap = match oldest {
            Some(o) => after + 1 < o,
            None => after < head,
        };
        let done = !events.is_empty() || gap || tokio::time::Instant::now() >= deadline;
        if done {
            return Ok(Json(ChangesResponse {
                history_id,
                head,
                oldest_offset: oldest,
                gap,
                events,
                accounts_generation: generation,
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
            r = gen_rx.changed() => {
                if r.is_ok() {
                    // Account data changed: answer now (no events) so the
                    // standby fetches it.
                    return Ok(Json(ChangesResponse {
                        history_id,
                        head,
                        oldest_offset: oldest,
                        gap,
                        events: Vec::new(),
                        accounts_generation: s.repl.generation(),
                    }));
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
        // Stop serving if this server stopped being a primary meanwhile.
        require_primary(&s)?;
    }
}

#[utoipa::path(
    get,
    path = "/replication/checksum",
    tag = "Replication",
    operation_id = "get_replication_checksum",
    summary = "Per-zone and account-data checksums (admin)",
    description = "Serial and SHA-256 of every zone (zone row, records with expiry state, members) and of the account data, at one changelog offset. A standby compares them periodically (`[follow].reconcile_interval_secs`) and re-bootstraps on a mismatch. Needs `replicate`; refused (409) on a server that is not a writable primary.",
    responses(
        (status = 200, description = "Checksums.", body = Checksums),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn checksum(State(s): St, caller: Caller) -> ApiResult<Json<Checksums>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    require_primary(&s)?;
    let generation = s.repl.generation();
    let storage = s.storage.clone();
    let out = tokio::task::spawn_blocking(move || {
        storage.read_tx(|c| {
            Ok(Checksums {
                history_id: data::history(c)?.history_id,
                offset: data::changelog_head(c)?,
                zones: data::zone_checksums(c)?,
                accounts_checksum: data::accounts(c, &generation)?.checksum,
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
