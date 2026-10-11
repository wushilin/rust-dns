//! Replication API: the status of either side, the public identity used
//! by a returning old primary, the replica list, promotion and rebootstrap.
//! The data itself travels over changelog v2 (`/rust-dns/changelog-api/v2`,
//! served by `crates/sqlite-cdc`, behind the same `replicate` permission).
//!
//! Everything except `identity` needs [`GlobalPerm::Replicate`]
//! (administrators).

use super::error::{ApiError, ApiResult};
use super::openapi::{Conflict, Forbidden, InvalidRequest, NotFound, Unauthorized};
use super::session::Caller;
use super::AppState;
use crate::model::{Actor, GlobalPerm};
use crate::replication::types::*;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use utoipa::IntoParams;

type St = State<Arc<AppState>>;

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
    description = "Role (primary, promoted, standby, fenced), history, and on a standby the connection to the primary: applied offset, lag, last error, last snapshot and reconcile. On a primary: its replicas (standbys by instance id, with state and lag). Needs `replicate`.",
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
    description = "Every standby following this server's changelog v2, by its `[follow].instance_id`: state (`up_to_date`, `catching_up`, `falling_behind`, `offline`, `bootstrapping`; thresholds in `[replication]`), applied position (v2 transaction), lag in transactions and in seconds, last seen, address, the token user. Kept in memory; a standby not seen for a day is dropped. Needs `replicate`.",
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
    description = "Removes an entry stored by an earlier version (before changelog v2) from the local replica table. The live list of changelog v2 followers cannot be edited: it drops a standby by itself a day after its last request (409 while it is listed). Local bookkeeping: audited as `replication.replica_forget`, not replicated. Needs `replicate`.",
    params(ReplicaPath),
    responses(
        (status = 200, description = "Forgotten.", body = super::types::StatusResponse),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 409, response = Conflict),
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
    if !removed {
        if s.repl.knows_replica(&p.id) {
            return Err(ApiError::conflict(format!(
                "standby '{}' follows this server's changelog v2: it stays listed while it follows, and is dropped a day after its last request",
                p.id
            )));
        }
        return Err(ApiError::not_found(format!("no replica '{}'", p.id)));
    }
    Ok(Json(super::types::StatusResponse {
        status: super::types::StatusValue::Deleted,
    }))
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct RebootstrapResult {
    pub message: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RebootstrapBody {
    /// Must be true.
    pub confirm: bool,
    /// New primary URL (default: the current `[follow] primary`).
    #[serde(default)]
    pub primary: Option<String>,
    /// New replication token (default: the current one).
    #[serde(default)]
    pub token: Option<String>,
    /// New instance id (default: the current one).
    #[serde(default)]
    pub instance_id: Option<String>,
}

#[utoipa::path(
    post,
    path = "/replication/rebootstrap",
    tag = "Replication",
    operation_id = "rebootstrap_standby",
    summary = "Replace this standby's data with a fresh snapshot of the primary (admin)",
    description = "Changelog v2. Atomic: the standby keeps serving its data until the snapshot replaces every replicated table in one transaction; a halt is cleared. Optional `primary`, `token`, `instance_id` repoint it (the config file's `[follow]` is rewritten first). Also turns a fenced old primary into a standby. Returns once the snapshot started loading; the replication status shows progress. Users signed in with an account that is not on the primary are signed out. Needs `replicate`. Audited as `replication.rebootstrap`.",
    request_body(content = RebootstrapBody, example = json!({ "confirm": true })),
    responses(
        (status = 200, description = "Started.", body = RebootstrapResult),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 409, response = Conflict),
    ),
)]
pub async fn rebootstrap(
    State(s): St,
    caller: Caller,
    Json(body): Json<RebootstrapBody>,
) -> ApiResult<Json<RebootstrapResult>> {
    s.require(&caller, GlobalPerm::Replicate)?;
    if !body.confirm {
        return Err(ApiError::bad_request(
            "set \"confirm\": true to rebootstrap this standby",
        ));
    }
    let actor = Actor {
        name: caller.user.username.clone(),
        ip: caller.ip.to_string(),
    };
    match s
        .repl
        .rebootstrap(actor, body.primary, body.token, body.instance_id)
        .await
    {
        Ok(message) => Ok(Json(RebootstrapResult { message })),
        Err((400, m)) => Err(ApiError::bad_request(m)),
        Err((409, m)) => Err(ApiError::conflict(m)),
        Err((_, m)) => Err(ApiError::new(axum::http::StatusCode::BAD_GATEWAY, m)),
    }
}
