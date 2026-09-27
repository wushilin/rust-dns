//! Realtime stream: change events (resumable by offset) and live queries.

use super::openapi::{InvalidRequest, Unauthorized};
use super::session::Caller;
use super::AppState;
use crate::model::ZonePerm;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WsQuery {
    /// Replay change events after this offset first (WAL-style cursor).
    pub after: Option<i64>,
    /// Also stream live DNS queries.
    #[param(default = false)]
    pub queries: Option<bool>,
}

/// Realtime stream. The `token` query parameter is read by the `Caller`
/// extractor (only on this path), so it is declared here, not in `WsQuery`.
#[utoipa::path(
    get,
    path = "/ws",
    tag = "Change log",
    operation_id = "websocket",
    summary = "WebSocket stream (not callable from Swagger UI)",
    description = "WebSocket upgrade; Swagger UI cannot open it, use a WebSocket client (e.g. `websocat 'ws://host/api/ws?after=0&token=rdns_...'`). Streams change events (resumable with `after`) and, with `queries=true`, live DNS queries for zones the caller owns. Browsers authenticate with the session cookie; other clients may pass `?token=`.",
    params(
        WsQuery,
        ("token" = Option<String>, Query, description = "API token (only accepted on this path, for clients that cannot set headers)."),
    ),
    responses(
        (status = 101, description = "Switching protocols. Text frames are JSON: `{\"type\":\"hello\",...}`, `{\"type\":\"change\",\"event\":ChangeEvent}`, `{\"type\":\"query\",\"event\":QueryEvent}`, `{\"type\":\"resync\",\"head\":N}` (see the ChangeEvent and QueryEvent schemas)."),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
    ),
)]
pub async fn ws(
    State(s): State<Arc<AppState>>,
    caller: Caller,
    Query(q): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| session(s, caller, q, socket))
}

async fn session(s: Arc<AppState>, caller: Caller, q: WsQuery, mut socket: WebSocket) {
    let admin = caller.user.is_admin;
    let visible: Vec<String> = match s.visible_zones(&caller.user) {
        Ok(v) => v.into_iter().map(|(z, _)| z.name).collect(),
        Err(_) => return,
    };
    // Live queries: per zone, from the permission table (owners), plus everything for admins.
    let watch: std::collections::HashSet<String> = match s.visible_zones(&caller.user) {
        Ok(v) => v
            .into_iter()
            .filter(|(_, r)| ZonePerm::WatchQueries.allowed(*r))
            .map(|(z, _)| z.name)
            .collect(),
        Err(_) => return,
    };
    let can_see_queries = admin || !watch.is_empty();

    // Subscribe before replaying so nothing is lost in between.
    let Some(changes) = s.bus.subscribe_changes() else {
        return;
    };
    let queries = if q.queries.unwrap_or(false) && can_see_queries {
        s.bus.subscribe_queries()
    } else {
        None
    };

    let (oldest, latest) = s.storage.changelog_bounds().unwrap_or((None, None));
    let head = s.storage.changelog_head().unwrap_or(0);
    let mut last_sent: i64 = q.after.unwrap_or(head);
    let hello = serde_json::json!({ "type": "hello", "oldest_offset": oldest, "latest_offset": latest, "head": head, "user": caller.user.username, "queries": queries.is_some() });
    if socket
        .send(Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    if let Some(after) = q.after {
        if matches!(oldest, Some(o) if after + 1 < o) {
            // Cursor fell behind retention: tell the client to refetch state.
            let _ = socket
                .send(Message::Text(
                    serde_json::json!({ "type": "resync", "head": head })
                        .to_string()
                        .into(),
                ))
                .await;
            last_sent = head;
        } else if let Ok(entries) = s.storage.changelog_after(after, 5000) {
            for e in entries {
                if admin || visible.contains(&e.zone) {
                    let msg = serde_json::json!({ "type": "change", "event": e });
                    if socket
                        .send(Message::Text(msg.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                last_sent = e.offset;
            }
        }
    }

    let mut ping = tokio::time::interval(Duration::from_secs(25));
    loop {
        tokio::select! {
            r = changes.recv_async() => {
                match r {
                    Ok(e) => {
                        if e.offset <= last_sent { continue; }
                        last_sent = e.offset;
                        if !(admin || visible.contains(&e.zone)) { continue; }
                        let msg = serde_json::json!({ "type": "change", "event": e });
                        if socket.send(Message::Text(msg.to_string().into())).await.is_err() { return; }
                    }
                    Err(_) => return,
                }
            }
            r = async { match &queries { Some(q) => q.recv_async().await, None => std::future::pending().await } } => {
                match r {
                    Ok(e) => {
                        if !admin {
                            // A query belongs to the most specific zone that answers it; owners
                            // see it only if that zone is one of theirs. Foreign names: admins only.
                            let key = if e.name.ends_with('.') { e.name.to_ascii_lowercase() } else { format!("{}.", e.name.to_ascii_lowercase()) };
                            let owner_zone = s.cache.load().find_zone(&key).map(|z| z.zone.name.clone());
                            if !owner_zone.is_some_and(|z| watch.contains(&z)) { continue; }
                        }
                        let msg = serde_json::json!({ "type": "query", "event": e });
                        if socket.send(Message::Text(msg.to_string().into())).await.is_err() { return; }
                    }
                    Err(_) => return,
                }
            }
            _ = ping.tick() => {
                if socket.send(Message::Ping(vec![].into())).await.is_err() { return; }
            }
            m = socket.recv() => {
                match m {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                    _ => {}
                }
            }
        }
    }
}
