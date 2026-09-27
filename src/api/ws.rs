//! Realtime stream: change events (resumable by offset) and live queries.
//!
//! The caller's credentials and zone rights are re-checked every
//! [`REVALIDATE`] and whenever a zone or membership change goes by: a
//! revoked token, deleted session, disabled account or removed membership
//! ends the stream (close code 1008) or narrows what it carries.

use super::openapi::{Forbidden, InvalidRequest, Unauthorized};
use super::session::{Caller, WS_PROTOCOL};
use super::AppState;
use crate::model::{ChangeEvent, User, ZonePerm, ZoneRole};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use utoipa::IntoParams;

/// How often an open stream re-checks the caller's session/token and rights.
pub const REVALIDATE: Duration = Duration::from_secs(10);
/// Policy violation: the credentials are no longer valid.
const CLOSE_POLICY: u16 = 1008;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WsQuery {
    /// Replay change events after this offset first (WAL-style cursor).
    pub after: Option<i64>,
    /// Also stream live DNS queries.
    #[param(default = false)]
    pub queries: Option<bool>,
}

/// What a caller may see of the change feed, derived from their rights.
pub struct View {
    admin: bool,
    username: String,
    roles: HashMap<String, ZoneRole>,
    /// Zones whose live queries the caller may watch.
    pub watch: HashSet<String>,
}

impl View {
    pub fn build(s: &AppState, user: &User) -> super::error::ApiResult<View> {
        let zones = s.visible_zones(user)?;
        Ok(View {
            admin: user.is_admin,
            username: user.username.clone(),
            watch: zones
                .iter()
                .filter(|(_, r)| ZonePerm::WatchQueries.allowed(*r))
                .map(|(z, _)| z.name.clone())
                .collect(),
            roles: zones.into_iter().map(|(z, r)| (z.name, r)).collect(),
        })
    }

    /// The event as this caller may see it, or `None`. Membership events
    /// (who has access) need the owner role on the zone, like the member
    /// list itself; other users' client addresses are shown only to
    /// administrators and zone owners.
    pub fn change(&self, e: &ChangeEvent) -> Option<ChangeEvent> {
        if self.admin {
            return Some(e.clone());
        }
        let role = *self.roles.get(&e.zone)?;
        let manages = ZonePerm::ManageAccess.allowed(role);
        if e.entity == "member" && !manages {
            return None;
        }
        let mut e = e.clone();
        if !manages && e.actor != self.username {
            e.actor_ip = String::new();
        }
        Some(e)
    }

    pub fn can_see_queries(&self) -> bool {
        self.admin || !self.watch.is_empty()
    }

    fn sees_query_zone(&self, zone: Option<&str>) -> bool {
        self.admin || zone.is_some_and(|z| self.watch.contains(z))
    }
}

/// Browser websockets carry cookies cross-site, so a cookie-authenticated
/// upgrade must come from this site: its `Origin` must name the same host
/// as `Host` (or `X-Forwarded-Host`). A missing `Origin` (non-browser
/// client) is allowed.
pub fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(origin_host) = origin
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/'))
    else {
        return false; // "null" and other opaque origins
    };
    let hosts = [header::HOST.as_str(), "x-forwarded-host"];
    hosts.iter().any(|h| {
        headers
            .get(*h)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|host| host.trim().eq_ignore_ascii_case(origin_host))
    })
}

/// Realtime stream. The token (subprotocol or `token` query parameter) is
/// read by the `Caller` extractor (only on this path), so it is declared
/// here, not in `WsQuery`.
#[utoipa::path(
    get,
    path = "/ws",
    tag = "Change log",
    operation_id = "websocket",
    summary = "WebSocket stream (not callable from Swagger UI)",
    description = "WebSocket upgrade; Swagger UI cannot open it, use a WebSocket client. Streams change events (resumable with `after`) and, with `queries=true`, live DNS queries for zones the caller owns.\n\nBrowsers authenticate with the session cookie; the page's `Origin` must match the host. Other clients send an API token as a subprotocol: `Sec-WebSocket-Protocol: rust-dns, rust-dns.bearer.<token>` (the server selects `rust-dns`), e.g. `websocat --protocol 'rust-dns, rust-dns.bearer.rdns_...' ws://host/api/ws?after=0`. `?token=` still works but is deprecated: URLs end up in proxy logs.\n\nThe stream re-checks the credentials and zone rights every 10 seconds and on membership changes; when the session or token is revoked or the account is disabled it closes with code 1008.",
    params(
        WsQuery,
        ("token" = Option<String>, Query, deprecated, description = "Deprecated: API token in the URL (ends up in logs). Use the `rust-dns.bearer.<token>` subprotocol."),
    ),
    responses(
        (status = 101, description = "Switching protocols. Text frames are JSON: `{\"type\":\"hello\",...}`, `{\"type\":\"change\",\"event\":ChangeEvent}`, `{\"type\":\"query\",\"event\":QueryEvent}`, `{\"type\":\"resync\",\"head\":N}` (see the ChangeEvent and QueryEvent schemas)."),
        (status = 400, response = InvalidRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn ws(
    State(s): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
    Query(q): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    if caller.session_id.is_some() && !origin_allowed(&headers) {
        tracing::warn!(ip = %caller.ip, origin = ?headers.get(header::ORIGIN), "rejected cross-site websocket upgrade");
        return super::error::ApiError::new(
            StatusCode::FORBIDDEN,
            "websocket Origin does not match this site",
        )
        .into_response();
    }
    ws.protocols([WS_PROTOCOL])
        .on_upgrade(move |socket| session(s, caller, q, socket))
}

/// Is the caller's session / token still valid? Returns the current user.
fn revalidate(s: &AppState, caller: &Caller) -> Result<User, &'static str> {
    if let Some(sid) = caller.session_id {
        match s.storage.get_session_by_id(sid) {
            Ok(Some(sess))
                if sess.state == "active" && sess.expires_at >= crate::model::now_rfc3339() => {}
            Ok(_) => return Err("session ended"),
            Err(_) => return Err("session check failed"),
        }
    }
    if let Some(tid) = caller.token_id {
        match s.storage.get_token(tid) {
            Ok(Some(t)) if t.revoked_at.is_none() => {}
            Ok(_) => return Err("token revoked"),
            Err(_) => return Err("token check failed"),
        }
    }
    match s.storage.get_user(caller.user.id) {
        Ok(Some(u)) if u.disabled_at.is_none() => Ok(u),
        Ok(Some(_)) => Err("account disabled"),
        Ok(None) => Err("account deleted"),
        Err(_) => Err("account check failed"),
    }
}

async fn close(socket: &mut WebSocket, why: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: CLOSE_POLICY,
            reason: why.into(),
        })))
        .await;
}

async fn session(s: Arc<AppState>, caller: Caller, q: WsQuery, mut socket: WebSocket) {
    let mut view = match View::build(&s, &caller.user) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Subscribe before replaying so nothing is lost in between.
    let Some(changes) = s.bus.subscribe_changes() else {
        return;
    };
    let queries = if q.queries.unwrap_or(false) && view.can_see_queries() {
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
                if let Some(e) = view.change(&e) {
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
    let mut recheck = tokio::time::interval(REVALIDATE);
    recheck.tick().await; // the first tick is immediate
    loop {
        tokio::select! {
            r = changes.recv_async() => {
                match r {
                    Ok(e) => {
                        if e.offset <= last_sent { continue; }
                        last_sent = e.offset;
                        let visible = view.change(&e);
                        // Access may have changed: re-check before the next event.
                        if matches!(e.entity.as_str(), "member" | "zone") {
                            match revalidate(&s, &caller).and_then(|u| View::build(&s, &u).map_err(|_| "rights check failed")) {
                                Ok(v) => view = v,
                                Err(why) => { close(&mut socket, why).await; return; }
                            }
                        }
                        let Some(e) = visible else { continue };
                        let msg = serde_json::json!({ "type": "change", "event": e });
                        if socket.send(Message::Text(msg.to_string().into())).await.is_err() { return; }
                    }
                    Err(_) => return,
                }
            }
            r = async { match &queries { Some(q) => q.recv_async().await, None => std::future::pending().await } } => {
                match r {
                    Ok(e) => {
                        if !view.admin {
                            // A query belongs to the most specific zone that answers it; owners
                            // see it only if that zone is one of theirs. Foreign names: admins only.
                            let key = if e.name.ends_with('.') { e.name.to_ascii_lowercase() } else { format!("{}.", e.name.to_ascii_lowercase()) };
                            let owner_zone = s.cache.load().find_zone(&key).map(|z| z.zone.name.clone());
                            if !view.sees_query_zone(owner_zone.as_deref()) { continue; }
                        }
                        let msg = serde_json::json!({ "type": "query", "event": e });
                        if socket.send(Message::Text(msg.to_string().into())).await.is_err() { return; }
                    }
                    Err(_) => return,
                }
            }
            _ = recheck.tick() => {
                match revalidate(&s, &caller).and_then(|u| View::build(&s, &u).map_err(|_| "rights check failed")) {
                    Ok(v) => view = v,
                    Err(why) => {
                        tracing::info!(user = %caller.user.username, why, "closing websocket");
                        close(&mut socket, why).await;
                        return;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.parse().unwrap());
        }
        m
    }

    /// L4 regression: cookie websocket upgrades from another site's page.
    #[test]
    fn origin_must_match_host() {
        assert!(
            origin_allowed(&h(&[("host", "dns.example.com")])),
            "no Origin: non-browser client"
        );
        assert!(origin_allowed(&h(&[
            ("host", "dns.example.com"),
            ("origin", "https://dns.example.com")
        ])));
        assert!(origin_allowed(&h(&[
            ("host", "localhost:8053"),
            ("origin", "http://localhost:8053")
        ])));
        assert!(!origin_allowed(&h(&[
            ("host", "localhost:8053"),
            ("origin", "http://localhost:9999")
        ])));
        assert!(!origin_allowed(&h(&[
            ("host", "dns.example.com"),
            ("origin", "https://evil.example")
        ])));
        assert!(!origin_allowed(&h(&[
            ("host", "dns.example.com"),
            ("origin", "null")
        ])));
        assert!(origin_allowed(&h(&[
            ("host", "127.0.0.1:8053"),
            ("x-forwarded-host", "dns.example.com"),
            ("origin", "https://dns.example.com")
        ])));
    }

    fn event(zone: &str, entity: &str, actor: &str) -> ChangeEvent {
        ChangeEvent {
            offset: 1,
            ts: String::new(),
            actor: actor.into(),
            actor_ip: "192.0.2.7".into(),
            action: "update".into(),
            entity: entity.into(),
            zone: zone.into(),
            entity_id: None,
            payload: serde_json::json!({}),
            txn: String::new(),
            command: String::new(),
        }
    }

    /// L8 regression: membership events and other users' IPs used to reach
    /// viewers and editors, who cannot see the member list.
    #[test]
    fn member_events_and_actor_ips_are_redacted_below_owner() {
        let view = View {
            admin: false,
            username: "vera".into(),
            roles: [
                ("a.test".to_string(), ZoneRole::Viewer),
                ("b.test".to_string(), ZoneRole::Owner),
            ]
            .into(),
            watch: HashSet::new(),
        };
        assert!(view.change(&event("a.test", "member", "root")).is_none());
        let rec = view.change(&event("a.test", "record", "root")).unwrap();
        assert_eq!(rec.actor_ip, "", "other users' IPs hidden from viewers");
        let own = view.change(&event("a.test", "record", "vera")).unwrap();
        assert_eq!(own.actor_ip, "192.0.2.7", "own IP shown");
        let owned = view.change(&event("b.test", "member", "root")).unwrap();
        assert_eq!(owned.actor_ip, "192.0.2.7", "owners see members and IPs");
        assert!(view.change(&event("c.test", "record", "root")).is_none());
    }
}
