//! Server-side awareness of followers: who is following, where each one
//! is, and whether it is up to date. In memory; a follower unseen for a
//! day is forgotten.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::http::HeaderMap;

use crate::wire::{ClientInfo, ClientView};

pub const CLIENT_ID: &str = "x-cdc-client-id";
pub const CLIENT_NAME: &str = "x-cdc-client-name";

const FORGET_AFTER_SECS: f64 = 86_400.0;
const FRESH_SECS: f64 = 60.0;

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Who is asking: set by the router's middleware.
#[derive(Debug, Clone)]
pub struct Caller {
    pub id: String,
    pub name: String,
    pub principal: Option<String>,
    pub addr: Option<String>,
}

impl Caller {
    pub fn from_headers(h: &HeaderMap, principal: Option<String>, addr: Option<String>) -> Caller {
        let get = |k: &str| {
            h.get(k)
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    v.chars()
                        .filter(|c| !c.is_control())
                        .take(128)
                        .collect::<String>()
                })
                .filter(|v| !v.is_empty())
        };
        let id = get(CLIENT_ID)
            .or_else(|| addr.clone())
            .unwrap_or_else(|| "anonymous".into());
        Caller {
            name: get(CLIENT_NAME).unwrap_or_else(|| id.clone()),
            id,
            principal,
            addr,
        }
    }
}

#[derive(Default)]
pub struct Clients {
    m: Mutex<HashMap<String, ClientInfo>>,
}

impl Clients {
    fn with<R>(&self, f: impl FnOnce(&mut HashMap<String, ClientInfo>) -> R) -> R {
        f(&mut self.m.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Record a request. `position`: the follower's applied transaction,
    /// when the request tells it.
    pub fn seen(&self, c: &Caller, mode: &str, position: Option<u64>, txns_sent: u64) {
        let t = now();
        self.with(|m| {
            let e = m.entry(c.id.clone()).or_insert_with(|| ClientInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                principal: None,
                addr: None,
                mode: String::new(),
                position: 0,
                connected: false,
                first_seen: t,
                last_seen: t,
                requests: 0,
                txns_sent: 0,
                lag_txns: 0,
                up_to_date: false,
            });
            e.name = c.name.clone();
            e.principal = c.principal.clone();
            e.addr = c.addr.clone().or(e.addr.take());
            e.mode = mode.into();
            if let Some(p) = position {
                e.position = p;
            }
            e.last_seen = t;
            e.requests += 1;
            e.txns_sent += txns_sent;
        });
    }

    pub fn set_connected(&self, id: &str, connected: bool) {
        self.with(|m| {
            if let Some(e) = m.get_mut(id) {
                e.connected = connected;
                e.last_seen = now();
            }
        });
    }

    fn fill(e: &mut ClientInfo, head: u64, t: f64) {
        e.lag_txns = head.saturating_sub(e.position);
        e.up_to_date = e.lag_txns == 0 && (e.connected || t - e.last_seen < FRESH_SECS);
    }

    /// Every known follower, with its lag against `head`.
    pub fn list(&self, head: u64) -> Vec<ClientInfo> {
        let t = now();
        self.with(|m| {
            m.retain(|_, e| e.connected || t - e.last_seen < FORGET_AFTER_SECS);
            let mut v: Vec<ClientInfo> = m
                .values_mut()
                .map(|e| {
                    Self::fill(e, head, t);
                    e.clone()
                })
                .collect();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            v
        })
    }

    pub fn view(&self, id: &str, head: u64) -> Option<ClientView> {
        let t = now();
        self.with(|m| {
            m.get_mut(id).map(|e| {
                Self::fill(e, head, t);
                ClientView {
                    server_last_txn: head,
                    position: e.position,
                    lag_txns: e.lag_txns,
                    up_to_date: e.up_to_date,
                }
            })
        })
    }
}
