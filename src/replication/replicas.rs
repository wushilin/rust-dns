//! Primary side: which standbys (replicas) follow this server and how far
//! behind they are. The list comes from changelog v2's client tracker
//! (`Replication::replica_list`); this module holds its API shape and the
//! `[follow].instance_id` rules.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// `[follow].instance_id` rules: a hostname label.
pub fn instance_id_problem(id: &str) -> Option<String> {
    if id.is_empty() || id.len() > 63 {
        return Some("must be 1-63 characters".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Some("may contain only a-z, 0-9 and '-' (lowercase, like a host name)".into());
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Some("must not start or end with '-'".into());
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaState {
    UpToDate,
    CatchingUp,
    FallingBehind,
    Offline,
    Bootstrapping,
    /// The standby reported that it stopped because its data diverged.
    Halted,
}

impl ReplicaState {
    pub const ALL: [ReplicaState; 6] = [
        ReplicaState::UpToDate,
        ReplicaState::CatchingUp,
        ReplicaState::FallingBehind,
        ReplicaState::Offline,
        ReplicaState::Bootstrapping,
        ReplicaState::Halted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReplicaState::UpToDate => "up_to_date",
            ReplicaState::CatchingUp => "catching_up",
            ReplicaState::FallingBehind => "falling_behind",
            ReplicaState::Offline => "offline",
            ReplicaState::Bootstrapping => "bootstrapping",
            ReplicaState::Halted => "halted",
        }
    }
}

/// A replica as the API shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({ "instance": "dns2", "state": "up_to_date", "conflict": false, "applied_offset": 1834, "head": 1834, "lag_changes": 0, "lag_seconds": 0, "last_seen_at": "2026-01-15T09:30:00.000Z", "last_caught_up_at": "2026-01-15T09:30:00.000Z", "first_seen_at": "2026-01-10T08:00:00.000Z", "address": "192.0.2.53", "version": "0.1.0", "user": "root", "bootstrapping": false, "halted_reason": null }))]
pub struct ReplicaInfo {
    pub instance: String,
    pub state: ReplicaState,
    /// The same id is used by two processes (addresses or sessions) at once.
    pub conflict: bool,
    /// The offset the standby has applied (the `after` of its last request).
    pub applied_offset: i64,
    /// This server's latest offset now.
    pub head: i64,
    pub lag_changes: i64,
    /// Seconds since the standby was last caught up (0 when it is).
    pub lag_seconds: i64,
    #[schema(format = DateTime)]
    pub last_seen_at: String,
    #[schema(required = true, format = DateTime)]
    pub last_caught_up_at: Option<String>,
    #[schema(format = DateTime)]
    pub first_seen_at: String,
    pub address: String,
    pub version: String,
    /// The token user the standby authenticates as.
    pub user: String,
    pub bootstrapping: bool,
    /// Why the standby halted (state `halted`).
    #[schema(required = true)]
    pub halted_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_ids_are_host_labels() {
        for ok in ["dns2", "a", "standby-1", &"a".repeat(63)] {
            assert!(instance_id_problem(ok).is_none(), "{ok}");
        }
        for bad in ["", "DNS2", "dns_2", "-a", "a-", "a.b", &"a".repeat(64)] {
            assert!(instance_id_problem(bad).is_some(), "{bad}");
        }
    }
}
