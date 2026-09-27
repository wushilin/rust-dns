//! How a standby relates its database to the primary it is told to follow:
//! continue tailing, adopt a promoted primary's history, re-bootstrap
//! (saving divergent changes first) or refuse. Pure logic, unit-tested.

use super::types::History;

/// What the standby knows about itself.
#[derive(Debug, Clone)]
pub struct LocalView {
    pub history: History,
    /// Latest local changelog offset.
    pub head: i64,
    /// No zones and an empty changelog: nothing to lose.
    pub empty: bool,
}

/// What the primary reports.
#[derive(Debug, Clone)]
pub struct RemoteView {
    pub history: History,
    pub head: i64,
    pub oldest: Option<i64>,
    /// The primary's transaction id at our head offset, when both have that
    /// row: `Some(same)` or `Some(different)`; `None` = not comparable.
    pub txn_matches_at_local_head: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Continue from the local head; `adopt` = switch to the primary's
    /// history first (it was promoted from ours, at or after our head).
    Tail { adopt: bool },
    /// Load a snapshot. `divergent` = local changes the primary does not
    /// have are about to be replaced: save them first, starting after
    /// `fork` (all retained changes when the fork point is unknown).
    Bootstrap {
        divergent: bool,
        fork: Option<i64>,
        reason: String,
    },
    /// Do not follow this primary.
    Refuse(String),
}

/// Can the local changelog continue from `head` given the primary's oldest
/// retained offset?
fn gap(head: i64, oldest: Option<i64>, remote_head: i64) -> bool {
    match oldest {
        Some(o) => head + 1 < o,
        // An empty (fully pruned) log: only fine if we are at its head.
        None => head < remote_head,
    }
}

pub fn plan(local: &LocalView, remote: &RemoteView) -> Plan {
    let l = &local.history;
    let r = &remote.history;
    if l.history_id == r.history_id {
        if local.head > remote.head {
            return Plan::Bootstrap {
                divergent: true,
                fork: Some(remote.head),
                reason: format!(
                    "this server has changes up to offset {} but the primary only up to {} (was the primary restored from an older backup?)",
                    local.head, remote.head
                ),
            };
        }
        if remote.txn_matches_at_local_head == Some(false) {
            return Plan::Bootstrap {
                divergent: true,
                fork: None,
                reason: format!(
                    "the change at offset {} differs from the primary's (same history id, different data)",
                    local.head
                ),
            };
        }
        if gap(local.head, remote.oldest, remote.head) {
            return Plan::Bootstrap {
                divergent: false,
                fork: None,
                reason: format!(
                    "the primary no longer has the changes after offset {} (changelog retention)",
                    local.head
                ),
            };
        }
        return Plan::Tail { adopt: false };
    }
    if r.parent_history_id.as_deref() == Some(l.history_id.as_str()) {
        let fork = r.fork_offset.unwrap_or(0);
        if local.head > fork {
            return Plan::Bootstrap {
                divergent: true,
                fork: Some(fork),
                reason: format!(
                    "the primary was promoted from this server's history at offset {fork}; this server has {} later change(s) the primary does not have",
                    local.head - fork
                ),
            };
        }
        if gap(local.head, remote.oldest, remote.head) {
            return Plan::Bootstrap {
                divergent: false,
                fork: None,
                reason: format!(
                    "the primary no longer has the changes after offset {} (changelog retention)",
                    local.head
                ),
            };
        }
        return Plan::Tail { adopt: true };
    }
    if l.parent_history_id.as_deref() == Some(r.history_id.as_str()) {
        return Plan::Refuse(format!(
            "this server was promoted from that server's history (at offset {}): it is the old primary. Configure the old primary to follow this server instead, and remove [follow] here",
            l.fork_offset.unwrap_or(0)
        ));
    }
    if local.empty {
        return Plan::Bootstrap {
            divergent: false,
            fork: None,
            reason: "initial copy".into(),
        };
    }
    Plan::Bootstrap {
        divergent: true,
        fork: None,
        reason: "this server's data has an unrelated history (it was not copied from this primary)"
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: &str, parent: Option<&str>, fork: Option<i64>) -> History {
        History {
            history_id: id.into(),
            parent_history_id: parent.map(str::to_string),
            fork_offset: fork,
            ..Default::default()
        }
    }

    fn local(id: &str, parent: Option<&str>, head: i64) -> LocalView {
        LocalView {
            history: h(id, parent, parent.map(|_| 5)),
            head,
            empty: false,
        }
    }

    fn remote(hist: History, head: i64, oldest: Option<i64>) -> RemoteView {
        RemoteView {
            history: hist,
            head,
            oldest,
            txn_matches_at_local_head: None,
        }
    }

    #[test]
    fn same_history_tails_or_detects_gaps_and_divergence() {
        let r = remote(h("A", None, None), 20, Some(1));
        assert_eq!(plan(&local("A", None, 10), &r), Plan::Tail { adopt: false });
        assert_eq!(plan(&local("A", None, 20), &r), Plan::Tail { adopt: false });
        // Retention pruned what we need.
        let pruned = remote(h("A", None, None), 20, Some(15));
        assert!(matches!(
            plan(&local("A", None, 10), &pruned),
            Plan::Bootstrap {
                divergent: false,
                ..
            }
        ));
        assert_eq!(
            plan(&local("A", None, 14), &pruned),
            Plan::Tail { adopt: false },
            "offset 15 is the next one needed and still there"
        );
        // Fully pruned log at the head is fine, behind it is not.
        let empty = remote(h("A", None, None), 20, None);
        assert_eq!(
            plan(&local("A", None, 20), &empty),
            Plan::Tail { adopt: false }
        );
        assert!(matches!(
            plan(&local("A", None, 19), &empty),
            Plan::Bootstrap { .. }
        ));
        // Primary restored from an older backup: we are ahead.
        assert_eq!(
            plan(&local("A", None, 25), &r),
            Plan::Bootstrap {
                divergent: true,
                fork: Some(20),
                reason: plan_reason(&local("A", None, 25), &r)
            }
        );
        // Same offsets, different transaction.
        let mut differs = r.clone();
        differs.txn_matches_at_local_head = Some(false);
        assert!(matches!(
            plan(&local("A", None, 10), &differs),
            Plan::Bootstrap {
                divergent: true,
                fork: None,
                ..
            }
        ));
    }

    fn plan_reason(l: &LocalView, r: &RemoteView) -> String {
        match plan(l, r) {
            Plan::Bootstrap { reason, .. } => reason,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn promoted_primary_is_adopted_or_divergence_saved() {
        // B was promoted from history A at offset 30.
        let b = remote(h("B", Some("A"), Some(30)), 40, Some(1));
        // A standby of A that was behind the fork just continues in B's history.
        assert_eq!(plan(&local("A", None, 25), &b), Plan::Tail { adopt: true });
        assert_eq!(plan(&local("A", None, 30), &b), Plan::Tail { adopt: true });
        // The old primary A wrote 5 more changes after the fork: saved, re-bootstrapped.
        assert!(matches!(
            plan(&local("A", None, 35), &b),
            Plan::Bootstrap {
                divergent: true,
                fork: Some(30),
                ..
            }
        ));
    }

    #[test]
    fn stale_old_primary_is_refused() {
        // We (B) were promoted from A; following A again would lose our writes.
        let a = remote(h("A", None, None), 30, Some(1));
        assert!(matches!(
            plan(&local("B", Some("A"), 40), &a),
            Plan::Refuse(_)
        ));
    }

    #[test]
    fn unrelated_history_bootstraps_saving_local_data() {
        let r = remote(h("X", None, None), 5, Some(1));
        let mut fresh = local("Y", None, 0);
        fresh.empty = true;
        assert!(matches!(
            plan(&fresh, &r),
            Plan::Bootstrap {
                divergent: false,
                ..
            }
        ));
        assert!(matches!(
            plan(&local("Y", None, 3), &r),
            Plan::Bootstrap {
                divergent: true,
                fork: None,
                ..
            }
        ));
    }
}
