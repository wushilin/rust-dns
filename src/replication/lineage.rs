//! How a standby relates its database to the primary it is told to follow:
//! continue tailing, adopt a promoted primary's history, load a snapshot, or
//! refuse. Pure logic, unit-tested.
//!
//! Local data is never discarded implicitly. A snapshot is loaded only when
//! the database is a copy of the primary's history (a gap after changelog
//! retention: the data being replaced came from the primary anyway) or when
//! it is fresh (see [`super::data::fresh_problems`]). Anything else is
//! refused until the operator runs `rust-dns --prepare-standby`, which backs
//! the database up and empties it.

use super::types::History;

/// What the standby knows about itself.
#[derive(Debug, Clone)]
pub struct LocalView {
    pub history: History,
    /// Latest local changelog offset.
    pub head: i64,
    /// Why the database is not fresh (empty: fresh, nothing to lose).
    pub data: Vec<String>,
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
    /// Load a snapshot (same lineage after a gap, or a fresh database).
    Bootstrap { reason: String },
    /// The database has data that is not a copy of this primary's history:
    /// following would replace it. `why` explains the relation, `data`
    /// lists what exists. Nothing is changed; the operator decides.
    NeedsFresh { why: String, data: Vec<String> },
    /// Never follow this primary (it is the stale old primary).
    Refuse(String),
    /// This standby's copy of the primary's history differs from the
    /// primary's: a bug (or a primary restored from an older backup). Halt.
    Diverged {
        reason: &'static str,
        detail: String,
    },
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

/// Snapshot when there is nothing to lose, otherwise ask the operator.
fn fresh_or_refuse(local: &LocalView, why: String) -> Plan {
    if local.data.is_empty() {
        Plan::Bootstrap {
            reason: format!("initial copy ({why}; this server has no data yet)"),
        }
    } else {
        Plan::NeedsFresh {
            why,
            data: local.data.clone(),
        }
    }
}

pub fn plan(local: &LocalView, remote: &RemoteView) -> Plan {
    let l = &local.history;
    let r = &remote.history;
    if l.history_id == r.history_id {
        if local.head > remote.head {
            return Plan::Diverged {
                reason: "ahead_of_primary",
                detail: format!(
                    "this server has changes up to offset {} of history {} but the primary only up to {} (was the primary restored from an older backup?)",
                    local.head, l.history_id, remote.head
                ),
            };
        }
        if remote.txn_matches_at_local_head == Some(false) {
            return Plan::Diverged {
                reason: "txn_mismatch",
                detail: format!(
                    "the change at offset {} differs from the primary's (same history {}, different transaction)",
                    local.head, l.history_id
                ),
            };
        }
        if gap(local.head, remote.oldest, remote.head) {
            // Same lineage: the data being replaced is a copy of the primary's.
            return Plan::Bootstrap {
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
            return fresh_or_refuse(
                local,
                format!(
                    "the primary was promoted from this server's history at offset {fork}; this server has {} later change(s) the primary does not have",
                    local.head - fork
                ),
            );
        }
        if gap(local.head, remote.oldest, remote.head) {
            return Plan::Bootstrap {
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
    fresh_or_refuse(
        local,
        "this server's database was not copied from this primary (unrelated history)".into(),
    )
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
            data: vec!["1 zone".into()],
        }
    }

    fn fresh(mut l: LocalView) -> LocalView {
        l.data.clear();
        l
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
    fn same_lineage_tails_and_rebootstraps_after_gaps_automatically() {
        let r = remote(h("A", None, None), 20, Some(1));
        assert_eq!(plan(&local("A", None, 10), &r), Plan::Tail { adopt: false });
        assert_eq!(plan(&local("A", None, 20), &r), Plan::Tail { adopt: false });
        // Retention pruned what we need: our data is a copy, reload it.
        let pruned = remote(h("A", None, None), 20, Some(15));
        assert!(matches!(
            plan(&local("A", None, 10), &pruned),
            Plan::Bootstrap { .. }
        ));
        assert_eq!(
            plan(&local("A", None, 14), &pruned),
            Plan::Tail { adopt: false }
        );
        let empty = remote(h("A", None, None), 20, None);
        assert_eq!(
            plan(&local("A", None, 20), &empty),
            Plan::Tail { adopt: false }
        );
        assert!(matches!(
            plan(&local("A", None, 19), &empty),
            Plan::Bootstrap { .. }
        ));
    }

    #[test]
    fn divergence_in_the_same_history_halts() {
        let r = remote(h("A", None, None), 20, Some(1));
        // Ahead of the primary (restored from a backup).
        assert!(matches!(
            plan(&local("A", None, 25), &r),
            Plan::Diverged {
                reason: "ahead_of_primary",
                ..
            }
        ));
        // Same offset, different transaction.
        let mut differs = r.clone();
        differs.txn_matches_at_local_head = Some(false);
        assert!(matches!(
            plan(&local("A", None, 10), &differs),
            Plan::Diverged {
                reason: "txn_mismatch",
                ..
            }
        ));
    }

    #[test]
    fn promoted_primary_is_adopted_or_the_old_primary_must_be_prepared() {
        // B was promoted from history A at offset 30.
        let b = remote(h("B", Some("A"), Some(30)), 40, Some(1));
        assert_eq!(plan(&local("A", None, 25), &b), Plan::Tail { adopt: true });
        assert_eq!(plan(&local("A", None, 30), &b), Plan::Tail { adopt: true });
        // The old primary A wrote after the fork: refused until prepared.
        assert!(matches!(
            plan(&local("A", None, 35), &b),
            Plan::NeedsFresh { .. }
        ));
    }

    #[test]
    fn stale_old_primary_is_refused() {
        let a = remote(h("A", None, None), 30, Some(1));
        assert!(matches!(
            plan(&local("B", Some("A"), 40), &a),
            Plan::Refuse(_)
        ));
    }

    #[test]
    fn unrelated_history_needs_a_fresh_database() {
        let r = remote(h("X", None, None), 5, Some(1));
        assert!(matches!(
            plan(&fresh(local("Y", None, 0)), &r),
            Plan::Bootstrap { .. }
        ));
        // A fresh database with an old changelog sequence is still fresh.
        assert!(matches!(
            plan(&fresh(local("Y", None, 9)), &r),
            Plan::Bootstrap { .. }
        ));
        assert!(matches!(
            plan(&local("Y", None, 3), &r),
            Plan::NeedsFresh { .. }
        ));
    }
}
