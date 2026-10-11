//! Replication bookkeeping writes: the promotion record, operator actions
//! (rebootstrap) and `--prepare-standby`. The data of a standby is written
//! by changelog v2's apply path (`crates/sqlite-cdc`), never here;
//! [`Mutator::replica_applied`] brings the in-memory state up to date after
//! it.
//!
//! These writes keep the structure of every other write: under the write
//! lock, with an audit row (`replication.*`, never secrets) in the same
//! transaction.

use super::accounts::AuditTx;
use super::{MResult, MutationError, Mutator, Rebuild, TOKEN};
use crate::model::Actor;
use crate::replication::data;
use crate::replication::types::*;
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;

// ---- replication_state ----------------------------------------------------

pub(crate) const K_HISTORY: &str = "history_id";
pub(crate) const K_PARENT: &str = "parent_history_id";
pub(crate) const K_FORK: &str = "fork_offset";
pub(crate) const K_PROMOTED_AT: &str = "promoted_at";
pub(crate) const K_PROMOTED_FROM: &str = "promoted_from";
/// The primary this database was a standby of (written by versions before
/// changelog v2, cleared by promotion). A database with this key but no
/// `[follow]` in the config was un-followed by hand: startup records a
/// promotion.
pub(crate) const K_FOLLOWING: &str = "following";

fn set_state(c: &Connection, key: &str, value: Option<&str>) -> Result<()> {
    match value {
        Some(v) => c.execute(
            "INSERT INTO replication_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, v],
        )?,
        None => c.execute("DELETE FROM replication_state WHERE key = ?1", params![key])?,
    };
    Ok(())
}

fn set_history(c: &Connection, h: &History) -> Result<()> {
    set_state(c, K_HISTORY, Some(&h.history_id))?;
    set_state(c, K_PARENT, h.parent_history_id.as_deref())?;
    set_state(c, K_FORK, h.fork_offset.map(|o| o.to_string()).as_deref())?;
    set_state(c, K_PROMOTED_AT, h.promoted_at.as_deref())?;
    set_state(c, K_PROMOTED_FROM, h.promoted_from.as_deref())?;
    Ok(())
}

/// What `--prepare-standby` removed (counts only; goes into the audit row).
#[derive(Debug, Default, Clone, Serialize)]
pub struct PrepareSummary {
    pub zones: i64,
    pub records: i64,
    pub zone_members: i64,
    pub changelog_rows: i64,
    pub tsig_keys: i64,
    pub settings: i64,
    pub api_tokens: i64,
    pub users: i64,
    pub sessions: i64,
}

/// `rust-dns --prepare-standby` (server stopped): make this database fresh
/// so it may follow a primary. Empties zones, records, zone members, the
/// changelog, TSIG keys, console settings, API tokens, every session and
/// every user except the config root `root_username`, and forgets the
/// replication lineage (a new history id). The audit log is kept (local
/// history) and gets a `replication.prepare_standby` row naming the backup.
/// The caller writes the backup first.
pub fn prepare_standby(
    storage: &crate::storage::Storage,
    root_username: &str,
    backup: &str,
    divergence: Option<&str>,
) -> Result<PrepareSummary> {
    storage.write(&TOKEN, |c| -> Result<PrepareSummary> {
        let count = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
        let users: i64 = c.query_row(
            "SELECT COUNT(*) FROM users WHERE username <> ?1",
            params![root_username],
            |r| r.get(0),
        )?;
        let sum = PrepareSummary {
            zones: count("SELECT COUNT(*) FROM zones")?,
            records: count("SELECT COUNT(*) FROM records")?,
            zone_members: count("SELECT COUNT(*) FROM zone_members")?,
            changelog_rows: count("SELECT COUNT(*) FROM changelog")?,
            tsig_keys: count("SELECT COUNT(*) FROM tsig_keys")?,
            settings: count("SELECT COUNT(*) FROM settings")?,
            api_tokens: count("SELECT COUNT(*) FROM api_tokens")?,
            users,
            sessions: count("SELECT COUNT(*) FROM sessions")?,
        };
        let old = data::history(c)?;
        // Replicated tables per the registry; then the local stream and state.
        crate::replication::tables::delete_replicated(c, root_username)?;
        c.execute_batch(
            "DELETE FROM changelog; DELETE FROM changelog_history; DELETE FROM sessions; DELETE FROM replication_state;",
        )?;
        set_state(c, K_HISTORY, Some(&crate::auth::random_token(12)))?;
        let mut t = AuditTx::begin(c);
        let mut detail = serde_json::to_value(&sum)?;
        detail["backup"] = backup.into();
        detail["divergence_file"] = divergence.into();
        detail["old_history_id"] = old.history_id.into();
        t.push("replication.prepare_standby", None, backup, detail);
        t.commit_entries(
            &Actor {
                name: "cli".into(),
                ip: "local".into(),
            },
            "prepare_standby",
        )?;
        Ok(sum)
    })
}

impl Mutator {
    /// Run a replication bookkeeping write under the write lock: `f` gets
    /// the raw connection and an [`AuditTx`] whose rows commit with it, and
    /// says how much of the catalog the write may have changed. Committed:
    /// the catalog is brought up to date (the same per-zone mechanism as a
    /// primary's commit, under the same lock).
    async fn replica_write<T: Send + 'static>(
        &self,
        operation: &'static str,
        actor: Actor,
        f: impl for<'t> FnOnce(&'t Connection, &mut AuditTx<'t>) -> Result<(T, Rebuild)>
            + Send
            + 'static,
    ) -> MResult<T> {
        let _guard = self.lock.lock().await;
        let storage = self.storage.clone();
        let a = actor.clone();
        let joined = tokio::task::spawn_blocking(move || {
            storage.write(&TOKEN, |conn| -> Result<_> {
                let mut t = AuditTx::begin(conn);
                let out = f(conn, &mut t)?;
                let audit = t.commit_entries(&a, operation)?;
                Ok((out, audit))
            })
        })
        .await;
        let ((out, rebuild), audit) = match joined {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(operation, error = %format!("{e:#}"), "replication transaction rolled back; nothing committed");
                return Err(MutationError::Internal(e));
            }
            Err(j) => {
                return Err(MutationError::Internal(anyhow::anyhow!(
                    "replication write task failed: {j}"
                )))
            }
        };
        for r in &audit {
            tracing::info!(audit_id = r.id, txn = %r.txn, operation, actor = %r.actor, action = %r.action, target = %r.target, "audit");
        }
        self.refresh_catalog(rebuild).await;
        self.expiry_wake.notify_one();
        Ok(out)
    }

    /// An operator action on this server's replication (rebootstrap):
    /// audited (on a standby in its local audit table).
    pub async fn replica_audit(
        &self,
        actor: Actor,
        action: &'static str,
        target: String,
        detail: serde_json::Value,
    ) -> MResult<()> {
        self.replica_write("replication_operator", actor, move |_c, t| {
            t.push(action, None, &target, detail);
            Ok(((), Rebuild::Zones(Vec::new())))
        })
        .await
    }

    /// A console event for a replicated change (see `Bus::publish_replicated`).
    pub fn publish_replicated(&self, ev: crate::model::ChangeEvent) {
        self.bus.publish_replicated(ev);
    }

    /// Changelog v2 applied changes on this standby (outside the mutation
    /// module's transactions): the catalog, the expiry sweeper and the
    /// console's live views follow.
    pub async fn replica_applied(&self) {
        let _guard = self.lock.lock().await;
        self.refresh_catalog(Rebuild::Full).await;
        self.expiry_wake.notify_one();
        self.bus.publish_access(crate::events::AccessEvent::All);
    }

    /// Promotion: start a new history whose parent is the current one,
    /// forked at the current changelog head, and stop being a standby of
    /// `from` (the primary URL). Audited.
    pub async fn replica_promote(
        &self,
        actor: Actor,
        from: String,
        how: &'static str,
    ) -> MResult<History> {
        self.replica_write("replication_promote", actor, move |c, t| {
            let old = data::history(c)?;
            let head = data::changelog_head(c)?;
            let h = History {
                history_id: crate::auth::random_token(12),
                parent_history_id: Some(old.history_id.clone()),
                fork_offset: Some(head),
                promoted_at: Some(crate::model::now_rfc3339()),
                promoted_from: Some(from.clone()),
            };
            set_history(c, &h)?;
            set_state(c, K_FOLLOWING, None)?;
            t.push(
                "replication.promote",
                None,
                &from,
                serde_json::json!({ "old_history_id": old.history_id, "new_history_id": h.history_id, "fork_offset": head, "how": how }),
            );
            Ok((h, Rebuild::Full))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::accounts::{Accounts, UserChanges};
    use super::*;
    use crate::cache::{Cache, Catalog};
    use crate::events::Bus;
    use crate::model::*;
    use crate::storage::Storage;
    use std::sync::Arc;

    fn node() -> (Arc<Storage>, Mutator, Accounts) {
        let storage = Arc::new(Storage::open_memory().unwrap());
        let m = Mutator::new(
            storage.clone(),
            Arc::new(Cache::new(Catalog::empty())),
            Arc::new(Bus::new(64, 64)),
            "",
            "",
        );
        let a = Accounts::new(storage.clone());
        (storage, m, a)
    }

    fn actor() -> Actor {
        Actor {
            name: "tester".into(),
            ip: "127.0.0.1".into(),
        }
    }

    fn zone_input(name: &str) -> ZoneInput {
        ZoneInput {
            name: Some(name.into()),
            ..Default::default()
        }
    }

    fn rec(name: &str, t: RecordType, v: &str) -> RecordInput {
        RecordInput {
            name: Some(name.into()),
            rtype: Some(t),
            value: Some(v.into()),
            ..Default::default()
        }
    }

    const PRIMARY_ROOT_HASH: &str = "$argon2id$primary-root-hash";

    /// A primary with every kind of replicated data.
    async fn populated_primary() -> (Arc<Storage>, Mutator, Accounts) {
        let (s, m, a) = node();
        let root = a.sync_root("root", PRIMARY_ROOT_HASH, false).unwrap();
        let alice = a
            .create_user(
                &actor(),
                &NewUser {
                    username: "alice".into(),
                    password_hash: "$argon2id$alice-hash".into(),
                    display_name: "Alice".into(),
                    is_admin: false,
                    mfa_required: true,
                },
            )
            .unwrap();
        a.run(&actor(), "mfa_enroll", |t| {
            let u = t.set_mfa(alice.id, Some("ALICETOTPSECRET"))?;
            t.accept_totp_step(&u, 1000)?;
            t.set_recovery_codes(&u, &["rc-hash-1".into(), "rc-hash-2".into()])
        })
        .unwrap();
        a.create_token(&actor(), &alice, "ci", "token-hash-alice", &["ci".into()])
            .unwrap();
        a.create_token(&actor(), &root, "repl", "token-hash-root", &[])
            .unwrap();
        a.run(&actor(), "settings", |t| {
            t.set_forwarding(
                "tester",
                None,
                &crate::mutation::settings::ForwardingSettings {
                    upstreams: vec!["192.0.2.53:53".parse().unwrap()],
                    // Open resolver mode travels in the snapshot too.
                    allowed_clients: vec!["0.0.0.0/0".into(), "::/0".into()],
                    timeout_ms: 1500,
                    cache_max_ttl: None,
                    cache_negative_max_ttl: None,
                    open_resolver: Some(true),
                },
            )?;
            t.create_tsig_key(
                "tester",
                &crate::mutation::tsig::NewTsigKey {
                    name: "k1.".into(),
                    algorithm: crate::dns::tsig::Algorithm::HmacSha256,
                    secret: b"tsig-secret-bytes".to_vec(),
                    zones: vec![],
                    imported: true,
                },
            )
        })
        .unwrap();
        m.create_zone(
            actor(),
            ZoneInput {
                name: Some("a.test".into()),
                ..Default::default()
            },
            Some(alice.id),
        )
        .await
        .unwrap();
        m.create_record(actor(), "a.test", rec("www", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        m.create_record(
            actor(),
            "a.test",
            RecordInput {
                expires_in: Some(1),
                ..rec("tmp", RecordType::A, "192.0.2.2")
            },
        )
        .await
        .unwrap();
        m.expire_due(chrono::Utc::now() + chrono::Duration::seconds(5))
            .await
            .unwrap();
        // DNSSEC: the key travels as an account-class change, the flag as a zone update.
        m.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        m.set_member(actor(), "a.test", root.id, ZoneRole::Viewer)
            .await
            .unwrap();
        (s, m, a)
    }

    /// Changelog v2 (shadow mode): every write through the real mutation
    /// paths (DNS, accounts, settings, TSIG, DNSSEC, cascades, expiry,
    /// audit) is captured, and replaying the v2 log into an empty database
    /// reproduces every captured table exactly; nothing escaped the capture.
    #[tokio::test]
    async fn changelog_v2_captures_every_change_exactly() {
        use rand::SeedableRng;
        let (ps, pm, pa) = node();
        ps.cdc_set_leader(true);
        let leader = ps.cdc().expect("v2 attached").clone();
        // A follower database: same schema, applying the v2 log.
        // Foreign keys stay on (as rust-dns runs): the crate turns them off
        // around replays itself.
        let fs = Storage::open_memory().unwrap();
        let follower = fs.cdc().expect("v2 attached").clone();
        let mut lines = Vec::new();
        leader
            .snapshot(|mut b| {
                b.pop();
                lines.push(b);
                Ok(())
            })
            .unwrap();
        follower
            .load_snapshot(lines.into_iter().map(Ok), None, &Default::default())
            .unwrap();

        // Accounts, MFA, tokens, settings, TSIG, zones, DNSSEC, members.
        let root = pa.sync_root("root", PRIMARY_ROOT_HASH, false).unwrap();
        let alice = pa
            .create_user(
                &actor(),
                &NewUser {
                    username: "alice".into(),
                    password_hash: "$argon2id$alice-hash".into(),
                    display_name: "Alice".into(),
                    is_admin: false,
                    mfa_required: true,
                },
            )
            .unwrap();
        pa.run(&actor(), "mfa_enroll", |t| {
            let u = t.set_mfa(alice.id, Some("ALICETOTPSECRET"))?;
            t.accept_totp_step(&u, 1000)?;
            t.set_recovery_codes(&u, &["rc-hash-1".into(), "rc-hash-2".into()])
        })
        .unwrap();
        pa.create_token(&actor(), &alice, "ci", "token-hash-alice", &["ci".into()])
            .unwrap();
        pa.run(&actor(), "settings", |t| {
            t.set_forwarding(
                "tester",
                None,
                &crate::mutation::settings::ForwardingSettings {
                    upstreams: vec!["192.0.2.53:53".parse().unwrap()],
                    allowed_clients: vec!["10.0.0.0/8".into()],
                    timeout_ms: 1500,
                    cache_max_ttl: None,
                    cache_negative_max_ttl: None,
                    open_resolver: None,
                },
            )?;
            t.create_tsig_key(
                "tester",
                &crate::mutation::tsig::NewTsigKey {
                    name: "k1.".into(),
                    algorithm: crate::dns::tsig::Algorithm::HmacSha256,
                    secret: b"tsig-secret-bytes".to_vec(),
                    zones: vec![],
                    imported: true,
                },
            )
        })
        .unwrap();
        pm.create_zone(
            actor(),
            ZoneInput {
                name: Some("a.test".into()),
                ..Default::default()
            },
            Some(alice.id),
        )
        .await
        .unwrap();
        pm.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        pm.set_member(actor(), "a.test", root.id, ZoneRole::Viewer)
            .await
            .unwrap();
        pm.create_record(
            actor(),
            "a.test",
            RecordInput {
                expires_in: Some(1),
                ..rec("tmp", RecordType::A, "192.0.2.2")
            },
        )
        .await
        .unwrap();
        pm.expire_due(chrono::Utc::now() + chrono::Duration::seconds(5))
            .await
            .unwrap();
        // Random DNS operations.
        let mut rng = rand::rngs::StdRng::seed_from_u64(20261011);
        for step in 0..250 {
            let _ = crate::mutation::test_support::random_dns_op(&mut rng, &ps, &pm, step).await;
        }
        // Deleting a user and a zone (cascades), and token use bookkeeping
        // (a per-server column: not a change).
        let alice = ps.get_user_by_name("alice").unwrap().unwrap();
        pa.run(&actor(), "delete_user", |t| {
            t.delete_user(&alice).map(|_| ())
        })
        .unwrap();
        let _ = pm.delete_zone(actor(), "a.test").await;

        // Replay into the follower.
        loop {
            let pos = follower.state().unwrap().position().unwrap();
            let (txns, _) = leader.changes(&pos, 1 << 20, 1000).unwrap();
            if txns.is_empty() {
                break;
            }
            follower.apply(&txns).unwrap();
        }
        let st = leader.state().unwrap();
        assert!(
            st.broken.is_none(),
            "a write escaped the capture: {:?}",
            st.broken
        );
        assert!(st.last_txn > 100, "{}", st.last_txn);
        assert!(leader.health().unwrap().is_empty(), "{:?}", leader.health());
        let check = leader.self_check().unwrap();
        assert_eq!(check["ok"], true, "{check}");
        for t in leader.tables() {
            let a = leader.bucket_hashes(&t.name, st.last_txn, 16).unwrap();
            let b = follower.bucket_hashes(&t.name, st.last_txn, 16).unwrap();
            assert_eq!(
                a.buckets, b.buckets,
                "table {} differs after replay",
                t.name
            );
        }
        // Every captured table really was exercised.
        let c = ps.cdc().unwrap().reader().unwrap();
        for t in [
            "zones",
            "records",
            "zone_members",
            "users",
            "recovery_codes",
            "api_tokens",
            "settings",
            "tsig_keys",
            "dnssec_keys",
            "audit_log",
        ] {
            let n: i64 = c
                .query_row("SELECT count(*) FROM _cdc WHERE tbl = ?1", [t], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(n > 0, "no change captured for {t}");
        }
    }

    /// H2: deleting a user releases its zones and memberships as DNS
    /// changes (no serial bump, window kept), and the catalog follows.
    #[tokio::test]
    async fn deleting_a_user_releases_its_zones_as_changes() {
        let (ps, pm, pa) = node();
        pa.sync_root("admin", PRIMARY_ROOT_HASH, false).unwrap();
        let carol = pa
            .create_user(
                &actor(),
                &NewUser {
                    username: "carol".into(),
                    password_hash: "$argon2id$x".into(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        pm.create_zone(actor(), zone_input("a.test"), Some(carol.id))
            .await
            .unwrap();
        pm.create_zone(actor(), zone_input("b.test"), None)
            .await
            .unwrap();
        pm.set_dnssec(actor(), "a.test", true, false).await.unwrap();
        pm.set_member(actor(), "b.test", carol.id, ZoneRole::Editor)
            .await
            .unwrap();
        let a_before = ps.get_zone("a.test").unwrap().unwrap();
        let head = ps.changelog_head().unwrap();

        let released = pm.release_user(actor(), carol.id).await.unwrap();
        assert_eq!(released, (1, 1));
        pa.run(&actor(), "delete_user", |t| t.delete_user(&carol))
            .unwrap();
        let a_after = ps.get_zone("a.test").unwrap().unwrap();
        assert_eq!(a_after.owner_id, None);
        assert_eq!(
            (a_after.serial, &a_after.updated_at, &a_after.signed_at),
            (a_before.serial, &a_before.updated_at, &a_before.signed_at),
            "no serial bump, same signature window"
        );
        assert_eq!(
            pm.cache.load().zones["a.test."].zone.owner_id,
            None,
            "the catalog's zone row follows"
        );
        let kinds: Vec<String> = ps
            .read_tx(|c| data::changelog_tail(c, head))
            .unwrap()
            .iter()
            .map(|e| e.payload["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, ["zone_updated", "member_removed", "user_deleted"]);
    }

    #[tokio::test]
    async fn promotion_starts_a_child_history_at_the_head() {
        let (s, m, _) = populated_primary().await;
        let before = s.read_tx(data::history).unwrap();
        let head = s.changelog_head().unwrap();
        let h = m
            .replica_promote(actor(), "https://old".into(), "api")
            .await
            .unwrap();
        assert_ne!(h.history_id, before.history_id);
        assert_eq!(
            h.parent_history_id.as_deref(),
            Some(before.history_id.as_str())
        );
        assert_eq!(h.fork_offset, Some(head));
        assert_eq!(s.read_tx(data::history).unwrap(), h);
        let audit = s.audit_after(0, 1000).unwrap();
        let row = audit
            .iter()
            .find(|r| r.action == "replication.promote")
            .unwrap();
        assert_eq!(row.detail["fork_offset"], head);
        // The changelog continues from the same sequence.
        m.create_zone(
            actor(),
            ZoneInput {
                name: Some("new.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(s.changelog_after(head, 10).unwrap()[0].offset, head + 1);
    }

    #[tokio::test]
    async fn account_change_payloads_are_scrubbed_after_retention() {
        let (ps, pm, pa) = populated_primary().await;
        pm.create_record(actor(), "a.test", rec("keep", RecordType::A, "192.0.2.9"))
            .await
            .unwrap();
        let before = ps.read_tx(|c| data::changelog_tail(c, 0)).unwrap();
        assert!(before
            .iter()
            .any(|e| e.payload.to_string().contains("alice-hash")));
        // Nothing is old enough yet.
        assert_eq!(
            ps.scrub_account_changes(chrono::Utc::now() - chrono::Duration::days(1))
                .unwrap(),
            0
        );
        let n = ps
            .scrub_account_changes(chrono::Utc::now() + chrono::Duration::days(1))
            .unwrap();
        assert!(n > 5, "{n}");
        let after = ps.read_tx(|c| data::changelog_tail(c, 0)).unwrap();
        assert_eq!(after.len(), before.len(), "offsets stay");
        let text = serde_json::to_string(&after).unwrap();
        for secret in [
            "alice-hash",
            "ALICETOTPSECRET",
            "token-hash-alice",
            "rc-hash-1",
        ] {
            assert!(!text.contains(secret), "{secret} survived the scrub");
        }
        assert!(after
            .iter()
            .filter(|e| e.payload["kind"] == "scrubbed")
            .all(|e| e.entity != "record" && e.entity != "zone"));
        assert!(
            after.iter().any(|e| e.payload["kind"] == "record_created"),
            "DNS rows untouched"
        );
        let _ = pa;
    }

    #[test]
    fn older_servers_report_protocol_1() {
        let id: Identity = serde_json::from_value(serde_json::json!({
            "role": "primary", "writable": true,
            "history": { "history_id": "x", "parent_history_id": null, "fork_offset": null, "promoted_at": null, "promoted_from": null }
        }))
        .unwrap();
        assert_eq!(id.protocol, 1);
        assert_ne!(id.protocol, crate::replication::types::REPLICATION_PROTOCOL);
    }

    /// A buffer the test subscriber writes to.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Secrets never reach the logs, the audit log or the user-facing
    /// changelog (API, websocket, event bus): account, MFA, token, TSIG and
    /// DNSSEC key changes, a key rollover's second private key included.
    #[tokio::test(flavor = "current_thread")]
    async fn secrets_never_reach_logs_audit_or_the_changelog_api() {
        let cap = Captured::default();
        let w = cap.clone();
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || w.clone())
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        // Other tests running in parallel may have cached "not interested"
        // for these call sites; make them ask this subscriber again.
        tracing::callsite::rebuild_interest_cache();
        let (ps, pm, pa) = populated_primary().await;
        pa.run(&actor(), "mfa_enroll", |t| {
            let u = t.change_user(2, &UserChanges::default())?;
            t.set_mfa(u.id, Some("ALICETOTPSECRET2"))
        })
        .unwrap();
        // N1: a key rollover carries a second private key.
        pm.rollover_start(actor(), "a.test").await.unwrap();
        tracing::info!("end of the captured operations");
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("end of the captured operations"),
            "the capture works: {logs}"
        );
        // The user-facing changelog never carries account changes.
        let visible = serde_json::to_string(&ps.changelog_after(0, 100_000).unwrap()).unwrap();
        assert!(!visible.contains("user_created") && !visible.contains("tsig_key_set"));
        assert!(!visible.contains("dnssec_key_set"));
        let audit = serde_json::to_string(&ps.audit_after(0, 1000).unwrap()).unwrap();
        let tsig_b64 = data_encoding::BASE64.encode(b"tsig-secret-bytes");
        let pz = ps.get_zone("a.test").unwrap().unwrap();
        let stored = ps.get_dnssec_key(pz.id).unwrap().unwrap();
        let dnssec_key = stored.private_key.0.clone();
        let rollover_key = stored.rollover.as_ref().unwrap().key.private_key.0.clone();
        for secret in [
            dnssec_key.as_str(),
            rollover_key.as_str(),
            "alice-hash",
            PRIMARY_ROOT_HASH,
            "ALICETOTPSECRET",
            "ALICETOTPSECRET2",
            "rc-hash-1",
            "token-hash-alice",
            tsig_b64.as_str(),
        ] {
            assert!(!logs.contains(secret), "log leaks {secret}");
            assert!(!audit.contains(secret), "audit leaks {secret}");
            assert!(!visible.contains(secret), "changelog API leaks {secret}");
        }
    }
}
