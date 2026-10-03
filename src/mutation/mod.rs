//! The single write path for DNS data (zones, records, zone members) and,
//! in [`accounts`], for users, credentials and sessions.
//!
//! Guarantees, enforced by the type system rather than by call sites:
//! - A write transaction can only be opened with a [`WriteToken`], which only
//!   this module can create. The SQL that writes these tables is private here.
//! - Every DNS operation runs inside [`Mutator::execute`] and receives a [`Tx`].
//!   `Tx` offers reads and a fixed set of write methods; each write method
//!   records a [`Change`]. Operations never see the raw connection.
//! - At commit, `Tx::finish` bumps the SOA serial of every zone whose DNS
//!   content changed and writes one changelog row per `Change`, all in the
//!   same SQLite transaction as the data. Either everything commits, or
//!   nothing does and no changelog row exists.
//! - Validation happens inside the transaction, so every failed operation is
//!   a rolled-back transaction: it is logged (tracing) but never changelogged.
//! - The changelog payload is the exact fact, with ids and timestamps, so
//!   [`replay`] rebuilds identical data from it.

pub mod accounts;
mod acct_sql;
mod dnssec_ops;
mod expiry;
mod gate;
mod import_export;
mod ops;
pub mod replay;
pub mod replica;
pub mod settings;
mod sql;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tsig;
mod tx;

// The module's public names, as before the split (some are named only by
// tests or through other items' signatures).
#[allow(unused_imports)]
pub use dnssec_ops::DnssecChange;
pub use gate::WriteGate;
#[allow(unused_imports)]
pub use import_export::{
    export_zone, ExportDoc, ExportRecord, ExportZone, ImportMode, ImportSummary,
};
pub(crate) use tx::catalog_zones;
#[allow(unused_imports)]
pub use tx::{Change, Tx, CLASS_ACCOUNT, CLASS_DNS};

use crate::cache::{Cache, Catalog};
use crate::events::Bus;
use crate::model::*;
use crate::replication::types::{Hidden, ReplSetting, ReplToken, ReplTsigKey, ReplUser};
use crate::storage::{self as db, Storage};
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Capability required by [`Storage::write`]. The field is private and the
/// only instance lives in this module, so no other module can open a write
/// transaction on the data tables.
pub struct WriteToken {
    _private: (),
}

const TOKEN: WriteToken = WriteToken { _private: () };

/// How much of the catalog a committed write may have changed.
pub(crate) enum Rebuild {
    /// These zones (possibly none).
    Zones(Vec<i64>),
    /// Anything (snapshot load, history change): build it all again.
    Full,
}

#[derive(Debug, thiserror::Error)]
pub enum MutationError {
    /// This server is a read-only standby (or a fenced old primary).
    #[error("{0}")]
    ReadOnly(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<serde_json::Error> for MutationError {
    fn from(e: serde_json::Error) -> Self {
        MutationError::Internal(e.into())
    }
}

impl From<rusqlite::Error> for MutationError {
    fn from(e: rusqlite::Error) -> Self {
        MutationError::Internal(e.into())
    }
}

impl From<Invalid> for MutationError {
    fn from(e: Invalid) -> Self {
        MutationError::Invalid(e.0)
    }
}

type MResult<T> = Result<T, MutationError>;

pub struct Mutator {
    storage: Arc<Storage>,
    cache: Arc<Cache>,
    bus: Arc<Bus>,
    lock: Mutex<()>,
    /// Defaults applied to new zones: (SOA MNAME, SOA RNAME), already normalised.
    zone_defaults: std::sync::RwLock<(Option<String>, Option<String>)>,
    /// Woken after every commit so the expiry sweeper can reschedule.
    expiry_wake: Arc<tokio::sync::Notify>,
    /// Closed on a standby: DNS operations are refused.
    gate: Arc<WriteGate>,
    /// DNSSEC signing settings and signed-zone cache (catalog builds).
    signer: Arc<crate::dnssec::Signer>,
}

/// Read zones, records and keys, build (and sign) the catalog and store it.
/// The ticket is taken before the read, so a slower build that read an
/// older state can never replace a newer catalog, whoever started it (a
/// commit, the DNSSEC re-signer, a retry, a promotion).
fn rebuild_catalog(storage: &Storage, signer: &crate::dnssec::Signer, cache: &Cache) -> Result<()> {
    let ticket = cache.ticket();
    let (zones, records, keys) = storage.catalog_inputs()?;
    let catalog = Catalog::build_signed(zones, records, &keys, signer, chrono::Utc::now());
    cache.store_built(ticket, catalog);
    Ok(())
}

/// Rebuild only the zones `ids` (read again from storage, converted and
/// signed) and keep every other zone of the current catalog. Must be
/// called with the mutator lock held, after the commit: see
/// [`Cache::apply`] for why no committed change can be lost.
fn update_catalog(
    storage: &Storage,
    signer: &crate::dnssec::Signer,
    cache: &Cache,
    ids: &[i64],
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let ticket = cache.ticket();
    let updates = storage.catalog_zone_inputs(ids)?;
    let now = chrono::Utc::now();
    cache.apply(ticket, |base| {
        Catalog::with_zones(base, &updates, signer, now)
    });
    Ok(())
}

impl Mutator {
    pub fn new(
        storage: Arc<Storage>,
        cache: Arc<Cache>,
        bus: Arc<Bus>,
        default_primary_ns: &str,
        default_hostmaster: &str,
    ) -> Self {
        let m = Mutator {
            storage,
            cache,
            bus,
            lock: Mutex::new(()),
            zone_defaults: std::sync::RwLock::new((None, None)),
            expiry_wake: Arc::new(tokio::sync::Notify::new()),
            gate: Arc::new(WriteGate::default()),
            signer: Arc::new(crate::dnssec::Signer::default()),
        };
        m.set_zone_defaults(default_primary_ns, default_hostmaster);
        m
    }

    pub fn set_zone_defaults(&self, default_primary_ns: &str, default_hostmaster: &str) {
        let mname = normalize_domain(default_primary_ns, true)
            .ok()
            .map(|n| format!("{n}."));
        let rname = ops::normalize_rname(default_hostmaster).ok();
        *self.zone_defaults.write().unwrap() = (mname, rname);
    }

    /// The write gate shared with the replication runtime.
    pub fn gate(&self) -> Arc<WriteGate> {
        self.gate.clone()
    }

    /// Wake the expiry sweeper (e.g. after a promotion made this node writable).
    pub fn wake_expiry(&self) {
        self.expiry_wake.notify_one();
    }

    fn defaults(&self) -> (Option<String>, Option<String>) {
        self.zone_defaults.read().unwrap().clone()
    }

    /// DNSSEC signing state (settings, signed-zone cache, errors).
    pub fn signer(&self) -> Arc<crate::dnssec::Signer> {
        self.signer.clone()
    }

    /// Apply `[dnssec]` (startup and reload). Takes effect at the next
    /// catalog build (the re-sign task rebuilds when windows change).
    pub fn set_dnssec_config(&self, cfg: crate::config::DnssecConfig) {
        self.signer.set_config(cfg);
        self.expiry_wake.notify_one();
    }

    /// Rebuild the catalog from storage (used at startup).
    pub fn rebuild(&self) -> Result<()> {
        rebuild_catalog(&self.storage, &self.signer, &self.cache)
    }

    /// Run one operation as one SQLite transaction.
    ///
    /// Committed: data and changelog rows are durable, the catalog is rebuilt
    /// and the change events are published. Rolled back (any error, or a
    /// panic): nothing is written, no changelog row exists, and the failure
    /// is logged.
    async fn execute<T: Send + 'static>(
        &self,
        actor: Actor,
        command: &'static str,
        f: impl for<'t> FnOnce(&mut Tx<'t>) -> MResult<T> + Send + 'static,
    ) -> MResult<T> {
        let _guard = self.lock.lock().await;
        if self.gate.read_only() {
            let why = self.gate.reason();
            tracing::warn!(command, actor = %actor.name, ip = %actor.ip, reason = %why, "write refused: read-only server");
            return Err(MutationError::ReadOnly(why));
        }
        let storage = self.storage.clone();
        let tx_actor = actor.clone();
        let joined = tokio::task::spawn_blocking(move || {
            storage.write(&TOKEN, |conn| -> MResult<(T, Vec<ChangeEvent>, Vec<i64>)> {
                let mut t = Tx::new(conn);
                let out = f(&mut t)?;
                let (events, zones) = t.finish(&tx_actor, command)?;
                Ok((out, events, zones))
            })
        })
        .await;
        let (out, events, zones) = match joined {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                match &e {
                    MutationError::Internal(_) => {
                        tracing::error!(command, actor = %actor.name, ip = %actor.ip, error = %e, "transaction rolled back; nothing committed, no changelog written")
                    }
                    _ => {
                        tracing::warn!(command, actor = %actor.name, ip = %actor.ip, error = %e, "transaction rolled back; nothing committed, no changelog written")
                    }
                }
                return Err(e);
            }
            Err(join) => {
                tracing::error!(command, actor = %actor.name, ip = %actor.ip, error = %join, "write task failed; transaction rolled back, no changelog written");
                return Err(MutationError::Internal(anyhow::anyhow!(
                    "write task failed: {join}"
                )));
            }
        };
        // Committed. From here on nothing may turn the result into an error:
        // the caller must learn that the change happened. Still under the
        // lock: only the zones this transaction touched are rebuilt.
        self.refresh_catalog(Rebuild::Zones(zones)).await;
        self.expiry_wake.notify_one();
        for ev in events {
            tracing::info!(offset = ev.offset, txn = %ev.txn, command, actor = %ev.actor, ip = %ev.actor_ip, action = %ev.action, entity = %ev.entity, zone = %ev.zone, "change committed");
            self.bus.publish_change(ev);
        }
        Ok(out)
    }

    /// Bring the in-memory catalog up to date after a commit:
    /// [`Rebuild::Zones`] rebuilds just those zones (the caller holds the
    /// mutator lock), [`Rebuild::Full`] everything. A failure is logged
    /// and retried in the background with full builds (which cover
    /// whatever an incremental build missed); it never un-commits the
    /// change.
    pub(crate) async fn refresh_catalog(&self, what: Rebuild) {
        let build =
            |storage: Arc<Storage>, signer: Arc<crate::dnssec::Signer>, cache: Arc<Cache>| {
                tokio::task::spawn_blocking(move || rebuild_catalog(&storage, &signer, &cache))
            };
        let (storage, signer, cache) = (
            self.storage.clone(),
            self.signer.clone(),
            self.cache.clone(),
        );
        let first = match what {
            Rebuild::Zones(ids) => {
                let (s, g, c) = (storage.clone(), signer.clone(), cache.clone());
                tokio::task::spawn_blocking(move || update_catalog(&s, &g, &c, &ids)).await
            }
            Rebuild::Full => build(storage.clone(), signer.clone(), cache.clone()).await,
        };
        let err = match first {
            Ok(Ok(())) => return,
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };
        tracing::error!(error = %err, "catalog rebuild failed after commit; DNS answers are stale until it succeeds");
        tokio::spawn(async move {
            for attempt in 1..=10u64 {
                tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
                if let Ok(Ok(())) = build(storage.clone(), signer.clone(), cache.clone()).await {
                    tracing::info!(attempt, "catalog rebuilt after earlier failure");
                    return;
                }
            }
            tracing::error!("catalog rebuild still failing; restart the server");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// D3: after every committed operation the incrementally maintained
    /// catalog equals a full build of the database (zone rows, records and
    /// their wire form, existing names, delegations, the reverse index
    /// across zones, the signed view), and all signatures verify.
    #[tokio::test]
    async fn incremental_catalog_builds_equal_full_builds() {
        for seed in [1u64, 20261003, 77] {
            let (s, m, _) = setup();
            let mut rng = StdRng::seed_from_u64(seed);
            let (mut ok, mut failed) = (0, 0);
            let mut kinds = std::collections::BTreeSet::new();
            let mut signed_steps = 0;
            for step in 0..260 {
                let before = s.changelog_head().unwrap();
                match random_dns_op(&mut rng, &s, &m, step).await {
                    Ok(()) => ok += 1,
                    Err(_) => failed += 1,
                }
                for e in s.changelog_after(before, 10_000).unwrap() {
                    kinds.insert(e.payload["kind"].as_str().unwrap().to_string());
                }
                assert_catalog_is_current(&s, &m, &format!("seed {seed} step {step}"));
                if m.cache.load().zones.values().any(|z| z.signed.is_some()) {
                    signed_steps += 1;
                }
            }
            assert!(
                ok > 120 && failed > 10,
                "seed {seed}: {ok} ok, {failed} rejected"
            );
            for k in [
                "zone_created",
                "zone_updated",
                "zone_deleted",
                "record_created",
                "record_updated",
                "record_deleted",
                "record_expired",
                "serial_bumped",
                "zone_resigned",
            ] {
                assert!(kinds.contains(k), "seed {seed}: no {k} in the sequence");
            }
            assert!(
                signed_steps > 20,
                "seed {seed}: signed zones in {signed_steps} steps"
            );

            // Real expiry: records whose time passes are dropped by the
            // sweep (as a full build at that moment drops them), then reaped.
            for z in ["eq.test", "other.test"] {
                let _ = m.create_zone(actor(), zone_input(z), None).await;
                m.create_record(
                    actor(),
                    z,
                    RecordInput {
                        expires_in: Some(1),
                        ..rec("soon", RecordType::A, "10.0.0.250")
                    },
                )
                .await
                .unwrap();
            }
            assert_catalog_is_current(&s, &m, "expiring records added");
            assert!(m
                .cache
                .load()
                .reverse
                .contains_key("250.0.0.10.in-addr.arpa."));
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            assert_eq!(m.expire_due(chrono::Utc::now()).await.unwrap(), 2);
            assert_catalog_is_current(&s, &m, "after expiry");
            assert!(!m
                .cache
                .load()
                .reverse
                .contains_key("250.0.0.10.in-addr.arpa."));
            m.reap_due(chrono::Utc::now()).await.unwrap();
            assert_catalog_is_current(&s, &m, "after reaping");
            // A zone replaced by a new one of the same name in one step.
            m.delete_zone(actor(), "eq.test").await.unwrap();
            m.create_zone(actor(), zone_input("eq.test"), None)
                .await
                .unwrap();
            assert_catalog_is_current(&s, &m, "zone recreated");
            // An empty zone deleted: `zone_deleted` is the only change.
            m.create_zone(actor(), zone_input("empty.test"), None)
                .await
                .unwrap();
            assert!(m.cache.load().zones.contains_key("empty.test."));
            m.delete_zone(actor(), "empty.test").await.unwrap();
            assert!(!m.cache.load().zones.contains_key("empty.test."));
            assert_catalog_is_current(&s, &m, "empty zone deleted");
        }
    }
}
