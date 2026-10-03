//! Record expiry: the in-memory watch (every node) and the sweeper that
//! records expiries and reaps old records (primary).

use super::*;

impl Mutator {
    // ---- expiry --------------------------------------------------------

    /// Stop serving records whose expiry has passed, in memory: the zones
    /// that serve one are built again as of `now` (expired records left
    /// out, a signed zone's NSEC chain and signatures follow). Never a
    /// write, so it runs on every node, a standby included. The primary's
    /// sweeper then records `record_expired` (and the serial bump); until
    /// that arrives, a standby serves the zone without the record at the
    /// old serial. Returns the zones rebuilt.
    pub async fn drop_expired_in_memory(&self, now: chrono::DateTime<chrono::Utc>) -> usize {
        let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if self.cache.load().zones_expiring_by(&now_s).is_empty() {
            return 0; // the usual case: do not wait for the lock
        }
        // Incremental builds only under the mutator lock (see `Cache::apply`).
        let _guard = self.lock.lock().await;
        let ids = self.cache.load().zones_expiring_by(&now_s);
        if ids.is_empty() {
            return 0;
        }
        let n = ids.len();
        let (s, g, c) = (
            self.storage.clone(),
            self.signer.clone(),
            self.cache.clone(),
        );
        let built = tokio::task::spawn_blocking(move || update_catalog(&s, &g, &c, &ids)).await;
        match built {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "in-memory expiry rebuild failed; retrying"),
            Err(e) => tracing::error!(error = %e, "in-memory expiry rebuild failed; retrying"),
        }
        n
    }

    /// Background task (every node): at the earliest expiry of a served
    /// record, rebuild its zone in memory without it
    /// ([`Mutator::drop_expired_in_memory`]). Wakes when a new catalog is
    /// stored (new records, replicated changes) and at least every minute.
    pub fn spawn_expiry_watch(self: &Arc<Self>) {
        let m = self.clone();
        tokio::spawn(async move {
            loop {
                let now = chrono::Utc::now();
                let n = m.drop_expired_in_memory(now).await;
                if n > 0 {
                    tracing::debug!(zones = n, "expired records dropped from the served catalog");
                    let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    if !m.cache.load().zones_expiring_by(&now_s).is_empty() {
                        // The rebuild failed: retry, but do not spin.
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
                let max = std::time::Duration::from_secs(60);
                let wait = m
                    .cache
                    .load()
                    .next_expiry()
                    .and_then(|n| chrono::DateTime::parse_from_rfc3339(n).ok())
                    .map(|next| {
                        // 1 ms past it: expiry times have millisecond precision.
                        (next.with_timezone(&chrono::Utc) - chrono::Utc::now()
                            + chrono::Duration::milliseconds(1))
                        .to_std()
                        .unwrap_or_default()
                        .min(max)
                    })
                    .unwrap_or(max);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = m.cache.stored() => {}
                }
            }
        });
    }

    fn system_actor() -> Actor {
        Actor {
            name: "system".into(),
            ip: "expiry".into(),
        }
    }

    /// Stop serving every record whose expiry is at or before `now`, in one
    /// transaction (changelog + serial bumps). Returns how many expired.
    pub async fn expire_due(&self, now: chrono::DateTime<chrono::Utc>) -> MResult<usize> {
        let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.execute(Self::system_actor(), "expire_records", move |t| {
            let due = sql::due_expiries(t.conn, &now_s)?;
            for r in &due {
                if let Some(z) = t.zone_by_id(r.zone_id)? {
                    t.expire_record(&z, r)?;
                }
            }
            Ok(due.len())
        })
        .await
    }

    /// Delete records whose expiry is at or before `cutoff` (now minus the retention period).
    pub async fn reap_due(&self, cutoff: chrono::DateTime<chrono::Utc>) -> MResult<usize> {
        let cutoff_s = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.execute(Self::system_actor(), "reap_expired_records", move |t| {
            let due = sql::due_reaps(t.conn, &cutoff_s)?;
            for r in &due {
                if let Some(z) = t.zone_by_id(r.zone_id)? {
                    // The sweeper runs expire_due first in the same pass, so a record is
                    // always marked expired (serial bumped) before it is reaped.
                    t.reap_record(&z, r)?;
                }
            }
            Ok(due.len())
        })
        .await
    }

    /// Background task: expire records exactly when due and reap them after
    /// `retention_days`. Wakes at the next expiry, after any commit, or at
    /// least every `sweep_interval_secs`.
    pub fn spawn_expiry_sweeper(
        self: &Arc<Self>,
        settings: impl Fn() -> crate::config::ExpiryConfig + Send + Sync + 'static,
    ) {
        let m = self.clone();
        tokio::spawn(async move {
            loop {
                let cfg = settings();
                // A standby does not expire records itself: RecordExpired /
                // RecordReaped arrive in the primary's changelog.
                if m.gate.read_only() {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(cfg.sweep_interval_secs.max(1))) => {}
                        _ = m.expiry_wake.notified() => {}
                    }
                    continue;
                }
                let now = chrono::Utc::now();
                if m.storage
                    .next_expiry()
                    .ok()
                    .flatten()
                    .is_some_and(|n| n <= now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                {
                    match m.expire_due(now).await {
                        Ok(n) if n > 0 => {
                            tracing::info!(expired = n, "records expired; no longer served")
                        }
                        Err(e) => tracing::error!(error = %e, "expiry sweep failed"),
                        _ => {}
                    }
                }
                let cutoff = now - chrono::Duration::days(cfg.retention_days as i64);
                if m.storage
                    .oldest_expiry_before(
                        &cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    )
                    .unwrap_or(false)
                {
                    match m.reap_due(cutoff).await {
                        Ok(n) if n > 0 => tracing::info!(
                            reaped = n,
                            retention_days = cfg.retention_days,
                            "expired records deleted"
                        ),
                        Err(e) => tracing::error!(error = %e, "expiry reap failed"),
                        _ => {}
                    }
                }
                // Sleep until the next expiry, but never longer than the sweep interval.
                let max = std::time::Duration::from_secs(cfg.sweep_interval_secs.max(1));
                let wait = match m
                    .storage
                    .next_expiry()
                    .ok()
                    .flatten()
                    .and_then(|n| chrono::DateTime::parse_from_rfc3339(&n).ok())
                {
                    Some(next) => (next.with_timezone(&chrono::Utc) - chrono::Utc::now())
                        .to_std()
                        .unwrap_or_default()
                        .min(max),
                    None => max,
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait + std::time::Duration::from_millis(5)) => {}
                    _ = m.expiry_wake.notified() => {}
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;

    /// H3: at its expiry a record leaves the served catalog without any
    /// commit (the watch rebuilds its zone in memory), here with the
    /// write gate closed, as on a standby. Nothing is written; the signed
    /// zone equals a full build at that time and its signatures verify;
    /// zones without a due record are not rebuilt.
    #[tokio::test]
    async fn expired_records_leave_the_catalog_at_their_expiry_without_a_commit() {
        let (s, m, _) = setup();
        let m = Arc::new(m);
        for z in ["e.test", "other.test"] {
            m.create_zone(actor(), zone_input(z), None).await.unwrap();
            m.create_record(actor(), z, rec("ns1", RecordType::A, "192.0.2.53"))
                .await
                .unwrap();
        }
        m.set_dnssec(actor(), "e.test", true, false).await.unwrap();
        m.create_record(actor(), "e.test", expiring("tmp", "192.0.2.1", 1))
            .await
            .unwrap();
        m.create_record(actor(), "e.test", expiring("later", "192.0.2.2", 3600))
            .await
            .unwrap();
        let head = s.changelog_head().unwrap();
        m.gate().close("standby");
        let cat = m.cache.load();
        assert!(cat.zones["e.test."].records_at("tmp.e.test.").is_some());
        let other = cat.zones["other.test."].clone();
        assert!(cat.next_expiry().is_some());
        assert_eq!(m.drop_expired_in_memory(chrono::Utc::now()).await, 0);

        m.spawn_expiry_watch();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while m.cache.load().zones["e.test."]
            .records_at("tmp.e.test.")
            .is_some()
        {
            assert!(std::time::Instant::now() < deadline, "still served");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let cat = m.cache.load();
        assert!(cat.zones["e.test."].records_at("later.e.test.").is_some());
        assert!(
            Arc::ptr_eq(&cat.zones["other.test."], &other),
            "other zones are shared, not rebuilt"
        );
        assert_eq!(s.changelog_head().unwrap(), head, "nothing written");
        let stored = s.get_zone("e.test").unwrap().unwrap();
        assert_eq!(s.list_records(stored.id).unwrap().len(), 3, "still stored");
        assert_catalog_is_current(&s, &m, "after the in-memory expiry");
        assert!(cat.verify_signatures() > 0);
    }

    #[tokio::test]
    async fn records_expire_then_get_reaped() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("e.test"), None)
            .await
            .unwrap();
        let (r, renewed) = m
            .create_record(actor(), "e.test", expiring("tmp", "192.0.2.1", 3600))
            .await
            .unwrap();
        assert!(!renewed && r.expires_at.is_some());
        let serial = s.get_zone("e.test").unwrap().unwrap().serial;
        let exp = chrono::DateTime::parse_from_rfc3339(r.expires_at.as_deref().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc);

        // Before expiry: nothing due.
        assert_eq!(
            m.expire_due(exp - chrono::Duration::seconds(1))
                .await
                .unwrap(),
            0
        );
        let before = log(&s).len();
        // At expiry: one change and one serial bump, in one transaction.
        assert_eq!(m.expire_due(exp).await.unwrap(), 1);
        let tail: Vec<String> = log(&s)[before..]
            .iter()
            .map(|e| format!("{} {}", e.action, e.entity))
            .collect();
        assert_eq!(tail, vec!["expire record", "update serial"]);
        assert_eq!(s.get_zone("e.test").unwrap().unwrap().serial, serial + 1);
        assert_eq!(
            m.expire_due(exp).await.unwrap(),
            0,
            "each record expires once"
        );
        let at = exp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let cat = Catalog::build_at(s.list_zones().unwrap(), s.all_records().unwrap(), &at);
        assert!(
            cat.zones["e.test."].records_at("tmp.e.test.").is_none(),
            "expired records are not served"
        );
        assert_eq!(
            s.all_records().unwrap().len(),
            1,
            "still stored until reaped"
        );

        // Reaped once expiry + retention has passed, without another serial bump.
        assert_eq!(
            m.reap_due(exp - chrono::Duration::seconds(1))
                .await
                .unwrap(),
            0
        );
        assert_eq!(m.reap_due(exp).await.unwrap(), 1);
        assert!(s.all_records().unwrap().is_empty());
        assert_eq!(s.get_zone("e.test").unwrap().unwrap().serial, serial + 1);
        assert_eq!(log(&s).last().unwrap().action, "reap");
    }
}
