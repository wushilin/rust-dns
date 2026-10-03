//! DNSSEC operations: signing on/off, key generation, and the re-signer.

use super::*;

/// What `PUT /zones/{zone}/dnssec` did.
#[derive(Debug, Clone)]
pub struct DnssecChange {
    pub zone: Zone,
    /// A new key was generated (first enable, or `new_key`).
    pub key_generated: bool,
    /// Signing was switched on or off by this call.
    pub changed: bool,
}

impl Mutator {
    // ---- DNSSEC --------------------------------------------------------

    /// Turn DNSSEC signing on or off for a zone. On: the zone's key is
    /// generated the first time (or replaced with `new_key`, only while
    /// signing is off) and the zone's `dnssec` flag set, all in one
    /// transaction (a serial bump; the key is an account-class change).
    /// Off: the flag is cleared; the key is kept, so turning signing back
    /// on reuses it (the DS at the registrar stays valid).
    pub async fn set_dnssec(
        &self,
        actor: Actor,
        zone_name: &str,
        enable: bool,
        new_key: bool,
    ) -> MResult<DnssecChange> {
        let zone_name = zone_name.to_string();
        let (name, key_generated, changed) = self
            .execute(actor, if enable { "enable_dnssec" } else { "disable_dnssec" }, move |t| {
                let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
                if !enable {
                    if new_key {
                        return Err(MutationError::Invalid(
                            "new_key applies only when turning signing on".into(),
                        ));
                    }
                    if !z.dnssec {
                        return Ok((z.name, false, false));
                    }
                    let mut after = z.clone();
                    after.dnssec = false;
                    t.update_zone(z.clone(), after)?;
                    return Ok((z.name, false, true));
                }
                if new_key && z.dnssec {
                    return Err(MutationError::Conflict(
                        "the key cannot be replaced while signing is on: remove the DS at the registrar, wait for its TTL, turn signing off, then turn it on with a new key".into(),
                    ));
                }
                let mut generated = false;
                if new_key || t.dnssec_key(z.id)?.is_none() {
                    let k = crate::dnssec::generate_key()?;
                    let rdata = crate::dnssec::wire::dnskey_rdata(
                        crate::dnssec::CSK_FLAGS,
                        crate::dnssec::ALGORITHM,
                        &k.public_key,
                    );
                    t.set_dnssec_key(crate::replication::types::ReplDnssecKey {
                        zone_id: z.id,
                        zone: z.name.clone(),
                        algorithm: crate::dnssec::ALGORITHM,
                        flags: crate::dnssec::CSK_FLAGS,
                        key_tag: crate::dnssec::wire::key_tag(&rdata),
                        public_key: data_encoding::BASE64.encode(&k.public_key),
                        private_key: crate::replication::types::Hidden(
                            data_encoding::BASE64.encode(&k.pkcs8),
                        ),
                        created_at: now_rfc3339(),
                    })?;
                    generated = true;
                }
                if z.dnssec {
                    return Ok((z.name, generated, false));
                }
                let mut after = z.clone();
                after.dnssec = true;
                t.update_zone(z.clone(), after)?;
                Ok((z.name, generated, true))
            })
            .await?;
        let zone = self
            .storage
            .get_zone(&name)?
            .ok_or_else(|| MutationError::NotFound(format!("zone '{name}' not found")))?;
        Ok(DnssecChange {
            zone,
            key_generated,
            changed,
        })
    }

    /// Signed zones whose signatures are due for re-signing at `now`
    /// (`[dnssec].resign_before_days` before they expire).
    pub fn resign_candidates(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<String> {
        let cfg = self.signer.config();
        self.cache
            .load()
            .zones
            .values()
            .filter(|z| z.zone.dnssec)
            .filter(|z| {
                crate::dnssec::resign_due_at(z.zone.signing_epoch(), &cfg)
                    .is_some_and(|due| now.timestamp() >= due)
            })
            .map(|z| z.zone.name.clone())
            .collect()
    }

    /// Re-sign every due zone: one transaction with a `zone_resigned` change
    /// and a serial bump per zone. Returns the zones re-signed. Refused on
    /// a standby (the primary's bumps replicate).
    pub async fn resign_due(&self, now: chrono::DateTime<chrono::Utc>) -> MResult<Vec<String>> {
        let due = self.resign_candidates(now);
        if due.is_empty() {
            return Ok(vec![]);
        }
        let cfg = self.signer.config();
        let ts = now.timestamp();
        self.execute(
            Actor {
                name: "system".into(),
                ip: "dnssec".into(),
            },
            "resign_zones",
            move |t| {
                let mut done = Vec::new();
                for name in due {
                    let Some(z) = t.zone(&name)? else { continue };
                    if !z.dnssec {
                        continue;
                    }
                    let Some(due) = crate::dnssec::resign_due_at(z.signing_epoch(), &cfg) else {
                        continue;
                    };
                    if ts < due {
                        continue; // changed meanwhile: signed afresh already
                    }
                    let Some(key) = t.dnssec_key(z.id)? else {
                        continue;
                    };
                    t.resign_zone(&z, key.key_tag)?;
                    done.push(z.name);
                }
                Ok(done)
            },
        )
        .await
    }

    /// Background task (every node): on a writable primary, re-sign zones
    /// when due; everywhere, rebuild the catalog in memory when a signature
    /// window would change without a serial bump (a standby cut off from
    /// its primary; never a write).
    pub fn spawn_resigner(self: &Arc<Self>) {
        let m = self.clone();
        tokio::spawn(async move {
            loop {
                let now = chrono::Utc::now();
                if !m.gate.read_only() {
                    match m.resign_due(now).await {
                        Ok(z) if !z.is_empty() => {
                            tracing::info!(zones = ?z, "DNSSEC: zones re-signed (serial bumped)")
                        }
                        Ok(_) => {}
                        Err(MutationError::ReadOnly(_)) => {}
                        Err(e) => tracing::error!(error = %e, "DNSSEC re-sign failed; retrying"),
                    }
                }
                if m.signer.window_stale(&m.cache.load(), now.timestamp()) {
                    tracing::info!("DNSSEC: signature window moved without a serial change; re-signing in memory");
                    m.refresh_catalog(Rebuild::Full).await;
                }
                // Next check: the earliest due re-sign, within 1 min .. 1 h.
                let cfg = m.signer.config();
                let next = m
                    .cache
                    .load()
                    .zones
                    .values()
                    .filter(|z| z.zone.dnssec)
                    .filter_map(|z| crate::dnssec::resign_due_at(z.zone.signing_epoch(), &cfg))
                    .min()
                    .map(|due| (due - chrono::Utc::now().timestamp()).clamp(60, 3600))
                    .unwrap_or(3600);
                tokio::time::sleep(std::time::Duration::from_secs(next as u64)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;

    /// Full contents of every replicated table (all columns except the
    /// per-server `last_used_*` of tokens), generic over the registry: a
    /// column missing from a change payload makes the comparison fail.

    #[tokio::test]
    async fn dnssec_enable_disable_keeps_the_key_and_hides_it() {
        let (s, m, _) = setup();
        let rx = m.bus.subscribe_changes().unwrap();
        m.create_zone(actor(), zone_input("sec.test"), None)
            .await
            .unwrap();
        m.create_record(actor(), "sec.test", rec("www", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        let before = s.get_zone("sec.test").unwrap().unwrap();
        let on = m
            .set_dnssec(actor(), "sec.test", true, false)
            .await
            .unwrap();
        assert!(on.changed && on.key_generated && on.zone.dnssec);
        assert_eq!(
            on.zone.serial,
            before.serial + 1,
            "turning signing on bumps the serial"
        );
        let key = s.get_dnssec_key(on.zone.id).unwrap().unwrap();
        assert_eq!((key.algorithm, key.flags), (13, 257));
        // The catalog serves the signed view.
        let signed = m.cache.load().zones["sec.test."].signed.clone().unwrap();
        assert_eq!(signed.key_tag, key.key_tag);

        // The key is an account-class change: in the full changelog (standbys),
        // never in the user-facing changelog, never on the event bus.
        let all = s
            .read_tx(|c| crate::replication::data::changelog_tail(c, 0))
            .unwrap();
        let key_rows: Vec<&ChangeEvent> = all
            .iter()
            .filter(|e| e.payload["kind"] == "dnssec_key_set")
            .collect();
        assert_eq!(key_rows.len(), 1);
        assert_eq!(key_rows[0].zone, "", "account rows carry no zone name");
        let secret = &key.private_key.0;
        let visible = s.changelog_after(0, 10_000).unwrap();
        assert!(visible
            .iter()
            .all(|e| e.payload["kind"] != "dnssec_key_set"));
        assert!(
            !serde_json::to_string(&visible)
                .unwrap()
                .contains(secret.as_str()),
            "private key never in the user-facing changelog"
        );
        let mut published = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            published.push(ev);
        }
        assert!(published
            .iter()
            .any(|e| e.payload["kind"] == "zone_updated"));
        assert!(
            !serde_json::to_string(&published)
                .unwrap()
                .contains(secret.as_str()),
            "private key never published to the websocket / live feed"
        );
        assert!(
            !format!("{key:?}").contains(secret.as_str()),
            "Debug hides it"
        );

        // Idempotent; the key cannot be replaced while signing is on.
        let again = m
            .set_dnssec(actor(), "sec.test", true, false)
            .await
            .unwrap();
        assert!(!again.changed && !again.key_generated);
        assert!(matches!(
            m.set_dnssec(actor(), "sec.test", true, true).await,
            Err(MutationError::Conflict(_))
        ));
        // Off keeps the key; on again reuses it (the published DS stays valid).
        let off = m
            .set_dnssec(actor(), "sec.test", false, false)
            .await
            .unwrap();
        assert!(off.changed && !off.zone.dnssec);
        assert!(m.cache.load().zones["sec.test."].signed.is_none());
        let on2 = m
            .set_dnssec(actor(), "sec.test", true, false)
            .await
            .unwrap();
        assert!(!on2.key_generated);
        assert_eq!(
            s.get_dnssec_key(on.zone.id).unwrap().unwrap().key_tag,
            key.key_tag
        );
        // A new key only while off.
        m.set_dnssec(actor(), "sec.test", false, false)
            .await
            .unwrap();
        let rotated = m.set_dnssec(actor(), "sec.test", true, true).await.unwrap();
        assert!(rotated.key_generated);
        assert_ne!(
            s.get_dnssec_key(on.zone.id).unwrap().unwrap().public_key,
            key.public_key
        );
        // Deleting the zone deletes its key, as a logged change.
        m.delete_zone(actor(), "sec.test").await.unwrap();
        assert!(s.get_dnssec_key(on.zone.id).unwrap().is_none());
        let all = s
            .read_tx(|c| crate::replication::data::changelog_tail(c, 0))
            .unwrap();
        assert!(all
            .iter()
            .any(|e| e.payload["kind"] == "dnssec_key_deleted"));
    }

    #[tokio::test]
    async fn resign_bumps_the_serial_only_when_due_and_never_on_a_standby() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("rs.test"), None)
            .await
            .unwrap();
        m.set_dnssec(actor(), "rs.test", true, false).await.unwrap();
        let z0 = s.get_zone("rs.test").unwrap().unwrap();
        let sig0 = m.cache.load().zones["rs.test."].signed.clone().unwrap();
        // Not due now, nor 6 days from now (validity 14, re-sign 7 days before expiry).
        assert!(m.resign_due(chrono::Utc::now()).await.unwrap().is_empty());
        assert!(m
            .resign_due(chrono::Utc::now() + chrono::Duration::days(6))
            .await
            .unwrap()
            .is_empty());
        assert_eq!(s.get_zone("rs.test").unwrap().unwrap().serial, z0.serial);
        // Due 7 days in: one zone_resigned + serial bump.
        let done = m
            .resign_due(chrono::Utc::now() + chrono::Duration::days(7))
            .await
            .unwrap();
        assert_eq!(done, vec!["rs.test".to_string()]);
        let z1 = s.get_zone("rs.test").unwrap().unwrap();
        assert_eq!(z1.serial, z0.serial + 1);
        let log = log(&s);
        assert!(log
            .iter()
            .any(|e| e.payload["kind"] == "zone_resigned" && e.zone == "rs.test"));
        let sig1 = m.cache.load().zones["rs.test."].signed.clone().unwrap();
        assert!(
            sig1.inception >= sig0.inception,
            "signed afresh for the new serial"
        );
        // The window follows the new change time: not due again right away.
        assert!(m
            .resign_due(chrono::Utc::now() + chrono::Duration::days(1))
            .await
            .unwrap()
            .is_empty());
        // A read-only standby never re-signs.
        m.gate().close("standby");
        assert!(matches!(
            m.resign_due(chrono::Utc::now() + chrono::Duration::days(30))
                .await,
            Err(MutationError::ReadOnly(_))
        ));
        assert_eq!(s.get_zone("rs.test").unwrap().unwrap().serial, z1.serial);
    }

    #[tokio::test]
    async fn signing_uses_the_same_window_for_the_same_zone_state() {
        let (_, m, _) = setup();
        m.create_zone(actor(), zone_input("w.test"), None)
            .await
            .unwrap();
        m.set_dnssec(actor(), "w.test", true, false).await.unwrap();
        let a = m.cache.load().zones["w.test."].signed.clone().unwrap();
        m.rebuild().unwrap();
        let b = m.cache.load().zones["w.test."].signed.clone().unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "unchanged zone: signatures reused from the cache"
        );
        // A change elsewhere does not re-sign this zone either.
        m.create_zone(actor(), zone_input("other.test"), None)
            .await
            .unwrap();
        let c = m.cache.load().zones["w.test."].signed.clone().unwrap();
        assert!(Arc::ptr_eq(&a, &c));
        // A change in the zone re-signs it.
        m.create_record(actor(), "w.test", rec("x", RecordType::A, "192.0.2.9"))
            .await
            .unwrap();
        let d = m.cache.load().zones["w.test."].signed.clone().unwrap();
        assert!(!Arc::ptr_eq(&a, &d));
        assert!(d.nsec_at("x.w.test.").is_some());
    }

    /// D2/D3 at size: one record change in a signed zone of 5,000 records
    /// signs a handful of RRsets, and does not touch the other zone.
    #[tokio::test]
    async fn one_change_in_a_large_signed_zone_signs_a_few_rrsets() {
        let (s, m, _) = setup();
        for z in ["big.test", "bystander.test"] {
            m.create_zone(actor(), zone_input(z), None).await.unwrap();
            let id = s.get_zone(z).unwrap().unwrap().id;
            let mut sql = String::from("BEGIN;");
            for i in 0..5000 {
                sql.push_str(&format!(
                    "INSERT INTO records (zone_id, name, rtype, value, created_at, updated_at) VALUES ({id}, 'h{i}', 'A', '10.{}.{}.{}', 't', 't');",
                    id, i / 250, i % 250 + 1
                ));
            }
            sql.push_str("COMMIT;");
            s.exec_raw(&sql).unwrap();
        }
        m.rebuild().unwrap();
        let t = std::time::Instant::now();
        m.set_dnssec(actor(), "big.test", true, false)
            .await
            .unwrap();
        m.set_dnssec(actor(), "bystander.test", true, false)
            .await
            .unwrap();
        let enable = t.elapsed();
        let signer = m.signer();
        let big = || m.cache.load().zones["big.test."].clone();
        let bystander = m.cache.load().zones["bystander.test."].clone();
        let all = big().signed.as_ref().unwrap().signed_rrsets;
        assert_eq!(all, 5000 + 5001 + 3, "RRsets + NSECs + apex SOA/NS/DNSKEY");

        // What a change cost before D1-D3: every zone read, every signed
        // zone signed again (the window moved with each change).
        let t = std::time::Instant::now();
        let full = full_build(&s, &m);
        let full_took = t.elapsed();
        let full_sigs: usize = full
            .zones
            .values()
            .map(|z| z.signed.as_ref().unwrap().fresh_signatures)
            .sum();

        let mut cases = Vec::new();
        let mut measure = |what: &'static str, made_before: u64, took: std::time::Duration| {
            let made = signer.signatures_made() - made_before;
            let z = big();
            let sz = z.signed.as_ref().unwrap();
            assert_eq!(sz.fresh_signatures as u64, made);
            assert_eq!(sz.fresh_signatures + sz.reused_signatures, sz.signed_rrsets);
            assert!(
                Arc::ptr_eq(&m.cache.load().zones["bystander.test."], &bystander),
                "{what}: the other zone was rebuilt"
            );
            cases.push((what, made, took));
            made
        };
        // A new name: its RRset, its NSEC, the previous NSEC, the SOA.
        let (b, t) = (signer.signatures_made(), std::time::Instant::now());
        let (r, _) = m
            .create_record(actor(), "big.test", rec("new", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        assert_eq!(measure("add a name", b, t.elapsed()), 4);
        // A changed record: its RRset and the SOA.
        let (b, t) = (signer.signatures_made(), std::time::Instant::now());
        m.update_record(
            actor(),
            "big.test",
            r.id,
            RecordInput {
                value: Some("192.0.2.2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(measure("change a record", b, t.elapsed()), 2);
        // A removed name: the previous NSEC and the SOA.
        let (b, t) = (signer.signatures_made(), std::time::Instant::now());
        m.delete_record(actor(), "big.test", r.id).await.unwrap();
        assert_eq!(measure("remove a name", b, t.elapsed()), 2);
        assert_catalog_is_current(&s, &m, "large zone");
        assert_eq!(big().signed.as_ref().unwrap().verify_all(&big()), all);
        eprintln!(
            "D2/D3 measure (2 signed zones x 5,000 records; enabling signing on both took {enable:?}): \
             before: a full build reads 10,000 record rows and computes {full_sigs} signatures in {full_took:?}; \
             after: a change reads the 5,000 rows of its zone and computes: {}",
            cases
                .iter()
                .map(|(w, n, d)| format!("{w}: {n} signatures, {d:?} (whole operation)"))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    /// The window formula of the version before `signed_at` (frozen copy
    /// of `dnssec::window` at 3884ba8), for the upgrade test.
    fn legacy_window(updated_at: &str, now: i64, cfg: &crate::config::DnssecConfig) -> (i64, i64) {
        let validity = cfg.signature_validity_days as i64 * 86400;
        let resign_before = cfg.resign_before_days as i64 * 86400;
        if let Ok(changed) = chrono::DateTime::parse_from_rfc3339(updated_at) {
            let inception = changed.timestamp() - 3600;
            let expiration = inception + validity;
            if expiration - now > resign_before / 2 && inception <= now - 300 {
                return (inception, expiration);
            }
        }
        let inception = now - now.rem_euclid(3600) - 3600;
        (inception, inception + validity)
    }

    /// D1: an upgrade must not move the signature window of a zone that is
    /// already signed, and afterwards ordinary changes must not move it
    /// either; only a re-sign does.
    #[tokio::test]
    async fn the_signature_window_survives_the_upgrade_and_ordinary_changes() {
        let (s, m, _) = setup();
        let cfg = m.signer().config();
        m.create_zone(actor(), zone_input("up.test"), None)
            .await
            .unwrap();
        m.create_record(actor(), "up.test", rec("www", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        m.set_dnssec(actor(), "up.test", true, false).await.unwrap();
        // A zone signed by the previous version: no signing epoch, last
        // changed two days ago (the window served before the upgrade).
        let two_days_ago = (chrono::Utc::now() - chrono::Duration::days(2))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        s.exec_raw(&format!(
            "UPDATE zones SET signed_at = NULL, updated_at = '{two_days_ago}' WHERE name = 'up.test'"
        ))
        .unwrap();
        let z0 = s.get_zone("up.test").unwrap().unwrap();
        assert!(z0.dnssec && z0.signed_at.is_none());
        // Old formula and new formula on the same row, at several times:
        // inside the window, near the re-sign time, and past the fallback.
        let now = chrono::Utc::now().timestamp();
        for dt in [
            0,
            3600,
            3 * 86400,
            5 * 86400,
            86400 * 9,
            86400 * 12,
            86400 * 20,
        ] {
            let old = legacy_window(&z0.updated_at, now + dt, &cfg);
            let new = crate::dnssec::window(z0.signing_epoch(), now + dt, &cfg);
            assert_eq!((new.inception, new.expiration), old, "at now + {dt}s");
            assert_eq!(
                crate::dnssec::resign_due_at(z0.signing_epoch(), &cfg),
                Some(old_due(&z0.updated_at, &cfg))
            );
        }
        // The upgraded server signs with exactly that window.
        m.rebuild().unwrap();
        let before = m.cache.load().zones["up.test."].signed.clone().unwrap();
        let old = legacy_window(&z0.updated_at, now, &cfg);
        assert_eq!((before.inception as i64, before.expiration as i64), old);

        // First change after the upgrade: the epoch is pinned to the old
        // change time (a typed, replicated fact) and the window stays.
        m.create_record(actor(), "up.test", rec("new", RecordType::A, "192.0.2.2"))
            .await
            .unwrap();
        let z1 = s.get_zone("up.test").unwrap().unwrap();
        assert_ne!(z1.updated_at, z0.updated_at);
        assert_eq!(z1.signed_at.as_deref(), Some(z0.updated_at.as_str()));
        let l = log(&s);
        let bump = l.last().unwrap();
        assert_eq!(bump.payload["kind"], "serial_bumped");
        assert_eq!(bump.payload["signed_at"], z0.updated_at.as_str());
        let after = m.cache.load().zones["up.test."].signed.clone().unwrap();
        assert_eq!(
            (after.inception, after.expiration),
            (before.inception, before.expiration),
            "an ordinary change does not move the window"
        );
        assert!(after.nsec_at("new.up.test.").is_some());
        // Nor do later changes (zone settings, record update, delete).
        m.update_zone(
            actor(),
            "up.test",
            ZoneInput {
                refresh: Some(7200),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        let z2 = s.get_zone("up.test").unwrap().unwrap();
        assert_eq!(z2.signed_at, z1.signed_at);
        let again = m.cache.load().zones["up.test."].signed.clone().unwrap();
        assert_eq!(again.inception, before.inception);

        // An unsigned zone never gets an epoch.
        m.create_zone(actor(), zone_input("plain.test"), None)
            .await
            .unwrap();
        m.create_record(actor(), "plain.test", rec("a", RecordType::A, "192.0.2.3"))
            .await
            .unwrap();
        assert!(s
            .get_zone("plain.test")
            .unwrap()
            .unwrap()
            .signed_at
            .is_none());
        assert!(log(&s).last().unwrap().payload.get("signed_at").is_none());

        // The re-sign (due 7 days after the epoch) moves it, with the serial.
        let due = chrono::Utc::now() + chrono::Duration::days(5) + chrono::Duration::hours(2);
        assert_eq!(
            m.resign_due(due).await.unwrap(),
            vec!["up.test".to_string()]
        );
        let z3 = s.get_zone("up.test").unwrap().unwrap();
        assert_eq!(z3.serial, z2.serial + 1);
        assert_eq!(z3.signed_at.as_deref(), Some(z3.updated_at.as_str()));
        let l = log(&s);
        assert_eq!(l[l.len() - 2].payload["kind"], "zone_resigned");
        assert_eq!(l[l.len() - 1].payload["signed_at"], z3.updated_at.as_str());
        let resigned = m.cache.load().zones["up.test."].signed.clone().unwrap();
        assert!(resigned.inception > before.inception && resigned.expiration > before.expiration);

        // Off clears the epoch; on starts a new one at that moment.
        m.set_dnssec(actor(), "up.test", false, false)
            .await
            .unwrap();
        assert!(s.get_zone("up.test").unwrap().unwrap().signed_at.is_none());
        m.set_dnssec(actor(), "up.test", true, false).await.unwrap();
        let z4 = s.get_zone("up.test").unwrap().unwrap();
        assert!(z4.signed_at.as_deref() > z3.signed_at.as_deref());

        // A standby replaying this history has the same epochs.
        let target = Storage::open_memory().unwrap();
        let events = s
            .read_tx(|c| crate::replication::data::changelog_tail(c, 0))
            .unwrap();
        // (The raw UPDATE above is not in the changelog: replay it too.)
        let cut = events
            .iter()
            .position(|e| {
                e.payload["kind"] == "record_created" && e.payload["record"]["name"] == "new"
            })
            .unwrap();
        replay::replay(&target, &events[..cut]).unwrap();
        target
            .exec_raw(&format!(
                "UPDATE zones SET signed_at = NULL, updated_at = '{two_days_ago}' WHERE name = 'up.test'"
            ))
            .unwrap();
        target
            .exec_raw(&format!(
                "UPDATE sqlite_sequence SET seq = {} WHERE name = 'changelog'",
                events[cut - 1].offset
            ))
            .ok();
        replay::replay(&target, &events[cut..]).unwrap();
        assert_eq!(
            target.get_zone("up.test").unwrap().unwrap().signed_at,
            z4.signed_at
        );
        assert_eq!(dump(&target)["zones"], dump(&s)["zones"]);
    }

    fn old_due(updated_at: &str, cfg: &crate::config::DnssecConfig) -> i64 {
        chrono::DateTime::parse_from_rfc3339(updated_at)
            .unwrap()
            .timestamp()
            - 3600
            + cfg.signature_validity_days as i64 * 86400
            - cfg.resign_before_days as i64 * 86400
    }
}
