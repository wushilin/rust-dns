//! Zone, record and member operations ([`Mutator`] methods, each one
//! transaction) and the validation helpers they share.

use super::*;

pub(super) fn normalize_rname(s: &str) -> Result<String, Invalid> {
    // Accept "hostmaster@example.com" as a convenience.
    let s = s.trim();
    let s = match s.split_once('@') {
        Some((local, domain)) => format!("{}.{}", local.replace('.', "\\."), domain),
        None => s.to_string(),
    };
    let n = normalize_domain(&s.replace("\\.", "\u{1}"), true)
        .map_err(|e| Invalid(format!("SOA RNAME: {}", e.0)))?;
    Ok(format!("{}.", n.replace('\u{1}', "\\.")))
}

pub(super) fn apply_zone_input(z: &mut Zone, input: &ZoneInput) -> Result<(), Invalid> {
    if let Some(m) = &input.soa_mname {
        z.soa_mname = format!(
            "{}.",
            normalize_domain(m, true).map_err(|e| Invalid(format!("SOA MNAME: {}", e.0)))?
        );
    }
    if let Some(r) = &input.soa_rname {
        z.soa_rname = normalize_rname(r)?;
    }
    if let Some(v) = input.refresh {
        z.refresh = v;
    }
    if let Some(v) = input.retry {
        z.retry = v;
    }
    if let Some(v) = input.expire {
        z.expire = v;
    }
    if let Some(v) = input.minimum {
        z.minimum = v;
    }
    if let Some(v) = input.default_ttl {
        if v == 0 {
            return Err(Invalid("default_ttl must be at least 1".into()));
        }
        z.default_ttl = v;
    }
    if let Some(p) = &input.record_policy {
        let p = p.clone().filter(|p| !p.is_empty());
        if let Some(p) = &p {
            p.validate()?;
        }
        z.record_policy = p.map(Box::new);
    }
    Ok(())
}

/// Apply the override part of a zone input (I1). Creating: an `override`
/// object makes an override zone. Updating: only an override zone takes
/// one (the type is chosen at creation).
pub(super) fn apply_override(
    z: &mut Zone,
    input: &ZoneInput,
    creating: bool,
) -> Result<(), Invalid> {
    let Some(o) = &input.overrides else {
        return Ok(());
    };
    if !creating && z.overrides.is_none() {
        return Err(Invalid(
            "an authoritative zone cannot become an override zone; the type is chosen when the zone is created".into(),
        ));
    }
    let mut spec = z.overrides.as_deref().cloned().unwrap_or_default();
    if let Some(m) = o.mode {
        spec.mode = m;
    }
    if let Some(ups) = &o.upstreams {
        let mut out: Vec<std::net::SocketAddr> = Vec::new();
        for u in ups.iter().map(|u| u.trim()).filter(|u| !u.is_empty()) {
            let sa = crate::mutation::settings::parse_upstream(u)
                .map_err(|e| Invalid(format!("override upstream: {e}")))?;
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
        if out.len() > crate::mutation::settings::MAX_UPSTREAMS {
            return Err(Invalid(format!(
                "at most {} override upstreams",
                crate::mutation::settings::MAX_UPSTREAMS
            )));
        }
        spec.upstreams = out;
    }
    if z.dnssec {
        return Err(Invalid("an override zone is never DNSSEC-signed".into()));
    }
    z.overrides = Some(Box::new(spec));
    Ok(())
}

pub(super) fn soa_differs(a: &Zone, b: &Zone) -> bool {
    (
        &a.soa_mname,
        &a.soa_rname,
        a.refresh,
        a.retry,
        a.expire,
        a.minimum,
        a.default_ttl,
        a.owner_id,
    ) != (
        &b.soa_mname,
        &b.soa_rname,
        b.refresh,
        b.retry,
        b.expire,
        b.minimum,
        b.default_ttl,
        b.owner_id,
    )
}

pub(super) fn new_zone(
    defaults: &(Option<String>, Option<String>),
    name: &str,
    owner_id: Option<i64>,
) -> Zone {
    let mut z = default_zone(name, owner_id);
    if let Some(m) = &defaults.0 {
        z.soa_mname = m.clone();
    }
    if let Some(r) = &defaults.1 {
        z.soa_rname = r.clone();
    }
    z
}

pub(super) fn default_zone(name: &str, owner_id: Option<i64>) -> Zone {
    let now = now_rfc3339();
    let base = if name == "." {
        String::new()
    } else {
        format!(".{name}")
    };
    Zone {
        id: 0,
        name: name.to_string(),
        serial: 1,
        soa_mname: format!("ns1{base}."),
        soa_rname: format!("hostmaster{base}."),
        refresh: 3600,
        retry: 600,
        expire: 1_209_600,
        minimum: 300,
        default_ttl: 300,
        created_at: now.clone(),
        updated_at: now,
        owner_id,
        dnssec: false,
        signed_at: None,
        overrides: None,
        record_policy: None,
        settings: None,
    }
}

/// Validate a record against the other records in the zone.
pub(super) fn check_record_rules(
    existing: &[Record],
    exclude_id: Option<i64>,
    name: &str,
    rtype: RecordType,
) -> MResult<()> {
    if rtype == RecordType::CNAME && name == "@" {
        return Err(MutationError::Invalid(
            "a CNAME is not allowed at the zone apex".into(),
        ));
    }
    let same_name: Vec<&Record> = existing
        .iter()
        .filter(|r| r.name == name && Some(r.id) != exclude_id)
        .collect();
    if rtype == RecordType::CNAME && !same_name.is_empty() {
        return Err(MutationError::Conflict(format!(
            "'{name}' already has other records; a CNAME must stand alone"
        )));
    }
    if rtype != RecordType::CNAME && same_name.iter().any(|r| r.rtype == RecordType::CNAME) {
        return Err(MutationError::Conflict(format!(
            "'{name}' is a CNAME; no other records may share the name"
        )));
    }
    Ok(())
}

impl Mutator {
    // ---- zones ---------------------------------------------------------

    pub async fn create_zone(
        &self,
        actor: Actor,
        input: ZoneInput,
        owner_id: Option<i64>,
    ) -> MResult<Zone> {
        let defaults = self.defaults();
        self.execute(actor, "create_zone", move |t| {
            let name = normalize_zone_name(input.name.as_deref().unwrap_or(""))?;
            let mut z = new_zone(&defaults, &name, owner_id);
            apply_zone_input(&mut z, &input)?;
            apply_override(&mut z, &input, true)?;
            t.create_zone(z)
        })
        .await
    }

    pub async fn update_zone(
        &self,
        actor: Actor,
        name: &str,
        input: ZoneInput,
        new_owner: Option<Option<i64>>,
    ) -> MResult<Zone> {
        let name = name.to_string();
        let zone_name = self
            .execute(actor, "update_zone", move |t| {
                let name = normalize_zone_name(&name)?;
                let before = t.require_zone(&name)?;
                let mut after = before.clone();
                apply_zone_input(&mut after, &input)?;
                apply_override(&mut after, &input, false)?;
                if let Some(o) = new_owner {
                    after.owner_id = o;
                }
                t.update_zone(before, after)?;
                Ok(name)
            })
            .await?;
        // Return the committed state, including the serial bumped at commit.
        self.storage
            .get_zone(&zone_name)?
            .ok_or_else(|| MutationError::NotFound(format!("zone '{zone_name}' not found")))
    }

    /// O16: set (or clear, with `None` / an empty object) a zone's own
    /// server settings. Override zones have none (they are never
    /// transferred or announced, and serve no automatic PTR).
    pub async fn set_zone_settings(
        &self,
        actor: Actor,
        name: &str,
        settings: Option<crate::model::ZoneSettings>,
    ) -> MResult<Zone> {
        let name = normalize_zone_name(name)?;
        let settings = match settings.filter(|s| !s.is_empty()) {
            Some(s) => Some(s.normalized()?),
            None => None,
        };
        self.execute(actor, "set_zone_settings", move |t| {
            let z = t.require_zone(&name)?;
            if z.is_override() && settings.is_some() {
                return Err(MutationError::Invalid(
                    "an override zone has no transfer, NOTIFY or automatic PTR settings".into(),
                ));
            }
            t.set_zone_settings(&z, settings)
        })
        .await
    }

    /// O11: rename `name` to `new_name` (one transaction). A key rollover
    /// in progress refuses it; whether a DS may be published is checked by
    /// the caller (it needs the network).
    pub async fn rename_zone(&self, actor: Actor, name: &str, new_name: &str) -> MResult<Zone> {
        let (name, new_name) = (normalize_zone_name(name)?, normalize_zone_name(new_name)?);
        if name == new_name {
            return Err(MutationError::Invalid(
                "the new name is the current one".into(),
            ));
        }
        self.execute(actor, "rename_zone", move |t| {
            let z = t.require_zone(&name)?;
            if t.dnssec_key(z.id)?.is_some_and(|k| k.rollover.is_some()) {
                return Err(MutationError::Conflict(
                    "a DNSSEC key rollover is in progress: finish or cancel it first".into(),
                ));
            }
            t.rename_zone(z, &new_name)
        })
        .await
    }

    /// O11: a new zone `new_name` with the settings of `name` (SOA timers
    /// and contacts, default TTL, record policy, override settings; not
    /// signing, not members) and, with `records`, a copy of its records
    /// (not expired ones; expiry times kept). One transaction.
    pub async fn clone_zone(
        &self,
        actor: Actor,
        name: &str,
        new_name: &str,
        owner_id: Option<i64>,
        records: bool,
    ) -> MResult<(Zone, usize)> {
        let (name, new_name) = (normalize_zone_name(name)?, normalize_zone_name(new_name)?);
        self.execute(actor, "clone_zone", move |t| {
            let src = t.require_zone(&name)?;
            let mut z = default_zone(&new_name, owner_id);
            for (from, to) in [
                (&src.soa_mname, &mut z.soa_mname),
                (&src.soa_rname, &mut z.soa_rname),
            ] {
                // Contacts inside the source zone move to the clone.
                *to = match from.strip_suffix(&format!("{}.", src.name)) {
                    Some(head) if head.ends_with('.') => format!("{head}{new_name}."),
                    _ => from.clone(),
                };
            }
            (z.refresh, z.retry, z.expire, z.minimum, z.default_ttl) = (
                src.refresh,
                src.retry,
                src.expire,
                src.minimum,
                src.default_ttl,
            );
            z.record_policy = src.record_policy.clone();
            z.overrides = src.overrides.clone();
            let z = t.create_zone(z)?;
            let mut n = 0;
            if records {
                let now = now_rfc3339();
                for r in t.records(src.id)? {
                    if r.is_expired_at(&now) {
                        continue;
                    }
                    t.create_record(&z, &r.name, r.rtype, &r.value, r.ttl, r.expires_at.clone())?;
                    n += 1;
                }
            }
            Ok((z, n))
        })
        .await
    }

    pub async fn delete_zone(&self, actor: Actor, name: &str) -> MResult<Zone> {
        let name = name.to_string();
        self.execute(actor, "delete_zone", move |t| {
            let z = t.require_zone(&normalize_zone_name(&name)?)?;
            t.delete_zone(&z)?;
            Ok(z)
        })
        .await
    }

    // ---- records -------------------------------------------------------

    pub async fn create_record(
        &self,
        actor: Actor,
        zone_name: &str,
        input: RecordInput,
    ) -> MResult<(Record, bool)> {
        let zone_name = zone_name.to_string();
        self.execute(actor, "create_record", move |t| {
            let expires = resolve_expiry(&input, chrono::Utc::now())?;
            let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
            let rtype = input
                .rtype
                .ok_or_else(|| MutationError::Invalid("type is required".into()))?;
            let name = normalize_record_name(input.name.as_deref().unwrap_or("@"), &z.name)?;
            let value = normalize_value(rtype, input.value.as_deref().unwrap_or(""))?;
            t.create_or_renew_record(&z, &name, rtype, &value, input.ttl.flatten(), expires)
        })
        .await
    }

    pub async fn update_record(
        &self,
        actor: Actor,
        zone_name: &str,
        id: i64,
        input: RecordInput,
    ) -> MResult<Record> {
        let zone_name = zone_name.to_string();
        self.execute(actor, "update_record", move |t| {
            let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
            let old = t.record_in(&z, id)?;
            let expires_at = match resolve_expiry(&input, chrono::Utc::now())? {
                None => old.expires_at.clone(),
                Some(e) => e,
            };
            let rtype = input.rtype.unwrap_or(old.rtype);
            let name = match &input.name {
                Some(n) => normalize_record_name(n, &z.name)?,
                None => old.name.clone(),
            };
            let value = match &input.value {
                Some(v) => normalize_value(rtype, v)?,
                None if rtype != old.rtype => normalize_value(rtype, &old.value)?,
                None => old.value.clone(),
            };
            t.update_record(
                &z,
                &old,
                &name,
                rtype,
                &value,
                input.ttl.unwrap_or(old.ttl),
                expires_at,
            )
        })
        .await
    }

    pub async fn delete_record(&self, actor: Actor, zone_name: &str, id: i64) -> MResult<Record> {
        let zone_name = zone_name.to_string();
        self.execute(actor, "delete_record", move |t| {
            let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
            let rec = t.record_in(&z, id)?;
            t.delete_record(&z, &rec)?;
            Ok(rec)
        })
        .await
    }

    // ---- members (RBAC bindings) ----------------------------------------

    pub async fn set_member(
        &self,
        actor: Actor,
        zone_name: &str,
        user_id: i64,
        role: ZoneRole,
    ) -> MResult<()> {
        let zone_name = zone_name.to_string();
        self.execute(actor, "set_member", move |t| {
            let role = match role {
                ZoneRole::Editor => "editor",
                ZoneRole::Viewer => "viewer",
                ZoneRole::Owner => {
                    return Err(MutationError::Invalid(
                        "use the zone owner field to transfer ownership".into(),
                    ))
                }
            };
            let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
            let u = t
                .user(user_id)?
                .ok_or_else(|| MutationError::NotFound(format!("user {user_id} not found")))?;
            t.set_member(&z, &u, role)
        })
        .await
    }

    pub async fn remove_member(&self, actor: Actor, zone_name: &str, user_id: i64) -> MResult<()> {
        let zone_name = zone_name.to_string();
        self.execute(actor, "remove_member", move |t| {
            let z = t.require_zone(&normalize_zone_name(&zone_name)?)?;
            t.remove_member(&z, user_id)
        })
        .await
    }

    /// Before a user account is deleted: every zone it owns loses its
    /// owner and every membership it has is removed, as DNS changes of
    /// their own. Without this the foreign keys (`ON DELETE SET NULL` /
    /// `CASCADE`) would do the same silently: no change in the
    /// changelog API, and the catalog's copy of the zone row would keep
    /// the old owner until the zone next changed. A standby replays these
    /// changes before `user_deleted`, so its rows follow even when it
    /// keeps the account (its local root of the same name). Returns the
    /// number of zones and memberships released.
    pub async fn release_user(&self, actor: Actor, user_id: i64) -> MResult<(usize, usize)> {
        self.execute(actor, "delete_user", move |t| {
            let mut owned = 0;
            let mut memberships = 0;
            for z in t.zones()? {
                if z.owner_id == Some(user_id) {
                    t.clear_owner(&z)?;
                    owned += 1;
                }
                if t.members(z.id)?.iter().any(|m| m.user_id == user_id) {
                    t.remove_member(&z, user_id)?;
                    memberships += 1;
                }
            }
            Ok((owned, memberships))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;

    #[tokio::test]
    async fn identical_record_with_expiry_renews() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("r.test"), None)
            .await
            .unwrap();
        let (a, _) = m
            .create_record(actor(), "r.test", expiring("host", "192.0.2.7", 60))
            .await
            .unwrap();
        let (b, renewed) = m
            .create_record(actor(), "r.test", expiring("host", "192.0.2.7", 7200))
            .await
            .unwrap();
        assert!(renewed);
        assert_eq!(a.id, b.id, "same record, renewed in place");
        assert!(b.expires_at > a.expires_at);
        // Without an expiry, an identical live record is still a conflict.
        assert!(matches!(
            m.create_record(actor(), "r.test", rec("host", RecordType::A, "192.0.2.7"))
                .await,
            Err(MutationError::Conflict(_))
        ));
        // Clearing the expiry with an update makes the record permanent.
        let c = m
            .update_record(
                actor(),
                "r.test",
                a.id,
                RecordInput {
                    expires_at: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(c.expires_at.is_none());
        assert_eq!(s.all_records().unwrap().len(), 1);
        // Bad expiry input is rejected inside the transaction.
        let past = RecordInput {
            expires_at: Some(Some("2001-01-01T00:00:00Z".into())),
            ..rec("old", RecordType::A, "192.0.2.8")
        };
        assert!(m.create_record(actor(), "r.test", past).await.is_err());
        let zero = RecordInput {
            expires_in: Some(0),
            ..rec("zero", RecordType::A, "192.0.2.8")
        };
        assert!(m.create_record(actor(), "r.test", zero).await.is_err());
    }

    #[tokio::test]
    async fn expired_records_do_not_block_new_ones() {
        let (_, m, _) = setup();
        m.create_zone(actor(), zone_input("b.test"), None)
            .await
            .unwrap();
        m.create_record(actor(), "b.test", expiring("svc", "192.0.2.1", 1))
            .await
            .unwrap();
        // While the A record is live, a CNAME at the same name conflicts.
        assert!(m
            .create_record(
                actor(),
                "b.test",
                rec("svc", RecordType::CNAME, "other.example.com")
            )
            .await
            .is_err());
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        // Once it has expired, the name is free again.
        assert!(m
            .create_record(
                actor(),
                "b.test",
                rec("svc", RecordType::CNAME, "other.example.com")
            )
            .await
            .is_ok());
    }

    /// M2: a zone's record expiry policy, enforced inside the transaction
    /// on every create/update/import path; the apex is exempt; a too-long
    /// expiry is refused, never shortened.
    #[tokio::test]
    async fn the_zone_record_policy_gives_defaults_and_refuses_long_expiries() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("dyn.test"), None)
            .await
            .unwrap();
        // A permanent record from before the policy.
        let (old, _) = m
            .create_record(actor(), "dyn.test", rec("old", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        let bad = |p: RecordPolicy| ZoneInput {
            record_policy: Some(Some(p)),
            ..Default::default()
        };
        for p in [
            RecordPolicy {
                default_expiry_secs: Some(7200),
                max_expiry_secs: Some(3600),
            },
            RecordPolicy {
                default_expiry_secs: Some(0),
                max_expiry_secs: None,
            },
        ] {
            assert!(matches!(
                m.update_zone(actor(), "dyn.test", bad(p), None).await,
                Err(MutationError::Invalid(_))
            ));
        }
        let z = m
            .update_zone(
                actor(),
                "dyn.test",
                bad(RecordPolicy {
                    default_expiry_secs: Some(3600),
                    max_expiry_secs: Some(86_400),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            z.record_policy.as_ref().unwrap().max_expiry_secs,
            Some(86_400)
        );
        let hour = |r: &Record| {
            let at = chrono::DateTime::parse_from_rfc3339(r.expires_at.as_deref().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc);
            (at - chrono::Utc::now()).num_seconds()
        };
        // No expiry: the default.
        let (a, _) = m
            .create_record(actor(), "dyn.test", rec("a", RecordType::A, "192.0.2.2"))
            .await
            .unwrap();
        assert!((3590..=3600).contains(&hour(&a)), "{:?}", a.expires_at);
        // Explicit "never" too.
        let never = RecordInput {
            expires_at: Some(None),
            ..rec("b", RecordType::A, "192.0.2.3")
        };
        let (b, _) = m.create_record(actor(), "dyn.test", never).await.unwrap();
        assert!(b.expires_at.is_some());
        // Within the maximum: kept as asked.
        let (c, _) = m
            .create_record(actor(), "dyn.test", expiring("c", "192.0.2.4", 600))
            .await
            .unwrap();
        assert!((590..=600).contains(&hour(&c)));
        // Longer: refused (create, renew, update).
        for input in [
            expiring("d", "192.0.2.5", 2 * 86_400),
            expiring("c", "192.0.2.4", 2 * 86_400),
        ] {
            assert!(matches!(
                m.create_record(actor(), "dyn.test", input).await,
                Err(MutationError::Invalid(_))
            ));
        }
        let longer = RecordInput {
            expires_in: Some(2 * 86_400),
            ..Default::default()
        };
        assert!(matches!(
            m.update_record(actor(), "dyn.test", c.id, longer).await,
            Err(MutationError::Invalid(_))
        ));
        // The apex is exempt (NS and friends stay permanent).
        let (ns, _) = m
            .create_record(
                actor(),
                "dyn.test",
                rec("@", RecordType::NS, "ns1.dyn.test."),
            )
            .await
            .unwrap();
        assert!(ns.expires_at.is_none());
        // An update that leaves the expiry alone keeps the old record
        // permanent; moving it off the apex applies the policy.
        let v = RecordInput {
            value: Some("192.0.2.9".into()),
            ..Default::default()
        };
        let o = m
            .update_record(actor(), "dyn.test", old.id, v)
            .await
            .unwrap();
        assert!(o.expires_at.is_none());
        // Import: records without an expiry get the default; a zone the
        // import creates takes the document's policy first.
        let mut doc = m.export_all(Some(&["dyn.test".to_string()])).unwrap();
        doc.zones[0].name = "dyn2.test".into();
        doc.zones[0].records = vec![ExportRecord {
            name: "imp".into(),
            rtype: RecordType::A,
            value: "192.0.2.10".into(),
            ttl: None,
            expires_at: None,
        }];
        m.import(actor(), doc, ImportMode::Merge, None, None)
            .await
            .unwrap();
        let z2 = s.get_zone("dyn2.test").unwrap().unwrap();
        assert_eq!(z2.record_policy, z.record_policy);
        let imp = s
            .all_records()
            .unwrap()
            .into_iter()
            .find(|r| r.name == "imp")
            .unwrap();
        assert!(imp.expires_at.is_some(), "imported with the default");
        // Max only: the maximum is the default.
        m.update_zone(
            actor(),
            "dyn.test",
            bad(RecordPolicy {
                default_expiry_secs: None,
                max_expiry_secs: Some(600),
            }),
            None,
        )
        .await
        .unwrap();
        let (e, _) = m
            .create_record(actor(), "dyn.test", rec("e", RecordType::A, "192.0.2.6"))
            .await
            .unwrap();
        assert!((590..=600).contains(&hour(&e)));
        // Removed: records may be permanent again.
        let z = m
            .update_zone(
                actor(),
                "dyn.test",
                ZoneInput {
                    record_policy: Some(None),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        assert!(z.record_policy.is_none());
        let (f, _) = m
            .create_record(actor(), "dyn.test", rec("f", RecordType::A, "192.0.2.7"))
            .await
            .unwrap();
        assert!(f.expires_at.is_none());
    }
}
