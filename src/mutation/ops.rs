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
}
