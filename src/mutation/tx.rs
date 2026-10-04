//! The transaction handle every DNS operation gets ([`Tx`]), the typed
//! [`Change`] it records, and the commit step (`Tx::finish`: serial bumps
//! and changelog rows in the same SQLite transaction).

use super::ops::check_record_rules;
use super::*;

/// A committed fact. Serialized as the changelog payload.
///
/// One envelope for DNS data and for accounts, settings and TSIG keys, so
/// there is one ordered changelog (one cursor for a standby, and a user
/// always exists before a change that refers to it), one exhaustive
/// replay, and one serialization. The two families are separate types:
/// [`SecretChange`]s carry password hashes, TOTP and TSIG secrets and
/// private keys and never leave through the user-facing changelog API or
/// websocket: only a [`DnsChange`] can make a [`DnsEvent`], the one thing
/// the event bus publishes, and the row's class column is the envelope's
/// variant.
///
/// Wire format: the envelope adds nothing. A change serializes exactly as
/// its inner enum (`{"kind": "zone_created", ...}`, the `kind` tags
/// unchanged), so rows written before the split read the same and are
/// written byte for byte the same (test
/// `stored_changelog_payloads_round_trip_byte_for_byte`).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Change {
    Dns(DnsChange),
    Secret(SecretChange),
}

/// Reads a change by its `kind`: tried as a DNS change, then as a secret
/// one (the kinds are disjoint); the error names what was wrong with the
/// family the kind belongs to.
impl<'de> Deserialize<'de> for Change {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        match DnsChange::deserialize(&v) {
            Ok(c) => Ok(Change::Dns(c)),
            Err(dns_err) => match SecretChange::deserialize(&v) {
                Ok(c) => Ok(Change::Secret(c)),
                Err(secret_err) => Err(D::Error::custom(
                    if dns_err.to_string().starts_with("unknown variant") {
                        secret_err
                    } else {
                        dns_err
                    },
                )),
            },
        }
    }
}

impl From<DnsChange> for Change {
    fn from(c: DnsChange) -> Self {
        Change::Dns(c)
    }
}

impl From<SecretChange> for Change {
    fn from(c: SecretChange) -> Self {
        Change::Secret(c)
    }
}

/// A fact about DNS data (class `dns`): zones, records, serials, members.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsChange {
    ZoneCreated {
        zone: Zone,
    },
    ZoneUpdated {
        before: Zone,
        after: Zone,
    },
    /// Written after the zone's records and members were removed (each with its own change).
    ZoneDeleted {
        zone: Zone,
    },
    RecordCreated {
        zone: String,
        record: Record,
    },
    RecordUpdated {
        zone: String,
        before: Record,
        after: Record,
    },
    /// The record's expiry passed: it is no longer served (still stored until reaped).
    RecordExpired {
        zone: String,
        record: Record,
    },
    /// An expired record was deleted after the retention period.
    RecordReaped {
        zone: String,
        record: Record,
    },
    RecordDeleted {
        zone: String,
        record: Record,
    },
    /// Written once per zone per transaction when its DNS content changed.
    SerialBumped {
        zone: String,
        zone_id: i64,
        serial: u32,
        updated_at: String,
        /// The zone's DNSSEC signing epoch from this serial on (the whole
        /// new value of `zones.signed_at`). Present for every bump of a
        /// signed zone, so a standby that missed it converges at the next
        /// change; absent for unsigned zones and in rows written before it
        /// existed (the epoch is then `updated_at`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_at: Option<String>,
    },
    MemberSet {
        zone: String,
        zone_id: i64,
        user_id: i64,
        username: String,
        role: String,
        previous: Option<String>,
        created_at: String,
    },
    MemberRemoved {
        zone: String,
        zone_id: i64,
        user_id: i64,
        username: String,
        role: String,
    },
    /// The primary re-signed a DNSSEC zone because its signatures were
    /// getting close to expiry; the zone's serial bump follows in the same
    /// transaction (secondaries transfer fresh signatures). Nothing else
    /// changes: replaying it is a no-op.
    ZoneResigned {
        zone: String,
        zone_id: i64,
        key_tag: u16,
    },
}

/// A fact about accounts, settings, TSIG and DNSSEC keys (class
/// `account`): may carry secrets; only standbys receive it.
///
/// Account facts are the resulting state (whole rows where a row changed),
/// not intents, so replaying them reproduces identical rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretChange {
    /// A new user (every column).
    UserCreated {
        user: ReplUser,
    },
    /// A user's row after any change (profile, admin flag, password, MFA
    /// enrollment, disable, root sync).
    UserUpdated {
        user: ReplUser,
    },
    UserDeleted {
        user_id: i64,
        username: String,
    },
    /// A TOTP code of this time step was accepted (replay protection).
    TotpStepAccepted {
        user_id: i64,
        step: i64,
    },
    RecoveryCodesReplaced {
        user_id: i64,
        code_hashes: Hidden<Vec<String>>,
    },
    RecoveryCodeUsed {
        user_id: i64,
        code_hash: Hidden<String>,
        used_at: String,
    },
    /// A new API token (hash, not the secret; `last_used_*` is local).
    TokenCreated {
        token: ReplToken,
    },
    /// A token's tags and, when `scope` is present (M1), its resulting
    /// scope (`{}` = unrestricted). Absent (every change written before
    /// M1, and tag-only edits) = the scope is unchanged.
    TokenTagsSet {
        token_id: i64,
        tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<crate::model::TokenScope>,
    },
    TokenRevoked {
        token_id: i64,
        revoked_at: String,
    },
    /// A TSIG key created or its zones changed (the whole row).
    TsigKeySet {
        key: ReplTsigKey,
    },
    TsigKeyDeleted {
        name: String,
    },
    /// A console setting stored (e.g. the forwarding override).
    SettingSet {
        setting: ReplSetting,
    },
    SettingCleared {
        key: String,
    },
    /// A zone's DNSSEC signing key (the whole row, private key included).
    DnssecKeySet {
        key: crate::replication::types::ReplDnssecKey,
    },
    DnssecKeyDeleted {
        zone_id: i64,
        zone: String,
    },
}

/// Changelog row class: `dns` rows are visible in the changelog API and the
/// websocket; `account` rows only to standbys (replication API).
pub const CLASS_DNS: &str = "dns";
pub const CLASS_ACCOUNT: &str = "account";

impl Change {
    /// (action, entity, zone, entity id) columns of the changelog row.
    pub fn meta(&self) -> (&'static str, &'static str, &str, Option<i64>) {
        match self {
            Change::Dns(c) => c.meta(),
            Change::Secret(c) => c.meta(),
        }
    }

    /// [`CLASS_DNS`] or [`CLASS_ACCOUNT`]: the envelope's variant.
    pub fn class(&self) -> &'static str {
        match self {
            Change::Dns(_) => CLASS_DNS,
            Change::Secret(_) => CLASS_ACCOUNT,
        }
    }

    /// The zone whose catalog entry this change can alter (its row, its
    /// served records, its signing key): after a commit exactly these zones
    /// are rebuilt. `None`: nothing the DNS server answers from changed.
    /// Exhaustive, so a new kind of change must decide.
    pub fn catalog_zone(&self) -> Option<i64> {
        match self {
            Change::Dns(c) => c.catalog_zone(),
            Change::Secret(c) => c.catalog_zone(),
        }
    }

    /// Settings or TSIG keys changed: the DNS server must reload them.
    pub fn affects_dns_runtime(&self) -> bool {
        matches!(
            self,
            Change::Secret(
                SecretChange::TsigKeySet { .. }
                    | SecretChange::TsigKeyDeleted { .. }
                    | SecretChange::SettingSet { .. }
                    | SecretChange::SettingCleared { .. }
            )
        )
    }
}

impl DnsChange {
    fn meta(&self) -> (&'static str, &'static str, &str, Option<i64>) {
        match self {
            DnsChange::ZoneCreated { zone } => ("create", "zone", &zone.name, Some(zone.id)),
            DnsChange::ZoneUpdated { after, .. } => ("update", "zone", &after.name, Some(after.id)),
            DnsChange::ZoneDeleted { zone } => ("delete", "zone", &zone.name, Some(zone.id)),
            DnsChange::RecordCreated { zone, record } => {
                ("create", "record", zone, Some(record.id))
            }
            DnsChange::RecordUpdated { zone, after, .. } => {
                ("update", "record", zone, Some(after.id))
            }
            DnsChange::RecordDeleted { zone, record } => {
                ("delete", "record", zone, Some(record.id))
            }
            DnsChange::RecordExpired { zone, record } => {
                ("expire", "record", zone, Some(record.id))
            }
            DnsChange::RecordReaped { zone, record } => ("reap", "record", zone, Some(record.id)),
            DnsChange::SerialBumped { zone, zone_id, .. } => {
                ("update", "serial", zone, Some(*zone_id))
            }
            DnsChange::MemberSet { zone, user_id, .. } => {
                ("update", "member", zone, Some(*user_id))
            }
            DnsChange::MemberRemoved { zone, user_id, .. } => {
                ("delete", "member", zone, Some(*user_id))
            }
            DnsChange::ZoneResigned { zone, zone_id, .. } => {
                ("resign", "zone", zone, Some(*zone_id))
            }
        }
    }

    fn catalog_zone(&self) -> Option<i64> {
        match self {
            DnsChange::ZoneCreated { zone } | DnsChange::ZoneDeleted { zone } => Some(zone.id),
            DnsChange::ZoneUpdated { after, .. } => Some(after.id),
            DnsChange::RecordCreated { record, .. }
            | DnsChange::RecordDeleted { record, .. }
            | DnsChange::RecordExpired { record, .. }
            | DnsChange::RecordReaped { record, .. } => Some(record.zone_id),
            // An update keeps the record in its zone.
            DnsChange::RecordUpdated { after, .. } => Some(after.zone_id),
            DnsChange::SerialBumped { zone_id, .. } | DnsChange::ZoneResigned { zone_id, .. } => {
                Some(*zone_id)
            }
            DnsChange::MemberSet { .. } | DnsChange::MemberRemoved { .. } => None,
        }
    }
}

impl SecretChange {
    fn meta(&self) -> (&'static str, &'static str, &str, Option<i64>) {
        match self {
            SecretChange::UserCreated { user } => ("create", "user", "", Some(user.id)),
            SecretChange::UserUpdated { user } => ("update", "user", "", Some(user.id)),
            SecretChange::UserDeleted { user_id, .. } => ("delete", "user", "", Some(*user_id)),
            SecretChange::TotpStepAccepted { user_id, .. } => {
                ("update", "totp_step", "", Some(*user_id))
            }
            SecretChange::RecoveryCodesReplaced { user_id, .. } => {
                ("update", "recovery_codes", "", Some(*user_id))
            }
            SecretChange::RecoveryCodeUsed { user_id, .. } => {
                ("update", "recovery_code", "", Some(*user_id))
            }
            SecretChange::TokenCreated { token } => ("create", "token", "", Some(token.id)),
            SecretChange::TokenTagsSet { token_id, .. } => ("update", "token", "", Some(*token_id)),
            SecretChange::TokenRevoked { token_id, .. } => ("revoke", "token", "", Some(*token_id)),
            SecretChange::TsigKeySet { .. } => ("update", "tsig_key", "", None),
            SecretChange::TsigKeyDeleted { .. } => ("delete", "tsig_key", "", None),
            SecretChange::SettingSet { .. } => ("update", "setting", "", None),
            SecretChange::SettingCleared { .. } => ("delete", "setting", "", None),
            // No zone name: account rows never reach zone-scoped views.
            SecretChange::DnssecKeySet { key } => ("update", "dnssec_key", "", Some(key.zone_id)),
            SecretChange::DnssecKeyDeleted { zone_id, .. } => {
                ("delete", "dnssec_key", "", Some(*zone_id))
            }
        }
    }

    /// A zone's signing key is served (DNSKEY, signatures); nothing else
    /// here is.
    fn catalog_zone(&self) -> Option<i64> {
        match self {
            SecretChange::DnssecKeySet { key } => Some(key.zone_id),
            SecretChange::DnssecKeyDeleted { zone_id, .. } => Some(*zone_id),
            SecretChange::UserCreated { .. }
            | SecretChange::UserUpdated { .. }
            | SecretChange::UserDeleted { .. }
            | SecretChange::TotpStepAccepted { .. }
            | SecretChange::RecoveryCodesReplaced { .. }
            | SecretChange::RecoveryCodeUsed { .. }
            | SecretChange::TokenCreated { .. }
            | SecretChange::TokenTagsSet { .. }
            | SecretChange::TokenRevoked { .. }
            | SecretChange::TsigKeySet { .. }
            | SecretChange::TsigKeyDeleted { .. }
            | SecretChange::SettingSet { .. }
            | SecretChange::SettingCleared { .. } => None,
        }
    }
}

/// A committed change event that may be published (event bus, websocket,
/// live feed): it can only be made from a [`DnsChange`], so a secret
/// change has no way onto the bus.
#[derive(Debug, Clone)]
pub struct DnsEvent(ChangeEvent);

impl DnsEvent {
    /// The event of a DNS change (`_change`: the proof of its class).
    pub(super) fn new(ev: ChangeEvent, _change: &DnsChange) -> Self {
        DnsEvent(ev)
    }

    pub fn event(&self) -> &ChangeEvent {
        &self.0
    }

    pub fn into_event(self) -> ChangeEvent {
        self.0
    }
}

/// The only handle an operation gets on the database during a transaction.
pub struct Tx<'a> {
    pub(super) conn: &'a Connection,
    changes: Vec<Change>,
    /// Zones whose DNS content changed: serial is bumped once at commit.
    touched: BTreeMap<i64, String>,
    /// Zones being re-signed: their signing epoch moves to the commit time.
    resigned: std::collections::BTreeSet<i64>,
}

impl<'a> Tx<'a> {
    pub(super) fn new(conn: &'a Connection) -> Self {
        Tx {
            conn,
            changes: Vec::new(),
            touched: BTreeMap::new(),
            resigned: Default::default(),
        }
    }

    // ---- reads ----------------------------------------------------------

    pub fn zone(&self, name: &str) -> MResult<Option<Zone>> {
        Ok(db::get_zone(self.conn, name)?)
    }

    pub fn require_zone(&self, name: &str) -> MResult<Zone> {
        self.zone(name)?
            .ok_or_else(|| MutationError::NotFound(format!("zone '{name}' not found")))
    }

    pub fn records(&self, zone_id: i64) -> MResult<Vec<Record>> {
        Ok(db::list_records(self.conn, zone_id)?)
    }

    /// The zone's records at `name` (relative): all that the record rules
    /// and the duplicate check look at (an index lookup, not a zone scan).
    pub fn records_named(&self, zone_id: i64, name: &str) -> MResult<Vec<Record>> {
        Ok(db::records_named(self.conn, zone_id, name)?)
    }

    pub fn record_in(&self, zone: &Zone, id: i64) -> MResult<Record> {
        db::get_record(self.conn, id)?
            .filter(|r| r.zone_id == zone.id)
            .ok_or_else(|| {
                MutationError::NotFound(format!("record {id} not found in zone '{}'", zone.name))
            })
    }

    pub fn user(&self, id: i64) -> MResult<Option<User>> {
        Ok(db::get_user(self.conn, id)?)
    }

    pub fn members(&self, zone_id: i64) -> MResult<Vec<Member>> {
        Ok(db::list_members(self.conn, zone_id)?)
    }

    pub fn zones(&self) -> MResult<Vec<Zone>> {
        Ok(db::list_zones(self.conn)?)
    }

    // ---- writes: each one records its Change ----------------------------

    pub fn create_zone(&mut self, z: Zone) -> MResult<Zone> {
        if self.zone(&z.name)?.is_some() {
            return Err(MutationError::Conflict(format!(
                "zone '{}' already exists",
                z.name
            )));
        }
        let zone = sql::insert_zone(self.conn, &z)?;
        self.changes
            .push(Change::Dns(DnsChange::ZoneCreated { zone: zone.clone() }));
        Ok(zone)
    }

    pub fn update_zone(&mut self, before: Zone, mut after: Zone) -> MResult<Zone> {
        after.id = before.id;
        after.name = before.name.clone();
        after.serial = before.serial;
        after.updated_at = now_rfc3339();
        if !after.dnssec {
            // No signing, no epoch: turning it on again starts a new one.
            after.signed_at = None;
        }
        let zone = sql::update_zone(self.conn, &after)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::ZoneUpdated {
            before,
            after: zone.clone(),
        }));
        Ok(zone)
    }

    /// O11: rename a zone (its records, members, owner and key stay with
    /// it, by id). Recorded as a `ZoneUpdated` whose rows differ in `name`
    /// (and `updated_at`); a signing key's row follows (`DnssecKeySet`).
    /// The serial is bumped at commit.
    pub fn rename_zone(&mut self, before: Zone, new_name: &str) -> MResult<Zone> {
        if db::get_zone(self.conn, new_name)?.is_some() {
            return Err(MutationError::Conflict(format!(
                "zone '{new_name}' already exists"
            )));
        }
        let mut after = before.clone();
        after.name = new_name.to_string();
        after.updated_at = now_rfc3339();
        let zone = sql::update_zone(self.conn, &after)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::ZoneUpdated {
            before,
            after: zone.clone(),
        }));
        if let Some(mut k) = self.dnssec_key(zone.id)? {
            k.zone = zone.name.clone();
            self.set_dnssec_key(k)?;
        }
        Ok(zone)
    }

    pub fn delete_zone(&mut self, zone: &Zone) -> MResult<()> {
        for r in self.records(zone.id)? {
            self.delete_record(zone, &r)?;
        }
        for m in self.members(zone.id)? {
            self.remove_member(zone, m.user_id)?;
        }
        if self.dnssec_key(zone.id)?.is_some() {
            self.delete_dnssec_key(zone)?;
        }
        sql::delete_zone(self.conn, zone.id)?;
        self.touched.remove(&zone.id);
        self.changes
            .push(Change::Dns(DnsChange::ZoneDeleted { zone: zone.clone() }));
        Ok(())
    }

    /// Why a record may not be added / changed, if anything. `existing`:
    /// the zone's records, or just those at `name` (nothing else is
    /// looked at).
    pub fn record_conflict(
        &self,
        existing: &[Record],
        exclude_id: Option<i64>,
        name: &str,
        rtype: RecordType,
        value: &str,
    ) -> Option<MutationError> {
        // Expired records are not served, so they do not constrain new ones.
        let now = now_rfc3339();
        let live: Vec<Record> = existing
            .iter()
            .filter(|r| r.name == name && !r.is_expired_at(&now))
            .cloned()
            .collect();
        let existing = &live[..];
        if let Err(e) = check_record_rules(existing, exclude_id, name, rtype) {
            return Some(e);
        }
        if existing.iter().any(|r| {
            Some(r.id) != exclude_id && r.name == name && r.rtype == rtype && r.value == value
        }) {
            return Some(MutationError::Conflict(
                "an identical record already exists".into(),
            ));
        }
        None
    }

    /// Create a record, or renew an identical one: if the same name/type/value
    /// already exists and the request carries an expiry (or the existing one
    /// has expired), its expiry is replaced instead of failing as a duplicate.
    /// `expires_at`: `None` = not specified, `Some(None)` = never.
    pub fn create_or_renew_record(
        &mut self,
        zone: &Zone,
        name: &str,
        rtype: RecordType,
        value: &str,
        ttl: Option<u32>,
        expires_at: Option<Option<String>>,
    ) -> MResult<(Record, bool)> {
        let existing = self.records_named(zone.id, name)?;
        if let Some(same) = existing
            .iter()
            .find(|r| r.name == name && r.rtype == rtype && r.value == value)
        {
            let expired = same.is_expired_at(&now_rfc3339());
            if expires_at.is_some() || expired {
                let ttl = ttl.or(same.ttl);
                let renewed = self.update_record(
                    zone,
                    same,
                    name,
                    rtype,
                    value,
                    ttl,
                    expires_at.unwrap_or(None),
                )?;
                return Ok((renewed, true));
            }
            return Err(MutationError::Conflict(
                "an identical record already exists (send expires_in or expires_at to renew it)"
                    .into(),
            ));
        }
        Ok((
            self.create_record(zone, name, rtype, value, ttl, expires_at.flatten())?,
            false,
        ))
    }

    pub fn create_record(
        &mut self,
        zone: &Zone,
        name: &str,
        rtype: RecordType,
        value: &str,
        ttl: Option<u32>,
        expires_at: Option<String>,
    ) -> MResult<Record> {
        if ttl == Some(0) {
            return Err(MutationError::Invalid(
                "ttl must be at least 1 (or empty for the zone default)".into(),
            ));
        }
        // M2: the zone's expiry policy, inside the transaction (every
        // create path: API, renewal, JSON and hosts imports).
        let expires_at = match &zone.record_policy {
            Some(p) => p.apply(name, expires_at, chrono::Utc::now())?,
            None => expires_at,
        };
        let existing = self.records_named(zone.id, name)?;
        if let Some(e) = self.record_conflict(&existing, None, name, rtype, value) {
            return Err(e);
        }
        let now = now_rfc3339();
        let record = sql::insert_record(
            self.conn,
            &Record {
                id: 0,
                zone_id: zone.id,
                name: name.into(),
                rtype,
                value: value.into(),
                ttl,
                created_at: now.clone(),
                updated_at: now,
                expires_at,
            },
        )?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::RecordCreated {
            zone: zone.name.clone(),
            record: record.clone(),
        }));
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_record(
        &mut self,
        zone: &Zone,
        before: &Record,
        name: &str,
        rtype: RecordType,
        value: &str,
        ttl: Option<u32>,
        expires_at: Option<String>,
    ) -> MResult<Record> {
        if ttl == Some(0) {
            return Err(MutationError::Invalid(
                "ttl must be at least 1 (or empty for the zone default)".into(),
            ));
        }
        // M2: an expiry the update sets (or a record moved off the apex)
        // follows the zone's policy; one it leaves alone is not re-checked.
        let expires_at = match &zone.record_policy {
            Some(p) if expires_at != before.expires_at || (before.name == "@" && name != "@") => {
                p.apply(name, expires_at, chrono::Utc::now())?
            }
            _ => expires_at,
        };
        let existing = self.records_named(zone.id, name)?;
        if let Some(e) = self.record_conflict(&existing, Some(before.id), name, rtype, value) {
            return Err(e);
        }
        let after = sql::update_record(
            self.conn,
            &Record {
                name: name.into(),
                rtype,
                value: value.into(),
                ttl,
                expires_at,
                updated_at: now_rfc3339(),
                ..before.clone()
            },
        )?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::RecordUpdated {
            zone: zone.name.clone(),
            before: before.clone(),
            after: after.clone(),
        }));
        Ok(after)
    }

    /// Stop serving a record whose expiry has passed. Bumps the serial (DNS content changed).
    pub fn expire_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::mark_expired(self.conn, record.id)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::RecordExpired {
            zone: zone.name.clone(),
            record: record.clone(),
        }));
        Ok(())
    }

    /// Delete an expired record after the retention period. It was already not
    /// served, so the serial does not change.
    pub fn reap_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::delete_record(self.conn, record.id)?;
        self.changes.push(Change::Dns(DnsChange::RecordReaped {
            zone: zone.name.clone(),
            record: record.clone(),
        }));
        Ok(())
    }

    pub fn zone_by_id(&self, id: i64) -> MResult<Option<Zone>> {
        Ok(db::get_zone_by_id(self.conn, id)?)
    }

    pub fn delete_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::delete_record(self.conn, record.id)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::Dns(DnsChange::RecordDeleted {
            zone: zone.name.clone(),
            record: record.clone(),
        }));
        Ok(())
    }

    pub fn set_member(&mut self, zone: &Zone, user: &User, role: &str) -> MResult<()> {
        let previous = self
            .members(zone.id)?
            .into_iter()
            .find(|m| m.user_id == user.id);
        if previous.as_ref().map(|m| m.role.as_str()) == Some(role) {
            return Ok(()); // no change, nothing to record
        }
        let created_at = previous
            .as_ref()
            .map(|m| m.created_at.clone())
            .unwrap_or_else(now_rfc3339);
        sql::upsert_member(self.conn, zone.id, user.id, role, &created_at)?;
        self.changes.push(Change::Dns(DnsChange::MemberSet {
            zone: zone.name.clone(),
            zone_id: zone.id,
            user_id: user.id,
            username: user.username.clone(),
            role: role.into(),
            previous: previous.map(|m| m.role),
            created_at,
        }));
        Ok(())
    }

    /// O16: replace a zone's own server settings (`None`: the server's).
    /// Recorded as a `ZoneUpdated` whose rows differ only in `settings`:
    /// `updated_at` is kept and the serial is not bumped, because nothing
    /// the zone serves changes (and a signed zone keeps its window).
    pub fn set_zone_settings(
        &mut self,
        zone: &Zone,
        settings: Option<crate::model::ZoneSettings>,
    ) -> MResult<Zone> {
        let after = Zone {
            settings: settings.filter(|s| !s.is_empty()).map(Box::new),
            ..zone.clone()
        };
        let after = sql::update_zone(self.conn, &after)?;
        self.changes.push(Change::Dns(DnsChange::ZoneUpdated {
            before: zone.clone(),
            after: after.clone(),
        }));
        Ok(after)
    }

    /// The zone loses its owner (the owner account is being deleted).
    /// Recorded as a `ZoneUpdated` whose rows differ only in `owner_id`:
    /// `updated_at` is kept and the serial is not bumped, because nothing
    /// the zone serves changes (and a signed zone keeps its window).
    pub fn clear_owner(&mut self, zone: &Zone) -> MResult<Zone> {
        let after = Zone {
            owner_id: None,
            ..zone.clone()
        };
        let after = sql::update_zone(self.conn, &after)?;
        self.changes.push(Change::Dns(DnsChange::ZoneUpdated {
            before: zone.clone(),
            after: after.clone(),
        }));
        Ok(after)
    }

    pub fn remove_member(&mut self, zone: &Zone, user_id: i64) -> MResult<()> {
        let m = self
            .members(zone.id)?
            .into_iter()
            .find(|m| m.user_id == user_id)
            .ok_or_else(|| MutationError::NotFound("membership not found".into()))?;
        sql::delete_member(self.conn, zone.id, user_id)?;
        self.changes.push(Change::Dns(DnsChange::MemberRemoved {
            zone: zone.name.clone(),
            zone_id: zone.id,
            user_id,
            username: m.username,
            role: m.role,
        }));
        Ok(())
    }

    // ---- DNSSEC ---------------------------------------------------------

    /// The zone's signing key (private key included; never returned by the API).
    pub fn dnssec_key(
        &self,
        zone_id: i64,
    ) -> MResult<Option<crate::replication::types::ReplDnssecKey>> {
        Ok(db::get_dnssec_key(self.conn, zone_id)?)
    }

    /// Store a zone's signing key. An account-class change: the private
    /// key reaches standbys but never the changelog API or websocket.
    pub fn set_dnssec_key(&mut self, key: crate::replication::types::ReplDnssecKey) -> MResult<()> {
        let change = SecretChange::DnssecKeySet { key };
        acct_sql::write(self.conn, &acct_sql::Ctx::verbatim(), &change)?
            .log_into(change, &mut self.changes);
        Ok(())
    }

    pub fn delete_dnssec_key(&mut self, zone: &Zone) -> MResult<()> {
        let change = SecretChange::DnssecKeyDeleted {
            zone_id: zone.id,
            zone: zone.name.clone(),
        };
        acct_sql::write(self.conn, &acct_sql::Ctx::verbatim(), &change)?
            .log_into(change, &mut self.changes);
        Ok(())
    }

    /// The zone's published data changed without a record or zone row
    /// change (N1: its DNSKEY RRset): the serial is bumped at commit.
    pub fn touch_zone(&mut self, zone: &Zone) {
        self.touched.insert(zone.id, zone.name.clone());
    }

    /// Re-sign: record why; at commit the serial is bumped and the signing
    /// epoch moves to the commit time (a new signature window).
    pub fn resign_zone(&mut self, zone: &Zone, key_tag: u16) -> MResult<()> {
        self.touched.insert(zone.id, zone.name.clone());
        self.resigned.insert(zone.id);
        self.changes.push(Change::Dns(DnsChange::ZoneResigned {
            zone: zone.name.clone(),
            zone_id: zone.id,
            key_tag,
        }));
        Ok(())
    }

    /// Bump serials of changed zones, then write every change to the
    /// changelog. Returns the events to publish and the zones whose catalog
    /// entries must be rebuilt (derived from the changes themselves).
    pub(super) fn finish(
        mut self,
        actor: &Actor,
        command: &str,
    ) -> MResult<(Vec<DnsEvent>, Vec<i64>)> {
        for (zone_id, name) in std::mem::take(&mut self.touched) {
            let Some(z) = db::get_zone_by_id(self.conn, zone_id)? else {
                continue;
            };
            let serial = z.serial.wrapping_add(1).max(1);
            let updated_at = now_rfc3339();
            // The signing epoch of a signed zone: a re-sign moves it to now;
            // otherwise it stays, so an ordinary change keeps the signature
            // window and only the changed RRsets need new signatures. A
            // zone without one yet is pinned to the change time its window
            // is derived from at this moment: signing just turned on (this
            // transaction set `updated_at`), or a zone signed by an older
            // version (its window does not move at the upgrade).
            let signed_at = if !z.dnssec {
                None
            } else if self.resigned.contains(&zone_id) {
                Some(updated_at.clone())
            } else {
                Some(z.signing_epoch().to_string())
            };
            sql::set_serial(
                self.conn,
                zone_id,
                serial,
                &updated_at,
                signed_at.as_deref(),
            )?;
            self.changes.push(Change::Dns(DnsChange::SerialBumped {
                zone: name,
                zone_id,
                serial,
                updated_at,
                signed_at,
            }));
        }
        let txn = crate::auth::random_token(9);
        let mut events = Vec::with_capacity(self.changes.len());
        for c in &self.changes {
            let ev = sql::append_changelog(self.conn, actor, command, &txn, c)?;
            // Account-class rows (secrets) are for standbys only: never
            // published to the websocket / live feed (no DnsEvent).
            if let Change::Dns(d) = c {
                events.push(DnsEvent::new(ev, d));
            }
        }
        Ok((events, catalog_zones(&self.changes)))
    }
}

/// The zones a list of changes touches, for the incremental catalog build.
pub(crate) fn catalog_zones<'a>(changes: impl IntoIterator<Item = &'a Change>) -> Vec<i64> {
    let ids: std::collections::BTreeSet<i64> = changes
        .into_iter()
        .filter_map(Change::catalog_zone)
        .collect();
    ids.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[tokio::test]
    async fn committed_changes_are_logged_with_serial_bumps() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("a.test"), None)
            .await
            .unwrap();
        let r = m
            .create_record(actor(), "a.test", rec("www", RecordType::A, "192.0.2.1"))
            .await
            .unwrap()
            .0;
        m.update_record(
            actor(),
            "a.test",
            r.id,
            RecordInput {
                value: Some("192.0.2.2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        m.delete_record(actor(), "a.test", r.id).await.unwrap();

        let l = log(&s);
        let kinds: Vec<(String, String)> = l
            .iter()
            .map(|e| (e.action.clone(), e.entity.clone()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("create".into(), "zone".into()),
                ("create".into(), "record".into()),
                ("update".into(), "serial".into()),
                ("update".into(), "record".into()),
                ("update".into(), "serial".into()),
                ("delete".into(), "record".into()),
                ("update".into(), "serial".into()),
            ]
        );
        // Each operation is one transaction: its rows share a txn id and command.
        assert_eq!(l[1].txn, l[2].txn);
        assert_ne!(l[2].txn, l[3].txn);
        assert_eq!(l[1].command, "create_record");
        // Serial moves once per committed transaction that changed DNS content.
        assert_eq!(s.get_zone("a.test").unwrap().unwrap().serial, 4);
        assert_eq!(l.last().unwrap().payload["serial"], 4);
    }

    #[tokio::test]
    async fn rolled_back_operations_write_nothing() {
        let (s, m, _) = setup();
        m.create_zone(actor(), zone_input("a.test"), None)
            .await
            .unwrap();
        let before = log(&s).len();
        let serial = s.get_zone("a.test").unwrap().unwrap().serial;

        // Validation failure inside the transaction.
        assert!(m
            .create_record(actor(), "a.test", rec("x", RecordType::A, "not-an-ip"))
            .await
            .is_err());
        // Failure after earlier writes in the same transaction: the import creates a
        // zone and adds a record, then hits an invalid record and must undo all of it.
        let doc = ExportDoc {
            version: 1,
            exported_at: String::new(),
            zones: vec![
                ExportZone {
                    name: "b.test".into(),
                    serial: None,
                    soa_mname: None,
                    soa_rname: None,
                    refresh: None,
                    retry: None,
                    expire: None,
                    minimum: None,
                    default_ttl: None,
                    owner: None,
                    overrides: None,
                    record_policy: None,
                    records: vec![ExportRecord {
                        name: "ok".into(),
                        rtype: RecordType::A,
                        value: "192.0.2.9".into(),
                        ttl: None,
                        expires_at: None,
                    }],
                },
                ExportZone {
                    name: "a.test".into(),
                    serial: None,
                    soa_mname: None,
                    soa_rname: None,
                    refresh: None,
                    retry: None,
                    expire: None,
                    minimum: None,
                    default_ttl: None,
                    owner: None,
                    overrides: None,
                    record_policy: None,
                    records: vec![ExportRecord {
                        name: "bad".into(),
                        rtype: RecordType::AAAA,
                        value: "nope".into(),
                        ttl: None,
                        expires_at: None,
                    }],
                },
            ],
        };
        assert!(m
            .import(actor(), doc, ImportMode::Replace, None, None)
            .await
            .is_err());
        // Not permitted zone after an allowed one.
        let doc = ExportDoc {
            version: 1,
            exported_at: String::new(),
            zones: vec![
                ExportZone {
                    name: "a.test".into(),
                    serial: None,
                    soa_mname: None,
                    soa_rname: None,
                    refresh: Some(7),
                    retry: None,
                    expire: None,
                    minimum: None,
                    default_ttl: None,
                    owner: None,
                    overrides: None,
                    record_policy: None,
                    records: vec![],
                },
                ExportZone {
                    name: "c.test".into(),
                    serial: None,
                    soa_mname: None,
                    soa_rname: None,
                    refresh: None,
                    retry: None,
                    expire: None,
                    minimum: None,
                    default_ttl: None,
                    owner: None,
                    overrides: None,
                    record_policy: None,
                    records: vec![],
                },
            ],
        };
        assert!(m
            .import(
                actor(),
                doc,
                ImportMode::Merge,
                None,
                Some(vec!["a.test".into()])
            )
            .await
            .is_err());
        // Deleting something that does not exist.
        assert!(m.delete_record(actor(), "a.test", 999).await.is_err());

        assert_eq!(
            log(&s).len(),
            before,
            "no changelog rows for rolled-back transactions"
        );
        assert!(
            s.get_zone("b.test").unwrap().is_none(),
            "zone created mid-transaction was rolled back"
        );
        let a = s.get_zone("a.test").unwrap().unwrap();
        assert_eq!(a.serial, serial, "serial untouched");
        assert_eq!(
            a.refresh, 3600,
            "SOA change from the rejected import was rolled back"
        );
        assert!(s.all_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn zone_delete_logs_every_record_and_member() {
        let (s, m, a) = setup();
        let u = a
            .create_user(
                &actor(),
                &NewUser {
                    username: "u1".into(),
                    password_hash: "h".into(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        m.create_zone(actor(), zone_input("d.test"), None)
            .await
            .unwrap();
        m.create_record(actor(), "d.test", rec("a", RecordType::A, "192.0.2.1"))
            .await
            .unwrap();
        m.create_record(actor(), "d.test", rec("b", RecordType::A, "192.0.2.2"))
            .await
            .unwrap();
        m.set_member(actor(), "d.test", u.id, ZoneRole::Editor)
            .await
            .unwrap();
        let before = log(&s).len();
        m.delete_zone(actor(), "d.test").await.unwrap();
        let tail: Vec<String> = log(&s)[before..]
            .iter()
            .map(|e| format!("{} {}", e.action, e.entity))
            .collect();
        assert_eq!(
            tail,
            vec![
                "delete record",
                "delete record",
                "delete member",
                "delete zone"
            ]
        );
    }

    /// The changelog wire format is a contract with stored rows and with
    /// servers of other versions: payloads written by an earlier version
    /// (the fixture: real rows of every kind) must deserialize and
    /// serialize back to the same bytes.
    #[test]
    fn stored_changelog_payloads_round_trip_byte_for_byte() {
        let text = std::fs::read_to_string(fixture_path()).unwrap();
        let mut kinds = std::collections::BTreeSet::new();
        for (i, line) in text.lines().enumerate() {
            let change: Change = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("fixture line {}: {e}: {line}", i + 1));
            // As `sql::append_changelog` writes it.
            let again = serde_json::to_string(&serde_json::to_value(&change).unwrap()).unwrap();
            assert_eq!(again, line, "fixture line {}", i + 1);
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            kinds.insert(v["kind"].as_str().unwrap().to_string());
            // The class and row columns derive from the payload alone.
            let (_, entity, _, _) = change.meta();
            assert!(!entity.is_empty());
        }
        let expected = [
            "dnssec_key_deleted",
            "dnssec_key_set",
            "member_removed",
            "member_set",
            "record_created",
            "record_deleted",
            "record_expired",
            "record_reaped",
            "record_updated",
            "recovery_code_used",
            "recovery_codes_replaced",
            "serial_bumped",
            "setting_cleared",
            "setting_set",
            "token_created",
            "token_revoked",
            "token_tags_set",
            "totp_step_accepted",
            "tsig_key_deleted",
            "tsig_key_set",
            "user_created",
            "user_deleted",
            "user_updated",
            "zone_created",
            "zone_deleted",
            "zone_resigned",
            "zone_updated",
        ];
        assert_eq!(
            kinds.iter().map(String::as_str).collect::<Vec<_>>(),
            expected,
            "the fixture covers every kind"
        );
    }

    /// E2: every stored kind reads into its family (the class it had as
    /// one enum: the changelog row's `class` column of rows already
    /// stored), and a bad payload's error says what is wrong.
    #[test]
    fn stored_kinds_read_into_their_family() {
        let dns_kinds = [
            "zone_created",
            "zone_updated",
            "zone_deleted",
            "record_created",
            "record_updated",
            "record_expired",
            "record_reaped",
            "record_deleted",
            "serial_bumped",
            "member_set",
            "member_removed",
            "zone_resigned",
        ];
        let text = std::fs::read_to_string(fixture_path()).unwrap();
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let kind = v["kind"].as_str().unwrap();
            let change: Change = serde_json::from_value(v.clone()).unwrap();
            let dns = dns_kinds.contains(&kind);
            assert_eq!(matches!(change, Change::Dns(_)), dns, "{kind}");
            assert_eq!(change.class(), if dns { CLASS_DNS } else { CLASS_ACCOUNT });
        }
        let err = |j: &str| serde_json::from_str::<Change>(j).unwrap_err().to_string();
        assert!(err(r#"{"kind":"no_such_kind"}"#).contains("unknown variant `no_such_kind`"));
        assert!(err(r#"{"kind":"user_deleted","user_id":1}"#).contains("missing field `username`"));
        assert!(err(r#"{"kind":"zone_deleted"}"#).contains("missing field `zone`"));
        assert!(err(r#"{"zone":1}"#).contains("missing field `kind`"));
    }

    #[tokio::test]
    async fn replaying_the_changelog_rebuilds_identical_data() {
        let (s, m, a) = setup();
        a.sync_root("root", "$argon2id$root-1", false).unwrap();
        let mut users = Vec::new();
        for i in 0..3 {
            users.push(
                a.create_user(
                    &actor(),
                    &NewUser {
                        username: format!("user{i}"),
                        password_hash: "h".into(),
                        display_name: String::new(),
                        is_admin: false,
                        mfa_required: false,
                    },
                )
                .unwrap(),
            );
        }
        let mut rng = StdRng::seed_from_u64(20260927);
        // O16 draws from its own generator, so the history above stays the
        // one that covers every kind.
        let mut rng16 = StdRng::seed_from_u64(16);
        let zones = ["r1.test", "r2.test", "r3.test"];
        let types = [
            (RecordType::A, "192.0.2."),
            (RecordType::AAAA, "2001:db8::"),
            (RecordType::TXT, "t"),
            (RecordType::CNAME, "c"),
        ];
        let mut failures = 0;
        let mut extra_users: Vec<i64> = Vec::new();
        for step in 0..600 {
            let z = zones[rng.random_range(0..zones.len())];
            let res: MResult<()> = match rng.random_range(0..140) {
                0..=4 => m
                    .create_zone(actor(), zone_input(z), Some(users[0].id))
                    .await
                    .map(|_| ()),
                5..=6 => m.delete_zone(actor(), z).await.map(|_| ()),
                7..=10 => m
                    .update_zone(
                        actor(),
                        z,
                        ZoneInput {
                            refresh: Some(rng.random_range(60..9000)),
                            // M2: a record expiry policy set, changed or removed.
                            record_policy: match rng.random_range(0..4) {
                                0 => Some(None),
                                1 => Some(Some(crate::model::RecordPolicy {
                                    default_expiry_secs: Some(rng.random_range(60..3600)),
                                    max_expiry_secs: Some(86_400),
                                })),
                                _ => None,
                            },
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .map(|_| ())
                    .and(match rng16.random_range(0..4) {
                        // O16: a zone's own settings set or cleared.
                        0 => Ok(()),
                        n => m
                            .set_zone_settings(
                                actor(),
                                z,
                                (n != 1).then(|| crate::model::ZoneSettings {
                                    auto_ptr: Some(n == 2),
                                    transfer_allow: Some(vec!["192.0.2.0/24".into()]),
                                    require_tsig: (n == 3).then_some(true),
                                    notify: Some(vec![crate::model::ZoneNotifyTarget {
                                        address: "192.0.2.53:53".into(),
                                        key: None,
                                    }]),
                                }),
                            )
                            .await
                            .map(|_| ()),
                    }),
                11..=50 => {
                    let (t, prefix) = types[rng.random_range(0..types.len())];
                    let n = rng.random_range(1..30);
                    let value = match t {
                        RecordType::CNAME => format!("host{n}.example.com"),
                        RecordType::TXT => format!("text {n}"),
                        _ => format!("{prefix}{n}"),
                    };
                    m.create_record(
                        actor(),
                        z,
                        rec(&format!("h{}", rng.random_range(0..8)), t, &value),
                    )
                    .await
                    .map(|_| ())
                }
                51..=70 => match s
                    .get_zone(z)
                    .unwrap()
                    .map(|zz| s.list_records(zz.id).unwrap())
                {
                    Some(rs) if !rs.is_empty() => {
                        let r = &rs[rng.random_range(0..rs.len())];
                        m.update_record(
                            actor(),
                            z,
                            r.id,
                            RecordInput {
                                ttl: Some(Some(rng.random_range(30..600))),
                                ..Default::default()
                            },
                        )
                        .await
                        .map(|_| ())
                    }
                    _ => Ok(()),
                },
                71..=85 => match s
                    .get_zone(z)
                    .unwrap()
                    .map(|zz| s.list_records(zz.id).unwrap())
                {
                    Some(rs) if !rs.is_empty() => m
                        .delete_record(actor(), z, rs[rng.random_range(0..rs.len())].id)
                        .await
                        .map(|_| ()),
                    _ => Ok(()),
                },
                86..=90 => {
                    m.set_member(
                        actor(),
                        z,
                        users[rng.random_range(0..users.len())].id,
                        if rng.random_bool(0.5) {
                            ZoneRole::Editor
                        } else {
                            ZoneRole::Viewer
                        },
                    )
                    .await
                }
                91..=93 => {
                    m.remove_member(actor(), z, users[rng.random_range(0..users.len())].id)
                        .await
                }
                94..=95 => m
                    .create_record(
                        actor(),
                        z,
                        RecordInput {
                            expires_in: Some(rng.random_range(1..5)),
                            ..rec(
                                &format!("tmp{}", rng.random_range(0..4)),
                                RecordType::A,
                                &format!("203.0.113.{}", rng.random_range(1..9)),
                            )
                        },
                    )
                    .await
                    .map(|_| ()),
                96 => {
                    let later = chrono::Utc::now() + chrono::Duration::seconds(10);
                    match m.expire_due(later).await {
                        Ok(_) => m.reap_due(later).await.map(|_| ()),
                        Err(e) => Err(e),
                    }
                }
                97..=99 => {
                    let recs = (0..rng.random_range(0..6))
                        .map(|i| ExportRecord {
                            name: format!("imp{i}"),
                            rtype: RecordType::A,
                            value: format!("198.51.100.{}", rng.random_range(1..50)),
                            ttl: None,
                            expires_at: None,
                        })
                        .collect();
                    let mode = if rng.random_bool(0.3) {
                        ImportMode::Replace
                    } else {
                        ImportMode::Merge
                    };
                    let doc = ExportDoc {
                        version: 1,
                        exported_at: String::new(),
                        zones: vec![ExportZone {
                            name: z.into(),
                            serial: None,
                            soa_mname: None,
                            soa_rname: None,
                            refresh: None,
                            retry: None,
                            expire: None,
                            minimum: None,
                            default_ttl: None,
                            owner: None,
                            overrides: None,
                            record_policy: None,
                            records: recs,
                        }],
                    };
                    m.import(actor(), doc, mode, Some(users[1].id), None)
                        .await
                        .map(|_| ())
                }
                // ---- DNSSEC: key (account class), flag, re-sign ----
                // O24: NSEC3 on, off or unchanged with it.
                130..=134 => m
                    .set_dnssec_with(
                        actor(),
                        z,
                        true,
                        step % 7 == 0,
                        [None, Some(true), Some(false)][step % 3],
                    )
                    .await
                    .map(|_| ()),
                135..=137 => m.set_dnssec(actor(), z, false, false).await.map(|_| ()),
                138..=139 => m
                    .resign_due(chrono::Utc::now() + chrono::Duration::days(8))
                    .await
                    .map(|_| ()),
                // ---- accounts, settings, TSIG ----
                k => {
                    let uid = users[rng.random_range(0..users.len())].id;
                    let r: anyhow::Result<()> = a.run(&actor(), "random", |t| {
                        match k {
                            100..=102 => {
                                let u = t.create_user(&NewUser {
                                    username: format!("x{step}"),
                                    password_hash: format!("h{step}"),
                                    display_name: String::new(),
                                    is_admin: step % 2 == 0,
                                    mfa_required: false,
                                })?;
                                extra_users.push(u.id);
                            }
                            103 => {
                                if step % 4 == 0 {
                                    // O6: a password history kept (part of the user row).
                                    let sec = settings::SecuritySettings {
                                        password_history: (step % 3) as u32 + 1,
                                        ..Default::default()
                                    };
                                    t.set_setting(
                                        settings::SECURITY_KEY,
                                        "settings.security.update",
                                        "tester",
                                        None::<&settings::SecuritySettings>,
                                        &sec,
                                    )?;
                                }
                                t.set_password(uid, &format!("p{step}"))?;
                            }
                            104 => {
                                t.set_mfa(uid, if step % 3 == 0 { None } else { Some("SECRETSECRET") })?;
                            }
                            105..=106 => {
                                let mut u = t.change_user(uid, &accounts::UserChanges::default())?;
                                if u.totp_secret.is_none() {
                                    u = t.set_mfa(uid, Some("SECRETSECRET"))?;
                                }
                                t.accept_totp_step(&u, step as u64)?;
                            }
                            107 => {
                                let u = t.change_user(uid, &accounts::UserChanges::default())?;
                                t.set_recovery_codes(&u, &[format!("c{step}a"), format!("c{step}b")])?;
                            }
                            108 => {
                                let u = t.change_user(uid, &accounts::UserChanges::default())?;
                                let hash: Option<String> = t.conn().query_row(
                                    "SELECT code_hash FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL LIMIT 1",
                                    [u.id],
                                    |r| r.get(0),
                                ).ok();
                                if let Some(h) = hash {
                                    t.use_recovery_code(&u, &h)?;
                                }
                            }
                            109..=111 => {
                                let u = t.change_user(uid, &accounts::UserChanges::default())?;
                                // M1: some tokens scoped (the scope is part of the row).
                                let scope = (step % 3 == 0).then(|| crate::model::TokenScope {
                                    zones: Some(vec![format!("z{}.test", step % 5)]),
                                    max_role: Some(crate::model::ZoneRole::Editor),
                                    expires_at: Some("2999-01-01T00:00:00.000Z".into()),
                                });
                                t.create_token_scoped(&u, &format!("t{step}"), &format!("th{step}"), &["a".into()], scope.as_ref())?;
                            }
                            112..=113 => {
                                let id: Option<i64> = t
                                    .conn()
                                    .query_row(
                                        "SELECT id FROM api_tokens WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 1",
                                        [],
                                        |r| r.get(0),
                                    )
                                    .ok();
                                if let Some(tk) = id.and_then(|id| db::get_token(t.conn(), id).ok().flatten()) {
                                    let owner = t.change_user(tk.user_id, &accounts::UserChanges::default())?;
                                    if step % 2 == 0 {
                                        t.revoke_token(&owner, &tk)?;
                                    } else if step % 3 == 0 {
                                        // M1: scope changed (set, or cleared with `{}`).
                                        let scope = if tk.scope.is_some() {
                                            crate::model::TokenScope::default()
                                        } else {
                                            crate::model::TokenScope {
                                                max_role: Some(crate::model::ZoneRole::Viewer),
                                                ..Default::default()
                                            }
                                        };
                                        t.update_token(&owner, &tk, None, Some(&scope))?;
                                    } else {
                                        t.update_token_tags(&owner, &tk, &[format!("g{step}")])?;
                                    }
                                }
                            }
                            114..=116 => {
                                let name = format!("k{}.", step % 3);
                                match crate::storage::get_tsig_key(t.conn(), &name)? {
                                    None => {
                                        t.create_tsig_key(
                                            "tester",
                                            &tsig::NewTsigKey {
                                                name,
                                                algorithm: crate::dns::tsig::Algorithm::HmacSha256,
                                                secret: format!("secret-{step}").into_bytes(),
                                                zones: vec![],
                                                imported: true,
                                            },
                                        )?;
                                    }
                                    Some(k) if step % 2 == 0 => {
                                        t.update_tsig_key_zones(&k, &[z.to_string()])?;
                                    }
                                    Some(k) => {
                                        t.delete_tsig_key(&k)?;
                                    }
                                }
                            }
                            117..=119 => {
                                // Open resolver mode (and its wide ACL) must replay too.
                                let open = step % 3 == 0;
                                let f = settings::ForwardingSettings {
                                    upstreams: vec![format!("192.0.2.{}:53", step % 200 + 1).parse().unwrap()],
                                    allowed_clients: if open {
                                        vec!["0.0.0.0/0".into(), "::/0".into()]
                                    } else {
                                        vec!["10.0.0.0/8".into()]
                                    },
                                    timeout_ms: 1000 + step as u64,
                                    cache_max_ttl: None,
                                    cache_negative_max_ttl: None,
                                    open_resolver: Some(open),
                                };
                                if step % 4 == 0 {
                                    t.clear_forwarding(&f)?;
                                } else {
                                    t.set_forwarding("tester", None, &f)?;
                                }
                            }
                            120..=121 => {
                                if let Some(id) = extra_users.pop() {
                                    let u = t.change_user(id, &accounts::UserChanges::default())?;
                                    t.delete_user(&u)?;
                                }
                            }
                            122..=124 => {
                                t.change_user(
                                    uid,
                                    &accounts::UserChanges {
                                        display_name: Some(format!("n{step}")),
                                        is_admin: Some(step % 2 == 0),
                                        disabled: Some(step % 5 == 0),
                                        mfa_required: Some(step % 3 == 0),
                                        ..Default::default()
                                    },
                                )?;
                            }
                            125 => {
                                t.sync_root("root", &format!("$argon2id$root-{step}"), step % 2 == 0)?;
                            }
                            _ => {
                                // A rolled-back account transaction: nothing may be logged.
                                t.create_user(&NewUser {
                                    username: format!("y{step}"),
                                    password_hash: "h".into(),
                                    display_name: String::new(),
                                    is_admin: false,
                                    mfa_required: false,
                                })?;
                                anyhow::bail!("rollback");
                            }
                        }
                        Ok(())
                    });
                    r.map_err(MutationError::Internal)
                }
            };
            if res.is_err() {
                failures += 1;
            }
        }
        assert!(
            failures > 0,
            "the sequence should include rejected operations (rollbacks)"
        );
        assert!(!s.list_zones().unwrap().is_empty());

        // N1: a whole key rollover (every stage is a `dnssec_key_set` of
        // the row, with the other key inside) and a cancelled one.
        {
            let mut cfg = m.signer.config();
            cfg.rollover_max_wait_secs = 1;
            m.signer.set_config(cfg);
            m.create_zone(actor(), zone_input("rr.test"), None)
                .await
                .unwrap();
            m.set_dnssec(actor(), "rr.test", true, false).await.unwrap();
            m.rollover_start(actor(), "rr.test").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            m.rollover_ds_added(actor(), "rr.test").await.unwrap();
            assert!(m
                .rollover_step("rr.test", RolloverStep::ParentOk { ds_ttl: 3600 })
                .await
                .unwrap());
            assert!(
                !m.rollover_step("rr.test", RolloverStep::Switch)
                    .await
                    .unwrap(),
                "wait first"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            assert!(m
                .rollover_step("rr.test", RolloverStep::Switch)
                .await
                .unwrap());
            assert!(
                m.rollover_cancel(actor(), "rr.test").await.is_err(),
                "no cancel after the switch"
            );
            assert!(m
                .rollover_step("rr.test", RolloverStep::ParentOk { ds_ttl: 3600 })
                .await
                .unwrap());
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            assert!(m
                .rollover_step("rr.test", RolloverStep::Finish)
                .await
                .unwrap());
            m.rollover_start(actor(), "rr.test").await.unwrap();
            m.rollover_cancel(actor(), "rr.test").await.unwrap();
            m.rollover_start(actor(), "rr.test").await.unwrap(); // left running
        }

        // Replay the whole changelog into an empty database.
        let target = Storage::open_memory().unwrap();
        let events = s
            .read_tx(|c| crate::replication::data::changelog_tail(c, 0))
            .unwrap();
        eprintln!(
            "replay test: {} changelog rows, {} rolled back, {} zones, {} records left",
            events.len(),
            failures,
            s.list_zones().unwrap().len(),
            s.all_records().unwrap().len()
        );
        assert!(events.len() > 500, "enough history: {}", events.len());
        assert!(failures >= 10, "rollbacks exercised: {failures}");
        for kind in [
            "zone_created",
            "zone_updated",
            "zone_deleted",
            "record_created",
            "record_updated",
            "record_deleted",
            "record_expired",
            "record_reaped",
            "serial_bumped",
            "member_set",
            "member_removed",
            "user_created",
            "user_updated",
            "user_deleted",
            "totp_step_accepted",
            "recovery_codes_replaced",
            "recovery_code_used",
            "token_created",
            "token_tags_set",
            "token_revoked",
            "tsig_key_set",
            "tsig_key_deleted",
            "setting_set",
            "setting_cleared",
            "dnssec_key_set",
            "dnssec_key_deleted",
            "zone_resigned",
        ] {
            assert!(
                events.iter().any(|e| e.payload["kind"] == kind),
                "history contains {kind}"
            );
        }
        // UPDATE_FIXTURES=1: store real payloads of every kind, exactly as
        // written to the changelog (the wire-format fixture, see
        // `stored_changelog_payloads_round_trip_byte_for_byte`).
        if std::env::var("UPDATE_FIXTURES").is_ok() {
            let raw: Vec<String> = s
                .read_tx(|c| {
                    let mut st = c.prepare("SELECT payload FROM changelog ORDER BY offset")?;
                    let rows = st.query_map([], |r| r.get(0))?;
                    Ok(rows.collect::<Result<_, _>>()?)
                })
                .unwrap();
            let mut per_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for line in raw {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                let list = per_kind
                    .entry(v["kind"].as_str().unwrap().to_string())
                    .or_default();
                if list.len() < 3 && !list.contains(&line) {
                    list.push(line);
                }
            }
            let out: Vec<String> = per_kind.into_values().flatten().collect();
            std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
            std::fs::write(fixture_path(), out.join("\n") + "\n").unwrap();
        }
        let n = replay::replay(&target, &events).unwrap();
        assert_eq!(n, events.len());
        assert_eq!(
            dump(&target),
            dump(&s),
            "replayed data must equal the source in every replicated table"
        );

        // The comparison is sensitive: dropping the last committed change breaks equality.
        let partial = Storage::open_memory().unwrap();
        replay::replay(&partial, &events[..events.len() - 1]).unwrap();
        assert_ne!(dump(&partial), dump(&s));

        // Rows written before the structured changelog are refused, and nothing is applied.
        let mut old = events[0].clone();
        old.payload = serde_json::json!({ "zone": "legacy" });
        let fresh = Storage::open_memory().unwrap();
        assert!(replay::replay(&fresh, &[old]).is_err());
        assert!(fresh.list_zones().unwrap().is_empty());
        let _ = &a;
    }
}
