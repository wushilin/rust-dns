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
pub mod replay;
pub mod settings;
mod sql;

use crate::cache::{Cache, Catalog};
use crate::events::Bus;
use crate::model::*;
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

/// A committed fact. Serialized as the changelog payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
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
}

impl Change {
    /// (action, entity, zone, entity id) columns of the changelog row.
    pub fn meta(&self) -> (&'static str, &'static str, &str, Option<i64>) {
        match self {
            Change::ZoneCreated { zone } => ("create", "zone", &zone.name, Some(zone.id)),
            Change::ZoneUpdated { after, .. } => ("update", "zone", &after.name, Some(after.id)),
            Change::ZoneDeleted { zone } => ("delete", "zone", &zone.name, Some(zone.id)),
            Change::RecordCreated { zone, record } => ("create", "record", zone, Some(record.id)),
            Change::RecordUpdated { zone, after, .. } => ("update", "record", zone, Some(after.id)),
            Change::RecordDeleted { zone, record } => ("delete", "record", zone, Some(record.id)),
            Change::RecordExpired { zone, record } => ("expire", "record", zone, Some(record.id)),
            Change::RecordReaped { zone, record } => ("reap", "record", zone, Some(record.id)),
            Change::SerialBumped { zone, zone_id, .. } => {
                ("update", "serial", zone, Some(*zone_id))
            }
            Change::MemberSet { zone, user_id, .. } => ("update", "member", zone, Some(*user_id)),
            Change::MemberRemoved { zone, user_id, .. } => {
                ("delete", "member", zone, Some(*user_id))
            }
        }
    }
}

/// The only handle an operation gets on the database during a transaction.
pub struct Tx<'a> {
    conn: &'a Connection,
    changes: Vec<Change>,
    /// Zones whose DNS content changed: serial is bumped once at commit.
    touched: BTreeMap<i64, String>,
}

impl<'a> Tx<'a> {
    fn new(conn: &'a Connection) -> Self {
        Tx {
            conn,
            changes: Vec::new(),
            touched: BTreeMap::new(),
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
            .push(Change::ZoneCreated { zone: zone.clone() });
        Ok(zone)
    }

    pub fn update_zone(&mut self, before: Zone, mut after: Zone) -> MResult<Zone> {
        after.id = before.id;
        after.name = before.name.clone();
        after.serial = before.serial;
        after.updated_at = now_rfc3339();
        let zone = sql::update_zone(self.conn, &after)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::ZoneUpdated {
            before,
            after: zone.clone(),
        });
        Ok(zone)
    }

    pub fn delete_zone(&mut self, zone: &Zone) -> MResult<()> {
        for r in self.records(zone.id)? {
            self.delete_record(zone, &r)?;
        }
        for m in self.members(zone.id)? {
            self.remove_member(zone, m.user_id)?;
        }
        sql::delete_zone(self.conn, zone.id)?;
        self.touched.remove(&zone.id);
        self.changes
            .push(Change::ZoneDeleted { zone: zone.clone() });
        Ok(())
    }

    /// Why a record may not be added / changed, if anything.
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
            .filter(|r| !r.is_expired_at(&now))
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
        let existing = self.records(zone.id)?;
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
        let existing = self.records(zone.id)?;
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
        self.changes.push(Change::RecordCreated {
            zone: zone.name.clone(),
            record: record.clone(),
        });
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
        let existing = self.records(zone.id)?;
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
        self.changes.push(Change::RecordUpdated {
            zone: zone.name.clone(),
            before: before.clone(),
            after: after.clone(),
        });
        Ok(after)
    }

    /// Stop serving a record whose expiry has passed. Bumps the serial (DNS content changed).
    pub fn expire_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::mark_expired(self.conn, record.id)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::RecordExpired {
            zone: zone.name.clone(),
            record: record.clone(),
        });
        Ok(())
    }

    /// Delete an expired record after the retention period. It was already not
    /// served, so the serial does not change.
    pub fn reap_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::delete_record(self.conn, record.id)?;
        self.changes.push(Change::RecordReaped {
            zone: zone.name.clone(),
            record: record.clone(),
        });
        Ok(())
    }

    pub fn zone_by_id(&self, id: i64) -> MResult<Option<Zone>> {
        Ok(db::get_zone_by_id(self.conn, id)?)
    }

    pub fn delete_record(&mut self, zone: &Zone, record: &Record) -> MResult<()> {
        sql::delete_record(self.conn, record.id)?;
        self.touched.insert(zone.id, zone.name.clone());
        self.changes.push(Change::RecordDeleted {
            zone: zone.name.clone(),
            record: record.clone(),
        });
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
        self.changes.push(Change::MemberSet {
            zone: zone.name.clone(),
            zone_id: zone.id,
            user_id: user.id,
            username: user.username.clone(),
            role: role.into(),
            previous: previous.map(|m| m.role),
            created_at,
        });
        Ok(())
    }

    pub fn remove_member(&mut self, zone: &Zone, user_id: i64) -> MResult<()> {
        let m = self
            .members(zone.id)?
            .into_iter()
            .find(|m| m.user_id == user_id)
            .ok_or_else(|| MutationError::NotFound("membership not found".into()))?;
        sql::delete_member(self.conn, zone.id, user_id)?;
        self.changes.push(Change::MemberRemoved {
            zone: zone.name.clone(),
            zone_id: zone.id,
            user_id,
            username: m.username,
            role: m.role,
        });
        Ok(())
    }

    /// Bump serials of changed zones, then write every change to the changelog.
    fn finish(mut self, actor: &Actor, command: &str) -> MResult<Vec<ChangeEvent>> {
        for (zone_id, name) in std::mem::take(&mut self.touched) {
            let Some(z) = db::get_zone_by_id(self.conn, zone_id)? else {
                continue;
            };
            let serial = z.serial.wrapping_add(1).max(1);
            let updated_at = now_rfc3339();
            sql::set_serial(self.conn, zone_id, serial, &updated_at)?;
            self.changes.push(Change::SerialBumped {
                zone: name,
                zone_id,
                serial,
                updated_at,
            });
        }
        let txn = crate::auth::random_token(9);
        let mut events = Vec::with_capacity(self.changes.len());
        for c in &self.changes {
            events.push(sql::append_changelog(self.conn, actor, command, &txn, c)?);
        }
        Ok(events)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MutationError {
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
}

/// JSON export / import document.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[schema(example = json!({
    "version": 1, "exported_at": "2026-01-15T09:30:00.000Z",
    "zones": [{
        "name": "example.com", "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "default_ttl": 3600,
        "records": [
            { "name": "@", "type": "NS", "value": "ns1.example.com." },
            { "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300 },
            { "name": "www", "type": "AAAA", "value": "2001:db8::10" },
            { "name": "@", "type": "MX", "value": "10 mail.example.com." }
        ]
    }]
}))]
pub struct ExportDoc {
    #[schema(example = 1)]
    pub version: u32,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub exported_at: String,
    pub zones: Vec<ExportZone>,
}

/// One zone of an export document. On import, omitted SOA fields fall back
/// to the server defaults (new zones) or are left unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportZone {
    pub name: String,
    #[serde(default)]
    #[schema(format = Int64, maximum = 4294967295_u64)]
    pub serial: Option<u32>,
    #[serde(default)]
    pub soa_mname: Option<String>,
    #[serde(default)]
    pub soa_rname: Option<String>,
    #[serde(default)]
    pub refresh: Option<u32>,
    #[serde(default)]
    pub retry: Option<u32>,
    #[serde(default)]
    pub expire: Option<u32>,
    #[serde(default)]
    pub minimum: Option<u32>,
    #[serde(default)]
    pub default_ttl: Option<u32>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    #[schema(default = json!([]))]
    pub records: Vec<ExportRecord>,
}

/// One record of an export document; `ttl: null` (or omitted) means the
/// zone default.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: RecordType,
    pub value: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Exported expiry. Records already expired at import time are skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub expires_at: Option<String>,
}

/// `merge` adds missing zones and records; `replace` replaces the records of
/// each zone in the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add zones and records that are missing; keep everything else.
    Merge,
    /// Zones in the document have their records replaced wholesale.
    Replace,
}

/// What an import changed.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
#[schema(example = json!({ "zones_created": 0, "zones_updated": 1, "records_added": 3, "records_removed": 0, "records_skipped": 0 }))]
pub struct ImportSummary {
    pub zones_created: usize,
    pub zones_updated: usize,
    pub records_added: usize,
    pub records_removed: usize,
    pub records_skipped: usize,
}

fn normalize_rname(s: &str) -> Result<String, Invalid> {
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

fn apply_zone_input(z: &mut Zone, input: &ZoneInput) -> Result<(), Invalid> {
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

fn soa_differs(a: &Zone, b: &Zone) -> bool {
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

fn new_zone(
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

fn default_zone(name: &str, owner_id: Option<i64>) -> Zone {
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
    }
}

/// Validate a record against the other records in the zone.
fn check_record_rules(
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
        };
        m.set_zone_defaults(default_primary_ns, default_hostmaster);
        m
    }

    pub fn set_zone_defaults(&self, default_primary_ns: &str, default_hostmaster: &str) {
        let mname = normalize_domain(default_primary_ns, true)
            .ok()
            .map(|n| format!("{n}."));
        let rname = normalize_rname(default_hostmaster).ok();
        *self.zone_defaults.write().unwrap() = (mname, rname);
    }

    fn defaults(&self) -> (Option<String>, Option<String>) {
        self.zone_defaults.read().unwrap().clone()
    }

    /// Rebuild the catalog from storage (used at startup).
    pub fn rebuild(&self) -> Result<()> {
        let catalog = Catalog::build(self.storage.list_zones()?, self.storage.all_records()?);
        self.cache.store(catalog);
        Ok(())
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
        let storage = self.storage.clone();
        let tx_actor = actor.clone();
        let joined = tokio::task::spawn_blocking(move || {
            storage.write(&TOKEN, |conn| -> MResult<(T, Vec<ChangeEvent>)> {
                let mut t = Tx::new(conn);
                let out = f(&mut t)?;
                let events = t.finish(&tx_actor, command)?;
                Ok((out, events))
            })
        })
        .await;
        let (out, events) = match joined {
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
        // the caller must learn that the change happened.
        self.refresh_catalog().await;
        self.expiry_wake.notify_one();
        for ev in events {
            tracing::info!(offset = ev.offset, txn = %ev.txn, command, actor = %ev.actor, ip = %ev.actor_ip, action = %ev.action, entity = %ev.entity, zone = %ev.zone, "change committed");
            self.bus.publish_change(ev);
        }
        Ok(out)
    }

    /// Rebuild the in-memory catalog after a commit. A failure is logged and
    /// retried in the background; it never un-commits the change.
    async fn refresh_catalog(&self) {
        let storage = self.storage.clone();
        let build = || {
            let storage = storage.clone();
            tokio::task::spawn_blocking(move || -> Result<Catalog> {
                Ok(Catalog::build(
                    storage.list_zones()?,
                    storage.all_records()?,
                ))
            })
        };
        match build().await {
            Ok(Ok(c)) => self.cache.store(c),
            other => {
                let err = match other {
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => e.to_string(),
                    _ => unreachable!(),
                };
                tracing::error!(error = %err, "catalog rebuild failed after commit; DNS answers are stale until it succeeds");
                let cache = self.cache.clone();
                tokio::spawn(async move {
                    for attempt in 1..=10u64 {
                        tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
                        let s = storage.clone();
                        if let Ok(Ok(c)) =
                            tokio::task::spawn_blocking(move || -> Result<Catalog> {
                                Ok(Catalog::build(s.list_zones()?, s.all_records()?))
                            })
                            .await
                        {
                            cache.store(c);
                            tracing::info!(attempt, "catalog rebuilt after earlier failure");
                            return;
                        }
                    }
                    tracing::error!("catalog rebuild still failing; restart the server");
                });
            }
        }
    }

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

    // ---- expiry --------------------------------------------------------

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

    // ---- import --------------------------------------------------------

    /// Import a document as one transaction: every zone and record in it is
    /// committed, or none is. `allowed` restricts which zones may be touched
    /// (None = any); new zones are owned by `owner_id`.
    pub async fn import(
        &self,
        actor: Actor,
        doc: ExportDoc,
        mode: ImportMode,
        owner_id: Option<i64>,
        allowed: Option<Vec<String>>,
    ) -> MResult<ImportSummary> {
        let defaults = self.defaults();
        self.execute(actor, "import", move |t| {
            let mut summary = ImportSummary::default();
            for ez in doc.zones {
                let name = normalize_zone_name(&ez.name)?;
                if let Some(a) = &allowed {
                    if !a.contains(&name) {
                        return Err(MutationError::Invalid(format!(
                            "not permitted to import zone '{name}'"
                        )));
                    }
                }
                let input = ZoneInput {
                    name: Some(name.clone()),
                    soa_mname: ez.soa_mname.clone(),
                    soa_rname: ez.soa_rname.clone(),
                    refresh: ez.refresh,
                    retry: ez.retry,
                    expire: ez.expire,
                    minimum: ez.minimum,
                    default_ttl: ez.default_ttl,
                    owner: None,
                };
                let zone = match t.zone(&name)? {
                    Some(before) => {
                        let mut after = before.clone();
                        apply_zone_input(&mut after, &input)?;
                        summary.zones_updated += 1;
                        if soa_differs(&before, &after) {
                            t.update_zone(before, after)?
                        } else {
                            before
                        }
                    }
                    None => {
                        let mut z = new_zone(&defaults, &name, owner_id);
                        apply_zone_input(&mut z, &input)?;
                        if let Some(s) = ez.serial {
                            z.serial = s;
                        }
                        summary.zones_created += 1;
                        t.create_zone(z)?
                    }
                };
                if mode == ImportMode::Replace {
                    for r in t.records(zone.id)? {
                        t.delete_record(&zone, &r)?;
                        summary.records_removed += 1;
                    }
                }
                let mut existing = t.records(zone.id)?;
                let now = chrono::Utc::now();
                for er in ez.records {
                    let rname = normalize_record_name(&er.name, &name)?;
                    let value = normalize_value(er.rtype, &er.value)?;
                    // Expiry travels with exported records; already-expired ones are not imported.
                    let expires_at = match &er.expires_at {
                        None => None,
                        Some(t0) => match resolve_expiry(
                            &RecordInput {
                                expires_at: Some(Some(t0.clone())),
                                ..Default::default()
                            },
                            now,
                        ) {
                            Ok(Some(e)) => e,
                            _ => {
                                summary.records_skipped += 1;
                                continue;
                            }
                        },
                    };
                    if t.record_conflict(&existing, None, &rname, er.rtype, &value)
                        .is_some()
                    {
                        summary.records_skipped += 1;
                        continue;
                    }
                    let rec = t.create_record(
                        &zone,
                        &rname,
                        er.rtype,
                        &value,
                        er.ttl.filter(|v| *v > 0),
                        expires_at,
                    )?;
                    existing.push(rec);
                    summary.records_added += 1;
                }
            }
            Ok(summary)
        })
        .await
    }

    pub fn export_all(&self, only: Option<&[String]>) -> Result<ExportDoc> {
        let catalog = self.cache.load();
        let mut zones = Vec::new();
        for zd in catalog.zones.values() {
            if let Some(o) = only {
                if !o.contains(&zd.zone.name) {
                    continue;
                }
            }
            zones.push(export_zone(zd));
        }
        Ok(ExportDoc {
            version: 1,
            exported_at: now_rfc3339(),
            zones,
        })
    }
}

pub fn export_zone(zd: &crate::cache::ZoneData) -> ExportZone {
    let z = &zd.zone;
    let mut records: Vec<ExportRecord> = zd
        .names
        .values()
        .flatten()
        .map(|r| ExportRecord {
            name: r.name.clone(),
            rtype: r.rtype,
            value: r.value.clone(),
            ttl: r.ttl,
            expires_at: r.expires_at.clone(),
        })
        .collect();
    records.sort_by(|a, b| {
        (a.name.len(), &a.name, a.rtype, &a.value).cmp(&(b.name.len(), &b.name, b.rtype, &b.value))
    });
    ExportZone {
        name: z.name.clone(),
        serial: Some(z.serial),
        soa_mname: Some(z.soa_mname.clone()),
        soa_rname: Some(z.soa_rname.clone()),
        refresh: Some(z.refresh),
        retry: Some(z.retry),
        expire: Some(z.expire),
        minimum: Some(z.minimum),
        default_ttl: Some(z.default_ttl),
        owner: None,
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::accounts::Accounts;
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn setup() -> (Arc<Storage>, Mutator, Accounts) {
        let storage = Arc::new(Storage::open_memory().unwrap());
        let cache = Arc::new(Cache::new(Catalog::empty()));
        let bus = Arc::new(Bus::new(64, 64));
        let m = Mutator::new(storage.clone(), cache, bus, "", "");
        let a = Accounts::new(storage.clone());
        (storage, m, a)
    }

    fn actor() -> Actor {
        Actor {
            name: "tester".into(),
            ip: "127.0.0.1".into(),
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

    fn zone_input(name: &str) -> ZoneInput {
        ZoneInput {
            name: Some(name.into()),
            ..Default::default()
        }
    }

    fn log(s: &Storage) -> Vec<ChangeEvent> {
        s.changelog_after(0, 1_000_000).unwrap()
    }

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

    fn expiring(name: &str, v: &str, secs: u64) -> RecordInput {
        RecordInput {
            expires_in: Some(secs),
            ..rec(name, RecordType::A, v)
        }
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

    /// Dump of all replicated state, for equality checks.
    fn dump(s: &Storage) -> serde_json::Value {
        let zones = s.list_zones().unwrap();
        let mut records = s.all_records().unwrap();
        records.sort_by_key(|r| r.id);
        let members: Vec<_> = zones
            .iter()
            .map(|z| (z.id, s.list_members(z.id).unwrap()))
            .collect();
        serde_json::json!({ "zones": zones, "records": records, "members": members })
    }

    #[tokio::test]
    async fn replaying_the_changelog_rebuilds_identical_data() {
        let (s, m, a) = setup();
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
        let zones = ["r1.test", "r2.test", "r3.test"];
        let types = [
            (RecordType::A, "192.0.2."),
            (RecordType::AAAA, "2001:db8::"),
            (RecordType::TXT, "t"),
            (RecordType::CNAME, "c"),
        ];
        let mut failures = 0;
        for step in 0..400 {
            let z = zones[rng.random_range(0..zones.len())];
            let res: MResult<()> = match rng.random_range(0..100) {
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
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .map(|_| ()),
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
                    // Simulated clock: expire and reap everything due within the next 10 s.
                    let later = chrono::Utc::now() + chrono::Duration::seconds(10);
                    match m.expire_due(later).await {
                        Ok(_) => m.reap_due(later).await.map(|_| ()),
                        Err(e) => Err(e),
                    }
                }
                _ => {
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
                            records: recs,
                        }],
                    };
                    m.import(actor(), doc, mode, Some(users[1].id), None)
                        .await
                        .map(|_| ())
                }
            };
            if res.is_err() {
                failures += 1;
            }
            let _ = step;
        }
        assert!(
            failures > 0,
            "the sequence should include rejected operations (rollbacks)"
        );
        assert!(!s.list_zones().unwrap().is_empty());

        // Replay into a fresh database that has the same users.
        let target = Storage::open_memory().unwrap();
        let ta = Accounts::new(Arc::new(target));
        for u in &users {
            ta.create_user(
                &actor(),
                &NewUser {
                    username: u.username.clone(),
                    password_hash: "h".into(),
                    display_name: String::new(),
                    is_admin: false,
                    mfa_required: false,
                },
            )
            .unwrap();
        }
        let target = ta_storage(&ta);
        let events = log(&s);
        eprintln!(
            "replay test: {} changelog rows, {} rolled back, {} zones, {} records left",
            events.len(),
            failures,
            s.list_zones().unwrap().len(),
            s.all_records().unwrap().len()
        );
        assert!(
            events.len() > 300,
            "enough history to be meaningful: {}",
            events.len()
        );
        assert!(failures >= 10, "rollbacks exercised: {failures}");
        assert!(!s.all_records().unwrap().is_empty());
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
        ] {
            assert!(
                events.iter().any(|e| e.payload["kind"] == kind),
                "history contains {kind}"
            );
        }
        let n = replay::replay(&target, &events).unwrap();
        assert_eq!(n, events.len());
        assert_eq!(
            dump(&target),
            dump(&s),
            "replayed data must equal the source"
        );

        // The comparison is sensitive: dropping the last committed change breaks equality.
        let partial = ta_storage(&{
            let a2 = Accounts::new(Arc::new(Storage::open_memory().unwrap()));
            for u in &users {
                a2.create_user(
                    &actor(),
                    &NewUser {
                        username: u.username.clone(),
                        password_hash: "h".into(),
                        display_name: String::new(),
                        is_admin: false,
                        mfa_required: false,
                    },
                )
                .unwrap();
            }
            a2
        });
        replay::replay(&partial, &events[..events.len() - 1]).unwrap();
        assert_ne!(dump(&partial), dump(&s));

        // Rows written before the structured changelog are refused, and nothing is applied.
        let mut old = events[0].clone();
        old.payload = serde_json::json!({ "zone": "legacy" });
        let fresh = Storage::open_memory().unwrap();
        assert!(replay::replay(&fresh, &[old]).is_err());
        assert!(fresh.list_zones().unwrap().is_empty());
    }

    fn ta_storage(a: &Accounts) -> Arc<Storage> {
        a.storage_for_tests()
    }
}
