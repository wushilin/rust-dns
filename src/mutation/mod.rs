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
pub mod replay;
pub mod replica;
pub mod settings;
mod sql;
pub mod tsig;

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

/// A committed fact. Serialized as the changelog payload.
///
/// One enum for DNS data and for accounts, settings and TSIG keys, so there
/// is one ordered changelog (one cursor for a standby, and a user always
/// exists before a change that refers to it), one exhaustive replay, and one
/// serialization. [`Change::class`] separates the two families: account
/// changes carry password hashes, TOTP and TSIG secrets and never leave
/// through the user-facing changelog API or websocket.
///
/// Account facts are the resulting state (whole rows where a row changed),
/// not intents, so replaying them reproduces identical rows.
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
    // ---- accounts, settings, TSIG (class "account") ----------------------
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
    TokenTagsSet {
        token_id: i64,
        tags: Vec<String>,
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
            Change::ZoneResigned { zone, zone_id, .. } => ("resign", "zone", zone, Some(*zone_id)),
            Change::UserCreated { user } => ("create", "user", "", Some(user.id)),
            Change::UserUpdated { user } => ("update", "user", "", Some(user.id)),
            Change::UserDeleted { user_id, .. } => ("delete", "user", "", Some(*user_id)),
            Change::TotpStepAccepted { user_id, .. } => ("update", "totp_step", "", Some(*user_id)),
            Change::RecoveryCodesReplaced { user_id, .. } => {
                ("update", "recovery_codes", "", Some(*user_id))
            }
            Change::RecoveryCodeUsed { user_id, .. } => {
                ("update", "recovery_code", "", Some(*user_id))
            }
            Change::TokenCreated { token } => ("create", "token", "", Some(token.id)),
            Change::TokenTagsSet { token_id, .. } => ("update", "token", "", Some(*token_id)),
            Change::TokenRevoked { token_id, .. } => ("revoke", "token", "", Some(*token_id)),
            Change::TsigKeySet { .. } => ("update", "tsig_key", "", None),
            Change::TsigKeyDeleted { .. } => ("delete", "tsig_key", "", None),
            Change::SettingSet { .. } => ("update", "setting", "", None),
            Change::SettingCleared { .. } => ("delete", "setting", "", None),
            // No zone name: account rows never reach zone-scoped views.
            Change::DnssecKeySet { key } => ("update", "dnssec_key", "", Some(key.zone_id)),
            Change::DnssecKeyDeleted { zone_id, .. } => {
                ("delete", "dnssec_key", "", Some(*zone_id))
            }
        }
    }

    /// [`CLASS_DNS`] or [`CLASS_ACCOUNT`].
    pub fn class(&self) -> &'static str {
        match self {
            Change::ZoneCreated { .. }
            | Change::ZoneUpdated { .. }
            | Change::ZoneDeleted { .. }
            | Change::RecordCreated { .. }
            | Change::RecordUpdated { .. }
            | Change::RecordExpired { .. }
            | Change::RecordReaped { .. }
            | Change::RecordDeleted { .. }
            | Change::SerialBumped { .. }
            | Change::MemberSet { .. }
            | Change::MemberRemoved { .. }
            | Change::ZoneResigned { .. } => CLASS_DNS,
            Change::UserCreated { .. }
            | Change::UserUpdated { .. }
            | Change::UserDeleted { .. }
            | Change::TotpStepAccepted { .. }
            | Change::RecoveryCodesReplaced { .. }
            | Change::RecoveryCodeUsed { .. }
            | Change::TokenCreated { .. }
            | Change::TokenTagsSet { .. }
            | Change::TokenRevoked { .. }
            | Change::TsigKeySet { .. }
            | Change::TsigKeyDeleted { .. }
            | Change::SettingSet { .. }
            | Change::SettingCleared { .. }
            | Change::DnssecKeySet { .. }
            | Change::DnssecKeyDeleted { .. } => CLASS_ACCOUNT,
        }
    }

    /// The zone whose catalog entry this change can alter (its row, its
    /// served records, its signing key): after a commit exactly these zones
    /// are rebuilt. `None`: nothing the DNS server answers from changed.
    /// Exhaustive, so a new kind of change must decide.
    pub fn catalog_zone(&self) -> Option<i64> {
        match self {
            Change::ZoneCreated { zone } | Change::ZoneDeleted { zone } => Some(zone.id),
            Change::ZoneUpdated { after, .. } => Some(after.id),
            Change::RecordCreated { record, .. }
            | Change::RecordDeleted { record, .. }
            | Change::RecordExpired { record, .. }
            | Change::RecordReaped { record, .. } => Some(record.zone_id),
            // An update keeps the record in its zone.
            Change::RecordUpdated { after, .. } => Some(after.zone_id),
            Change::SerialBumped { zone_id, .. } | Change::ZoneResigned { zone_id, .. } => {
                Some(*zone_id)
            }
            Change::DnssecKeySet { key } => Some(key.zone_id),
            Change::DnssecKeyDeleted { zone_id, .. } => Some(*zone_id),
            Change::MemberSet { .. }
            | Change::MemberRemoved { .. }
            | Change::UserCreated { .. }
            | Change::UserUpdated { .. }
            | Change::UserDeleted { .. }
            | Change::TotpStepAccepted { .. }
            | Change::RecoveryCodesReplaced { .. }
            | Change::RecoveryCodeUsed { .. }
            | Change::TokenCreated { .. }
            | Change::TokenTagsSet { .. }
            | Change::TokenRevoked { .. }
            | Change::TsigKeySet { .. }
            | Change::TsigKeyDeleted { .. }
            | Change::SettingSet { .. }
            | Change::SettingCleared { .. } => None,
        }
    }

    /// Settings or TSIG keys changed: the DNS server must reload them.
    pub fn affects_dns_runtime(&self) -> bool {
        matches!(
            self,
            Change::TsigKeySet { .. }
                | Change::TsigKeyDeleted { .. }
                | Change::SettingSet { .. }
                | Change::SettingCleared { .. }
        )
    }
}

/// The only handle an operation gets on the database during a transaction.
pub struct Tx<'a> {
    conn: &'a Connection,
    changes: Vec<Change>,
    /// Zones whose DNS content changed: serial is bumped once at commit.
    touched: BTreeMap<i64, String>,
    /// Zones being re-signed: their signing epoch moves to the commit time.
    resigned: std::collections::BTreeSet<i64>,
}

impl<'a> Tx<'a> {
    fn new(conn: &'a Connection) -> Self {
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
            .push(Change::ZoneCreated { zone: zone.clone() });
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
        if self.dnssec_key(zone.id)?.is_some() {
            self.delete_dnssec_key(zone)?;
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
        self.changes.push(Change::ZoneUpdated {
            before: zone.clone(),
            after: after.clone(),
        });
        Ok(after)
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
        let change = Change::DnssecKeySet { key };
        acct_sql::write(self.conn, &acct_sql::Ctx::verbatim(), &change)?
            .log_into(change, &mut self.changes);
        Ok(())
    }

    pub fn delete_dnssec_key(&mut self, zone: &Zone) -> MResult<()> {
        let change = Change::DnssecKeyDeleted {
            zone_id: zone.id,
            zone: zone.name.clone(),
        };
        acct_sql::write(self.conn, &acct_sql::Ctx::verbatim(), &change)?
            .log_into(change, &mut self.changes);
        Ok(())
    }

    /// Re-sign: record why; at commit the serial is bumped and the signing
    /// epoch moves to the commit time (a new signature window).
    pub fn resign_zone(&mut self, zone: &Zone, key_tag: u16) -> MResult<()> {
        self.touched.insert(zone.id, zone.name.clone());
        self.resigned.insert(zone.id);
        self.changes.push(Change::ZoneResigned {
            zone: zone.name.clone(),
            zone_id: zone.id,
            key_tag,
        });
        Ok(())
    }

    /// Bump serials of changed zones, then write every change to the
    /// changelog. Returns the events to publish and the zones whose catalog
    /// entries must be rebuilt (derived from the changes themselves).
    fn finish(mut self, actor: &Actor, command: &str) -> MResult<(Vec<ChangeEvent>, Vec<i64>)> {
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
            self.changes.push(Change::SerialBumped {
                zone: name,
                zone_id,
                serial,
                updated_at,
                signed_at,
            });
        }
        let txn = crate::auth::random_token(9);
        let mut events = Vec::with_capacity(self.changes.len());
        for c in &self.changes {
            let ev = sql::append_changelog(self.conn, actor, command, &txn, c)?;
            // Account-class rows (secrets) are for standbys only: never
            // published to the websocket / live feed.
            if c.class() == CLASS_DNS {
                events.push(ev);
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

/// How much of the catalog a committed write may have changed.
pub(crate) enum Rebuild {
    /// These zones (possibly none).
    Zones(Vec<i64>),
    /// Anything (snapshot load, history change): build it all again.
    Full,
}

/// Whether this server accepts writes. Closed on a standby (and on a fenced
/// old primary): [`Mutator::execute`] refuses every DNS operation, so no
/// background writer (the expiry sweeper) or forgotten route can write. The
/// replication apply path (`replica`) is the only DNS writer then.
pub struct WriteGate {
    read_only: std::sync::atomic::AtomicBool,
    reason: std::sync::RwLock<String>,
}

impl Default for WriteGate {
    fn default() -> Self {
        WriteGate {
            read_only: std::sync::atomic::AtomicBool::new(false),
            reason: std::sync::RwLock::new(String::new()),
        }
    }
}

impl WriteGate {
    pub fn read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The message given to refused writers.
    pub fn reason(&self) -> String {
        self.reason
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn close(&self, reason: impl Into<String>) {
        *self.reason.write().unwrap_or_else(|p| p.into_inner()) = reason.into();
        self.read_only
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn open(&self) {
        self.read_only
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.reason
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
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

/// What `PUT /zones/{zone}/dnssec` did.
#[derive(Debug, Clone)]
pub struct DnssecChange {
    pub zone: Zone,
    /// A new key was generated (first enable, or `new_key`).
    pub key_generated: bool,
    /// Signing was switched on or off by this call.
    pub changed: bool,
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
        dnssec: false,
        signed_at: None,
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
        let rname = normalize_rname(default_hostmaster).ok();
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

    /// A full build of what `s` holds now, with a signer of its own (no
    /// shared cache), configured like `m`'s.
    pub(crate) fn full_build(s: &Storage, m: &Mutator) -> Catalog {
        let signer = crate::dnssec::Signer::default();
        signer.set_config(m.signer().config());
        let (zones, records, keys) = s.catalog_inputs().unwrap();
        Catalog::build_signed(zones, records, &keys, &signer, chrono::Utc::now())
    }

    /// The served catalog must equal a full build of the database, and
    /// every signature in it must verify.
    pub(crate) fn assert_catalog_is_current(s: &Storage, m: &Mutator, what: &str) {
        let served = m.cache.load();
        let full = full_build(s, m);
        let (a, b) = (served.describe(), full.describe());
        if a != b {
            for (k, v) in a["zones"].as_object().unwrap() {
                if b["zones"].get(k) != Some(v) {
                    panic!(
                        "{what}: zone {k} differs\nincremental: {v:#}\nfull: {:#}",
                        b["zones"][k]
                    );
                }
            }
            panic!("{what}: catalogs differ\nincremental: {a:#}\nfull: {b:#}");
        }
        served.verify_signatures();
        full.verify_signatures();
    }

    /// One random DNS operation (zones incl. a parent/child pair, records
    /// incl. delegations, DS, wildcards, DNAME, addresses shared between
    /// zones for the reverse index, expiry, import, DNSSEC on/off/new
    /// key/re-sign). Used by the catalog equality tests here and in
    /// `replica`.
    pub(crate) async fn random_dns_op(
        rng: &mut StdRng,
        s: &Storage,
        m: &Mutator,
        step: usize,
    ) -> MResult<()> {
        let zones = ["eq.test", "sub.eq.test", "other.test", "10.in-addr.arpa"];
        let z = zones[rng.random_range(0..zones.len())];
        let names = [
            "@", "www", "a.b", "*.w", "x.w", "deleg", "ns.deleg", "old", "y.old", "sub",
        ];
        let pick = |rng: &mut StdRng| names[rng.random_range(0..names.len())];
        match rng.random_range(0..100) {
            0..=7 => m
                .create_zone(actor(), zone_input(z), None)
                .await
                .map(|_| ()),
            8..=9 => m.delete_zone(actor(), z).await.map(|_| ()),
            10..=14 => m
                .update_zone(
                    actor(),
                    z,
                    ZoneInput {
                        refresh: Some(rng.random_range(60..9000)),
                        default_ttl: Some(rng.random_range(30..600)),
                        minimum: Some(rng.random_range(30..600)),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .map(|_| ()),
            15..=54 => {
                let name = pick(rng);
                // Few addresses: several zones share them (reverse index).
                let n = rng.random_range(1..6);
                let (t, v) = match rng.random_range(0..12) {
                    0..=3 => (RecordType::A, format!("10.0.0.{n}")),
                    4 => (RecordType::AAAA, format!("2001:db8::{n}")),
                    5 => (RecordType::TXT, format!("text {n}")),
                    6 => (RecordType::CNAME, format!("host{n}.example.com.")),
                    7 => (RecordType::NS, format!("ns{n}.example.org.")),
                    8 => (RecordType::MX, format!("10 mx{n}.eq.test.")),
                    9 => (RecordType::DS, format!("{n} 13 2 {}", "ab".repeat(32))),
                    10 => (RecordType::DNAME, format!("target{n}.example.net.")),
                    _ => (RecordType::PTR, format!("host{n}.eq.test.")),
                };
                let mut input = rec(name, t, &v);
                match rng.random_range(0..10) {
                    0 => input.ttl = Some(Some(rng.random_range(10..900))),
                    1 => input.expires_in = Some(rng.random_range(3600..7200)),
                    _ => {}
                }
                m.create_record(actor(), z, input).await.map(|_| ())
            }
            55..=69 => match s
                .get_zone(z)
                .unwrap()
                .map(|zz| s.list_records(zz.id).unwrap())
            {
                Some(rs) if !rs.is_empty() => {
                    let r = &rs[rng.random_range(0..rs.len())];
                    let input = if r.rtype == RecordType::A {
                        RecordInput {
                            value: Some(format!("10.0.0.{}", rng.random_range(1..6))),
                            ..Default::default()
                        }
                    } else {
                        RecordInput {
                            ttl: Some(Some(rng.random_range(10..900))),
                            ..Default::default()
                        }
                    };
                    m.update_record(actor(), z, r.id, input).await.map(|_| ())
                }
                _ => Ok(()),
            },
            70..=79 => match s
                .get_zone(z)
                .unwrap()
                .map(|zz| s.list_records(zz.id).unwrap())
            {
                Some(rs) if !rs.is_empty() => {
                    let r = &rs[rng.random_range(0..rs.len())];
                    m.delete_record(actor(), z, r.id).await.map(|_| ())
                }
                _ => Ok(()),
            },
            80..=85 => m
                .set_dnssec(actor(), z, true, step.is_multiple_of(5))
                .await
                .map(|_| ()),
            86..=88 => m.set_dnssec(actor(), z, false, false).await.map(|_| ()),
            89..=90 => m
                .resign_due(chrono::Utc::now() + chrono::Duration::days(8))
                .await
                .map(|_| ()),
            // Marks the records with an expiry as expired (they stay in
            // the catalog until their time really passes) / reaps nothing.
            91..=92 => m
                .expire_due(chrono::Utc::now() + chrono::Duration::hours(3))
                .await
                .map(|_| ()),
            93 => m
                .reap_due(chrono::Utc::now() - chrono::Duration::days(30))
                .await
                .map(|_| ()),
            _ => {
                let recs = (0..rng.random_range(0..5))
                    .map(|i| ExportRecord {
                        name: format!("imp{i}"),
                        rtype: RecordType::A,
                        value: format!("10.0.1.{}", rng.random_range(1..4)),
                        ttl: None,
                        expires_at: None,
                    })
                    .collect();
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
                let mode = if rng.random_bool(0.4) {
                    ImportMode::Replace
                } else {
                    ImportMode::Merge
                };
                m.import(actor(), doc, mode, None, None).await.map(|_| ())
            }
        }
    }

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

    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/changelog_payloads.jsonl")
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

    fn dump(s: &Storage) -> serde_json::Value {
        s.read_tx(|c| {
            let mut v = serde_json::Map::new();
            for t in crate::replication::tables::replicated_tables() {
                v.insert(
                    t.name.into(),
                    crate::replication::tables::dump(
                        c,
                        t,
                        &["last_used_at", "last_used_ip"],
                        None,
                    )?
                    .into(),
                );
            }
            Ok(serde_json::Value::Object(v))
        })
        .unwrap()
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
                            records: recs,
                        }],
                    };
                    m.import(actor(), doc, mode, Some(users[1].id), None)
                        .await
                        .map(|_| ())
                }
                // ---- DNSSEC: key (account class), flag, re-sign ----
                130..=134 => m
                    .set_dnssec(actor(), z, true, step % 7 == 0)
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
                                t.create_token(&u, &format!("t{step}"), &format!("th{step}"), &["a".into()])?;
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
