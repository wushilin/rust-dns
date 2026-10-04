//! The only SQL that writes zones, records, members and the changelog.
//! Private to the mutation module: nothing outside it can call these.

use super::Change;
use crate::model::*;
use crate::storage::{self as db};
use anyhow::Result;
use rusqlite::{params, Connection};

/// Insert a zone. `z.id == 0` allocates a new id; a non-zero id is kept
/// (replay), and replaying an existing zone overwrites it with the fact
/// (idempotent: a standby may re-apply changes from an earlier offset).
pub(super) fn insert_zone(c: &Connection, z: &Zone) -> Result<Zone> {
    c.execute(
        "INSERT INTO zones (id, name, serial, soa_mname, soa_rname, refresh, retry, expire, minimum, default_ttl, created_at, updated_at, owner_id, dnssec, signed_at, override_spec, record_policy, zone_settings, nsec3)
         VALUES (NULLIF(?1, 0), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, serial = excluded.serial, soa_mname = excluded.soa_mname,
            soa_rname = excluded.soa_rname, refresh = excluded.refresh, retry = excluded.retry, expire = excluded.expire,
            minimum = excluded.minimum, default_ttl = excluded.default_ttl, created_at = excluded.created_at,
            updated_at = excluded.updated_at, owner_id = excluded.owner_id, dnssec = excluded.dnssec,
            signed_at = excluded.signed_at, override_spec = excluded.override_spec,
            record_policy = excluded.record_policy, zone_settings = excluded.zone_settings,
            nsec3 = excluded.nsec3",
        params![
            z.id, z.name, z.serial as i64, z.soa_mname, z.soa_rname, z.refresh as i64, z.retry as i64,
            z.expire as i64, z.minimum as i64, z.default_ttl as i64, z.created_at, z.updated_at, z.owner_id,
            z.dnssec as i64, z.signed_at, override_json(z)?, policy_json(z)?, settings_json(z)?,
            nsec3_col(z)
        ],
    )?;
    let id = if z.id != 0 {
        z.id
    } else {
        c.last_insert_rowid()
    };
    Ok(db::get_zone_by_id(c, id)?.expect("zone just inserted"))
}

pub(super) fn update_zone(c: &Connection, z: &Zone) -> Result<Zone> {
    c.execute(
        "UPDATE zones SET serial=?2, soa_mname=?3, soa_rname=?4, refresh=?5, retry=?6, expire=?7, minimum=?8,
         default_ttl=?9, updated_at=?10, owner_id=?11, dnssec=?12, signed_at=?13, override_spec=?14,
         record_policy=?15, name=?16, zone_settings=?17, nsec3=?18 WHERE id = ?1",
        params![
            z.id, z.serial as i64, z.soa_mname, z.soa_rname, z.refresh as i64, z.retry as i64,
            z.expire as i64, z.minimum as i64, z.default_ttl as i64, z.updated_at, z.owner_id,
            z.dnssec as i64, z.signed_at, override_json(z)?, policy_json(z)?,
            // O11: the name too (a rename); unchanged for every other update.
            z.name,
            settings_json(z)?,
            nsec3_col(z)
        ],
    )?;
    Ok(db::get_zone_by_id(c, z.id)?.expect("zone exists"))
}

/// O24: `zones.nsec3` as stored: NULL for NSEC (every zone before O24).
fn nsec3_col(z: &Zone) -> Option<i64> {
    z.nsec3.then_some(1)
}

fn override_json(z: &Zone) -> Result<Option<String>> {
    Ok(match &z.overrides {
        Some(o) => Some(serde_json::to_string(o)?),
        None => None,
    })
}

fn policy_json(z: &Zone) -> Result<Option<String>> {
    Ok(match z.record_policy.as_ref().filter(|p| !p.is_empty()) {
        Some(p) => Some(serde_json::to_string(p)?),
        None => None,
    })
}

fn settings_json(z: &Zone) -> Result<Option<String>> {
    Ok(match z.settings.as_ref().filter(|s| !s.is_empty()) {
        Some(s) => Some(serde_json::to_string(s)?),
        None => None,
    })
}

pub(super) fn delete_zone(c: &Connection, id: i64) -> Result<()> {
    c.execute("DELETE FROM zones WHERE id = ?1", params![id])?;
    Ok(())
}

/// A serial bump: the new serial, change time and DNSSEC signing epoch
/// (`signed_at` is the whole new value: `None` clears it, which is what a
/// bump written by a version without it means: the epoch is `updated_at`).
pub(super) fn set_serial(
    c: &Connection,
    zone_id: i64,
    serial: u32,
    updated_at: &str,
    signed_at: Option<&str>,
) -> Result<()> {
    c.execute(
        "UPDATE zones SET serial = ?2, updated_at = ?3, signed_at = ?4 WHERE id = ?1",
        params![zone_id, serial as i64, updated_at, signed_at],
    )?;
    Ok(())
}

/// Insert a record. `r.id == 0` allocates a new id; a non-zero id is kept
/// (replay; an existing record is overwritten with the fact: idempotent).
pub(super) fn insert_record(c: &Connection, r: &Record) -> Result<Record> {
    c.execute(
        "INSERT INTO records (id, zone_id, name, rtype, value, ttl, created_at, updated_at, expires_at)
         VALUES (NULLIF(?1, 0), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET zone_id = excluded.zone_id, name = excluded.name, rtype = excluded.rtype,
            value = excluded.value, ttl = excluded.ttl, created_at = excluded.created_at,
            updated_at = excluded.updated_at, expires_at = excluded.expires_at",
        params![r.id, r.zone_id, r.name, r.rtype.as_str(), r.value, r.ttl.map(|t| t as i64), r.created_at, r.updated_at, r.expires_at],
    )?;
    let id = if r.id != 0 {
        r.id
    } else {
        c.last_insert_rowid()
    };
    Ok(db::get_record(c, id)?.expect("record just inserted"))
}

/// Update a record. A cleared or future expiry makes it eligible to expire again.
pub(super) fn update_record(c: &Connection, r: &Record) -> Result<Record> {
    c.execute(
        "UPDATE records SET name=?2, rtype=?3, value=?4, ttl=?5, updated_at=?6, expires_at=?7,
            expired_noted = CASE WHEN ?7 IS NULL OR ?7 > ?6 THEN 0 ELSE expired_noted END
         WHERE id = ?1",
        params![
            r.id,
            r.name,
            r.rtype.as_str(),
            r.value,
            r.ttl.map(|t| t as i64),
            r.updated_at,
            r.expires_at
        ],
    )?;
    Ok(db::get_record(c, r.id)?.expect("record exists"))
}

/// Record that an expired record has been processed (it stopped being served).
pub(super) fn mark_expired(c: &Connection, id: i64) -> Result<()> {
    c.execute(
        "UPDATE records SET expired_noted = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Records that are expired at `now` but not yet processed.
pub(super) fn due_expiries(c: &Connection, now: &str) -> Result<Vec<Record>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {} FROM records WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND expired_noted = 0 ORDER BY expires_at, id",
        db::RECORD_COLS
    ))?;
    let rows = stmt.query_map(params![now], db::row_to_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Records whose expiry is at or before `cutoff` (expiry + retention has passed).
pub(super) fn due_reaps(c: &Connection, cutoff: &str) -> Result<Vec<Record>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {} FROM records WHERE expires_at IS NOT NULL AND expires_at <= ?1 ORDER BY expires_at, id",
        db::RECORD_COLS
    ))?;
    let rows = stmt.query_map(params![cutoff], db::row_to_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub(super) fn delete_record(c: &Connection, id: i64) -> Result<()> {
    c.execute("DELETE FROM records WHERE id = ?1", params![id])?;
    Ok(())
}

pub(super) fn upsert_member(
    c: &Connection,
    zone_id: i64,
    user_id: i64,
    role: &str,
    created_at: &str,
) -> Result<()> {
    c.execute(
        "INSERT INTO zone_members (zone_id, user_id, role, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(zone_id, user_id) DO UPDATE SET role = excluded.role",
        params![zone_id, user_id, role, created_at],
    )?;
    Ok(())
}

pub(super) fn delete_member(c: &Connection, zone_id: i64, user_id: i64) -> Result<()> {
    c.execute(
        "DELETE FROM zone_members WHERE zone_id = ?1 AND user_id = ?2",
        params![zone_id, user_id],
    )?;
    Ok(())
}

/// Current changelog payload format. Rows written before the structured
/// changelog carry schema 1 and cannot be replayed.
pub(super) const CHANGELOG_SCHEMA: i64 = 2;

pub(super) fn append_changelog(
    c: &Connection,
    actor: &Actor,
    command: &str,
    txn: &str,
    change: &Change,
) -> Result<ChangeEvent> {
    let ts = now_rfc3339();
    let (action, entity, zone, entity_id) = change.meta();
    let payload = serde_json::to_value(change)?;
    c.execute(
        "INSERT INTO changelog (ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command, schema, class)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            ts,
            actor.name,
            actor.ip,
            action,
            entity,
            zone,
            entity_id,
            serde_json::to_string(&payload)?,
            txn,
            command,
            CHANGELOG_SCHEMA,
            change.class()
        ],
    )?;
    Ok(ChangeEvent {
        offset: c.last_insert_rowid(),
        ts,
        actor: actor.name.clone(),
        actor_ip: actor.ip.clone(),
        action: action.to_string(),
        entity: entity.to_string(),
        zone: zone.to_string(),
        entity_id,
        payload,
        txn: txn.to_string(),
        command: command.to_string(),
    })
}
