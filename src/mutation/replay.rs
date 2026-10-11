//! Rebuild DNS data from the changelog.
//!
//! Each changelog payload is the exact committed fact (ids, timestamps,
//! serials), so applying the payloads in offset order to an empty database
//! reproduces the zones, records and zone members of the source. This is the
//! user-facing changelog's accuracy check: the replay tests compare a
//! database with its replay. (Replication itself is changelog v2.)

use super::acct_sql;
use super::{sql, Change, DnsChange, TOKEN};
use crate::model::ChangeEvent;
use crate::storage::Storage;
use anyhow::{bail, Context, Result};
use rusqlite::Connection;

/// Apply one committed fact. The match is exhaustive: a new kind of change
/// does not compile until it can be replayed.
pub(super) fn apply(c: &Connection, change: &Change) -> Result<()> {
    match change {
        Change::Dns(d) => apply_dns(c, d)?,
        // Account class: one entry point, which hands back a receipt; this
        // is a replay.
        Change::Secret(s) => acct_sql::write(c, s)?.replayed(),
    }
    Ok(())
}

fn apply_dns(c: &Connection, change: &DnsChange) -> Result<()> {
    match change {
        DnsChange::ZoneCreated { zone } => {
            sql::insert_zone(c, zone)?;
        }
        DnsChange::ZoneUpdated { after, .. } => {
            sql::update_zone(c, after)?;
        }
        DnsChange::ZoneDeleted { zone } => sql::delete_zone(c, zone.id)?,
        DnsChange::RecordCreated { record, .. } => {
            sql::insert_record(c, record)?;
        }
        DnsChange::RecordUpdated { after, .. } => {
            sql::update_record(c, after)?;
        }
        DnsChange::RecordDeleted { record, .. } => sql::delete_record(c, record.id)?,
        DnsChange::RecordExpired { record, .. } => sql::mark_expired(c, record.id)?,
        DnsChange::RecordReaped { record, .. } => sql::delete_record(c, record.id)?,
        DnsChange::SerialBumped {
            zone_id,
            serial,
            updated_at,
            signed_at,
            ..
        } => sql::set_serial(c, *zone_id, *serial, updated_at, signed_at.as_deref())?,
        DnsChange::MemberSet {
            zone_id,
            user_id,
            role,
            created_at,
            ..
        } => sql::upsert_member(c, *zone_id, *user_id, role, created_at)?,
        DnsChange::MemberRemoved {
            zone_id, user_id, ..
        } => sql::delete_member(c, *zone_id, *user_id)?,
        // The serial bump that goes with it is its own change.
        DnsChange::ZoneResigned { .. } => {}
    }
    Ok(())
}

/// Apply changelog events (in offset order) to `target` in one transaction.
/// Fails without writing anything if any event predates the structured
/// changelog or does not apply cleanly.
pub fn replay(target: &Storage, events: &[ChangeEvent]) -> Result<usize> {
    target.write(&TOKEN, |c| -> Result<usize> {
        let mut last = 0;
        for ev in events {
            if ev.offset <= last {
                bail!(
                    "changelog offsets must be increasing (offset {} after {})",
                    ev.offset,
                    last
                );
            }
            last = ev.offset;
            let change: Change = serde_json::from_value(ev.payload.clone()).with_context(|| {
                format!(
                    "changelog offset {} is not a structured change (written by an older version?)",
                    ev.offset
                )
            })?;
            apply(c, &change)
                .with_context(|| format!("applying changelog offset {}", ev.offset))?;
        }
        Ok(events.len())
    })
}
