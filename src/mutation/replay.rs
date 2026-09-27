//! Rebuild DNS data from the changelog.
//!
//! Each changelog payload is the exact committed fact (ids, timestamps,
//! serials), so applying the payloads in offset order to an empty database
//! reproduces the zones, records and zone members of the source. This is the
//! basis for a follower server and is checked by the replay tests.
// Not called by the server yet: used by the tests and intended for follower mode.
#![allow(dead_code)]

use super::{sql, Change, TOKEN};
use crate::model::ChangeEvent;
use crate::storage::Storage;
use anyhow::{bail, Context, Result};
use rusqlite::Connection;

/// Apply one committed fact.
pub(super) fn apply(c: &Connection, change: &Change) -> Result<()> {
    match change {
        Change::ZoneCreated { zone } => {
            sql::insert_zone(c, zone)?;
        }
        Change::ZoneUpdated { after, .. } => {
            sql::update_zone(c, after)?;
        }
        Change::ZoneDeleted { zone } => sql::delete_zone(c, zone.id)?,
        Change::RecordCreated { record, .. } => {
            sql::insert_record(c, record)?;
        }
        Change::RecordUpdated { after, .. } => {
            sql::update_record(c, after)?;
        }
        Change::RecordDeleted { record, .. } => sql::delete_record(c, record.id)?,
        Change::RecordExpired { record, .. } => sql::mark_expired(c, record.id)?,
        Change::RecordReaped { record, .. } => sql::delete_record(c, record.id)?,
        Change::SerialBumped {
            zone_id,
            serial,
            updated_at,
            ..
        } => sql::set_serial(c, *zone_id, *serial, updated_at)?,
        Change::MemberSet {
            zone_id,
            user_id,
            role,
            created_at,
            ..
        } => sql::upsert_member(c, *zone_id, *user_id, role, created_at)?,
        Change::MemberRemoved {
            zone_id, user_id, ..
        } => sql::delete_member(c, *zone_id, *user_id)?,
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
