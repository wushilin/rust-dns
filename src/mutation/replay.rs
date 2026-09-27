//! Rebuild DNS data from the changelog.
//!
//! Each changelog payload is the exact committed fact (ids, timestamps,
//! serials), so applying the payloads in offset order to an empty database
//! reproduces the zones, records and zone members of the source. This is the
//! basis for a follower server and is checked by the replay tests.
// `apply` is used by standby mode (mutation::replica) and by `AuditTx`;
// `replay` by the tests.
#![allow(dead_code)]

use super::acct_sql::{self, Ctx};
use super::{sql, Change, TOKEN};
use crate::model::ChangeEvent;
use crate::storage::Storage;
use anyhow::{bail, Context, Result};
use rusqlite::Connection;

/// Apply one committed fact. The match is exhaustive: a new kind of change
/// does not compile until it can be replayed.
pub(super) fn apply(c: &Connection, change: &Change, ctx: &Ctx) -> Result<()> {
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
        Change::UserCreated { user } | Change::UserUpdated { user } => {
            acct_sql::put_user(c, ctx, user)?
        }
        Change::UserDeleted { user_id, username } => {
            acct_sql::delete_user(c, ctx, *user_id, username)?
        }
        Change::TotpStepAccepted { user_id, step } => acct_sql::totp_step(c, ctx, *user_id, *step)?,
        Change::RecoveryCodesReplaced {
            user_id,
            code_hashes,
        } => acct_sql::recovery_codes(c, ctx, *user_id, &code_hashes.0)?,
        Change::RecoveryCodeUsed {
            user_id,
            code_hash,
            used_at,
        } => acct_sql::recovery_code_used(c, ctx, *user_id, &code_hash.0, used_at)?,
        Change::TokenCreated { token } => acct_sql::put_token(c, token)?,
        Change::TokenTagsSet { token_id, tags } => acct_sql::token_tags(c, *token_id, tags)?,
        Change::TokenRevoked {
            token_id,
            revoked_at,
        } => acct_sql::token_revoked(c, *token_id, revoked_at)?,
        Change::TsigKeySet { key } => acct_sql::put_tsig_key(c, key)?,
        Change::TsigKeyDeleted { name } => acct_sql::delete_tsig_key(c, name)?,
        Change::SettingSet { setting } => acct_sql::put_setting(c, setting)?,
        Change::SettingCleared { key } => acct_sql::delete_setting(c, key)?,
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
            apply(c, &change, &Ctx::verbatim())
                .with_context(|| format!("applying changelog offset {}", ev.offset))?;
        }
        Ok(events.len())
    })
}
