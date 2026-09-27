//! Reads for replication: snapshots, account data, checksums and changelog
//! batches. Pure reads over a `Connection`; callers run them inside
//! [`Storage::read_tx`](crate::storage::Storage::read_tx) so one answer is
//! one consistent state. Writes are in `mutation::replica`.

use super::types::*;
use crate::model::{ChangeEvent, RecordType, Zone};
use crate::storage as db;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

pub fn history(c: &Connection) -> Result<History> {
    let st = db::replication_state(c)?;
    let get = |k: &str| st.get(k).filter(|v| !v.is_empty()).cloned();
    Ok(History {
        history_id: get("history_id").unwrap_or_default(),
        parent_history_id: get("parent_history_id"),
        fork_offset: get("fork_offset").and_then(|v| v.parse().ok()),
        promoted_at: get("promoted_at"),
        promoted_from: get("promoted_from"),
    })
}

/// The next offset that will be assigned minus one (0 for a fresh log).
pub fn changelog_head(c: &Connection) -> Result<i64> {
    Ok(c.query_row(
        "SELECT seq FROM sqlite_sequence WHERE name = 'changelog'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .optional()?
    .unwrap_or(0))
}

pub fn changelog_oldest(c: &Connection) -> Result<Option<i64>> {
    Ok(c.query_row("SELECT MIN(offset) FROM changelog", [], |r| r.get(0))?)
}

fn row_to_change(r: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeEvent> {
    let payload: String = r.get(8)?;
    Ok(ChangeEvent {
        offset: r.get(0)?,
        ts: r.get(1)?,
        actor: r.get(2)?,
        actor_ip: r.get(3)?,
        action: r.get(4)?,
        entity: r.get(5)?,
        zone: r.get(6)?,
        entity_id: r.get(7)?,
        payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
        txn: r.get(9)?,
        command: r.get(10)?,
    })
}

const CHANGE_COLS: &str =
    "offset, ts, actor, actor_ip, action, entity, zone, entity_id, payload, txn, command";

/// Up to `limit` changes after `after`, extended to the end of the last
/// transaction so a batch never splits one (a standby applies whole
/// transactions atomically).
pub fn changes_after(c: &Connection, after: i64, limit: usize) -> Result<Vec<ChangeEvent>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {CHANGE_COLS} FROM changelog WHERE offset > ?1 ORDER BY offset ASC LIMIT ?2"
    ))?;
    let mut out: Vec<ChangeEvent> = stmt
        .query_map(params![after, limit.max(1) as i64], row_to_change)?
        .collect::<Result<_, _>>()?;
    if let Some(last) = out.last().cloned() {
        let mut more = c.prepare(&format!(
            "SELECT {CHANGE_COLS} FROM changelog WHERE offset > ?1 AND txn = ?2 ORDER BY offset ASC"
        ))?;
        let rest: Vec<ChangeEvent> = more
            .query_map(params![last.offset, last.txn], row_to_change)?
            .collect::<Result<_, _>>()?;
        // Only the contiguous continuation of that transaction.
        for (next, e) in (last.offset + 1..).zip(rest) {
            if e.offset != next {
                break;
            }
            out.push(e);
        }
    }
    Ok(out)
}

/// Every changelog row after `after` (divergence reports).
pub fn changelog_tail(c: &Connection, after: i64) -> Result<Vec<ChangeEvent>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {CHANGE_COLS} FROM changelog WHERE offset > ?1 ORDER BY offset ASC"
    ))?;
    let rows = stmt.query_map(params![after], row_to_change)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn changelog_row(c: &Connection, offset: i64) -> Result<Option<ChangeEvent>> {
    Ok(c.query_row(
        &format!("SELECT {CHANGE_COLS} FROM changelog WHERE offset = ?1"),
        params![offset],
        row_to_change,
    )
    .optional()?)
}

fn records(c: &Connection, zone_id: Option<i64>) -> Result<Vec<ReplRecord>> {
    let mut stmt = c.prepare(
        "SELECT id, zone_id, name, rtype, value, ttl, created_at, updated_at, expires_at, expired_noted
         FROM records WHERE (?1 IS NULL OR zone_id = ?1) ORDER BY id",
    )?;
    let rows = stmt.query_map(params![zone_id], |r| {
        let rtype: String = r.get(3)?;
        Ok(ReplRecord {
            id: r.get(0)?,
            zone_id: r.get(1)?,
            name: r.get(2)?,
            rtype: RecordType::parse(&rtype).unwrap_or(RecordType::TXT),
            value: r.get(4)?,
            ttl: r.get::<_, Option<i64>>(5)?.map(|t| t as u32),
            created_at: r.get(6)?,
            updated_at: r.get(7)?,
            expires_at: r.get(8)?,
            expired_noted: r.get::<_, i64>(9)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn members(c: &Connection, zone_id: Option<i64>) -> Result<Vec<ReplMember>> {
    let mut stmt = c.prepare(
        "SELECT zone_id, user_id, role, created_at FROM zone_members
         WHERE (?1 IS NULL OR zone_id = ?1) ORDER BY zone_id, user_id",
    )?;
    let rows = stmt.query_map(params![zone_id], |r| {
        Ok(ReplMember {
            zone_id: r.get(0)?,
            user_id: r.get(1)?,
            role: r.get(2)?,
            created_at: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn users(c: &Connection) -> Result<Vec<ReplUser>> {
    let mut stmt = c.prepare(
        "SELECT id, username, password_hash, display_name, is_admin, is_root, mfa_required, totp_secret,
                totp_enrolled_at, totp_last_step, disabled_at, created_at, updated_at
         FROM users ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ReplUser {
            id: r.get(0)?,
            username: r.get(1)?,
            password_hash: r.get(2)?,
            display_name: r.get(3)?,
            is_admin: r.get::<_, i64>(4)? != 0,
            is_root: r.get::<_, i64>(5)? != 0,
            mfa_required: r.get::<_, i64>(6)? != 0,
            totp_secret: r.get(7)?,
            totp_enrolled_at: r.get(8)?,
            totp_last_step: r.get(9)?,
            disabled_at: r.get(10)?,
            created_at: r.get(11)?,
            updated_at: r.get(12)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn recovery_codes(c: &Connection) -> Result<Vec<ReplRecoveryCode>> {
    let mut stmt = c.prepare(
        "SELECT user_id, code_hash, used_at FROM recovery_codes ORDER BY user_id, code_hash",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ReplRecoveryCode {
            user_id: r.get(0)?,
            code_hash: r.get(1)?,
            used_at: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn tokens(c: &Connection) -> Result<Vec<ReplToken>> {
    let mut stmt = c.prepare(
        "SELECT id, user_id, name, token_hash, created_at, revoked_at, tags FROM api_tokens ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        let tags: String = r.get(6)?;
        Ok(ReplToken {
            id: r.get(0)?,
            user_id: r.get(1)?,
            name: r.get(2)?,
            token_hash: r.get(3)?,
            created_at: r.get(4)?,
            revoked_at: r.get(5)?,
            tags: serde_json::from_str(&tags).unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn settings(c: &Connection) -> Result<Vec<ReplSetting>> {
    let mut stmt =
        c.prepare("SELECT key, value, updated_by, updated_at FROM settings ORDER BY key")?;
    let rows = stmt.query_map([], |r| {
        Ok(ReplSetting {
            key: r.get(0)?,
            value: r.get(1)?,
            updated_by: r.get(2)?,
            updated_at: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn tsig_keys(c: &Connection) -> Result<Vec<ReplTsigKey>> {
    Ok(db::list_tsig_keys(c)?
        .into_iter()
        .map(|k| ReplTsigKey {
            name: k.name,
            algorithm: k.algorithm,
            secret: data_encoding::BASE64.encode(&k.secret),
            zones: k.zones,
            created_by: k.created_by,
            created_at: k.created_at,
            updated_at: k.updated_at,
        })
        .collect())
}

fn sha256_json<T: serde::Serialize>(v: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(v)?)))
}

/// Checksum over the replicated account data, as the primary has it.
pub fn accounts_checksum(
    users: &[ReplUser],
    codes: &[ReplRecoveryCode],
    tokens: &[ReplToken],
    settings: &[ReplSetting],
    tsig: &[ReplTsigKey],
) -> Result<String> {
    sha256_json(&(users, codes, tokens, settings, tsig))
}

pub fn accounts(c: &Connection, generation: &str) -> Result<AccountsSnapshot> {
    let users = users(c)?;
    let recovery_codes = recovery_codes(c)?;
    let tokens = tokens(c)?;
    let settings = settings(c)?;
    let tsig_keys = tsig_keys(c)?;
    let checksum = accounts_checksum(&users, &recovery_codes, &tokens, &settings, &tsig_keys)?;
    Ok(AccountsSnapshot {
        users,
        recovery_codes,
        tokens,
        settings,
        tsig_keys,
        checksum,
        generation: generation.to_string(),
    })
}

pub fn snapshot(c: &Connection, generation: &str) -> Result<Snapshot> {
    Ok(Snapshot {
        format: 1,
        history: history(c)?,
        offset: changelog_head(c)?,
        taken_at: crate::model::now_rfc3339(),
        zones: db::list_zones(c)?,
        records: records(c, None)?,
        members: members(c, None)?,
        accounts: accounts(c, generation)?,
    })
}

/// Checksum of one zone: its row, its records (with expiry state) and members.
pub fn zone_checksum(c: &Connection, z: &Zone) -> Result<String> {
    sha256_json(&(z, records(c, Some(z.id))?, members(c, Some(z.id))?))
}

pub fn zone_checksums(c: &Connection) -> Result<Vec<ZoneChecksum>> {
    db::list_zones(c)?
        .iter()
        .map(|z| {
            Ok(ZoneChecksum {
                name: z.name.clone(),
                serial: z.serial,
                checksum: zone_checksum(c, z)?,
            })
        })
        .collect()
}

/// Local zones, records and members (divergence reports; no secrets).
pub fn dns_dump(c: &Connection) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "zones": db::list_zones(c)?,
        "records": records(c, None)?,
        "members": members(c, None)?,
    }))
}
