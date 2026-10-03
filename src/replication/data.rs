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

const USER_COLS: &str =
    "id, username, password_hash, display_name, is_admin, is_root, mfa_required, totp_secret,
                totp_enrolled_at, totp_last_step, disabled_at, created_at, updated_at";

/// One user, every column (None when absent).
pub fn user_row(c: &Connection, id: i64) -> Result<Option<ReplUser>> {
    Ok(users_where(c, "WHERE id = ?1", params![id])?
        .into_iter()
        .next())
}

pub fn user_by_name(c: &Connection, name: &str) -> Result<Option<ReplUser>> {
    Ok(users_where(c, "WHERE username = ?1", params![name])?
        .into_iter()
        .next())
}

pub fn users(c: &Connection) -> Result<Vec<ReplUser>> {
    users_where(c, "", params![])
}

fn users_where(c: &Connection, filter: &str, p: &[&dyn rusqlite::ToSql]) -> Result<Vec<ReplUser>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {USER_COLS} FROM users {filter} ORDER BY id"
    ))?;
    let rows = stmt.query_map(p, |r| {
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
    tokens_where(c, "", params![])
}

fn tokens_where(
    c: &Connection,
    filter: &str,
    p: &[&dyn rusqlite::ToSql],
) -> Result<Vec<ReplToken>> {
    let mut stmt = c.prepare(&format!(
        "SELECT id, user_id, name, token_hash, created_at, revoked_at, tags FROM api_tokens {filter} ORDER BY id"
    ))?;
    let rows = stmt.query_map(p, |r| {
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

pub fn tsig_row(k: crate::storage::StoredTsigKey) -> ReplTsigKey {
    ReplTsigKey {
        name: k.name,
        algorithm: k.algorithm,
        secret: data_encoding::BASE64.encode(&k.secret),
        zones: k.zones,
        created_by: k.created_by,
        created_at: k.created_at,
        updated_at: k.updated_at,
    }
}

pub fn tsig_keys(c: &Connection) -> Result<Vec<ReplTsigKey>> {
    Ok(db::list_tsig_keys(c)?.into_iter().map(tsig_row).collect())
}

pub(crate) fn sha256_json<T: serde::Serialize>(v: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(v)?)))
}

/// Everything replicated as logical entities (see [`Snapshot`]).
pub fn snapshot(c: &Connection) -> Result<Snapshot> {
    use crate::mutation::Change;
    let mut e = Vec::new();
    for u in users(c)? {
        e.push(Change::UserCreated { user: u });
    }
    let codes = recovery_codes(c)?;
    let mut by_user: std::collections::BTreeMap<i64, Vec<String>> = Default::default();
    for rc in &codes {
        by_user
            .entry(rc.user_id)
            .or_default()
            .push(rc.code_hash.clone());
    }
    for (user_id, hashes) in by_user {
        e.push(Change::RecoveryCodesReplaced {
            user_id,
            code_hashes: Hidden(hashes),
        });
    }
    for rc in codes {
        if let Some(used_at) = rc.used_at {
            e.push(Change::RecoveryCodeUsed {
                user_id: rc.user_id,
                code_hash: Hidden(rc.code_hash),
                used_at,
            });
        }
    }
    for t in tokens(c)? {
        e.push(Change::TokenCreated { token: t });
    }
    for st in settings(c)? {
        e.push(Change::SettingSet { setting: st });
    }
    for k in tsig_keys(c)? {
        e.push(Change::TsigKeySet { key: k });
    }
    let zones = db::list_zones(c)?;
    let names: std::collections::HashMap<i64, String> =
        zones.iter().map(|z| (z.id, z.name.clone())).collect();
    for z in zones {
        e.push(Change::ZoneCreated { zone: z });
    }
    for k in db::list_dnssec_keys(c)? {
        e.push(Change::DnssecKeySet { key: k });
    }
    for r in records(c, None)? {
        let zone = names.get(&r.zone_id).cloned().unwrap_or_default();
        let record = crate::model::Record {
            id: r.id,
            zone_id: r.zone_id,
            name: r.name,
            rtype: r.rtype,
            value: r.value,
            ttl: r.ttl,
            created_at: r.created_at,
            updated_at: r.updated_at,
            expires_at: r.expires_at,
        };
        let expired = r.expired_noted;
        e.push(Change::RecordCreated {
            zone: zone.clone(),
            record: record.clone(),
        });
        if expired {
            e.push(Change::RecordExpired { zone, record });
        }
    }
    let usernames: std::collections::HashMap<i64, String> =
        users(c)?.into_iter().map(|u| (u.id, u.username)).collect();
    for m in members(c, None)? {
        e.push(Change::MemberSet {
            zone: names.get(&m.zone_id).cloned().unwrap_or_default(),
            zone_id: m.zone_id,
            user_id: m.user_id,
            username: usernames.get(&m.user_id).cloned().unwrap_or_default(),
            role: m.role,
            previous: None,
            created_at: m.created_at,
        });
    }
    Ok(Snapshot {
        format: REPLICATION_PROTOCOL,
        history: history(c)?,
        offset: changelog_head(c)?,
        taken_at: crate::model::now_rfc3339(),
        entities: e,
    })
}

/// Checksum of one zone: its row, its records (with expiry state) and members.
///
/// Without `signed_at` (see `tables::TABLES`): the checksum is the same as
/// the one a version without that column computes.
pub fn zone_checksum(c: &Connection, z: &Zone) -> Result<String> {
    let row = Zone {
        signed_at: None,
        ..z.clone()
    };
    sha256_json(&(&row, records(c, Some(z.id))?, members(c, Some(z.id))?))
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

/// What makes this database not fresh, for a standby that would load a
/// snapshot over it: zones, records, zone members, TSIG keys, console
/// settings (the forwarding override), API tokens, and users other than the
/// local config root `root_username`. Empty = fresh: following cannot lose
/// anything. (Sessions, the audit log and the changelog sequence do not
/// count: they are local history, not data a snapshot would replace.)
pub fn fresh_problems(c: &Connection, root_username: &str) -> Result<Vec<String>> {
    super::tables::not_fresh(c, root_username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    fn exec(s: &Storage, sql: &str) {
        s.exec_raw(sql).unwrap();
    }

    /// D1: `signed_at` is in no checksum, so a pair of servers of which
    /// only one knows the column keeps matching (a mismatch halts a
    /// standby). The value below is what a version without the column
    /// computes for the same zone.
    #[test]
    fn checksums_do_not_cover_the_signing_epoch() {
        let s = Storage::open_memory().unwrap();
        exec(
            &s,
            "INSERT INTO zones (id, name, soa_mname, soa_rname, created_at, updated_at, dnssec)
             VALUES (1, 'a.test', 'n.', 'h.', 't', 'u', 1);
             INSERT INTO records (zone_id, name, rtype, value, created_at, updated_at) VALUES (1,'www','A','192.0.2.1','t','t');",
        );
        let sums = |s: &Storage| {
            s.read_tx(|c| {
                Ok((
                    zone_checksums(c)?[0].checksum.clone(),
                    crate::replication::tables::checksums(c, "root")?
                        .into_iter()
                        .find(|t| t.table == "zones")
                        .unwrap()
                        .checksum,
                ))
            })
            .unwrap()
        };
        let before = sums(&s);
        // The zone row exactly as the previous version serialized it.
        let legacy_zone = serde_json::json!({
            "id": 1, "name": "a.test", "serial": 1, "soa_mname": "n.", "soa_rname": "h.",
            "refresh": 3600, "retry": 600, "expire": 1209600, "minimum": 300, "default_ttl": 300,
            "created_at": "t", "updated_at": "u", "owner_id": null, "dnssec": true
        });
        let z = s.get_zone("a.test").unwrap().unwrap();
        assert_eq!(serde_json::to_value(&z).unwrap(), legacy_zone);
        exec(
            &s,
            "UPDATE zones SET signed_at = '2026-10-01T00:00:00.000Z'",
        );
        assert!(s.get_zone("a.test").unwrap().unwrap().signed_at.is_some());
        assert_eq!(sums(&s), before);
    }

    #[test]
    fn freshness_counts_every_kind_of_replicated_data() {
        let s = Storage::open_memory().unwrap();
        let fresh = |s: &Storage| s.read_tx(|c| fresh_problems(c, "root")).unwrap();
        assert!(fresh(&s).is_empty(), "a new database is fresh");
        // The config root, sessions, audit rows and an old changelog sequence do not count.
        exec(
            &s,
            "INSERT INTO users (username, password_hash, is_admin, is_root, created_at, updated_at) VALUES ('root','h',1,1,'t','t');
             INSERT INTO sessions (token_hash, user_id, ip, created_at, expires_at, last_seen_at) VALUES ('s',1,'ip','t','t','t');
             INSERT INTO audit_log (ts, txn, operation, actor, actor_ip, action, target, detail) VALUES ('t','x','o','a','i','x','t','{}');
             INSERT INTO sqlite_sequence (name, seq) VALUES ('changelog', 40);",
        );
        assert!(fresh(&s).is_empty(), "{:?}", fresh(&s));
        let steps = [
            ("INSERT INTO users (username, password_hash, created_at, updated_at) VALUES ('bob','h','t','t')", "1 user besides the config root"),
            ("INSERT INTO api_tokens (user_id, name, token_hash, created_at) VALUES (1,'t','th','t')", "1 API token"),
            ("INSERT INTO settings (key, value, updated_by, updated_at) VALUES ('forwarding','{}','a','t')", "1 console setting (forwarding override)"),
            ("INSERT INTO tsig_keys (name, algorithm, secret, created_by, created_at, updated_at) VALUES ('k.','hmac-sha256',x'00','a','t','t')", "1 TSIG key"),
            ("INSERT INTO zones (name, soa_mname, soa_rname, created_at, updated_at) VALUES ('a.test','n.','h.','t','t')", "1 zone"),
            ("INSERT INTO records (zone_id, name, rtype, value, created_at, updated_at) VALUES (1,'www','A','192.0.2.1','t','t')", "1 record"),
            ("INSERT INTO zone_members (zone_id, user_id, role, created_at) VALUES (1,2,'viewer','t')", "1 zone member"),
        ];
        for (sql, what) in steps {
            exec(&s, sql);
            assert!(
                fresh(&s).contains(&what.to_string()),
                "{what}: {:?}",
                fresh(&s)
            );
        }
        assert_eq!(fresh(&s).len(), 7, "{:?}", fresh(&s));
        // Under another root name, 'root' itself is a foreign user.
        let other = s.read_tx(|c| fresh_problems(c, "admin")).unwrap();
        assert!(other.contains(&"2 users besides the config root".to_string()));
    }
}
