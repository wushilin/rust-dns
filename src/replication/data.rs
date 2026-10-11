//! Reads for replication bookkeeping and the account write path: the
//! history, the changelog head and tail (divergence reports), users and
//! TSIG rows as change payloads, freshness. Pure reads over a `Connection`;
//! callers run them inside
//! [`Storage::read_tx`](crate::storage::Storage::read_tx) so one answer is
//! one consistent state. Writes are in `mutation::replica`.

use super::types::*;
use crate::model::{ChangeEvent, RecordType};
use crate::storage as db;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

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

/// Every changelog row after `after` (divergence reports).
pub fn changelog_tail(c: &Connection, after: i64) -> Result<Vec<ChangeEvent>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {CHANGE_COLS} FROM changelog WHERE offset > ?1 ORDER BY offset ASC"
    ))?;
    let rows = stmt.query_map(params![after], row_to_change)?;
    Ok(rows.collect::<Result<_, _>>()?)
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
                totp_enrolled_at, totp_last_step, disabled_at, created_at, updated_at, password_history";

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
            password_history: r
                .get::<_, Option<String>>(13)?
                .and_then(|h| serde_json::from_str(&h).ok()),
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
