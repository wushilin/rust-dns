//! Every table of the schema, declared once as replicated (its writes are
//! changelog changes that a standby replays) or local to each server. A test
//! fails when a table is not classified. The freshness check, `rust-dns
//! --prepare-standby` and the reconcile checksums are driven by this list.

use anyhow::Result;
use rusqlite::{params, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Written only through `Change`s (and the snapshot loader).
    Replicated,
    /// Per-server state (sessions, logs, bookkeeping); never replicated.
    Local,
}

pub struct Table {
    pub name: &'static str,
    pub class: Class,
    /// Replicated table: columns that are per server (local bookkeeping, or
    /// merged with local state on a standby); left out of checksums.
    pub node_columns: &'static [&'static str],
    /// Replicated columns left out of the table checksum because another
    /// checksum covers them (the per-zone checksum) and older versions do
    /// not have them (a mixed-version primary/standby pair keeps matching).
    pub compat_columns: &'static [&'static str],
    /// Replicated columns newer versions added, in the table checksum only
    /// where not NULL: a version without the column computes the same
    /// checksum while every value is NULL, and a row that uses it differs
    /// there (an older peer cannot represent it: it halts, see plan.md).
    pub optional_columns: &'static [&'static str],
    /// Rows a fresh database may still have (`?1` = the config root's name).
    pub fresh_keeps: Option<&'static str>,
    /// Rows of the server's own root account, which is local on a standby
    /// (`?1` = the config root's name); left out of checksums.
    pub own_root_rows: Option<&'static str>,
    /// Stable row order for dumps.
    pub order: &'static str,
    /// For messages: singular, plural.
    pub label: (&'static str, &'static str),
}

const ROOT_USER: &str = "username = ?1";
const ROOT_CODES: &str = "user_id IN (SELECT id FROM users WHERE username = ?1)";

const fn replicated(
    name: &'static str,
    order: &'static str,
    label: (&'static str, &'static str),
) -> Table {
    Table {
        name,
        class: Class::Replicated,
        node_columns: &[],
        compat_columns: &[],
        optional_columns: &[],
        fresh_keeps: None,
        own_root_rows: None,
        order,
        label,
    }
}

const fn local(name: &'static str) -> Table {
    Table {
        name,
        class: Class::Local,
        node_columns: &[],
        compat_columns: &[],
        optional_columns: &[],
        fresh_keeps: None,
        own_root_rows: None,
        order: "rowid",
        label: ("", ""),
    }
}

pub const TABLES: &[Table] = &[
    Table {
        // `dnssec` (added with DNSSEC signing) is covered by the per-zone
        // checksum (the zone row as JSON, where it appears only when on).
        // `signed_at` (the signing epoch) is in no checksum: it only picks
        // the signature window, every server signs for itself, and a
        // standby whose value lags (changes applied by a version without
        // the column) converges at the zone's next serial bump. Comparing
        // it would halt such a standby in a mixed-version pair.
        // `override_spec` (I1, override zones) is covered by the per-zone
        // checksum (the zone row as JSON, where `override` appears only for
        // an override zone), so a version without the column computes the
        // same table checksum while no override zone exists.
        // `record_policy` (M2) likewise: in the zone row JSON only when set.
        compat_columns: &["dnssec", "signed_at", "override_spec", "record_policy"],
        ..replicated("zones", "id", ("zone", "zones"))
    },
    replicated("records", "id", ("record", "records")),
    replicated(
        "zone_members",
        "zone_id, user_id",
        ("zone member", "zone members"),
    ),
    Table {
        // is_root: only the local root is root on a standby; totp_last_step:
        // a later step accepted on the standby is kept (replay protection).
        node_columns: &["is_root", "totp_last_step"],
        fresh_keeps: Some(ROOT_USER),
        own_root_rows: Some(ROOT_USER),
        ..replicated(
            "users",
            "id",
            (
                "user besides the config root",
                "users besides the config root",
            ),
        )
    },
    Table {
        // Ids are assigned locally; a code used on the standby stays used.
        node_columns: &["id", "used_at"],
        fresh_keeps: Some(ROOT_CODES),
        own_root_rows: Some(ROOT_CODES),
        ..replicated(
            "recovery_codes",
            "user_id, code_hash",
            ("recovery code", "recovery codes"),
        )
    },
    Table {
        node_columns: &["last_used_at", "last_used_ip"],
        // M1: `scope` NULL = unrestricted (every token before M1).
        optional_columns: &["scope"],
        ..replicated("api_tokens", "id", ("API token", "API tokens"))
    },
    replicated(
        "settings",
        "key",
        (
            "console setting (forwarding override)",
            "console settings (forwarding override)",
        ),
    ),
    replicated("tsig_keys", "name", ("TSIG key", "TSIG keys")),
    // Written by DnssecKeySet / DnssecKeyDeleted (account class: secrets).
    replicated("dnssec_keys", "zone_id", ("DNSSEC key", "DNSSEC keys")),
    // Sign-in sessions exist on the server where the user signed in.
    local("sessions"),
    // Each server audits its own actions.
    local("audit_log"),
    // The stream itself: copied row by row with the primary's offsets.
    local("changelog"),
    // A standby's copy of the primary's DNS rows from before its snapshot
    // (display only).
    local("changelog_history"),
    // History id, lineage and standby bookkeeping.
    local("replication_state"),
    // Primary side: the standbys that follow this server.
    local("replicas"),
    // SQLite's AUTOINCREMENT counters.
    local("sqlite_sequence"),
];

pub fn replicated_tables() -> impl Iterator<Item = &'static Table> {
    TABLES.iter().filter(|t| t.class == Class::Replicated)
}

fn columns(c: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = c.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Every row of `t` as JSON arrays of its columns (minus `exclude`),
/// optionally without the rows of the root account named `skip_root`.
pub fn dump(
    c: &Connection,
    t: &Table,
    exclude: &[&str],
    skip_root: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let cols: Vec<String> = columns(c, t.name)?
        .into_iter()
        .filter(|col| !exclude.contains(&col.as_str()))
        .collect();
    let filter = match (skip_root, t.own_root_rows) {
        (Some(_), Some(cond)) => format!("WHERE NOT ({cond})"),
        _ => "WHERE ?1 IS NULL OR ?1 IS NOT NULL".into(),
    };
    let sql = format!(
        "SELECT {} FROM {} {filter} ORDER BY {}",
        cols.join(", "),
        t.name,
        t.order
    );
    let mut stmt = c.prepare(&sql)?;
    let n = cols.len();
    let optional: Vec<bool> = cols
        .iter()
        .map(|c| t.optional_columns.contains(&c.as_str()))
        .collect();
    let rows = stmt.query_map(params![skip_root], |r| {
        let mut v = Vec::with_capacity(n);
        for (i, &opt) in optional.iter().enumerate() {
            let value = r.get_ref(i)?;
            if opt && value == rusqlite::types::ValueRef::Null {
                continue;
            }
            v.push(match value {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(x) => x.into(),
                rusqlite::types::ValueRef::Real(x) => x.into(),
                rusqlite::types::ValueRef::Text(x) => {
                    String::from_utf8_lossy(x).into_owned().into()
                }
                rusqlite::types::ValueRef::Blob(x) => hex::encode(x).into(),
            });
        }
        Ok(serde_json::Value::Array(v))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Checksums of every replicated table as both sides compare them: node
/// columns and the rows of the root account named `root` left out.
pub fn checksums(c: &Connection, root: &str) -> Result<Vec<super::types::TableChecksum>> {
    replicated_tables()
        .map(|t| {
            let exclude: Vec<&str> = t
                .node_columns
                .iter()
                .chain(t.compat_columns)
                .copied()
                .collect();
            let rows = dump(c, t, &exclude, Some(root))?;
            Ok(super::types::TableChecksum {
                table: t.name.to_string(),
                rows: rows.len() as i64,
                checksum: super::data::sha256_json(&rows)?,
            })
        })
        .collect()
}

/// Rows that make the database not fresh, per replicated table.
pub fn not_fresh(c: &Connection, root: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for t in replicated_tables() {
        let cond = t
            .fresh_keeps
            .map(|k| format!("WHERE NOT ({k})"))
            .unwrap_or_else(|| "WHERE ?1 IS NULL OR ?1 IS NOT NULL".into());
        let n: i64 = c.query_row(
            &format!("SELECT COUNT(*) FROM {} {cond}", t.name),
            params![root],
            |r| r.get(0),
        )?;
        // Recovery codes belong to users, which are listed already.
        if n > 0 && t.name != "recovery_codes" {
            out.push(format!(
                "{n} {}",
                if n == 1 { t.label.0 } else { t.label.1 }
            ));
        }
    }
    Ok(out)
}

/// `--prepare-standby`: delete every replicated row a fresh database may
/// not have. (Local tables are handled by the caller.)
pub(crate) fn delete_replicated(c: &Connection, root: &str) -> Result<()> {
    for t in replicated_tables() {
        let cond = t
            .fresh_keeps
            .map(|k| format!("WHERE NOT ({k})"))
            .unwrap_or_else(|| "WHERE ?1 IS NULL OR ?1 IS NOT NULL".into());
        c.execute(&format!("DELETE FROM {} {cond}", t.name), params![root])?;
    }
    Ok(())
}

/// Snapshot load: delete every replicated row except users (kept so their
/// sessions survive; the loader deletes the ones the primary lacks) and the
/// local root's recovery codes.
pub(crate) fn delete_for_snapshot(c: &Connection, root: &str) -> Result<()> {
    for t in replicated_tables().filter(|t| t.name != "users") {
        let cond = t
            .own_root_rows
            .map(|k| format!("WHERE NOT ({k})"))
            .unwrap_or_else(|| "WHERE ?1 IS NULL OR ?1 IS NOT NULL".into());
        c.execute(&format!("DELETE FROM {} {cond}", t.name), params![root])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    /// A new table (or column name typo) must be classified here.
    #[test]
    fn every_table_is_classified() {
        let s = Storage::open_memory().unwrap();
        s.read_tx(|c| {
            let mut stmt =
                c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let names: Vec<String> = stmt
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for n in &names {
                assert!(
                    TABLES.iter().any(|t| t.name == n),
                    "table {n} is not classified in replication::tables::TABLES"
                );
            }
            for t in TABLES {
                assert!(
                    names.iter().any(|n| n == t.name),
                    "{} does not exist",
                    t.name
                );
                let cols = columns(c, t.name)?;
                for col in t
                    .node_columns
                    .iter()
                    .chain(t.compat_columns)
                    .chain(t.optional_columns)
                {
                    assert!(
                        cols.iter().any(|x| x == col),
                        "{}.{col} does not exist",
                        t.name
                    );
                }
            }
            Ok(())
        })
        .unwrap();
    }

    /// M1: `api_tokens.scope` is in the table checksum only where set, so
    /// a version without the column (d32d67f, 3884ba8) computes the same
    /// checksum while no token is scoped, and a scoped token differs (an
    /// older standby cannot enforce it: it must halt, not serve it unscoped).
    #[test]
    fn a_scope_column_matches_older_versions_until_used() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, token_hash TEXT,
                created_at TEXT, last_used_at TEXT, revoked_at TEXT, last_used_ip TEXT, tags TEXT);
             INSERT INTO api_tokens VALUES (1, 1, 'a', 'h1', 't', 'u', NULL, '1.2.3.4', '[]');
             INSERT INTO api_tokens VALUES (2, 1, 'b', 'h2', 't', NULL, 't2', NULL, '[\"x\"]');",
        )
        .unwrap();
        let t = TABLES.iter().find(|t| t.name == "api_tokens").unwrap();
        let sum = |c: &Connection| {
            let exclude: Vec<&str> = t.node_columns.to_vec();
            super::super::data::sha256_json(&dump(c, t, &exclude, None).unwrap()).unwrap()
        };
        let old = sum(&c);
        c.execute_batch("ALTER TABLE api_tokens ADD COLUMN scope TEXT")
            .unwrap();
        assert_eq!(sum(&c), old, "unscoped tokens: same as without the column");
        c.execute(
            "UPDATE api_tokens SET scope = ?1 WHERE id = 2",
            params![r#"{"max_role":"viewer"}"#],
        )
        .unwrap();
        assert_ne!(sum(&c), old, "a scoped token is compared");
    }
}
