//! Every table of the schema, declared once as replicated (captured by
//! changelog v2 and copied to standbys) or local to each server. A test
//! fails when a table is not classified. The v2 capture (`cdc_tables`), the
//! freshness check and `rust-dns --prepare-standby` are driven by this list.

use anyhow::Result;
use rusqlite::{params, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Written only through the mutation module; captured by changelog v2.
    Replicated,
    /// Per-server state (sessions, logs, bookkeeping); never replicated.
    Local,
}

pub struct Table {
    pub name: &'static str,
    pub class: Class,
    /// Replicated table: columns that are per server (local bookkeeping);
    /// left out of the v2 capture.
    pub node_columns: &'static [&'static str],
    /// Rows a fresh database may still have (`?1` = the config root's name).
    pub fresh_keeps: Option<&'static str>,
    /// For messages: singular, plural.
    pub label: (&'static str, &'static str),
}

const ROOT_USER: &str = "username = ?1";
const ROOT_CODES: &str = "user_id IN (SELECT id FROM users WHERE username = ?1)";

const fn replicated(name: &'static str, label: (&'static str, &'static str)) -> Table {
    Table {
        name,
        class: Class::Replicated,
        node_columns: &[],
        fresh_keeps: None,
        label,
    }
}

const fn local(name: &'static str) -> Table {
    Table {
        name,
        class: Class::Local,
        node_columns: &[],
        fresh_keeps: None,
        label: ("", ""),
    }
}

pub const TABLES: &[Table] = &[
    replicated("zones", ("zone", "zones")),
    replicated("records", ("record", "records")),
    replicated("zone_members", ("zone member", "zone members")),
    Table {
        // is_root: the config root of each server; totp_last_step: a step
        // accepted at sign-in on this server (replay protection).
        node_columns: &["is_root", "totp_last_step"],
        fresh_keeps: Some(ROOT_USER),
        ..replicated(
            "users",
            (
                "user besides the config root",
                "users besides the config root",
            ),
        )
    },
    Table {
        // Ids are assigned locally; a code used on a server stays used there.
        node_columns: &["id", "used_at"],
        fresh_keeps: Some(ROOT_CODES),
        ..replicated("recovery_codes", ("recovery code", "recovery codes"))
    },
    Table {
        node_columns: &["last_used_at", "last_used_ip"],
        ..replicated("api_tokens", ("API token", "API tokens"))
    },
    replicated(
        "settings",
        (
            "console setting (forwarding override)",
            "console settings (forwarding override)",
        ),
    ),
    replicated("tsig_keys", ("TSIG key", "TSIG keys")),
    // Written by DnssecKeySet / DnssecKeyDeleted (account class: secrets).
    replicated("dnssec_keys", ("DNSSEC key", "DNSSEC keys")),
    // Sign-in sessions exist on the server where the user signed in.
    local("sessions"),
    // The audit trail. Captured by changelog v2 (see `cdc_tables`): a
    // standby's audit_log is a copy of its primary's.
    local("audit_log"),
    // The v1 changelog: the user-facing history (changelog page, websocket,
    // event bus). Each server writes its own; not the replication stream.
    local("changelog"),
    // v1 only (a standby's copy of the primary's DNS rows from before its
    // snapshot); no longer written, kept in the schema.
    local("changelog_history"),
    // History id, lineage and promotion records.
    local("replication_state"),
    // v1 only (the primary's list of its standbys); no longer written, kept
    // in the schema. The replica list now comes from changelog v2.
    local("replicas"),
    // O3: failed sign-in counters; each server slows down attempts made
    // against it (like sessions). Bookkeeping in storage.rs, not audited:
    // the failures themselves are (O4).
    local("login_failures"),
    // O27: the transferred data of secondary zones. Every server is a
    // secondary of the zone's primaries itself (as BIND secondaries are);
    // the zone definition replicates, its content does not.
    local("secondary_transfers"),
    // SQLite's AUTOINCREMENT counters.
    local("sqlite_sequence"),
    // A standby's own audit events (sign-ins on it); audit_log is the
    // primary's, replicated by changelog v2.
    local("audit_local"),
    // Changelog v2 (crates/sqlite-cdc): its own log, chain and position.
    // Local because it IS the replication stream (a follower stores the
    // leader's rows verbatim through its own apply path).
    local("_cdc"),
    local("_cdc_txn"),
    local("_cdc_state"),
    local("_cdc_pending"),
];

/// Tables changelog v2 captures: every replicated data table, plus the
/// audit log (the leader's audit trail; a follower's own audit events will
/// need a local table once v2 is authoritative). Per-server columns are
/// left out; a primary key column is always captured. The v1 changelog and
/// per-server bookkeeping (sessions, login failures, replica list,
/// replication state, secondary transfers) are not captured.
pub fn cdc_tables() -> Vec<sqlite_cdc::schema::TableConfig> {
    let mut v: Vec<sqlite_cdc::schema::TableConfig> = replicated_tables()
        .map(|t| {
            let exclude: Vec<&str> = t
                .node_columns
                .iter()
                .copied()
                .filter(|c| *c != "id")
                .collect();
            sqlite_cdc::schema::TableConfig::new(t.name).exclude(&exclude)
        })
        .collect();
    v.push(sqlite_cdc::schema::TableConfig::new("audit_log"));
    v
}

pub fn replicated_tables() -> impl Iterator<Item = &'static Table> {
    TABLES.iter().filter(|t| t.class == Class::Replicated)
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
                let mut stmt =
                    c.prepare(&format!("SELECT name FROM pragma_table_info('{}')", t.name))?;
                let cols: Vec<String> = stmt
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                for col in t.node_columns {
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
}
