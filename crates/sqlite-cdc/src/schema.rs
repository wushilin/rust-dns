//! Table introspection and the SQL generated from it: capture triggers, the
//! canonical row JSON, and the generic statements a follower applies.
//!
//! Everything is derived from `PRAGMA table_info`, so a new column is
//! captured and applied without hand-written code.

use anyhow::{Context, Result, bail};
use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Column {
    pub name: String,
    /// Declared BLOB: carried as hex text in JSON.
    pub blob: bool,
    /// Numeric affinity (INTEGER, REAL, NUMERIC): a REAL value is carried
    /// as a string holding its shortest exact decimal form (`_cdc_real`),
    /// because `json_object` keeps only 15 digits and SQLite's own number
    /// parsing is not exact; `_cdc_num` parses it back exactly.
    pub numeric: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TableSpec {
    pub name: String,
    pub columns: Vec<Column>,
    /// Primary key columns, in key order.
    pub pk: Vec<String>,
}

/// Internal tables of this crate. Never replicated, never captured.
pub fn is_internal(name: &str) -> bool {
    name.starts_with("_cdc") || name.starts_with("sqlite_")
}

fn check_ident(s: &str) -> Result<()> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("identifier {s:?}: only [A-Za-z0-9_] is supported");
    }
    Ok(())
}

/// A table to capture: CDC is enabled per table. `exclude` lists columns
/// that stay local to each node (a last-used timestamp, say): they are not
/// captured, not applied and not compared, and an update that touches
/// only them is not a change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TableConfig {
    pub name: String,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl TableConfig {
    pub fn new(name: &str) -> TableConfig {
        TableConfig {
            name: name.into(),
            exclude: Vec::new(),
        }
    }

    pub fn exclude(mut self, cols: &[&str]) -> TableConfig {
        self.exclude.extend(cols.iter().map(|c| c.to_string()));
        self
    }
}

/// The specs of the enabled tables, in name order. Fails on a missing
/// table, one without a declared primary key, or an excluded column that
/// does not exist or is part of the key.
pub fn introspect(conn: &Connection, enabled: &[TableConfig]) -> Result<Vec<TableSpec>> {
    let mut configs: Vec<&TableConfig> = enabled.iter().collect();
    configs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    for cfg in configs {
        let name = cfg.name.clone();
        check_ident(&name)?;
        if is_internal(&name) {
            bail!("table {name}: names starting with _cdc or sqlite_ are reserved");
        }
        let exists: bool = conn.query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [&name],
            |r| r.get(0),
        )?;
        if !exists {
            bail!("table {name} is enabled for CDC but does not exist");
        }
        let mut cols = Vec::new();
        let mut pk: Vec<(i64, String)> = Vec::new();
        let mut st = conn.prepare(&format!("PRAGMA table_info(\"{name}\")"))?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (col, ty, pk_pos) = row?;
            check_ident(&col).with_context(|| format!("table {name}"))?;
            if pk_pos > 0 {
                pk.push((pk_pos, col.clone()));
            }
            if cfg.exclude.contains(&col) {
                if pk_pos > 0 {
                    bail!("table {name}: primary key column {col} cannot be excluded");
                }
                continue;
            }
            let t = ty.to_ascii_uppercase();
            let blob = t.contains("BLOB");
            let text = t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT");
            cols.push(Column {
                numeric: !blob && !text && !t.is_empty(),
                blob,
                name: col,
            });
        }
        if pk.is_empty() {
            bail!("table {name} has no declared PRIMARY KEY; replicated tables need one");
        }
        pk.sort();
        for x in &cfg.exclude {
            if !cols.iter().any(|c: &Column| &c.name == x) && !pk.iter().any(|(_, p)| p == x) {
                let exists: bool = conn.query_row(
                    &format!(
                        "SELECT count(*) > 0 FROM pragma_table_info('{name}') WHERE name = ?1"
                    ),
                    [x],
                    |r| r.get(0),
                )?;
                if !exists {
                    bail!("table {name}: excluded column {x} does not exist");
                }
            }
        }
        out.push(TableSpec {
            name,
            columns: cols,
            pk: pk.into_iter().map(|(_, c)| c).collect(),
        });
    }
    Ok(out)
}

impl TableSpec {
    pub fn column(&self, name: &str) -> &Column {
        self.columns
            .iter()
            .find(|c| c.name == name)
            .expect("pk column exists")
    }

    fn value(c: &Column, prefix: &str) -> String {
        let r = format!("{prefix}.\"{}\"", c.name);
        if c.blob {
            format!("CASE WHEN {r} IS NULL THEN NULL ELSE hex({r}) END")
        } else if c.numeric {
            format!("CASE WHEN typeof({r}) = 'real' THEN _cdc_real({r}) ELSE {r} END")
        } else {
            r
        }
    }

    /// `json_object(...)` of the whole row, as captured and as hashed.
    pub fn row_json(&self, prefix: &str) -> String {
        let parts: Vec<String> = self
            .columns
            .iter()
            .map(|c| format!("'{}', {}", c.name, Self::value(c, prefix)))
            .collect();
        format!("json_object({})", parts.join(", "))
    }

    /// `json_object(...)` of the primary key.
    pub fn pk_json(&self, prefix: &str) -> String {
        let parts: Vec<String> = self
            .pk
            .iter()
            .map(|p| format!("'{p}', {}", Self::value(self.column(p), prefix)))
            .collect();
        format!("json_object({})", parts.join(", "))
    }

    /// Drop and recreate the three capture triggers. `temp`: TEMP triggers,
    /// which exist only on the connection that creates them and are never
    /// stored in the database file.
    pub fn trigger_sql(&self, temp: bool) -> String {
        let (kw, schema, on) = if temp {
            ("TEMP TRIGGER", "temp.", "main.")
        } else {
            ("TRIGGER", "", "")
        };
        let t = &self.name;
        let pk_new = self.pk_json("NEW");
        let pk_old = self.pk_json("OLD");
        let row_new = self.row_json("NEW");
        let row_old = self.row_json("OLD");
        let cols = self
            .columns
            .iter()
            .map(|c| format!("\"{}\"", c.name))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "DROP TRIGGER IF EXISTS {schema}\"_cdc_i_{t}\";
DROP TRIGGER IF EXISTS {schema}\"_cdc_u_{t}\";
DROP TRIGGER IF EXISTS {schema}\"_cdc_d_{t}\";
CREATE {kw} \"_cdc_i_{t}\" AFTER INSERT ON {on}\"{t}\" WHEN _cdc_capture() BEGIN
  INSERT INTO _cdc_pending(op, tbl, pk, before, after) VALUES ('I', '{t}', {pk_new}, NULL, {row_new});
END;
CREATE {kw} \"_cdc_u_{t}\" AFTER UPDATE OF {cols} ON {on}\"{t}\" WHEN {row_old} IS NOT {row_new} AND _cdc_capture() BEGIN
  SELECT RAISE(ABORT, 'cdc: primary key of {t} changed') WHERE {pk_old} IS NOT {pk_new};
  INSERT INTO _cdc_pending(op, tbl, pk, before, after) VALUES ('U', '{t}', {pk_new}, {row_old}, {row_new});
END;
CREATE {kw} \"_cdc_d_{t}\" AFTER DELETE ON {on}\"{t}\" WHEN _cdc_capture() BEGIN
  INSERT INTO _cdc_pending(op, tbl, pk, before, after) VALUES ('D', '{t}', {pk_old}, {row_old}, NULL);
END;
"
        )
    }

    fn decode(c: &Column, param: &str) -> String {
        let e = format!("json_extract({param}, '$.{}')", c.name);
        if c.blob {
            format!("unhex({e})")
        } else if c.numeric {
            format!("_cdc_num({e})")
        } else {
            e
        }
    }

    fn pk_where(&self, param: &str) -> String {
        self.pk
            .iter()
            .map(|p| format!("\"{p}\" IS {}", Self::decode(self.column(p), param)))
            .collect::<Vec<_>>()
            .join(" AND ")
    }

    /// `?1` = row JSON.
    pub fn insert_sql(&self) -> String {
        let cols: Vec<String> = self
            .columns
            .iter()
            .map(|c| format!("\"{}\"", c.name))
            .collect();
        let vals: Vec<String> = self.columns.iter().map(|c| Self::decode(c, "?1")).collect();
        format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            self.name,
            cols.join(", "),
            vals.join(", ")
        )
    }

    /// `?1` = new row JSON, `?2` = primary key JSON.
    pub fn update_sql(&self) -> String {
        let sets: Vec<String> = self
            .columns
            .iter()
            .map(|c| format!("\"{}\" = {}", c.name, Self::decode(c, "?1")))
            .collect();
        format!(
            "UPDATE \"{}\" SET {} WHERE {}",
            self.name,
            sets.join(", "),
            self.pk_where("?2")
        )
    }

    /// `?1` = primary key JSON.
    pub fn delete_sql(&self) -> String {
        format!(
            "DELETE FROM \"{}\" WHERE {}",
            self.name,
            self.pk_where("?1")
        )
    }

    /// `SELECT pk_json, row_json FROM t ORDER BY pk`.
    pub fn scan_sql(&self) -> String {
        let order: Vec<String> = self.pk.iter().map(|p| format!("t0.\"{p}\"")).collect();
        format!(
            "SELECT {}, {} FROM \"{}\" AS t0 ORDER BY {}",
            self.pk_json("t0"),
            self.row_json("t0"),
            self.name,
            order.join(", ")
        )
    }
}

/// Create tables for a follower that has no schema of its own, from the
/// leader's specs (`GET <api>/schema`): declared types that reproduce the
/// same specs (BLOB, INTEGER for numeric affinity, TEXT otherwise) and the
/// primary key. Excluded (per-node) columns are not part of a spec, so
/// such a follower does not have them. Existing tables are left alone.
pub fn create_tables(conn: &Connection, specs: &[TableSpec]) -> Result<()> {
    for t in specs {
        check_ident(&t.name)?;
        let cols: Vec<String> = t
            .columns
            .iter()
            .map(|c| {
                let ty = if c.blob {
                    "BLOB"
                } else if c.numeric {
                    "INTEGER"
                } else {
                    "TEXT"
                };
                format!("\"{}\" {ty}", c.name)
            })
            .collect();
        let pk: Vec<String> = t.pk.iter().map(|p| format!("\"{p}\"")).collect();
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS \"{}\" ({}, PRIMARY KEY ({}))",
            t.name,
            cols.join(", "),
            pk.join(", ")
        ))?;
    }
    Ok(())
}
