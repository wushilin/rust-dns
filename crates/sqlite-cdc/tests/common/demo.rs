//! A schema shaped like rust-dns (zones, records, users, members, settings,
//! a local sessions table) and a random workload over it, for tests and the
//! benchmark.

use rand::Rng;
use rand::rngs::StdRng;
use rusqlite::{Connection, params};

/// CDC is enabled per table; `sessions` stays local, and a user's
/// `last_login` is a per-node column.
pub fn config() -> sqlite_cdc::store::Config {
    use sqlite_cdc::schema::TableConfig;
    sqlite_cdc::store::Config::new(vec![
        TableConfig::new("zones"),
        TableConfig::new("records"),
        TableConfig::new("users").exclude(&["last_login"]),
        TableConfig::new("members"),
        TableConfig::new("settings"),
    ])
}

pub fn migrate(c: &Connection) -> anyhow::Result<()> {
    c.execute_batch(
        "
CREATE TABLE IF NOT EXISTS zones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  serial INTEGER NOT NULL,
  dnssec INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  name TEXT NOT NULL, rtype TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER,
  UNIQUE (zone_id, name, rtype, value));
CREATE INDEX IF NOT EXISTS records_zone ON records(zone_id);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pw_hash BLOB,
  weight REAL,
  last_login TEXT);
CREATE TABLE IF NOT EXISTS members (
  zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  PRIMARY KEY (zone_id, user_id));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER, seen TEXT);
",
    )?;
    Ok(())
}

fn pick(c: &Connection, sql: &str, rng: &mut StdRng) -> rusqlite::Result<Option<i64>> {
    let ids: Vec<i64> = c
        .prepare_cached(sql)?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok((!ids.is_empty()).then(|| ids[rng.random_range(0..ids.len())]))
}

/// One random operation, in the caller's transaction. Covers every op on
/// every replicated table, cascades, BLOBs, REALs and NULLs.
pub fn random_op(c: &Connection, rng: &mut StdRng) -> rusqlite::Result<()> {
    let n: u32 = rng.random_range(0..100);
    match n {
        0..=7 => {
            c.execute(
                "INSERT OR IGNORE INTO zones(name, serial) VALUES (?1, 1)",
                [format!("z{}.example", rng.random_range(0..400))],
            )?;
        }
        8..=45 => {
            if let Some(z) = pick(c, "SELECT id FROM zones", rng)? {
                let ttl: Option<i64> = rng.random_bool(0.3).then(|| rng.random_range(60..86400));
                c.execute(
                    "INSERT OR IGNORE INTO records(zone_id, name, rtype, value, ttl) VALUES (?1, ?2, 'A', ?3, ?4)",
                    params![
                        z,
                        format!("h{}", rng.random_range(0..50)),
                        format!("10.0.{}.{}", rng.random_range(0..255), rng.random_range(0..255)),
                        ttl
                    ],
                )?;
                c.execute("UPDATE zones SET serial = serial + 1 WHERE id = ?1", [z])?;
            }
        }
        46..=60 => {
            if let Some(r) = pick(c, "SELECT id FROM records", rng)? {
                c.execute(
                    "UPDATE records SET ttl = ?2, value = value || 'x' WHERE id = ?1",
                    params![r, rng.random_range(60..600)],
                )?;
            }
        }
        61..=70 => {
            if let Some(r) = pick(c, "SELECT id FROM records", rng)? {
                c.execute("DELETE FROM records WHERE id = ?1", [r])?;
            }
        }
        71..=73 => {
            // Cascades to records and members.
            if let Some(z) = pick(c, "SELECT id FROM zones", rng)? {
                c.execute("DELETE FROM zones WHERE id = ?1", [z])?;
            }
        }
        74..=80 => {
            let mut pw = vec![0u8; 32];
            rng.fill(&mut pw[..]);
            let weight: f64 = rng.random::<f64>() * 1e6 / 3.0;
            c.execute(
                "INSERT OR IGNORE INTO users(username, pw_hash, weight) VALUES (?1, ?2, ?3)",
                params![format!("u{}", rng.random_range(0..100)), pw, weight],
            )?;
        }
        81..=84 => {
            if let Some(u) = pick(c, "SELECT id FROM users", rng)? {
                let pw: Option<Vec<u8>> =
                    rng.random_bool(0.8).then(|| vec![rng.random::<u8>(); 16]);
                c.execute(
                    "UPDATE users SET pw_hash = ?2, weight = ?3 WHERE id = ?1",
                    params![u, pw, rng.random::<f64>()],
                )?;
            }
        }
        85..=86 => {
            if let Some(u) = pick(c, "SELECT id FROM users", rng)? {
                c.execute("DELETE FROM users WHERE id = ?1", [u])?;
            }
        }
        87..=92 => {
            if let (Some(z), Some(u)) = (
                pick(c, "SELECT id FROM zones", rng)?,
                pick(c, "SELECT id FROM users", rng)?,
            ) {
                c.execute(
                    "INSERT INTO members(zone_id, user_id, role) VALUES (?1, ?2, ?3)
                     ON CONFLICT(zone_id, user_id) DO UPDATE SET role = excluded.role",
                    params![
                        z,
                        u,
                        if rng.random_bool(0.5) {
                            "admin"
                        } else {
                            "editor"
                        }
                    ],
                )?;
            }
        }
        93..=94 => {
            c.execute(
                "DELETE FROM members WHERE rowid IN (SELECT rowid FROM members ORDER BY random() LIMIT 1)",
                [],
            )?;
        }
        _ => {
            c.execute(
                "INSERT INTO settings(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![
                    format!("k{}", rng.random_range(0..10)),
                    format!(
                        "{{\"v\": {}, \"s\": \"quote\\\" and unicode \u{00e9}\"}}",
                        rng.random::<u32>()
                    )
                ],
            )?;
        }
    }
    Ok(())
}
