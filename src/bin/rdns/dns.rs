//! `rdns dns`: records, addressed by their full name. The zone is the
//! longest zone you can see that contains the name (or `-z ZONE`, with the
//! name relative to it).

use crate::api::{query, seg};
use crate::{term, Ctx};
use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List records: a whole zone, one name, or a search across zones.
    ///
    /// `rdns dns ls` lists records in every zone you can see;
    /// `rdns dns ls example.com` the zone; `rdns dns ls www.example.com`
    /// that name. Anything that is not in one of your zones is searched for
    /// (name, type and value), e.g. `rdns dns ls 192.0.2`.
    #[command(visible_alias = "ls")]
    List {
        /// A zone, a name, or search text.
        target: Option<String>,
        /// Only records of this type.
        #[arg(short = 't', long = "type")]
        rtype: Option<String>,
        /// Only records whose name, type or value contains this text.
        #[arg(short, long)]
        query: Option<String>,
        /// The zone (the name is then relative to it).
        #[arg(short, long)]
        zone: Option<String>,
    },
    /// Add a record; other records at the name stay.
    ///
    /// The value is the rest of the line, in zone-file form:
    /// `rdns dns add example.com MX 10 mail.example.com.`;
    /// quote values that contain `;` or start with `-`, e.g. TXT.
    #[command(visible_alias = "create")]
    Add {
        /// Full name (`www.example.com`), or relative with `-z`; `@` is the apex.
        name: String,
        /// Record type: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS, PTR, ...
        rtype: String,
        /// The value (several words are joined with spaces).
        #[arg(required = true, num_args = 1..)]
        value: Vec<String>,
        /// TTL in seconds (default: the zone's).
        #[arg(long)]
        ttl: Option<u32>,
        /// Stop serving the record after this long (e.g. 24h, 7d), unless
        /// added again before; adding it again renews it.
        #[arg(long, value_name = "DURATION")]
        expires: Option<String>,
        #[arg(short, long)]
        zone: Option<String>,
    },
    /// Replace every record of a type at a name with one value, in one
    /// transaction; without a value, only change their TTL.
    #[command(visible_alias = "replace")]
    Set {
        name: String,
        rtype: String,
        /// The new value; leave out to keep the values and change `--ttl`.
        value: Vec<String>,
        /// TTL in seconds, or `default` for the zone's (default: unchanged).
        #[arg(long)]
        ttl: Option<String>,
        #[arg(short, long)]
        zone: Option<String>,
    },
    /// Delete records: all at a name, all of one type there, or one value.
    ///
    /// `rdns dns rm www.example.com A 192.0.2.10` deletes one record;
    /// leaving out the value or the type deletes more (asks first when more
    /// than one record matches).
    #[command(
        visible_alias = "del",
        visible_alias = "delete",
        visible_alias = "remove"
    )]
    Rm {
        #[arg(required_unless_present = "id")]
        name: Option<String>,
        rtype: Option<String>,
        value: Vec<String>,
        /// Delete the record with this id (with `-z`).
        #[arg(long, requires = "zone", conflicts_with_all = ["name", "rtype", "value"])]
        id: Option<i64>,
        #[arg(short, long)]
        zone: Option<String>,
        /// Do not ask.
        #[arg(short, long)]
        yes: bool,
    },
    /// Add many records to a zone in one transaction, from zone-file lines
    /// (`name [ttl] [IN] type value`, `@` for the apex, names relative).
    Apply {
        zone: String,
        /// The file of lines; `-` or nothing reads stdin.
        file: Option<String>,
        /// Only check: show what would be added, change nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

/// A zone the caller can see.
#[derive(Debug, Clone)]
pub struct ZoneInfo {
    pub name: String,
    pub default_ttl: u64,
}

pub async fn zones(ctx: &Ctx) -> Result<Vec<ZoneInfo>> {
    let v = ctx.api.get("/zones").await?;
    Ok(v["zones"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|z| ZoneInfo {
                    name: z["name"].as_str().unwrap_or_default().to_string(),
                    default_ttl: z["default_ttl"].as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Lower case, IDNA (A-labels), no trailing dot; `.` and `@` stay.
pub fn normalize_name(s: &str) -> Result<String> {
    let t = s.trim();
    if t == "." || t == "@" {
        return Ok(t.to_string());
    }
    let t = t.trim_end_matches('.');
    if t.is_empty() {
        bail!("empty name");
    }
    if t.is_ascii() {
        return Ok(t.to_ascii_lowercase());
    }
    idna::domain_to_ascii(t).map_err(|_| anyhow!("'{s}' is not a valid domain name"))
}

fn in_zone(name: &str, zone: &str) -> bool {
    zone == "." || name == zone || name.ends_with(&format!(".{zone}"))
}

fn relative(name: &str, zone: &str) -> String {
    if name == zone {
        "@".into()
    } else if zone == "." {
        name.to_string()
    } else {
        name[..name.len() - zone.len() - 1].to_string()
    }
}

/// The zone and relative name a name means.
pub fn locate(zones: &[ZoneInfo], name: &str, zone: Option<&str>) -> Result<(ZoneInfo, String)> {
    if let Some(z) = zone {
        let zn = normalize_name(z)?;
        let zi = zones
            .iter()
            .find(|x| x.name == zn)
            .cloned()
            .ok_or_else(|| anyhow!("zone '{zn}' not found (or not visible to you)"))?;
        let absolute = name.trim().ends_with('.') && name.trim() != ".";
        let n = normalize_name(name)?;
        // `www`, `www.example.com` and `www.example.com.` all name the
        // same record; a name with a trailing dot must be in the zone.
        let rel = if n == "@" {
            n
        } else if absolute {
            if !in_zone(&n, &zi.name) {
                bail!("{n} is not in zone {}", zi.name);
            }
            relative(&n, &zi.name)
        } else if n == zi.name || (zi.name != "." && n.ends_with(&format!(".{}", zi.name))) {
            relative(&n, &zi.name)
        } else {
            n
        };
        return Ok((zi, rel));
    }
    let n = normalize_name(name)?;
    if n == "@" {
        bail!("`@` needs the zone: -z ZONE");
    }
    let zi = zones
        .iter()
        .filter(|z| in_zone(&n, &z.name))
        .max_by_key(|z| if z.name == "." { 0 } else { z.name.len() + 1 })
        .cloned()
        .ok_or_else(|| anyhow!("{n} is not in any zone you can see (rdns zone ls)"))?;
    let rel = relative(&n, &zi.name);
    Ok((zi, rel))
}

pub fn fqdn(zone: &str, rel: &str) -> String {
    match (rel, zone) {
        ("@", z) => z.to_string(),
        (r, ".") => r.to_string(),
        (r, z) => format!("{r}.{z}"),
    }
}

/// Every record of a zone (paged), optionally narrowed by server-side text.
async fn zone_records(ctx: &Ctx, zone: &str, q: Option<&str>) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    loop {
        let path = format!(
            "/zones/{}/records{}",
            seg(zone),
            query(&[
                ("q", q.map(str::to_string)),
                ("offset", Some(out.len().to_string())),
                ("limit", Some("5000".into())),
            ])
        );
        let v = ctx.api.get(&path).await?;
        let page = v["records"].as_array().cloned().unwrap_or_default();
        let total = v["total"].as_u64().unwrap_or(0) as usize;
        let empty = page.is_empty();
        out.extend(page);
        if empty || out.len() >= total {
            return Ok(out);
        }
    }
}

/// The records at one name, optionally of one type.
async fn records_at(ctx: &Ctx, zone: &str, rel: &str, rtype: Option<&str>) -> Result<Vec<Value>> {
    let q = (rel != "@").then_some(rel);
    Ok(zone_records(ctx, zone, q)
        .await?
        .into_iter()
        .filter(|r| {
            r["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(rel))
        })
        .filter(|r| {
            rtype.is_none_or(|t| {
                r["type"]
                    .as_str()
                    .is_some_and(|x| x.eq_ignore_ascii_case(t))
            })
        })
        .collect())
}

/// Whether the value typed means the stored one: exactly, as the same
/// address, or ignoring case, quotes, spacing and trailing dots.
fn same_value(typed: &str, stored: &str) -> bool {
    let typed = typed.split_whitespace().collect::<Vec<_>>().join(" ");
    if typed == stored {
        return true;
    }
    if let (Ok(a), Ok(b)) = (
        typed.parse::<std::net::IpAddr>(),
        stored.parse::<std::net::IpAddr>(),
    ) {
        return a == b;
    }
    let loose = |s: &str| {
        s.replace('"', "")
            .split_whitespace()
            .map(|t| t.trim_end_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" ")
    };
    loose(&typed) == loose(stored)
}

fn ttl_of(r: &Value, zone_default: u64) -> String {
    r["ttl"].as_u64().unwrap_or(zone_default).to_string()
}

/// `www.example.com  300  A  192.0.2.10`
fn line(zone: &ZoneInfo, r: &Value) -> String {
    format!(
        "{}  {}  {}  {}",
        fqdn(&zone.name, r["name"].as_str().unwrap_or("@")),
        ttl_of(r, zone.default_ttl),
        r["type"].as_str().unwrap_or("?"),
        r["value"].as_str().unwrap_or("")
    )
}

fn print_records(rows: &[(ZoneInfo, Value)]) {
    let expiring = rows.iter().any(|(_, r)| r["expires_at"].is_string());
    let mut header = vec!["ID", "NAME", "TTL", "TYPE", "VALUE"];
    if expiring {
        header.insert(4, "EXPIRES");
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|(z, r)| {
            let mut row = vec![
                r["id"].to_string(),
                fqdn(&z.name, r["name"].as_str().unwrap_or("@")),
                ttl_of(r, z.default_ttl),
                r["type"].as_str().unwrap_or("?").to_string(),
                r["value"].as_str().unwrap_or("").to_string(),
            ];
            if expiring {
                row.insert(4, r["expires_at"].as_str().unwrap_or("-").to_string());
            }
            row
        })
        .collect();
    term::table(&header, &table);
}

fn value_arg(v: &[String]) -> String {
    v.join(" ")
}

pub async fn run(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::List {
            target,
            rtype,
            query: q,
            zone,
        } => list(ctx, target, rtype, q, zone).await,
        Cmd::Add {
            name,
            rtype,
            value,
            ttl,
            expires,
            zone,
        } => {
            let zs = zones(ctx).await?;
            let (z, rel) = locate(&zs, &name, zone.as_deref())?;
            let mut body = json!({
                "name": rel,
                "type": rtype.to_ascii_uppercase(),
                "value": value_arg(&value),
            });
            if let Some(t) = ttl {
                body["ttl"] = json!(t);
            }
            if let Some(e) = expires {
                body["expires_in"] = json!(term::parse_duration(&e)?);
            }
            let r = ctx
                .api
                .post(&format!("/zones/{}/records", seg(&z.name)), &body)
                .await?;
            ctx.show(&r, || {
                let verb = if r["created_at"] == r["updated_at"] {
                    "Added"
                } else {
                    "Renewed"
                };
                println!("{verb} {} (id {})", line(&z, &r), r["id"]);
            });
            Ok(())
        }
        Cmd::Set {
            name,
            rtype,
            value,
            ttl,
            zone,
        } => set(ctx, name, rtype.to_ascii_uppercase(), value, ttl, zone).await,
        Cmd::Rm {
            name,
            rtype,
            value,
            id,
            zone,
            yes,
        } => {
            let zs = zones(ctx).await?;
            if let Some(id) = id {
                let z = normalize_name(zone.as_deref().unwrap_or_default())?;
                let v = ctx
                    .api
                    .delete(&format!("/zones/{}/records/{id}", seg(&z)))
                    .await?;
                ctx.show(&v, || println!("Deleted record {id} of {z}"));
                return Ok(());
            }
            let name = name.unwrap_or_default();
            let (z, rel) = locate(&zs, &name, zone.as_deref())?;
            let typed = value_arg(&value);
            let mut found = records_at(ctx, &z.name, &rel, rtype.as_deref()).await?;
            if !typed.is_empty() {
                found.retain(|r| same_value(&typed, r["value"].as_str().unwrap_or("")));
            }
            let what = [
                Some(fqdn(&z.name, &rel)),
                rtype.clone(),
                (!typed.is_empty()).then_some(typed),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
            if found.is_empty() {
                bail!("no record matches {what}");
            }
            if found.len() > 1 {
                if !ctx.json {
                    for r in &found {
                        eprintln!("  {}", line(&z, r));
                    }
                }
                term::confirm(&format!("Delete these {} records", found.len()), yes)?;
            }
            let ids: Vec<i64> = found.iter().filter_map(|r| r["id"].as_i64()).collect();
            let v = bulk(ctx, &z.name, &ids, "", false).await?;
            ctx.show(&v, || {
                for r in v["deleted"].as_array().into_iter().flatten() {
                    println!("Deleted {}", line(&z, r));
                }
            });
            Ok(())
        }
        Cmd::Apply {
            zone,
            file,
            dry_run,
        } => {
            let zs = zones(ctx).await?;
            let zn = normalize_name(&zone)?;
            let z = zs
                .iter()
                .find(|x| x.name == zn)
                .cloned()
                .ok_or_else(|| anyhow!("zone '{zn}' not found (or not visible to you)"))?;
            let text = match file.as_deref() {
                None | Some("-") => std::io::read_to_string(std::io::stdin())?,
                Some(p) => std::fs::read_to_string(p).map_err(|e| anyhow!("{p}: {e}"))?,
            };
            let v = bulk(ctx, &z.name, &[], &text, dry_run).await?;
            ctx.show(&v, || {
                let verb = if dry_run { "Would add" } else { "Added" };
                for r in v["added"].as_array().into_iter().flatten() {
                    println!("{verb} {}", line(&z, r));
                }
            });
            Ok(())
        }
    }
}

/// One bulk transaction; per-line errors become one error listing them.
async fn bulk(ctx: &Ctx, zone: &str, delete: &[i64], add: &str, preview: bool) -> Result<Value> {
    let v = ctx
        .api
        .post(
            &format!("/zones/{}/records/bulk", seg(zone)),
            &json!({ "delete": delete, "add": add, "preview": preview }),
        )
        .await?;
    let errors = v["errors"].as_array().cloned().unwrap_or_default();
    if !errors.is_empty() {
        let lines: Vec<String> = errors
            .iter()
            .map(|e| {
                let msg = e["error"].as_str().unwrap_or("?");
                match (e["line"].as_u64(), e["record_id"].as_i64()) {
                    (_, Some(id)) => format!("  record {id}: {msg}"),
                    (Some(l), _) if l > 0 => format!("  line {l}: {msg}"),
                    _ => format!("  {msg}"),
                }
            })
            .collect();
        bail!("nothing was changed:\n{}", lines.join("\n"));
    }
    Ok(v)
}

async fn list(
    ctx: &Ctx,
    target: Option<String>,
    rtype: Option<String>,
    q: Option<String>,
    zone: Option<String>,
) -> Result<()> {
    let zs = zones(ctx).await?;
    let located = match (&target, &zone) {
        (None, None) => None,
        (None, Some(z)) => Some(locate(&zs, "@", Some(z)).map(|(z, _)| (z, None))?),
        (Some(t), z) => match locate(&zs, t, z.as_deref()) {
            // The zone itself (not `@` typed with -z): the whole zone.
            Ok((zi, rel)) if rel == "@" && t.trim() != "@" => Some((zi, None)),
            Ok((zi, rel)) => Some((zi, Some(rel))),
            Err(e) if z.is_some() => return Err(e),
            Err(_) => None,
        },
    };
    let type_ok = |r: &Value| {
        rtype.as_deref().is_none_or(|t| {
            r["type"]
                .as_str()
                .is_some_and(|x| x.eq_ignore_ascii_case(t))
        })
    };
    let rows: Vec<(ZoneInfo, Value)> = match located {
        Some((zi, rel)) => {
            let recs = match &rel {
                Some(rel) => records_at(ctx, &zi.name, rel, None).await?,
                None => zone_records(ctx, &zi.name, q.as_deref()).await?,
            };
            let q_ok = |r: &Value| {
                rel.is_none()
                    || q.as_deref().is_none_or(|q| {
                        let q = q.to_ascii_lowercase();
                        ["name", "type", "value"].iter().any(|k| {
                            r[*k]
                                .as_str()
                                .is_some_and(|s| s.to_ascii_lowercase().contains(&q))
                        })
                    })
            };
            recs.into_iter()
                .filter(|r| type_ok(r) && q_ok(r))
                .map(|r| (zi.clone(), r))
                .collect()
        }
        None => {
            // Search across zones: the target is search text.
            let text = [target.clone(), q.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            let path = format!(
                "/search{}",
                query(&[
                    ("q", (!text.is_empty()).then_some(text)),
                    ("type", rtype.clone()),
                    ("limit", Some("1000".into())),
                ])
            );
            let v = ctx.api.get(&path).await?;
            let by_name: HashMap<&str, &ZoneInfo> =
                zs.iter().map(|z| (z.name.as_str(), z)).collect();
            let hits = v["hits"].as_array().cloned().unwrap_or_default();
            let total = v["total"].as_u64().unwrap_or(0);
            if !ctx.json && total as usize > hits.len() {
                eprintln!(
                    "(showing {} of {total} matches; narrow it down with -t, -q or a zone)",
                    hits.len()
                );
            }
            hits.into_iter()
                .map(|h| {
                    let zn = h["zone"].as_str().unwrap_or_default();
                    let zi = by_name.get(zn).map(|z| (*z).clone()).unwrap_or(ZoneInfo {
                        name: zn.to_string(),
                        default_ttl: 0,
                    });
                    (zi, h["record"].clone())
                })
                .collect()
        }
    };
    let v = Value::Array(rows.iter().map(|(_, r)| r.clone()).collect());
    ctx.show(&v, || {
        if rows.is_empty() {
            eprintln!("No records.");
        } else {
            print_records(&rows);
        }
    });
    Ok(())
}

async fn set(
    ctx: &Ctx,
    name: String,
    rtype: String,
    value: Vec<String>,
    ttl: Option<String>,
    zone: Option<String>,
) -> Result<()> {
    // Some(None): the zone default; Some(Some(n)): n; None: not given.
    let ttl: Option<Option<u32>> = match ttl.as_deref() {
        None => None,
        Some("default") => Some(None),
        Some(t) => {
            Some(Some(t.parse().map_err(|_| {
                anyhow!("--ttl: a number of seconds or `default`")
            })?))
        }
    };
    let zs = zones(ctx).await?;
    let (z, rel) = locate(&zs, &name, zone.as_deref())?;
    let existing = records_at(ctx, &z.name, &rel, Some(&rtype)).await?;
    let typed = value_arg(&value);

    if typed.is_empty() {
        let Some(ttl) = ttl else {
            bail!("give a value to set, or --ttl to change the TTL");
        };
        if existing.is_empty() {
            bail!("no {rtype} record at {}", fqdn(&z.name, &rel));
        }
        let mut out = Vec::new();
        for r in &existing {
            let id = r["id"].as_i64().unwrap_or_default();
            out.push(
                ctx.api
                    .put(
                        &format!("/zones/{}/records/{id}", seg(&z.name)),
                        &json!({ "ttl": ttl }),
                    )
                    .await?,
            );
        }
        let v = Value::Array(out);
        ctx.show(&v, || {
            for r in v.as_array().into_iter().flatten() {
                println!("Updated {}", line(&z, r));
            }
        });
        return Ok(());
    }

    // Unchanged TTL: keep the one the records share.
    let ttl = ttl.unwrap_or_else(|| {
        let ttls: Vec<Option<u64>> = existing.iter().map(|r| r["ttl"].as_u64()).collect();
        match ttls.first() {
            Some(first) if ttls.iter().all(|t| t == first) => first.map(|t| t as u32),
            _ => None,
        }
    });
    if let [only] = existing.as_slice() {
        if same_value(&typed, only["value"].as_str().unwrap_or("")) {
            let id = only["id"].as_i64().unwrap_or_default();
            let v = if only["ttl"].as_u64().map(|t| t as u32) != ttl {
                ctx.api
                    .put(
                        &format!("/zones/{}/records/{id}", seg(&z.name)),
                        &json!({ "ttl": ttl }),
                    )
                    .await?
            } else {
                only.clone()
            };
            ctx.show(&v, || println!("Set {}", line(&z, &v)));
            return Ok(());
        }
    }
    let ids: Vec<i64> = existing.iter().filter_map(|r| r["id"].as_i64()).collect();
    let add = match ttl {
        Some(t) => format!("{rel} {t} {rtype} {typed}"),
        None => format!("{rel} {rtype} {typed}"),
    };
    let v = bulk(ctx, &z.name, &ids, &add, false).await?;
    ctx.show(&v, || {
        for r in v["added"].as_array().into_iter().flatten() {
            println!("Set {}", line(&z, r));
        }
        let n = v["deleted"].as_array().map_or(0, Vec::len);
        if n > 0 {
            println!("(replaced {n} record{})", if n == 1 { "" } else { "s" });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zs() -> Vec<ZoneInfo> {
        ["example.com", "sub.example.com", "example.org"]
            .iter()
            .map(|n| ZoneInfo {
                name: n.to_string(),
                default_ttl: 3600,
            })
            .collect()
    }

    fn loc(name: &str, zone: Option<&str>) -> (String, String) {
        let (z, r) = locate(&zs(), name, zone).unwrap();
        (z.name, r)
    }

    #[test]
    fn names_find_the_longest_zone() {
        assert_eq!(
            loc("www.example.com", None),
            ("example.com".into(), "www".into())
        );
        assert_eq!(
            loc("WWW.Example.COM.", None),
            ("example.com".into(), "www".into())
        );
        assert_eq!(loc("example.com", None), ("example.com".into(), "@".into()));
        assert_eq!(
            loc("a.sub.example.com", None),
            ("sub.example.com".into(), "a".into())
        );
        assert_eq!(
            loc("_sip._tcp.example.org", None),
            ("example.org".into(), "_sip._tcp".into())
        );
        assert!(locate(&zs(), "www.example.net", None).is_err());
        assert!(locate(&zs(), "notexample.com", None).is_err());
        assert!(locate(&zs(), "@", None).is_err());
    }

    #[test]
    fn names_with_an_explicit_zone() {
        let z = Some("example.com");
        assert_eq!(loc("www", z), ("example.com".into(), "www".into()));
        assert_eq!(loc("@", z), ("example.com".into(), "@".into()));
        assert_eq!(
            loc("www.example.com", z),
            ("example.com".into(), "www".into())
        );
        assert_eq!(loc("example.com.", z), ("example.com".into(), "@".into()));
        // Relative names that happen to contain dots.
        assert_eq!(loc("a.b", z), ("example.com".into(), "a.b".into()));
        assert!(locate(&zs(), "www.example.org.", z).is_err());
        assert!(locate(&zs(), "www", Some("nope.test")).is_err());
    }

    #[test]
    fn values_match_loosely() {
        assert!(same_value("192.0.2.10", "192.0.2.10"));
        assert!(same_value("2001:db8:0::10", "2001:db8::10"));
        assert!(same_value("10 Mail.Example.com", "10 mail.example.com."));
        assert!(same_value("v=spf1  -all", "\"v=spf1 -all\""));
        assert!(!same_value("192.0.2.1", "192.0.2.10"));
    }

    #[test]
    fn fqdns() {
        assert_eq!(fqdn("example.com", "@"), "example.com");
        assert_eq!(fqdn("example.com", "www"), "www.example.com");
        assert_eq!(fqdn(".", "com"), "com");
    }
}
