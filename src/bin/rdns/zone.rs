//! `rdns zone`: zones, their access, import and export.

use crate::api::{query, seg};
use crate::dns::normalize_name;
use crate::{term, Ctx};
use anyhow::{anyhow, bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{json, Map, Value};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List the zones you can see.
    #[command(visible_alias = "ls")]
    List,
    /// Show a zone: SOA, settings and who has access.
    #[command(visible_alias = "info", visible_alias = "get")]
    Show { zone: String },
    /// Create a zone (you own it unless --owner says otherwise).
    #[command(visible_alias = "create")]
    Add {
        zone: String,
        #[command(flatten)]
        f: Fields,
    },
    /// Change a zone's SOA values, default TTL or owner.
    #[command(visible_alias = "update")]
    Set {
        zone: String,
        #[command(flatten)]
        f: Fields,
    },
    /// Rename a zone; its records, access and settings move with it.
    #[command(visible_alias = "mv")]
    Rename { zone: String, new_name: String },
    /// Copy a zone (with its records unless --empty) under a new name.
    #[command(visible_alias = "cp")]
    Clone {
        zone: String,
        new_name: String,
        /// Copy the settings only, not the records.
        #[arg(long)]
        empty: bool,
    },
    /// Delete a zone and all its records.
    #[command(
        visible_alias = "del",
        visible_alias = "delete",
        visible_alias = "remove"
    )]
    Rm {
        zone: String,
        /// Do not ask.
        #[arg(short, long)]
        yes: bool,
    },
    /// Who has access to a zone.
    #[command(visible_alias = "members")]
    Access { zone: String },
    /// Give a user access to a zone (or change their role).
    Grant {
        zone: String,
        user: String,
        #[arg(long, value_enum, default_value_t = Role::Editor)]
        role: Role,
    },
    /// Take a user's access to a zone away.
    Revoke { zone: String, user: String },
    /// Export zones as a JSON document (all you can see, or one).
    Export {
        zone: Option<String>,
        /// Write to this file instead of stdout.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import a JSON export document (`-` reads stdin).
    Import {
        file: String,
        /// Replace the records of each zone in the document instead of
        /// adding the missing ones.
        #[arg(long)]
        replace: bool,
        /// Do not ask (with --replace).
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Role {
    Editor,
    Viewer,
}

/// The values of a zone; on `set` only those given change.
#[derive(Args, Debug, Default)]
pub struct Fields {
    /// Primary name server (SOA MNAME), e.g. ns1.example.com.
    #[arg(long, value_name = "NAME")]
    ns: Option<String>,
    /// Responsible mailbox (SOA RNAME): hostmaster@example.com
    #[arg(long, value_name = "ADDRESS")]
    email: Option<String>,
    /// Default TTL of the zone's records, seconds.
    #[arg(long)]
    ttl: Option<u32>,
    /// Owner username (administrators; `""` clears it on set).
    #[arg(long)]
    owner: Option<String>,
    /// SOA refresh, seconds.
    #[arg(long)]
    refresh: Option<u32>,
    /// SOA retry, seconds.
    #[arg(long)]
    retry: Option<u32>,
    /// SOA expire, seconds.
    #[arg(long)]
    expire: Option<u32>,
    /// SOA minimum (negative caching TTL), seconds.
    #[arg(long)]
    minimum: Option<u32>,
}

impl Fields {
    fn body(&self) -> Map<String, Value> {
        let mut m = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                m.insert(k.into(), v);
            }
        };
        put("soa_mname", self.ns.clone().map(Value::from));
        put("soa_rname", self.email.clone().map(Value::from));
        put("default_ttl", self.ttl.map(Value::from));
        put("owner", self.owner.clone().map(Value::from));
        put("refresh", self.refresh.map(Value::from));
        put("retry", self.retry.map(Value::from));
        put("expire", self.expire.map(Value::from));
        put("minimum", self.minimum.map(Value::from));
        m
    }
}

fn zpath(zone: &str) -> Result<String> {
    Ok(format!("/zones/{}", seg(&normalize_name(zone)?)))
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        v => v.to_string(),
    }
}

fn kind(z: &Value) -> &'static str {
    if z["override"].is_object() {
        "override"
    } else if z["secondary"].is_object() {
        "secondary"
    } else {
        "primary"
    }
}

fn print_zone(z: &Value) {
    let rows = [
        ("Zone", s(&z["name"])),
        ("Type", kind(z).to_string()),
        ("Owner", s(&z["owner"])),
        ("Your role", s(&z["role"])),
        ("Records", s(&z["record_count"])),
        ("Serial", s(&z["serial"])),
        ("Name server", s(&z["soa_mname"])),
        ("Mailbox", s(&z["soa_rname"])),
        ("Default TTL", s(&z["default_ttl"])),
        (
            "Refresh/retry/expire/min",
            format!(
                "{} / {} / {} / {}",
                s(&z["refresh"]),
                s(&z["retry"]),
                s(&z["expire"]),
                s(&z["minimum"])
            ),
        ),
        (
            "DNSSEC",
            if z["dnssec"].as_bool() == Some(true) {
                "signed"
            } else {
                "off"
            }
            .into(),
        ),
    ];
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in rows {
        println!("{k:<w$}  {v}");
    }
}

fn print_members(owner: &Value, members: &[Value]) {
    let mut rows = vec![vec![s(owner), "owner".into(), String::new()]];
    rows.extend(members.iter().map(|m| {
        vec![
            s(&m["username"]),
            s(&m["role"]),
            m["created_at"].as_str().unwrap_or("").to_string(),
        ]
    }));
    term::table(&["USER", "ROLE", "SINCE"], &rows);
}

pub async fn run(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    let api = &ctx.api;
    match cmd {
        Cmd::List => {
            let v = api.get("/zones").await?;
            ctx.show(&v, || {
                let zones = v["zones"].as_array().cloned().unwrap_or_default();
                if zones.is_empty() {
                    eprintln!("No zones.");
                    return;
                }
                let rows: Vec<Vec<String>> = zones
                    .iter()
                    .map(|z| {
                        vec![
                            s(&z["name"]),
                            kind(z).into(),
                            s(&z["record_count"]),
                            s(&z["owner"]),
                            s(&z["role"]),
                            if z["dnssec"].as_bool() == Some(true) {
                                "yes"
                            } else {
                                ""
                            }
                            .into(),
                        ]
                    })
                    .collect();
                term::table(
                    &["ZONE", "TYPE", "RECORDS", "OWNER", "ROLE", "DNSSEC"],
                    &rows,
                );
            });
        }
        Cmd::Show { zone } => {
            let v = api.get(&zpath(&zone)?).await?;
            ctx.show(&v, || {
                print_zone(&v);
                let members = v["members"].as_array().cloned().unwrap_or_default();
                if !members.is_empty() {
                    println!();
                    print_members(&v["owner"], &members);
                }
            });
        }
        Cmd::Add { zone, f } => {
            let mut body = f.body();
            body.insert("name".into(), normalize_name(&zone)?.into());
            let v = api.post("/zones", &Value::Object(body)).await?;
            ctx.show(&v, || {
                println!("Created zone {}", s(&v["name"]));
                print_zone(&v);
            });
        }
        Cmd::Set { zone, f } => {
            let body = f.body();
            if body.is_empty() {
                bail!("nothing to change: give --ns, --email, --ttl, --owner, --refresh, --retry, --expire or --minimum");
            }
            let v = api.put(&zpath(&zone)?, &Value::Object(body)).await?;
            ctx.show(&v, || {
                println!("Updated zone {}", s(&v["name"]));
                print_zone(&v);
            });
        }
        Cmd::Rename { zone, new_name } => {
            let v = api
                .post(
                    &format!("{}/rename", zpath(&zone)?),
                    &json!({ "name": normalize_name(&new_name)? }),
                )
                .await?;
            ctx.show(&v, || println!("Renamed {zone} to {}", s(&v["name"])));
        }
        Cmd::Clone {
            zone,
            new_name,
            empty,
        } => {
            let v = api
                .post(
                    &format!("{}/clone", zpath(&zone)?),
                    &json!({ "name": normalize_name(&new_name)?, "records": !empty }),
                )
                .await?;
            ctx.show(&v, || {
                println!(
                    "Copied {zone} to {} ({} records)",
                    s(&v["name"]),
                    s(&v["record_count"])
                )
            });
        }
        Cmd::Rm { zone, yes } => {
            let path = zpath(&zone)?;
            let z = api.get(&path).await?;
            term::confirm(
                &format!(
                    "Delete zone {} and its {} records",
                    s(&z["name"]),
                    s(&z["record_count"])
                ),
                yes,
            )?;
            let v = api.delete(&path).await?;
            ctx.show(&v, || println!("Deleted zone {}", s(&z["name"])));
        }
        Cmd::Access { zone } => {
            let v = api.get(&zpath(&zone)?).await?;
            let members = v["members"].clone();
            ctx.show(&json!({ "owner": v["owner"], "members": members }), || {
                print_members(
                    &v["owner"],
                    members.as_array().map_or(&[], |a| a.as_slice()),
                );
                if v["role"] != "owner" {
                    eprintln!("(members are shown to the zone's owner and administrators)");
                }
            });
        }
        Cmd::Grant { zone, user, role } => {
            let role = match role {
                Role::Editor => "editor",
                Role::Viewer => "viewer",
            };
            let v = api
                .put(
                    &format!("{}/members/{}", zpath(&zone)?, seg(user.trim())),
                    &json!({ "role": role }),
                )
                .await?;
            ctx.show(&v, || println!("{user} is now {role} of {zone}"));
        }
        Cmd::Revoke { zone, user } => {
            let v = api
                .delete(&format!("{}/members/{}", zpath(&zone)?, seg(user.trim())))
                .await?;
            ctx.show(&v, || println!("{user} no longer has access to {zone}"));
        }
        Cmd::Export { zone, output } => {
            let v = match &zone {
                Some(z) => api.get(&format!("{}/export", zpath(z)?)).await?,
                None => api.get("/export").await?,
            };
            let text = serde_json::to_string_pretty(&v)? + "\n";
            match output {
                Some(p) => {
                    std::fs::write(&p, text).map_err(|e| anyhow!("{p}: {e}"))?;
                    let n = v["zones"].as_array().map_or(0, Vec::len);
                    eprintln!("Exported {n} zone{} to {p}", if n == 1 { "" } else { "s" });
                }
                None => print!("{text}"),
            }
        }
        Cmd::Import { file, replace, yes } => {
            let text = if file == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(&file).map_err(|e| anyhow!("{file}: {e}"))?
            };
            let doc: Value =
                serde_json::from_str(&text).map_err(|e| anyhow!("{file}: not JSON: {e}"))?;
            if replace {
                let names: Vec<String> = doc["zones"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|z| s(&z["name"]))
                    .collect();
                term::confirm(
                    &format!("Replace every record of {}", names.join(", ")),
                    yes,
                )?;
            }
            let mode = if replace { "replace" } else { "merge" };
            let v = api
                .post(
                    &format!("/import{}", query(&[("mode", Some(mode.into()))])),
                    &doc,
                )
                .await?;
            ctx.show(&v, || {
                println!(
                    "Imported: {} zones created, {} updated; {} records added, {} removed, {} skipped",
                    s(&v["zones_created"]),
                    s(&v["zones_updated"]),
                    s(&v["records_added"]),
                    s(&v["records_removed"]),
                    s(&v["records_skipped"])
                )
            });
        }
    }
    Ok(())
}
