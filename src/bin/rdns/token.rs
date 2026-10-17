//! `rdns token`: API tokens (your own; administrators see everyone's with --all).

use crate::dns::normalize_name;
use crate::{term, Ctx};
use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List active tokens.
    #[command(visible_alias = "ls")]
    List {
        /// Every user's tokens (administrators).
        #[arg(long)]
        all: bool,
    },
    /// Create a token; it is printed once.
    #[command(visible_alias = "create")]
    Add {
        name: String,
        /// Only these zones (repeat for several).
        #[arg(long = "zone", value_name = "ZONE")]
        zones: Vec<String>,
        /// At most this role on any zone.
        #[arg(long, value_parser = ["viewer", "editor", "owner"])]
        role: Option<String>,
        /// Stop working at this time (RFC 3339) or after this long (e.g. 90d).
        #[arg(long, value_name = "WHEN")]
        expires: Option<String>,
        /// Labels (repeat for several).
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Revoke a token.
    #[command(
        visible_alias = "del",
        visible_alias = "delete",
        visible_alias = "revoke"
    )]
    Rm { id: i64 },
}

/// Days without use after which a token is called stale.
const STALE_DAYS: i64 = 90;

/// Why a token deserves a look: expired, never used, or unused for long.
fn note(t: &Value, now: chrono::DateTime<chrono::Utc>) -> String {
    let at = |k: &Value| {
        k.as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
    };
    if at(&t["scope"]["expires_at"]).is_some_and(|e| e <= now) {
        return "expired".into();
    }
    match (at(&t["last_used_at"]), at(&t["created_at"])) {
        (Some(used), _) if (now - used).num_days() >= STALE_DAYS => {
            format!("unused for {} days", (now - used).num_days())
        }
        (None, Some(created)) if (now - created).num_days() >= 7 => {
            format!("never used ({} days old)", (now - created).num_days())
        }
        _ => String::new(),
    }
}

pub async fn run(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    let api = &ctx.api;
    match cmd {
        Cmd::List { all } => {
            let v = api
                .get(if all { "/tokens?all=true" } else { "/tokens" })
                .await?;
            ctx.show(&v, || {
                let rows: Vec<Vec<String>> = v["tokens"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|t| t["revoked_at"].is_null())
                    .map(|t| {
                        let scope = &t["scope"];
                        let mut lim = vec![];
                        if let Some(z) = scope["zones"].as_array() {
                            lim.push(
                                z.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(","),
                            );
                        }
                        if let Some(r) = scope["max_role"].as_str() {
                            lim.push(format!("≤{r}"));
                        }
                        if let Some(e) = scope["expires_at"].as_str() {
                            lim.push(format!("until {e}"));
                        }
                        vec![
                            t["id"].to_string(),
                            t["name"].as_str().unwrap_or("").into(),
                            t["username"].as_str().unwrap_or("").into(),
                            lim.join(" "),
                            t["last_used_at"].as_str().unwrap_or("never").into(),
                            note(t, chrono::Utc::now()),
                        ]
                    })
                    .collect();
                term::table(
                    &["ID", "NAME", "USER", "LIMITS", "LAST USED", "NOTE"],
                    &rows,
                );
                if rows.iter().any(|r| !r[5].is_empty()) {
                    eprintln!("(revoke tokens nobody uses: rdns token rm ID)");
                }
            });
        }
        Cmd::Add {
            name,
            zones,
            role,
            expires,
            tags,
        } => {
            let mut scope = json!({});
            if !zones.is_empty() {
                scope["zones"] = json!(zones
                    .iter()
                    .map(|z| normalize_name(z))
                    .collect::<Result<Vec<_>>>()?);
            }
            if let Some(r) = role {
                scope["max_role"] = json!(r);
            }
            if let Some(e) = expires {
                scope["expires_at"] = json!(term::parse_instant(&e)?);
            }
            let v = api
                .post(
                    "/tokens",
                    &json!({ "name": name, "tags": tags, "scope": scope }),
                )
                .await?;
            ctx.show(&v, || {
                eprintln!(
                    "Created token {} (id {}); it is shown only now:",
                    name, v["info"]["id"]
                );
                println!("{}", v["token"].as_str().unwrap_or(""));
            });
        }
        Cmd::Rm { id } => {
            let v = api.delete(&format!("/tokens/{id}")).await?;
            ctx.show(&v, || println!("Revoked token {id}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stale_tokens_are_noted() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-17T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let fresh =
            json!({ "created_at": "2026-10-01T00:00:00Z", "last_used_at": "2026-10-16T00:00:00Z" });
        assert_eq!(note(&fresh, now), "");
        let stale =
            json!({ "created_at": "2026-01-01T00:00:00Z", "last_used_at": "2026-06-01T00:00:00Z" });
        assert_eq!(note(&stale, now), "unused for 138 days");
        let unused = json!({ "created_at": "2026-10-01T00:00:00Z", "last_used_at": null });
        assert_eq!(note(&unused, now), "never used (16 days old)");
        let new = json!({ "created_at": "2026-10-15T00:00:00Z", "last_used_at": null });
        assert_eq!(note(&new, now), "");
        let expired = json!({ "created_at": "2026-01-01T00:00:00Z", "last_used_at": null,
            "scope": { "expires_at": "2026-10-01T00:00:00Z" } });
        assert_eq!(note(&expired, now), "expired");
    }
}
