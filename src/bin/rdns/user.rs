//! `rdns user`: accounts (administrators). Users are named by username.

use crate::{term, Ctx};
use anyhow::{anyhow, bail, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List users.
    #[command(visible_alias = "ls")]
    List,
    /// Show a user and the zones they can reach.
    #[command(visible_alias = "info", visible_alias = "get")]
    Show { user: String },
    /// Create a user (the password is asked for unless given).
    #[command(visible_alias = "create")]
    Add {
        user: String,
        #[command(flatten)]
        pw: Password,
        /// Display name.
        #[arg(long)]
        name: Option<String>,
        /// Make them an administrator.
        #[arg(long)]
        admin: bool,
        /// Make them set up an authenticator (MFA) at their next sign-in.
        #[arg(long)]
        require_mfa: bool,
    },
    /// Change a user: password, name, administrator, MFA, enabled.
    #[command(visible_alias = "update")]
    Set {
        user: String,
        #[command(flatten)]
        pw: Password,
        /// Ask for the new password.
        #[arg(long, conflicts_with_all = ["password", "password_stdin"])]
        ask_password: bool,
        /// With a new password: also revoke all their API tokens.
        #[arg(long)]
        revoke_tokens: bool,
        /// Display name.
        #[arg(long)]
        name: Option<String>,
        /// Make them an administrator.
        #[arg(long, overrides_with = "no_admin")]
        admin: bool,
        /// Make them an ordinary user.
        #[arg(long)]
        no_admin: bool,
        /// Make them set up an authenticator at their next sign-in.
        #[arg(long, overrides_with = "no_require_mfa")]
        require_mfa: bool,
        /// No longer require an authenticator.
        #[arg(long)]
        no_require_mfa: bool,
        /// Disable the account (signs them out everywhere).
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Enable the account again.
        #[arg(long)]
        enable: bool,
    },
    /// Delete a user; their zones are released. You cannot delete yourself.
    #[command(
        visible_alias = "del",
        visible_alias = "delete",
        visible_alias = "remove"
    )]
    Rm {
        user: String,
        /// Do not ask.
        #[arg(short, long)]
        yes: bool,
    },
    /// Remove a user's authenticator (MFA) and sign them out.
    ResetMfa { user: String },
    /// Sign a user out of every browser session.
    Signout { user: String },
}

#[derive(Args, Debug)]
pub struct Password {
    /// The password (visible to other local users in the process list;
    /// prefer the prompt or --password-stdin).
    #[arg(long)]
    password: Option<String>,
    /// Read the password from the first line of stdin.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
}

impl Password {
    fn given(&self) -> Result<Option<String>> {
        if let Some(p) = &self.password {
            return Ok(Some(p.clone()));
        }
        if self.password_stdin {
            return Ok(Some(term::stdin_line()?));
        }
        Ok(None)
    }
}

async fn all(ctx: &Ctx) -> Result<Vec<Value>> {
    let v = ctx.api.get("/users").await?;
    Ok(v["users"].as_array().cloned().unwrap_or_default())
}

/// The user called `name` (or with that id).
async fn find(ctx: &Ctx, name: &str) -> Result<Value> {
    let users = all(ctx).await?;
    let n = name.trim();
    users
        .iter()
        .find(|u| {
            u["username"]
                .as_str()
                .is_some_and(|x| x.eq_ignore_ascii_case(n))
        })
        .or_else(|| {
            n.trim_start_matches('#')
                .parse::<i64>()
                .ok()
                .and_then(|id| users.iter().find(|u| u["id"].as_i64() == Some(id)))
        })
        .cloned()
        .ok_or_else(|| anyhow!("no user '{n}'"))
}

fn id_of(u: &Value) -> i64 {
    u["id"].as_i64().unwrap_or_default()
}

fn role(u: &Value) -> &'static str {
    if u["is_root"].as_bool() == Some(true) {
        "root"
    } else if u["is_admin"].as_bool() == Some(true) {
        "admin"
    } else {
        "user"
    }
}

fn state(u: &Value) -> String {
    let mut s = vec![];
    if u["disabled_at"].is_string() {
        s.push("disabled");
    }
    if u["mfa_enrolled"].as_bool() == Some(true) {
        s.push("mfa");
    } else if u["mfa_required"].as_bool() == Some(true) {
        s.push("mfa required");
    }
    if s.is_empty() {
        return "active".into();
    }
    s.join(", ")
}

fn name(u: &Value) -> &str {
    u["username"].as_str().unwrap_or("?")
}

pub async fn run(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    let api = &ctx.api;
    match cmd {
        Cmd::List => {
            let users = all(ctx).await?;
            ctx.show(&Value::Array(users.clone()), || {
                let rows: Vec<Vec<String>> = users
                    .iter()
                    .map(|u| {
                        vec![
                            u["id"].to_string(),
                            name(u).into(),
                            role(u).into(),
                            state(u),
                            u["display_name"].as_str().unwrap_or("").into(),
                        ]
                    })
                    .collect();
                term::table(&["ID", "USER", "ROLE", "STATE", "NAME"], &rows);
            });
        }
        Cmd::Show { user } => {
            let u = find(ctx, &user).await?;
            let rights = api.get(&format!("/users/{}/rights", id_of(&u))).await?;
            ctx.show(&json!({ "user": u, "rights": rights }), || {
                let rows = [
                    ("User", name(&u).to_string()),
                    ("Id", u["id"].to_string()),
                    ("Name", u["display_name"].as_str().unwrap_or("").into()),
                    ("Role", role(&u).into()),
                    ("State", state(&u)),
                    ("Created", u["created_at"].as_str().unwrap_or("").into()),
                    ("API tokens", rights["active_tokens"].to_string()),
                ];
                for (k, v) in rows {
                    println!("{k:<10}  {v}");
                }
                let zones = rights["zones"].as_array().cloned().unwrap_or_default();
                if !zones.is_empty() {
                    println!();
                    let rows: Vec<Vec<String>> = zones
                        .iter()
                        .map(|z| {
                            vec![
                                z["zone"].as_str().unwrap_or("").into(),
                                z["role"].as_str().unwrap_or("").into(),
                                z["source"].as_str().unwrap_or("").into(),
                            ]
                        })
                        .collect();
                    term::table(&["ZONE", "ROLE", "VIA"], &rows);
                }
            });
        }
        Cmd::Add {
            user,
            pw,
            name: display,
            admin,
            require_mfa,
        } => {
            let password = match pw.given()? {
                Some(p) => p,
                None => term::ask_new_password(&format!("Password for {user}: "))?,
            };
            let v = api
                .post(
                    "/users",
                    &json!({
                        "username": user.trim(),
                        "password": password,
                        "display_name": display.unwrap_or_default(),
                        "is_admin": admin,
                        "mfa_required": require_mfa,
                    }),
                )
                .await?;
            ctx.show(&v, || {
                println!("Created {} {} (id {})", role(&v), name(&v), v["id"])
            });
        }
        Cmd::Set {
            user,
            pw,
            ask_password,
            revoke_tokens,
            name: display,
            admin,
            no_admin,
            require_mfa,
            no_require_mfa,
            disable,
            enable,
        } => {
            let u = find(ctx, &user).await?;
            let mut b = Map::new();
            let password = if ask_password {
                Some(term::ask_new_password(&format!(
                    "New password for {}: ",
                    name(&u)
                ))?)
            } else {
                pw.given()?
            };
            if revoke_tokens && password.is_none() {
                bail!("--revoke-tokens goes with a new password (rdns token rm revokes single tokens)");
            }
            if let Some(p) = password {
                b.insert("password".into(), p.into());
                b.insert("revoke_tokens".into(), revoke_tokens.into());
            }
            if let Some(d) = display {
                b.insert("display_name".into(), d.into());
            }
            if admin || no_admin {
                b.insert("is_admin".into(), admin.into());
            }
            if require_mfa || no_require_mfa {
                b.insert("mfa_required".into(), require_mfa.into());
            }
            if disable || enable {
                b.insert("disabled".into(), disable.into());
            }
            if b.is_empty() {
                bail!("nothing to change: see `rdns user set --help`");
            }
            let v = api
                .put(&format!("/users/{}", id_of(&u)), &Value::Object(b))
                .await?;
            ctx.show(&v, || {
                println!("Updated {} {} ({})", role(&v), name(&v), state(&v))
            });
        }
        Cmd::Rm { user, yes } => {
            let u = find(ctx, &user).await?;
            let me = api.get("/me").await?;
            if me["user"]["id"] == u["id"] {
                bail!("you cannot delete yourself");
            }
            if u["is_root"].as_bool() == Some(true) {
                bail!("root cannot be deleted");
            }
            term::confirm(
                &format!("Delete user {} (their zones are released)", name(&u)),
                yes,
            )?;
            let v = api.delete(&format!("/users/{}", id_of(&u))).await?;
            ctx.show(&v, || println!("Deleted user {}", name(&u)));
        }
        Cmd::ResetMfa { user } => {
            let u = find(ctx, &user).await?;
            let v = api
                .post(&format!("/users/{}/reset-mfa", id_of(&u)), &json!({}))
                .await?;
            ctx.show(&v, || {
                println!(
                    "Removed the authenticator of {} and signed them out",
                    name(&u)
                )
            });
        }
        Cmd::Signout { user } => {
            let u = find(ctx, &user).await?;
            let v = api
                .post(&format!("/users/{}/sessions/revoke", id_of(&u)), &json!({}))
                .await?;
            ctx.show(&v, || {
                println!(
                    "Signed {} out of {} session(s)",
                    name(&u),
                    v["revoked"].as_u64().unwrap_or(0)
                )
            });
        }
    }
    Ok(())
}
