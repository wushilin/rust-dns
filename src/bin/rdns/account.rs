//! Signing in and out, profiles, and the caller's own account.

use crate::api::Client;
use crate::{config, term, Ctx, Global};
use anyhow::{anyhow, bail, Result};
use clap::Args;
use serde_json::json;

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Server URL, e.g. https://dns.example.com (default: the profile's).
    server: Option<String>,
    /// Username (prompted when missing).
    #[arg(short, long)]
    user: Option<String>,
    /// Read the password from the first line of stdin instead of prompting.
    #[arg(long)]
    password_stdin: bool,
    /// Save an existing API token instead of signing in with a password
    /// (asked for without echo; RDNS_TOKEN also works).
    #[arg(long, conflicts_with_all = ["user", "password_stdin", "token_stdin"])]
    with_token: bool,
    /// Like --with-token, reading the token from the first line of stdin.
    #[arg(long, conflicts_with_all = ["user", "password_stdin"])]
    token_stdin: bool,
    /// Let the token this creates stop working after this long (e.g. 90d)
    /// or at this RFC 3339 time. The server treats a token with an expiry
    /// as scoped: it cannot create or revoke tokens, so `rdns token add/rm`
    /// and revoking it at `rdns logout` need the console or another token.
    #[arg(long, value_name = "WHEN", conflicts_with_all = ["with_token", "token_stdin"])]
    expires: Option<String>,
    /// Save as this profile (default: the server's host name).
    #[arg(long = "as", value_name = "PROFILE")]
    as_: Option<String>,
    /// PEM file of the CA certificates to trust for this server.
    #[arg(long)]
    ca_file: Option<String>,
}

/// Sign in with a password and mint an API token for this machine (or take
/// an existing token), and save it. Only the token is stored.
pub async fn login(g: &Global, a: LoginArgs) -> Result<()> {
    let mut file = config::File::load()?;
    let existing = file
        .pick(g.profile.as_deref())
        .and_then(|n| file.profiles.get(&n).cloned());
    let server = match a.server.as_deref().or(g.server.as_deref()) {
        Some(s) => config::normalize_server(s)?,
        None => match &existing {
            Some(p) => p.server.clone(),
            None => config::normalize_server(&term::ask("Server URL: ")?)?,
        },
    };
    let ca_file = a
        .ca_file
        .clone()
        .or_else(|| existing.as_ref().and_then(|p| p.ca_file.clone()));
    let name = a
        .as_
        .clone()
        .or_else(|| g.profile.clone())
        .unwrap_or_else(|| profile_name(&server));
    // The token `rdns login` minted for this profile before, to revoke.
    let old = file
        .profiles
        .get(&name)
        .filter(|p| p.server == server && p.token_id.is_some())
        .cloned();
    let expires_at = a.expires.as_deref().map(term::parse_instant).transpose()?;

    let given = if a.token_stdin {
        Some(term::stdin_line()?)
    } else if a.with_token {
        Some(term::ask_secret("API token: ")?)
    } else {
        g.token.clone()
    };
    let (token, token_id, user) = if let Some(t) = given {
        let t = t.trim().to_string();
        let c = Client::new(&server, Some(t.clone()), ca_file.as_deref())?;
        let me = c.get("/me").await?;
        if let Some(old) = &old {
            // Revoked with itself (an unrestricted token may).
            revoke_quietly(&server, &old.token, old.token_id, ca_file.as_deref()).await;
        }
        (t, None, me["user"]["username"].as_str().map(str::to_string))
    } else {
        let user = match a.user {
            Some(u) => u,
            None => term::ask("Username: ")?,
        };
        let password = if a.password_stdin {
            term::stdin_line()?
        } else {
            term::ask_secret(&format!("Password for {user}: "))?
        };
        let s = Client::new(&server, None, ca_file.as_deref())?
            .session(&user, &password, || {
                term::ask("Authenticator code (or a recovery code): ")
            })
            .await?;
        let mut body = json!({ "name": format!("rdns@{}", host_name()), "tags": ["rdns-cli"] });
        if let Some(at) = &expires_at {
            body["scope"] = json!({ "expires_at": at });
        }
        let created = s.post("/tokens", &body).await;
        if let (Ok(_), Some(id)) = (&created, old.as_ref().and_then(|o| o.token_id)) {
            // The session may revoke any of the user's tokens.
            let _ = s.delete(&format!("/tokens/{id}")).await;
        }
        s.sign_out().await;
        let created = created?;
        let token = created["token"]
            .as_str()
            .ok_or_else(|| anyhow!("the server returned no token"))?
            .to_string();
        (token, created["info"]["id"].as_i64(), Some(user))
    };

    file.profiles.insert(
        name.clone(),
        config::Profile {
            server: server.clone(),
            token,
            token_id,
            user: user.clone(),
            ca_file,
        },
    );
    if file.default.is_none() || file.profiles.len() == 1 {
        file.default = Some(name.clone());
    }
    let path = file.save()?;
    println!(
        "Signed in to {server} as {} (profile '{name}', saved in {})",
        user.as_deref().unwrap_or("?"),
        path.display()
    );
    if let Some(at) = expires_at {
        println!("The token expires at {at}; sign in again before then.");
    }
    Ok(())
}

/// Revoke a token with itself; a failure is only reported.
async fn revoke_quietly(server: &str, token: &str, id: Option<i64>, ca: Option<&str>) -> bool {
    let Some(id) = id else { return false };
    let Ok(c) = Client::new(server, Some(token.to_string()), ca) else {
        return false;
    };
    match c.delete(&format!("/tokens/{id}")).await {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "rdns: warning: could not revoke token {id} on the server ({e:#}); revoke it in the console under API tokens"
            );
            false
        }
    }
}

pub async fn logout(g: &Global) -> Result<()> {
    let mut file = config::File::load()?;
    let name = file
        .pick(g.profile.as_deref())
        .ok_or_else(|| anyhow!("no profile to sign out of"))?;
    let p = file
        .profiles
        .remove(&name)
        .ok_or_else(|| anyhow!("no profile '{name}'"))?;
    revoke_quietly(&p.server, &p.token, p.token_id, p.ca_file.as_deref()).await;
    if file.default.as_deref() == Some(name.as_str()) {
        file.default = None;
    }
    file.save()?;
    println!("Signed out of {} (profile '{name}' removed)", p.server);
    Ok(())
}

pub fn profiles(use_: Option<String>) -> Result<()> {
    let mut file = config::File::load()?;
    if let Some(n) = use_ {
        if !file.profiles.contains_key(&n) {
            bail!("no profile '{n}'");
        }
        file.default = Some(n.clone());
        file.save()?;
        println!("Default profile: {n}");
        return Ok(());
    }
    if file.profiles.is_empty() {
        println!("No profiles. Sign in with `rdns login <server>`.");
        return Ok(());
    }
    let default = file.pick(None);
    let rows: Vec<Vec<String>> = file
        .profiles
        .iter()
        .map(|(n, p)| {
            vec![
                if default.as_deref() == Some(n) {
                    "*"
                } else {
                    ""
                }
                .into(),
                n.clone(),
                p.server.clone(),
                p.user.clone().unwrap_or_default(),
            ]
        })
        .collect();
    term::table(&["", "PROFILE", "SERVER", "USER"], &rows);
    Ok(())
}

pub async fn whoami(ctx: &Ctx) -> Result<()> {
    let me = ctx.api.get("/me").await?;
    ctx.show(&me, || {
        let u = &me["user"];
        let role = if u["is_root"].as_bool() == Some(true) {
            "root"
        } else if u["is_admin"].as_bool() == Some(true) {
            "administrator"
        } else {
            "user"
        };
        println!(
            "{} ({role}) on {} via {}",
            u["username"].as_str().unwrap_or("?"),
            ctx.api.server,
            me["via"].as_str().unwrap_or("?")
        );
    });
    Ok(())
}

/// The server only lets a signed-in session change a password, so this
/// signs in with the current one for the change and signs out again.
pub async fn passwd(ctx: &Ctx) -> Result<()> {
    let me = ctx.api.get("/me").await?;
    let user = me["user"]["username"]
        .as_str()
        .ok_or_else(|| anyhow!("the server did not say who you are"))?
        .to_string();
    if me["user"]["is_root"].as_bool() == Some(true) {
        bail!("the root password is set in the server's configuration file");
    }
    let current = term::ask_secret(&format!("Current password for {user}: "))?;
    let new = term::ask_new_password("New password: ")?;
    let s = ctx
        .api
        .session(&user, &current, || {
            term::ask("Authenticator code (or a recovery code): ")
        })
        .await?;
    let r = s
        .put(
            "/me/password",
            &json!({ "current_password": current, "new_password": new }),
        )
        .await;
    s.sign_out().await;
    r?;
    println!("Password changed for {user}. Your API tokens keep working.");
    Ok(())
}

/// The host part of a server URL: `https://[::1]:8053/x` -> `::1`.
fn profile_name(server: &str) -> String {
    let rest = server.split("://").nth(1).unwrap_or(server);
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6).to_string(),
        None => authority.split(':').next().unwrap_or(authority).to_string(),
    }
}

fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes at most buf.len() bytes into buf.
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..end]) {
                if !s.is_empty() {
                    return s.chars().take(80).collect();
                }
            }
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "cli".into())
}
