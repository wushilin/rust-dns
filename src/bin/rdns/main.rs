//! `rdns`: manage a rust-dns server from the command line (records, zones,
//! users, API tokens) through its REST API.
//!
//! A pure API client: every change goes through the server, which checks
//! the caller's rights and token scope and refuses writes on a standby.

mod account;
mod api;
mod config;
mod dns;
mod term;
mod token;
mod user;
mod zone;

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};

const EXAMPLES: &str = "\
Examples:
  rdns login https://dns.example.com -u alice
  rdns dns add www.example.com A 192.0.2.10 --ttl 300
  rdns dns add example.com MX 10 mail.example.com.
  rdns dns set www.example.com A 192.0.2.20
  rdns dns ls example.com
  rdns dns rm www.example.com A
  rdns zone add example.org --ns ns1.example.org. --email hostmaster@example.org
  rdns zone grant example.org bob --role viewer
  rdns user add bob --password 'correct-horse-battery'
  rdns user rm bob";

#[derive(Parser, Debug)]
#[command(
    name = "rdns",
    version,
    about = "Manage a rust-dns server: records, zones, users and API tokens",
    after_help = EXAMPLES,
    propagate_version = true
)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Global options")]
pub struct Global {
    /// Saved server profile to use (see `rdns login`).
    #[arg(short, long, global = true, env = "RDNS_PROFILE")]
    profile: Option<String>,
    /// Server URL, overriding the profile's.
    #[arg(short, long, global = true, env = "RDNS_SERVER")]
    server: Option<String>,
    /// API token (rdns_...), overriding the profile's. Prefer the variable:
    /// a token on the command line shows in the process list.
    #[arg(long, global = true, env = "RDNS_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Print the server's JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Sign in to a server and save it as a profile.
    Login(account::LoginArgs),
    /// Forget the saved token (and revoke it, when `rdns login` created it).
    Logout,
    /// Show who you are signed in as, and where.
    Whoami,
    /// Change your own password.
    Passwd,
    /// List saved profiles, or choose the default one.
    Profile {
        /// Make this profile the default.
        #[arg(long = "use", value_name = "NAME")]
        use_: Option<String>,
    },
    /// Records: list, add, replace, delete.
    #[command(subcommand, visible_alias = "record", visible_alias = "r")]
    Dns(dns::Cmd),
    /// Zones: create, change, rename, delete, grant access, import, export.
    #[command(subcommand, visible_alias = "z")]
    Zone(zone::Cmd),
    /// User accounts (administrators).
    #[command(subcommand, visible_alias = "u")]
    User(user::Cmd),
    /// API tokens.
    #[command(subcommand)]
    Token(token::Cmd),
}

/// What every command needs: a signed-in client and the output mode.
pub struct Ctx {
    pub api: api::Client,
    pub json: bool,
}

impl Ctx {
    /// Print `v` as JSON when `--json`, else run `human`.
    pub fn show(&self, v: &serde_json::Value, human: impl FnOnce()) {
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
            );
        } else {
            human();
        }
    }
}

/// The client for a command: `--server`/`--token` (or their variables)
/// over the selected profile.
pub fn connect(g: &Global) -> Result<Ctx> {
    let file = config::File::load()?;
    let name = file.pick(g.profile.as_deref());
    let profile = match &name {
        Some(n) => file.profiles.get(n).cloned(),
        None => None,
    };
    if let (Some(n), None) = (&g.profile, &profile) {
        return Err(anyhow!("no profile '{n}' (rdns profile lists them)"));
    }
    let server = match (&g.server, &profile) {
        (Some(s), _) => config::normalize_server(s)?,
        (None, Some(p)) => p.server.clone(),
        (None, None) => {
            return Err(anyhow!(
                "not signed in: run `rdns login <server>` (or set RDNS_SERVER and RDNS_TOKEN)"
            ))
        }
    };
    let token = g
        .token
        .clone()
        .or_else(|| profile.as_ref().map(|p| p.token.clone()))
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("no API token: run `rdns login {server}` or set RDNS_TOKEN"))?;
    let ca = profile.as_ref().and_then(|p| p.ca_file.clone());
    Ok(Ctx {
        api: api::Client::new(&server, Some(token), ca.as_deref())?,
        json: g.json,
    })
}

async fn run(cli: Cli) -> Result<()> {
    let g = &cli.global;
    match cli.cmd {
        Cmd::Login(a) => account::login(g, a).await,
        Cmd::Logout => account::logout(g).await,
        Cmd::Profile { use_ } => account::profiles(use_),
        Cmd::Whoami => account::whoami(&connect(g)?).await,
        Cmd::Passwd => account::passwd(&connect(g)?).await,
        Cmd::Dns(c) => dns::run(&connect(g)?, c).await,
        Cmd::Zone(c) => zone::run(&connect(g)?, c).await,
        Cmd::User(c) => user::run(&connect(g)?, c).await,
        Cmd::Token(c) => token::run(&connect(g)?, c).await,
    }
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(run(cli)) {
        eprintln!("rdns: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}
