//! The REST API of a rust-dns server, as `rdns` uses it: an API token for
//! everything, and a short cookie session only where the server insists on
//! one (minting the token at `rdns login`, changing one's own password).
//! Every check (rights, token scope, read-only standby) is the server's.

use anyhow::{anyhow, Context, Result};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// A non-2xx answer: the server's `{ "error", "code" }`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub code: Option<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        match self.code.as_deref() {
            Some("login_required") if self.status == StatusCode::UNAUTHORIZED => {
                write!(f, " (sign in again with `rdns login`)")
            }
            _ => Ok(()),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct Client {
    http: reqwest::Client,
    /// `https://host[:port]`, without `/rust-dns/api`.
    pub server: String,
    auth: Auth,
}

enum Auth {
    None,
    Token(String),
    /// Cookies of a session and its CSRF token.
    Session {
        cookies: String,
        csrf: String,
    },
}

pub fn http_client(ca_file: Option<&str>) -> Result<reqwest::Client> {
    // ring, as the server uses: builds on every release target.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut b = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("rdns/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_file.map(str::trim).filter(|p| !p.is_empty()) {
        let pem = std::fs::read(path).with_context(|| format!("reading CA file {path}"))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("CA file {path}: not PEM certificates"))?;
        if certs.is_empty() {
            return Err(anyhow!("CA file {path} holds no certificate"));
        }
        b = b.tls_certs_only(certs);
    }
    Ok(b.build()?)
}

impl Client {
    pub fn new(server: &str, token: Option<String>, ca_file: Option<&str>) -> Result<Self> {
        Ok(Client {
            http: http_client(ca_file)?,
            server: server.to_string(),
            auth: token.map(Auth::Token).unwrap_or(Auth::None),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/rust-dns/api{path}", self.server)
    }

    pub async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut rq = self.http.request(method.clone(), self.url(path));
        match &self.auth {
            Auth::None => {}
            Auth::Token(t) => rq = rq.bearer_auth(t),
            Auth::Session { cookies, csrf } => {
                rq = rq
                    .header("Cookie", cookies)
                    .header("X-Requested-With", "rust-dns")
                    .header("X-CSRF-Token", csrf);
            }
        }
        if let Some(b) = body {
            rq = rq.json(b);
        }
        let resp = rq
            .send()
            .await
            .map_err(|e| anyhow!("cannot reach {}: {}", self.server, error_chain(&e)))?;
        decode(resp).await
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.call(Method::GET, path, None).await
    }
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.call(Method::POST, path, Some(body)).await
    }
    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.call(Method::PUT, path, Some(body)).await
    }
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.call(Method::DELETE, path, None).await
    }

    /// Sign in with a password (and a TOTP or recovery code from `code`
    /// when the account has MFA) and return a client on that session.
    pub async fn session(
        &self,
        username: &str,
        password: &str,
        code: impl FnOnce() -> Result<String>,
    ) -> Result<Client> {
        let resp = self
            .http
            .post(self.url("/auth/login"))
            .json(&json!({ "username": username, "password": password }))
            .send()
            .await
            .map_err(|e| anyhow!("cannot reach {}: {}", self.server, error_chain(&e)))?;
        let cookies = cookies_of(&resp);
        let v = decode(resp).await?;
        let s = Client {
            http: self.http.clone(),
            server: self.server.clone(),
            auth: Auth::Session {
                cookies,
                csrf: v["csrf_token"].as_str().unwrap_or_default().to_string(),
            },
        };
        match v["status"].as_str() {
            Some("ok") => Ok(s),
            Some("mfa_required") => {
                let code = code()?;
                s.post("/auth/mfa", &json!({ "code": code.trim() })).await?;
                Ok(s)
            }
            Some("enroll_required") => Err(anyhow!(
                "this account must set up an authenticator (MFA) first: sign in to the web console once, then run rdns again"
            )),
            other => Err(anyhow!("unexpected sign-in status {other:?}")),
        }
    }

    /// End a session client's session (a token client: nothing).
    pub async fn sign_out(&self) {
        if matches!(self.auth, Auth::Session { .. }) {
            let _ = self.post("/auth/logout", &json!({})).await;
        }
    }
}

/// `name=value` of every `Set-Cookie`, as one `Cookie` header.
fn cookies_of(resp: &reqwest::Response) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .map(str::trim)
        .filter(|c| c.contains('='))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn decode(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let v: Value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    if status.is_success() {
        return Ok(v);
    }
    let message = match &v {
        Value::Object(o) => o
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string()),
        Value::String(s) if !s.is_empty() => s.trim().to_string(),
        _ => status.to_string(),
    };
    Err(ApiError {
        status,
        message,
        code: v["code"].as_str().map(str::to_string),
    }
    .into())
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        let t = c.to_string();
        if !s.contains(&t) {
            s.push_str(": ");
            s.push_str(&t);
        }
        src = c.source();
    }
    s
}

/// Percent-encode one path segment (zone names, usernames).
pub fn seg(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// A query string from the pairs that have a value.
pub fn query(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", seg(v))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}
