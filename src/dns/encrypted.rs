//! O29: DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484), inbound and
//! as forwarding upstreams. Off unless configured in `[encrypted_dns]`
//! (per server, in its config file; nothing replicates).
//!
//! Inbound, both carry the same queries as DNS over TCP and go through the
//! same path: admission (the per-client rate limit, C2) and every filter;
//! DoT connections also count against the TCP connection caps (total and
//! per client) and timeouts. DoH answers GET (`?dns=` base64url) and POST
//! (`application/dns-message`) on `doh_path`, over HTTP/2 or HTTP/1.1.
//!
//! As upstreams (`upstreams`: `tls://ip[:port][#name]`,
//! `https://host[:port]/path`), they replace `[forwarding].upstreams` for
//! the global forwarding (override zones keep their own plain upstreams);
//! tried in order, one query per connection (no pooling).

use super::{DnsServer, Proto, Reply};
use crate::config::EncryptedDnsConfig;
use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The server's TLS settings from its certificate and key files (PEM).
pub fn server_tls(cfg: &EncryptedDnsConfig, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    crate::replication::ensure_crypto();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cfg.cert_file)
        .with_context(|| format!("[encrypted_dns].cert_file '{}'", cfg.cert_file))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("[encrypted_dns].cert_file '{}'", cfg.cert_file))?;
    if certs.is_empty() {
        bail!(
            "[encrypted_dns].cert_file '{}' holds no certificate",
            cfg.cert_file
        );
    }
    let key = PrivateKeyDer::from_pem_file(&cfg.key_file)
        .with_context(|| format!("[encrypted_dns].key_file '{}'", cfg.key_file))?;
    let mut c = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("[encrypted_dns]: certificate and key do not match: {e}"))?;
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(c))
}

/// Bind and run the DoT and DoH listeners of `[encrypted_dns]`.
pub async fn serve(server: Arc<DnsServer>) {
    let cfg = server.encrypted.clone();
    if cfg.dot_listen.is_empty() && cfg.doh_listen.is_empty() {
        return;
    }
    let mut tasks = Vec::new();
    match server_tls(&cfg, &[b"dot"]) {
        Ok(tls) => {
            for addr in &cfg.dot_listen {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => {
                        tracing::info!(%addr, "listening for DNS over TLS");
                        tasks.push(tokio::spawn(run_dot(server.clone(), l, tls.clone())));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "cannot bind DNS over TLS"),
                }
            }
        }
        Err(e) if !cfg.dot_listen.is_empty() => {
            tracing::error!(error = %e, "DNS over TLS not started")
        }
        Err(_) => {}
    }
    match server_tls(&cfg, &[b"h2", b"http/1.1"]) {
        Ok(tls) => {
            for addr in &cfg.doh_listen {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => {
                        tracing::info!(%addr, path = %cfg.doh_path, "listening for DNS over HTTPS");
                        tasks.push(tokio::spawn(run_doh(server.clone(), l, tls.clone())));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "cannot bind DNS over HTTPS"),
                }
            }
        }
        Err(e) if !cfg.doh_listen.is_empty() => {
            tracing::error!(error = %e, "DNS over HTTPS not started")
        }
        Err(_) => {}
    }
    for t in tasks {
        let _ = t.await;
    }
}

const HANDSHAKE: Duration = Duration::from_secs(10);

async fn run_dot(
    server: Arc<DnsServer>,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Ok(permit) = server.tcp_slots.clone().try_acquire_owned() else {
            continue; // the TCP connection cap covers DoT too
        };
        let (server, acceptor) = (server.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            let Some(_slot) = server
                .tcp_per_client
                .acquire(peer.ip(), server.listen.max_tcp_connections_per_client)
            else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await else {
                tracing::debug!(%peer, "DoT handshake failed");
                return;
            };
            server
                .stats
                .dot
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = super::tcp::serve_stream(server, tls, peer).await;
        });
    }
}

async fn run_doh(
    server: Arc<DnsServer>,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
) {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let path = server.encrypted.doh_path.clone();
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Ok(permit) = server.tcp_slots.clone().try_acquire_owned() else {
            continue;
        };
        let (server, acceptor, path) = (server.clone(), acceptor.clone(), path.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            let Some(_slot) = server
                .tcp_per_client
                .acquire(peer.ip(), server.listen.max_tcp_connections_per_client)
            else {
                return;
            };
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await else {
                tracing::debug!(%peer, "DoH handshake failed");
                return;
            };
            let svc = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let (server, path) = (server.clone(), path.clone());
                    async move { Ok::<_, std::convert::Infallible>(doh(server, &path, peer, req).await) }
                },
            );
            let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            b.http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            let _ = b.serve_connection(TokioIo::new(tls), svc).await;
        });
    }
}

type Resp = hyper::Response<http_body_util::Full<bytes::Bytes>>;

fn status(code: u16, why: &str) -> Resp {
    hyper::Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(http_body_util::Full::new(bytes::Bytes::from(format!(
            "{why}\n"
        ))))
        .expect("response")
}

/// One DoH request (RFC 8484 §4.1): GET `?dns=<base64url>` or POST of
/// `application/dns-message`.
async fn doh(
    server: Arc<DnsServer>,
    path: &str,
    peer: SocketAddr,
    req: hyper::Request<hyper::body::Incoming>,
) -> Resp {
    use http_body_util::BodyExt;
    if req.uri().path() != path {
        return status(404, "not found");
    }
    let msg: Vec<u8> = match *req.method() {
        hyper::Method::GET => {
            let q = req.uri().query().unwrap_or("");
            let Some(v) = q.split('&').find_map(|kv| kv.strip_prefix("dns=")) else {
                return status(400, "missing dns parameter");
            };
            match data_encoding::BASE64URL_NOPAD.decode(v.trim_end_matches('=').as_bytes()) {
                Ok(b) => b,
                Err(_) => return status(400, "dns parameter is not base64url"),
            }
        }
        hyper::Method::POST => {
            let ct = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.eq_ignore_ascii_case("application/dns-message") {
                return status(415, "content-type must be application/dns-message");
            }
            let limited = http_body_util::Limited::new(req.into_body(), 65_535);
            match limited.collect().await {
                Ok(b) => b.to_bytes().to_vec(),
                Err(_) => return status(413, "message too large or body unreadable"),
            }
        }
        _ => return status(405, "use GET or POST"),
    };
    if msg.len() < 12 {
        return status(400, "not a DNS message");
    }
    server
        .stats
        .doh
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match server.handle(&msg, peer, Proto::Tcp).await {
        Reply::One(m) => {
            let ttl = min_ttl(&m);
            hyper::Response::builder()
                .status(200)
                .header("content-type", "application/dns-message")
                .header("cache-control", format!("max-age={ttl}"))
                .body(http_body_util::Full::new(bytes::Bytes::from(m)))
                .expect("response")
        }
        Reply::Many(_) => status(400, "zone transfers are not offered over DNS over HTTPS"),
        Reply::None => status(400, "no answer for this message"),
    }
}

/// RFC 8484 §5.1: the smallest TTL of the answer (0 without records).
fn min_ttl(m: &[u8]) -> u32 {
    use hickory_proto::serialize::binary::BinDecodable;
    hickory_proto::op::Message::from_bytes(m)
        .ok()
        .and_then(|m| {
            m.answers
                .iter()
                .chain(m.authorities.iter())
                .map(|r| r.ttl)
                .min()
        })
        .unwrap_or(0)
}

// ---- upstreams -----------------------------------------------------------

/// One encrypted upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// DNS over TLS to `addr`, verifying the certificate for `name`.
    Tls { addr: SocketAddr, name: String },
    /// DNS over HTTPS (POST) to `url`.
    Https { url: String },
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Tls { addr, name } => write!(f, "tls://{addr}#{name}"),
            Upstream::Https { url } => write!(f, "{url}"),
        }
    }
}

/// `tls://ip[:port][#name]` (port 853; name: the address) or
/// `https://host[:port]/path`.
pub fn parse_upstream(s: &str) -> Result<Upstream, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("tls://") {
        let (hostport, name) = match rest.split_once('#') {
            Some((h, n)) => (h, Some(n.trim().to_string())),
            None => (rest, None),
        };
        let addr: SocketAddr = hostport
            .parse()
            .or_else(|_| {
                hostport
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .map(|ip| SocketAddr::new(ip, 853))
            })
            .map_err(|_| format!("'{s}': tls:// takes an IP address with an optional port, e.g. tls://9.9.9.9:853#dns.quad9.net"))?;
        let name = name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| addr.ip().to_string());
        return Ok(Upstream::Tls { addr, name });
    }
    if s.starts_with("https://") {
        let u = reqwest::Url::parse(s).map_err(|e| format!("'{s}': {e}"))?;
        if u.host().is_none() || u.query().is_some() {
            return Err(format!(
                "'{s}': an https URL with a host and a path, e.g. https://1.1.1.1/dns-query"
            ));
        }
        return Ok(Upstream::Https { url: s.to_string() });
    }
    Err(format!(
        "'{s}': an encrypted upstream starts with tls:// or https://"
    ))
}

/// TLS clients for the upstreams (built once at startup).
pub struct Clients {
    tls: Arc<rustls::ClientConfig>,
    http: reqwest::Client,
}

impl Clients {
    /// `ca_file`: trust only these CAs (PEM); empty: the system trust store.
    pub fn new(ca_file: &str) -> Result<Self> {
        crate::replication::ensure_crypto();
        let ca_file = ca_file.trim();
        let mut tls = if ca_file.is_empty() {
            use rustls_platform_verifier::ConfigVerifierExt;
            rustls::ClientConfig::with_platform_verifier()
                .map_err(|e| anyhow!("system trust store: {e}"))?
        } else {
            use rustls::pki_types::pem::PemObject;
            let mut roots = rustls::RootCertStore::empty();
            for c in rustls::pki_types::CertificateDer::pem_file_iter(ca_file)
                .with_context(|| format!("[encrypted_dns].upstream_ca_file '{ca_file}'"))?
            {
                roots
                    .add(
                        c.with_context(|| format!("[encrypted_dns].upstream_ca_file '{ca_file}'"))?,
                    )
                    .map_err(|e| anyhow!("[encrypted_dns].upstream_ca_file: {e}"))?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        tls.alpn_protocols = vec![b"dot".to_vec()];
        let mut b = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("rust-dns/", env!("CARGO_PKG_VERSION"), " doh"));
        if !ca_file.is_empty() {
            b = b.tls_certs_only(crate::config::load_ca_file(
                "[encrypted_dns].upstream_ca_file",
                ca_file,
            )?);
        }
        Ok(Clients {
            tls: Arc::new(tls),
            http: b.build().map_err(|e| anyhow!("DoH client: {e}"))?,
        })
    }
}

async fn exchange_tls(
    c: &Clients,
    addr: SocketAddr,
    name: &str,
    msg: &[u8],
    to: Duration,
) -> Result<Vec<u8>> {
    let server_name = rustls::pki_types::ServerName::try_from(name.to_string())
        .map_err(|e| anyhow!("tls name '{name}': {e}"))?;
    let tcp = tokio::time::timeout(to, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("{addr}: connect timed out"))??;
    let _ = tcp.set_nodelay(true);
    let mut s = tokio::time::timeout(
        to,
        tokio_rustls::TlsConnector::from(c.tls.clone()).connect(server_name, tcp),
    )
    .await
    .map_err(|_| anyhow!("{addr}: TLS handshake timed out"))??;
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    let read = async {
        s.write_all(&framed).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    Ok(tokio::time::timeout(to, read)
        .await
        .map_err(|_| anyhow!("{addr}: no answer"))??)
}

async fn exchange_https(c: &Clients, url: &str, msg: &[u8], to: Duration) -> Result<Vec<u8>> {
    let r = c
        .http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .timeout(to)
        .body(msg.to_vec())
        .send()
        .await
        .map_err(|e| anyhow!("{url}: {e}"))?;
    if !r.status().is_success() {
        bail!("{url}: HTTP {}", r.status());
    }
    Ok(r.bytes().await.map_err(|e| anyhow!("{url}: {e}"))?.to_vec())
}

/// Forward `req` to the encrypted upstreams in order; the accepted answer
/// carries the client's ID and question bytes. DoH requests are sent with
/// ID 0 (RFC 8484 §4.1, cache friendly).
pub async fn forward(
    c: &Clients,
    ups: &[Upstream],
    req: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let span = super::forward::question_span(req)
        .ok_or_else(|| anyhow!("query has no single question"))?;
    let to = Duration::from_millis(timeout_ms.max(100));
    let mut last = anyhow!("no encrypted upstreams configured");
    for u in ups {
        let mut msg = req.to_vec();
        if matches!(u, Upstream::Https { .. }) {
            msg[0] = 0;
            msg[1] = 0;
        }
        let r = match u {
            Upstream::Tls { addr, name } => exchange_tls(c, *addr, name, &msg, to).await,
            Upstream::Https { url } => exchange_https(c, url, &msg, to).await,
        };
        match r {
            Ok(b)
                if b.len() >= 12
                    && b[2] & 0x80 != 0
                    && b.get(span.clone())
                        .is_some_and(|q| q.eq_ignore_ascii_case(&req[span.clone()]))
                    && b[..2] == msg[..2] =>
            {
                return Ok(super::forward::restore(req, &span, b));
            }
            Ok(_) => last = anyhow!("{u}: the answer does not match the query"),
            Err(e) => {
                tracing::debug!(upstream = %u, error = %e, "encrypted upstream failed");
                last = e;
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_parse() {
        assert_eq!(
            parse_upstream("tls://9.9.9.9#dns.quad9.net").unwrap(),
            Upstream::Tls {
                addr: "9.9.9.9:853".parse().unwrap(),
                name: "dns.quad9.net".into()
            }
        );
        assert_eq!(
            parse_upstream("tls://127.0.0.1:8853").unwrap(),
            Upstream::Tls {
                addr: "127.0.0.1:8853".parse().unwrap(),
                name: "127.0.0.1".into()
            }
        );
        assert_eq!(
            parse_upstream("tls://[2001:db8::1]").unwrap(),
            Upstream::Tls {
                addr: "[2001:db8::1]:853".parse().unwrap(),
                name: "2001:db8::1".into()
            }
        );
        assert!(matches!(
            parse_upstream("https://1.1.1.1/dns-query").unwrap(),
            Upstream::Https { .. }
        ));
        for bad in [
            "9.9.9.9",
            "tls://dns.quad9.net",
            "https://x/dns-query?dns=1",
            "udp://1.1.1.1",
        ] {
            assert!(parse_upstream(bad).is_err(), "{bad}");
        }
    }

    /// `--check` / startup refuse unusable `[encrypted_dns]` settings.
    #[test]
    fn config_is_validated() {
        let tls = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
        let check = |toml_text: &str| {
            let cfg: crate::config::Config = toml::from_str(toml_text).unwrap();
            crate::config::validate(&cfg).map_err(|e| format!("{e:#}"))
        };
        let ok = format!(
            "[encrypted_dns]\ncert_file = \"{c}\"\nkey_file = \"{k}\"\ndot_listen = [\"127.0.0.1:853\"]\nupstreams = [\"tls://9.9.9.9#dns.quad9.net\"]\nupstream_ca_file = \"{ca}\"\n",
            c = tls.join("server.pem").display(),
            k = tls.join("server.key").display(),
            ca = tls.join("ca.pem").display()
        );
        assert!(check(&ok).is_ok(), "{:?}", check(&ok));
        assert!(check("").is_ok(), "off by default");
        let e = check("[encrypted_dns]\ndoh_listen = [\"127.0.0.1:443\"]\n").unwrap_err();
        assert!(e.contains("need cert_file and key_file"), "{e}");
        let e = check("[encrypted_dns]\ncert_file = \"/nonexistent.pem\"\nkey_file = \"/nonexistent.key\"\ndot_listen = [\"127.0.0.1:853\"]\n").unwrap_err();
        assert!(e.contains("cert_file"), "{e}");
        let e = check("[encrypted_dns]\nupstreams = [\"udp://1.1.1.1\"]\n").unwrap_err();
        assert!(e.contains("tls:// or https://"), "{e}");
        assert!(
            toml::from_str::<crate::config::Config>("[encrypted_dns]\nbogus = 1\n").is_err(),
            "unknown keys are refused"
        );
    }

    #[test]
    fn doh_cache_lifetime_is_the_smallest_ttl() {
        use hickory_proto::op::{Message, MessageType, OpCode};
        use hickory_proto::rr::{rdata::A, Name, RData, Record};
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        for ttl in [300, 60, 120] {
            m.add_answer(Record::from_rdata(
                Name::from_ascii("a.").unwrap(),
                ttl,
                RData::A(A::new(192, 0, 2, 1)),
            ));
        }
        assert_eq!(min_ttl(&m.to_vec().unwrap()), 60);
        assert_eq!(
            min_ttl(
                &Message::new(0, MessageType::Response, OpCode::Query)
                    .to_vec()
                    .unwrap()
            ),
            0
        );
    }
}
