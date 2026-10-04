//! O27: secondary zones (zones hosted elsewhere, served read-only here).
//!
//! A secondary zone is a zone row with a `secondary` spec (its primaries
//! and an optional TSIG key). The definition is ordinary replicated zone
//! data; the *content* is not: every server (primary and standbys alike)
//! is a secondary of the zone's primaries itself, exactly as several BIND
//! secondaries of one primary are. It checks the primary's SOA serial
//! every `refresh` seconds (from the transferred SOA; `retry` after a
//! failure), transfers with IXFR when it holds data (AXFR otherwise, or
//! when the primary answers an IXFR with the whole zone), refreshes at once
//! on a NOTIFY from a primary (or signed with the zone's key), and stops
//! serving the zone (SERVFAIL) when no refresh succeeded for `expire`
//! seconds. The transferred data is kept in the local table
//! `secondary_transfers` (bookkeeping, never replicated) so a restart
//! serves the last good copy until it expires. A standby never writes
//! replicated data for it; the changelog never carries transferred records
//! (they change whenever the primary changes, and a standby would need the
//! primary's data anyway to verify them).
//!
//! Nothing is signed here: a signed primary's DNSKEY, RRSIG and NSEC /
//! NSEC3 records are served as transferred
//! ([`crate::dnssec::SignedZone::from_transfer`]).

use crate::dns::tsig::{self, Chain, Key, ResponseVerifier, SignParams};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// DNSSEC record types served from the signed view, not as records.
pub fn is_dnssec_type(code: u16) -> bool {
    matches!(code, 46..=48 | 50 | 51)
}

/// `www` for `www.example.com.` in `example.com.`, `@` for the apex.
pub fn relative_name(owner: &str, apex: &str) -> String {
    if owner == apex {
        return "@".into();
    }
    if apex == "." {
        return owner.trim_end_matches('.').to_string();
    }
    owner
        .strip_suffix(&format!(".{apex}"))
        .unwrap_or(owner)
        .to_string()
}

/// A record's value in presentation format, as the catalog keeps it (used
/// for CNAME / DNAME targets and delegations).
pub fn value_text(r: &Record) -> String {
    if u16::from(r.record_type()) == 39 {
        if let Some(n) = crate::dnssec::wire::raw_rdata(r)
            .and_then(|b| crate::dnssec::wire::read_name(b, 0))
            .map(|(n, _)| n.to_ascii())
        {
            return n;
        }
    }
    r.data.to_string()
}

/// RFC 1982 serial comparison: `a` is newer than `b`.
pub fn serial_newer(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

/// The data of one secondary zone as last transferred.
#[derive(Debug, Clone)]
pub struct Transferred {
    pub serial: u32,
    /// Every record, the apex SOA first (once), DNSSEC types in raw form.
    pub records: Vec<Record>,
    /// Unix seconds of the last successful transfer or up-to-date check.
    pub refreshed_unix: i64,
    pub source: SocketAddr,
}

impl Transferred {
    pub fn soa(&self) -> Option<&Record> {
        self.records
            .first()
            .filter(|r| r.record_type() == RecordType::SOA)
    }

    fn soa_timers(&self) -> (u32, u32, u32) {
        match self.soa().map(|r| &r.data) {
            Some(RData::SOA(s)) => (
                s.refresh.max(1) as u32,
                s.retry.max(1) as u32,
                s.expire.max(1) as u32,
            ),
            _ => (3600, 600, 1_209_600),
        }
    }

    /// No successful refresh for the SOA expire time.
    pub fn expired_at(&self, now_unix: i64) -> bool {
        now_unix > self.refreshed_unix + self.soa_timers().2 as i64
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for r in &self.records {
            if let Ok(b) = r.to_bytes() {
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(&b);
            }
        }
        out
    }

    fn decode(mut b: &[u8]) -> Option<Vec<Record>> {
        let mut out = Vec::new();
        while !b.is_empty() {
            let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
            let rec = Record::from_bytes(b.get(4..4 + n)?).ok()?;
            out.push(raw_dnssec(rec));
            b = &b[4 + n..];
        }
        Some(out)
    }
}

/// What this server knows about one secondary zone (local, per server).
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct SecondaryStatus {
    /// `ok` (data current), `pending` (no data yet), `expired` (not
    /// refreshed within the SOA expire time: answered SERVFAIL), `error`
    /// (the last refresh failed; the data is still served until it expires).
    pub state: String,
    /// The serial served; `null` without data.
    #[schema(required = true)]
    pub serial: Option<u32>,
    /// Records served (DNSSEC records included).
    pub records: usize,
    /// Types the primary sends that this server does not serve.
    pub unsupported_types: Vec<String>,
    #[schema(required = true, format = DateTime)]
    pub last_transfer_at: Option<String>,
    /// `axfr` or `ixfr`.
    #[schema(required = true)]
    pub last_transfer: Option<String>,
    /// The last successful transfer or up-to-date check.
    #[schema(required = true, format = DateTime)]
    pub last_refresh_at: Option<String>,
    #[schema(required = true)]
    pub last_error: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub last_error_at: Option<String>,
    /// When the data stops being served without a refresh.
    #[schema(required = true, format = DateTime)]
    pub expires_at: Option<String>,
    /// The primary of the data served (`ip:port`).
    #[schema(required = true)]
    pub source: Option<String>,
    /// NOTIFYs accepted since start.
    pub notifies: u64,
    /// The data is signed by the primary (DNSKEY at the apex).
    pub signed: bool,
}

/// Transferred data and status of every secondary zone, by zone name.
#[derive(Default)]
pub struct Store {
    data: RwLock<HashMap<String, Arc<Transferred>>>,
    status: Mutex<HashMap<String, SecondaryStatus>>,
    wake: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
}

fn unix_rfc3339(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Store {
    pub fn get(&self, zone: &str) -> Option<Arc<Transferred>> {
        self.data
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(zone)
            .cloned()
    }

    fn put(&self, zone: &str, t: Arc<Transferred>) {
        self.data
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(zone.to_string(), t);
    }

    fn remove(&self, zone: &str) {
        self.data
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(zone);
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(zone);
    }

    fn status_mut<R>(&self, zone: &str, f: impl FnOnce(&mut SecondaryStatus) -> R) -> R {
        let mut g = self.status.lock().unwrap_or_else(|p| p.into_inner());
        f(g.entry(zone.to_string()).or_default())
    }

    /// The status of `zone` as of now.
    pub fn status(&self, zone: &str) -> SecondaryStatus {
        let mut st = self.status_mut(zone, |s| s.clone());
        match self.get(zone) {
            None => st.state = "pending".into(),
            Some(t) => {
                st.serial = Some(t.serial);
                st.records = t.records.len();
                st.signed = t.records.iter().any(|r| u16::from(r.record_type()) == 48);
                st.source = Some(t.source.to_string());
                st.last_refresh_at = Some(unix_rfc3339(t.refreshed_unix));
                st.expires_at = Some(unix_rfc3339(t.refreshed_unix + t.soa_timers().2 as i64));
                let mut unsupported: Vec<String> = t
                    .records
                    .iter()
                    .map(|r| r.record_type())
                    .filter(|rt| {
                        let c = u16::from(*rt);
                        !is_dnssec_type(c)
                            && *rt != RecordType::SOA
                            && !crate::model::RecordType::ALL
                                .iter()
                                .any(|m| u16::from(m.to_hickory()) == c)
                    })
                    .map(|rt| rt.to_string())
                    .collect();
                unsupported.sort();
                unsupported.dedup();
                st.unsupported_types = unsupported;
                st.state = if t.expired_at(now_unix()) {
                    "expired".into()
                } else if st.last_error.is_some() {
                    "error".into()
                } else {
                    "ok".into()
                };
            }
        }
        st
    }

    fn waker(&self, zone: &str) -> Arc<tokio::sync::Notify> {
        self.wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(zone.to_string())
            .or_default()
            .clone()
    }

    /// A NOTIFY for `zone` was accepted: refresh now.
    pub fn notified(&self, zone: &str) {
        self.status_mut(zone, |s| s.notifies += 1);
        self.waker(zone).notify_one();
    }

    /// Load what was transferred before a restart (startup, before the
    /// first catalog build).
    pub fn load(&self, storage: &crate::storage::Storage) -> anyhow::Result<usize> {
        let rows = storage.load_secondary_transfers()?;
        let n = rows.len();
        for (zone, serial, blob, at, source) in rows {
            let Some(records) = Transferred::decode(&blob) else {
                tracing::warn!(zone = %zone, "stored secondary zone data does not decode; transferring again");
                continue;
            };
            let refreshed_unix = chrono::DateTime::parse_from_rfc3339(&at)
                .map(|t| t.timestamp())
                .unwrap_or(0);
            self.put(
                &zone,
                Arc::new(Transferred {
                    serial,
                    records,
                    refreshed_unix,
                    source: source.parse().unwrap_or_else(|_| ([0, 0, 0, 0], 53).into()),
                }),
            );
        }
        Ok(n)
    }
}

/// A DNSSEC-type record in raw form (its RDATA bytes as an unknown type),
/// whatever hickory decoded it as: the signed view reads raw RDATA.
fn raw_dnssec(r: Record) -> Record {
    let code = u16::from(r.record_type());
    if !is_dnssec_type(code) || crate::dnssec::wire::raw_rdata(&r).is_some() {
        return r;
    }
    match r.data.to_bytes() {
        Ok(b) => crate::dnssec::wire::raw_record(r.name.clone(), r.ttl, code, b),
        Err(_) => r,
    }
}

/// Identity of a record for IXFR deletions: owner (lower case), type and
/// RDATA bytes.
fn identity(r: &Record) -> (String, u16, Vec<u8>) {
    (
        r.name.to_lowercase().to_ascii(),
        u16::from(r.record_type()),
        r.data.to_bytes().unwrap_or_default(),
    )
}

/// What a transfer produced.
#[derive(Debug)]
pub enum Outcome {
    /// The primary has nothing newer (IXFR answered with our SOA only).
    UpToDate,
    /// New data, and how it came: `axfr` or `ixfr`.
    Data(Vec<Record>, &'static str),
}

/// Interpret a transfer's answer records (every message's answer section
/// in order). `have`: our data for an IXFR (`None`: AXFR asked).
pub fn interpret(recs: Vec<Record>, have: Option<&[Record]>) -> anyhow::Result<Outcome> {
    use anyhow::bail;
    let soa_serial = |r: &Record| match &r.data {
        RData::SOA(s) => Some(s.serial),
        _ => None,
    };
    let Some(first) = recs.first() else {
        bail!("empty transfer");
    };
    let Some(new_serial) = soa_serial(first) else {
        bail!("transfer does not start with the SOA");
    };
    if recs.len() == 1 {
        if have.is_some() {
            return Ok(Outcome::UpToDate);
        }
        bail!("transfer holds only the SOA");
    }
    let last_is_soa = recs.last().and_then(soa_serial) == Some(new_serial);
    if !last_is_soa {
        bail!("transfer does not end with the SOA (incomplete)");
    }
    // AXFR form: SOA, records, SOA (also an IXFR answered with the zone).
    let incremental = have.is_some() && soa_serial(&recs[1]).is_some();
    if !incremental {
        let mut out: Vec<Record> = recs[..recs.len() - 1].to_vec();
        out = out.into_iter().map(raw_dnssec).collect();
        return Ok(Outcome::Data(out, "axfr"));
    }
    // IXFR (RFC 1995 §4): new SOA, then (old SOA, deletions..., new SOA,
    // additions...)*, then the new SOA.
    let have = have.unwrap_or_default();
    let mut set: Vec<Record> = have.iter().skip(1).cloned().collect();
    let body = &recs[1..recs.len() - 1];
    let mut i = 0;
    let mut current = have.first().and_then(soa_serial);
    while i < body.len() {
        let Some(from) = soa_serial(&body[i]) else {
            bail!("IXFR: expected the SOA of a difference sequence");
        };
        if Some(from) != current {
            bail!("IXFR: a difference starts at serial {from}, ours is {current:?}");
        }
        i += 1;
        while i < body.len() && soa_serial(&body[i]).is_none() {
            let id = identity(&raw_dnssec(body[i].clone()));
            let before = set.len();
            set.retain(|r| identity(r) != id);
            if set.len() == before {
                bail!("IXFR: deletes a record we do not hold");
            }
            i += 1;
        }
        let Some(to) = body.get(i).and_then(soa_serial) else {
            bail!("IXFR: difference sequence without its new SOA");
        };
        i += 1;
        while i < body.len() && soa_serial(&body[i]).is_none() {
            let r = raw_dnssec(body[i].clone());
            let id = identity(&r);
            set.retain(|x| identity(x) != id);
            set.push(r);
            i += 1;
        }
        current = Some(to);
    }
    if current != Some(new_serial) {
        bail!("IXFR: ends at serial {current:?}, not {new_serial}");
    }
    let mut out = vec![raw_dnssec(first.clone())];
    out.extend(set);
    Ok(Outcome::Data(out, "ixfr"))
}

fn query_msg(zone: &Name, qtype: RecordType, ours: Option<&Record>) -> Vec<u8> {
    let id = rand::random::<u16>();
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(zone.clone(), qtype));
    if let Some(soa) = ours {
        m.add_authority(soa.clone());
    }
    m.to_vec().unwrap_or_default()
}

fn sign(msg: Vec<u8>, key: Option<&Key>) -> (Vec<u8>, Vec<u8>) {
    match key {
        None => (msg, Vec::new()),
        Some(k) => {
            let id = u16::from_be_bytes([msg[0], msg[1]]);
            tsig::sign(
                &msg,
                k,
                Chain::Request,
                &SignParams {
                    time: tsig::now(),
                    fudge: tsig::MAX_FUDGE,
                    original_id: id,
                    error: 0,
                    other: Vec::new(),
                },
            )
        }
    }
}

const TIMEOUT: Duration = Duration::from_secs(10);

/// The primary's SOA serial (UDP, TCP when truncated).
pub async fn soa_serial(
    primary: SocketAddr,
    zone: &Name,
    key: Option<&Key>,
) -> anyhow::Result<u32> {
    let (msg, mac) = sign(query_msg(zone, RecordType::SOA, None), key);
    let bind = if primary.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.send_to(&msg, primary).await?;
    let mut buf = vec![0u8; 4096];
    let reply = loop {
        let (n, from) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("SOA query to {primary}: no answer"))??;
        if from == primary && n >= 12 && buf[..2] == msg[..2] {
            break buf[..n].to_vec();
        }
    };
    let reply = if reply[2] & 0x02 != 0 {
        let mut msgs = tcp_exchange(primary, &msg, key, &mac, false).await?;
        msgs.remove(0)
    } else {
        if let Some(k) = key {
            ResponseVerifier::new(k.clone(), &mac)
                .verify(&reply, tsig::now())
                .map_err(|e| anyhow::anyhow!("SOA answer from {primary}: {e}"))?;
        }
        reply
    };
    let m = Message::from_vec(&reply)?;
    if m.metadata.response_code != hickory_proto::op::ResponseCode::NoError {
        anyhow::bail!("SOA query to {primary}: {}", m.metadata.response_code);
    }
    m.answers
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(s) if r.name.to_lowercase() == zone.to_lowercase() => Some(s.serial),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("{primary} has no SOA for the zone (not authoritative?)"))
}

/// Send one TCP request and read its answer: one message, or (`stream`)
/// every message until the closing SOA of a transfer. Each is verified
/// against `key`.
async fn tcp_exchange(
    primary: SocketAddr,
    msg: &[u8],
    key: Option<&Key>,
    mac: &[u8],
    stream: bool,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut s = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(primary))
        .await
        .map_err(|_| anyhow::anyhow!("connect to {primary}: timed out"))??;
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    s.write_all(&framed).await?;
    let mut verifier = key.map(|k| ResponseVerifier::new(k.clone(), mac));
    let mut out = Vec::new();
    let mut soas = 0;
    let mut first_serial: Option<u32> = None;
    loop {
        let mut len = [0u8; 2];
        tokio::time::timeout(TIMEOUT, s.read_exact(&mut len))
            .await
            .map_err(|_| anyhow::anyhow!("transfer from {primary}: timed out"))??;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        tokio::time::timeout(TIMEOUT, s.read_exact(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("transfer from {primary}: timed out"))??;
        if buf.len() < 12 || buf[..2] != msg[..2] {
            anyhow::bail!("transfer from {primary}: unexpected message");
        }
        if let Some(v) = verifier.as_mut() {
            v.verify(&buf, tsig::now())
                .map_err(|e| anyhow::anyhow!("transfer from {primary}: {e}"))?;
        }
        if !stream {
            out.push(buf);
            return Ok(out);
        }
        let m = Message::from_vec(&buf)?;
        if m.metadata.response_code != hickory_proto::op::ResponseCode::NoError {
            anyhow::bail!(
                "transfer refused by {primary}: {}",
                m.metadata.response_code
            );
        }
        for r in &m.answers {
            if let RData::SOA(soa) = &r.data {
                match first_serial {
                    None => first_serial = Some(soa.serial),
                    Some(f) if f == soa.serial => soas += 1,
                    _ => {}
                }
            }
        }
        let n_answers = m.answers.len();
        out.push(buf);
        // Done: the closing SOA (a second occurrence of the first serial),
        // or an IXFR "up to date" answer (a lone SOA).
        if soas >= 1 || (out.len() == 1 && n_answers == 1 && first_serial.is_some()) {
            return Ok(out);
        }
        if out.len() > 100_000 {
            anyhow::bail!("transfer from {primary}: too many messages");
        }
    }
}

/// Transfer `zone` from `primary`: IXFR from `have` when given, else AXFR.
pub async fn transfer(
    primary: SocketAddr,
    zone: &Name,
    key: Option<&Key>,
    have: Option<&Transferred>,
) -> anyhow::Result<Outcome> {
    let qtype = if have.is_some() {
        RecordType::IXFR
    } else {
        RecordType::AXFR
    };
    let (msg, mac) = sign(query_msg(zone, qtype, have.and_then(|h| h.soa())), key);
    let msgs = tcp_exchange(primary, &msg, key, &mac, true).await?;
    let mut recs = Vec::new();
    for b in msgs {
        let m = Message::from_vec(&b)?;
        recs.extend(m.answers);
    }
    interpret(recs, have.map(|h| h.records.as_slice()))
}

/// What the refresh task needs.
pub struct Ctx {
    pub storage: Arc<crate::storage::Storage>,
    pub mutator: Arc<crate::mutation::Mutator>,
    pub cache: Arc<crate::cache::Cache>,
    pub dns: Arc<crate::dns::DnsServer>,
    pub store: Arc<Store>,
}

/// Start a refresh task for every secondary zone in the catalog (checked
/// every 2 seconds); a task ends when its zone is gone or no longer a
/// secondary, and its local data is removed then.
pub async fn run(ctx: Arc<Ctx>) {
    let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let cat = ctx.cache.load();
        let wanted: Vec<String> = cat
            .zones
            .values()
            .filter(|z| z.zone.is_secondary())
            .map(|z| z.zone.name.clone())
            .collect();
        running.retain(|name, h| {
            if wanted.contains(name) && !h.is_finished() {
                return true;
            }
            if !wanted.contains(name) {
                h.abort();
                ctx.store.remove(name);
                if let Err(e) = ctx.storage.delete_secondary_transfer(name) {
                    tracing::warn!(zone = %name, error = %e, "could not remove a secondary zone's local data");
                }
            }
            false
        });
        for name in wanted {
            if let std::collections::hash_map::Entry::Vacant(e) = running.entry(name) {
                let c = ctx.clone();
                let n = e.key().clone();
                e.insert(tokio::spawn(async move { zone_task(c, n).await }));
            }
        }
    }
}

/// The spec of `zone` in the catalog (`None`: gone or not a secondary).
fn spec_of(ctx: &Ctx, zone: &str) -> Option<(i64, crate::model::ZoneSecondary)> {
    let cat = ctx.cache.load();
    let z = cat.zones.get(&crate::model::zone_fqdn(zone))?;
    Some((z.zone.id, z.zone.secondary.as_deref()?.clone()))
}

async fn zone_task(ctx: Arc<Ctx>, zone: String) {
    let wake = ctx.store.waker(&zone);
    let mut expired_built = false;
    loop {
        let Some((id, spec)) = spec_of(&ctx, &zone) else {
            return;
        };
        let have = ctx.store.get(&zone);
        let (refresh, retry, _) = have
            .as_ref()
            .map(|t| t.soa_timers())
            .unwrap_or((3600, 600, 0));
        // Refresh when due: no data, or `refresh` seconds after the last
        // success (`retry` after the last failure).
        let failed_at = ctx.store.status_mut(&zone, |s| {
            s.last_error_at
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.timestamp())
        });
        let now = now_unix();
        let due = match &have {
            // No data yet: at once, then every minute after a failure.
            None => failed_at.map(|f| f + 60).unwrap_or(now),
            Some(t) => match failed_at.filter(|f| *f >= t.refreshed_unix) {
                Some(f) => f + retry as i64,
                None => t.refreshed_unix + refresh as i64,
            },
        };
        if let Some(t) = &have {
            let exp = t.expired_at(now);
            if exp && !expired_built {
                tracing::warn!(zone = %zone, "secondary zone expired: no refresh within the SOA expire time; answering SERVFAIL until a transfer succeeds");
                let _ = ctx.mutator.rebuild_zones(vec![id]).await;
            }
            expired_built = exp;
        }
        if due > now {
            let mut wait = (due - now) as u64;
            if let Some(t) = &have {
                let until_expiry = t.refreshed_unix + t.soa_timers().2 as i64 + 1 - now;
                if until_expiry > 0 {
                    wait = wait.min(until_expiry as u64);
                }
            }
            let notified = tokio::select! {
                _ = wake.notified() => true,
                _ = tokio::time::sleep(Duration::from_secs(wait.clamp(1, 3600))) => false,
            };
            if !notified {
                continue; // due now, or expired: recompute
            }
        }
        refresh_once(&ctx, &zone, id, &spec, have.as_deref()).await;
    }
}

/// One refresh: SOA check, transfer when newer, store and rebuild.
async fn refresh_once(
    ctx: &Ctx,
    zone: &str,
    id: i64,
    spec: &crate::model::ZoneSecondary,
    have: Option<&Transferred>,
) {
    let key = match &spec.key {
        None => None,
        Some(k) => match ctx.dns.tsig_keys.load().get(k) {
            Some(e) => Some(e.key.clone()),
            None => {
                fail(
                    ctx,
                    zone,
                    format!("TSIG key {k} does not exist (create it under TSIG keys)"),
                );
                return;
            }
        },
    };
    let Ok(name) = Name::from_ascii(crate::model::zone_fqdn(zone)) else {
        return;
    };
    let mut errors = Vec::new();
    for &p in &spec.primaries {
        let serial = match soa_serial(p, &name, key.as_ref()).await {
            Ok(s) => s,
            Err(e) => {
                errors.push(e.to_string());
                continue;
            }
        };
        let current = have;
        if let Some(h) = current {
            if !serial_newer(serial, h.serial) {
                // Up to date: the refresh succeeded.
                let t = Arc::new(Transferred {
                    refreshed_unix: now_unix(),
                    ..h.clone()
                });
                let expired = h.expired_at(now_unix());
                ctx.store.put(zone, t.clone());
                ctx.store.status_mut(zone, |s| {
                    s.last_error = None;
                    s.last_error_at = None;
                });
                persist(ctx, zone, &t);
                if expired {
                    let _ = ctx.mutator.rebuild_zones(vec![id]).await;
                }
                tracing::debug!(zone = %zone, primary = %p, serial, "secondary zone up to date");
                return;
            }
        }
        match transfer(p, &name, key.as_ref(), current).await {
            Ok(Outcome::UpToDate) => {
                if let Some(h) = current {
                    let t = Arc::new(Transferred {
                        refreshed_unix: now_unix(),
                        ..h.clone()
                    });
                    ctx.store.put(zone, t.clone());
                    persist(ctx, zone, &t);
                }
                return;
            }
            Ok(Outcome::Data(records, how)) => {
                let serial = match records.first().map(|r| &r.data) {
                    Some(RData::SOA(s)) => s.serial,
                    _ => serial,
                };
                let t = Arc::new(Transferred {
                    serial,
                    records,
                    refreshed_unix: now_unix(),
                    source: p,
                });
                ctx.store.put(zone, t.clone());
                ctx.store.status_mut(zone, |s| {
                    s.last_error = None;
                    s.last_error_at = None;
                    s.last_transfer = Some(how.to_string());
                    s.last_transfer_at = Some(unix_rfc3339(now_unix()));
                });
                persist(ctx, zone, &t);
                if let Err(e) = ctx.mutator.rebuild_zones(vec![id]).await {
                    tracing::error!(zone = %zone, error = %e, "catalog update after a transfer failed");
                }
                tracing::info!(zone = %zone, primary = %p, serial, records = t.records.len(), transfer = how, "secondary zone transferred");
                return;
            }
            Err(e) => {
                // An IXFR the primary could not serve: try a full transfer.
                if current.is_some() {
                    tracing::info!(zone = %zone, primary = %p, error = %e, "IXFR failed; trying AXFR");
                    if let Ok(Outcome::Data(records, _)) =
                        transfer(p, &name, key.as_ref(), None).await
                    {
                        let serial = match records.first().map(|r| &r.data) {
                            Some(RData::SOA(s)) => s.serial,
                            _ => serial,
                        };
                        let t = Arc::new(Transferred {
                            serial,
                            records,
                            refreshed_unix: now_unix(),
                            source: p,
                        });
                        ctx.store.put(zone, t.clone());
                        ctx.store.status_mut(zone, |s| {
                            s.last_error = None;
                            s.last_error_at = None;
                            s.last_transfer = Some("axfr".into());
                            s.last_transfer_at = Some(unix_rfc3339(now_unix()));
                        });
                        persist(ctx, zone, &t);
                        let _ = ctx.mutator.rebuild_zones(vec![id]).await;
                        return;
                    }
                }
                errors.push(e.to_string());
            }
        }
    }
    fail(ctx, zone, errors.join("; "));
}

fn fail(ctx: &Ctx, zone: &str, error: String) {
    tracing::warn!(zone = %zone, error = %error, "secondary zone refresh failed");
    ctx.store.status_mut(zone, |s| {
        s.last_error = Some(error);
        s.last_error_at = Some(unix_rfc3339(now_unix()));
    });
}

fn persist(ctx: &Ctx, zone: &str, t: &Transferred) {
    if let Err(e) = ctx.storage.save_secondary_transfer(
        zone,
        t.serial,
        &t.encode(),
        &unix_rfc3339(t.refreshed_unix),
        &t.source.to_string(),
    ) {
        tracing::warn!(zone = %zone, error = %e, "could not store a secondary zone's data locally");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, SOA};

    fn soa(serial: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("h.example.com.").unwrap(),
                serial,
                2,
                1,
                5,
                60,
            )),
        )
    }

    fn a(name: &str, ip: [u8; 4]) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            60,
            RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
        )
    }

    #[test]
    fn serials_compare_by_rfc1982() {
        assert!(serial_newer(2, 1));
        assert!(!serial_newer(1, 1));
        assert!(!serial_newer(1, 2));
        assert!(serial_newer(1, u32::MAX), "wraps around");
        assert!(!serial_newer(0x8000_0001, 1));
    }

    #[test]
    fn axfr_and_ixfr_answers_are_interpreted() {
        let www = a("www.example.com.", [192, 0, 2, 1]);
        let old = vec![soa(1), www.clone(), a("old.example.com.", [192, 0, 2, 2])];
        // AXFR.
        match interpret(
            vec![
                soa(1),
                www.clone(),
                a("old.example.com.", [192, 0, 2, 2]),
                soa(1),
            ],
            None,
        )
        .unwrap()
        {
            Outcome::Data(r, how) => {
                assert_eq!((r.len(), how), (3, "axfr"));
            }
            o => panic!("{o:?}"),
        }
        // IXFR up to date, and an IXFR answered with the whole zone.
        assert!(matches!(
            interpret(vec![soa(1)], Some(&old)).unwrap(),
            Outcome::UpToDate
        ));
        assert!(matches!(
            interpret(vec![soa(2), www.clone(), soa(2)], Some(&old)).unwrap(),
            Outcome::Data(_, "axfr")
        ));
        // Two difference sequences: 1 -> 2 deletes old, adds new; 2 -> 3
        // changes www.
        let new = a("new.example.com.", [192, 0, 2, 3]);
        let www3 = a("www.example.com.", [192, 0, 2, 9]);
        let ixfr = vec![
            soa(3),
            soa(1),
            a("old.example.com.", [192, 0, 2, 2]),
            soa(2),
            new.clone(),
            soa(2),
            www.clone(),
            soa(3),
            www3.clone(),
            soa(3),
        ];
        match interpret(ixfr, Some(&old)).unwrap() {
            Outcome::Data(r, how) => {
                assert_eq!(how, "ixfr");
                let names: Vec<String> =
                    r.iter().map(|r| format!("{} {}", r.name, r.data)).collect();
                assert_eq!(r.len(), 3, "{names:?}");
                assert!(matches!(&r[0].data, RData::SOA(s) if s.serial == 3));
                assert!(r.contains(&new) && r.contains(&www3) && !r.contains(&www));
            }
            o => panic!("{o:?}"),
        }
        // A difference from another serial, a deletion we do not hold, an
        // incomplete transfer: refused (the caller falls back to AXFR).
        assert!(interpret(vec![soa(3), soa(2), soa(3), soa(3)], Some(&old)).is_err());
        assert!(interpret(
            vec![
                soa(2),
                soa(1),
                a("nope.example.com.", [1, 1, 1, 1]),
                soa(2),
                soa(2)
            ],
            Some(&old)
        )
        .is_err());
        assert!(interpret(vec![soa(2), www.clone()], None).is_err());
    }

    #[test]
    fn stored_data_round_trips_and_expires() {
        let t = Transferred {
            serial: 7,
            records: vec![soa(7), a("www.example.com.", [192, 0, 2, 1])],
            refreshed_unix: 1000,
            source: "192.0.2.53:53".parse().unwrap(),
        };
        let back = Transferred::decode(&t.encode()).unwrap();
        assert_eq!(back, t.records);
        assert!(!t.expired_at(1005), "expire 5 s");
        assert!(t.expired_at(1006));
        assert_eq!(relative_name("www.example.com.", "example.com."), "www");
        assert_eq!(relative_name("example.com.", "example.com."), "@");
    }
}
