//! Blocklists (I7): domain lists downloaded by each server, kept in memory
//! in a compact form and consulted for forwarded queries only (own and
//! override zones always win: they are answered before the `blocklist`
//! filter runs).
//!
//! Only the configuration (URLs, allowlist, action, refresh interval)
//! replicates, as the `blocklists` console setting. Each server downloads
//! and parses the lists itself, keeps the last good copy of each when a
//! refresh fails, and swaps the compiled set atomically.
//!
//! Matching is by suffix: an entry `ads.example.com` blocks that name and
//! every name below it. The allowlist wins over every list, also by suffix.
//!
//! Memory: a list is a sorted `Vec<u64>` of keyed 64-bit hashes of its
//! domains (8 bytes per entry; a lookup is one binary search per label of
//! the query name). The hash key is random per process, so nobody can craft
//! names that collide with an entry; an accidental collision of two of
//! 2^64 values is negligible (about 1M^2 / 2^65 = 3e-8 for 1M entries
//! against all names ever asked). The domain text itself is not kept.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use utoipa::ToSchema;

/// Settings key in the `settings` table.
pub const SETTINGS_KEY: &str = "blocklists";
pub const MAX_LISTS: usize = 32;
pub const MAX_ALLOW: usize = 1000;
/// Largest download accepted per list.
pub const MAX_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;
/// Most entries kept per list (the rest of a larger list is ignored and
/// the status says so).
pub const MAX_ENTRIES_PER_LIST: usize = 2_000_000;

/// What a blocked name is answered with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockAction {
    /// NXDOMAIN.
    #[default]
    Nxdomain,
    /// `0.0.0.0` for A, `::` for AAAA, NODATA for other types.
    NullAddress,
}

/// One list to download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BlocklistSource {
    /// Display name.
    #[schema(example = "StevenBlack hosts")]
    pub name: String,
    /// `https://` (or `http://`) URL of a hosts file, a plain list of
    /// domains or an Adblock-style list (`||domain^`); the format is
    /// detected per line.
    #[schema(example = "https://blocklists.example/hosts.txt")]
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn default_refresh_hours() -> u32 {
    24
}

/// The blocklist configuration (replicated; downloads are per server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BlocklistSettings {
    #[serde(default)]
    pub lists: Vec<BlocklistSource>,
    /// Domains never blocked (suffix match: `example.com` also allows
    /// `www.example.com`).
    #[serde(default)]
    #[schema(example = json!(["example.com"]))]
    pub allow: Vec<String>,
    #[serde(default)]
    pub action: BlockAction,
    /// Hours between downloads of each list (1 to 168).
    #[serde(default = "default_refresh_hours")]
    #[schema(example = 24)]
    pub refresh_hours: u32,
}

impl Default for BlocklistSettings {
    fn default() -> Self {
        BlocklistSettings {
            lists: Vec::new(),
            allow: Vec::new(),
            action: BlockAction::Nxdomain,
            refresh_hours: default_refresh_hours(),
        }
    }
}

impl BlocklistSettings {
    /// Any list switched on (the `blocklist` filter is in the chain).
    pub fn active(&self) -> bool {
        self.lists.iter().any(|l| l.enabled)
    }

    /// Validate and normalise user input; every problem is listed.
    pub fn validate(mut self) -> Result<Self, Vec<String>> {
        let mut errs = Vec::new();
        if self.lists.len() > MAX_LISTS {
            errs.push(format!("at most {MAX_LISTS} lists"));
        }
        let mut urls: Vec<String> = Vec::new();
        for l in &mut self.lists {
            l.name = l.name.trim().to_string();
            l.url = l.url.trim().to_string();
            if l.name.is_empty() {
                l.name = l.url.clone();
            }
            match reqwest::Url::parse(&l.url) {
                Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => {}
                _ => errs.push(format!("'{}' is not an http(s) URL", l.url)),
            }
            if urls.contains(&l.url) {
                errs.push(format!("list {} is listed twice", l.url));
            }
            urls.push(l.url.clone());
        }
        let mut allow = Vec::new();
        for a in self
            .allow
            .iter()
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
        {
            match normalize_domain(a) {
                Some(d) => {
                    if !allow.contains(&d) {
                        allow.push(d)
                    }
                }
                None => errs.push(format!("'{a}' is not a domain name")),
            }
        }
        if allow.len() > MAX_ALLOW {
            errs.push(format!("at most {MAX_ALLOW} allowlist entries"));
        }
        self.allow = allow;
        if !(1..=168).contains(&self.refresh_hours) {
            errs.push("refresh_hours must be between 1 and 168".into());
        }
        if errs.is_empty() {
            Ok(self)
        } else {
            Err(errs)
        }
    }
}

fn hasher() -> &'static std::collections::hash_map::RandomState {
    static H: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    H.get_or_init(std::collections::hash_map::RandomState::new)
}

/// Keyed hash of a lower-case domain without the trailing dot.
fn hash(domain: &str) -> u64 {
    let mut h = hasher().build_hasher();
    h.write(domain.as_bytes());
    h.finish()
}

/// Lower-case, no trailing dot, `*.` prefix removed; `None` unless it is a
/// plausible host name with at least two labels (a single label would
/// block a whole top-level domain).
pub fn normalize_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.');
    let s = s.strip_prefix("*.").unwrap_or(s);
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let ok = lower.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    // An address is not a domain (hosts files list "0.0.0.0 0.0.0.0").
    (ok && lower.parse::<std::net::IpAddr>().is_err()).then_some(lower)
}

/// Domains of a list in any of the three formats (detected per line):
/// hosts (`0.0.0.0 ads.example.com [more names]`), plain (`ads.example.com`)
/// and Adblock (`||ads.example.com^`). Comments (`#`, `!`), Adblock headers
/// and rules with options or exceptions are skipped. Returns the domains
/// (at most `max`) and how many lines were skipped as not understood.
pub fn parse(text: &str, max: usize) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        if out.len() >= max {
            break;
        }
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        if let Some(rest) = line.strip_prefix("||") {
            match rest.strip_suffix('^').and_then(normalize_domain) {
                Some(d) => out.push(d),
                None => skipped += 1,
            }
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else {
            continue;
        };
        if first.parse::<std::net::IpAddr>().is_ok() {
            // hosts format: every name after the address.
            for w in words {
                if out.len() >= max {
                    break;
                }
                // Skips localhost, broadcasthost, ip6-loopback, ...
                if let Some(d) = normalize_domain(w) {
                    out.push(d);
                }
            }
            continue;
        }
        match (normalize_domain(first), words.next()) {
            (Some(d), None) => out.push(d),
            _ => skipped += 1,
        }
    }
    (out, skipped)
}

/// A compact set of domains matched by suffix (see the module docs).
#[derive(Default)]
pub struct DomainSet {
    hashes: Vec<u64>,
}

impl DomainSet {
    pub fn new<'a>(domains: impl IntoIterator<Item = &'a str>) -> Self {
        let mut hashes: Vec<u64> = domains.into_iter().map(hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes.shrink_to_fit();
        DomainSet { hashes }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Bytes held by the set.
    pub fn heap_bytes(&self) -> usize {
        self.hashes.capacity() * std::mem::size_of::<u64>()
    }

    /// The suffix of `name` (lower-case, no trailing dot) that is in the
    /// set, if any: the name itself or one of its parents.
    pub fn matching_suffix<'n>(&self, name: &'n str) -> Option<&'n str> {
        if self.is_empty() {
            return None;
        }
        let mut cur = name;
        loop {
            if !cur.is_empty() && self.hashes.binary_search(&hash(cur)).is_ok() {
                return Some(cur);
            }
            cur = cur.split_once('.')?.1;
        }
    }
}

/// One downloaded list.
pub struct LoadedList {
    pub url: String,
    pub name: String,
    /// Shared with the download slot (no copy per recompile).
    pub set: Arc<DomainSet>,
}

/// What the `blocklist` filter consults; swapped whole.
#[derive(Default)]
pub struct Compiled {
    pub lists: Vec<LoadedList>,
    pub allow: DomainSet,
    pub action: BlockAction,
}

/// Why a name is blocked: the list and the entry that matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlockMatch {
    /// Name of the list.
    pub list: String,
    pub url: String,
    /// The entry that matched (the name or a parent of it).
    pub entry: String,
}

/// The outcome of a name test (`POST /blocklists/test`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlockTest {
    /// The name tested (lower-case, no trailing dot).
    pub name: String,
    /// Blocked (forwarded queries for it are answered by the block action).
    pub blocked: bool,
    /// The allowlist entry that exempts it, if any.
    #[schema(required = true)]
    pub allowed_by: Option<String>,
    /// Every list entry that matches.
    pub matches: Vec<BlockMatch>,
}

impl Compiled {
    /// The list that blocks `name` (lower-case, no trailing dot), unless
    /// the allowlist exempts it.
    pub fn blocks(&self, name: &str) -> Option<usize> {
        if self.allow.matching_suffix(name).is_some() {
            return None;
        }
        self.lists
            .iter()
            .position(|l| l.set.matching_suffix(name).is_some())
    }

    pub fn test(&self, name: &str) -> BlockTest {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let allowed_by = self.allow.matching_suffix(&name).map(str::to_string);
        let matches: Vec<BlockMatch> = self
            .lists
            .iter()
            .filter_map(|l| {
                l.set.matching_suffix(&name).map(|e| BlockMatch {
                    list: l.name.clone(),
                    url: l.url.clone(),
                    entry: e.to_string(),
                })
            })
            .collect();
        BlockTest {
            blocked: allowed_by.is_none() && !matches.is_empty(),
            allowed_by,
            matches,
            name,
        }
    }
}

/// Download state of one list on this server.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct ListStatus {
    pub url: String,
    pub name: String,
    pub enabled: bool,
    /// Domains in the copy in use (0 before the first good download).
    pub entries: usize,
    /// Lines not understood in the last good download.
    pub skipped_lines: usize,
    /// The list had more than the per-list maximum; the rest was ignored.
    pub capped: bool,
    /// Time of the last good download.
    #[schema(required = true, format = DateTime)]
    pub loaded_at: Option<String>,
    /// Time of the last attempt.
    #[schema(required = true, format = DateTime)]
    pub attempted_at: Option<String>,
    /// Error of the last attempt (the last good copy stays in use).
    #[schema(required = true)]
    pub error: Option<String>,
    /// Forwarded queries this list blocked since start.
    pub blocked: u64,
}

struct Slot {
    status: ListStatus,
    domains: Option<Arc<DomainSet>>,
    next_due: Option<std::time::Instant>,
}

/// Per-server blocklist state: the compiled set the DNS path reads, the
/// downloaded copies and their status.
pub struct Blocklists {
    compiled: arc_swap::ArcSwap<Compiled>,
    state: Mutex<(BlocklistSettings, HashMap<String, Slot>)>,
    wake: tokio::sync::Notify,
    /// Queries blocked since start (all lists).
    pub blocked: std::sync::atomic::AtomicU64,
}

impl Default for Blocklists {
    fn default() -> Self {
        Blocklists {
            compiled: arc_swap::ArcSwap::from_pointee(Compiled::default()),
            state: Mutex::new((BlocklistSettings::default(), HashMap::new())),
            wake: tokio::sync::Notify::new(),
            blocked: Default::default(),
        }
    }
}

impl Blocklists {
    pub fn compiled(&self) -> arc_swap::Guard<Arc<Compiled>> {
        self.compiled.load()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (BlocklistSettings, HashMap<String, Slot>)> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn settings(&self) -> BlocklistSettings {
        self.lock().0.clone()
    }

    /// Apply new settings: lists no longer configured are dropped, new
    /// ones are downloaded by the refresh task (woken now).
    pub fn configure(&self, s: BlocklistSettings) {
        {
            let mut g = self.lock();
            let (settings, slots) = &mut *g;
            slots.retain(|url, _| s.lists.iter().any(|l| &l.url == url));
            for l in &s.lists {
                let slot = slots.entry(l.url.clone()).or_insert_with(|| Slot {
                    status: ListStatus {
                        url: l.url.clone(),
                        ..Default::default()
                    },
                    domains: None,
                    next_due: None,
                });
                slot.status.name = l.name.clone();
                slot.status.enabled = l.enabled;
            }
            *settings = s;
            self.recompile(settings, slots);
        }
        self.wake.notify_one();
    }

    fn recompile(&self, settings: &BlocklistSettings, slots: &HashMap<String, Slot>) {
        let lists = settings
            .lists
            .iter()
            .filter(|l| l.enabled)
            .filter_map(|l| {
                let slot = slots.get(&l.url)?;
                let set = slot.domains.clone()?;
                Some(LoadedList {
                    url: l.url.clone(),
                    name: l.name.clone(),
                    set,
                })
            })
            .collect();
        self.compiled.store(Arc::new(Compiled {
            lists,
            allow: DomainSet::new(settings.allow.iter().map(String::as_str)),
            action: settings.action,
        }));
    }

    /// Count a blocked query against list `i` of the compiled set.
    pub fn count(&self, compiled: &Compiled, i: usize) {
        self.blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(l) = compiled.lists.get(i) {
            if let Some(s) = self.lock().1.get_mut(&l.url) {
                s.status.blocked += 1;
            }
        }
    }

    /// Status of every configured list, in configuration order.
    pub fn status(&self) -> Vec<ListStatus> {
        let g = self.lock();
        g.0.lists
            .iter()
            .filter_map(|l| g.1.get(&l.url).map(|s| s.status.clone()))
            .collect()
    }

    /// Install a downloaded list (or record the failure; the last good
    /// copy stays in use).
    pub fn loaded(&self, url: &str, result: Result<String, String>) {
        let now = crate::model::now_rfc3339();
        let parsed = result.map(|text| parse(&text, MAX_ENTRIES_PER_LIST + 1));
        let mut g = self.lock();
        let refresh = std::time::Duration::from_secs(u64::from(g.0.refresh_hours.max(1)) * 3600);
        let (settings, slots) = &mut *g;
        let Some(slot) = slots.get_mut(url) else {
            return; // removed meanwhile
        };
        slot.status.attempted_at = Some(now.clone());
        match parsed {
            Ok((mut domains, skipped)) => {
                slot.status.capped = domains.len() > MAX_ENTRIES_PER_LIST;
                domains.truncate(MAX_ENTRIES_PER_LIST);
                let set = DomainSet::new(domains.iter().map(String::as_str));
                slot.status.entries = set.len();
                slot.status.skipped_lines = skipped;
                slot.status.loaded_at = Some(now);
                slot.status.error = None;
                slot.domains = Some(Arc::new(set));
                slot.next_due = Some(std::time::Instant::now() + refresh);
            }
            Err(e) => {
                slot.status.error = Some(e);
                // Retry sooner than a full interval: in 15 minutes.
                slot.next_due = Some(
                    std::time::Instant::now()
                        + refresh.min(std::time::Duration::from_secs(15 * 60)),
                );
            }
        }
        self.recompile(settings, slots);
    }

    /// Lists due for a download now, and when the next one is due.
    fn due(&self) -> (Vec<String>, Option<std::time::Instant>) {
        let now = std::time::Instant::now();
        let g = self.lock();
        let mut due = Vec::new();
        let mut next: Option<std::time::Instant> = None;
        for l in g.0.lists.iter().filter(|l| l.enabled) {
            let Some(slot) = g.1.get(&l.url) else {
                continue;
            };
            match slot.next_due {
                None => due.push(l.url.clone()),
                Some(t) if t <= now => due.push(l.url.clone()),
                Some(t) => next = Some(next.map_or(t, |n: std::time::Instant| n.min(t))),
            }
        }
        (due, next)
    }

    /// Mark every list due (the console's "refresh now").
    pub fn refresh_now(&self) {
        for s in self.lock().1.values_mut() {
            s.next_due = None;
        }
        self.wake.notify_one();
    }

    /// The download task: fetch what is due, sleep until the next list is
    /// due or the settings change.
    pub async fn run(self: Arc<Self>, client: reqwest::Client) {
        loop {
            let (due, next) = self.due();
            for url in due {
                let r = download(&client, &url).await;
                match &r {
                    Ok(t) => tracing::info!(%url, bytes = t.len(), "blocklist downloaded"),
                    Err(e) => {
                        tracing::warn!(%url, error = %e, "blocklist download failed; keeping the last good copy")
                    }
                }
                self.loaded(&url, r);
            }
            let sleep = next
                .map(|t| t.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or(std::time::Duration::from_secs(3600));
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(sleep) => {}
            }
        }
    }
}

/// Download one list (size-limited, 60 s overall).
pub async fn download(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let fetch = async {
        let mut resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("reading the body failed: {e}"))?
        {
            if body.len() + chunk.len() > MAX_DOWNLOAD_BYTES {
                return Err(format!(
                    "larger than {} MiB",
                    MAX_DOWNLOAD_BYTES / 1024 / 1024
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), fetch)
        .await
        .map_err(|_| "timed out after 60 s".to_string())?
}

/// The HTTP client for downloads (rustls with ring, OS trust store).
pub fn http_client() -> reqwest::Client {
    crate::replication::ensure_crypto();
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!(
            "rust-dns/",
            env!("CARGO_PKG_VERSION"),
            " blocklists"
        ))
        .build()
        .expect("HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_parses() {
        let text = "\
# hosts file
127.0.0.1 localhost
::1 ip6-localhost ip6-loopback
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com tracker.example.net # trailing comment
127.0.0.1\tAds2.Example.Com.
! Adblock
[Adblock Plus 2.0]
||adblock.example.org^
||with-options.example.org^$third-party
@@||exception.example.org^
plain.example.io
*.wild.example.io
two words.example.io
single
";
        let (d, skipped) = parse(text, 100);
        assert_eq!(
            d,
            vec![
                "ads.example.com",
                "tracker.example.net",
                "ads2.example.com",
                "adblock.example.org",
                "plain.example.io",
                "wild.example.io",
            ]
        );
        assert_eq!(skipped, 4, "options, exception, two words, single label");
        let (d, _) = parse(text, 2);
        assert_eq!(d.len(), 2, "capped");
    }

    #[test]
    fn suffix_matching_and_the_allowlist() {
        let c = Compiled {
            lists: vec![
                LoadedList {
                    url: "u1".into(),
                    name: "one".into(),
                    set: Arc::new(DomainSet::new(["ads.example.com", "tracker.net"])),
                },
                LoadedList {
                    url: "u2".into(),
                    name: "two".into(),
                    set: Arc::new(DomainSet::new(["tracker.net"])),
                },
            ],
            allow: DomainSet::new(["good.tracker.net"]),
            action: BlockAction::Nxdomain,
        };
        assert_eq!(c.blocks("ads.example.com"), Some(0));
        assert_eq!(c.blocks("x.y.ads.example.com"), Some(0), "below an entry");
        assert_eq!(c.blocks("example.com"), None, "above an entry");
        assert_eq!(c.blocks("notads.example.com"), None, "label boundary");
        assert_eq!(c.blocks("a.tracker.net"), Some(0));
        assert_eq!(c.blocks("good.tracker.net"), None, "allowlisted");
        assert_eq!(
            c.blocks("x.good.tracker.net"),
            None,
            "allowlist is a suffix too"
        );
        let t = c.test("A.Tracker.Net.");
        assert!(t.blocked);
        assert_eq!(t.name, "a.tracker.net");
        assert_eq!(t.matches.len(), 2);
        assert_eq!(t.matches[1].entry, "tracker.net");
        let t = c.test("good.tracker.net");
        assert!(!t.blocked);
        assert_eq!(t.allowed_by.as_deref(), Some("good.tracker.net"));
    }

    #[test]
    fn settings_validate() {
        let s = BlocklistSettings {
            lists: vec![
                BlocklistSource {
                    name: " ".into(),
                    url: "https://lists.example/hosts".into(),
                    enabled: true,
                },
                BlocklistSource {
                    name: "x".into(),
                    url: "ftp://x".into(),
                    enabled: true,
                },
                BlocklistSource {
                    name: "dup".into(),
                    url: "https://lists.example/hosts".into(),
                    enabled: false,
                },
            ],
            allow: vec!["Example.COM.".into(), "nodot".into(), "".into()],
            action: BlockAction::NullAddress,
            refresh_hours: 0,
        };
        let errs = s.validate().unwrap_err();
        assert_eq!(errs.len(), 4, "{errs:?}");
        let ok = BlocklistSettings {
            lists: vec![BlocklistSource {
                name: "".into(),
                url: " https://lists.example/hosts ".into(),
                enabled: true,
            }],
            allow: vec!["Example.COM.".into(), "example.com".into()],
            ..Default::default()
        }
        .validate()
        .unwrap();
        assert_eq!(ok.lists[0].name, "https://lists.example/hosts");
        assert_eq!(ok.allow, vec!["example.com"]);
        // Stored settings of older/newer shapes load with defaults.
        let s: BlocklistSettings =
            serde_json::from_str(r#"{"lists":[{"name":"a","url":"https://a.example/x"}]}"#)
                .unwrap();
        assert!(s.lists[0].enabled && s.refresh_hours == 24 && s.action == BlockAction::Nxdomain);
    }

    /// Memory for 1M entries (I7): the set itself is 8 bytes per entry.
    #[test]
    fn a_million_entries_are_compact() {
        let names: Vec<String> = (0..1_000_000)
            .map(|i| format!("host{i}.ads{}.example.com", i % 977))
            .collect();
        let t = std::time::Instant::now();
        let set = DomainSet::new(names.iter().map(String::as_str));
        let built = t.elapsed();
        assert_eq!(set.len(), 1_000_000);
        assert_eq!(set.heap_bytes(), 8_000_000);
        let t = std::time::Instant::now();
        let mut hits = 0;
        for i in 0..100_000 {
            if set
                .matching_suffix(&format!("www.host{i}.ads{}.example.com", i % 977))
                .is_some()
            {
                hits += 1;
            }
        }
        assert_eq!(hits, 100_000);
        eprintln!(
            "1M entries: {} bytes, built in {built:?}; 100k suffix lookups in {:?}",
            set.heap_bytes(),
            t.elapsed()
        );
    }

    /// Download, keep the last good copy on failure, swap atomically.
    #[tokio::test]
    async fn refresh_keeps_the_last_good_copy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f2 = fail.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let resp = if f2.load(std::sync::atomic::Ordering::SeqCst) {
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
                } else {
                    let body =
                        "0.0.0.0 ads.example.com\n||tracker.example.net^\nplain.example.org\n";
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        let url = format!("http://127.0.0.1:{port}/list.txt");
        let b = Blocklists::default();
        b.configure(BlocklistSettings {
            lists: vec![BlocklistSource {
                name: "local".into(),
                url: url.clone(),
                enabled: true,
            }],
            ..Default::default()
        });
        let client = http_client();
        b.loaded(&url, download(&client, &url).await);
        assert_eq!(b.compiled().blocks("x.ads.example.com"), Some(0));
        assert_eq!(b.status()[0].entries, 3);
        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let r = download(&client, &url).await;
        assert!(r.as_ref().unwrap_err().contains("500"), "{r:?}");
        b.loaded(&url, r);
        assert_eq!(
            b.compiled().blocks("x.ads.example.com"),
            Some(0),
            "last good copy kept"
        );
        let st = &b.status()[0];
        assert_eq!(st.entries, 3);
        assert!(st.error.as_deref().unwrap().contains("500"));
        // Switching the list off removes it from the compiled set.
        b.configure(BlocklistSettings {
            lists: vec![BlocklistSource {
                name: "local".into(),
                url: url.clone(),
                enabled: false,
            }],
            ..Default::default()
        });
        assert_eq!(b.compiled().blocks("x.ads.example.com"), None);
    }
}
