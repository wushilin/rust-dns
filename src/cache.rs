//! In-memory catalog of all zones and records, rebuilt from storage after
//! every mutation and swapped in atomically. DNS lookups only ever read
//! from here.

use crate::model::*;
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// A single zone with its records indexed by owner name.
pub struct ZoneData {
    pub zone: Zone,
    /// Apex as a fully qualified lower-case name (`example.com.`).
    pub apex: String,
    /// Records grouped by fully qualified owner name.
    pub names: HashMap<String, Vec<Record>>,
    /// Every name that "exists" in the zone: owners plus empty non-terminals.
    pub existing: HashSet<String>,
    /// Names below the apex that hold NS records: delegation points.
    pub delegations: Vec<String>,
    /// The signed view when DNSSEC signing is on for this zone.
    pub signed: Option<Arc<crate::dnssec::SignedZone>>,
}

impl ZoneData {
    pub fn records_at(&self, owner: &str) -> Option<&Vec<Record>> {
        self.names.get(owner)
    }

    /// If `owner` is at or below a delegation point (but not the apex),
    /// return that delegation's owner name.
    pub fn delegation_for(&self, owner: &str) -> Option<&str> {
        self.delegations
            .iter()
            .filter(|d| owner == d.as_str() || owner.ends_with(&format!(".{d}")))
            .max_by_key(|d| d.len())
            .map(|s| s.as_str())
    }

    /// The zone cut `owner` is at or below, taking the highest one when
    /// delegations are nested (everything below the first cut belongs to
    /// the child). Used for signed zones.
    pub fn cut_for(&self, owner: &str) -> Option<&str> {
        self.delegations
            .iter()
            .filter(|d| owner == d.as_str() || crate::dnssec::signed::is_below(owner, d))
            .min_by_key(|d| d.len())
            .map(|s| s.as_str())
    }
}

pub struct Catalog {
    /// Keyed by apex fqdn.
    pub zones: BTreeMap<String, Arc<ZoneData>>,
    /// Auto-generated reverse index: `10.0.168.192.in-addr.arpa.` -> owner names.
    pub reverse: HashMap<String, Vec<String>>,
    pub built_at: String,
}

impl Catalog {
    pub fn empty() -> Self {
        Catalog {
            zones: BTreeMap::new(),
            reverse: HashMap::new(),
            built_at: now_rfc3339(),
        }
    }

    /// Build the catalog as of now: expired records are left out, so they stop
    /// answering, stop appearing in zone transfers and exports, and no longer
    /// produce automatic PTR answers. (Unsigned; tests.)
    #[cfg(test)]
    pub fn build(zones: Vec<Zone>, records: Vec<Record>) -> Self {
        Self::build_at(zones, records, &now_rfc3339())
    }

    /// Build the catalog and sign the zones that have DNSSEC on (with the
    /// zone's key from `keys`; a zone without a usable key is served
    /// unsigned and the error is kept by the signer).
    pub fn build_signed(
        zones: Vec<Zone>,
        records: Vec<Record>,
        keys: &[crate::replication::types::ReplDnssecKey],
        signer: &crate::dnssec::Signer,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut c = Self::build_at(zones, records, &now_s);
        let mut signed_ids = Vec::new();
        for zd in c.zones.values_mut() {
            if !zd.zone.dnssec {
                continue;
            }
            signed_ids.push(zd.zone.id);
            let Some(key) = keys.iter().find(|k| k.zone_id == zd.zone.id) else {
                tracing::error!(zone = %zd.zone.name, "DNSSEC is on but the zone has no key; serving it unsigned");
                continue;
            };
            if let Some(s) = signer.sign(zd, key, now.timestamp()) {
                if let Some(z) = Arc::get_mut(zd) {
                    z.signed = Some(s);
                }
            }
        }
        signer.retain(&signed_ids);
        c
    }

    pub fn build_at(zones: Vec<Zone>, records: Vec<Record>, now: &str) -> Self {
        let mut by_zone: HashMap<i64, Vec<Record>> = HashMap::new();
        for r in records.into_iter().filter(|r| !r.is_expired_at(now)) {
            by_zone.entry(r.zone_id).or_default().push(r);
        }
        let mut reverse: HashMap<String, Vec<String>> = HashMap::new();
        let mut out = BTreeMap::new();
        for zone in zones {
            let apex = zone.fqdn();
            let mut names: HashMap<String, Vec<Record>> = HashMap::new();
            let mut existing: HashSet<String> = HashSet::new();
            let mut delegations = Vec::new();
            existing.insert(apex.clone());
            for r in by_zone.remove(&zone.id).unwrap_or_default() {
                let owner = r.owner(&zone);
                // Register the owner and every ancestor up to the apex as existing.
                let mut cur = owner.clone();
                while cur != apex && !cur.is_empty() {
                    if !existing.insert(cur.clone()) {
                        break;
                    }
                    cur = match cur.split_once('.') {
                        Some((_, rest)) if !rest.is_empty() => rest.to_string(),
                        _ => ".".to_string(),
                    };
                }
                if r.rtype == RecordType::NS && owner != apex && !delegations.contains(&owner) {
                    delegations.push(owner.clone());
                }
                match r.rtype {
                    RecordType::A | RecordType::AAAA => {
                        if let Ok(ip) = r.value.parse::<std::net::IpAddr>() {
                            let key = reverse_name(&ip);
                            let list = reverse.entry(key).or_default();
                            if !list.contains(&owner) {
                                list.push(owner.clone());
                            }
                        }
                    }
                    _ => {}
                }
                names.entry(owner).or_default().push(r);
            }
            out.insert(
                apex.clone(),
                Arc::new(ZoneData {
                    zone,
                    apex,
                    names,
                    existing,
                    delegations,
                    signed: None,
                }),
            );
        }
        Catalog {
            zones: out,
            reverse,
            built_at: now_rfc3339(),
        }
    }

    /// Longest-suffix match: the zone that contains `qname` (fqdn, lower-case).
    pub fn find_zone(&self, qname: &str) -> Option<&Arc<ZoneData>> {
        let mut cur = qname;
        loop {
            if let Some(z) = self.zones.get(cur) {
                return Some(z);
            }
            if cur == "." {
                return None;
            }
            cur = match cur.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => rest,
                _ => ".",
            };
        }
    }

    /// Find records of any zone at an absolute owner name (used for CNAME
    /// chasing and glue).
    pub fn records_anywhere(&self, owner: &str) -> Option<(&Arc<ZoneData>, &Vec<Record>)> {
        let z = self.find_zone(owner)?;
        z.records_at(owner).map(|r| (z, r))
    }
}

pub struct Cache {
    inner: ArcSwap<Catalog>,
    /// Build tickets: taken before a build reads the database.
    next_ticket: std::sync::atomic::AtomicU64,
    /// Ticket of the catalog currently stored.
    stored_ticket: std::sync::Mutex<u64>,
}

impl Cache {
    pub fn new(catalog: Catalog) -> Self {
        Cache {
            inner: ArcSwap::from_pointee(catalog),
            next_ticket: std::sync::atomic::AtomicU64::new(1),
            stored_ticket: std::sync::Mutex::new(0),
        }
    }

    pub fn load(&self) -> Arc<Catalog> {
        self.inner.load_full()
    }

    /// Take a build ticket. Call it BEFORE reading the database for a
    /// rebuild: a build with a later ticket has read at least as new a state
    /// as any change committed before that ticket was taken.
    pub fn ticket(&self) -> u64 {
        self.next_ticket
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Store a catalog built under `ticket`, unless a catalog from a later
    /// ticket is already in place (a slower, older build must never replace
    /// a newer one). Returns whether it was stored.
    pub fn store_built(&self, ticket: u64, catalog: Catalog) -> bool {
        let mut stored = self.stored_ticket.lock().unwrap_or_else(|p| p.into_inner());
        if ticket <= *stored {
            return false;
        }
        *stored = ticket;
        self.inner.store(Arc::new(catalog));
        true
    }

    #[cfg(test)]
    pub fn store(&self, catalog: Catalog) {
        let t = self.ticket();
        self.store_built(t, catalog);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: i64, name: &str) -> Zone {
        Zone {
            id,
            name: name.into(),
            serial: 1,
            soa_mname: format!("ns1.{name}."),
            soa_rname: format!("hostmaster.{name}."),
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
            default_ttl: 60,
            created_at: String::new(),
            updated_at: String::new(),
            owner_id: None,
            dnssec: false,
        }
    }
    fn rec(id: i64, zone_id: i64, name: &str, t: RecordType, v: &str) -> Record {
        Record {
            id,
            zone_id,
            name: name.into(),
            rtype: t,
            value: v.into(),
            ttl: None,
            created_at: String::new(),
            updated_at: String::new(),
            expires_at: None,
        }
    }

    #[test]
    fn find_and_reverse() {
        let c = Catalog::build(
            vec![zone(1, "example.com"), zone(2, "sub.example.com")],
            vec![
                rec(1, 1, "www", RecordType::A, "10.0.0.1"),
                rec(2, 1, "a.b.c", RecordType::A, "10.0.0.2"),
                rec(3, 2, "@", RecordType::A, "10.0.0.3"),
                rec(4, 1, "deleg", RecordType::NS, "ns.deleg.example.com."),
            ],
        );
        assert_eq!(
            c.find_zone("www.example.com.").unwrap().apex,
            "example.com."
        );
        assert_eq!(
            c.find_zone("x.sub.example.com.").unwrap().apex,
            "sub.example.com."
        );
        assert!(c.find_zone("example.org.").is_none());
        let z = c.find_zone("example.com.").unwrap();
        assert!(
            z.existing.contains("b.c.example.com."),
            "empty non-terminal"
        );
        assert!(z.existing.contains("c.example.com."));
        assert!(!z.existing.contains("nope.example.com."));
        assert_eq!(
            c.reverse["1.0.0.10.in-addr.arpa."],
            vec!["www.example.com."]
        );
        assert_eq!(
            z.delegation_for("x.deleg.example.com."),
            Some("deleg.example.com.")
        );
        assert_eq!(z.delegation_for("www.example.com."), None);
    }

    #[test]
    fn an_older_build_never_replaces_a_newer_one() {
        let cache = Cache::new(Catalog::empty());
        let slow = cache.ticket(); // started first, finishes last
        let fast = cache.ticket();
        let mut newer = Catalog::empty();
        newer.built_at = "newer".into();
        assert!(cache.store_built(fast, newer));
        let mut older = Catalog::empty();
        older.built_at = "older".into();
        assert!(!cache.store_built(slow, older), "stale build refused");
        assert_eq!(cache.load().built_at, "newer");
        cache.store(Catalog::empty());
        assert_ne!(cache.load().built_at, "newer", "a later build still wins");
    }
}
