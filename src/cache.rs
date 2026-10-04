//! In-memory catalog of all zones and records, swapped in atomically. DNS
//! lookups only ever read from here.
//!
//! The catalog is built from storage in full at startup (and as the
//! fallback), and per zone after a change: only the zones a transaction
//! touched are read again, converted and signed; every other zone is the
//! same `Arc<ZoneData>` as before. Both ways go through the same two
//! functions ([`ZoneData::build`] for one zone, [`Catalog::assemble`] for
//! what spans zones), so an incremental build equals a full one.
//!
//! Record data is converted to wire records once, here ([`Rec`]); a query
//! clones the prepared record instead of parsing text.

use crate::model::*;
use crate::replication::types::ReplDnssecKey;
use arc_swap::ArcSwap;
use hickory_proto::rr::{Name, Record as WireRecord};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// A stored record with its wire form, prepared when the catalog is built.
pub struct Rec {
    stored: Record,
    /// The record as served (TTL resolved against the zone default), with
    /// a placeholder owner: callers set the name they answer with. `None`
    /// when the stored value does not convert (never served).
    wire: Option<WireRecord>,
}

impl std::ops::Deref for Rec {
    type Target = Record;
    fn deref(&self) -> &Record {
        &self.stored
    }
}

impl Rec {
    fn new(zone: &Zone, stored: Record) -> Rec {
        let wire = crate::zones::to_rr(zone, &stored, &Name::root());
        Rec { stored, wire }
    }

    /// O27: a transferred record, already in wire form.
    fn from_wire(stored: Record, mut wire: WireRecord) -> Rec {
        wire.name = Name::root();
        Rec {
            stored,
            wire: Some(wire),
        }
    }

    /// The wire record, owned by `owner` (the query name: its letter case
    /// is echoed; or the wildcard-expanded name).
    pub fn rr(&self, owner: &Name) -> Option<WireRecord> {
        let mut r = self.wire.clone()?;
        r.name = owner.clone();
        Some(r)
    }
}

/// A single zone with its records indexed by owner name.
pub struct ZoneData {
    pub zone: Zone,
    /// Apex as a fully qualified lower-case name (`example.com.`).
    pub apex: String,
    /// Records grouped by fully qualified owner name.
    pub names: HashMap<String, Vec<Rec>>,
    /// Every name that "exists" in the zone: owners plus empty non-terminals.
    pub existing: HashSet<String>,
    /// Names below the apex that hold NS records: delegation points.
    pub delegations: Vec<String>,
    /// The signed view when DNSSEC signing is on for this zone.
    pub signed: Option<Arc<crate::dnssec::SignedZone>>,
    /// The SOA record (TTL = the zone default), prepared.
    pub soa: Option<WireRecord>,
    /// The apex NS RRset (explicit, or synthesized from the SOA MNAME), prepared.
    pub apex_ns: Vec<WireRecord>,
    /// This zone's part of the automatic reverse index: (reverse name,
    /// owner) for every A / AAAA record, in record order.
    pub reverse: Vec<(String, String)>,
    /// The earliest `expires_at` of the records served: at that time the
    /// zone must be built again without it (every node does so in memory,
    /// see `Mutator::spawn_expiry_watch`).
    pub next_expiry: Option<String>,
    /// O27: a secondary zone without usable data (never transferred, or
    /// expired: no refresh within the SOA expire time): answered SERVFAIL.
    pub unavailable: bool,
}

impl ZoneData {
    /// One zone as of `now`: expired records are left out, so they stop
    /// answering, stop appearing in zone transfers and exports, and no
    /// longer produce automatic PTR answers. Unsigned (see [`Catalog`]).
    /// `records`: the zone's records in id order.
    pub fn build(zone: Zone, records: Vec<Record>, now: &str) -> ZoneData {
        let recs = records
            .into_iter()
            .filter(|r| !r.is_expired_at(now))
            .map(|r| Rec::new(&zone, r))
            .collect();
        Self::from_recs(zone, recs)
    }

    /// One zone from prepared records (ours: [`Self::build`]; a secondary
    /// zone's: [`Self::build_secondary`]).
    fn from_recs(zone: Zone, recs: Vec<Rec>) -> ZoneData {
        let apex = zone.fqdn();
        let mut names: HashMap<String, Vec<Rec>> = HashMap::new();
        let mut existing: HashSet<String> = HashSet::new();
        let mut delegations = Vec::new();
        let mut reverse = Vec::new();
        let mut next_expiry: Option<String> = None;
        existing.insert(apex.clone());
        for r in recs {
            if let Some(e) = &r.expires_at {
                if next_expiry.as_ref().is_none_or(|n| e < n) {
                    next_expiry = Some(e.clone());
                }
            }
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
            // Override zones are not authoritative: their addresses give
            // no automatic PTR answers; nor do a secondary zone's (O27).
            if matches!(r.rtype, RecordType::A | RecordType::AAAA)
                && zone.overrides.is_none()
                && zone.secondary.is_none()
            {
                if let Ok(ip) = r.value.parse::<std::net::IpAddr>() {
                    reverse.push((reverse_name(&ip), owner.clone()));
                }
            }
            names.entry(owner).or_default().push(r);
        }
        let mut z = ZoneData {
            zone,
            apex,
            names,
            existing,
            delegations,
            signed: None,
            soa: None,
            apex_ns: Vec::new(),
            reverse,
            next_expiry,
            unavailable: false,
        };
        z.soa = crate::zones::build_soa(&z);
        z.apex_ns = crate::zones::build_apex_ns(&z);
        z
    }

    /// O27: a secondary zone from its transferred data as of `now_unix`.
    /// The SOA, its timers and TTL are the transferred SOA's (copied into
    /// this catalog's zone row, which only the catalog sees); records of a
    /// type this server does not model are not served (counted in the
    /// transfer status); a signed primary's DNSSEC records make the signed
    /// view ([`SignedZone::from_transfer`]). No data, or expired data:
    /// `unavailable` (SERVFAIL).
    ///
    /// [`SignedZone::from_transfer`]: crate::dnssec::SignedZone::from_transfer
    pub fn build_secondary(
        mut zone: Zone,
        data: Option<&crate::secondary::Transferred>,
        now_unix: i64,
    ) -> ZoneData {
        let data = data.filter(|d| !d.expired_at(now_unix));
        let Some((d, soa)) = data.and_then(|d| Some((d, d.soa()?))) else {
            let mut z = Self::from_recs(zone, Vec::new());
            z.unavailable = true;
            z.soa = None;
            z.apex_ns = Vec::new();
            return z;
        };
        if let hickory_proto::rr::RData::SOA(s) = &soa.data {
            zone.serial = s.serial;
            zone.soa_mname = s.mname.to_ascii();
            zone.soa_rname = s.rname.to_ascii();
            zone.refresh = s.refresh.max(0) as u32;
            zone.retry = s.retry.max(0) as u32;
            zone.expire = s.expire.max(0) as u32;
            zone.minimum = s.minimum;
        }
        zone.default_ttl = soa.ttl;
        let apex = zone.fqdn();
        let mut recs = Vec::new();
        let mut sec = Vec::new();
        for r in &d.records {
            let code = u16::from(r.record_type());
            if crate::secondary::is_dnssec_type(code) {
                sec.push(r.clone());
                continue;
            }
            let Some(rt) = RecordType::ALL
                .iter()
                .copied()
                .find(|t| u16::from(t.to_hickory()) == code)
            else {
                continue;
            };
            let owner = r.name.to_lowercase().to_ascii();
            let stored = Record {
                id: 0,
                zone_id: zone.id,
                name: crate::secondary::relative_name(&owner, &apex),
                rtype: rt,
                value: crate::secondary::value_text(r),
                ttl: Some(r.ttl),
                created_at: String::new(),
                updated_at: String::new(),
                expires_at: None,
            };
            recs.push(Rec::from_wire(stored, r.clone()));
        }
        let mut z = Self::from_recs(zone, recs);
        z.soa = Some(soa.clone());
        z.signed =
            crate::dnssec::SignedZone::from_transfer(&z.apex, &z.existing, &sec).map(Arc::new);
        z
    }

    pub fn records_at(&self, owner: &str) -> Option<&Vec<Rec>> {
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

/// What storage holds for one zone id now (`None`: the zone is gone).
pub type ZoneInput = Option<(Zone, Vec<Record>, Option<ReplDnssecKey>)>;

pub struct Catalog {
    /// Keyed by apex fqdn.
    pub zones: BTreeMap<String, Arc<ZoneData>>,
    /// Auto-generated reverse index: `10.0.168.192.in-addr.arpa.` -> owner
    /// names. It spans zones; shared with the previous catalog when the
    /// zones that changed contribute the same entries as before.
    pub reverse: Arc<HashMap<String, Vec<String>>>,
    pub built_at: String,
}

impl Catalog {
    pub fn empty() -> Self {
        Catalog {
            zones: BTreeMap::new(),
            reverse: Arc::new(HashMap::new()),
            built_at: now_rfc3339(),
        }
    }

    /// Unsigned catalog as of now (tests).
    #[cfg(test)]
    pub fn build(zones: Vec<Zone>, records: Vec<Record>) -> Self {
        Self::build_at(zones, records, &now_rfc3339())
    }

    /// What is derived from all zones together: the reverse index, in a
    /// fixed order (zones by apex, records in id order within a zone), so
    /// it does not depend on how the catalog came to be.
    fn assemble(zones: BTreeMap<String, Arc<ZoneData>>) -> Self {
        let mut reverse: HashMap<String, Vec<String>> = HashMap::new();
        for z in zones.values() {
            for (key, owner) in &z.reverse {
                let list = reverse.entry(key.clone()).or_default();
                if !list.contains(owner) {
                    list.push(owner.clone());
                }
            }
        }
        Catalog {
            zones,
            reverse: Arc::new(reverse),
            built_at: now_rfc3339(),
        }
    }

    fn sign_zone(
        zd: &mut ZoneData,
        key: Option<&ReplDnssecKey>,
        signer: &crate::dnssec::Signer,
        now: i64,
    ) {
        // An override zone is never signed (the flag cannot be set on one;
        // this is the second line).
        if !zd.zone.dnssec || zd.zone.is_override() {
            signer.forget(zd.zone.id);
            return;
        }
        let Some(key) = key else {
            tracing::error!(zone = %zd.zone.name, "DNSSEC is on but the zone has no key; serving it unsigned");
            return;
        };
        zd.signed = signer.sign(zd, key, now);
    }

    /// Full build: every zone, signed where DNSSEC is on (with the zone's
    /// key from `keys`; a zone without a usable key is served unsigned and
    /// the error is kept by the signer).
    pub fn build_signed(
        zones: Vec<Zone>,
        records: Vec<Record>,
        keys: &[ReplDnssecKey],
        signer: &crate::dnssec::Signer,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut by_zone: HashMap<i64, Vec<Record>> = HashMap::new();
        for r in records {
            by_zone.entry(r.zone_id).or_default().push(r);
        }
        let mut out = BTreeMap::new();
        let mut signed_ids = Vec::new();
        for zone in zones {
            let id = zone.id;
            let mut zd = if zone.is_secondary() {
                let data = signer.secondaries.get(&zone.name);
                ZoneData::build_secondary(zone, data.as_deref(), now.timestamp())
            } else {
                ZoneData::build(zone, by_zone.remove(&id).unwrap_or_default(), &now_s)
            };
            if zd.zone.dnssec {
                signed_ids.push(id);
            }
            Self::sign_zone(
                &mut zd,
                keys.iter().find(|k| k.zone_id == id),
                signer,
                now.timestamp(),
            );
            out.insert(zd.apex.clone(), Arc::new(zd));
        }
        signer.retain(&signed_ids);
        Self::assemble(out)
    }

    /// Incremental build: `base` with the zones in `updates` (by id)
    /// replaced by what storage holds for them now (or removed). Every
    /// other zone is shared with `base`. Equal to a full build of the same
    /// database state at the same time (test
    /// `incremental_catalog_builds_equal_full_builds`).
    pub fn with_zones(
        base: &Catalog,
        updates: &[(i64, ZoneInput)],
        signer: &crate::dnssec::Signer,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let now_s = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut zones = base.zones.clone();
        let ids: HashSet<i64> = updates.iter().map(|(id, _)| *id).collect();
        let mut old_reverse: Vec<(String, String)> = Vec::new();
        zones.retain(|_, z| {
            let gone = ids.contains(&z.zone.id);
            if gone {
                old_reverse.extend(z.reverse.iter().cloned());
            }
            !gone
        });
        let mut new_reverse: Vec<(String, String)> = Vec::new();
        for (id, input) in updates {
            let Some((zone, records, key)) = input else {
                signer.forget(*id);
                continue;
            };
            let mut zd = if zone.is_secondary() {
                let data = signer.secondaries.get(&zone.name);
                ZoneData::build_secondary(zone.clone(), data.as_deref(), now.timestamp())
            } else {
                ZoneData::build(zone.clone(), records.clone(), &now_s)
            };
            Self::sign_zone(&mut zd, key.as_ref(), signer, now.timestamp());
            new_reverse.extend(zd.reverse.iter().cloned());
            // A new zone takes over the name of one deleted in the same
            // transaction (its id is in `updates` too and was removed above).
            zones.insert(zd.apex.clone(), Arc::new(zd));
        }
        // The reverse index spans zones. When the touched zones contribute
        // exactly the entries they did before, it cannot have changed and
        // is shared; else it is derived again from all zones, as a full
        // build does.
        old_reverse.sort();
        new_reverse.sort();
        if old_reverse == new_reverse {
            return Catalog {
                zones,
                reverse: base.reverse.clone(),
                built_at: now_rfc3339(),
            };
        }
        Self::assemble(zones)
    }

    /// Unsigned full build as of `now` (tests).
    #[cfg(test)]
    pub fn build_at(zones: Vec<Zone>, records: Vec<Record>, now: &str) -> Self {
        let mut by_zone: HashMap<i64, Vec<Record>> = HashMap::new();
        for r in records {
            by_zone.entry(r.zone_id).or_default().push(r);
        }
        let mut out = BTreeMap::new();
        for zone in zones {
            let recs = by_zone.remove(&zone.id).unwrap_or_default();
            let zd = ZoneData::build(zone, recs, now);
            out.insert(zd.apex.clone(), Arc::new(zd));
        }
        Self::assemble(out)
    }

    /// The earliest expiry of any record served (see [`ZoneData::next_expiry`]).
    pub fn next_expiry(&self) -> Option<&str> {
        self.zones
            .values()
            .filter_map(|z| z.next_expiry.as_deref())
            .min()
    }

    /// Zones serving a record whose expiry is at or before `now`.
    pub fn zones_expiring_by(&self, now: &str) -> Vec<i64> {
        self.zones
            .values()
            .filter(|z| z.next_expiry.as_deref().is_some_and(|e| e <= now))
            .map(|z| z.zone.id)
            .collect()
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

    /// Longest-suffix match among the authoritative zones only: `None` when
    /// the closest zone is an override zone (its data is never served
    /// authoritatively, e.g. by a CNAME chase or as glue).
    pub fn find_auth_zone(&self, qname: &str) -> Option<&Arc<ZoneData>> {
        self.find_zone(qname).filter(|z| !z.zone.is_override())
    }

    /// Find records of any authoritative zone at an absolute owner name
    /// (used for CNAME chasing and glue).
    pub fn records_anywhere(&self, owner: &str) -> Option<(&Arc<ZoneData>, &Vec<Rec>)> {
        let z = self.find_auth_zone(owner)?;
        z.records_at(owner).map(|r| (z, r))
    }
}

/// Test support: everything a catalog holds, in a comparable form
/// (signature bytes left out: they are randomised and are verified
/// instead). `owner_id` of the zone row is left out: the API releases a
/// user's zones as changes before deleting it (`Mutator::release_user`),
/// but an account transaction that deletes a user directly (tests, or
/// changes written by an older primary) still clears it through the
/// foreign key only, and nothing reads it from the catalog.
#[cfg(test)]
impl Catalog {
    pub(crate) fn describe(&self) -> serde_json::Value {
        let wire = |r: &WireRecord| format!("{} {} {} {}", r.name, r.ttl, r.record_type(), r.data);
        let zones: BTreeMap<&String, serde_json::Value> = self
            .zones
            .iter()
            .map(|(apex, z)| {
                let mut row = serde_json::to_value(&z.zone).unwrap();
                row["owner_id"] = serde_json::Value::Null;
                let names: BTreeMap<&String, Vec<serde_json::Value>> = z
                    .names
                    .iter()
                    .map(|(o, rs)| {
                        let owner = Name::from_ascii(o).unwrap_or_else(|_| Name::root());
                        (
                            o,
                            rs.iter()
                                .map(|r| {
                                    serde_json::json!([
                                        serde_json::to_value(&**r).unwrap(),
                                        r.rr(&owner).as_ref().map(wire)
                                    ])
                                })
                                .collect(),
                        )
                    })
                    .collect();
                let mut existing: Vec<&String> = z.existing.iter().collect();
                existing.sort();
                (
                    apex,
                    serde_json::json!({
                        "zone": row,
                        "apex": z.apex,
                        "names": names,
                        "existing": existing,
                        "delegations": z.delegations,
                        "soa": z.soa.as_ref().map(wire),
                        "apex_ns": z.apex_ns.iter().map(wire).collect::<Vec<_>>(),
                        "reverse": z.reverse,
                        "signed": z.signed.as_ref().map(|s| s.describe()),
                    }),
                )
            })
            .collect();
        let reverse: BTreeMap<&String, &Vec<String>> = self.reverse.iter().collect();
        serde_json::json!({ "zones": zones, "reverse": reverse })
    }

    /// Verify every signature of every signed zone; returns how many.
    pub(crate) fn verify_signatures(&self) -> usize {
        self.zones
            .values()
            .filter_map(|z| z.signed.as_ref().map(|s| s.verify_all(z)))
            .sum()
    }
}

pub struct Cache {
    inner: ArcSwap<Catalog>,
    /// Build tickets: taken before a build reads the database.
    next_ticket: std::sync::atomic::AtomicU64,
    /// Ticket of the catalog currently stored.
    stored_ticket: std::sync::Mutex<u64>,
    /// Signalled whenever a new catalog is stored (the expiry watch
    /// re-reads the next expiry).
    stored: tokio::sync::Notify,
}

impl Cache {
    pub fn new(catalog: Catalog) -> Self {
        Cache {
            inner: ArcSwap::from_pointee(catalog),
            next_ticket: std::sync::atomic::AtomicU64::new(1),
            stored_ticket: std::sync::Mutex::new(0),
            stored: tokio::sync::Notify::new(),
        }
    }

    pub fn load(&self) -> Arc<Catalog> {
        self.inner.load_full()
    }

    /// Resolves after the next catalog is stored (or at once if one was
    /// stored since the last call: one waiter, a stored permit).
    pub async fn stored(&self) {
        self.stored.notified().await
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
        self.stored.notify_one();
        true
    }

    /// Incremental build: store `f(current catalog)` under `ticket`.
    /// Returns whether it was stored.
    ///
    /// Why no committed change can be lost. The caller holds the mutator
    /// lock from before its transaction committed until this returns, so
    /// incremental builds never overlap each other: every commit's delta
    /// is applied in commit order. `ticket` is taken after the commit and
    /// before the touched zones are read. Full builds (startup, the
    /// DNSSEC re-sign timer, retries) do not take the lock; they interleave
    /// in two ways:
    /// - A full build with a LATER ticket read the database after our
    ///   commit: it contains our delta. If it is stored first, ours is
    ///   refused (`ticket <= stored`), which is right; if ours is stored
    ///   first, it replaces ours, which is right too.
    /// - A full build with an EARLIER ticket may have read the database
    ///   before our commit. If it comes after us, `store_built` refuses it.
    ///   If it was stored between our reading the current catalog and our
    ///   storing, the catalog we derived from is no longer the current one:
    ///   the pointer check below sees that and `f` runs again on the new
    ///   current catalog. Applying a delta is idempotent (it replaces the
    ///   touched zones by their current database state), so the result
    ///   again holds every commit up to ours.
    pub fn apply(&self, ticket: u64, f: impl Fn(&Catalog) -> Catalog) -> bool {
        loop {
            let base = self.inner.load_full();
            let next = f(&base);
            let mut stored = self.stored_ticket.lock().unwrap_or_else(|p| p.into_inner());
            if ticket <= *stored {
                return false;
            }
            if !Arc::ptr_eq(&self.inner.load_full(), &base) {
                continue; // an older full build was stored meanwhile
            }
            *stored = ticket;
            self.inner.store(Arc::new(next));
            self.stored.notify_one();
            return true;
        }
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
            signed_at: None,
            overrides: None,
            record_policy: None,
            nsec3: false,
            secondary: None,
            settings: None,
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

    /// D3: an incremental build is applied to the current catalog and never
    /// loses to (or resurrects) an older full build.
    #[test]
    fn incremental_builds_apply_to_the_current_catalog() {
        let signer = crate::dnssec::Signer::default();
        let now = chrono::Utc::now();
        let cache = Cache::new(Catalog::empty());
        let add = |id: i64, name: &str| -> (i64, ZoneInput) {
            (
                id,
                Some((
                    zone(id, name),
                    vec![rec(
                        id * 10,
                        id,
                        "www",
                        RecordType::A,
                        &format!("10.0.0.{id}"),
                    )],
                    None,
                )),
            )
        };
        // Zone 1 arrives incrementally.
        let t1 = cache.ticket();
        let u1 = vec![add(1, "one.test")];
        assert!(cache.apply(t1, |b| Catalog::with_zones(b, &u1, &signer, now)));
        // A full build started before the next commit (older ticket) ...
        let slow_full = cache.ticket();
        let stale = Catalog::build_at(vec![zone(1, "one.test")], vec![], "2026-01-01T00:00:00Z");
        // ... zone 2 is committed and applied ...
        let t2 = cache.ticket();
        let u2 = vec![add(2, "two.test")];
        assert!(cache.apply(t2, |b| Catalog::with_zones(b, &u2, &signer, now)));
        // ... and the stale full build is refused: zone 2 stays.
        assert!(!cache.store_built(slow_full, stale));
        let c = cache.load();
        assert_eq!(c.zones.len(), 2);
        assert!(c.reverse.contains_key("2.0.0.10.in-addr.arpa."));
        // A full build with a later ticket wins over a late incremental one.
        let t3 = cache.ticket();
        let full = cache.ticket();
        assert!(cache.store_built(full, Catalog::empty()));
        let u3 = vec![add(3, "three.test")];
        assert!(!cache.apply(t3, |b| Catalog::with_zones(b, &u3, &signer, now)));
        assert!(cache.load().zones.is_empty());
        // The untouched zone is shared, not rebuilt; a removed zone goes
        // with its reverse entries; an unchanged reverse index is shared.
        cache.store(Catalog::build_at(
            vec![zone(1, "one.test"), zone(2, "two.test")],
            vec![
                rec(10, 1, "www", RecordType::A, "10.0.0.1"),
                rec(20, 2, "www", RecordType::A, "10.0.0.2"),
            ],
            "2026-01-01T00:00:00Z",
        ));
        let before = cache.load();
        let t = cache.ticket();
        let txt = vec![(
            2,
            Some((
                zone(2, "two.test"),
                vec![
                    rec(20, 2, "www", RecordType::A, "10.0.0.2"),
                    rec(21, 2, "t", RecordType::TXT, "x"),
                ],
                None,
            )),
        )];
        assert!(cache.apply(t, |b| Catalog::with_zones(b, &txt, &signer, now)));
        let after = cache.load();
        assert!(Arc::ptr_eq(
            &before.zones["one.test."],
            &after.zones["one.test."]
        ));
        assert!(!Arc::ptr_eq(
            &before.zones["two.test."],
            &after.zones["two.test."]
        ));
        assert!(Arc::ptr_eq(&before.reverse, &after.reverse));
        let t = cache.ticket();
        let gone: Vec<(i64, ZoneInput)> = vec![(2, None)];
        assert!(cache.apply(t, |b| Catalog::with_zones(b, &gone, &signer, now)));
        let c = cache.load();
        assert_eq!(c.zones.len(), 1);
        assert!(!c.reverse.contains_key("2.0.0.10.in-addr.arpa."));
        assert!(c.reverse.contains_key("1.0.0.10.in-addr.arpa."));
    }

    /// D4: the wire form prepared at build time is what `zones::to_rr`
    /// gives for the same record, for every type, with the asked owner;
    /// a value that does not convert is not served.
    #[test]
    fn records_are_converted_once_at_build() {
        let z = zone(1, "example.com");
        let cases = [
            (RecordType::A, "192.0.2.1"),
            (RecordType::AAAA, "2001:db8::1"),
            (RecordType::CNAME, "t.example.net."),
            (RecordType::NS, "ns.example.net."),
            (RecordType::PTR, "p.example.net."),
            (RecordType::MX, "10 mx.example.net."),
            (RecordType::SRV, "1 2 443 s.example.net."),
            (RecordType::TXT, "hello world"),
            (RecordType::DNAME, "d.example.net."),
            (RecordType::CAA, "0 issue \"ca.example\""),
            (
                RecordType::DS,
                "1 13 2 0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (RecordType::A, "not an address"),
        ];
        let records: Vec<Record> = cases
            .iter()
            .enumerate()
            .map(|(i, (t, v))| {
                let mut r = rec(i as i64 + 1, 1, &format!("n{i}"), *t, v);
                if i % 2 == 0 {
                    r.ttl = Some(77);
                }
                r
            })
            .collect();
        let c = Catalog::build(vec![z.clone()], records.clone());
        let zd = &c.zones["example.com."];
        let asked = Name::from_ascii("MiXeD.Example.COM.").unwrap();
        for (i, r) in records.iter().enumerate() {
            let prepared = &zd.names[&format!("n{i}.example.com.")][0];
            let expect = crate::zones::to_rr(&z, r, &asked);
            assert_eq!(prepared.rr(&asked), expect, "{:?}", cases[i]);
            assert_eq!(expect.is_some(), i != cases.len() - 1);
            if let Some(rr) = prepared.rr(&asked) {
                assert_eq!(rr.name.to_ascii(), "MiXeD.Example.COM.");
                assert_eq!(rr.ttl, if i % 2 == 0 { 77 } else { 60 });
            }
        }
        assert_eq!(crate::zones::soa_record(zd, 5).unwrap().ttl, 5);
        assert_eq!(
            crate::zones::apex_ns(zd).len(),
            1,
            "synthesized from the MNAME"
        );
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
