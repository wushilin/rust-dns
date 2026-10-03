//! JSON export and import (one transaction).

use super::ops::{apply_override, apply_zone_input, new_zone, soa_differs};
use super::*;

/// JSON export / import document.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[schema(example = json!({
    "version": 1, "exported_at": "2026-01-15T09:30:00.000Z",
    "zones": [{
        "name": "example.com", "soa_mname": "ns1.example.com.", "soa_rname": "hostmaster.example.com.", "default_ttl": 3600,
        "records": [
            { "name": "@", "type": "NS", "value": "ns1.example.com." },
            { "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300 },
            { "name": "www", "type": "AAAA", "value": "2001:db8::10" },
            { "name": "@", "type": "MX", "value": "10 mail.example.com." }
        ]
    }]
}))]
pub struct ExportDoc {
    #[schema(example = 1)]
    pub version: u32,
    #[schema(format = DateTime, example = "2026-01-15T09:30:00.000Z")]
    pub exported_at: String,
    pub zones: Vec<ExportZone>,
}

/// One zone of an export document. On import, omitted SOA fields fall back
/// to the server defaults (new zones) or are left unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportZone {
    pub name: String,
    #[serde(default)]
    #[schema(format = Int64, maximum = 4294967295_u64)]
    pub serial: Option<u32>,
    #[serde(default)]
    pub soa_mname: Option<String>,
    #[serde(default)]
    pub soa_rname: Option<String>,
    #[serde(default)]
    pub refresh: Option<u32>,
    #[serde(default)]
    pub retry: Option<u32>,
    #[serde(default)]
    pub expire: Option<u32>,
    #[serde(default)]
    pub minimum: Option<u32>,
    #[serde(default)]
    pub default_ttl: Option<u32>,
    #[serde(default)]
    pub owner: Option<String>,
    /// An override zone's settings (I1). On import they apply to a zone
    /// the import creates; an existing zone keeps its type.
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub overrides: Option<ZoneOverride>,
    /// The zone's record expiry policy (M2). On import it applies to a
    /// zone the import creates (before its records are added); an existing
    /// zone keeps its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub record_policy: Option<RecordPolicy>,
    #[serde(default)]
    #[schema(default = json!([]))]
    pub records: Vec<ExportRecord>,
}

/// One record of an export document; `ttl: null` (or omitted) means the
/// zone default.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: RecordType,
    pub value: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Exported expiry. Records already expired at import time are skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub expires_at: Option<String>,
}

/// `merge` adds missing zones and records; `replace` replaces the records of
/// each zone in the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add zones and records that are missing; keep everything else.
    Merge,
    /// Zones in the document have their records replaced wholesale.
    Replace,
}

/// What an import changed.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
#[schema(example = json!({ "zones_created": 0, "zones_updated": 1, "records_added": 3, "records_removed": 0, "records_skipped": 0 }))]
pub struct ImportSummary {
    pub zones_created: usize,
    pub zones_updated: usize,
    pub records_added: usize,
    pub records_removed: usize,
    pub records_skipped: usize,
}

/// A name of a hosts file that is not imported, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct HostsSkip {
    /// Line number (1-based).
    pub line: usize,
    #[schema(example = "www.other.example")]
    pub name: String,
    #[schema(example = "outside the zone")]
    pub reason: String,
}

/// A hosts file read for one zone (I8).
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct HostsParse {
    /// The A / AAAA records to import (names relative to the zone).
    pub records: Vec<HostsRecord>,
    pub skipped: Vec<HostsSkip>,
}

/// One record from a hosts file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct HostsRecord {
    /// Relative to the zone (`@` for the apex).
    #[schema(example = "nas")]
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: RecordType,
    #[schema(example = "192.168.1.10")]
    pub value: String,
}

/// Read `/etc/hosts`-format text for `zone`: `address name [name...]`,
/// `#` comments. Names inside the zone (or with no dot: taken as relative
/// to the zone, as dnsmasq's `expand-hosts`) become A / AAAA records;
/// names outside the zone, loopback and unspecified addresses, and lines
/// that are not understood are listed as skipped. Duplicates are dropped.
pub fn parse_hosts(text: &str, zone: &str) -> HostsParse {
    let mut out = HostsParse::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("");
        let skip = |out: &mut HostsParse, name: &str, reason: &str| {
            out.skipped.push(HostsSkip {
                line: i + 1,
                name: name.to_string(),
                reason: reason.to_string(),
            })
        };
        let ip: std::net::IpAddr = match first.parse() {
            Ok(ip) => ip,
            Err(_) => {
                skip(&mut out, first, "not an IP address");
                continue;
            }
        };
        let names: Vec<&str> = words.collect();
        if names.is_empty() {
            skip(&mut out, first, "no name after the address");
            continue;
        }
        if ip.is_loopback() || ip.is_unspecified() {
            for n in names {
                skip(&mut out, n, "loopback or unspecified address");
            }
            continue;
        }
        let rtype = if ip.is_ipv4() {
            RecordType::A
        } else {
            RecordType::AAAA
        };
        for n in names {
            let lower = n.trim_end_matches('.').to_ascii_lowercase();
            // A dotted name is absolute; a single label is relative.
            let input = if lower.contains('.') || zone == "." {
                format!("{lower}.")
            } else {
                lower.clone()
            };
            match normalize_record_name(&input, zone) {
                Ok(name) => {
                    let r = HostsRecord {
                        name,
                        rtype,
                        value: ip.to_string(),
                    };
                    if !out.records.contains(&r) {
                        out.records.push(r);
                    }
                }
                Err(e) if e.0.contains("not inside zone") => skip(&mut out, n, "outside the zone"),
                Err(e) => skip(&mut out, n, &e.0),
            }
        }
    }
    out
}

impl Mutator {
    /// Import a hosts file into `zone` (one transaction, as a JSON import
    /// of its A / AAAA records with `mode`).
    pub async fn import_hosts(
        &self,
        actor: Actor,
        zone: &str,
        records: &[HostsRecord],
        mode: ImportMode,
        allowed: Option<Vec<String>>,
    ) -> MResult<ImportSummary> {
        let name = normalize_zone_name(zone)?;
        if self.storage.get_zone(&name)?.is_none() {
            return Err(MutationError::NotFound(format!("zone '{name}' not found")));
        }
        let doc = ExportDoc {
            version: 1,
            exported_at: now_rfc3339(),
            zones: vec![ExportZone {
                name,
                serial: None,
                soa_mname: None,
                soa_rname: None,
                refresh: None,
                retry: None,
                expire: None,
                minimum: None,
                default_ttl: None,
                owner: None,
                overrides: None,
                record_policy: None,
                records: records
                    .iter()
                    .map(|r| ExportRecord {
                        name: r.name.clone(),
                        rtype: r.rtype,
                        value: r.value.clone(),
                        ttl: None,
                        expires_at: None,
                    })
                    .collect(),
            }],
        };
        self.import(actor, doc, mode, None, allowed).await
    }

    // ---- import --------------------------------------------------------

    /// Import a document as one transaction: every zone and record in it is
    /// committed, or none is. `allowed` restricts which zones may be touched
    /// (None = any); new zones are owned by `owner_id`.
    pub async fn import(
        &self,
        actor: Actor,
        doc: ExportDoc,
        mode: ImportMode,
        owner_id: Option<i64>,
        allowed: Option<Vec<String>>,
    ) -> MResult<ImportSummary> {
        let defaults = self.defaults();
        self.execute(actor, "import", move |t| {
            let mut summary = ImportSummary::default();
            for ez in doc.zones {
                let name = normalize_zone_name(&ez.name)?;
                if let Some(a) = &allowed {
                    if !a.contains(&name) {
                        return Err(MutationError::Invalid(format!(
                            "not permitted to import zone '{name}'"
                        )));
                    }
                }
                let input = ZoneInput {
                    name: Some(name.clone()),
                    soa_mname: ez.soa_mname.clone(),
                    soa_rname: ez.soa_rname.clone(),
                    refresh: ez.refresh,
                    retry: ez.retry,
                    expire: ez.expire,
                    minimum: ez.minimum,
                    default_ttl: ez.default_ttl,
                    owner: None,
                    overrides: ez.overrides.as_ref().map(|o| ZoneOverrideInput {
                        mode: Some(o.mode),
                        upstreams: Some(o.upstreams.iter().map(|u| u.to_string()).collect()),
                    }),
                    record_policy: None,
                };
                let zone = match t.zone(&name)? {
                    Some(before) => {
                        let mut after = before.clone();
                        apply_zone_input(&mut after, &input)?;
                        summary.zones_updated += 1;
                        if soa_differs(&before, &after) {
                            t.update_zone(before, after)?
                        } else {
                            before
                        }
                    }
                    None => {
                        let mut z = new_zone(&defaults, &name, owner_id);
                        apply_zone_input(&mut z, &input)?;
                        if let Some(p) = ez.record_policy.as_ref().filter(|p| !p.is_empty()) {
                            p.validate()?;
                            z.record_policy = Some(p.clone());
                        }
                        apply_override(&mut z, &input, true)?;
                        if let Some(s) = ez.serial {
                            z.serial = s;
                        }
                        summary.zones_created += 1;
                        t.create_zone(z)?
                    }
                };
                if mode == ImportMode::Replace {
                    for r in t.records(zone.id)? {
                        t.delete_record(&zone, &r)?;
                        summary.records_removed += 1;
                    }
                }
                let now = chrono::Utc::now();
                for er in ez.records {
                    let rname = normalize_record_name(&er.name, &name)?;
                    let value = normalize_value(er.rtype, &er.value)?;
                    // Expiry travels with exported records; already-expired ones are not imported.
                    let expires_at = match &er.expires_at {
                        None => None,
                        Some(t0) => match resolve_expiry(
                            &RecordInput {
                                expires_at: Some(Some(t0.clone())),
                                ..Default::default()
                            },
                            now,
                        ) {
                            Ok(Some(e)) => e,
                            _ => {
                                summary.records_skipped += 1;
                                continue;
                            }
                        },
                    };
                    let same_name = t.records_named(zone.id, &rname)?;
                    if t.record_conflict(&same_name, None, &rname, er.rtype, &value)
                        .is_some()
                    {
                        summary.records_skipped += 1;
                        continue;
                    }
                    t.create_record(
                        &zone,
                        &rname,
                        er.rtype,
                        &value,
                        er.ttl.filter(|v| *v > 0),
                        expires_at,
                    )?;
                    summary.records_added += 1;
                }
            }
            Ok(summary)
        })
        .await
    }

    pub fn export_all(&self, only: Option<&[String]>) -> Result<ExportDoc> {
        let catalog = self.cache.load();
        let mut zones = Vec::new();
        for zd in catalog.zones.values() {
            if let Some(o) = only {
                if !o.contains(&zd.zone.name) {
                    continue;
                }
            }
            zones.push(export_zone(zd));
        }
        Ok(ExportDoc {
            version: 1,
            exported_at: now_rfc3339(),
            zones,
        })
    }
}

pub fn export_zone(zd: &crate::cache::ZoneData) -> ExportZone {
    let z = &zd.zone;
    let mut records: Vec<ExportRecord> = zd
        .names
        .values()
        .flatten()
        .map(|r| ExportRecord {
            name: r.name.clone(),
            rtype: r.rtype,
            value: r.value.clone(),
            ttl: r.ttl,
            expires_at: r.expires_at.clone(),
        })
        .collect();
    records.sort_by(|a, b| {
        (a.name.len(), &a.name, a.rtype, &a.value).cmp(&(b.name.len(), &b.name, b.rtype, &b.value))
    });
    ExportZone {
        name: z.name.clone(),
        serial: Some(z.serial),
        soa_mname: Some(z.soa_mname.clone()),
        soa_rname: Some(z.soa_rname.clone()),
        refresh: Some(z.refresh),
        retry: Some(z.retry),
        expire: Some(z.expire),
        minimum: Some(z.minimum),
        default_ttl: Some(z.default_ttl),
        owner: None,
        overrides: z.overrides.as_deref().cloned(),
        record_policy: z.record_policy.clone(),
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;

    #[test]
    fn hosts_files_parse() {
        let text = "\
# comment
127.0.0.1   localhost
::1         localhost ip6-localhost
192.168.1.10  nas.home.test nas   # trailing comment
192.168.1.11\tPrinter.Home.Test. printer
fd00::10    nas.home.test
10.0.0.1    www.other.example home.test
not-an-ip   x.home.test
0.0.0.0     blocked.home.test
192.168.1.12
192.168.1.10 nas
";
        let p = parse_hosts(text, "home.test");
        let got: Vec<(&str, RecordType, &str)> = p
            .records
            .iter()
            .map(|r| (r.name.as_str(), r.rtype, r.value.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("nas", RecordType::A, "192.168.1.10"),
                ("printer", RecordType::A, "192.168.1.11"),
                ("nas", RecordType::AAAA, "fd00::10"),
                ("@", RecordType::A, "10.0.0.1"),
            ],
            "duplicates dropped, case folded, apex as @"
        );
        let reasons: Vec<(usize, &str, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.line, s.name.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            vec![
                (2, "localhost", "loopback or unspecified address"),
                (3, "localhost", "loopback or unspecified address"),
                (3, "ip6-localhost", "loopback or unspecified address"),
                (7, "www.other.example", "outside the zone"),
                (8, "not-an-ip", "not an IP address"),
                (9, "blocked.home.test", "loopback or unspecified address"),
                (10, "192.168.1.12", "no name after the address"),
            ]
        );
    }

    /// A hosts import is one transaction: an invalid record rolls the whole
    /// import back; replace mode keeps only what the file has.
    #[tokio::test]
    async fn hosts_import_is_one_transaction() {
        let (s, m, _) = setup();
        m.create_zone(
            actor(),
            ZoneInput {
                name: Some("home.test".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        let p = parse_hosts("192.168.1.10 nas\n192.168.1.11 printer\n", "home.test");
        let sum = m
            .import_hosts(actor(), "home.test", &p.records, ImportMode::Merge, None)
            .await
            .unwrap();
        assert_eq!(sum.records_added, 2);
        // Bad value: the whole import fails, nothing is added.
        let mut bad = parse_hosts("192.168.1.20 tv\n", "home.test").records;
        bad.push(HostsRecord {
            name: "broken".into(),
            rtype: RecordType::A,
            value: "not-an-address".into(),
        });
        assert!(m
            .import_hosts(actor(), "home.test", &bad, ImportMode::Merge, None)
            .await
            .is_err());
        let zid = s.get_zone("home.test").unwrap().unwrap().id;
        let names: Vec<String> = s
            .list_records(zid)
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert!(!names.contains(&"tv".to_string()), "rolled back: {names:?}");
        // Replace: only what the file has.
        let p = parse_hosts("192.168.1.30 only\n", "home.test");
        let sum = m
            .import_hosts(actor(), "home.test", &p.records, ImportMode::Replace, None)
            .await
            .unwrap();
        assert_eq!((sum.records_added, sum.records_removed), (1, 2));
        assert!(m
            .import_hosts(actor(), "missing.test", &p.records, ImportMode::Merge, None)
            .await
            .is_err());
    }

    /// H1: an import's record checks look at one name (an index lookup),
    /// not the whole zone, so a large import is linear. 6,000 records took
    /// 44 s in a debug build before, 0.6 s after; also importing them
    /// again (all duplicates, skipped) and once more in replace mode.
    #[tokio::test]
    async fn a_large_import_is_linear() {
        let (s, m, _) = setup();
        let doc = |n: usize| ExportDoc {
            version: 1,
            exported_at: String::new(),
            zones: vec![ExportZone {
                name: "big.test".into(),
                serial: None,
                soa_mname: None,
                soa_rname: None,
                refresh: None,
                retry: None,
                expire: None,
                minimum: None,
                default_ttl: None,
                owner: None,
                overrides: None,
                record_policy: None,
                records: (0..n)
                    .map(|i| ExportRecord {
                        // Two records per name: the per-name checks still apply.
                        name: format!("h{}", i / 2),
                        rtype: RecordType::A,
                        value: format!("198.51.{}.{}", i / 250, i % 250 + 1),
                        ttl: None,
                        expires_at: None,
                    })
                    .collect(),
            }],
        };
        let n = 6000;
        let t = std::time::Instant::now();
        let sum = m
            .import(actor(), doc(n), ImportMode::Merge, None, None)
            .await
            .unwrap();
        let first = t.elapsed();
        assert_eq!((sum.records_added, sum.records_skipped), (n, 0));
        let t = std::time::Instant::now();
        let sum = m
            .import(actor(), doc(n), ImportMode::Merge, None, None)
            .await
            .unwrap();
        let again = t.elapsed();
        assert_eq!((sum.records_added, sum.records_skipped), (0, n));
        let t = std::time::Instant::now();
        let sum = m
            .import(actor(), doc(n), ImportMode::Replace, None, None)
            .await
            .unwrap();
        let replace = t.elapsed();
        assert_eq!((sum.records_removed, sum.records_added), (n, n));
        eprintln!("H1: import of {n} records {first:?}, again {again:?}, replace {replace:?}");
        let z = s.get_zone("big.test").unwrap().unwrap();
        assert_eq!(s.list_records(z.id).unwrap().len(), n);
        // Rules still hold inside an import: a CNAME beside an A is skipped.
        let mut d = doc(2);
        d.zones[0].records.push(ExportRecord {
            name: "h0".into(),
            rtype: RecordType::CNAME,
            value: "x.example.".into(),
            ttl: None,
            expires_at: None,
        });
        let sum = m
            .import(actor(), d, ImportMode::Merge, None, None)
            .await
            .unwrap();
        assert_eq!(sum.records_skipped, 3);
        for took in [first, again, replace] {
            assert!(
                took < std::time::Duration::from_secs(5),
                "import of {n} records took {took:?}"
            );
        }
    }
}
