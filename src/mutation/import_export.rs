//! JSON export and import (one transaction).

use super::ops::{apply_zone_input, new_zone, soa_differs};
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

impl Mutator {
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
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::test_support::*;

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
