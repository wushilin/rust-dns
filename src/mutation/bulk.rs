//! O10: bulk record editing: delete several records and add several
//! pasted lines in one transaction (every change commits, or none), with a
//! preview that runs the very same transaction and rolls it back.

use super::*;
use std::sync::{Arc, Mutex};

/// One pasted line, parsed: `name [ttl] type value...` (zone-file order;
/// `@` for the apex; `;` or `#` starts a comment line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkLine {
    /// 1-based line number in the pasted text.
    pub line: usize,
    pub name: String,
    pub ttl: Option<u32>,
    pub rtype: RecordType,
    pub value: String,
}

/// A line that cannot be applied, and why.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct BulkError {
    /// 1-based line of the pasted text; 0 for a record to delete.
    pub line: usize,
    /// The id of the record to delete it is about (deletes only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<i64>,
    pub error: String,
}

/// What a bulk edit did (or, previewed, would do).
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct BulkOutcome {
    pub deleted: Vec<Record>,
    pub added: Vec<Record>,
    /// Empty when the edit was (or can be) applied.
    pub errors: Vec<BulkError>,
}

/// Parse pasted text; lines that cannot be parsed are reported, blank and
/// comment lines skipped.
pub fn parse_bulk(text: &str) -> (Vec<BulkLine>, Vec<BulkError>) {
    let (mut ok, mut errs) = (Vec::new(), Vec::new());
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let t = raw.trim();
        if t.is_empty() || t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let name = parts.next().unwrap_or("").to_string();
        let mut next = parts.next();
        let mut ttl = None;
        if let Some(n) = next.and_then(|x| x.parse::<u32>().ok()) {
            ttl = Some(n);
            next = parts.next();
        }
        // An optional class, as in zone files.
        if next.is_some_and(|x| x.eq_ignore_ascii_case("IN")) {
            next = parts.next();
        }
        let Some(rtype) = next.and_then(|x| RecordType::parse(&x.to_ascii_uppercase())) else {
            errs.push(BulkError {
                line,
                record_id: None,
                error: format!(
                    "expected `name [ttl] type value`, e.g. `www 300 A 192.0.2.10`; '{}' is not a supported type",
                    next.unwrap_or("")
                ),
            });
            continue;
        };
        let value = parts.collect::<Vec<_>>().join(" ");
        if value.is_empty() {
            errs.push(BulkError {
                line,
                record_id: None,
                error: "the value is missing".into(),
            });
            continue;
        }
        ok.push(BulkLine {
            line,
            name,
            ttl,
            rtype,
            value,
        });
    }
    (ok, errs)
}

/// At most this many deletes plus lines in one bulk edit.
pub const MAX_BULK: usize = 5000;

impl Mutator {
    /// Delete `delete` (record ids of `zone`) and add `add`, as one
    /// transaction. With `preview`, or when any delete or line fails, the
    /// transaction is rolled back and the outcome lists what would happen
    /// and every error (per line). `parse_errors` are reported with the
    /// others (and make it a preview).
    pub async fn bulk_records(
        &self,
        actor: Actor,
        zone: &str,
        delete: Vec<i64>,
        add: Vec<BulkLine>,
        parse_errors: Vec<BulkError>,
        preview: bool,
    ) -> MResult<BulkOutcome> {
        if delete.len() + add.len() > MAX_BULK {
            return Err(MutationError::Invalid(format!(
                "at most {MAX_BULK} changes in one bulk edit"
            )));
        }
        let zone = normalize_zone_name(zone)?;
        let slot: Arc<Mutex<Option<BulkOutcome>>> = Arc::new(Mutex::new(None));
        let out_slot = slot.clone();
        let res = self
            .execute(actor, "bulk_records", move |t| {
                let z = t.require_zone(&zone)?;
                let mut out = BulkOutcome {
                    errors: parse_errors,
                    ..Default::default()
                };
                for id in delete {
                    match t.record_in(&z, id).and_then(|r| {
                        t.delete_record(&z, &r)?;
                        Ok(r)
                    }) {
                        Ok(r) => out.deleted.push(r),
                        Err(e) => out.errors.push(BulkError {
                            line: 0,
                            record_id: Some(id),
                            error: e.to_string(),
                        }),
                    }
                }
                for l in add {
                    let r = normalize_record_name(&l.name, &z.name)
                        .map_err(MutationError::from)
                        .and_then(|name| {
                            let value = normalize_value(l.rtype, &l.value)?;
                            t.create_or_renew_record(&z, &name, l.rtype, &value, l.ttl, None)
                        });
                    match r {
                        Ok((rec, _)) => out.added.push(rec),
                        Err(e) => out.errors.push(BulkError {
                            line: l.line,
                            record_id: None,
                            error: e.to_string(),
                        }),
                    }
                }
                out.errors.sort_by_key(|e| e.line);
                let apply = !preview && out.errors.is_empty();
                *out_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(out.clone());
                if apply {
                    Ok(out)
                } else {
                    // Roll back: a preview, or something failed.
                    Err(MutationError::Invalid(if preview {
                        "bulk edit preview: rolled back".into()
                    } else {
                        "bulk edit has errors: nothing applied".into()
                    }))
                }
            })
            .await;
        match res {
            Ok(out) => Ok(out),
            Err(e) => match slot.lock().unwrap_or_else(|p| p.into_inner()).take() {
                Some(out) => Ok(out),
                None => Err(e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_lines_parse_with_per_line_errors() {
        let (ok, errs) = parse_bulk(
            "www 300 A 192.0.2.1\n\n; comment\n@ IN MX 10 mail.example.com.\nbad\ntxt TXT \"a b\"\nx 60 NOPE 1\n",
        );
        assert_eq!(ok.len(), 3);
        assert_eq!(
            (ok[0].line, ok[0].ttl, ok[0].rtype),
            (1, Some(300), RecordType::A)
        );
        assert_eq!(
            (ok[1].name.as_str(), ok[1].value.as_str()),
            ("@", "10 mail.example.com.")
        );
        assert_eq!(ok[2].value, "\"a b\"");
        assert_eq!(errs.iter().map(|e| e.line).collect::<Vec<_>>(), vec![5, 7]);
    }
}
