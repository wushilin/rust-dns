//! Outbound zone transfer (AXFR, RFC 5936) for secondaries.

use crate::cache::ZoneData;
use crate::zones::{apex_ns, soa_record, to_rr};
use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, Record, RecordType};

/// Message size we try to stay under for each AXFR chunk.
const CHUNK_BYTES: usize = 48 * 1024;

/// Build the full transfer as a sequence of response messages:
/// SOA, apex NS, all other records, SOA.
pub fn build(z: &ZoneData, id: u16, query: &Query) -> Vec<Vec<u8>> {
    let zone = &z.zone;
    let apex = match Name::from_ascii(&z.apex) {
        Ok(a) => a,
        Err(_) => return vec![],
    };
    let Some(soa) = soa_record(z, zone.default_ttl) else {
        return vec![];
    };
    let mut records: Vec<Record> = vec![soa.clone()];
    records.extend(apex_ns(z));
    let mut owners: Vec<&String> = z.names.keys().collect();
    owners.sort();
    for owner in owners {
        let Ok(owner_name) = Name::from_ascii(owner) else {
            continue;
        };
        for r in &z.names[owner] {
            if owner == &z.apex && r.rtype == crate::model::RecordType::NS {
                continue; // already emitted with apex_ns
            }
            if let Some(rr) = to_rr(zone, r, &owner_name) {
                records.push(rr);
            }
        }
    }
    records.push(soa);
    let _ = apex;

    let mut out = Vec::new();
    let mut current = new_message(id, query);
    let mut current_len = 0usize;
    for rr in records {
        let est = rr.name().len() + 12 + rr.data().to_string().len();
        if current_len + est > CHUNK_BYTES && !current.answers().is_empty() {
            out.push(current.to_vec().unwrap_or_default());
            current = new_message(id, query);
            current_len = 0;
        }
        current_len += est;
        current.add_answer(rr);
    }
    out.push(current.to_vec().unwrap_or_default());
    out
}

fn new_message(id: u16, query: &Query) -> Message {
    let mut h = Header::new();
    h.set_id(id)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true);
    let mut m = Message::new();
    m.set_header(h);
    m.add_query(query.clone());
    m
}

/// IXFR over UDP (RFC 1995 §4): a single SOA tells the secondary to use AXFR.
pub fn soa_only(z: &ZoneData, id: u16, query: &Query) -> Option<Vec<u8>> {
    let mut m = new_message(id, query);
    m.add_answer(soa_record(z, z.zone.default_ttl)?);
    m.to_vec().ok()
}

pub fn is_transfer(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::AXFR | RecordType::IXFR)
}
