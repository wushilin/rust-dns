//! N1: what every authoritative server of the parent zone says about a
//! zone's DS, for the key rollover wizard. The parent's NS set and their
//! addresses are resolved through the forwarding upstreams (recursion);
//! each address is then asked directly, without recursion (RD=0), so a
//! cached answer somewhere cannot make a change look done before every
//! parent server serves it.

use super::wire;
use super::KeyInfo;
use crate::config::ForwardingConfig;
use crate::dns::forward::{forward, forward_via, UpstreamStrategy};
use crate::dns::Proto;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;

/// One DS record as published, and which of our keys it matches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct SeenDs {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    /// Upper-case hex.
    pub digest: String,
    /// `new`, `old` or `none` (matches neither key).
    pub matches: String,
    /// For a DS that matches neither key: which fields differ from the
    /// expected DS of the key it is closest to (key tag, algorithm, digest
    /// type, digest).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub differs: Vec<String>,
}

/// One parent server's answer.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ParentServer {
    /// The name server's host name.
    pub ns: String,
    /// The address asked (`ip:port`).
    pub address: String,
    /// DS records for the zone in its answer (empty: none).
    pub ds: Vec<SeenDs>,
    /// The DS RRset's TTL (absent when there was none).
    #[schema(required = true)]
    pub ttl: Option<u32>,
    /// Why it could not be asked (timeout, error rcode); the server then
    /// counts as "not confirmed".
    #[schema(required = true)]
    pub error: Option<String>,
}

/// The probe's result: the parent zone and every server's answer.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ParentProbe {
    /// The parent zone (lower case, trailing dot).
    pub parent: String,
    pub servers: Vec<ParentServer>,
    #[schema(format = DateTime)]
    pub checked_at: String,
}

/// What the parent's servers say about a DS, per name server (a name
/// server counts once, whichever of its addresses answered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every name server answered (through at least one address) and every
    /// answer agrees.
    Agree,
    /// At least one answer contradicts (the change is not everywhere yet).
    Disagree,
    /// No answer contradicts, but some name server could not be asked
    /// (timeouts, an address family without a route): try again later.
    Unknown,
}

impl ParentProbe {
    /// Whether the parent publishes a DS matching `which` (`present`) or
    /// does not (`!present`), per name server. An address that did not
    /// answer is ignored when another address of the same name server did
    /// (no IPv6 route on this host, say); a name server none of whose
    /// addresses answered makes the verdict `Unknown`, never `Agree`.
    pub fn verdict(&self, which: &str, present: bool) -> Verdict {
        if self.servers.is_empty() {
            return Verdict::Unknown;
        }
        let mut names: Vec<&str> = self.servers.iter().map(|s| s.ns.as_str()).collect();
        names.sort();
        names.dedup();
        let mut unknown = false;
        for n in names {
            let answered: Vec<&ParentServer> = self
                .servers
                .iter()
                .filter(|s| s.ns == n && s.error.is_none())
                .collect();
            if answered.is_empty() {
                unknown = true;
                continue;
            }
            if answered
                .iter()
                .any(|s| s.ds.iter().any(|d| d.matches == which) != present)
            {
                return Verdict::Disagree;
            }
        }
        if unknown {
            Verdict::Unknown
        } else {
            Verdict::Agree
        }
    }

    /// The longest DS TTL any server returned.
    pub fn ds_ttl(&self) -> Option<u32> {
        self.servers.iter().filter_map(|s| s.ttl).max()
    }
}

/// Classify a DS against the new and old keys (expected digests computed
/// for `apex`).
pub fn classify(
    apex: &Name,
    ds: (u16, u8, u8, Vec<u8>),
    new: &KeyInfo,
    old: Option<&KeyInfo>,
) -> SeenDs {
    let (tag, alg, dt, digest) = ds;
    let matches = |k: &KeyInfo| {
        tag == k.key_tag
            && alg == k.algorithm
            && wire::ds_digest(apex, &k.dnskey_rdata(), dt).as_deref() == Some(digest.as_slice())
    };
    let m = if matches(new) {
        "new"
    } else if old.is_some_and(matches) {
        "old"
    } else {
        "none"
    };
    let mut differs = Vec::new();
    if m == "none" {
        // Compare with the new key's DS (what the owner was asked to add),
        // or the old one's when the key tag is the old key's.
        let k = match old {
            Some(o) if o.key_tag == tag && new.key_tag != tag => o,
            _ => new,
        };
        if tag != k.key_tag {
            differs.push(format!("key tag {tag} (expected {})", k.key_tag));
        }
        if alg != k.algorithm {
            differs.push(format!("algorithm {alg} (expected {})", k.algorithm));
        }
        match wire::ds_digest(apex, &k.dnskey_rdata(), dt) {
            None => differs.push(format!(
                "digest type {dt} (expected 2, SHA-256, or 4, SHA-384)"
            )),
            Some(want) if want != digest => differs.push(format!(
                "digest {} (expected {})",
                hex::encode_upper(&digest),
                hex::encode_upper(&want)
            )),
            Some(_) => {}
        }
    }
    SeenDs {
        key_tag: tag,
        algorithm: alg,
        digest_type: dt,
        digest: hex::encode_upper(&digest),
        matches: m.into(),
        differs,
    }
}

async fn recurse(fwd: &ForwardingConfig, name: &Name, t: RecordType) -> anyhow::Result<Message> {
    let q = super::check::query_bytes(name, t, true, false);
    let b = forward(fwd, &q, Proto::Udp).await?;
    Ok(Message::from_bytes(&b)?)
}

/// Find the parent zone of `apex` (the nearest ancestor with an NS set)
/// and its name servers' addresses, through the forwarding upstreams.
async fn parent_servers(
    fwd: &ForwardingConfig,
    apex: &Name,
    port: u16,
) -> anyhow::Result<(Name, Vec<(String, SocketAddr)>, Vec<String>)> {
    let mut p = apex.base_name();
    loop {
        let m = recurse(fwd, &p, RecordType::NS).await?;
        let ns: Vec<Name> = m
            .answers
            .iter()
            .filter(|r| super::check::same_name(&r.name, &p))
            .filter_map(|r| match &r.data {
                RData::NS(n) => Some(n.0.clone()),
                _ => None,
            })
            .collect();
        if m.metadata.response_code == ResponseCode::NoError && !ns.is_empty() {
            let mut out = Vec::new();
            let mut missing = Vec::new();
            for n in ns {
                let before = out.len();
                for t in [RecordType::A, RecordType::AAAA] {
                    let Ok(a) = recurse(fwd, &n, t).await else {
                        continue;
                    };
                    for r in &a.answers {
                        let ip = match &r.data {
                            RData::A(a) => std::net::IpAddr::V4(a.0),
                            RData::AAAA(a) => std::net::IpAddr::V6(a.0),
                            _ => continue,
                        };
                        out.push((n.to_ascii().to_lowercase(), SocketAddr::new(ip, port)));
                    }
                }
                if out.len() == before {
                    missing.push(n.to_ascii().to_lowercase());
                }
            }
            out.sort();
            out.dedup();
            if out.is_empty() {
                anyhow::bail!("no address for the name servers of {p}");
            }
            return Ok((p, out, missing));
        }
        if p.is_root() {
            anyhow::bail!("no parent zone with name servers found for {apex}");
        }
        p = p.base_name();
    }
}

/// Ask every parent server for `apex`'s DS (RD=0) and classify what each
/// returns against `new` (and `old`). `port`: the port the parent servers
/// are asked on (53; tests use another).
pub async fn probe(
    fwd: &ForwardingConfig,
    apex: &Name,
    port: u16,
    new: &KeyInfo,
    old: Option<&KeyInfo>,
) -> anyhow::Result<ParentProbe> {
    if fwd.upstreams.is_empty() {
        anyhow::bail!("no forwarding upstream is configured to find the parent's name servers (Server settings > Forwarding)");
    }
    let (parent, servers, missing) = parent_servers(fwd, apex, port).await?;
    let q = super::check::query_bytes(apex, RecordType::DS, false, true);
    // All addresses at once (a TLD has a dozen name servers, two addresses
    // each); the answers keep the servers' order.
    let mut set = tokio::task::JoinSet::new();
    for (i, (ns, addr)) in servers.into_iter().enumerate() {
        let (q, apex, new, old) = (q.clone(), apex.clone(), new.clone(), old.cloned());
        let timeout = fwd.timeout_ms.max(2000);
        set.spawn(async move {
            let mut s = ParentServer {
                ns,
                address: addr.to_string(),
                ds: vec![],
                ttl: None,
                error: None,
            };
            let r = forward_via(
                &[addr],
                timeout,
                UpstreamStrategy::InOrder,
                None,
                &q,
                Proto::Udp,
            )
            .await
            .and_then(|b| Ok(Message::from_bytes(&b)?));
            match r {
                Err(e) => s.error = Some(format!("no answer: {e}")),
                Ok(m) => match m.metadata.response_code {
                    ResponseCode::NoError | ResponseCode::NXDomain => {
                        for rr in m.answers.iter().filter(|r| {
                            u16::from(r.record_type()) == wire::T_DS
                                && super::check::same_name(&r.name, &apex)
                        }) {
                            if let Some(ds) = wire::raw_rdata(rr).and_then(wire::parse_ds) {
                                s.ttl = Some(s.ttl.map_or(rr.ttl, |t| t.max(rr.ttl)));
                                s.ds.push(classify(&apex, ds, &new, old.as_ref()));
                            }
                        }
                    }
                    rc => s.error = Some(format!("answered {rc}")),
                },
            }
            (i, s)
        });
    }
    let mut out: Vec<(usize, ParentServer)> = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(v) = r {
            out.push(v);
        }
    }
    out.sort_by_key(|(i, _)| *i);
    let mut out: Vec<ParentServer> = out.into_iter().map(|(_, s)| s).collect();
    // A name server without an address cannot confirm anything.
    for ns in missing {
        out.push(ParentServer {
            ns,
            address: String::new(),
            ds: vec![],
            ttl: None,
            error: Some("no address found for this name server".into()),
        });
    }
    Ok(ParentProbe {
        parent: parent.to_ascii().to_lowercase(),
        servers: out,
        checked_at: crate::model::now_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> KeyInfo {
        let k = super::super::generate_key().unwrap();
        let _ = seed;
        KeyInfo {
            algorithm: super::super::ALGORITHM,
            flags: super::super::CSK_FLAGS,
            key_tag: wire::key_tag(&wire::dnskey_rdata(
                super::super::CSK_FLAGS,
                super::super::ALGORITHM,
                &k.public_key,
            )),
            public_key: k.public_key,
        }
    }

    /// Per name server: an unreachable address of a server that answered
    /// elsewhere is ignored; an unreachable server is "unknown", never
    /// "agree"; one contrary answer is "disagree".
    #[test]
    fn verdict_counts_name_servers_not_addresses() {
        let srv = |ns: &str, matches: Option<&str>, error: bool| ParentServer {
            ns: ns.into(),
            address: "192.0.2.1:53".into(),
            ds: matches
                .map(|m| {
                    vec![SeenDs {
                        key_tag: 1,
                        algorithm: 13,
                        digest_type: 2,
                        digest: "AA".into(),
                        matches: m.into(),
                        differs: vec![],
                    }]
                })
                .unwrap_or_default(),
            ttl: Some(86400),
            error: error.then(|| "no answer".to_string()),
        };
        let p = |servers| ParentProbe {
            parent: "net.".into(),
            servers,
            checked_at: String::new(),
        };
        // a: v4 answers, v6 unreachable; b: answers.
        let both = p(vec![
            srv("a", Some("new"), false),
            srv("a", None, true),
            srv("b", Some("new"), false),
        ]);
        assert_eq!(both.verdict("new", true), Verdict::Agree);
        assert_eq!(both.verdict("old", false), Verdict::Agree);
        let one_down = p(vec![srv("a", Some("new"), false), srv("b", None, true)]);
        assert_eq!(one_down.verdict("new", true), Verdict::Unknown);
        let stale = p(vec![
            srv("a", Some("new"), false),
            srv("b", Some("old"), false),
        ]);
        assert_eq!(stale.verdict("new", true), Verdict::Disagree);
        assert_eq!(stale.verdict("old", false), Verdict::Disagree);
        let none_yet = p(vec![srv("a", None, false), srv("b", None, true)]);
        assert_eq!(none_yet.verdict("new", true), Verdict::Disagree);
        assert_eq!(p(vec![]).verdict("new", true), Verdict::Unknown);
    }

    /// A mistyped DS names the field that differs.
    #[test]
    fn classify_names_the_differing_field() {
        let apex = Name::from_ascii("roll.test.").unwrap();
        let (new, old) = (key(1), key(2));
        let ds = |k: &KeyInfo, dt: u8| {
            (
                k.key_tag,
                k.algorithm,
                dt,
                wire::ds_digest(&apex, &k.dnskey_rdata(), dt).unwrap(),
            )
        };
        assert_eq!(
            classify(&apex, ds(&new, 2), &new, Some(&old)).matches,
            "new"
        );
        assert_eq!(
            classify(&apex, ds(&new, 4), &new, Some(&old)).matches,
            "new"
        );
        assert_eq!(
            classify(&apex, ds(&old, 2), &new, Some(&old)).matches,
            "old"
        );
        // One hex digit off.
        let mut bad = ds(&new, 2);
        bad.3[5] ^= 0x01;
        let c = classify(&apex, bad, &new, Some(&old));
        assert_eq!(c.matches, "none");
        assert_eq!(c.differs.len(), 1, "{c:?}");
        assert!(c.differs[0].starts_with("digest "), "{c:?}");
        // Wrong key tag, right digest.
        let mut bad = ds(&new, 2);
        bad.0 = bad.0.wrapping_add(1);
        let c = classify(&apex, bad, &new, Some(&old));
        assert_eq!(c.differs.len(), 1);
        assert!(c.differs[0].starts_with("key tag"), "{c:?}");
        // Wrong algorithm.
        let mut bad = ds(&new, 2);
        bad.1 = 8;
        let c = classify(&apex, bad, &new, Some(&old));
        assert!(
            c.differs.iter().any(|d| d.starts_with("algorithm")),
            "{c:?}"
        );
        // Unknown digest type.
        let mut bad = ds(&new, 2);
        bad.2 = 3;
        let c = classify(&apex, bad, &new, Some(&old));
        assert!(
            c.differs.iter().any(|d| d.starts_with("digest type")),
            "{c:?}"
        );
    }
}
