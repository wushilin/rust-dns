//! Resolve the real client address: PROXY protocol source, then
//! X-Forwarded-For, then X-Real-IP, then the socket peer, honouring headers
//! only when they arrive from a trusted proxy.

use crate::config::Cidr;
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug)]
pub struct ConnInfo {
    pub remote: SocketAddr,
    pub proxy_src: Option<SocketAddr>,
}

#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

fn trusted(cidrs: &[Cidr], ip: IpAddr) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

pub fn resolve(conn: &ConnInfo, headers: &HeaderMap, cidrs: &[Cidr]) -> IpAddr {
    resolve_raw(conn, headers, cidrs).to_canonical()
}

fn resolve_raw(conn: &ConnInfo, headers: &HeaderMap, cidrs: &[Cidr]) -> IpAddr {
    let mut ip = conn.remote.ip().to_canonical();
    if let Some(p) = conn.proxy_src {
        if trusted(cidrs, ip) {
            ip = p.ip();
        }
    }
    if !trusted(cidrs, ip) {
        return ip;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let hops: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        // Walk from the right: the first hop that is not one of our proxies is the client.
        for hop in hops.iter().rev() {
            if !trusted(cidrs, *hop) {
                return *hop;
            }
        }
        if let Some(first) = hops.first() {
            return *first;
        }
    }
    if let Some(real) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
    {
        return real;
    }
    ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_cidrs;

    fn conn(remote: &str, proxy: Option<&str>) -> ConnInfo {
        ConnInfo {
            remote: remote.parse().unwrap(),
            proxy_src: proxy.map(|p| p.parse().unwrap()),
        }
    }
    fn hdr(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn precedence() {
        let cidrs = parse_cidrs(&["10.0.0.0/8".into(), "127.0.0.0/8".into()]);
        // Untrusted remote: headers ignored.
        assert_eq!(
            resolve(
                &conn("8.8.8.8:1", None),
                &hdr(&[("x-forwarded-for", "1.1.1.1")]),
                &cidrs
            ),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        // Trusted remote, XFF with proxy chain.
        assert_eq!(
            resolve(
                &conn("10.0.0.1:1", None),
                &hdr(&[("x-forwarded-for", "1.1.1.1, 10.0.0.2")]),
                &cidrs
            ),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        // Trusted remote, X-Real-IP only.
        assert_eq!(
            resolve(
                &conn("10.0.0.1:1", None),
                &hdr(&[("x-real-ip", "2.2.2.2")]),
                &cidrs
            ),
            "2.2.2.2".parse::<IpAddr>().unwrap()
        );
        // PROXY protocol from trusted proxy wins over remote; untrusted PROXY src stops header trust.
        assert_eq!(
            resolve(
                &conn("10.0.0.1:1", Some("3.3.3.3:5")),
                &hdr(&[("x-forwarded-for", "1.1.1.1")]),
                &cidrs
            ),
            "3.3.3.3".parse::<IpAddr>().unwrap()
        );
        // PROXY src is itself a trusted proxy: keep walking headers.
        assert_eq!(
            resolve(
                &conn("127.0.0.1:1", Some("10.0.0.9:5")),
                &hdr(&[("x-forwarded-for", "4.4.4.4")]),
                &cidrs
            ),
            "4.4.4.4".parse::<IpAddr>().unwrap()
        );
        // PROXY header from an untrusted peer is ignored.
        assert_eq!(
            resolve(&conn("8.8.8.8:1", Some("3.3.3.3:5")), &hdr(&[]), &cidrs),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        // IPv4 clients on a dual-stack listener are reported in plain IPv4 form.
        assert_eq!(
            resolve(&conn("[::ffff:8.8.8.8]:1", None), &hdr(&[]), &cidrs),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        // ...and still count as trusted proxies when their IPv4 range is trusted.
        assert_eq!(
            resolve(
                &conn("[::ffff:10.0.0.1]:1", None),
                &hdr(&[("x-real-ip", "2.2.2.2")]),
                &cidrs
            ),
            "2.2.2.2".parse::<IpAddr>().unwrap()
        );
        // Nothing: remote.
        assert_eq!(
            resolve(&conn("10.0.0.1:1", None), &hdr(&[]), &cidrs),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
