//! Follow interfaces (I11, dnsmasq `interface=` / `bind-dynamic`): with
//! `[server].interfaces` set, the DNS listeners are bound to the current
//! addresses of those interfaces and re-bound when addresses appear or
//! disappear. Per server (config file), never replicated.
//!
//! Addresses are polled (`getifaddrs`) every `[server].interface_poll_secs`
//! on every platform: one syscall per interval, and the same code on Linux
//! and macOS. (Netlink would notice a change at once on Linux; polling
//! notices it within the interval, which is what `run.sh`'s one-time
//! rewrite of `bind` never did at all.) IPv6 link-local addresses are not
//! bound (they need a scope id and are of no use to DNS clients).

use super::{tcp, udp, DnsServer};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// One interface's addresses and which of them are bound.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct InterfaceStatus {
    #[schema(example = "eth0")]
    pub name: String,
    /// Current addresses (link-local IPv6 left out).
    #[schema(value_type = Vec<String>)]
    pub addresses: Vec<IpAddr>,
    /// Addresses with a DNS listener (UDP and/or TCP) right now.
    #[schema(value_type = Vec<String>)]
    pub bound: Vec<IpAddr>,
}

/// Every address of every interface (`getifaddrs`), by interface name.
pub fn interface_addrs() -> BTreeMap<String, BTreeSet<IpAddr>> {
    let mut out: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    // SAFETY: getifaddrs allocates a list we only read and then free with
    // freeifaddrs; every pointer is checked for null before use.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                .to_string_lossy()
                .into_owned();
            let ip = match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::from(u32::from_be(sa.sin_addr.s_addr).to_be_bytes())
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::from(sa.sin6_addr.s6_addr)
                }
                _ => continue,
            };
            out.entry(name).or_default().insert(ip);
        }
        libc::freeifaddrs(head);
    }
    out
}

/// The addresses to listen on for `wanted` interfaces (link-local IPv6
/// left out), from a snapshot of all interfaces.
pub fn wanted_addrs(
    all: &BTreeMap<String, BTreeSet<IpAddr>>,
    wanted: &[String],
) -> BTreeSet<IpAddr> {
    wanted
        .iter()
        .filter_map(|w| all.get(w))
        .flatten()
        .filter(|ip| !is_link_local_v6(ip))
        .copied()
        .collect()
}

fn is_link_local_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80)
}

/// Addresses to bind and to release to get from `bound` to `want`.
pub fn diff(bound: &BTreeSet<IpAddr>, want: &BTreeSet<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
    (
        want.difference(bound).copied().collect(),
        bound.difference(want).copied().collect(),
    )
}

/// Listeners of one address (aborted on drop).
struct Bound(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Bound {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

/// The interface follower's state, for `/api/status`.
#[derive(Default)]
pub struct Follower {
    status: Mutex<Vec<InterfaceStatus>>,
}

impl Follower {
    pub fn status(&self) -> Vec<InterfaceStatus> {
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Bind listeners for one address; `None` when nothing could be bound.
async fn bind(server: &Arc<DnsServer>, ip: IpAddr) -> Option<Bound> {
    let addr = SocketAddr::new(ip, server.listen.port);
    let mut tasks = Vec::new();
    if server.listen.udp {
        match crate::dns::bind_udp(addr) {
            Ok(sock) => {
                tracing::info!(%addr, "listening for DNS over UDP (interface address)");
                tasks.push(tokio::spawn(udp::run(server.clone(), Arc::new(sock))));
            }
            Err(e) => tracing::warn!(%addr, error = %e, "cannot bind UDP on an interface address"),
        }
    }
    if server.listen.tcp {
        match crate::dns::bind_tcp(addr) {
            Ok(l) => {
                tracing::info!(%addr, "listening for DNS over TCP (interface address)");
                tasks.push(tokio::spawn(tcp::run(server.clone(), l)));
            }
            Err(e) => tracing::warn!(%addr, error = %e, "cannot bind TCP on an interface address"),
        }
    }
    (!tasks.is_empty()).then_some(Bound(tasks))
}

/// Follow `[server].interfaces` until the process exits.
pub async fn follow(server: Arc<DnsServer>) {
    let wanted = server.listen.interfaces.clone();
    let every = std::time::Duration::from_secs(server.listen.interface_poll_secs.max(1));
    let mut bound: BTreeMap<IpAddr, Bound> = BTreeMap::new();
    let mut warned = false;
    loop {
        let all = interface_addrs();
        let want = wanted_addrs(&all, &wanted);
        let have: BTreeSet<IpAddr> = bound.keys().copied().collect();
        let (add, remove) = diff(&have, &want);
        for ip in remove {
            tracing::info!(%ip, "interface address gone; closing its DNS listeners");
            bound.remove(&ip);
        }
        for ip in add {
            if let Some(b) = bind(&server, ip).await {
                bound.insert(ip, b);
            }
        }
        if want.is_empty() && !warned {
            tracing::warn!(interfaces = ?wanted, "none of [server].interfaces has an address yet; DNS is not served until one appears");
            warned = true;
        } else if !want.is_empty() {
            warned = false;
        }
        let status = wanted
            .iter()
            .map(|w| {
                let addresses: Vec<IpAddr> = all
                    .get(w)
                    .map(|s| {
                        s.iter()
                            .filter(|ip| !is_link_local_v6(ip))
                            .copied()
                            .collect()
                    })
                    .unwrap_or_default();
                InterfaceStatus {
                    name: w.clone(),
                    bound: addresses
                        .iter()
                        .filter(|ip| bound.contains_key(ip))
                        .copied()
                        .collect(),
                    addresses,
                }
            })
            .collect();
        *server
            .interfaces
            .status
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = status;
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> BTreeSet<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn address_changes_are_diffed() {
        let (add, rm) = diff(
            &set(&["10.0.0.1", "fd00::1"]),
            &set(&["10.0.0.2", "fd00::1"]),
        );
        assert_eq!(add, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(rm, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
        let (add, rm) = diff(&set(&["10.0.0.1"]), &set(&["10.0.0.1"]));
        assert!(add.is_empty() && rm.is_empty());
        let (add, rm) = diff(&set(&[]), &set(&["10.0.0.1"]));
        assert_eq!((add.len(), rm.len()), (1, 0));
    }

    #[test]
    fn wanted_interfaces_without_link_local() {
        let mut all = BTreeMap::new();
        all.insert(
            "eth0".to_string(),
            set(&["192.0.2.5", "fe80::1", "2001:db8::5"]),
        );
        all.insert("lo".to_string(), set(&["127.0.0.1"]));
        let w = wanted_addrs(&all, &["eth0".into(), "missing".into()]);
        assert_eq!(w, set(&["192.0.2.5", "2001:db8::5"]));
    }

    /// The real interfaces: the loopback interface has 127.0.0.1.
    #[test]
    fn loopback_is_listed() {
        let all = interface_addrs();
        let lo = all
            .iter()
            .find(|(_, a)| a.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(lo.is_some(), "{all:?}");
    }

    /// Following the loopback interface binds 127.0.0.1 and answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn following_an_interface_binds_its_addresses() {
        let lo = interface_addrs()
            .into_iter()
            .find(|(_, a)| a.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()))
            .map(|(n, _)| n)
            .unwrap();
        let port = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };
        let mut cfg = crate::config::Config::default();
        cfg.server.port = port;
        cfg.server.interfaces = vec![lo.clone()];
        cfg.server.interface_poll_secs = 1;
        cfg.rate_limit.max_resolutions_per_second_per_address = 0;
        let server = Arc::new(DnsServer::new(
            Arc::new(crate::cache::Cache::new(crate::cache::Catalog::empty())),
            Arc::new(crate::events::Bus::new(8, 8)),
            Arc::new(crate::ratelimit::RateLimiter::new(
                0,
                std::time::Duration::from_secs(1),
                10,
            )),
            &cfg,
        ));
        let task = tokio::spawn(follow(server.clone()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let st = server.interfaces.status();
            if st
                .first()
                .is_some_and(|s| s.bound.contains(&"127.0.0.1".parse().unwrap()))
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "not bound: {st:?}");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // A CHAOS version.bind query is answered on the followed address.
        let mut m = hickory_proto::op::Message::query();
        let mut q = hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("version.bind.").unwrap(),
            hickory_proto::rr::RecordType::TXT,
        );
        q.set_query_class(hickory_proto::rr::DNSClass::CH);
        m.add_query(q);
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port))
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 12);
        task.abort();
    }
}
