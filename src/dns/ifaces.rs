//! Follow interfaces (I11, dnsmasq `interface=` / `bind-dynamic`): with
//! `[server].interfaces` set, the DNS listeners are bound to the current
//! addresses of those interfaces and re-bound when addresses appear or
//! disappear. Per server (config file), never replicated.
//!
//! The addresses are always read with `getifaddrs` and diffed against what
//! is bound. When to read them: on Linux a netlink socket subscribed to
//! address changes (`RTM_NEWADDR` / `RTM_DELADDR`) wakes the follower at
//! once, with a full re-read every [`NETLINK_RESYNC`] as a safety net;
//! elsewhere, or when the netlink socket cannot be opened or fails (e.g. a
//! systemd unit without `AF_NETLINK` in `RestrictAddressFamilies`), every
//! `[server].interface_poll_secs`. IPv6 link-local addresses are not bound
//! (they need a scope id and are of no use to DNS clients).

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
/// Unix only: on Windows (O20) there are none, so `[server].interfaces`
/// binds nothing there (use `[server].bind`).
#[cfg(not(unix))]
pub fn interface_addrs() -> BTreeMap<String, BTreeSet<IpAddr>> {
    BTreeMap::new()
}

/// Every address of every interface (`getifaddrs`), by interface name.
#[cfg(unix)]
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

/// With netlink, the addresses are still re-read this often.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const NETLINK_RESYNC: std::time::Duration = std::time::Duration::from_secs(300);

/// Netlink message types that mean "an address changed" (linux/rtnetlink.h),
/// and the ones that mean "messages were lost" (re-read to be safe).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RTM_NEWADDR: u16 = 20;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RTM_DELADDR: u16 = 21;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLMSG_ERROR: u16 = 2;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLMSG_OVERRUN: u16 = 4;

/// Whether a buffer of netlink messages (as read from the socket: a
/// sequence of `nlmsghdr` + payload, 4-byte aligned, native byte order)
/// reports an address change, or anything that warrants a re-read
/// (an error, an overrun, a malformed buffer).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn netlink_addr_change(buf: &[u8]) -> bool {
    let mut at = 0usize;
    while at < buf.len() {
        let Some(hdr) = buf.get(at..at + 16) else {
            return true; // truncated header
        };
        let len = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let kind = u16::from_ne_bytes([hdr[4], hdr[5]]);
        if len < 16 || at + len > buf.len() {
            return true;
        }
        if matches!(
            kind,
            RTM_NEWADDR | RTM_DELADDR | NLMSG_ERROR | NLMSG_OVERRUN
        ) {
            return true;
        }
        at += (len + 3) & !3;
    }
    false
}

#[cfg(target_os = "linux")]
mod netlink {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    /// A netlink route socket subscribed to IPv4 and IPv6 address changes.
    pub struct Watch(AsyncFd<OwnedFd>);

    impl Watch {
        pub fn open() -> io::Result<Watch> {
            // SAFETY: plain socket/bind calls; the fd is owned (closed on
            // drop) from the moment it exists, the address is zeroed and
            // sized correctly.
            unsafe {
                let fd = libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let fd = OwnedFd::from_raw_fd(fd);
                let mut sa: libc::sockaddr_nl = std::mem::zeroed();
                sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                sa.nl_groups = (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
                if libc::bind(
                    fd.as_raw_fd(),
                    &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Watch(AsyncFd::new(fd)?))
            }
        }

        /// Wait until an address changes (all pending messages are read).
        pub async fn changed(&mut self) -> io::Result<()> {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let mut guard = self.0.readable().await?;
                let mut changed = false;
                loop {
                    let r = guard.try_io(|fd| {
                        // SAFETY: reads at most buf.len() bytes into buf.
                        let n = unsafe {
                            libc::recv(
                                fd.as_raw_fd(),
                                buf.as_mut_ptr() as *mut libc::c_void,
                                buf.len(),
                                0,
                            )
                        };
                        if n < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    });
                    match r {
                        Ok(Ok(n)) => changed |= super::netlink_addr_change(&buf[..n]),
                        // The kernel dropped messages: re-read to be safe.
                        Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => changed = true,
                        Ok(Err(e)) => return Err(e),
                        Err(_would_block) => break,
                    }
                }
                if changed {
                    return Ok(());
                }
            }
        }
    }
}

/// What wakes the follower: netlink (Linux) or the poll interval.
enum Wake {
    #[cfg(target_os = "linux")]
    Netlink(netlink::Watch),
    Poll,
}

impl Wake {
    fn open() -> Wake {
        #[cfg(target_os = "linux")]
        match netlink::Watch::open() {
            Ok(w) => {
                tracing::info!("following interface addresses through netlink");
                return Wake::Netlink(w);
            }
            Err(e) => {
                tracing::warn!(error = %e, "netlink unavailable; polling interface addresses every [server].interface_poll_secs")
            }
        }
        #[cfg(not(target_os = "linux"))]
        tracing::info!("polling interface addresses every [server].interface_poll_secs");
        Wake::Poll
    }

    /// Wait for the next re-read; falls back to polling if netlink fails.
    async fn wait(&mut self, every: std::time::Duration) {
        match self {
            #[cfg(target_os = "linux")]
            Wake::Netlink(w) => {
                let r = tokio::select! {
                    r = w.changed() => r,
                    _ = tokio::time::sleep(NETLINK_RESYNC.max(every)) => Ok(()),
                };
                if let Err(e) = r {
                    tracing::warn!(error = %e, "netlink failed; polling interface addresses every [server].interface_poll_secs from now on");
                    *self = Wake::Poll;
                }
            }
            Wake::Poll => tokio::time::sleep(every).await,
        }
    }
}

/// Follow `[server].interfaces` until the process exits.
pub async fn follow(server: Arc<DnsServer>) {
    let wanted = server.listen.interfaces.clone();
    let every = std::time::Duration::from_secs(server.listen.interface_poll_secs.max(1));
    let mut bound: BTreeMap<IpAddr, Bound> = BTreeMap::new();
    let mut warned = false;
    // Opened before the first read, so no change between the two is missed.
    let mut wake = Wake::open();
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
        wake.wait(every).await;
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

    /// One netlink message: header (len, type, flags, seq, pid) + payload,
    /// padded to 4 bytes.
    fn nlmsg(kind: u16, payload: usize) -> Vec<u8> {
        let len = 16 + payload;
        let mut m = Vec::new();
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&1u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.resize(len, 0xaa);
        m.resize((len + 3) & !3, 0);
        m
    }

    #[test]
    fn netlink_address_messages_wake_the_follower() {
        const RTM_NEWLINK: u16 = 16;
        const RTM_NEWROUTE: u16 = 24;
        assert!(!netlink_addr_change(&[]));
        // Link and route messages alone do not.
        let mut other = nlmsg(RTM_NEWLINK, 17);
        other.extend(nlmsg(RTM_NEWROUTE, 28));
        assert!(!netlink_addr_change(&other));
        // An address message anywhere in the buffer does (after an
        // unaligned payload, so the padding is honoured).
        for kind in [RTM_NEWADDR, RTM_DELADDR] {
            let mut buf = other.clone();
            buf.extend(nlmsg(kind, 24));
            assert!(netlink_addr_change(&buf), "{kind}");
        }
        // Errors, overruns and malformed buffers mean "re-read".
        assert!(netlink_addr_change(&nlmsg(NLMSG_ERROR, 20)));
        assert!(netlink_addr_change(&nlmsg(NLMSG_OVERRUN, 0)));
        assert!(netlink_addr_change(&other[..10]), "truncated header");
        let mut bad = nlmsg(RTM_NEWLINK, 4);
        bad[0] = 200; // longer than the buffer
        assert!(netlink_addr_change(&bad));
        let mut bad = nlmsg(RTM_NEWLINK, 4);
        bad[..4].copy_from_slice(&8u32.to_ne_bytes()); // shorter than a header
        assert!(netlink_addr_change(&bad));
    }

    /// Linux: the netlink socket opens (unprivileged) and an address added
    /// in a private network namespace wakes it. The namespace part needs
    /// `unshare -rn` or passwordless sudo; see `tests/netlink.rs` for the
    /// end-to-end test. Here only the socket.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_netlink_socket_opens() {
        netlink::Watch::open().expect("netlink route socket");
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
