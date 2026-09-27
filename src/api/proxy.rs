//! HAProxy PROXY protocol (v1 and v2) detection on an accepted TCP stream.
//! The header is consumed only when present; plain connections pass through.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Result of looking for a PROXY header on a fresh connection.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyHeader {
    /// No header on the wire: use the socket peer.
    Absent,
    /// A header of the configured version carrying this source address.
    Source(SocketAddr),
    /// A header was present but wrong version / malformed: reject the connection.
    Rejected(&'static str),
}

/// Peek at the stream; if a PROXY header of `version` (1 or 2) is present,
/// consume it and return the original source address.
pub async fn read_proxy_header(stream: &mut TcpStream, version: u8) -> ProxyHeader {
    let mut peek = [0u8; 16];
    let n = match tokio::time::timeout(Duration::from_secs(3), stream.peek(&mut peek)).await {
        Ok(Ok(n)) => n,
        _ => return ProxyHeader::Absent,
    };
    let is_v2 = n >= 12 && peek[..12] == V2_SIG;
    let is_v1 = n >= 6 && &peek[..6] == b"PROXY ";
    match (version, is_v1, is_v2) {
        (2, _, true) => match read_v2(stream).await {
            Some(Some(src)) => ProxyHeader::Source(src),
            Some(None) => ProxyHeader::Absent, // LOCAL / UNSPEC: keep socket peer
            None => ProxyHeader::Rejected("malformed PROXY v2 header"),
        },
        (1, true, _) => match read_v1(stream).await {
            Some(Some(src)) => ProxyHeader::Source(src),
            Some(None) => ProxyHeader::Absent,
            None => ProxyHeader::Rejected("malformed PROXY v1 header"),
        },
        (2, true, _) => ProxyHeader::Rejected("PROXY v1 header received but proxy_version = 2"),
        (1, _, true) => ProxyHeader::Rejected("PROXY v2 header received but proxy_version = 1"),
        _ => ProxyHeader::Absent,
    }
}

/// `None` = malformed; `Some(None)` = valid but carries no address (UNKNOWN).
async fn read_v1(stream: &mut TcpStream) -> Option<Option<SocketAddr>> {
    // Up to 107 bytes terminated by CRLF.
    let mut buf = [0u8; 108];
    let mut have = 0;
    let line_len = loop {
        let n = tokio::time::timeout(Duration::from_secs(3), stream.peek(&mut buf))
            .await
            .ok()?
            .ok()?;
        if let Some(pos) = buf[..n].windows(2).position(|w| w == b"\r\n") {
            break pos + 2;
        }
        if n >= buf.len() || n == have {
            return None;
        }
        have = n;
    };
    let mut line = vec![0u8; line_len];
    stream.read_exact(&mut line).await.ok()?;
    let text = std::str::from_utf8(&line[..line_len - 2]).ok()?;
    let parts: Vec<&str> = text.split(' ').collect();
    // PROXY TCP4 src dst sport dport
    if parts.len() == 6 && (parts[1] == "TCP4" || parts[1] == "TCP6") {
        let ip: IpAddr = parts[2].parse().ok()?;
        let port: u16 = parts[4].parse().ok()?;
        return Some(Some(SocketAddr::new(ip, port)));
    }
    if parts.get(1) == Some(&"UNKNOWN") {
        return Some(None);
    }
    None
}

/// `None` = malformed; `Some(None)` = LOCAL command or unsupported family.
async fn read_v2(stream: &mut TcpStream) -> Option<Option<SocketAddr>> {
    let mut head = [0u8; 16];
    stream.read_exact(&mut head).await.ok()?;
    let ver_cmd = head[12];
    let fam = head[13];
    let len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut body = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut body).await.ok()?;
    }
    if ver_cmd >> 4 != 2 {
        return None;
    }
    if ver_cmd & 0x0f == 0 {
        return Some(None); // LOCAL command: health check from the proxy itself
    }
    match fam >> 4 {
        1 if len >= 12 => {
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Some(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        2 if len >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Some(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)))
        }
        0 => Some(None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn roundtrip(header: Vec<u8>, version: u8) -> (ProxyHeader, Vec<u8>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&header).await.unwrap();
            c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            c
        });
        let (mut s, _) = l.accept().await.unwrap();
        let src = read_proxy_header(&mut s, version).await;
        let _keep = client.await.unwrap();
        let mut rest = vec![0u8; 18];
        s.read_exact(&mut rest).await.unwrap();
        (src, rest)
    }

    #[tokio::test]
    async fn v1() {
        let (src, rest) =
            roundtrip(b"PROXY TCP4 203.0.113.9 10.0.0.1 51234 443\r\n".to_vec(), 1).await;
        assert_eq!(
            src,
            ProxyHeader::Source("203.0.113.9:51234".parse().unwrap())
        );
        assert_eq!(&rest, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[tokio::test]
    async fn v2() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21); // v2, PROXY
        h.push(0x11); // TCP over IPv4
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 7, 10, 0, 0, 1]);
        h.extend_from_slice(&4000u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        let (src, rest) = roundtrip(h.clone(), 2).await;
        assert_eq!(
            src,
            ProxyHeader::Source("203.0.113.7:4000".parse().unwrap())
        );
        assert_eq!(&rest, b"GET / HTTP/1.0\r\n\r\n");
        let (src, _) = roundtrip(h, 1).await;
        assert!(
            matches!(src, ProxyHeader::Rejected(_)),
            "version mismatch is rejected"
        );
        assert_eq!(&rest, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[tokio::test]
    async fn plain() {
        let (src, rest) = roundtrip(vec![], 2).await;
        assert_eq!(src, ProxyHeader::Absent);
        assert_eq!(&rest, b"GET / HTTP/1.0\r\n\r\n");
    }
}
