use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn drain_to_decoy(
    client: TcpStream,
    already_read: BytesMut,
    fallback_target: &str,
    drain_timeout: Duration,
) {
    match tokio::time::timeout(drain_timeout, TcpStream::connect(fallback_target)).await {
        Ok(Ok(decoy)) => relay_to_decoy(client, decoy, already_read, fallback_target).await,
        _ => refuse(client, fallback_target, drain_timeout).await,
    }
}

/// Tries every candidate in order and relays the client to the first one
/// that accepts a connection. If none does, the client is drained and
/// closed instead of being left hanging.
pub async fn drain_to_decoy_chain(
    client: TcpStream,
    already_read: BytesMut,
    candidates: &[SocketAddr],
    drain_timeout: Duration,
) {
    for addr in candidates {
        if let Ok(Ok(decoy)) = tokio::time::timeout(drain_timeout, TcpStream::connect(addr)).await {
            relay_to_decoy(client, decoy, already_read, &addr.to_string()).await;
            return;
        }
    }
    refuse(client, "no reachable decoy", drain_timeout).await;
}

/// Builds the ordered decoy target list: the probe's own SNI first (only
/// if it resolves to a public address, so a crafted SNI can never point the
/// server at loopback, LAN or the forward target), then the configured
/// fallback.
pub async fn decoy_candidates(
    sni: Option<&str>,
    sni_port: u16,
    configured: SocketAddr,
    forward: SocketAddr,
    timeout: Duration,
) -> Vec<SocketAddr> {
    let sni_addr = match sni.filter(|name| is_plausible_hostname(name)) {
        Some(name) => resolve_public(name, sni_port, forward, timeout).await,
        None => None,
    };
    let mut candidates = Vec::with_capacity(2);
    candidates.extend(sni_addr);
    if !candidates.contains(&configured) {
        candidates.push(configured);
    }
    candidates
}

async fn resolve_public(
    name: &str,
    port: u16,
    forward: SocketAddr,
    timeout: Duration,
) -> Option<SocketAddr> {
    let mut resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((name, port)))
        .await
        .ok()?
        .ok()?;
    resolved.find(|addr| is_public_ip(addr.ip()) && *addr != forward)
}

fn is_plausible_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name.parse::<IpAddr>().is_err()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => {
                let first = v6.segments()[0];
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80)
            }
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b)))
}

async fn relay_to_decoy(
    mut client: TcpStream,
    mut decoy: TcpStream,
    already_read: BytesMut,
    target: &str,
) {
    let peer = client.peer_addr().ok();
    let _ = decoy.set_nodelay(true);

    if !already_read.is_empty() && decoy.write_all(&already_read).await.is_err() {
        return;
    }

    tracing::debug!(
        ?peer,
        target = target,
        "no valid Shift handshake: relaying to decoy target"
    );
    let _ = tokio::io::copy_bidirectional(&mut client, &mut decoy).await;
}

async fn refuse(mut client: TcpStream, target: &str, drain_timeout: Duration) {
    let peer = client.peer_addr().ok();
    tracing::debug!(
        ?peer,
        target = target,
        "decoy fallback target is unreachable"
    );
    let _ = tokio::time::timeout(drain_timeout, drain_and_close(&mut client)).await;
}

async fn drain_and_close(client: &mut TcpStream) -> std::io::Result<()> {
    let mut sink = [0u8; 4096];
    loop {
        if client.read(&mut sink).await? == 0 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_loopback_addresses_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.10",
            "172.16.5.5",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip} must be rejected");
        }
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} must be accepted");
        }
    }

    #[test]
    fn hostname_filter_rejects_literals_and_single_labels() {
        assert!(is_plausible_hostname("www.example.com"));
        assert!(!is_plausible_hostname("localhost"));
        assert!(!is_plausible_hostname("127.0.0.1"));
        assert!(!is_plausible_hostname("a b.example"));
        assert!(!is_plausible_hostname(""));
    }
}