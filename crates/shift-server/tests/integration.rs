use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use shift_client::core::{run_socks5, PskSource};
use shift_client::ClientConfig;
use shift_proto::{CipherSuite, Psk, ServerHandshake, ServerIdentity};
use shift_server::{serve, RuntimeConfig};

async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    let read = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn socks5_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [5, 0]);

    let SocketAddr::V4(v4) = target else {
        panic!("test target must be IPv4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks5 connect should succeed");
    stream
}

#[tokio::test]
async fn full_tunnel_relays_bytes_end_to_end() {
    let echo_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("integration-test-psk");
    let identity = ServerIdentity::generate();
    let server_public_key = identity.public_bytes();
    let handshake = Arc::new(ServerHandshake::new(identity, psk.clone()));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let fallback_addr = spawn_echo_server().await;

    let runtime_cfg = Arc::new(RuntimeConfig {
        listen: server_addr,
        forward: echo_addr,
        fallback: fallback_addr,
        handshake_timeout: Duration::from_secs(5),
        fallback_drain: Duration::from_millis(500),
        shaper: shift_proto::ShaperConfig::default(),
        camouflage: false,
        camouflage_port: 443,
    });
    tokio::spawn(serve(server_listener, runtime_cfg, handshake));

    let client_config = ClientConfig {
        server_addr: server_addr.to_string(),
        server_public_key,
        psk: PskSource::Passphrase("integration-test-psk".to_owned()),
        cipher: CipherSuite::preferred(),
        connect_timeout: Duration::from_secs(5),
        camouflage_sni: None,
    };
    let socks_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socks_listener = tokio::net::TcpListener::bind(socks_bind).await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    run_socks5(client_config, socks_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut tunnel = socks5_connect(socks_addr, echo_addr).await;

    for round in 0..20u8 {
        let payload: Vec<u8> = (0..(500 + round as usize * 37))
            .map(|i| (i as u8).wrapping_add(round))
            .collect();
        tunnel.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round {round} mismatch");
    }
}

#[tokio::test]
async fn wrong_psk_falls_back_instead_of_reaching_forward() {
    let real_forward = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("server-secret");
    let identity = ServerIdentity::generate();
    let server_public_key = identity.public_bytes();
    let handshake = Arc::new(ServerHandshake::new(identity, psk));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let runtime_cfg = Arc::new(RuntimeConfig {
        listen: server_addr,
        forward: real_forward,
        fallback: fallback_addr,
        handshake_timeout: Duration::from_secs(2),
        fallback_drain: Duration::from_millis(500),
        shaper: shift_proto::ShaperConfig::default(),
        camouflage: false,
        camouflage_port: 443,
    });
    tokio::spawn(serve(server_listener, runtime_cfg, handshake));

    let client_config = ClientConfig {
        server_addr: server_addr.to_string(),
        server_public_key,
        psk: PskSource::Passphrase("wrong-guess".to_owned()),
        cipher: CipherSuite::preferred(),
        connect_timeout: Duration::from_secs(2),
        camouflage_sni: None,
    };
    let socks_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socks_listener = tokio::net::TcpListener::bind(socks_addr).await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    run_socks5(client_config, socks_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut direct = TcpStream::connect(socks_addr).await.unwrap();
    direct.write_all(&[5, 1, 0]).await.unwrap();
    let mut method_reply = [0u8; 2];
    let outcome =
        tokio::time::timeout(Duration::from_secs(2), direct.read_exact(&mut method_reply)).await;
    assert!(
        outcome.is_ok(),
        "server must still speak to fallback path, not hang"
    );
}

#[tokio::test]
async fn masqueraded_tunnel_relays_bytes_end_to_end() {
    let echo_addr = spawn_echo_server().await;
    let fallback_addr = spawn_echo_server().await;

    let psk = Psk::from_passphrase("camouflage-test-psk");
    let identity = ServerIdentity::generate();
    let server_public_key = identity.public_bytes();
    let handshake = Arc::new(ServerHandshake::new(identity, psk.clone()));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let runtime_cfg = Arc::new(RuntimeConfig {
        listen: server_addr,
        forward: echo_addr,
        fallback: fallback_addr,
        handshake_timeout: Duration::from_secs(5),
        fallback_drain: Duration::from_millis(500),
        shaper: shift_proto::ShaperConfig::default(),
        camouflage: true,
        camouflage_port: 443,
    });
    tokio::spawn(serve(server_listener, runtime_cfg, handshake));

    let client_config = ClientConfig {
        server_addr: server_addr.to_string(),
        server_public_key,
        psk: PskSource::Passphrase("camouflage-test-psk".to_owned()),
        cipher: CipherSuite::preferred(),
        connect_timeout: Duration::from_secs(5),
        camouflage_sni: Some("www.example.com".to_owned()),
    };
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    run_socks5(client_config, socks_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut tunnel = socks5_connect(socks_addr, echo_addr).await;
    for round in 0..15u8 {
        let payload: Vec<u8> = (0..(600 + round as usize * 41))
            .map(|i| (i as u8).wrapping_mul(3).wrapping_add(round))
            .collect();
        tunnel.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round {round} mismatch");
    }
}
