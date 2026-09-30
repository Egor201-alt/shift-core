use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::Mutex;

use shift_proto::tunnel::{
    client_handshake, client_handshake_masqueraded, tune_socket, Established,
};
use shift_proto::ShaperConfig;

use crate::ClientConfig;

const MAX_IDLE_SECS: u64 = 45;

pub struct PooledConnection {
    pub stream: TcpStream,
    pub session: Established,
    pub created_at: Instant,
}

/// A pre-warmed pool of authenticated Shift sessions. Holding ready
/// connections amortizes the TLS 1.3 masquerade and X25519 handshake
/// over subsequent SOCKS5 requests, eliminating per-connection latency
/// without suffering from TCP Head-of-Line blocking.
#[derive(Clone)]
pub struct ConnectionPool {
    rx: Arc<Mutex<Receiver<PooledConnection>>>,
    config: Arc<ClientConfig>,
}

impl ConnectionPool {
    pub fn spawn(config: Arc<ClientConfig>, pool_size: usize, stop: Arc<AtomicBool>) -> Self {
        let (tx, rx) = channel(pool_size);
        let worker_config = Arc::clone(&config);

        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                match establish_connection(&worker_config).await {
                    Ok(conn) => {
                        if tx.send(conn).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                }
            }
        });

        ConnectionPool {
            rx: Arc::new(Mutex::new(rx)),
            config,
        }
    }

    /// Acquires an established connection from the pool, or falls back to
    /// connecting on demand if the pool is exhausted.
    pub async fn acquire(&self) -> std::io::Result<(TcpStream, Established)> {
        let mut guard = self.rx.lock().await;
        while let Ok(conn) = guard.try_recv() {
            if conn.created_at.elapsed() < Duration::from_secs(MAX_IDLE_SECS) {
                return Ok((conn.stream, conn.session));
            }
        }
        drop(guard);

        let conn = establish_connection(&self.config).await?;
        Ok((conn.stream, conn.session))
    }
}

pub async fn establish_connection(config: &ClientConfig) -> std::io::Result<PooledConnection> {
    let psk = config
        .psk
        .resolve()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    let mut stream = TcpStream::connect(&config.server_addr).await?;
    tune_socket(&stream)?;

    let shaper = ShaperConfig::default();
    let session = match &config.camouflage_sni {
        Some(sni) => {
            client_handshake_masqueraded(
                &mut stream,
                &psk,
                config.server_public_key,
                config.cipher,
                &shaper,
                config.connect_timeout,
                sni,
            )
            .await?
        }
        None => {
            client_handshake(
                &mut stream,
                &psk,
                config.server_public_key,
                config.cipher,
                &shaper,
                config.connect_timeout,
            )
            .await?
        }
    };

    Ok(PooledConnection {
        stream,
        session,
        created_at: Instant::now(),
    })
}
