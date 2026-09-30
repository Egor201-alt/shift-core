use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use shift_proto::tunnel::relay;
use shift_proto::{CipherSuite, OpenRequest, OpenStatus, Psk};

use crate::pool::ConnectionPool;
use crate::socks5::{read_connect_request, reply_failure, reply_success, Socks5Listener};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_public_key: [u8; 32],
    pub psk: PskSource,
    pub cipher: CipherSuite,
    pub connect_timeout: Duration,
    /// When set, precede the handshake with a real ClientHello for this
    /// hostname and wrap every frame in a fake TLS record. See
    /// `shift_proto::masquerade` for the framing rationale.
    pub camouflage_sni: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PskSource {
    Passphrase(String),
    Hex(String),
}

impl PskSource {
    pub fn resolve(&self) -> shift_proto::Result<Psk> {
        match self {
            PskSource::Passphrase(text) => Ok(Psk::from_passphrase(text)),
            PskSource::Hex(hex) => Psk::from_hex(hex),
        }
    }
}

pub struct RunningClient {
    stop: Arc<AtomicBool>,
}

impl RunningClient {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub async fn run_socks5(config: ClientConfig, bind: SocketAddr) -> std::io::Result<RunningClient> {
    let listener = Socks5Listener::bind(bind).await?;
    tracing::info!(bind = %listener.local_addr()?, server = %config.server_addr, "shift-client SOCKS5 listening");
    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let config = Arc::new(config);
    let pool = ConnectionPool::spawn(Arc::clone(&config), 4, Arc::clone(&stop));

    tokio::spawn(async move {
        loop {
            if loop_stop.load(Ordering::SeqCst) {
                return;
            }
            let (client, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "socks5 accept failed");
                    continue;
                }
            };
            let config = Arc::clone(&config);
            let pool = pool.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_socks_client(client, config, pool).await {
                    tracing::debug!(%peer, error = %err, "socks5 connection ended");
                }
            });
        }
    });

    Ok(RunningClient { stop })
}

async fn handle_socks_client(
    mut client: TcpStream,
    _config: Arc<ClientConfig>,
    pool: ConnectionPool,
) -> std::io::Result<()> {
    let target = read_connect_request(&mut client).await?;
    let (mut server_stream, mut session) = pool.acquire().await?;

    let request = OpenRequest::Connect(target.clone())
        .encode()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    session.send(&mut server_stream, &request).await?;

    let status_frame = session
        .recv_frame(&mut server_stream)
        .await?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof waiting for status",
            )
        })?;

    let status = match status_frame.as_ref() {
        [byte] => OpenStatus::from_byte(*byte)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed open status",
            ))
        }
    };

    if status != OpenStatus::Ok {
        reply_failure(&mut client).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("server refused to open {target}"),
        ));
    }

    reply_success(&mut client).await?;
    relay(client, server_stream, session).await
}
