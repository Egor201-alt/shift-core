pub mod config;
pub mod fallback;
pub mod forwarder;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use shift_proto::masquerade::{self, ParsedClientHello, RECORD_HANDSHAKE, RECORD_HEADER_LEN};
use shift_proto::tunnel::{tune_socket, unix_now, Established};
use shift_proto::{
    AdaptiveShaper, ClientInit, Host, OpenRequest, OpenStatus, ServerHandshake, Target,
    CLIENT_INIT_LEN,
};

pub use config::{load_identity, Cli, Identity, RuntimeConfig};

const MAX_CLIENT_HELLO_LEN: usize = 4096;

pub async fn serve(
    listener: TcpListener,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let runtime = Arc::clone(&runtime);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let result = if runtime.camouflage {
                handle_connection_masqueraded(stream, peer, runtime, server).await
            } else {
                handle_connection_plain(stream, peer, runtime, server).await
            };
            if let Err(err) = result {
                tracing::debug!(%peer, error = %err, "connection ended");
            }
        });
    }
}

pub async fn handle_connection_plain(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> anyhow::Result<()> {
    tune_socket(&stream)?;

    let mut init_buf = BytesMut::with_capacity(CLIENT_INIT_LEN);
    let filled = tokio::time::timeout(
        runtime.handshake_timeout,
        ensure_captured(&mut stream, &mut init_buf, CLIENT_INIT_LEN),
    )
    .await;
    if !matches!(filled, Ok(true)) {
        let target = runtime.fallback.to_string();
        fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
        return Ok(());
    }

    let init = match ClientInit::from_bytes(&init_buf[..CLIENT_INIT_LEN]) {
        Ok(init) => init,
        Err(_) => {
            let target = runtime.fallback.to_string();
            fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
            return Ok(());
        }
    };

    let (reply, keys) = match server.accept(&init, unix_now()) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(%peer, error = %err, "handshake rejected, falling back to decoy");
            let target = runtime.fallback.to_string();
            fallback::drain_to_decoy(stream, init_buf, &target, runtime.fallback_drain).await;
            return Ok(());
        }
    };

    if tokio::time::timeout(
        runtime.handshake_timeout,
        stream.write_all(&reply.to_bytes()),
    )
    .await
    .is_err()
    {
        return Ok(());
    }

    let remainder = if init_buf.len() > CLIENT_INIT_LEN {
        init_buf.split_off(CLIENT_INIT_LEN)
    } else {
        BytesMut::with_capacity(4096)
    };

    let shaper = AdaptiveShaper::new(runtime.shaper.clone(), Instant::now())?;
    let session = Established::new(keys.keys, remainder, shaper);
    finish_connection(stream, peer, runtime, session).await
}

pub async fn handle_connection_masqueraded(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    server: Arc<ServerHandshake>,
) -> anyhow::Result<()> {
    tune_socket(&stream)?;

    let mut capture = BytesMut::new();
    let (hello, consumed) =
        match read_client_hello(&mut stream, &mut capture, runtime.handshake_timeout).await {
            Ok(pair) => pair,
            Err(FallbackNow) => {
                decoy_fallback(stream, capture, None, &runtime).await;
                return Ok(());
            }
        };

    let Some(init) = hello.client_init() else {
        decoy_fallback(stream, capture, hello.server_name.as_deref(), &runtime).await;
        return Ok(());
    };

    let (reply, keys) = match server.accept(&init, unix_now()) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(%peer, error = %err, sni = ?hello.server_name, "handshake rejected, falling back to decoy");
            decoy_fallback(stream, capture, hello.server_name.as_deref(), &runtime).await;
            return Ok(());
        }
    };

    let shaper = AdaptiveShaper::new(runtime.shaper.clone(), Instant::now())?;
    let mut session = Established::new_with_masquerade(keys.keys, BytesMut::new(), shaper, true);

    let mut flight = BytesMut::with_capacity(8192);
    masquerade::build_server_hello(&init, &reply, &hello.cipher_suites, &mut flight);
    session.encode_cover_records(&masquerade::server_flight_record_lens(), &mut flight)?;
    let sent = tokio::time::timeout(runtime.handshake_timeout, stream.write_all(&flight)).await;
    if !matches!(sent, Ok(Ok(()))) {
        return Ok(());
    }

    let after_spec = consumed + masquerade::CHANGE_CIPHER_SPEC_RECORD.len();
    if read_change_cipher_spec(
        &mut stream,
        &mut capture,
        consumed,
        runtime.handshake_timeout,
    )
    .await
    .is_err()
    {
        return Ok(());
    }
    let remainder = capture.split_off(after_spec);
    session.feed_leftover(&remainder);

    finish_connection(stream, peer, runtime, session).await
}

async fn decoy_fallback(
    stream: TcpStream,
    capture: BytesMut,
    sni: Option<&str>,
    runtime: &RuntimeConfig,
) {
    let candidates = fallback::decoy_candidates(
        sni,
        runtime.camouflage_port,
        runtime.fallback,
        runtime.forward,
        runtime.fallback_drain,
    )
    .await;
    fallback::drain_to_decoy_chain(stream, capture, &candidates, runtime.fallback_drain).await;
}

/// Common tail shared by both accept paths once a `Established` session is
/// ready: read the first in-tunnel frame as an [`OpenRequest`], dial the
/// requested (or configured) upstream, and relay.
async fn finish_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<RuntimeConfig>,
    mut session: Established,
) -> anyhow::Result<()> {
    let request_bytes = match tokio::time::timeout(
        runtime.handshake_timeout,
        session.recv_frame(&mut stream),
    )
    .await
    {
        Ok(Ok(Some(bytes))) => bytes,
        _ => return Ok(()),
    };
    let request = OpenRequest::decode(&request_bytes)?;

    let target = match &request {
        OpenRequest::Raw => DialTarget::Addr(runtime.forward),
        OpenRequest::Connect(target) => DialTarget::Named(target_to_string(target)),
    };

    let remote = match dial(target, runtime.handshake_timeout).await {
        Ok(remote) => remote,
        Err(err) => {
            tracing::debug!(%peer, ?request, error = %err, "upstream dial failed");
            let _ = session
                .send(&mut stream, &[OpenStatus::Failed.byte()])
                .await;
            return Ok(());
        }
    };

    session.send(&mut stream, &[OpenStatus::Ok.byte()]).await?;
    tracing::info!(%peer, target = %describe(&request), "tunnel established");
    shift_proto::tunnel::relay(remote, stream, session).await?;
    Ok(())
}

/// Marker error meaning "stop trying to interpret this connection as a
/// Shift client; hand `capture` to the decoy fallback as-is."
struct FallbackNow;

/// Reads the ClientHello record from the start of the connection. Returns
/// its parsed fields alongside how many bytes of `capture` it
/// occupies, so the next stage knows where to continue reading from.
/// `capture` may end up holding a few bytes beyond that boundary already —
/// TCP has no message framing, so a single `read_buf` can pull in the
/// start of the next record too; every stage therefore addresses `capture`
/// by absolute offset rather than by `capture.len()` at call time.
async fn read_client_hello(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    timeout: Duration,
) -> Result<(ParsedClientHello, usize), FallbackNow> {
    let read = async {
        if !ensure_captured(stream, capture, RECORD_HEADER_LEN).await {
            return Err(FallbackNow);
        }
        if capture[0] != RECORD_HANDSHAKE {
            return Err(FallbackNow);
        }
        let len = u16::from_be_bytes([capture[3], capture[4]]) as usize;
        if len == 0 || len > MAX_CLIENT_HELLO_LEN {
            return Err(FallbackNow);
        }
        let total = RECORD_HEADER_LEN + len;
        if !ensure_captured(stream, capture, total).await {
            return Err(FallbackNow);
        }
        let body = &capture[RECORD_HEADER_LEN..total];
        match masquerade::parse_client_hello(body) {
            Ok(parsed) => Ok((parsed, total)),
            Err(_) => Err(FallbackNow),
        }
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(FallbackNow),
    }
}

/// Waits for the client's ChangeCipherSpec record at absolute offset
/// `offset` within `capture`, the last step of the TLS-shaped handshake.
/// See [`read_client_hello`] for why offsets are absolute.
async fn read_change_cipher_spec(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    offset: usize,
    timeout: Duration,
) -> Result<(), FallbackNow> {
    let total = offset + masquerade::CHANGE_CIPHER_SPEC_RECORD.len();
    let read = async {
        if !ensure_captured(stream, capture, total).await {
            return Err(FallbackNow);
        }
        if capture[offset..total] != masquerade::CHANGE_CIPHER_SPEC_RECORD[..] {
            return Err(FallbackNow);
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(FallbackNow),
    }
}

/// Grows `capture` (appending, never discarding) until it holds at least
/// `need_total` bytes from the start of the connection, regardless of
/// whether the read ultimately succeeds — so a caller can always hand the
/// exact bytes seen so far to the decoy fallback. Returns `false` on EOF
/// or a socket error before that many bytes arrived. `capture` may end up
/// slightly longer than `need_total`, since a single `read_buf` call can
/// pull in more than requested when the OS has more already buffered.
async fn ensure_captured(
    stream: &mut TcpStream,
    capture: &mut BytesMut,
    need_total: usize,
) -> bool {
    while capture.len() < need_total {
        capture.reserve(need_total - capture.len());
        match stream.read_buf(capture).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    true
}

enum DialTarget {
    Addr(SocketAddr),
    Named(String),
}

async fn dial(target: DialTarget, timeout: Duration) -> std::io::Result<TcpStream> {
    let stream = match target {
        DialTarget::Addr(addr) => forwarder::dial(addr, timeout).await?,
        DialTarget::Named(name) => {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(name))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timed out")
                })??;
            tune_socket(&stream)?;
            stream
        }
    };
    Ok(stream)
}

fn target_to_string(target: &Target) -> String {
    match &target.host {
        Host::Domain(name) => format!("{name}:{}", target.port),
        other => format!("{other}:{}", target.port),
    }
}

fn describe(request: &OpenRequest) -> String {
    match request {
        OpenRequest::Raw => "forward".to_owned(),
        OpenRequest::Connect(target) => target.to_string(),
    }
}