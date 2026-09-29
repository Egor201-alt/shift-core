use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::masquerade::{self, RECORD_APPLICATION_DATA};
use crate::{
    codec_pair, AdaptiveShaper, CipherSuite, ClientHandshake, FrameDecoder, FrameEncoder, Psk,
    ServerReply, SessionKeys, ShaperConfig, ShiftError, SERVER_REPLY_LEN,
};

pub const READ_CHUNK: usize = 64 * 1024;

pub fn io_error(err: ShiftError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub fn tune_socket(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(20));
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

pub struct Established {
    encoder: FrameEncoder,
    decoder: FrameDecoder,
    inbound: BytesMut,
    shaper: AdaptiveShaper,
    masquerade: bool,
}

impl Established {
    pub fn new(keys: SessionKeys, inbound: BytesMut, shaper: AdaptiveShaper) -> Self {
        Self::new_with_masquerade(keys, inbound, shaper, false)
    }

    pub fn new_with_masquerade(
        keys: SessionKeys,
        inbound: BytesMut,
        shaper: AdaptiveShaper,
        masquerade: bool,
    ) -> Self {
        let (encoder, decoder) = codec_pair(keys);
        Established {
            encoder,
            decoder,
            inbound,
            shaper,
            masquerade,
        }
    }

    pub async fn send<W>(&mut self, writer: &mut W, data: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let now = Instant::now();
        let mut out = BytesMut::with_capacity(data.len() + 256);
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let plan = self.shaper.plan(now, remaining);
            let take = plan.payload_len.clamp(1, remaining);
            self.encoder
                .encode(&data[offset..offset + take], plan.padding_len, &mut out)
                .map_err(io_error)?;
            offset += take;
        }
        write_maybe_wrapped(writer, &out, self.masquerade).await
    }

    pub async fn recv_frame<R>(&mut self, reader: &mut R) -> io::Result<Option<BytesMut>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some(payload) = self.decoder.decode(&mut self.inbound).map_err(io_error)? {
                return Ok(Some(payload));
            }
            if !fill_maybe_wrapped(reader, &mut self.inbound, self.masquerade).await? {
                return if self.inbound.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }
}

async fn write_maybe_wrapped<W>(writer: &mut W, payload: &[u8], masquerade: bool) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if masquerade {
        masquerade::write_application_data(writer, payload).await
    } else {
        writer.write_all(payload).await
    }
}

/// Reads more bytes into `inbound`. Returns `Ok(false)` on a clean,
/// frame-boundary-aligned end of stream, matching the `read_buf() == 0`
/// convention of the non-masquerade path.
async fn fill_maybe_wrapped<R>(
    reader: &mut R,
    inbound: &mut BytesMut,
    masquerade: bool,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    if masquerade {
        match masquerade::read_record(
            reader,
            RECORD_APPLICATION_DATA,
            masquerade::MAX_RECORD_PAYLOAD,
        )
        .await
        {
            Ok(record) => {
                inbound.extend_from_slice(&record);
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && inbound.is_empty() => {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    } else {
        inbound.reserve(READ_CHUNK);
        Ok(reader.read_buf(inbound).await? > 0)
    }
}

pub async fn client_handshake(
    stream: &mut TcpStream,
    psk: &Psk,
    server_public: [u8; 32],
    suite: CipherSuite,
    shaper: &ShaperConfig,
    timeout: Duration,
) -> io::Result<Established> {
    let (handshake, init) =
        ClientHandshake::start(psk, server_public, suite, unix_now()).map_err(io_error)?;
    let exchange = async {
        stream.write_all(&init.to_bytes()).await?;
        let mut reply = [0u8; SERVER_REPLY_LEN];
        stream.read_exact(&mut reply).await?;
        Ok::<_, io::Error>(reply)
    };
    let raw = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;
    let reply = ServerReply::from_bytes(&raw).map_err(io_error)?;
    let keys = handshake.finish(&reply).map_err(io_error)?;
    let shaper = AdaptiveShaper::new(shaper.clone(), Instant::now()).map_err(io_error)?;
    Ok(Established::new(
        keys,
        BytesMut::with_capacity(READ_CHUNK),
        shaper,
    ))
}

/// Same handshake as [`client_handshake`], but preceded by a real,
/// browser-shaped TLS ClientHello for `camouflage_sni`, and with every
/// frame from this point on wrapped in a fake `application_data` TLS
/// record. See `masquerade.rs` for the framing rationale.
pub async fn client_handshake_masqueraded(
    stream: &mut TcpStream,
    psk: &Psk,
    server_public: [u8; 32],
    suite: CipherSuite,
    shaper: &ShaperConfig,
    timeout: Duration,
    camouflage_sni: &str,
) -> io::Result<Established> {
    let (handshake, init) =
        ClientHandshake::start(psk, server_public, suite, unix_now()).map_err(io_error)?;
    let exchange = async {
        let hello = masquerade::build_client_hello(camouflage_sni).map_err(io_error)?;
        stream.write_all(&hello).await?;
        masquerade::write_application_data(stream, &init.to_bytes()).await?;
        let reply =
            masquerade::read_record(stream, RECORD_APPLICATION_DATA, SERVER_REPLY_LEN + 64).await?;
        Ok::<_, io::Error>(reply)
    };
    let raw = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;
    let reply = ServerReply::from_bytes(&raw).map_err(io_error)?;
    let keys = handshake.finish(&reply).map_err(io_error)?;
    let shaper = AdaptiveShaper::new(shaper.clone(), Instant::now()).map_err(io_error)?;
    Ok(Established::new_with_masquerade(
        keys,
        BytesMut::with_capacity(READ_CHUNK),
        shaper,
        true,
    ))
}

pub async fn relay<L, R>(local: L, remote: R, session: Established) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let Established {
        mut encoder,
        mut decoder,
        mut inbound,
        mut shaper,
        masquerade,
    } = session;
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let upstream = async {
        let mut chunk = BytesMut::with_capacity(READ_CHUNK);
        let mut out = BytesMut::with_capacity(READ_CHUNK + 4096);
        loop {
            chunk.clear();
            chunk.reserve(READ_CHUNK);
            let read = local_read.read_buf(&mut chunk).await?;
            if read == 0 {
                let _ = remote_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            let now = Instant::now();
            shaper.observe(now, read);
            let mut delay: Option<Duration> = None;
            let mut offset = 0;
            while offset < read {
                let remaining = read - offset;
                let plan = shaper.plan(now, remaining);
                let take = plan.payload_len.clamp(1, remaining);
                encoder
                    .encode(&chunk[offset..offset + take], plan.padding_len, &mut out)
                    .map_err(io_error)?;
                offset += take;
                delay = delay.max(plan.delay);
            }
            if let Some(pause) = delay {
                tokio::time::sleep(pause).await;
            }
            write_maybe_wrapped(&mut remote_write, &out, masquerade).await?;
            out.clear();
        }
    };

    let downstream = async {
        loop {
            while let Some(payload) = decoder.decode(&mut inbound).map_err(io_error)? {
                local_write.write_all(&payload).await?;
            }
            if !fill_maybe_wrapped(&mut remote_read, &mut inbound, masquerade).await? {
                if inbound.has_remaining() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                let _ = local_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
        }
    };

    tokio::try_join!(upstream, downstream).map(|_| ())
}
