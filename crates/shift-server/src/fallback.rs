use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn drain_to_decoy(
    mut client: TcpStream,
    already_read: BytesMut,
    fallback_target: &str,
    drain_timeout: Duration,
) {
    let peer = client.peer_addr().ok();
    let mut decoy =
        match tokio::time::timeout(drain_timeout, TcpStream::connect(fallback_target)).await {
            Ok(Ok(stream)) => stream,
            _ => {
                tracing::debug!(
                    ?peer,
                    target = fallback_target,
                    "decoy fallback target is unreachable"
                );
                let _ = tokio::time::timeout(drain_timeout, drain_and_close(&mut client)).await;
                return;
            }
        };
    let _ = decoy.set_nodelay(true);

    if !already_read.is_empty() && decoy.write_all(&already_read).await.is_err() {
        return;
    }

    tracing::debug!(
        ?peer,
        target = fallback_target,
        "no valid Shift handshake: relaying to decoy target"
    );
    let _ = tokio::io::copy_bidirectional(&mut client, &mut decoy).await;
}

async fn drain_and_close(client: &mut TcpStream) -> std::io::Result<()> {
    let mut sink = [0u8; 4096];
    loop {
        if client.read(&mut sink).await? == 0 {
            return Ok(());
        }
    }
}
