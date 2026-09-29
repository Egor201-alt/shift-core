use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use shift_proto::tunnel::tune_socket;

pub async fn dial(forward: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(forward))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "forward dial timed out")
        })??;
    tune_socket(&stream)?;
    Ok(stream)
}
