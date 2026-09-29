use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use shift_proto::ServerHandshake;
use shift_server::{load_identity, serve, Cli, RuntimeConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let identity = load_identity(&cli)?;
    let runtime = Arc::new(RuntimeConfig::from_cli(&cli)?);
    let server = Arc::new(ServerHandshake::new(identity.server, identity.psk));

    tracing::info!(
        listen = %runtime.listen,
        forward = %runtime.forward,
        fallback = %runtime.fallback,
        public_key = %shift_proto::hex_encode(&server.public_key()),
        "starting shift-server"
    );

    let listener = TcpListener::bind(runtime.listen).await?;
    serve(listener, runtime, server).await?;
    Ok(())
}
