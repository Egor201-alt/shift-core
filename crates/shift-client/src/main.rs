use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

use shift_client::core::{run_socks5, PskSource};
use shift_client::ClientConfig;
use shift_proto::CipherSuite;

#[derive(Parser, Debug)]
#[command(name = "shift-cli", version, about = "Shift Protocol CLI client")]
struct Cli {
    #[arg(long, env = "SHIFT_SERVER")]
    server: String,

    #[arg(long, env = "SHIFT_SERVER_PUBLIC_KEY")]
    server_public_key: String,

    #[arg(long, env = "SHIFT_PSK")]
    psk: String,

    #[arg(long, env = "SHIFT_SOCKS_BIND", default_value = "127.0.0.1:1080")]
    socks_bind: SocketAddr,

    #[arg(long, env = "SHIFT_CIPHER", default_value = "auto")]
    cipher: String,

    #[arg(long, env = "SHIFT_CONNECT_TIMEOUT_MS", default_value_t = 5_000)]
    connect_timeout_ms: u64,

    /// Real hostname to wrap the handshake in a camouflage TLS ClientHello
    /// for (e.g. www.cloudflare.com). Must match what the server expects.
    #[arg(long, env = "SHIFT_CAMOUFLAGE_SNI")]
    camouflage_sni: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let server_public_key = shift_proto::hex_decode32(&cli.server_public_key)?;
    let cipher = match cli.cipher.as_str() {
        "auto" => CipherSuite::preferred(),
        "chacha20poly1305" => CipherSuite::ChaCha20Poly1305,
        "aes256gcm" => CipherSuite::Aes256Gcm,
        other => {
            anyhow::bail!("unknown cipher '{other}', expected auto|chacha20poly1305|aes256gcm")
        }
    };

    let config = ClientConfig {
        server_addr: cli.server,
        server_public_key,
        psk: PskSource::Passphrase(cli.psk),
        cipher,
        connect_timeout: Duration::from_millis(cli.connect_timeout_ms),
        camouflage_sni: cli.camouflage_sni,
    };

    let running = run_socks5(config, cli.socks_bind).await?;
    tokio::signal::ctrl_c().await?;
    running.stop();
    Ok(())
}
