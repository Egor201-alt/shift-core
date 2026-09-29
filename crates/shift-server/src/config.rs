use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use shift_proto::{Psk, ServerIdentity, ShaperConfig};

#[derive(Parser, Debug)]
#[command(name = "shift-server", version, about = "Shift Protocol server daemon")]
pub struct Cli {
    #[arg(long, env = "SHIFT_LISTEN", default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,

    #[arg(long, env = "SHIFT_FORWARD", default_value = "127.0.0.1:10001")]
    pub forward: SocketAddr,

    #[arg(long, env = "SHIFT_FALLBACK", default_value = "1.1.1.1:443")]
    pub fallback: SocketAddr,

    #[arg(long, env = "SHIFT_PSK")]
    pub psk: String,

    #[arg(long, env = "SHIFT_SERVER_SECRET")]
    pub server_secret: Option<String>,

    #[arg(long, env = "SHIFT_HANDSHAKE_TIMEOUT_MS", default_value_t = 4_000)]
    pub handshake_timeout_ms: u64,

    #[arg(long, env = "SHIFT_FALLBACK_DRAIN_MS", default_value_t = 1_500)]
    pub fallback_drain_ms: u64,

    /// Wrap the handshake and every frame in a fake TLS 1.3 record, preceded
    /// by a real ClientHello. See crates/shift-proto/src/masquerade.rs.
    #[arg(long, env = "SHIFT_CAMOUFLAGE")]
    pub camouflage: bool,

    /// Port used to dial a probe's own ClientHello SNI when camouflage is
    /// on and the SNI parses (real sites almost always mean 443 here).
    #[arg(long, env = "SHIFT_CAMOUFLAGE_PORT", default_value_t = 443)]
    pub camouflage_port: u16,
}

pub struct Identity {
    pub psk: Psk,
    pub server: ServerIdentity,
}

pub struct RuntimeConfig {
    pub listen: SocketAddr,
    pub forward: SocketAddr,
    pub fallback: SocketAddr,
    pub handshake_timeout: Duration,
    pub fallback_drain: Duration,
    pub shaper: ShaperConfig,
    pub camouflage: bool,
    pub camouflage_port: u16,
}

impl RuntimeConfig {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let shaper = ShaperConfig::default();
        shaper.validate()?;
        Ok(RuntimeConfig {
            listen: cli.listen,
            forward: cli.forward,
            fallback: cli.fallback,
            handshake_timeout: Duration::from_millis(cli.handshake_timeout_ms),
            fallback_drain: Duration::from_millis(cli.fallback_drain_ms),
            shaper,
            camouflage: cli.camouflage,
            camouflage_port: cli.camouflage_port,
        })
    }
}

pub fn load_identity(cli: &Cli) -> anyhow::Result<Identity> {
    let psk = Psk::from_passphrase(&cli.psk);
    let server = match &cli.server_secret {
        Some(hex) => ServerIdentity::from_secret_bytes(shift_proto::hex_decode32(hex)?),
        None => {
            let generated = ServerIdentity::generate();
            tracing::warn!(
                secret = %shift_proto::hex_encode(&generated.secret_bytes()),
                public = %shift_proto::hex_encode(&generated.public_bytes()),
                "no --server-secret given: generated an ephemeral identity, save the secret to keep the same public key on restart"
            );
            generated
        }
    };
    Ok(Identity { psk, server })
}
