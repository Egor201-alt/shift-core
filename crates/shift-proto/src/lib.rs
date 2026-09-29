pub mod crypto;
pub mod frame;
pub mod handshake;
#[cfg(feature = "tokio")]
pub mod masquerade;
pub mod morphing;
pub mod open;
#[cfg(feature = "tokio")]
pub mod tunnel;

pub use crypto::{
    hex_decode32, hex_encode, CipherSuite, DirectionKeys, DirectionState, Psk, Role, SessionKeys,
};
pub use frame::{codec_pair, FrameDecoder, FrameEncoder};
pub use handshake::{
    ClientHandshake, ClientInit, ReplayFilter, ServerHandshake, ServerIdentity, ServerReply,
    CLIENT_INIT_LEN, SERVER_REPLY_LEN,
};
pub use morphing::{AdaptiveShaper, FramePlan, Phase, ShaperConfig, SizeBucket, SizeProfile};
pub use open::{Host, OpenRequest, OpenStatus, Target};

pub const PROTOCOL_VERSION: u8 = 1;
pub const LENGTH_FIELD_LEN: usize = 2;
pub const INNER_HEADER_LEN: usize = 4;
pub const MAX_BODY_LEN: usize = 16 * 1024;
pub const MAX_PAYLOAD_LEN: usize = MAX_BODY_LEN - INNER_HEADER_LEN;
pub const FRAME_OVERHEAD: usize = LENGTH_FIELD_LEN + INNER_HEADER_LEN + crypto::TAG_LEN;
pub const MAX_CLOCK_SKEW_SECS: u64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum ShiftError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("cipher operation failed")]
    Crypto,
    #[error("invalid frame: {0}")]
    InvalidFrame(&'static str),
    #[error("frame body of {len} bytes exceeds the limit of {max}")]
    FrameTooLarge { len: usize, max: usize },
    #[error("handshake failed: {0}")]
    HandshakeFailed(&'static str),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported cipher suite {0}")]
    UnsupportedSuite(u8),
    #[error("timestamp outside the accepted window")]
    ClockSkew,
    #[error("replayed handshake")]
    Replay,
    #[error("low-order public key rejected")]
    WeakKey,
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid open request: {0}")]
    InvalidRequest(&'static str),
}

impl ShiftError {
    pub fn should_fallback(&self) -> bool {
        matches!(
            self,
            ShiftError::AuthenticationFailed
                | ShiftError::UnsupportedVersion(_)
                | ShiftError::UnsupportedSuite(_)
                | ShiftError::ClockSkew
                | ShiftError::Replay
                | ShiftError::WeakKey
                | ShiftError::HandshakeFailed(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, ShiftError>;
