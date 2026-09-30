use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, ShiftError};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const CONFIRM_LEN: usize = 16;
pub const REKEY_INTERVAL: u64 = 1 << 20;

const CTX_SESSION: &str = "shift/v1 session";
const CTX_REKEY_AEAD: &str = "shift/v1 rekey aead";
const CTX_REKEY_LENGTH: &str = "shift/v1 rekey length";
const CTX_PSK_PASSPHRASE: &str = "shift/v1 psk passphrase";
const CTX_CONFIRM: &[u8] = b"shift/v1 server confirm";
const CTX_RESUMPTION_SECRET: &str = "shift/v1 resumption secret";
const CTX_RESUMPTION_AUTH: &str = "shift/v1 resumption auth";
const CTX_RESUMPTION_SESSION: &str = "shift/v1 resumption session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl CipherSuite {
    pub fn id(self) -> u8 {
        match self {
            CipherSuite::ChaCha20Poly1305 => 1,
            CipherSuite::Aes256Gcm => 2,
        }
    }

    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(CipherSuite::ChaCha20Poly1305),
            2 => Ok(CipherSuite::Aes256Gcm),
            other => Err(ShiftError::UnsupportedSuite(other)),
        }
    }

    pub fn preferred() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
                return CipherSuite::Aes256Gcm;
            }
        }
        CipherSuite::ChaCha20Poly1305
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Psk([u8; KEY_LEN]);

impl Psk {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Psk(bytes)
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        Psk(blake3::derive_key(
            CTX_PSK_PASSPHRASE,
            passphrase.as_bytes(),
        ))
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Psk(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Psk(hex_decode32(hex)?))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode32(hex: &str) -> Result<[u8; 32]> {
    let raw = hex.trim().as_bytes();
    if raw.len() != 64 {
        return Err(ShiftError::InvalidConfig("expected 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ShiftError::InvalidConfig("non-hex character")),
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectionKeys {
    aead: [u8; KEY_LEN],
    length: [u8; KEY_LEN],
}

impl DirectionKeys {
    pub fn new(aead: [u8; KEY_LEN], length: [u8; KEY_LEN]) -> Self {
        DirectionKeys { aead, length }
    }
}

impl std::fmt::Debug for DirectionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectionKeys(..)")
    }
}

pub struct SessionKeys {
    pub send: DirectionKeys,
    pub recv: DirectionKeys,
    pub suite: CipherSuite,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<Aes256Gcm>),
}

impl Cipher {
    fn new(suite: CipherSuite, key: &[u8; KEY_LEN]) -> Self {
        let key = GenericArray::from_slice(key);
        match suite {
            CipherSuite::ChaCha20Poly1305 => Cipher::ChaCha(ChaCha20Poly1305::new(key)),
            CipherSuite::Aes256Gcm => Cipher::Aes(Box::new(Aes256Gcm::new(key))),
        }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = match self {
            Cipher::ChaCha(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buf),
            Cipher::Aes(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buf),
        }
        .map_err(|_| ShiftError::Crypto)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<()> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = GenericArray::from_slice(tag);
        match self {
            Cipher::ChaCha(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buf, tag),
            Cipher::Aes(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buf, tag),
        }
        .map_err(|_| ShiftError::AuthenticationFailed)
    }
}

pub struct DirectionState {
    keys: DirectionKeys,
    suite: CipherSuite,
    cipher: Cipher,
    counter: u64,
    rekey_interval: u64,
}

impl DirectionState {
    pub fn new(keys: DirectionKeys, suite: CipherSuite) -> Self {
        let cipher = Cipher::new(suite, &keys.aead);
        DirectionState {
            keys,
            suite,
            cipher,
            counter: 0,
            rekey_interval: REKEY_INTERVAL,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_rekey_interval(mut self, interval: u64) -> Self {
        self.rekey_interval = interval;
        self
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn length_mask(&self) -> u16 {
        let digest = blake3::keyed_hash(&self.keys.length, &self.counter.to_le_bytes());
        let bytes = digest.as_bytes();
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    pub fn seal(&mut self, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self.cipher.seal(&self.nonce(), aad, buf)?;
        self.advance();
        Ok(tag)
    }

    pub fn open(&mut self, aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        self.cipher.open(&self.nonce(), aad, buf, tag)?;
        self.advance();
        Ok(())
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 8..].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }

    fn advance(&mut self) {
        self.counter += 1;
        if self.counter >= self.rekey_interval {
            self.rekey();
        }
    }

    fn rekey(&mut self) {
        let aead = blake3::derive_key(CTX_REKEY_AEAD, &self.keys.aead);
        let length = blake3::derive_key(CTX_REKEY_LENGTH, &self.keys.length);
        self.keys.aead = aead;
        self.keys.length = length;
        self.cipher = Cipher::new(self.suite, &self.keys.aead);
        self.counter = 0;
    }
}

pub(crate) fn derive_session(
    role: Role,
    suite: CipherSuite,
    psk: &Psk,
    dh_static: &[u8; 32],
    dh_ephemeral: &[u8; 32],
    transcript: &[u8; 32],
) -> (SessionKeys, [u8; KEY_LEN]) {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_SESSION);
    hasher.update(psk.as_bytes());
    hasher.update(dh_static);
    hasher.update(dh_ephemeral);
    hasher.update(transcript);
    let mut block = [0u8; KEY_LEN * 5];
    hasher.finalize_xof().fill(&mut block);

    let take = |index: usize| -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&block[index * KEY_LEN..(index + 1) * KEY_LEN]);
        out
    };
    let client_to_server = DirectionKeys::new(take(0), take(1));
    let server_to_client = DirectionKeys::new(take(2), take(3));
    let confirm_key = take(4);
    block.zeroize();

    let (send, recv) = match role {
        Role::Client => (client_to_server, server_to_client),
        Role::Server => (server_to_client, client_to_server),
    };
    (SessionKeys { send, recv, suite }, confirm_key)
}

pub(crate) fn confirm_tag(confirm_key: &[u8; KEY_LEN], transcript: &[u8; 32]) -> [u8; CONFIRM_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(confirm_key);
    hasher.update(CTX_CONFIRM);
    hasher.update(transcript);
    let digest = hasher.finalize();
    let mut out = [0u8; CONFIRM_LEN];
    out.copy_from_slice(&digest.as_bytes()[..CONFIRM_LEN]);
    out
}

pub(crate) fn tags_equal(a: &[u8; CONFIRM_LEN], b: &[u8; CONFIRM_LEN]) -> bool {
    a.ct_eq(b).into()
}

pub(crate) fn seal_token(key: &[u8; KEY_LEN], plaintext: &mut [u8; 16]) -> Result<[u8; TAG_LEN]> {
    Cipher::new(CipherSuite::ChaCha20Poly1305, key).seal(&[0u8; NONCE_LEN], &[], plaintext)
}

pub(crate) fn open_token(
    key: &[u8; KEY_LEN],
    ciphertext: &mut [u8; 16],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    Cipher::new(CipherSuite::ChaCha20Poly1305, key).open(&[0u8; NONCE_LEN], &[], ciphertext, tag)
}

/// Derives a ticket's resumption secret from the same DH outputs and
/// transcript as the full handshake's session keys, under a distinct
/// context string so it is cryptographically independent of them. Both
/// sides compute this once, right after a full handshake; the server then
/// hands the client only a random `ticket_id` to look it up by later, the
/// client already has the secret itself.
pub(crate) fn derive_resumption_secret(
    psk: &Psk,
    dh_static: &[u8; 32],
    dh_ephemeral: &[u8; 32],
    transcript: &[u8; 32],
) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_RESUMPTION_SECRET);
    hasher.update(psk.as_bytes());
    hasher.update(dh_static);
    hasher.update(dh_ephemeral);
    hasher.update(transcript);
    *hasher.finalize().as_bytes()
}

/// The key used to seal/open a resumption request's token, derived from
/// the ticket secret alone (no fresh DH output exists at redemption time).
pub(crate) fn resumption_auth_key(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    blake3::derive_key(CTX_RESUMPTION_AUTH, secret)
}

/// PSK-only key schedule for a resumed session: no fresh Diffie-Hellman
/// output feeds this, so a resumed session's secrecy is bounded by the
/// ticket secret's own protection (and the ticket's single use), not by a
/// fresh ephemeral exchange. Callers that need forward secrecy on every
/// reconnect should use a full handshake (`derive_session`) instead.
pub(crate) fn derive_resumed_session(
    role: Role,
    suite: CipherSuite,
    secret: &[u8; KEY_LEN],
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> (SessionKeys, [u8; KEY_LEN]) {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_RESUMPTION_SESSION);
    hasher.update(secret);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    let mut block = [0u8; KEY_LEN * 5];
    hasher.finalize_xof().fill(&mut block);

    let take = |index: usize| -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&block[index * KEY_LEN..(index + 1) * KEY_LEN]);
        out
    };
    let client_to_server = DirectionKeys::new(take(0), take(1));
    let server_to_client = DirectionKeys::new(take(2), take(3));
    let confirm_key = take(4);
    block.zeroize();

    let (send, recv) = match role {
        Role::Client => (client_to_server, server_to_client),
        Role::Server => (server_to_client, client_to_server),
    };
    (SessionKeys { send, recv, suite }, confirm_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(seed: u8) -> DirectionKeys {
        DirectionKeys::new([seed; KEY_LEN], [seed.wrapping_add(1); KEY_LEN])
    }

    #[test]
    fn seal_open_roundtrip_both_suites() {
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let mut tx = DirectionState::new(keys(7), suite);
            let mut rx = DirectionState::new(keys(7), suite);
            for round in 0..50u8 {
                let mut buf = vec![round; 100 + round as usize];
                let original = buf.clone();
                let tag = tx.seal(b"aad", &mut buf).unwrap();
                assert_ne!(buf, original);
                rx.open(b"aad", &mut buf, &tag).unwrap();
                assert_eq!(buf, original);
            }
        }
    }

    #[test]
    fn tamper_is_rejected() {
        let mut tx = DirectionState::new(keys(1), CipherSuite::ChaCha20Poly1305);
        let mut rx = DirectionState::new(keys(1), CipherSuite::ChaCha20Poly1305);
        let mut buf = vec![9u8; 64];
        let tag = tx.seal(b"aad", &mut buf).unwrap();
        buf[3] ^= 1;
        assert!(matches!(
            rx.open(b"aad", &mut buf, &tag),
            Err(ShiftError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rekey_keeps_both_sides_in_sync() {
        let mut tx =
            DirectionState::new(keys(3), CipherSuite::ChaCha20Poly1305).with_rekey_interval(4);
        let mut rx =
            DirectionState::new(keys(3), CipherSuite::ChaCha20Poly1305).with_rekey_interval(4);
        for round in 0..20u8 {
            let mask_tx = tx.length_mask();
            let mask_rx = rx.length_mask();
            assert_eq!(mask_tx, mask_rx);
            let mut buf = vec![round; 33];
            let original = buf.clone();
            let tag = tx.seal(&[], &mut buf).unwrap();
            rx.open(&[], &mut buf, &tag).unwrap();
            assert_eq!(buf, original);
        }
        assert!(tx.counter() < 4);
    }

    #[test]
    fn psk_hex_parsing() {
        let psk = Psk::from_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(psk.as_bytes(), &[0xab; 32]);
        assert!(Psk::from_hex("zz").is_err());
        assert!(Psk::from_hex(&"g".repeat(64)).is_err());
    }
}
