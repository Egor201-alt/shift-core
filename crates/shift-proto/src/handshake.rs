use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{
    confirm_tag, derive_session, open_token, seal_token, tags_equal, CipherSuite, Psk, Role,
    SessionKeys, CONFIRM_LEN, TAG_LEN,
};
use crate::{Result, ShiftError, MAX_CLOCK_SKEW_SECS, PROTOCOL_VERSION};

pub const CLIENT_INIT_LEN: usize = 64;
pub const SERVER_REPLY_LEN: usize = 32 + CONFIRM_LEN;
const TOKEN_PLAIN_LEN: usize = 16;
const REPLAY_CAPACITY: usize = 1 << 20;
const REPLAY_PRUNE_INTERVAL_SECS: u64 = 30;

const CTX_AUTH: &str = "shift/v1 auth";
const CTX_TRANSCRIPT: &str = "shift/v1 transcript";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientInit {
    pub ephemeral_public: [u8; 32],
    pub token: [u8; 32],
}

impl ClientInit {
    pub fn to_bytes(&self) -> [u8; CLIENT_INIT_LEN] {
        let mut out = [0u8; CLIENT_INIT_LEN];
        out[..32].copy_from_slice(&self.ephemeral_public);
        out[32..].copy_from_slice(&self.token);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CLIENT_INIT_LEN {
            return Err(ShiftError::HandshakeFailed("bad client init length"));
        }
        Ok(Self::parse_prefix(bytes))
    }

    pub fn peek(src: &[u8]) -> Option<Self> {
        if src.len() < CLIENT_INIT_LEN {
            return None;
        }
        Some(Self::parse_prefix(src))
    }

    fn parse_prefix(bytes: &[u8]) -> Self {
        let mut ephemeral_public = [0u8; 32];
        let mut token = [0u8; 32];
        ephemeral_public.copy_from_slice(&bytes[..32]);
        token.copy_from_slice(&bytes[32..CLIENT_INIT_LEN]);
        ClientInit {
            ephemeral_public,
            token,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerReply {
    pub ephemeral_public: [u8; 32],
    pub confirm: [u8; CONFIRM_LEN],
}

impl ServerReply {
    pub fn to_bytes(&self) -> [u8; SERVER_REPLY_LEN] {
        let mut out = [0u8; SERVER_REPLY_LEN];
        out[..32].copy_from_slice(&self.ephemeral_public);
        out[32..].copy_from_slice(&self.confirm);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SERVER_REPLY_LEN {
            return Err(ShiftError::HandshakeFailed("bad server reply length"));
        }
        Ok(Self::parse_prefix(bytes))
    }

    pub fn peek(src: &[u8]) -> Option<Self> {
        if src.len() < SERVER_REPLY_LEN {
            return None;
        }
        Some(Self::parse_prefix(src))
    }

    fn parse_prefix(bytes: &[u8]) -> Self {
        let mut ephemeral_public = [0u8; 32];
        let mut confirm = [0u8; CONFIRM_LEN];
        ephemeral_public.copy_from_slice(&bytes[..32]);
        confirm.copy_from_slice(&bytes[32..SERVER_REPLY_LEN]);
        ServerReply {
            ephemeral_public,
            confirm,
        }
    }
}

pub struct ServerIdentity {
    secret: StaticSecret,
    public: PublicKey,
}

impl ServerIdentity {
    pub fn generate() -> Self {
        Self::from_secret_bytes(StaticSecret::random_from_rng(OsRng).to_bytes())
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        ServerIdentity { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

pub struct ReplayFilter {
    inner: Mutex<ReplayInner>,
}

struct ReplayInner {
    seen: HashMap<[u8; 32], u64>,
    last_prune: u64,
}

impl ReplayFilter {
    pub fn new() -> Self {
        ReplayFilter {
            inner: Mutex::new(ReplayInner {
                seen: HashMap::new(),
                last_prune: 0,
            }),
        }
    }

    pub fn register(&self, id: [u8; 32], timestamp: u64, now: u64) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let inner = &mut *guard;
        if now.saturating_sub(inner.last_prune) >= REPLAY_PRUNE_INTERVAL_SECS {
            inner.seen.retain(|_, expiry| *expiry > now);
            inner.last_prune = now;
        }
        if inner.seen.contains_key(&id) {
            return Err(ShiftError::Replay);
        }
        if inner.seen.len() >= REPLAY_CAPACITY {
            return Err(ShiftError::HandshakeFailed("replay cache is full"));
        }
        inner
            .seen
            .insert(id, timestamp.saturating_add(MAX_CLOCK_SKEW_SECS + 1));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn checked_dh(secret: &StaticSecret, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(ShiftError::WeakKey);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

fn auth_key(
    psk: &Psk,
    dh: &[u8; 32],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_AUTH);
    hasher.update(psk.as_bytes());
    hasher.update(dh);
    hasher.update(client_public);
    hasher.update(server_public);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn transcript_hash(
    init: &ClientInit,
    server_static: &[u8; 32],
    server_ephemeral: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_TRANSCRIPT);
    hasher.update(&init.ephemeral_public);
    hasher.update(&init.token);
    hasher.update(server_static);
    hasher.update(server_ephemeral);
    *hasher.finalize().as_bytes()
}

pub struct ClientHandshake {
    secret: StaticSecret,
    psk: Psk,
    suite: CipherSuite,
    server_public: [u8; 32],
    dh_static: Zeroizing<[u8; 32]>,
    init: ClientInit,
}

impl ClientHandshake {
    pub fn start(
        psk: &Psk,
        server_public: [u8; 32],
        suite: CipherSuite,
        now_unix: u64,
    ) -> Result<(Self, ClientInit)> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let dh_static = checked_dh(&secret, &server_public)?;
        let key = auth_key(psk, &dh_static, public.as_bytes(), &server_public);

        let mut plain = [0u8; TOKEN_PLAIN_LEN];
        plain[0] = PROTOCOL_VERSION;
        plain[1] = suite.id();
        plain[2..10].copy_from_slice(&now_unix.to_be_bytes());
        OsRng.fill_bytes(&mut plain[10..]);
        let tag = seal_token(&key, &mut plain)?;

        let mut token = [0u8; 32];
        token[..TOKEN_PLAIN_LEN].copy_from_slice(&plain);
        token[TOKEN_PLAIN_LEN..].copy_from_slice(&tag);

        let init = ClientInit {
            ephemeral_public: *public.as_bytes(),
            token,
        };
        let handshake = ClientHandshake {
            secret,
            psk: psk.clone(),
            suite,
            server_public,
            dh_static,
            init,
        };
        Ok((handshake, init))
    }

    pub fn finish(self, reply: &ServerReply) -> Result<SessionKeys> {
        let dh_ephemeral = checked_dh(&self.secret, &reply.ephemeral_public)?;
        let transcript = transcript_hash(&self.init, &self.server_public, &reply.ephemeral_public);
        let (keys, confirm_key) = derive_session(
            Role::Client,
            self.suite,
            &self.psk,
            &self.dh_static,
            &dh_ephemeral,
            &transcript,
        );
        let confirm_key = Zeroizing::new(confirm_key);
        let expected = confirm_tag(&confirm_key, &transcript);
        if !tags_equal(&expected, &reply.confirm) {
            return Err(ShiftError::AuthenticationFailed);
        }
        Ok(keys)
    }
}

pub struct ServerHandshake {
    identity: ServerIdentity,
    psk: Psk,
    replay: ReplayFilter,
}

impl ServerHandshake {
    pub fn new(identity: ServerIdentity, psk: Psk) -> Self {
        ServerHandshake {
            identity,
            psk,
            replay: ReplayFilter::new(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_bytes()
    }

    pub fn replay_filter(&self) -> &ReplayFilter {
        &self.replay
    }

    pub fn accept(&self, init: &ClientInit, now_unix: u64) -> Result<(ServerReply, SessionKeys)> {
        let server_public = self.identity.public_bytes();
        let dh_static = checked_dh(&self.identity.secret, &init.ephemeral_public)?;
        let key = auth_key(
            &self.psk,
            &dh_static,
            &init.ephemeral_public,
            &server_public,
        );

        let mut plain = [0u8; TOKEN_PLAIN_LEN];
        let mut tag = [0u8; TAG_LEN];
        plain.copy_from_slice(&init.token[..TOKEN_PLAIN_LEN]);
        tag.copy_from_slice(&init.token[TOKEN_PLAIN_LEN..]);
        open_token(&key, &mut plain, &tag)?;

        if plain[0] != PROTOCOL_VERSION {
            return Err(ShiftError::UnsupportedVersion(plain[0]));
        }
        let suite = CipherSuite::from_id(plain[1])?;
        let mut stamp = [0u8; 8];
        stamp.copy_from_slice(&plain[2..10]);
        let timestamp = u64::from_be_bytes(stamp);
        if timestamp.abs_diff(now_unix) > MAX_CLOCK_SKEW_SECS {
            return Err(ShiftError::ClockSkew);
        }
        self.replay
            .register(init.ephemeral_public, timestamp, now_unix)?;

        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = *PublicKey::from(&ephemeral).as_bytes();
        let dh_ephemeral = checked_dh(&ephemeral, &init.ephemeral_public)?;
        let transcript = transcript_hash(init, &server_public, &ephemeral_public);
        let (keys, confirm_key) = derive_session(
            Role::Server,
            suite,
            &self.psk,
            &dh_static,
            &dh_ephemeral,
            &transcript,
        );
        let confirm_key = Zeroizing::new(confirm_key);
        let reply = ServerReply {
            ephemeral_public,
            confirm: confirm_tag(&confirm_key, &transcript),
        };
        Ok((reply, keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::codec_pair;
    use bytes::BytesMut;

    const NOW: u64 = 1_800_000_000;

    fn setup() -> (ServerHandshake, Psk, [u8; 32]) {
        let psk = Psk::from_passphrase("correct horse battery staple");
        let identity = ServerIdentity::generate();
        let public = identity.public_bytes();
        (ServerHandshake::new(identity, psk.clone()), psk, public)
    }

    #[test]
    fn full_exchange_and_data_both_directions() {
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let (server, psk, public) = setup();
            let (client, init) = ClientHandshake::start(&psk, public, suite, NOW).unwrap();
            let (reply, server_keys) = server
                .accept(&ClientInit::from_bytes(&init.to_bytes()).unwrap(), NOW + 1)
                .unwrap();
            let client_keys = client
                .finish(&ServerReply::from_bytes(&reply.to_bytes()).unwrap())
                .unwrap();
            assert_eq!(client_keys.suite, suite);
            assert_eq!(server_keys.suite, suite);

            let (mut c_enc, mut c_dec) = codec_pair(client_keys);
            let (mut s_enc, mut s_dec) = codec_pair(server_keys);

            let mut wire = BytesMut::new();
            c_enc.encode(b"hello server", 24, &mut wire).unwrap();
            assert_eq!(
                &s_dec.decode(&mut wire).unwrap().unwrap()[..],
                b"hello server"
            );

            s_enc.encode(b"hello client", 0, &mut wire).unwrap();
            assert_eq!(
                &c_dec.decode(&mut wire).unwrap().unwrap()[..],
                b"hello client"
            );
        }
    }

    #[test]
    fn wrong_psk_is_rejected() {
        let (server, _, public) = setup();
        let other = Psk::from_passphrase("something else");
        let (_, init) =
            ClientHandshake::start(&other, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        let err = server.accept(&init, NOW).unwrap_err();
        assert!(matches!(err, ShiftError::AuthenticationFailed));
        assert!(err.should_fallback());
        assert!(server.replay_filter().is_empty());
    }

    #[test]
    fn wrong_server_key_is_rejected() {
        let (server, psk, _) = setup();
        let stranger = ServerIdentity::generate().public_bytes();
        let (_, init) =
            ClientHandshake::start(&psk, stranger, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        assert!(matches!(
            server.accept(&init, NOW),
            Err(ShiftError::AuthenticationFailed)
        ));
    }

    #[test]
    fn replay_is_rejected() {
        let (server, psk, public) = setup();
        let (_, init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        server.accept(&init, NOW).unwrap();
        assert!(matches!(
            server.accept(&init, NOW + 5),
            Err(ShiftError::Replay)
        ));
    }

    #[test]
    fn stale_and_future_timestamps_are_rejected() {
        let (server, psk, public) = setup();
        let (_, old) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW - 500).unwrap();
        assert!(matches!(
            server.accept(&old, NOW),
            Err(ShiftError::ClockSkew)
        ));
        let (_, future) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW + 500).unwrap();
        assert!(matches!(
            server.accept(&future, NOW),
            Err(ShiftError::ClockSkew)
        ));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let (server, psk, public) = setup();
        let (_, mut init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        init.token[5] ^= 1;
        assert!(matches!(
            server.accept(&init, NOW),
            Err(ShiftError::AuthenticationFailed)
        ));
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        let (server, _, _) = setup();
        let init = ClientInit {
            ephemeral_public: [0u8; 32],
            token: [1u8; 32],
        };
        assert!(matches!(
            server.accept(&init, NOW),
            Err(ShiftError::WeakKey)
        ));
    }

    #[test]
    fn forged_server_confirmation_is_rejected() {
        let (server, psk, public) = setup();
        let (client, init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        let (mut reply, _) = server.accept(&init, NOW).unwrap();
        reply.confirm[0] ^= 0xff;
        assert!(matches!(
            client.finish(&reply),
            Err(ShiftError::AuthenticationFailed)
        ));
    }

    #[test]
    fn sessions_do_not_share_keys() {
        let (server, psk, public) = setup();
        let mut ciphertexts = Vec::new();
        for _ in 0..2 {
            let (client, init) =
                ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
            let (reply, _) = server.accept(&init, NOW).unwrap();
            let keys = client.finish(&reply).unwrap();
            let (mut enc, _) = codec_pair(keys);
            let mut wire = BytesMut::new();
            enc.encode(b"same plaintext", 0, &mut wire).unwrap();
            ciphertexts.push(wire.to_vec());
        }
        assert_ne!(ciphertexts[0], ciphertexts[1]);
    }

    #[test]
    fn replay_cache_expires_entries() {
        let filter = ReplayFilter::new();
        filter.register([1u8; 32], NOW, NOW).unwrap();
        assert_eq!(filter.len(), 1);
        filter.register([2u8; 32], NOW + 400, NOW + 400).unwrap();
        assert_eq!(filter.len(), 1);
    }
}
