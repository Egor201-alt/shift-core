use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{
    confirm_tag, derive_resumed_session, derive_resumption_secret, derive_session, open_token,
    resumption_auth_key, seal_token, tags_equal, CipherSuite, Psk, Role, SessionKeys, CONFIRM_LEN,
    TAG_LEN,
};
use crate::resumption::{unix_now as resumption_now, Ticket, TicketStore, TICKET_ID_LEN};
use crate::{Result, ShiftError, MAX_CLOCK_SKEW_SECS, PROTOCOL_VERSION};

pub const CLIENT_INIT_LEN: usize = 64;
pub const SERVER_REPLY_MIN_LEN: usize = 32 + CONFIRM_LEN;
pub const SERVER_REPLY_MAX_LEN: usize = SERVER_REPLY_MIN_LEN + TICKET_ID_LEN;
pub const SERVER_REPLY_LEN: usize = SERVER_REPLY_MIN_LEN;
const TOKEN_PLAIN_LEN: usize = 16;
const REPLAY_CAPACITY: usize = 1 << 20;
const REPLAY_PRUNE_INTERVAL_SECS: u64 = 30;

const CTX_AUTH: &str = "shift/v1 auth";
const CTX_TRANSCRIPT: &str = "shift/v1 transcript";
const CTX_RESUMPTION_BINDING: &str = "shift/v1 resumption binding";

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

/// The server's reply, 48 bytes for a fresh handshake or 64 bytes when a
/// resumption ticket is attached (the last 16 bytes are the ticket id).
/// Both transports (`tunnel.rs`, `masquerade.rs`) already length-prefix
/// this message, so its variable size needs no wire-format change beyond
/// that: a client just checks how many bytes actually arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerReply {
    pub ephemeral_public: [u8; 32],
    pub confirm: [u8; CONFIRM_LEN],
    pub ticket_id: Option<[u8; TICKET_ID_LEN]>,
}

impl ServerReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SERVER_REPLY_MAX_LEN);
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.confirm);
        if let Some(id) = self.ticket_id {
            out.extend_from_slice(&id);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SERVER_REPLY_MIN_LEN && bytes.len() != SERVER_REPLY_MAX_LEN {
            return Err(ShiftError::HandshakeFailed("bad server reply length"));
        }
        let mut ephemeral_public = [0u8; 32];
        let mut confirm = [0u8; CONFIRM_LEN];
        ephemeral_public.copy_from_slice(&bytes[..32]);
        confirm.copy_from_slice(&bytes[32..SERVER_REPLY_MIN_LEN]);
        let ticket_id = if bytes.len() == SERVER_REPLY_MAX_LEN {
            let mut id = [0u8; TICKET_ID_LEN];
            id.copy_from_slice(&bytes[SERVER_REPLY_MIN_LEN..]);
            Some(id)
        } else {
            None
        };
        Ok(ServerReply {
            ephemeral_public,
            confirm,
            ticket_id,
        })
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

fn resumption_binding(
    ticket_id: &[u8; TICKET_ID_LEN],
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_RESUMPTION_BINDING);
    hasher.update(ticket_id);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    *hasher.finalize().as_bytes()
}

fn build_token(key: &[u8; 32], suite: CipherSuite, now_unix: u64) -> Result<[u8; 32]> {
    let mut plain = [0u8; TOKEN_PLAIN_LEN];
    plain[0] = PROTOCOL_VERSION;
    plain[1] = suite.id();
    plain[2..10].copy_from_slice(&now_unix.to_be_bytes());
    OsRng.fill_bytes(&mut plain[10..]);
    let tag = seal_token(key, &mut plain)?;
    let mut token = [0u8; 32];
    token[..TOKEN_PLAIN_LEN].copy_from_slice(&plain);
    token[TOKEN_PLAIN_LEN..].copy_from_slice(&tag);
    Ok(token)
}

/// The version/suite/timestamp fields recovered from an opened token.
struct TokenFields {
    suite: CipherSuite,
    timestamp: u64,
}

fn open_and_check_token(key: &[u8; 32], token: &[u8; 32], now_unix: u64) -> Result<TokenFields> {
    let mut plain = [0u8; TOKEN_PLAIN_LEN];
    let mut tag = [0u8; TAG_LEN];
    plain.copy_from_slice(&token[..TOKEN_PLAIN_LEN]);
    tag.copy_from_slice(&token[TOKEN_PLAIN_LEN..]);
    open_token(key, &mut plain, &tag)?;

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
    Ok(TokenFields { suite, timestamp })
}

/// Output of a successful handshake: the session keys, plus (for a fresh,
/// full handshake only) the secret a caller can hand to `TicketStore` to
/// let this client resume later without a new Diffie-Hellman exchange.
/// Resumed sessions never carry a fresh `resumption_secret`, so a
/// resumption chain cannot extend past the original full handshake.
#[derive(Debug)]
pub struct Handshaked {
    pub keys: SessionKeys,
    pub resumption_secret: Option<[u8; 32]>,
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
        let token = build_token(&key, suite, now_unix)?;

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

    pub fn finish(self, reply: &ServerReply) -> Result<Handshaked> {
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
        let resumption_secret =
            derive_resumption_secret(&self.psk, &self.dh_static, &dh_ephemeral, &transcript);
        Ok(Handshaked {
            keys,
            resumption_secret: Some(resumption_secret),
        })
    }
}

/// Resumes a session from a previously issued [`Ticket`] instead of doing
/// a fresh X25519 exchange. This is cheaper (no asymmetric crypto) but,
/// unlike [`ClientHandshake`], does not provide forward secrecy for the
/// resumed session on its own: its confidentiality is bounded by the
/// ticket secret, which is why tickets are single-use and short-lived.
/// Use a full [`ClientHandshake`] whenever that tradeoff is not wanted.
pub struct ResumingClientHandshake {
    secret: [u8; 32],
    suite: CipherSuite,
    ticket_id: [u8; TICKET_ID_LEN],
    client_nonce: [u8; 16],
}

impl ResumingClientHandshake {
    pub fn start(ticket: &Ticket, now_unix: u64) -> Result<(Self, ClientInit)> {
        let mut client_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut client_nonce);
        let key = resumption_auth_key(&ticket.secret);
        let token = build_token(&key, ticket.suite, now_unix)?;

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public[..TICKET_ID_LEN].copy_from_slice(&ticket.id);
        ephemeral_public[TICKET_ID_LEN..].copy_from_slice(&client_nonce);

        let init = ClientInit {
            ephemeral_public,
            token,
        };
        let handshake = ResumingClientHandshake {
            secret: ticket.secret,
            suite: ticket.suite,
            ticket_id: ticket.id,
            client_nonce,
        };
        Ok((handshake, init))
    }

    pub fn finish(self, reply: &ServerReply) -> Result<SessionKeys> {
        let mut server_nonce = [0u8; 16];
        server_nonce.copy_from_slice(&reply.ephemeral_public[..16]);
        let (keys, confirm_key) = derive_resumed_session(
            Role::Client,
            self.suite,
            &self.secret,
            &self.client_nonce,
            &server_nonce,
        );
        let confirm_key = Zeroizing::new(confirm_key);
        let binding = resumption_binding(&self.ticket_id, &self.client_nonce, &server_nonce);
        let expected = confirm_tag(&confirm_key, &binding);
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
    tickets: TicketStore,
    ticket_ttl_secs: Option<u64>,
}

impl ServerHandshake {
    pub fn new(identity: ServerIdentity, psk: Psk) -> Self {
        ServerHandshake {
            identity,
            psk,
            replay: ReplayFilter::new(),
            tickets: TicketStore::new(),
            ticket_ttl_secs: None,
        }
    }

    /// Like [`Self::new`], but issues a single-use resumption ticket after
    /// every fresh handshake, valid for `ticket_ttl_secs`. See
    /// [`ResumingClientHandshake`] for the security tradeoff this implies.
    pub fn with_resumption(identity: ServerIdentity, psk: Psk, ticket_ttl_secs: u64) -> Self {
        ServerHandshake {
            identity,
            psk,
            replay: ReplayFilter::new(),
            tickets: TicketStore::new(),
            ticket_ttl_secs: Some(ticket_ttl_secs),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_bytes()
    }

    pub fn replay_filter(&self) -> &ReplayFilter {
        &self.replay
    }

    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }

    pub fn accept(&self, init: &ClientInit, now_unix: u64) -> Result<(ServerReply, Handshaked)> {
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&init.ephemeral_public[..TICKET_ID_LEN]);
        if let Some((secret, suite)) = self.tickets.redeem(&ticket_id) {
            return self.accept_resumed(init, &ticket_id, secret, suite, now_unix);
        }
        self.accept_fresh(init, now_unix)
    }

    fn accept_fresh(&self, init: &ClientInit, now_unix: u64) -> Result<(ServerReply, Handshaked)> {
        let server_public = self.identity.public_bytes();
        let dh_static = checked_dh(&self.identity.secret, &init.ephemeral_public)?;
        let key = auth_key(
            &self.psk,
            &dh_static,
            &init.ephemeral_public,
            &server_public,
        );
        let fields = open_and_check_token(&key, &init.token, now_unix)?;
        self.replay
            .register(init.ephemeral_public, fields.timestamp, now_unix)?;

        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = *PublicKey::from(&ephemeral).as_bytes();
        let dh_ephemeral = checked_dh(&ephemeral, &init.ephemeral_public)?;
        let transcript = transcript_hash(init, &server_public, &ephemeral_public);
        let (keys, confirm_key) = derive_session(
            Role::Server,
            fields.suite,
            &self.psk,
            &dh_static,
            &dh_ephemeral,
            &transcript,
        );
        let confirm_key = Zeroizing::new(confirm_key);
        let resumption_secret =
            derive_resumption_secret(&self.psk, &dh_static, &dh_ephemeral, &transcript);

        let ticket_id = self
            .ticket_ttl_secs
            .map(|ttl| self.tickets.issue(resumption_secret, fields.suite, ttl).id);

        let reply = ServerReply {
            ephemeral_public,
            confirm: confirm_tag(&confirm_key, &transcript),
            ticket_id,
        };
        Ok((
            reply,
            Handshaked {
                keys,
                resumption_secret: Some(resumption_secret),
            },
        ))
    }

    fn accept_resumed(
        &self,
        init: &ClientInit,
        ticket_id: &[u8; TICKET_ID_LEN],
        secret: [u8; 32],
        suite: CipherSuite,
        now_unix: u64,
    ) -> Result<(ServerReply, Handshaked)> {
        let key = resumption_auth_key(&secret);
        let fields = open_and_check_token(&key, &init.token, now_unix)?;
        if fields.suite != suite {
            return Err(ShiftError::HandshakeFailed(
                "resumption token cipher suite does not match the ticket",
            ));
        }
        let mut client_nonce = [0u8; 16];
        client_nonce.copy_from_slice(&init.ephemeral_public[TICKET_ID_LEN..]);
        let mut server_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut server_nonce);

        let (keys, confirm_key) =
            derive_resumed_session(Role::Server, suite, &secret, &client_nonce, &server_nonce);
        let confirm_key = Zeroizing::new(confirm_key);
        let binding = resumption_binding(ticket_id, &client_nonce, &server_nonce);

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public[..16].copy_from_slice(&server_nonce);
        let reply = ServerReply {
            ephemeral_public,
            confirm: confirm_tag(&confirm_key, &binding),
            ticket_id: None,
        };
        Ok((
            reply,
            Handshaked {
                keys,
                resumption_secret: None,
            },
        ))
    }
}

pub fn now_unix() -> u64 {
    resumption_now()
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

    fn setup_with_resumption(ttl: u64) -> (ServerHandshake, Psk, [u8; 32]) {
        let psk = Psk::from_passphrase("correct horse battery staple");
        let identity = ServerIdentity::generate();
        let public = identity.public_bytes();
        (
            ServerHandshake::with_resumption(identity, psk.clone(), ttl),
            psk,
            public,
        )
    }

    #[test]
    fn full_exchange_and_data_both_directions() {
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let (server, psk, public) = setup();
            let (client, init) = ClientHandshake::start(&psk, public, suite, NOW).unwrap();
            let (reply, server_handshaked) = server
                .accept(&ClientInit::from_bytes(&init.to_bytes()).unwrap(), NOW + 1)
                .unwrap();
            let client_handshaked = client
                .finish(&ServerReply::from_bytes(&reply.to_bytes()).unwrap())
                .unwrap();
            assert_eq!(client_handshaked.keys.suite, suite);
            assert_eq!(server_handshaked.keys.suite, suite);
            assert!(reply.ticket_id.is_none());

            let (mut c_enc, mut c_dec) = codec_pair(client_handshaked.keys);
            let (mut s_enc, mut s_dec) = codec_pair(server_handshaked.keys);

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
            let handshaked = client.finish(&reply).unwrap();
            let (mut enc, _) = codec_pair(handshaked.keys);
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

    fn full_handshake_pair(
        server: &ServerHandshake,
        psk: &Psk,
        public: [u8; 32],
        now: u64,
    ) -> (ServerReply, SessionKeys, SessionKeys) {
        let (client, init) =
            ClientHandshake::start(psk, public, CipherSuite::ChaCha20Poly1305, now).unwrap();
        let (reply, server_handshaked) = server.accept(&init, now).unwrap();
        let client_handshaked = client.finish(&reply).unwrap();
        (reply, client_handshaked.keys, server_handshaked.keys)
    }

    #[test]
    fn full_handshake_issues_a_ticket_when_enabled() {
        let (server, psk, public) = setup_with_resumption(3600);
        let (reply, _, _) = full_handshake_pair(&server, &psk, public, NOW);
        assert!(reply.ticket_id.is_some());
        assert_eq!(server.ticket_count(), 1);
    }

    #[test]
    fn resumed_handshake_round_trips_data() {
        let (server, psk, public) = setup_with_resumption(3600);
        let (client, init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        let (reply, _) = server.accept(&init, NOW).unwrap();
        let ticket_id = reply.ticket_id.unwrap();
        let handshaked = client.finish(&reply).unwrap();
        let resumption_secret = handshaked.resumption_secret.unwrap();

        let ticket = Ticket {
            id: ticket_id,
            secret: resumption_secret,
            suite: CipherSuite::ChaCha20Poly1305,
            not_after: NOW + 3600,
        };

        let (resuming_client, resume_init) =
            ResumingClientHandshake::start(&ticket, NOW + 10).unwrap();
        let (resume_reply, server_handshaked) = server.accept(&resume_init, NOW + 10).unwrap();
        assert!(resume_reply.ticket_id.is_none());
        assert!(server_handshaked.resumption_secret.is_none());
        let client_keys = resuming_client.finish(&resume_reply).unwrap();

        let (mut c_enc, mut c_dec) = codec_pair(client_keys);
        let (mut s_enc, mut s_dec) = codec_pair(server_handshaked.keys);
        let mut wire = BytesMut::new();
        c_enc.encode(b"resumed hello", 8, &mut wire).unwrap();
        assert_eq!(
            &s_dec.decode(&mut wire).unwrap().unwrap()[..],
            b"resumed hello"
        );
        s_enc.encode(b"resumed reply", 0, &mut wire).unwrap();
        assert_eq!(
            &c_dec.decode(&mut wire).unwrap().unwrap()[..],
            b"resumed reply"
        );
    }

    #[test]
    fn ticket_is_single_use() {
        let (server, psk, public) = setup_with_resumption(3600);
        let (client, init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        let (reply, _) = server.accept(&init, NOW).unwrap();
        let ticket_id = reply.ticket_id.unwrap();
        let handshaked = client.finish(&reply).unwrap();
        let resumption_secret = handshaked.resumption_secret.unwrap();

        let ticket = Ticket {
            id: ticket_id,
            secret: resumption_secret,
            suite: CipherSuite::ChaCha20Poly1305,
            not_after: NOW + 3600,
        };
        let (_, resume_init) = ResumingClientHandshake::start(&ticket, NOW + 1).unwrap();
        assert!(server.accept(&resume_init, NOW + 1).is_ok());
        assert!(matches!(
            server.accept(&resume_init, NOW + 2),
            Err(ShiftError::HandshakeFailed(_)) | Err(ShiftError::AuthenticationFailed)
        ));
    }

    #[test]
    fn resumption_disabled_by_default() {
        let (server, psk, public) = setup();
        let (reply, _, _) = full_handshake_pair(&server, &psk, public, NOW);
        assert!(reply.ticket_id.is_none());
        assert_eq!(server.ticket_count(), 0);
    }

    #[test]
    fn tampered_resumption_confirm_is_rejected() {
        let (server, psk, public) = setup_with_resumption(3600);
        let (client, init) =
            ClientHandshake::start(&psk, public, CipherSuite::ChaCha20Poly1305, NOW).unwrap();
        let (reply, _) = server.accept(&init, NOW).unwrap();
        let ticket_id = reply.ticket_id.unwrap();
        let handshaked = client.finish(&reply).unwrap();
        let ticket = Ticket {
            id: ticket_id,
            secret: handshaked.resumption_secret.unwrap(),
            suite: CipherSuite::ChaCha20Poly1305,
            not_after: NOW + 3600,
        };
        let (resuming_client, resume_init) =
            ResumingClientHandshake::start(&ticket, NOW + 5).unwrap();
        let (mut resume_reply, _) = server.accept(&resume_init, NOW + 5).unwrap();
        resume_reply.confirm[0] ^= 0xff;
        assert!(matches!(
            resuming_client.finish(&resume_reply),
            Err(ShiftError::AuthenticationFailed)
        ));
    }
}
