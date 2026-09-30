use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{CipherSuite, KEY_LEN};

pub const TICKET_ID_LEN: usize = 16;
const DEFAULT_MAX_TICKETS: usize = 1 << 16;
const PRUNE_INTERVAL_SECS: u64 = 30;

/// A single-use resumption ticket issued by the server at the end of a
/// fresh handshake. Holding this ticket allows a client to reconnect via
/// [`crate::handshake::ResumingClientHandshake`] without performing a new
/// X25519 Diffie-Hellman exchange.
///
/// Confidentiality is bounded by `secret`: tickets are single-use and
/// short-lived to prevent replay and forward-secrecy degradation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ticket {
    pub id: [u8; TICKET_ID_LEN],
    pub secret: [u8; KEY_LEN],
    #[zeroize(skip)]
    pub suite: CipherSuite,
    #[zeroize(skip)]
    pub not_after: u64,
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("id", &self.id)
            .field("suite", &self.suite)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

struct TicketEntry {
    secret: [u8; KEY_LEN],
    suite: CipherSuite,
    not_after: u64,
}

struct StoreInner {
    tickets: HashMap<[u8; TICKET_ID_LEN], TicketEntry>,
    last_prune: u64,
}

/// Thread-safe in-memory store for issued resumption tickets.
///
/// Enforces single-use redemption: calling [`TicketStore::redeem`] removes
/// the ticket immediately, preventing replay attacks. Expired entries are
/// lazily pruned on mutation.
pub struct TicketStore {
    inner: Mutex<StoreInner>,
    capacity: usize,
}

impl TicketStore {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_TICKETS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        TicketStore {
            inner: Mutex::new(StoreInner {
                tickets: HashMap::new(),
                last_prune: unix_now(),
            }),
            capacity,
        }
    }

    /// Issues and stores a new single-use ticket for `resumption_secret`,
    /// valid for `ttl_secs` seconds from now.
    pub fn issue(&self, secret: [u8; KEY_LEN], suite: CipherSuite, ttl_secs: u64) -> Ticket {
        let now = unix_now();
        let mut id = [0u8; TICKET_ID_LEN];
        OsRng.fill_bytes(&mut id);

        let not_after = now.saturating_add(ttl_secs);
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if now.saturating_sub(guard.last_prune) >= PRUNE_INTERVAL_SECS {
            guard.tickets.retain(|_, entry| entry.not_after > now);
            guard.last_prune = now;
        }

        if guard.tickets.len() >= self.capacity {
            if let Some(evict) = guard.tickets.keys().next().copied() {
                guard.tickets.remove(&evict);
            }
        }

        guard.tickets.insert(
            id,
            TicketEntry {
                secret,
                suite,
                not_after,
            },
        );

        Ticket {
            id,
            secret,
            suite,
            not_after,
        }
    }

    /// Redeems a ticket by its identifier. The ticket is immediately
    /// removed from the store, guaranteeing single-use semantics. Returns
    /// `None` if the ticket is unknown or expired.
    pub fn redeem(&self, id: &[u8; TICKET_ID_LEN]) -> Option<([u8; KEY_LEN], CipherSuite)> {
        let now = unix_now();
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let entry = guard.tickets.remove(id)?;
        if entry.not_after <= now {
            return None;
        }
        Some((entry.secret, entry.suite))
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tickets
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn issue_and_redeem_roundtrip() {
        let store = TicketStore::new();
        let secret = [42u8; KEY_LEN];
        let ticket = store.issue(secret, CipherSuite::ChaCha20Poly1305, 3600);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        let redeemed = store.redeem(&ticket.id).unwrap();
        assert_eq!(redeemed.0, secret);
        assert_eq!(redeemed.1, CipherSuite::ChaCha20Poly1305);

        // Tickets are strictly single-use
        assert!(store.redeem(&ticket.id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn expired_ticket_is_not_redeemed() {
        let store = TicketStore::new();
        let secret = [7u8; KEY_LEN];
        // 0 TTL means it expires immediately
        let ticket = store.issue(secret, CipherSuite::Aes256Gcm, 0);
        assert!(store.redeem(&ticket.id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn capacity_eviction_prevents_unbounded_growth() {
        let store = TicketStore::with_capacity(2);
        let t1 = store.issue([1u8; KEY_LEN], CipherSuite::ChaCha20Poly1305, 3600);
        let t2 = store.issue([2u8; KEY_LEN], CipherSuite::ChaCha20Poly1305, 3600);
        assert_eq!(store.len(), 2);

        // Third ticket forces eviction of one entry
        let _t3 = store.issue([3u8; KEY_LEN], CipherSuite::ChaCha20Poly1305, 3600);
        assert_eq!(store.len(), 2);

        let valid_count = [t1.id, t2.id]
            .iter()
            .filter(|id| store.redeem(id).is_some())
            .count();
        assert_eq!(valid_count, 1);
    }

    #[test]
    fn manual_ticket_construction() {
        let ticket = Ticket {
            id: [1u8; TICKET_ID_LEN],
            secret: [2u8; KEY_LEN],
            suite: CipherSuite::Aes256Gcm,
            not_after: NOW + 300,
        };
        assert_eq!(ticket.id, [1u8; TICKET_ID_LEN]);
        assert_eq!(ticket.suite, CipherSuite::Aes256Gcm);
    }
}
