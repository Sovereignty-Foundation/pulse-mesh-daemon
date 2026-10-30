// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The forward cache (ADR-0021, item 5).

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::num::NonZeroUsize;

use pulse_canon::PulseEnvelopeId;

use crate::{Forwarded, QualifiedOrigin};

/// The keys a [`ForwardCache`] holds by default: 65,536, about 3 MB.
pub const DEFAULT_FORWARD_CACHE: usize = 65_536;

/// The domain tag the BLAKE3 hash of a [`ForwardKey`] starts with.
const FORWARD_KEY_DOMAIN: &[u8] = b"pulse-mesh-link/forward-key/v1";

/// Which send a forwarded envelope is: its content id, the qualified origin
/// that sent it, and the `monotonic_nanos` its hub stamped on it when it
/// was sent, hashed together.
///
/// A copy of one send, arriving by a second path, has all three the same;
/// a second send of the same content by the same client has a later stamp,
/// so it is another key and is delivered too. The key is the first 16
/// bytes of the BLAKE3 hash of a domain tag, the id's 16 bytes, the
/// daemon id's 8 bytes, the name's length as a little-endian `u64` and its
/// bytes, and the stamp as a little-endian `u64`, so two sends share a key
/// only by a collision of that hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForwardKey([u8; 16]);

impl ForwardKey {
    /// The key of the envelope `id` that `origin` sent at
    /// `monotonic_nanos`.
    #[must_use]
    pub fn new(id: &PulseEnvelopeId, origin: &QualifiedOrigin, monotonic_nanos: u64) -> Self {
        let name = origin.name().as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORWARD_KEY_DOMAIN);
        hasher.update(&id.0);
        hasher.update(origin.daemon().as_bytes());
        hasher.update(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(name);
        hasher.update(&monotonic_nanos.to_le_bytes());
        let mut key = [0; 16];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self(key)
    }

    /// The key of a forwarded envelope: its id, its origin and its stamp.
    #[must_use]
    pub fn of(forwarded: &Forwarded) -> Self {
        Self::new(
            &forwarded.envelope.id(),
            &forwarded.origin,
            forwarded.envelope.monotonic_nanos,
        )
    }

    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ForwardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ForwardKey(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// The keys of the sends a daemon received from its peers lately
/// ([`ForwardKey`]), so that one arriving twice, by two paths or as a copy,
/// is delivered once, and two sends of the same content are each
/// delivered.
///
/// It holds the last `capacity` distinct keys inserted and forgets the
/// oldest first, a ring; seeing a key again does not make it newer. Inside
/// that bound it is exact: [`ForwardCache::seen_or_insert`] says a key was
/// seen exactly when it is among them.
#[derive(Debug, Clone)]
pub struct ForwardCache {
    capacity: NonZeroUsize,
    held: HashSet<ForwardKey>,
    order: VecDeque<ForwardKey>,
}

impl Default for ForwardCache {
    /// A cache of [`DEFAULT_FORWARD_CACHE`] keys.
    fn default() -> Self {
        Self::new(NonZeroUsize::new(DEFAULT_FORWARD_CACHE).unwrap_or(NonZeroUsize::MIN))
    }
}

impl ForwardCache {
    /// An empty cache that holds up to `capacity` keys.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            held: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Whether `key` was seen: true when it is held, which leaves the
    /// cache as it was; false when it is not, and then it is held from now
    /// on, the oldest key forgotten if the cache is full.
    pub fn seen_or_insert(&mut self, key: ForwardKey) -> bool {
        if self.held.contains(&key) {
            return true;
        }
        if self.order.len() == self.capacity.get() {
            if let Some(oldest) = self.order.pop_front() {
                self.held.remove(&oldest);
            }
        }
        self.held.insert(key);
        self.order.push_back(key);
        false
    }

    /// Whether `key` is held.
    #[must_use]
    pub fn contains(&self, key: &ForwardKey) -> bool {
        self.held.contains(key)
    }

    /// The most keys held.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity.get()
    }

    /// The keys held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no key is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::DaemonId;
    use proptest::prelude::*;
    use pulse_canon::PulseEnvelope;

    fn origin(daemon: u8, name: &str) -> QualifiedOrigin {
        QualifiedOrigin::new(DaemonId::from_bytes([daemon; 8]), name).unwrap()
    }

    fn key(n: u8) -> ForwardKey {
        ForwardKey::new(&PulseEnvelopeId([n; 16]), &origin(1, "w"), 0)
    }

    /// `payload` as `origin` sends it at `stamp`.
    fn sent(origin: &QualifiedOrigin, payload: &[u8], stamp: u64) -> Forwarded {
        let mut envelope = PulseEnvelope::with_content(0, Some("jobs".into()), payload.to_vec());
        envelope.monotonic_nanos = stamp;
        Forwarded::new(origin.clone(), "jobs", envelope)
    }

    #[test]
    fn a_key_is_one_send_of_one_origin() {
        let w = origin(1, "w");
        let first = sent(&w, b"same", 10);
        assert_eq!(
            ForwardKey::of(&first),
            ForwardKey::of(&first.clone()),
            "a copy"
        );
        let again = sent(&w, b"same", 11);
        assert_eq!(first.envelope.id(), again.envelope.id(), "the same content");
        assert_ne!(
            ForwardKey::of(&first),
            ForwardKey::of(&again),
            "a second send"
        );
        assert_ne!(
            ForwardKey::of(&first),
            ForwardKey::of(&sent(&origin(2, "w"), b"same", 10)),
            "another host's client of the same name"
        );
        assert_ne!(
            ForwardKey::of(&first),
            ForwardKey::of(&sent(&origin(1, "x"), b"same", 10)),
            "another client"
        );
        assert_ne!(
            ForwardKey::of(&first),
            ForwardKey::of(&sent(&w, b"other", 10)),
            "other content"
        );
        let text = format!("{:?}", ForwardKey::of(&first));
        assert!(text.starts_with("ForwardKey(") && text.len() == "ForwardKey()".len() + 32);
    }

    #[test]
    fn the_same_content_sent_twice_is_seen_once_each_and_a_copy_is_seen() {
        let mut cache = ForwardCache::default();
        let w = origin(1, "w");
        let first = sent(&w, b"same", 10);
        let second = sent(&w, b"same", 11);
        assert!(!cache.seen_or_insert(ForwardKey::of(&first)));
        assert!(!cache.seen_or_insert(ForwardKey::of(&second)));
        assert!(cache.seen_or_insert(ForwardKey::of(&first.clone())));
        assert!(cache.seen_or_insert(ForwardKey::of(&second)));
    }

    #[test]
    fn a_key_is_seen_until_capacity_newer_keys_push_it_out() {
        let mut cache = ForwardCache::new(NonZeroUsize::new(2).unwrap());
        assert!(!cache.seen_or_insert(key(1)));
        assert!(cache.seen_or_insert(key(1)));
        assert!(!cache.seen_or_insert(key(2)));
        assert!(
            cache.seen_or_insert(key(1)),
            "seeing it again keeps its place"
        );
        assert!(!cache.seen_or_insert(key(3)));
        assert!(!cache.contains(&key(1)), "the oldest went first");
        assert!(cache.contains(&key(2)) && cache.contains(&key(3)));
        assert_eq!((cache.len(), cache.capacity()), (2, 2));
        assert_eq!(ForwardCache::default().capacity(), DEFAULT_FORWARD_CACHE);
        assert!(ForwardCache::default().is_empty());
    }

    proptest! {
        /// Against a model that keeps the last `capacity` distinct keys.
        #[test]
        fn the_cache_is_exact_inside_its_bound(
            capacity in 1usize..8,
            keys in proptest::collection::vec(0u8..12, 0..200),
        ) {
            let mut cache = ForwardCache::new(NonZeroUsize::new(capacity).unwrap());
            let mut model: VecDeque<u8> = VecDeque::new();
            for n in keys {
                let seen = model.contains(&n);
                prop_assert_eq!(cache.seen_or_insert(key(n)), seen);
                if !seen {
                    if model.len() == capacity {
                        model.pop_front();
                    }
                    model.push_back(n);
                }
                prop_assert_eq!(cache.len(), model.len());
            }
        }
    }
}
