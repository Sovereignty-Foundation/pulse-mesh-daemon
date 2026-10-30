// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Symbol-keyed, last-write-wins conflation: the updates a key receives
//! between two drains are delivered once, as the latest, so a consumer's work
//! per drain is bounded by its keys rather than by the message rate.
//!
//! - [`ConflationRing`] conflates in place, in a shared-memory
//!   [`core_ring::PulseRing`].
//! - [`ConflationDrainer`] conflates the messages of any [`Source`].
//! - A [`KeyExtractor`] finds each message's key: [`BytesExtractor`] reads a
//!   byte range, [`Crc32Extractor`] hashes the payload.

use std::collections::HashMap;
use std::hash::Hash;
use thiserror::Error;

/// Per-message timing token; every field is 0 when not measured, as in
/// `Token::default()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Token {
    /// Sender's `quanta` timestamp in nanoseconds.
    pub send_ns: u64,
    /// Receiver's `quanta` timestamp in nanoseconds.
    pub recv_ns: u64,
    /// Monotonic per-publisher sequence number.
    pub seq: u64,
    /// Wire-payload length in bytes.
    pub payload_size: u32,
}

/// A message source for a [`ConflationDrainer`]: anything that yields
/// `(payload, token)` pairs.
pub trait Source: Send {
    /// Receive one message.
    ///
    /// # Errors
    ///
    /// An `Err` means the source is closed or permanently degraded, and it is
    /// not retried; a source with no data now returns `Ok(0)` from
    /// [`Self::drain`] instead. Wrap the transport's own error with
    /// [`ConflationError::source`].
    fn recv(&mut self) -> Result<(Vec<u8>, Token), ConflationError>;

    /// Pass up to `max` messages to `f` and return how many; `Ok(0)` means no
    /// data now. The default passes one message from [`Self::recv`] (none
    /// when `max` is 0); a source that can take a batch overrides it.
    ///
    /// # Errors
    ///
    /// As [`Self::recv`]: an `Err` means the source has failed for good.
    fn drain(
        &mut self,
        max: usize,
        f: &mut dyn FnMut(&[u8], &Token),
    ) -> Result<usize, ConflationError> {
        if max == 0 {
            return Ok(0);
        }
        match self.recv() {
            Ok((p, t)) => {
                f(&p, &t);
                Ok(1)
            }
            Err(e) => Err(e),
        }
    }
}

/// The longest payload a [`ConflationRing`] takes: a 128-byte pulse slot less
/// the 8-byte SeqLock word the ring reserves.
pub const MAX_LOGICAL_PAYLOAD: usize = 128 - 8;

/// Errors returned by [`ConflationRing`] / [`ConflationDrainer`] / [`KeyExtractor`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ConflationError {
    /// More keys than ring slots. Nothing in this module raises it; a
    /// [`KeyExtractor`] that enforces the bound may.
    #[error("ring at capacity (symbol-cardinality {cardinality} ≥ ring_slots {slots})")]
    Saturated {
        /// Number of distinct keys observed.
        cardinality: usize,
        /// Configured ring slot capacity.
        slots: usize,
    },
    /// Payload is shorter than the configured key-extraction range.
    #[error("payload too short for key extraction (need {needed} bytes, got {got})")]
    PayloadTooShort {
        /// Bytes the extractor needed for the key.
        needed: usize,
        /// Bytes the payload actually contained.
        got: usize,
    },
    /// The payload is longer than [`MAX_LOGICAL_PAYLOAD`].
    #[error("payload exceeds MAX_LOGICAL_PAYLOAD ({MAX_LOGICAL_PAYLOAD} bytes); got {got}")]
    PayloadTooLarge {
        /// Caller-supplied payload length in bytes.
        got: usize,
    },
    /// The [`Source`] behind a drainer has failed for good; its own error is
    /// carried as the cause.
    #[error("the source failed: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ConflationError {
    /// [`ConflationError::Source`] over the error a source raised.
    pub fn source(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Source(Box::new(error))
    }
}

/// Finds a payload's conflation key. It runs on every message, so it must be
/// cheap, and it must be deterministic.
pub trait KeyExtractor<K: Hash + Eq + Copy>: Send + Sync {
    /// Extract the key from `payload`.
    ///
    /// # Errors
    ///
    /// A [`ConflationError`] when the payload has no key; [`BytesExtractor`]
    /// returns [`ConflationError::PayloadTooShort`].
    fn extract(&self, payload: &[u8]) -> Result<K, ConflationError>;
}

/// Keys on payload bytes `START..END` read as a little-endian `u64` (only the
/// first 8 bytes of a longer range count), for protocols with a fixed
/// symbol-id field such as FIX or ITCH.
pub struct BytesExtractor<const START: usize, const END: usize>;

impl<const START: usize, const END: usize> KeyExtractor<u64> for BytesExtractor<START, END> {
    #[inline(always)]
    fn extract(&self, payload: &[u8]) -> Result<u64, ConflationError> {
        if payload.len() < END {
            return Err(ConflationError::PayloadTooShort {
                needed: END,
                got: payload.len(),
            });
        }
        let mut buf = [0u8; 8];
        let span = END - START;
        let copy_len = span.min(8);
        buf[..copy_len].copy_from_slice(&payload[START..START + copy_len]);
        Ok(u64::from_le_bytes(buf))
    }
}

/// Keys on the CRC32C of the whole payload, for payloads with no fixed
/// symbol-id field; costlier than [`BytesExtractor`].
pub struct Crc32Extractor;

impl KeyExtractor<u32> for Crc32Extractor {
    #[inline(always)]
    fn extract(&self, payload: &[u8]) -> Result<u32, ConflationError> {
        Ok(crc32c::crc32c(payload))
    }
}

/// Conflation in place, in a shared-memory [`core_ring::PulseRing`]: a key's
/// next publish overwrites its slot, and a drain delivers each key once.
///
/// Keep the keys tracked between drains within the ring's slots: beyond that,
/// a new key's slot overwrites the oldest slot, which another tracked key may
/// still name.
pub struct ConflationRing<K, E>
where
    K: Hash + Eq + Copy + Send + Sync + 'static,
    E: KeyExtractor<K>,
{
    inner: core_ring::PulseRing,
    index: HashMap<K, u64>,
    extractor: E,
    epoch: u64,
}

impl<K, E> ConflationRing<K, E>
where
    K: Hash + Eq + Copy + Send + Sync + 'static,
    E: KeyExtractor<K>,
{
    /// Conflate in `inner`, keyed by `extractor`. The conflation ring is
    /// `inner`'s one writer: every publish and drain takes `&mut self`.
    pub fn new(inner: core_ring::PulseRing, extractor: E) -> Self {
        Self {
            inner,
            index: HashMap::new(),
            extractor,
            epoch: 0,
        }
    }

    /// Publish `payload` into the slot its key holds, or into a new slot for a
    /// new key, and return the slot index. The payload fills the slot's bytes
    /// 8..128, after the SeqLock word, zero-padded.
    ///
    /// # Errors
    ///
    /// [`ConflationError::PayloadTooLarge`] when `payload` is longer than
    /// [`MAX_LOGICAL_PAYLOAD`], or the [`KeyExtractor`]'s error.
    pub fn publish(&mut self, payload: &[u8]) -> Result<u64, ConflationError> {
        if payload.len() > MAX_LOGICAL_PAYLOAD {
            return Err(ConflationError::PayloadTooLarge { got: payload.len() });
        }
        let key = self.extractor.extract(payload)?;

        let mut wire = [0u8; 128];
        wire[8..8 + payload.len()].copy_from_slice(payload);
        let pulse = pulse_canon::Pulse::from_array(&wire);

        match self.index.get(&key) {
            Some(&slot) => {
                self.inner.publish_at_slot(slot, &pulse);
                Ok(slot)
            }
            None => {
                // Not `publish`, which returns the write number: `read_slot`
                // takes the slot index.
                let slot = self.inner.publish_returning_slot(&pulse);
                self.index.insert(key, slot);
                Ok(slot)
            }
        }
    }

    /// Deliver up to `max` tracked keys to `callback`, each once with its
    /// latest payload zero-padded to [`MAX_LOGICAL_PAYLOAD`] bytes, stop
    /// tracking them, start a new epoch, and return how many were delivered.
    /// A key whose slot does not read back stably is dropped undelivered.
    /// Checked by `tests/conflation_with_pulse_wire.rs`.
    pub fn drain_latest(&mut self, max: usize, mut callback: impl FnMut(&K, &[u8])) -> usize {
        let mut delivered = 0usize;
        let mut to_remove: Vec<K> = Vec::with_capacity(max.min(self.index.len()));

        for (&key, &slot) in &self.index {
            if delivered >= max {
                break;
            }
            if let Some(pulse) = self.inner.read_slot(slot) {
                let bytes = pulse.as_bytes();
                callback(&key, &bytes[8..]);
                delivered += 1;
            }
            to_remove.push(key);
        }

        for k in to_remove {
            self.index.remove(&k);
        }

        self.epoch += 1;
        delivered
    }

    /// How many times [`Self::drain_latest`] has run.
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of keys published and not yet drained.
    pub fn tracked_keys(&self) -> usize {
        self.index.len()
    }
}

/// Conflation in process memory over any [`Source`]: each drain delivers
/// every key it took once, with its latest payload.
pub struct ConflationDrainer<K, E>
where
    K: std::hash::Hash + Eq + Copy + Send + Sync + 'static,
    E: KeyExtractor<K>,
{
    inner: Box<dyn Source>,
    extractor: E,
    latest: std::collections::HashMap<K, Vec<u8>>,
    epoch: u64,
}

impl<K, E> ConflationDrainer<K, E>
where
    K: std::hash::Hash + Eq + Copy + Send + Sync + 'static,
    E: KeyExtractor<K>,
{
    /// Conflate the messages of `inner`, keyed by `extractor`.
    pub fn new(inner: Box<dyn Source>, extractor: E) -> Self {
        Self {
            inner,
            extractor,
            latest: std::collections::HashMap::with_capacity(1024),
            epoch: 0,
        }
    }

    /// Take up to `max_inbound` messages from the source and deliver each of
    /// their keys once, with its latest payload; returns the number of keys
    /// delivered. A message whose key cannot be extracted is skipped, logged
    /// at `trace`, so that one malformed message does not fail the drain.
    ///
    /// # Errors
    ///
    /// The source's error, after the keys taken before it are delivered.
    pub fn drain_latest(
        &mut self,
        max_inbound: usize,
        mut callback: impl FnMut(&K, &[u8]),
    ) -> Result<usize, ConflationError> {
        let extractor = &self.extractor;
        let latest = &mut self.latest;
        let mut last_err: Option<ConflationError> = None;
        self.inner
            .drain(max_inbound, &mut |payload, _tok| {
                if let Ok(key) = extractor.extract(payload) {
                    latest.insert(key, payload.to_vec());
                } else {
                    tracing::trace!("ConflationDrainer: extractor failed on payload");
                }
            })
            .unwrap_or_else(|e| {
                last_err = Some(e);
                0
            });
        let delivered = self.latest.len();
        for (k, p) in self.latest.drain() {
            callback(&k, &p);
        }
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(e) = last_err {
            return Err(e);
        }
        Ok(delivered)
    }

    /// How many times [`Self::drain_latest`] has run.
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bytes_extractor_extracts_le_u32() {
        let ext = BytesExtractor::<0, 4>;
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let key = ext.extract(&payload).unwrap();
        assert_eq!(key, 0x04030201);
    }

    #[test]
    fn bytes_extractor_short_payload_errors() {
        let ext = BytesExtractor::<0, 4>;
        let payload = [0x01, 0x02];
        assert!(matches!(
            ext.extract(&payload),
            Err(ConflationError::PayloadTooShort { needed: 4, got: 2 })
        ));
    }

    #[test]
    fn crc32_extractor_is_deterministic() {
        let ext = Crc32Extractor;
        let p1 = b"AAPL:152.30";
        let p2 = b"AAPL:152.31";
        let k1 = ext.extract(p1).unwrap();
        let k1_again = ext.extract(p1).unwrap();
        let k2 = ext.extract(p2).unwrap();
        assert_eq!(k1, k1_again);
        assert_ne!(k1, k2);
    }

    /// A source that hands out a queue in batches.
    struct MockRecv {
        queue: std::collections::VecDeque<Vec<u8>>,
    }
    impl Source for MockRecv {
        fn recv(&mut self) -> Result<(Vec<u8>, Token), ConflationError> {
            match self.queue.pop_front() {
                Some(p) => Ok((
                    p,
                    Token {
                        send_ns: 0,
                        recv_ns: 0,
                        seq: 0,
                        payload_size: 0,
                    },
                )),
                None => Err(ConflationError::Source("queue empty".into())),
            }
        }
        fn drain(
            &mut self,
            max: usize,
            f: &mut dyn FnMut(&[u8], &Token),
        ) -> Result<usize, ConflationError> {
            let mut n = 0;
            while n < max {
                if let Some(p) = self.queue.pop_front() {
                    let tok = Token {
                        send_ns: 0,
                        recv_ns: 0,
                        seq: 0,
                        payload_size: 0,
                    };
                    f(&p, &tok);
                    n += 1;
                } else {
                    break;
                }
            }
            Ok(n)
        }
    }

    #[test]
    fn conflation_drainer_works_with_arbitrary_driverrecv() {
        let mut queue = std::collections::VecDeque::new();
        for i in 0..100u32 {
            let key = i % 5;
            let mut p = vec![0u8; 16];
            p[0..4].copy_from_slice(&key.to_le_bytes());
            p[4..8].copy_from_slice(&i.to_le_bytes());
            queue.push_back(p);
        }
        let mock = Box::new(MockRecv { queue });
        let mut drainer = ConflationDrainer::new(mock, BytesExtractor::<0, 4>);

        let mut got_keys: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut got_max_seq: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        let n = drainer
            .drain_latest(200, |key, payload| {
                got_keys.insert(*key);
                let mut sb = [0u8; 4];
                sb.copy_from_slice(&payload[4..8]);
                got_max_seq.insert(*key, u32::from_le_bytes(sb));
            })
            .expect("drain");

        assert_eq!(n, 5, "100 inbound × 5 keys → 5 distinct delivered");
        assert_eq!(got_keys.len(), 5);
        assert_eq!(got_max_seq[&0], 95);
        assert_eq!(got_max_seq[&1], 96);
        assert_eq!(got_max_seq[&2], 97);
        assert_eq!(got_max_seq[&3], 98);
        assert_eq!(got_max_seq[&4], 99);
    }

    /// A source that fails once it has handed out its messages.
    struct FailingRecv {
        left: u32,
    }
    impl Source for FailingRecv {
        fn recv(&mut self) -> Result<(Vec<u8>, Token), ConflationError> {
            if self.left == 0 {
                return Err(ConflationError::source(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the transport went away",
                )));
            }
            self.left -= 1;
            let mut p = vec![0u8; 8];
            p[0..4].copy_from_slice(&7u32.to_le_bytes());
            Ok((
                p,
                Token {
                    send_ns: 0,
                    recv_ns: 0,
                    seq: 0,
                    payload_size: 8,
                },
            ))
        }
    }

    #[test]
    fn a_failing_source_is_reported_typed_with_its_cause() {
        let mut drainer =
            ConflationDrainer::new(Box::new(FailingRecv { left: 1 }), BytesExtractor::<0, 4>);
        let mut delivered = Vec::new();
        // The default `drain` takes one message per call, so the first
        // call delivers it and the second meets the failure.
        let n = drainer
            .drain_latest(10, |key, _| delivered.push(*key))
            .expect("first drain");
        assert_eq!(n, 1);
        assert_eq!(delivered, [7]);
        let err = drainer
            .drain_latest(10, |_, _| {})
            .expect_err("the source failed");
        assert!(matches!(err, ConflationError::Source(_)), "got {err:?}");
        assert_eq!(
            err.to_string(),
            "the source failed: the transport went away"
        );
        let cause = std::error::Error::source(&err).expect("the cause is carried");
        assert_eq!(
            cause
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::BrokenPipe)
        );
    }
}
