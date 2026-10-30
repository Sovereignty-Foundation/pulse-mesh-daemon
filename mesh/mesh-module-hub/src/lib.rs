// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `ModuleHub`, tier 2: a node's private hub beside the shared one.
//! **Status: pre-integration** (ADR-0014): vendored from sovOS™, used by
//! nothing in the tree at this revision. The daemon runs one shared hub
//! and no module hubs; the crate integrates when a node's processing runs
//! beside the daemon's hub through one.
//!
//! It collects the envelopes a parent `PulseHub` listener delivers and
//! keeps an outbox for the results bound back upstream, so a module
//! processes in its own loop without holding the parent's lock.
//!
//! The inbox is bounded ([`DEFAULT_INBOX_CAPACITY`], or the capacity given to
//! [`ModuleHub::with_inbox_capacity`]): a module that falls behind its parent
//! would otherwise hold every envelope the parent delivers, without limit. An
//! envelope that arrives while the inbox is full is dropped and counted
//! ([`ModuleHub::inbox_dropped`]), the newest dropped as the daemon's event
//! queues drop theirs. The outbox holds what the module itself emits, so its
//! size is the module's to keep.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.
#![forbid(unsafe_code)]

use mesh_broadcast::ListenFilter;
use mesh_hub_runtime::{HubError, PulseHub};
use parking_lot::Mutex;
use pulse_canon::{NodeId, PulseEnvelope};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Envelopes a module hub's inbox holds before it drops new ones, unless
/// [`ModuleHub::with_inbox_capacity`] gives another bound.
pub const DEFAULT_INBOX_CAPACITY: usize = 4096;

/// The bounded inbox, shared with the parent's listener.
struct Inbox {
    queue: Mutex<Vec<PulseEnvelope>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl Inbox {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(Vec::new()),
            capacity,
            dropped: AtomicU64::new(0),
        })
    }

    /// Queue `envelope` unless the inbox is full; `false` when it was dropped
    /// and counted.
    fn offer(&self, envelope: PulseEnvelope) -> bool {
        let mut queue = self.queue.lock();
        if queue.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        queue.push(envelope);
        true
    }
}

/// A child hub that filters inbound envelopes from a parent and queues
/// emitted results for propagation back upstream.
pub struct ModuleHub {
    name: String,
    node_id: NodeId,
    inbox: Arc<Inbox>,
    outbox: Arc<Mutex<Vec<PulseEnvelope>>>,
}

impl ModuleHub {
    /// Create a ModuleHub and register it as a listener on the parent hub,
    /// its inbox holding up to [`DEFAULT_INBOX_CAPACITY`] envelopes.
    pub fn new(parent: &mut PulseHub, name: &str, inbound_filter: ListenFilter) -> Self {
        Self::with_inbox_capacity(parent, name, inbound_filter, DEFAULT_INBOX_CAPACITY)
    }

    /// [`Self::new`] with an inbox that holds up to `capacity` envelopes; 0
    /// drops every one.
    pub fn with_inbox_capacity(
        parent: &mut PulseHub,
        name: &str,
        inbound_filter: ListenFilter,
        capacity: usize,
    ) -> Self {
        let node_id = NodeId::from_name(name);
        let inbox = Inbox::new(capacity);
        let inbox_clone = inbox.clone();

        parent.listen(node_id, inbound_filter, move |envelope| {
            let _ = inbox_clone.offer(envelope.clone());
        });

        Self {
            name: name.to_string(),
            node_id,
            inbox,
            outbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a standalone ModuleHub without a parent (for testing).
    pub fn standalone(name: &str) -> Self {
        Self {
            name: name.to_string(),
            node_id: NodeId::from_name(name),
            inbox: Inbox::new(DEFAULT_INBOX_CAPACITY),
            outbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Drain inbound envelopes that arrived from the parent hub.
    pub fn drain_inbox(&self) -> Vec<PulseEnvelope> {
        std::mem::take(&mut *self.inbox.queue.lock())
    }

    /// Push an envelope into the inbox (for testing or manual injection);
    /// `false` when the inbox was full and the envelope was dropped and
    /// counted.
    pub fn inject(&self, envelope: PulseEnvelope) -> bool {
        self.inbox.offer(envelope)
    }

    /// Envelopes dropped because the inbox was full, since the hub was made.
    pub fn inbox_dropped(&self) -> u64 {
        self.inbox.dropped.load(Ordering::Relaxed)
    }

    /// The most envelopes the inbox holds.
    pub fn inbox_capacity(&self) -> usize {
        self.inbox.capacity
    }

    /// Queue an envelope for propagation back to the parent hub.
    pub fn emit(&self, envelope: PulseEnvelope) {
        self.outbox.lock().push(envelope);
    }

    /// Drain outbound envelopes and route each through the parent hub,
    /// returning the error of every envelope the parent refused, in order;
    /// an empty list means every envelope was routed. The queues are
    /// `parking_lot` mutexes, which do not poison, so a panic elsewhere never
    /// makes an envelope vanish here.
    #[must_use = "an envelope the parent refused is lost unless its error is handled"]
    pub fn flush_to_parent(&self, parent: &mut PulseHub) -> Vec<HubError> {
        let envelopes = std::mem::take(&mut *self.outbox.lock());
        envelopes
            .into_iter()
            .filter_map(|envelope| parent.route_envelope(envelope, &self.node_id).err())
            .collect()
    }

    /// Drain outbound envelopes (for manual handling).
    pub fn drain_outbox(&self) -> Vec<PulseEnvelope> {
        std::mem::take(&mut *self.outbox.lock())
    }

    /// Return the module hub's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the node identifier derived from the module hub's name.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Return the number of envelopes currently queued in the inbox.
    pub fn inbox_len(&self) -> usize {
        self.inbox.queue.lock().len()
    }

    /// Return the number of envelopes currently queued in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    use mesh_hub_runtime::{HubConfig, ValidationMode};

    fn unique_name() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!(
            "mh{:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn flush_routes_every_envelope_to_the_parents_listeners() {
        let mut parent = PulseHub::create(
            &unique_name(),
            HubConfig::default().with_validation(ValidationMode::Passthrough),
        )
        .unwrap();
        let heard = Arc::new(AtomicU64::new(0));
        let h = heard.clone();
        parent.listen(NodeId::from_name("watcher"), ListenFilter::All, move |_| {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let module = ModuleHub::new(
            &mut parent,
            "processor",
            ListenFilter::TypeName("in/none".into()),
        );
        module.emit(PulseEnvelope::typed("out/a", vec![1]));
        module.emit(PulseEnvelope::typed("out/b", vec![2]));
        let refused = module.flush_to_parent(&mut parent);
        assert!(refused.is_empty(), "the parent refused {refused:?}");
        assert_eq!(heard.load(Ordering::SeqCst), 2);
        assert_eq!(module.outbox_len(), 0);
    }

    #[test]
    fn a_panic_while_queueing_never_drops_later_envelopes() {
        // A std mutex poisons here and the old code then dropped every
        // later envelope silently; the queues no longer poison.
        let hub = Arc::new(ModuleHub::standalone("poisoned"));
        let h = hub.clone();
        let _ = std::thread::spawn(move || {
            let _guard = h.outbox.lock();
            panic!("a module panics while holding its outbox");
        })
        .join();
        hub.emit(PulseEnvelope::typed("after/panic", vec![]));
        assert_eq!(hub.outbox_len(), 1);
        assert_eq!(hub.drain_outbox().len(), 1);
    }

    #[test]
    fn a_full_inbox_drops_and_counts_new_envelopes_until_drained() {
        let mut parent = PulseHub::create(
            &unique_name(),
            HubConfig::default().with_validation(ValidationMode::Passthrough),
        )
        .unwrap();
        let module = ModuleHub::with_inbox_capacity(&mut parent, "bounded", ListenFilter::All, 3);
        assert_eq!(module.inbox_capacity(), 3);
        for i in 0..5u8 {
            parent
                .broadcast_envelope(
                    PulseEnvelope::typed("in/x", vec![i]),
                    &NodeId::from_name("src"),
                )
                .unwrap();
        }
        assert_eq!(module.inbox_len(), 3);
        assert_eq!(module.inbox_dropped(), 2);
        let kept: Vec<Vec<u8>> = module
            .drain_inbox()
            .iter()
            .map(|e| e.payload().to_bytes())
            .collect();
        assert_eq!(kept, vec![vec![0], vec![1], vec![2]], "the oldest kept");
        assert!(module.inject(PulseEnvelope::typed("in/y", vec![])));
        assert_eq!(module.inbox_dropped(), 2, "room again after the drain");
        let none = ModuleHub::standalone("zero");
        assert_eq!(none.inbox_capacity(), DEFAULT_INBOX_CAPACITY);
    }

    #[test]
    fn standalone_module_hub() {
        let hub = ModuleHub::standalone("test");
        assert_eq!(hub.name(), "test");
        assert_eq!(hub.inbox_len(), 0);
        assert_eq!(hub.outbox_len(), 0);
    }

    #[test]
    fn inject_and_drain_inbox() {
        let hub = ModuleHub::standalone("test");
        let env = PulseEnvelope::typed("test/signal", vec![]);
        hub.inject(env);

        assert_eq!(hub.inbox_len(), 1);
        let drained = hub.drain_inbox();
        assert_eq!(drained.len(), 1);
        assert_eq!(hub.inbox_len(), 0);
    }

    #[test]
    fn emit_and_drain_outbox() {
        let hub = ModuleHub::standalone("test");
        let env = PulseEnvelope::typed("test/result", vec![]);
        hub.emit(env);

        assert_eq!(hub.outbox_len(), 1);
        let drained = hub.drain_outbox();
        assert_eq!(drained.len(), 1);
        assert_eq!(hub.outbox_len(), 0);
    }

    #[test]
    fn round_trip_inject_emit() {
        let hub = ModuleHub::standalone("processor");

        let input = PulseEnvelope::typed("input/signal", vec![1, 2, 3]);
        hub.inject(input);

        let inbox = hub.drain_inbox();
        assert_eq!(inbox.len(), 1);

        let output = PulseEnvelope::typed("output/result", vec![4, 5, 6]);
        hub.emit(output);

        let outbox = hub.drain_outbox();
        assert_eq!(outbox.len(), 1);

        assert_eq!(hub.inbox_len(), 0);
        assert_eq!(hub.outbox_len(), 0);
    }

    #[test]
    fn multiple_envelopes_queued() {
        let hub = ModuleHub::standalone("multi");

        for i in 0..5 {
            hub.inject(PulseEnvelope::new(i, vec![]));
        }
        assert_eq!(hub.inbox_len(), 5);

        let all = hub.drain_inbox();
        assert_eq!(all.len(), 5);
        for (i, env) in all.iter().enumerate() {
            assert_eq!(env.envelope_type(), i as u16);
        }
    }

    #[test]
    fn node_id_derived_from_name() {
        let hub = ModuleHub::standalone("my_module");
        assert_eq!(hub.node_id(), NodeId::from_name("my_module"));
    }

    #[test]
    fn drain_inbox_is_idempotent() {
        let hub = ModuleHub::standalone("test");
        hub.inject(PulseEnvelope::new(1, vec![]));
        hub.drain_inbox();

        let second = hub.drain_inbox();
        assert!(second.is_empty());
    }

    #[test]
    fn drain_outbox_is_idempotent() {
        let hub = ModuleHub::standalone("test");
        hub.emit(PulseEnvelope::new(1, vec![]));
        hub.drain_outbox();

        let second = hub.drain_outbox();
        assert!(second.is_empty());
    }
}
