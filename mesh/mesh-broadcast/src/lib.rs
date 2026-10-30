// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `BroadcastRegistry`: in-process fan-out of envelopes, tier 2.
//!
//! Listeners register a node id, a [`ListenFilter`] and a callback;
//! [`BroadcastRegistry::dispatch`] runs the callbacks whose filters match an
//! envelope. The hub runtime routes envelopes inside one process with it.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.
#![forbid(unsafe_code)]

pub mod filter;

use std::collections::HashMap;

use pulse_canon::Instruction;
use pulse_canon::NodeId;
use pulse_canon::PulseEnvelope;

pub use filter::ListenFilter;

/// A registered listener: filter + callback bound to a `NodeId`.
pub struct Listener {
    /// Unique listener ID, monotonically allocated by the registry.
    pub id: u64,
    /// Owning node identifier.
    pub node_id: NodeId,
    /// Filter predicate.
    pub filter: ListenFilter,
    /// Callback invoked when the filter matches.
    pub callback: Box<dyn FnMut(&PulseEnvelope) + Send>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("id", &self.id)
            .field("node_id", &self.node_id)
            .field("filter", &self.filter)
            .finish()
    }
}

/// Result of a single `dispatch` call.
#[derive(Debug, Clone, Default)]
pub struct BroadcastResult {
    /// Number of listeners whose filter matched.
    pub matched: usize,
    /// Number of callbacks invoked; every match is delivered, so this is
    /// `matched`.
    pub delivered: usize,
    /// Listener IDs that received the envelope, in dispatch order.
    pub recipients: Vec<u64>,
}

impl BroadcastResult {
    /// Create an empty result (matched = delivered = 0, no recipients).
    pub fn new() -> Self {
        Self::default()
    }
}

/// Registry of broadcast listeners, indexed by node and by envelope type.
pub struct BroadcastRegistry {
    listeners: Vec<Listener>,
    by_node: HashMap<NodeId, Vec<u64>>,
    by_type: HashMap<u16, Vec<u64>>,
    next_id: u64,
}

impl Default for BroadcastRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BroadcastRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            by_node: HashMap::new(),
            by_type: HashMap::new(),
            next_id: 1,
        }
    }

    /// Register a listener and return its id, for [`Self::unlisten`].
    pub fn listen<F>(&mut self, node_id: NodeId, filter: ListenFilter, callback: F) -> u64
    where
        F: FnMut(&PulseEnvelope) + Send + 'static,
    {
        let id = self.next_id;
        self.next_id += 1;

        if let ListenFilter::Type(t) = &filter {
            self.by_type.entry(*t).or_default().push(id);
        }
        self.by_node.entry(node_id).or_default().push(id);

        self.listeners.push(Listener {
            id,
            node_id,
            filter,
            callback: Box::new(callback),
        });

        id
    }

    /// Deregister a listener; `false` if none has this id.
    pub fn unlisten(&mut self, listener_id: u64) -> bool {
        let Some(pos) = self.listeners.iter().position(|l| l.id == listener_id) else {
            return false;
        };
        let listener = self.listeners.remove(pos);

        if let Some(ids) = self.by_node.get_mut(&listener.node_id) {
            ids.retain(|&id| id != listener_id);
        }
        if let ListenFilter::Type(t) = &listener.filter {
            if let Some(ids) = self.by_type.get_mut(t) {
                ids.retain(|&id| id != listener_id);
            }
        }

        true
    }

    /// Deregister all listeners belonging to the given node.
    pub fn unlisten_node(&mut self, node_id: &NodeId) {
        let Some(ids) = self.by_node.remove(node_id) else {
            return;
        };
        let removed: std::collections::HashSet<u64> = ids.into_iter().collect();
        self.listeners.retain(|l| !removed.contains(&l.id));
        for slot in self.by_type.values_mut() {
            slot.retain(|id| !removed.contains(id));
        }
    }

    /// Run the callback of every listener whose filter matches `envelope`;
    /// `instruction` and `scope` are the Pulse context that
    /// [`ListenFilter::matches`] takes.
    pub fn dispatch(
        &mut self,
        envelope: &PulseEnvelope,
        instruction: Option<Instruction>,
        scope: Option<u32>,
    ) -> BroadcastResult {
        let mut result = BroadcastResult::new();

        // The index skips only `Type` listeners whose type differs, which
        // could not match: the result is what evaluating every filter gives.
        let type_indexed_ids: Option<&Vec<u64>> = self.by_type.get(&envelope.envelope_type());

        for listener in &mut self.listeners {
            if matches!(listener.filter, ListenFilter::Type(_)) {
                let in_index = type_indexed_ids
                    .map(|ids| ids.contains(&listener.id))
                    .unwrap_or(false);
                if !in_index {
                    continue;
                }
            }

            if listener.filter.matches(envelope, instruction, scope) {
                result.matched += 1;
                (listener.callback)(envelope);
                result.delivered += 1;
                result.recipients.push(listener.id);
            }
        }

        result
    }

    /// The node ids of the `Type(envelope_type)` and `All` listeners, one per
    /// listener, in no set order.
    pub fn listeners_for_type(&self, envelope_type: u16) -> Vec<NodeId> {
        self.listeners
            .iter()
            .filter(|l| {
                matches!(&l.filter, ListenFilter::Type(t) if *t == envelope_type)
                    || matches!(&l.filter, ListenFilter::All)
            })
            .map(|l| l.node_id)
            .collect()
    }

    /// Total number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// True iff `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// Number of listeners belonging to a specific node.
    pub fn listeners_for_node(&self, node_id: &NodeId) -> usize {
        self.by_node.get(node_id).map(|v| v.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for BroadcastRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BroadcastRegistry")
            .field("listener_count", &self.listeners.len())
            .field("nodes", &self.by_node.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn envelope() -> PulseEnvelope {
        let mut env = PulseEnvelope::with_content(42, Some("orders/fills".into()), b"x".to_vec());
        env.origin = NodeId::from_name("src").0;
        env
    }

    /// Every filter variant on one envelope and one Pulse context.
    #[test]
    fn each_filter_matches_what_it_names_and_nothing_else() {
        let env = envelope();
        let (data, scope) = (Some(Instruction::Data), Some(7));
        let cases = [
            (ListenFilter::All, true),
            (ListenFilter::Type(42), true),
            (ListenFilter::Type(43), false),
            (ListenFilter::TypeName("orders/fills".into()), true),
            (ListenFilter::TypeName("orders".into()), false),
            (ListenFilter::TypePrefix("orders/".into()), true),
            (ListenFilter::TypePrefix("quotes/".into()), false),
            (ListenFilter::Instruction(Instruction::Data), true),
            (ListenFilter::Instruction(Instruction::Heartbeat), false),
            (ListenFilter::Origin(NodeId::from_name("src")), true),
            (ListenFilter::Origin(NodeId::from_name("other")), false),
            (ListenFilter::Scope(7), true),
            (ListenFilter::Scope(8), false),
            (ListenFilter::And(vec![]), true),
            (ListenFilter::Or(vec![]), false),
            (
                ListenFilter::And(vec![ListenFilter::Type(42), ListenFilter::Scope(7)]),
                true,
            ),
            (
                ListenFilter::And(vec![ListenFilter::Type(42), ListenFilter::Scope(8)]),
                false,
            ),
            (
                ListenFilter::Or(vec![ListenFilter::Type(43), ListenFilter::Scope(7)]),
                true,
            ),
        ];
        for (filter, want) in cases {
            assert_eq!(filter.matches(&env, data, scope), want, "{filter:?}");
        }
    }

    /// Without a Pulse, the Instruction and Scope filters match nothing.
    #[test]
    fn instruction_and_scope_filters_need_a_pulse_context() {
        let env = envelope();
        assert!(!ListenFilter::Instruction(Instruction::Data).matches(&env, None, None));
        assert!(!ListenFilter::Scope(0).matches(&env, None, None));
        assert!(ListenFilter::All.matches(&env, None, None));
    }

    fn counting(
        registry: &mut BroadcastRegistry,
        node: &str,
        filter: ListenFilter,
    ) -> (u64, Arc<Mutex<u32>>) {
        let count = Arc::new(Mutex::new(0));
        let sink = Arc::clone(&count);
        let id = registry.listen(NodeId::from_name(node), filter, move |_| {
            *sink.lock().unwrap() += 1
        });
        (id, count)
    }

    /// Dispatch calls exactly the matching listeners, the type index skipping
    /// only `Type` listeners of another type, and reports them.
    #[test]
    fn dispatch_reaches_the_matching_listeners_and_reports_them() {
        let mut registry = BroadcastRegistry::new();
        let (typed, typed_n) = counting(&mut registry, "a", ListenFilter::Type(42));
        let (_other, other_n) = counting(&mut registry, "a", ListenFilter::Type(7));
        let (all, all_n) = counting(&mut registry, "b", ListenFilter::All);
        let (_scoped, scoped_n) = counting(&mut registry, "b", ListenFilter::Scope(3));

        let result = registry.dispatch(&envelope(), Some(Instruction::Data), Some(9));
        assert_eq!((result.matched, result.delivered), (2, 2));
        assert_eq!(result.recipients, vec![typed, all]);
        assert_eq!(*typed_n.lock().unwrap(), 1);
        assert_eq!(*all_n.lock().unwrap(), 1);
        assert_eq!(*other_n.lock().unwrap(), 0);
        assert_eq!(*scoped_n.lock().unwrap(), 0);
    }

    /// Unlisten removes one listener and its index entries; unlisten_node
    /// removes every listener of the node.
    #[test]
    fn unlisten_and_unlisten_node_remove_listeners_and_their_index_entries() {
        let mut registry = BroadcastRegistry::new();
        let (typed, typed_n) = counting(&mut registry, "a", ListenFilter::Type(42));
        let (_all, all_n) = counting(&mut registry, "b", ListenFilter::All);
        let _ = counting(&mut registry, "b", ListenFilter::Type(42));
        assert_eq!(registry.listeners_for_type(42).len(), 3);

        assert!(registry.unlisten(typed));
        assert!(!registry.unlisten(typed), "a second unlisten finds nothing");
        registry.unlisten_node(&NodeId::from_name("b"));
        assert!(registry.is_empty());
        assert!(registry.listeners_for_type(42).is_empty());

        let result = registry.dispatch(&envelope(), None, None);
        assert_eq!(result.delivered, 0);
        assert_eq!(*typed_n.lock().unwrap(), 0);
        assert_eq!(*all_n.lock().unwrap(), 0);
    }
}
