// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `HealthRegistry`: per-node liveness with escalation, tier 2.
//!
//! Every registered node has a [`NodeHealth`] record. A heartbeat resets
//! its misses, [`HealthRegistry::tick`] counts them, and they escalate the
//! node through the [`NodeState`]s at the [`HeartbeatConfig`] thresholds.
//! Drift is a flag of its own ([`NodeHealth::record_drift`]). The unit
//! tests in `src/lib.rs` check each transition.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.
#![forbid(unsafe_code)]

use std::collections::HashMap;

use pulse_canon::NodeId;

/// A node's state: where its miss count puts it, or `Degraded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Miss count below `warn_after`, and no drift recorded since the
    /// node's last heartbeat.
    Healthy,
    /// Miss count has reached `warn_after`.
    Warning,
    /// Miss count has reached `restart_after`; restart attempt in progress.
    Restarting,
    /// Miss count has reached `isolate_after`; node has been isolated.
    Isolated,
    /// Drift recorded ([`NodeHealth::record_drift`]) while the miss count
    /// is below `warn_after`. Misses that reach it give their own state,
    /// the drift still recorded ([`NodeHealth::drifted`]).
    Degraded,
}

/// Heartbeat configuration: cadence + escalation thresholds.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HeartbeatConfig {
    /// Expected heartbeat cadence in milliseconds.
    pub interval_ms: u64,
    /// Misses required before transitioning Healthy → Warning.
    pub warn_after: u32,
    /// Misses required before transitioning Warning → Restarting.
    pub restart_after: u32,
    /// Misses required before transitioning Restarting → Isolated.
    pub isolate_after: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_ms: 500,
            warn_after: 3,
            restart_after: 5,
            isolate_after: 10,
        }
    }
}

impl HeartbeatConfig {
    /// This configuration with the expected cadence in milliseconds.
    #[must_use]
    pub fn with_interval_ms(mut self, interval_ms: u64) -> Self {
        self.interval_ms = interval_ms;
        self
    }

    /// This configuration with the misses that make a node Warning.
    #[must_use]
    pub fn with_warn_after(mut self, warn_after: u32) -> Self {
        self.warn_after = warn_after;
        self
    }

    /// This configuration with the misses that make a node Restarting.
    #[must_use]
    pub fn with_restart_after(mut self, restart_after: u32) -> Self {
        self.restart_after = restart_after;
        self
    }

    /// This configuration with the misses that make a node Isolated.
    #[must_use]
    pub fn with_isolate_after(mut self, isolate_after: u32) -> Self {
        self.isolate_after = isolate_after;
        self
    }
}

/// One node's health record.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    node_id: NodeId,
    last_heartbeat: u64,
    miss_count: u32,
    error_count: u64,
    restart_count: u32,
    /// The state the miss count gives: never `Degraded`.
    liveness: NodeState,
    /// Drift recorded since the last heartbeat; see [`Self::drifted`].
    drifted: bool,
    /// Heartbeated since the registry's last tick, so the next one counts
    /// no miss.
    heard_since_tick: bool,
    schema_version: u64,
    stage_count: u32,
}

impl NodeHealth {
    /// Node identifier.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Last seen heartbeat tick (caller-supplied units).
    pub fn last_heartbeat(&self) -> u64 {
        self.last_heartbeat
    }

    /// Consecutive misses since the last heartbeat.
    pub fn miss_count(&self) -> u32 {
        self.miss_count
    }

    /// Total error count reported by the node.
    pub fn error_count(&self) -> u64 {
        self.error_count
    }

    /// Number of times this node has been restarted.
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Current state (see [`NodeState::Degraded`]).
    pub fn state(&self) -> NodeState {
        if self.drifted && self.liveness == NodeState::Healthy {
            NodeState::Degraded
        } else {
            self.liveness
        }
    }

    /// Whether drift is recorded ([`Self::record_drift`]), whatever the
    /// state reads.
    pub fn drifted(&self) -> bool {
        self.drifted
    }

    /// Most recent schema-version fingerprint reported by the node.
    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }

    /// Number of stages registered in this node.
    pub fn stage_count(&self) -> u32 {
        self.stage_count
    }

    /// Create a fresh `NodeHealth` for the given node, in `Healthy` state
    /// with all counters at zero.
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            last_heartbeat: 0,
            miss_count: 0,
            error_count: 0,
            restart_count: 0,
            liveness: NodeState::Healthy,
            drifted: false,
            heard_since_tick: false,
            schema_version: 0,
            stage_count: 0,
        }
    }

    /// Update the schema fingerprint and stage count.
    pub fn set_schema(&mut self, version: u64, count: u32) {
        self.schema_version = version;
        self.stage_count = count;
    }

    /// Record a successful heartbeat: reset misses, clear any drift, return
    /// to `Healthy`, and spare the node a miss at the registry's next tick.
    pub fn record_heartbeat(&mut self, tick: u64) {
        self.last_heartbeat = tick;
        self.miss_count = 0;
        self.liveness = NodeState::Healthy;
        self.drifted = false;
        self.heard_since_tick = true;
    }

    /// Record a missed heartbeat (saturating) and set the state the
    /// thresholds give; drift is left as it is.
    pub fn record_miss(&mut self, config: &HeartbeatConfig) {
        self.miss_count = self.miss_count.saturating_add(1);
        self.liveness = if self.miss_count >= config.isolate_after {
            NodeState::Isolated
        } else if self.miss_count >= config.restart_after {
            NodeState::Restarting
        } else if self.miss_count >= config.warn_after {
            NodeState::Warning
        } else {
            NodeState::Healthy
        };
    }

    /// A miss unless the node heartbeated since the last tick; the new
    /// state, if it changed.
    fn tick(&mut self, config: &HeartbeatConfig) -> Option<NodeState> {
        if std::mem::take(&mut self.heard_since_tick) {
            return None;
        }
        let before = self.state();
        self.record_miss(config);
        let after = self.state();
        (after != before).then_some(after)
    }

    /// Record an application error. Saturates `error_count` at `u64::MAX`.
    pub fn record_error(&mut self) {
        self.error_count = self.error_count.saturating_add(1);
    }

    /// Record drift, such as a changed schema version. Ticks and misses
    /// keep it; the next heartbeat or restart clears it.
    pub fn record_drift(&mut self) {
        self.drifted = true;
    }

    /// Record a successful restart: count it, reset the misses and clear
    /// any drift, returning the node to `Healthy`.
    pub fn record_restart(&mut self) {
        self.restart_count = self.restart_count.saturating_add(1);
        self.miss_count = 0;
        self.liveness = NodeState::Healthy;
        self.drifted = false;
    }
}

/// Registry tracking the heartbeat state of all known nodes.
pub struct HealthRegistry {
    nodes: HashMap<NodeId, NodeHealth>,
    config: HeartbeatConfig,
}

impl HealthRegistry {
    /// Create an empty registry with the given heartbeat configuration.
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            nodes: HashMap::new(),
            config,
        }
    }

    /// Register a new node. Idempotent: re-registering the same `NodeId`
    /// preserves any existing health record.
    pub fn register(&mut self, node_id: NodeId) {
        self.nodes
            .entry(node_id)
            .or_insert_with(|| NodeHealth::new(node_id));
    }

    /// Forget a node, returning its last health record, or `None` if it was
    /// not registered. A later [`Self::register`] of the same id starts it
    /// over, `Healthy` with every counter at zero, and the ticks between
    /// count nothing for it.
    pub fn unregister(&mut self, node_id: &NodeId) -> Option<NodeHealth> {
        self.nodes.remove(node_id)
    }

    /// Record a heartbeat for `node_id`. No-op if the node isn't registered.
    pub fn heartbeat(&mut self, node_id: &NodeId, tick: u64) {
        if let Some(health) = self.nodes.get_mut(node_id) {
            health.record_heartbeat(tick);
        }
    }

    /// Count a miss for every node that has not heartbeated since the
    /// previous tick (or since it registered), and return the nodes whose
    /// state changed, with the new state.
    pub fn tick(&mut self) -> Vec<(NodeId, NodeState)> {
        let config = &self.config;
        let mut transitions = Vec::new();
        for health in self.nodes.values_mut() {
            if let Some(state) = health.tick(config) {
                transitions.push((health.node_id, state));
            }
        }
        transitions
    }

    /// Look up a node's health record.
    pub fn get(&self, node_id: &NodeId) -> Option<&NodeHealth> {
        self.nodes.get(node_id)
    }

    /// Mutably look up a node's health record, to record drift or errors.
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeHealth> {
        self.nodes.get_mut(node_id)
    }

    /// Return references to all currently `Healthy` node records.
    pub fn healthy_nodes(&self) -> Vec<&NodeHealth> {
        self.nodes
            .values()
            .filter(|h| h.state() == NodeState::Healthy)
            .collect()
    }

    /// Return references to all node records whose state is anything other
    /// than `Healthy`.
    pub fn unhealthy_nodes(&self) -> Vec<&NodeHealth> {
        self.nodes
            .values()
            .filter(|h| h.state() != NodeState::Healthy)
            .collect()
    }

    /// Borrow the registry's heartbeat configuration.
    pub fn config(&self) -> &HeartbeatConfig {
        &self.config
    }

    /// Number of registered nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True iff `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Thresholds a few ticks apart, so each state is reached on its own.
    fn config() -> HeartbeatConfig {
        HeartbeatConfig {
            interval_ms: 500,
            warn_after: 2,
            restart_after: 3,
            isolate_after: 5,
        }
    }

    fn registry_with(node: NodeId, config: HeartbeatConfig) -> HealthRegistry {
        let mut registry = HealthRegistry::new(config);
        registry.register(node);
        registry
    }

    fn state(registry: &HealthRegistry, node: &NodeId) -> NodeState {
        registry.get(node).unwrap().state()
    }

    #[test]
    fn a_node_starts_healthy() {
        let node = NodeId::from_name("new");
        let registry = registry_with(node, config());
        let health = registry.get(&node).unwrap();
        assert_eq!(health.state(), NodeState::Healthy);
        assert_eq!(health.miss_count(), 0);
        assert!(!health.drifted());
        assert_eq!(registry.healthy_nodes().len(), 1);
        assert!(registry.unhealthy_nodes().is_empty());
    }

    #[test]
    fn a_node_that_heartbeats_before_every_tick_stays_healthy() {
        let node = NodeId::from_name("punctual");
        let mut registry = registry_with(
            node,
            HeartbeatConfig {
                warn_after: 1,
                ..config()
            },
        );
        for round in 1..=10 {
            registry.heartbeat(&node, round);
            assert_eq!(registry.tick(), [], "round {round}");
            assert_eq!(state(&registry, &node), NodeState::Healthy);
            assert_eq!(registry.get(&node).unwrap().miss_count(), 0);
        }
    }

    #[test]
    fn a_silent_node_escalates_at_each_threshold_and_is_reported_once_there() {
        let node = NodeId::from_name("silent");
        let mut registry = registry_with(node, config());
        let expected = [
            (1, NodeState::Healthy, false),
            (2, NodeState::Warning, true),
            (3, NodeState::Restarting, true),
            (4, NodeState::Restarting, false),
            (5, NodeState::Isolated, true),
            (6, NodeState::Isolated, false),
        ];
        for (misses, want, reported) in expected {
            let transitions = registry.tick();
            assert_eq!(state(&registry, &node), want, "after {misses} misses");
            assert_eq!(registry.get(&node).unwrap().miss_count(), misses);
            let want_transitions = if reported { vec![(node, want)] } else { vec![] };
            assert_eq!(transitions, want_transitions, "after {misses} misses");
        }
    }

    #[test]
    fn a_heartbeat_returns_an_escalated_node_to_healthy_and_the_count_starts_over() {
        let node = NodeId::from_name("late");
        let mut registry = registry_with(node, config());
        for _ in 0..3 {
            registry.tick();
        }
        assert_eq!(state(&registry, &node), NodeState::Restarting);
        registry.heartbeat(&node, 7);
        let health = registry.get(&node).unwrap();
        assert_eq!(health.state(), NodeState::Healthy);
        assert_eq!((health.miss_count(), health.last_heartbeat()), (0, 7));
        // That heartbeat spares the node the next tick, not the one after.
        assert_eq!(registry.tick(), []);
        assert_eq!(registry.get(&node).unwrap().miss_count(), 0);
        registry.tick();
        assert_eq!(registry.get(&node).unwrap().miss_count(), 1);
    }

    #[test]
    fn drift_reads_degraded_through_ticks_until_the_next_heartbeat() {
        let node = NodeId::from_name("drifter");
        let mut registry = registry_with(node, config());
        registry.heartbeat(&node, 1);
        registry.get_mut(&node).unwrap().record_drift();
        assert_eq!(state(&registry, &node), NodeState::Degraded);
        assert_eq!(registry.unhealthy_nodes().len(), 1);
        // A tick after the heartbeat counts nothing and keeps the drift.
        assert_eq!(registry.tick(), []);
        assert_eq!(state(&registry, &node), NodeState::Degraded);
        // A silent tick counts a miss below the threshold and keeps it too.
        assert_eq!(registry.tick(), []);
        let health = registry.get(&node).unwrap();
        assert_eq!(
            (health.state(), health.miss_count()),
            (NodeState::Degraded, 1)
        );
        // The next heartbeat clears it.
        registry.heartbeat(&node, 2);
        let health = registry.get(&node).unwrap();
        assert_eq!(health.state(), NodeState::Healthy);
        assert!(!health.drifted());
    }

    #[test]
    fn a_drifted_node_that_falls_silent_escalates_and_keeps_its_drift() {
        let node = NodeId::from_name("gone");
        let mut registry = registry_with(node, config());
        registry.get_mut(&node).unwrap().record_drift();
        assert_eq!(registry.tick(), []);
        assert_eq!(state(&registry, &node), NodeState::Degraded);
        assert_eq!(registry.tick(), [(node, NodeState::Warning)]);
        let health = registry.get(&node).unwrap();
        assert_eq!(health.state(), NodeState::Warning);
        assert!(health.drifted(), "the drift went with the escalation");
        registry.heartbeat(&node, 3);
        assert_eq!(state(&registry, &node), NodeState::Healthy);
    }

    #[test]
    fn a_restart_counts_and_returns_the_node_to_healthy() {
        let node = NodeId::from_name("restarted");
        let mut registry = registry_with(node, config());
        for _ in 0..3 {
            registry.tick();
        }
        let health = registry.get_mut(&node).unwrap();
        health.record_drift();
        health.record_restart();
        assert_eq!(health.state(), NodeState::Healthy);
        assert_eq!((health.miss_count(), health.restart_count()), (0, 1));
        assert!(!health.drifted());
    }

    #[test]
    fn an_unregistered_node_is_forgotten_and_a_second_registration_starts_over() {
        let (gone, kept) = (NodeId::from_name("gone"), NodeId::from_name("kept"));
        let mut registry = registry_with(gone, config());
        registry.register(kept);
        for _ in 0..2 {
            registry.tick();
        }
        assert_eq!(state(&registry, &gone), NodeState::Warning);
        let last = registry.unregister(&gone).expect("it was registered");
        assert_eq!((last.state(), last.miss_count()), (NodeState::Warning, 2));
        assert!(registry.get(&gone).is_none());
        assert_eq!(registry.len(), 1, "the other node stays");
        assert!(registry.unregister(&gone).is_none(), "once only");
        // A heartbeat for it is a no-op, and ticks report only the other.
        registry.heartbeat(&gone, 1);
        assert_eq!(registry.tick(), [(kept, NodeState::Restarting)]);
        assert!(registry.get(&gone).is_none());
        registry.register(gone);
        let fresh = registry.get(&gone).unwrap();
        assert_eq!((fresh.state(), fresh.miss_count()), (NodeState::Healthy, 0));
    }

    #[test]
    fn only_the_nodes_silent_since_the_last_tick_accrue_misses() {
        let (talker, mute) = (NodeId::from_name("talker"), NodeId::from_name("mute"));
        let mut registry = registry_with(talker, config());
        registry.register(mute);
        let mut transitions = Vec::new();
        for round in 1..=2 {
            registry.heartbeat(&talker, round);
            transitions.extend(registry.tick());
        }
        assert_eq!(transitions, [(mute, NodeState::Warning)]);
        assert_eq!(registry.get(&talker).unwrap().miss_count(), 0);
        assert_eq!(registry.get(&mute).unwrap().miss_count(), 2);
        let unhealthy: Vec<NodeId> = registry
            .unhealthy_nodes()
            .iter()
            .map(|h| h.node_id())
            .collect();
        assert_eq!(unhealthy, [mute]);
    }
}
