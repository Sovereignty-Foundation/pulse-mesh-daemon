// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's registry: attached names and their node ids, the connections
//! holding a place under the cap, the counters and queue budget every listener
//! shares, and the attached connections' liveness (`health`). The links to
//! other daemons (`crate::link`) watch its attaches and detaches, which they
//! announce to their peers, and find a send's destination in it.

use crate::connection::ConnectionPolicy;
use crate::health::HealthTracker;
use crate::hub_bridge::SubscriptionId;
use crate::queue::{EventSink, QueueTotal};
use mesh_health::NodeState;
use mesh_port_protocol::attach;
use parking_lot::RwLock;
use pulse_canon::NodeId;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// A unique identifier for a daemon-side connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn-{}", self.0)
    }
}

/// A producer as the daemon names it: the node id derived from its attach name,
/// or from the key it proved at attach, and that id's canonical `name@suffix`
/// form ([`crate::protocol::AckFields::node_id`]): 8 hex digits after the `@`
/// for a name, 32 for a key (`mesh_port_protocol::attach`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    node_id: NodeId,
    canonical: String,
    /// The name its sends carry across links, before `@` and this daemon's
    /// id ([`Origin::link_name`]).
    link_name: String,
}

impl Origin {
    /// The origin of a connection attached as `name`.
    #[must_use]
    pub fn named(name: &str) -> Self {
        let node_id = NodeId::from_name(name);
        let suffix: String = node_id.as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            canonical: format!("{name}@{suffix}"),
            node_id,
            link_name: name.to_string(),
        }
    }

    /// The origin of a connection attached as `name` that proved
    /// `public_key`: the node id the key derives
    /// ([`attach::key_node_id`]), whatever the name, and `name@` with that
    /// id's 32 hex digits.
    #[must_use]
    pub fn keyed(name: &str, public_key: &[u8; attach::PUBLIC_KEY_LEN]) -> Self {
        let canonical = attach::keyed_node_id(name, public_key);
        Self {
            node_id: NodeId::from_bytes(attach::key_node_id(public_key)),
            link_name: canonical.clone(),
            canonical,
        }
    }

    /// The name this origin's sends carry across links (ADR-0021, item 3),
    /// which a peer qualifies with this daemon's id as `name@` and 16 hex
    /// digits (`mesh_link::QualifiedOrigin`): the attach name, or for a
    /// connection that proved a key the name the key gives it, `name@` and
    /// the key's 32 hex digits, so that a peer can tell a proven key from a
    /// claimed name.
    #[must_use]
    pub fn link_name(&self) -> &str {
        &self.link_name
    }

    /// The node id.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The canonical `name@suffix` form.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

/// State the daemon tracks for an attached connection.
#[derive(Debug, Clone)]
pub struct AttachedEntry {
    /// The name the connection attached under, which no other attached
    /// connection holds.
    pub name: String,
    /// The node the connection publishes as.
    pub origin: Origin,
    /// The connection that attached.
    pub connection_id: ConnectionId,
    /// When it attached, in nanoseconds since the Unix epoch (0 for a clock
    /// that reads earlier than the epoch).
    pub attached_at_unix_nanos: u128,
}

/// Attached connections by name and by id, and the counts every listener of a
/// daemon shares.
#[derive(Debug, Default)]
pub struct Registry {
    inner: RwLock<RegistryInner>,
    next_conn: AtomicU64,
    /// Connections holding a place: accepted and not yet closed.
    live: AtomicUsize,
    /// Connections turned away because `live` was at the cap.
    refused: AtomicU64,
    /// WebSocket upgrades refused for their `Origin`.
    origins_refused: AtomicU64,
    /// Attaches refused with `auth_failed`.
    attaches_refused: AtomicU64,
    /// Bytes of event JSON queued across every connection, and the events
    /// dropped at the daemon-wide budget.
    queued: Arc<QueueTotal>,
    /// The attached connections' liveness, and the connections watching it;
    /// `None` when it is not tracked ([`Registry::new`], or an idle timeout of
    /// zero).
    health: Option<HealthTracker>,
    /// Called after every attach and detach, once the links watch them
    /// ([`Registry::watch_nodes`]).
    nodes_changed: NodesHook,
}

/// What [`Registry::watch_nodes`] set, if anything.
#[derive(Default)]
struct NodesHook(OnceLock<Box<dyn Fn() + Send + Sync>>);

impl fmt::Debug for NodesHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.get().is_some() {
            "NodesHook(set)"
        } else {
            "NodesHook(unset)"
        })
    }
}

/// A place among the daemon's live connections, held from accept until the
/// connection has closed. Dropping it frees the place.
#[derive(Debug)]
#[must_use = "dropping the slot frees the place at once"]
pub struct ConnectionSlot {
    registry: Arc<Registry>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.registry.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection turned away because the daemon held as many as its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtCapacity {
    /// Connections refused since the registry was created, this one
    /// included, so a caller can rate-limit its log by it.
    pub refused: u64,
}

#[derive(Debug, Default)]
struct RegistryInner {
    by_name: HashMap<String, AttachedEntry>,
    by_conn: HashMap<ConnectionId, AttachedEntry>,
}

/// Outcome of an attach attempt.
#[derive(Debug)]
pub enum AttachResult {
    /// Attached, with the connection's entry.
    Attached(AttachedEntry),
    /// Another connection already owns this name.
    NameInUse,
    /// Another connection, under another name, is attached as the same node:
    /// it proved the same key.
    NodeInUse {
        /// The name that connection attached under.
        holder: String,
    },
}

impl Registry {
    /// An empty registry, behind the `Arc` a daemon's listeners share:
    /// nothing attached, no connection admitted, every count at zero, and no
    /// liveness tracked.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// [`Registry::new`], for connections served under `policy`: it tracks
    /// their liveness, ticked every tenth of the policy's idle timeout by the
    /// task `health::ticks` makes, unless that timeout is zero.
    pub fn for_policy(policy: &ConnectionPolicy) -> Arc<Self> {
        Arc::new(Self {
            health: HealthTracker::for_idle_timeout(policy.idle_timeout),
            ..Self::default()
        })
    }

    /// Allocate a fresh connection id (called once per accept).
    pub fn next_connection_id(&self) -> ConnectionId {
        ConnectionId(self.next_conn.fetch_add(1, Ordering::Relaxed))
    }

    /// Take a place for a new connection if fewer than `max` hold one, until
    /// the returned slot drops.
    ///
    /// # Errors
    ///
    /// [`AtCapacity`], counted in [`Registry::connections_refused`], when `max`
    /// already do.
    pub fn admit(self: &Arc<Self>, max: usize) -> Result<ConnectionSlot, AtCapacity> {
        match self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < max).then_some(n + 1)
            }) {
            Ok(_) => Ok(ConnectionSlot {
                registry: Arc::clone(self),
            }),
            Err(_) => Err(AtCapacity {
                refused: self.refused.fetch_add(1, Ordering::Relaxed) + 1,
            }),
        }
    }

    /// Connections holding a place now, on either transport: accepted and
    /// not yet closed, a WebSocket still upgrading included.
    pub fn connections(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Connections refused at the cap since the registry was created.
    pub fn connections_refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Count a WebSocket upgrade refused for its `Origin`, returning the count
    /// so far to rate-limit the log by.
    pub fn refuse_origin(&self) -> u64 {
        self.origins_refused.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// WebSocket upgrades refused for their `Origin` since the registry was
    /// created.
    pub fn origins_refused(&self) -> u64 {
        self.origins_refused.load(Ordering::Relaxed)
    }

    /// Count an attach refused with `auth_failed`, returning the count so far
    /// to rate-limit the log by: a flood of bad attaches must not flood it.
    pub fn refuse_attach(&self) -> u64 {
        self.attaches_refused.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Attaches refused with `auth_failed` since the registry was created.
    pub fn attaches_refused(&self) -> u64 {
        self.attaches_refused.load(Ordering::Relaxed)
    }

    /// The daemon-wide event queue budget its connections share.
    pub fn queue_total(&self) -> &Arc<QueueTotal> {
        &self.queued
    }

    /// Register a connection under a name, and its node with the liveness
    /// tracking. Returns `NameInUse` if the name is already taken by another
    /// live connection.
    pub fn attach(&self, name: &str, connection_id: ConnectionId) -> AttachResult {
        self.attach_as(name, Origin::named(name), connection_id)
    }

    /// [`Registry::attach`] as `origin`, the node a proved key names
    /// ([`Origin::keyed`]) say. Names and nodes are each held by one attached
    /// connection at a time: `NameInUse` if another holds the name, and
    /// `NodeInUse` if another, under another name, is the same node.
    pub fn attach_as(
        &self,
        name: &str,
        origin: Origin,
        connection_id: ConnectionId,
    ) -> AttachResult {
        let mut g = self.inner.write();
        if g.by_name.contains_key(name) {
            return AttachResult::NameInUse;
        }
        let node = origin.node_id();
        if let Some(holder) = g.by_conn.values().find(|e| e.origin.node_id() == node) {
            return AttachResult::NodeInUse {
                holder: holder.name.clone(),
            };
        }
        let entry = AttachedEntry {
            name: name.to_string(),
            origin,
            connection_id,
            attached_at_unix_nanos: now_unix_nanos(),
        };
        g.by_name.insert(name.to_string(), entry.clone());
        g.by_conn.insert(connection_id, entry.clone());
        // Under the lock, so the tracking follows the names in their order.
        if let Some(health) = &self.health {
            health.attach(&entry.origin, connection_id);
        }
        drop(g);
        self.nodes_changed();
        AttachResult::Attached(entry)
    }

    /// Detach by connection id (drops both indexes, the node's liveness, and
    /// any watch the connection kept on it, telling the other watchers it
    /// detached). Returns the entry that was removed, if any.
    pub fn detach(&self, connection_id: ConnectionId) -> Option<AttachedEntry> {
        let mut g = self.inner.write();
        let entry = g.by_conn.remove(&connection_id);
        if let Some(entry) = &entry {
            g.by_name.remove(&entry.name);
        }
        if let Some(health) = &self.health {
            health.detach(connection_id, entry.as_ref().map(|e| &e.origin));
        }
        drop(g);
        if entry.is_some() {
            self.nodes_changed();
        }
        entry
    }

    /// Call `f` after every attach and detach from now on; a second watch is
    /// ignored. The links watch so, to announce the attached nodes.
    pub(crate) fn watch_nodes(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.nodes_changed.0.set(Box::new(f));
    }

    fn nodes_changed(&self) {
        if let Some(f) = self.nodes_changed.0.get() {
            f();
        }
    }

    /// The name each attached connection's sends carry across links
    /// ([`Origin::link_name`]), one for each connection.
    pub(crate) fn link_names(&self) -> Vec<String> {
        self.inner
            .read()
            .by_conn
            .values()
            .map(|e| e.origin.link_name().to_owned())
            .collect()
    }

    /// The attached connection whose node id is `canonical`
    /// ([`Origin::canonical`]), if any.
    pub(crate) fn find_canonical(&self, canonical: &str) -> Option<AttachedEntry> {
        self.inner
            .read()
            .by_conn
            .values()
            .find(|e| e.origin.canonical() == canonical)
            .cloned()
    }

    /// The attached connection whose sends carry `name` across links
    /// ([`Origin::link_name`]), if any. A connection attached by name may
    /// have taken a name that reads as a proven key's (`name@` and 32 hex
    /// digits); when one such and the connection that proved the key are
    /// both attached, the one that proved it is the one named.
    pub(crate) fn find_link_name(&self, name: &str) -> Option<AttachedEntry> {
        let g = self.inner.read();
        let mut named = g.by_conn.values().filter(|e| e.origin.link_name() == name);
        let first = named.next()?;
        let proved = |e: &&AttachedEntry| e.origin.canonical() == e.origin.link_name();
        if proved(&first) {
            return Some(first.clone());
        }
        Some(named.find(proved).unwrap_or(first).clone())
    }

    /// The attached connections' liveness, `None` when it is not tracked.
    pub(crate) fn health_tracker(&self) -> Option<&HealthTracker> {
        self.health.as_ref()
    }

    /// Count a frame or a pong from the connection attached as `origin` as
    /// its heartbeat.
    pub(crate) fn heard(&self, origin: &Origin) {
        if let Some(health) = &self.health {
            health.heard(origin.node_id());
        }
    }

    /// Record the state the `health` frame of the connection attached as
    /// `origin` reported: `degraded`, or anything else
    /// (`HealthTracker::reported`).
    pub(crate) fn reported_health(&self, origin: &Origin, state: Option<&str>) {
        if let Some(health) = &self.health {
            health.reported(origin.node_id(), state);
        }
    }

    /// Send the attached connections' changes of state to `connection_id`'s
    /// event queue `sink`, as its subscription `subscription` asked
    /// (`FilterSpec::health`), until that and every other subscription of
    /// the connection that asked is gone ([`Registry::unwatch_health`]) or the
    /// connection detaches.
    pub(crate) fn watch_health(
        &self,
        connection_id: ConnectionId,
        subscription: SubscriptionId,
        sink: &EventSink,
    ) {
        if let Some(health) = &self.health {
            health.watch(connection_id, subscription, sink);
        }
    }

    /// Forget `subscription` among those of `connection_id` that asked for
    /// changes of state; nothing for one that did not.
    pub(crate) fn unwatch_health(
        &self,
        connection_id: ConnectionId,
        subscription: &SubscriptionId,
    ) {
        if let Some(health) = &self.health {
            health.unwatch(connection_id, subscription);
        }
    }

    /// How often the liveness is ticked, or `None` when it is not tracked.
    pub(crate) fn health_period(&self) -> Option<Duration> {
        self.health.as_ref().map(HealthTracker::period)
    }

    /// One tick of the liveness: a miss for every attached connection not
    /// heard from since the last, and a notice of each change of state.
    pub(crate) fn tick_health(&self) {
        if let Some(health) = &self.health {
            health.tick();
        }
    }

    fn nodes_in(&self, state: NodeState) -> usize {
        self.health.as_ref().map_or(0, |health| health.count(state))
    }

    /// Attached connections in good health: heard from within about half the
    /// idle timeout. Every count of nodes is 0 when liveness is not tracked.
    pub fn nodes_healthy(&self) -> usize {
        self.nodes_in(NodeState::Healthy)
    }

    /// Attached connections silent for half the idle timeout or more, and
    /// not yet for the whole of it.
    pub fn nodes_warning(&self) -> usize {
        self.nodes_in(NodeState::Warning)
    }

    /// Attached connections silent for the whole idle timeout, which the
    /// connection loop closes as their state changes: rarely more than 0.
    pub fn nodes_isolated(&self) -> usize {
        self.nodes_in(NodeState::Isolated)
    }

    /// Attached connections whose drift is recorded; the daemon records none
    /// yet, so 0.
    pub fn nodes_degraded(&self) -> usize {
        self.nodes_in(NodeState::Degraded)
    }

    /// Health notices dropped since the registry was created, at a watcher's
    /// queue or at the daemon's queue budget.
    pub fn health_notices_dropped(&self) -> u64 {
        self.health
            .as_ref()
            .map_or(0, HealthTracker::notices_dropped)
    }

    /// Look up the entry for a connection.
    pub fn entry_for(&self, connection_id: ConnectionId) -> Option<AttachedEntry> {
        self.inner.read().by_conn.get(&connection_id).cloned()
    }

    /// Number of currently-attached connections.
    pub fn len(&self) -> usize {
        self.inner.read().by_conn.len()
    }

    /// True if no connections are attached.
    pub fn is_empty(&self) -> bool {
        self.inner.read().by_conn.is_empty()
    }
}

fn now_unix_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_the_name_and_the_first_four_bytes_of_its_node_id() {
        let origin = Origin::named("worker");
        assert_eq!(origin.node_id(), NodeId::from_name("worker"));
        let hex: String = NodeId::from_name("worker").as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(origin.canonical(), format!("worker@{hex}"));
    }

    #[test]
    fn a_keyed_origin_is_the_name_and_the_keys_node_id() {
        let key = attach::SigningKey::from_bytes(&[5; 32])
            .verifying_key()
            .to_bytes();
        let origin = Origin::keyed("worker", &key);
        assert_eq!(
            origin.node_id(),
            NodeId::from_bytes(attach::key_node_id(&key))
        );
        assert_eq!(origin.canonical(), attach::keyed_node_id("worker", &key));
        assert_ne!(origin.node_id(), Origin::named("worker").node_id());
        assert_eq!(
            Origin::keyed("other", &key).node_id(),
            origin.node_id(),
            "the node is the key's, whatever the name"
        );
    }

    #[test]
    fn one_key_is_one_attached_node_at_a_time() {
        let key = attach::SigningKey::from_bytes(&[6; 32])
            .verifying_key()
            .to_bytes();
        let reg = Registry::new();
        let (a, b) = (reg.next_connection_id(), reg.next_connection_id());
        assert!(matches!(
            reg.attach_as("a", Origin::keyed("a", &key), a),
            AttachResult::Attached(_)
        ));
        match reg.attach_as("b", Origin::keyed("b", &key), b) {
            AttachResult::NodeInUse { holder } => assert_eq!(holder, "a"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            reg.attach_as("a", Origin::named("a"), b),
            AttachResult::NameInUse
        ));
        reg.detach(a);
        assert!(matches!(
            reg.attach_as("b", Origin::keyed("b", &key), b),
            AttachResult::Attached(_)
        ));
    }

    #[test]
    fn attach_and_detach() {
        let reg = Registry::new();
        let c1 = reg.next_connection_id();
        match reg.attach("ingest", c1) {
            AttachResult::Attached(e) => assert_eq!(e.name, "ingest"),
            _ => panic!("expected attach"),
        }
        match reg.attach("ingest", reg.next_connection_id()) {
            AttachResult::NameInUse => {}
            _ => panic!("expected name-in-use"),
        }
        assert!(reg.detach(c1).is_some());
        assert!(reg.is_empty());
    }

    #[test]
    fn a_registry_for_a_policy_tracks_its_attached_nodes_unless_the_idle_timeout_is_zero() {
        let policy = ConnectionPolicy::default();
        let reg = Registry::for_policy(&policy);
        assert_eq!(reg.health_period(), Some(policy.idle_timeout / 10));
        let (a, b) = (reg.next_connection_id(), reg.next_connection_id());
        assert!(matches!(reg.attach("a", a), AttachResult::Attached(_)));
        assert!(matches!(reg.attach("b", b), AttachResult::Attached(_)));
        assert!(matches!(reg.attach("a", b), AttachResult::NameInUse));
        assert_eq!(reg.nodes_healthy(), 2);
        // Five misses after the tick the attach spared: Warning, unless heard.
        for _ in 0..6 {
            reg.heard(&Origin::named("b"));
            reg.tick_health();
        }
        assert_eq!((reg.nodes_healthy(), reg.nodes_warning()), (1, 1));
        reg.detach(a);
        assert_eq!((reg.nodes_healthy(), reg.nodes_warning()), (1, 0));
        // The name, taken again, is a fresh node.
        let c = reg.next_connection_id();
        assert!(matches!(reg.attach("a", c), AttachResult::Attached(_)));
        assert_eq!(reg.nodes_healthy(), 2);
        assert_eq!(reg.health_notices_dropped(), 0);

        let off = Registry::for_policy(&policy.with_idle_timeout(Duration::ZERO));
        assert_eq!(off.health_period(), None);
        assert!(matches!(off.attach("a", a), AttachResult::Attached(_)));
        assert_eq!(off.nodes_healthy(), 0, "nothing is tracked");
        assert_eq!(Registry::new().health_period(), None);
    }

    #[test]
    fn admission_holds_at_most_max_and_a_dropped_slot_frees_its_place() {
        let reg = Registry::new();
        let first = reg.admit(2).expect("first");
        let _second = reg.admit(2).expect("second");
        assert_eq!(reg.connections(), 2);
        assert_eq!(reg.admit(2).err(), Some(AtCapacity { refused: 1 }));
        assert_eq!(reg.admit(2).err(), Some(AtCapacity { refused: 2 }));
        assert_eq!(reg.connections(), 2, "a refusal takes no place");
        drop(first);
        assert_eq!(reg.connections(), 1);
        let _third = reg.admit(2).expect("the freed place");
        assert!(reg.admit(0).is_err(), "a cap of zero admits nothing");
        assert_eq!(reg.connections_refused(), 3);
    }
}
