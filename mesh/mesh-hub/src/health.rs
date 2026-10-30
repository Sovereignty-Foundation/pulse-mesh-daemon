// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The attached connections' liveness: a `mesh_health::HealthRegistry` the
//! daemon's registry keeps ([`HealthTracker`]), ticked by the task [`ticks`]
//! makes, and the `health` notices it sends the connections that asked for
//! them.
//!
//! Every attached connection is a node. Names are unique among the attached
//! connections, so the node id an attach name gives names one connection while
//! it is attached; it is registered at the attach, which counts as a heartbeat
//! as every inbound frame and pong after it does, and unregistered at the
//! detach, explicit or at the connection's end.
//!
//! The cadence comes from the connection policy's idle timeout, so the states
//! line up with what the connection loop enforces: a tick every tenth of it
//! ([`TICKS_PER_IDLE_TIMEOUT`]), a node `Warning` after [`WARN_AFTER`] ticks
//! without a frame, half the timeout, and `Isolated` after [`ISOLATE_AFTER`].
//! A heartbeat spares the tick after it, so a node silent since its last frame
//! turns `Warning` between five and six tenths of the timeout after that frame
//! (45 to 54 seconds at the default 90, past the Rust client's 30-second idle
//! heartbeat, so a healthy idle client never shows it), and `Isolated` between
//! eight and nine tenths, at least a tick before the idle timeout closes the
//! connection; a watcher then sees `isolated` and, at the close, `detached`.
//! `Isolated` is the daemon's notice that it is about to drop the node.
//! `Restarting` is never entered, since its
//! threshold is the isolation's and isolation is checked first; the daemon
//! cannot restart a client. A client reports itself `Degraded` with a
//! `health` frame whose state is `degraded`, and stays so, whatever else it
//! sends, until a `health` frame reports any other state (or none), which
//! makes it `Healthy`; misses that reach `Warning` or `Isolated` still give
//! their own state. An idle timeout of zero turns tracking off: nothing is
//! registered and nothing ticks.
//!
//! A connection holding at least one subscription whose filter sets `health`
//! is a watcher. As it becomes one, it is told the state of every other
//! attached node that is not `Healthy`, so it starts from what the daemon
//! knows. Each change of a node's state, and each detach, goes to every
//! watcher but the node's own connection, once per connection however many of
//! its subscriptions asked, as `{"op":"health","node_id":"<name@suffix>",
//! "state":"<state>","since_unix_nanos":<now>}`, the state `healthy`,
//! `warning`, `isolated`, `degraded` or `detached`. A notice goes through the
//! watcher's event queue, under the bounds and the daemon-wide budget its
//! events are held to (`queue`); one dropped there is counted in
//! [`HealthTracker::notices_dropped`] and logged at the first drop and at each
//! doubling. Notices are made and offered under the tracker's lock, so a
//! watcher receives a node's notices in the order its states changed, and none
//! after its `detached`.
//!
//! # Nodes of linked daemons
//!
//! With links to other daemons (`crate::link`), the tracker also holds what
//! the peers report of their own nodes, and tells the watchers here of it in
//! the same notices, the node named by its qualified id (`name@` and its
//! daemon's 16 hex digits). Each change of a peer's node's state that the
//! peer reports ([`HealthTracker::remote`]) is a notice to every watcher,
//! once: a report of the state already held for the node is none, and a
//! node no report has named counts as `healthy`. The tracker keeps each
//! remote node that is not `healthy` with its state, and a connection that
//! becomes a watcher is told those too in its first notices, after the
//! attached nodes. A node its daemon no longer announces, and every node of
//! a daemon whose link goes down or starts afresh, is reported `detached`
//! ([`HealthTracker::remote_gone`]) and forgotten. While no subscription
//! here watches health, the links stop taking reports and the tracker
//! forgets what it held ([`HealthTracker::clear_remote`]), since the peers
//! stop sending them; the next watcher learns the peers' nodes that are not
//! healthy a moment after it subscribes, as notices, once its summary
//! reaches them.
//!
//! Each change of an attached node's state here (not its detach, which the
//! links' announcement carries) is also handed to the links, under the
//! tracker's lock and so in order ([`HealthTracker::watch_local`]), and they
//! report it to the peers that watch health.

use crate::hub_bridge::SubscriptionId;
use crate::queue::{EventSink, Offer};
use crate::registry::{ConnectionId, Origin, Registry};
use mesh_health::{HealthRegistry, HeartbeatConfig, NodeState};
use mesh_link::{DaemonId, HealthState, QualifiedOrigin};
use parking_lot::Mutex;
use pulse_canon::NodeId;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

/// Ticks in one idle timeout: a node silent for the whole of it has missed
/// this many, the threshold of `Isolated`.
pub(crate) const TICKS_PER_IDLE_TIMEOUT: u32 = 10;

/// Ticks missed before a node is `Warning`: half the idle timeout.
pub(crate) const WARN_AFTER: u32 = 5;

/// Ticks missed before a node is `Isolated`: eight, so that with the tick a
/// heartbeat spares it lands at most nine tenths of the idle timeout after the
/// node's last frame, a tick before the timeout closes the connection.
pub(crate) const ISOLATE_AFTER: u32 = 8;

/// The shortest tick, for an idle timeout under ten milliseconds: the timer
/// is no finer.
const MIN_PERIOD: Duration = Duration::from_millis(1);

/// The state a detached node is reported in.
pub(crate) const DETACHED: &str = "detached";

/// The `health` frame state by which a client reports itself degraded.
pub(crate) const DEGRADED: &str = "degraded";

/// The opening of every health notice: `{"op":"health",`.
const NOTICE_HEAD: &str = r#"{"op":"health","#;

/// The wire name of a state.
pub(crate) fn state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Healthy => "healthy",
        NodeState::Warning => "warning",
        NodeState::Restarting => "restarting",
        NodeState::Isolated => "isolated",
        NodeState::Degraded => "degraded",
    }
}

/// A notice's fields after its `op`, in `ServerMessage::Health`'s order, so
/// that [`NOTICE_HEAD`] and the body are that message's JSON.
#[derive(Serialize)]
struct NoticeFields<'a> {
    node_id: &'a str,
    state: &'a str,
    since_unix_nanos: u64,
}

impl NoticeFields<'_> {
    /// The notice after its `op`, closing brace included; `None` only if
    /// serialising failed, which it cannot here.
    fn body(&self) -> Option<Arc<str>> {
        let json = serde_json::to_string(self).ok()?;
        json.strip_prefix('{').map(Arc::from)
    }
}

/// The liveness of a daemon's attached connections, and the connections
/// watching it; see the module documentation.
pub(crate) struct HealthTracker {
    /// How often [`Self::tick`] is to run.
    period: Duration,
    tracked: Mutex<Tracked>,
    /// [`NOTICE_HEAD`], shared by every notice.
    head: Arc<str>,
    /// Notices dropped at a watcher's queue or the daemon's budget, refused
    /// or given up later.
    dropped: Arc<AtomicU64>,
    /// Notices about peers' nodes queued for watchers, one for each watcher.
    remote_notices: AtomicU64,
    /// Called under the lock with each change of an attached node's state,
    /// once the links watch them ([`Self::watch_local`]).
    on_local: OnceLock<LocalHook>,
}

/// What [`HealthTracker::watch_local`] is given: called with a node's name
/// across links ([`Origin::link_name`]) and its new state.
type LocalHook = Box<dyn Fn(&str, NodeState) + Send + Sync>;

impl fmt::Debug for HealthTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthTracker")
            .field("period", &self.period)
            .field("notices_dropped", &self.notices_dropped())
            .finish_non_exhaustive()
    }
}

/// What the tracker's lock guards.
struct Tracked {
    nodes: HealthRegistry,
    /// Ticks so far, the heartbeats' tick.
    ticks: u64,
    /// The connection and the canonical name of each node registered.
    attached: HashMap<NodeId, Attached>,
    /// The connections that asked for notices.
    watchers: HashMap<ConnectionId, Watcher>,
    /// The nodes whose last `health` frame said `degraded`; each stays
    /// `Degraded` (unless its misses give a worse state) until a `health`
    /// frame says anything else, however many other frames it sends.
    degraded: HashSet<NodeId>,
    /// The peers' nodes their daemons last reported in a state other than
    /// `healthy`, with that state.
    remote: BTreeMap<QualifiedOrigin, HealthState>,
}

/// A registered node's connection, its `name@suffix` and its name across
/// links.
struct Attached {
    connection_id: ConnectionId,
    canonical: Box<str>,
    link_name: Box<str>,
}

/// A connection that asked for notices: its event queue, and the
/// subscriptions whose filters set `health`.
struct Watcher {
    sink: EventSink,
    subscriptions: HashSet<SubscriptionId>,
}

/// A change to log once the tracker's lock is released.
struct Change {
    canonical: Box<str>,
    state: NodeState,
}

impl HealthTracker {
    /// Tracking for connections served under `idle_timeout`, ticking every
    /// tenth of it; `None` when it is zero, which turns tracking off.
    pub(crate) fn for_idle_timeout(idle_timeout: Duration) -> Option<Self> {
        if idle_timeout.is_zero() {
            return None;
        }
        let period = (idle_timeout / TICKS_PER_IDLE_TIMEOUT).max(MIN_PERIOD);
        let config = HeartbeatConfig::default()
            .with_interval_ms(u64::try_from(period.as_millis()).unwrap_or(u64::MAX))
            .with_warn_after(WARN_AFTER)
            .with_isolate_after(ISOLATE_AFTER)
            .with_restart_after(ISOLATE_AFTER);
        Some(Self {
            period,
            tracked: Mutex::new(Tracked {
                nodes: HealthRegistry::new(config),
                ticks: 0,
                attached: HashMap::new(),
                watchers: HashMap::new(),
                degraded: HashSet::new(),
                remote: BTreeMap::new(),
            }),
            head: Arc::from(NOTICE_HEAD),
            dropped: Arc::new(AtomicU64::new(0)),
            remote_notices: AtomicU64::new(0),
            on_local: OnceLock::new(),
        })
    }

    /// How often [`Self::tick`] is to run.
    pub(crate) fn period(&self) -> Duration {
        self.period
    }

    /// Register the node `origin` names for the connection that attached as
    /// it, `Healthy`, its attach counted as a heartbeat. The registry calls
    /// this under its own lock, so a name released and taken again is
    /// registered for the connection that holds it.
    pub(crate) fn attach(&self, origin: &Origin, connection_id: ConnectionId) {
        let node = origin.node_id();
        let mut tracked = self.tracked.lock();
        let tick = tracked.ticks;
        // A fresh record, whatever was left under the id.
        tracked.nodes.unregister(&node);
        tracked.nodes.register(node);
        tracked.nodes.heartbeat(&node, tick);
        tracked.attached.insert(
            node,
            Attached {
                connection_id,
                canonical: origin.canonical().into(),
                link_name: origin.link_name().into(),
            },
        );
    }

    /// Forget `connection_id` as a watcher and, when it was attached as
    /// `origin`, as a node, telling every other watcher it detached. The
    /// registry calls this under its own lock, as [`Self::attach`].
    pub(crate) fn detach(&self, connection_id: ConnectionId, origin: Option<&Origin>) {
        let mut tracked = self.tracked.lock();
        tracked.watchers.remove(&connection_id);
        let Some(origin) = origin else { return };
        let node = origin.node_id();
        if tracked
            .attached
            .get(&node)
            .is_none_or(|a| a.connection_id != connection_id)
        {
            return;
        }
        tracked.attached.remove(&node);
        tracked.nodes.unregister(&node);
        tracked.degraded.remove(&node);
        self.offer(
            &mut tracked.watchers,
            Some(connection_id),
            origin.canonical(),
            DETACHED,
            now_unix_nanos(),
        );
    }

    /// Count a frame or a pong from `node` as a heartbeat; a node that was
    /// not `Healthy` is again, and the watchers are told.
    pub(crate) fn heard(&self, node: NodeId) {
        let change = {
            let mut tracked = self.tracked.lock();
            let tracked = &mut *tracked;
            let tick = tracked.ticks;
            let Some(health) = tracked.nodes.get_mut(&node) else {
                return;
            };
            let before = health.state();
            health.record_heartbeat(tick);
            // A heartbeat clears drift; a node that reported itself degraded
            // stays so until it reports otherwise (`Self::reported`).
            if tracked.degraded.contains(&node) {
                health.record_drift();
            }
            let after = health.state();
            if after == before {
                return;
            }
            let Some(attached) = tracked.attached.get(&node) else {
                return;
            };
            self.offer(
                &mut tracked.watchers,
                Some(attached.connection_id),
                &attached.canonical,
                state_name(after),
                now_unix_nanos(),
            );
            self.local_changed(attached, after);
            Change {
                canonical: attached.canonical.clone(),
                state: after,
            }
        };
        log(&change);
    }

    /// Record the state a node's `health` frame reported: `degraded` makes it
    /// `Degraded` until a later `health` frame reports anything else, which
    /// makes it `Healthy` again; the watchers are told of either change. The
    /// frame's arrival has already counted as the node's heartbeat
    /// ([`Self::heard`]).
    pub(crate) fn reported(&self, node: NodeId, state: Option<&str>) {
        let degraded = state == Some(DEGRADED);
        let change = {
            let mut tracked = self.tracked.lock();
            let tracked = &mut *tracked;
            let changed_report = if degraded {
                tracked.degraded.insert(node)
            } else {
                tracked.degraded.remove(&node)
            };
            if !changed_report {
                return;
            }
            let tick = tracked.ticks;
            let Some(health) = tracked.nodes.get_mut(&node) else {
                return;
            };
            let before = health.state();
            if degraded {
                health.record_drift();
            } else {
                health.record_heartbeat(tick);
            }
            let after = health.state();
            if after == before {
                return;
            }
            let Some(attached) = tracked.attached.get(&node) else {
                return;
            };
            self.offer(
                &mut tracked.watchers,
                Some(attached.connection_id),
                &attached.canonical,
                state_name(after),
                now_unix_nanos(),
            );
            self.local_changed(attached, after);
            Change {
                canonical: attached.canonical.clone(),
                state: after,
            }
        };
        log(&change);
    }

    /// Count a miss for every node not heard since the last tick, and tell
    /// the watchers of each state that changed.
    pub(crate) fn tick(&self) {
        let changes = {
            let mut tracked = self.tracked.lock();
            let tracked = &mut *tracked;
            tracked.ticks = tracked.ticks.wrapping_add(1);
            let transitions = tracked.nodes.tick();
            if transitions.is_empty() {
                return;
            }
            let since = now_unix_nanos();
            let mut changes = Vec::with_capacity(transitions.len());
            for (node, state) in transitions {
                let Some(attached) = tracked.attached.get(&node) else {
                    continue;
                };
                self.offer(
                    &mut tracked.watchers,
                    Some(attached.connection_id),
                    &attached.canonical,
                    state_name(state),
                    since,
                );
                self.local_changed(attached, state);
                changes.push(Change {
                    canonical: attached.canonical.clone(),
                    state,
                });
            }
            changes
        };
        for change in &changes {
            log(change);
        }
    }

    /// Send `connection_id`'s notices to the queue `sink`, for its
    /// subscription `subscription`, whose filter set `health`.
    ///
    /// A connection that becomes a watcher is first told the state of every
    /// other attached node that is not `Healthy`, one notice each, then of
    /// every peer's node held in a state other than `healthy` (the module's
    /// documentation says which), so it starts from what the daemon knows
    /// rather than from the next change; a node absent from that snapshot is
    /// healthy, or not attached, as far as the daemon knows.
    pub(crate) fn watch(
        &self,
        connection_id: ConnectionId,
        subscription: SubscriptionId,
        sink: &EventSink,
    ) {
        let mut tracked = self.tracked.lock();
        let tracked = &mut *tracked;
        if let Some(watcher) = tracked.watchers.get_mut(&connection_id) {
            watcher.subscriptions.insert(subscription);
            return;
        }
        let since = now_unix_nanos();
        for (node, attached) in &tracked.attached {
            if attached.connection_id == connection_id {
                continue;
            }
            let Some(state) = tracked.nodes.get(node).map(|h| h.state()) else {
                continue;
            };
            if state == NodeState::Healthy {
                continue;
            }
            let fields = NoticeFields {
                node_id: &attached.canonical,
                state: state_name(state),
                since_unix_nanos: since,
            };
            if let Some(body) = fields.body() {
                if let Offer::Dropped = sink.offer(&self.head, &body, &self.dropped) {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        for (node, state) in &tracked.remote {
            let node_id = node.to_string();
            let fields = NoticeFields {
                node_id: &node_id,
                state: state.as_str(),
                since_unix_nanos: since,
            };
            if let Some(body) = fields.body() {
                match sink.offer(&self.head, &body, &self.dropped) {
                    Offer::Queued => {
                        self.remote_notices.fetch_add(1, Ordering::Relaxed);
                    }
                    Offer::Dropped => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Offer::Closed => {}
                }
            }
        }
        tracked.watchers.insert(
            connection_id,
            Watcher {
                sink: sink.clone(),
                subscriptions: HashSet::from([subscription]),
            },
        );
    }

    /// Stop counting `subscription` among `connection_id`'s; with its last,
    /// the connection is no longer sent notices. Nothing for a subscription
    /// that did not ask for them.
    pub(crate) fn unwatch(&self, connection_id: ConnectionId, subscription: &SubscriptionId) {
        let mut tracked = self.tracked.lock();
        if let Some(watcher) = tracked.watchers.get_mut(&connection_id) {
            watcher.subscriptions.remove(subscription);
            if watcher.subscriptions.is_empty() {
                tracked.watchers.remove(&connection_id);
            }
        }
    }

    /// How many registered nodes are in `state` now.
    pub(crate) fn count(&self, state: NodeState) -> usize {
        let tracked = self.tracked.lock();
        tracked
            .attached
            .keys()
            .filter_map(|node| tracked.nodes.get(node))
            .filter(|health| health.state() == state)
            .count()
    }

    /// Notices dropped since the daemon started, at a watcher's queue or at
    /// the daemon's budget.
    pub(crate) fn notices_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Notices about peers' nodes queued for watchers since the daemon
    /// started, one for each watcher.
    pub(crate) fn remote_notices(&self) -> u64 {
        self.remote_notices.load(Ordering::Relaxed)
    }

    /// Call `f`, under the tracker's lock, with each change of an attached
    /// node's state from now on: its name across links and its new state. A
    /// detach is not one. A second watch is ignored.
    pub(crate) fn watch_local(&self, f: impl Fn(&str, NodeState) + Send + Sync + 'static) {
        let _ = self.on_local.set(Box::new(f));
    }

    fn local_changed(&self, attached: &Attached, state: NodeState) {
        if let Some(f) = self.on_local.get() {
            f(&attached.link_name, state);
        }
    }

    /// Call `f`, under the tracker's lock, with every attached node that is
    /// not `Healthy`: its name across links and its state. Under the lock, a
    /// change of state that `watch_local` hands on comes after these.
    pub(crate) fn with_unhealthy(&self, mut f: impl FnMut(&str, NodeState)) {
        let tracked = self.tracked.lock();
        for (node, attached) in &tracked.attached {
            let Some(state) = tracked.nodes.get(node).map(|h| h.state()) else {
                continue;
            };
            if state != NodeState::Healthy {
                f(&attached.link_name, state);
            }
        }
    }

    /// A peer reports its node `node` in `state`: when that is not the state
    /// held for it (`healthy` when none is), every watcher is told, and the
    /// state is held for the snapshot unless it is `healthy` or `detached`.
    pub(crate) fn remote(&self, node: &QualifiedOrigin, state: HealthState) {
        let mut tracked = self.tracked.lock();
        let tracked = &mut *tracked;
        let held = tracked
            .remote
            .get(node)
            .copied()
            .unwrap_or(HealthState::Healthy);
        if held == state {
            return;
        }
        match state {
            HealthState::Healthy | HealthState::Detached => {
                tracked.remote.remove(node);
            }
            _ => {
                tracked.remote.insert(node.clone(), state);
            }
        }
        let queued = self.offer(
            &mut tracked.watchers,
            None,
            &node.to_string(),
            state.as_str(),
            now_unix_nanos(),
        );
        self.remote_notices
            .fetch_add(u64::try_from(queued).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// The peers' nodes `nodes` are gone, as is every node held of the
    /// daemon `daemon`, when given: every watcher is told each is
    /// `detached`, once, and the tracker forgets them.
    pub(crate) fn remote_gone(
        &self,
        daemon: Option<DaemonId>,
        nodes: impl IntoIterator<Item = QualifiedOrigin>,
    ) {
        let mut tracked = self.tracked.lock();
        let tracked = &mut *tracked;
        let mut gone: BTreeSet<QualifiedOrigin> = nodes.into_iter().collect();
        if let Some(daemon) = daemon {
            gone.extend(
                tracked
                    .remote
                    .keys()
                    .filter(|node| node.daemon() == daemon)
                    .cloned(),
            );
        }
        if gone.is_empty() {
            return;
        }
        let since = now_unix_nanos();
        let mut queued = 0;
        for node in &gone {
            tracked.remote.remove(node);
            queued += self.offer(
                &mut tracked.watchers,
                None,
                &node.to_string(),
                DETACHED,
                since,
            );
        }
        self.remote_notices
            .fetch_add(u64::try_from(queued).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Forget the states held of the nodes of the daemon `daemon` and of
    /// the nodes `via`, which it relays, telling no one: the summary this
    /// daemon last sent it does not watch health, so it reports none of
    /// them.
    pub(crate) fn forget_remote(&self, daemon: DaemonId, via: &BTreeSet<QualifiedOrigin>) {
        self.tracked
            .lock()
            .remote
            .retain(|node, _| node.daemon() != daemon && !via.contains(node));
    }

    /// Call `f`, under the tracker's lock, with every peer's node held that
    /// is not healthy, and its state.
    pub(crate) fn with_remote_unhealthy(&self, mut f: impl FnMut(&QualifiedOrigin, HealthState)) {
        for (node, &state) in &self.tracked.lock().remote {
            f(node, state);
        }
    }

    /// Offer one notice about a node to every watcher but the connection
    /// `about`, the node's own when it is attached here, forgetting a
    /// watcher whose connection has gone; how many watchers queued it.
    fn offer(
        &self,
        watchers: &mut HashMap<ConnectionId, Watcher>,
        about: Option<ConnectionId>,
        canonical: &str,
        state: &str,
        since_unix_nanos: u64,
    ) -> usize {
        if watchers.keys().all(|&id| Some(id) == about) {
            return 0;
        }
        let fields = NoticeFields {
            node_id: canonical,
            state,
            since_unix_nanos,
        };
        let Some(body) = fields.body() else {
            tracing::error!(
                node = %canonical,
                state,
                "a health notice could not be encoded; it was not sent"
            );
            return 0;
        };
        let mut queued = 0;
        watchers.retain(|&id, watcher| {
            if Some(id) == about {
                return true;
            }
            match watcher.sink.offer(&self.head, &body, &self.dropped) {
                Offer::Queued => {
                    queued += 1;
                    true
                }
                Offer::Dropped => {
                    // Logged at the first drop and at each doubling.
                    let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_power_of_two() {
                        warn!(
                            conn = %id,
                            dropped = n,
                            "health notice dropped: the watcher's queue, or the daemon's budget, is full"
                        );
                    }
                    true
                }
                Offer::Closed => false,
            }
        });
        queued
    }
}

/// Log a node's change of state: a return to `Healthy` at info, any other
/// at warn.
fn log(change: &Change) {
    let state = state_name(change.state);
    if change.state == NodeState::Healthy {
        info!(node = %change.canonical, state, "node heard from again");
    } else {
        warn!(node = %change.canonical, state, "node health changed");
    }
}

/// The task that ticks `registry`'s liveness every period, to be spawned on
/// the runtime serving it, or `None` when the registry tracks none. It ends
/// only when dropped, or at once for a period too long for the clock, which
/// would never tick, as the connection loop's timers then never fire.
pub(crate) fn ticks(registry: &Arc<Registry>) -> Option<impl Future<Output = ()> + Send + 'static> {
    let period = registry.health_period()?;
    let registry = Arc::clone(registry);
    Some(async move {
        let Some(first) = tokio::time::Instant::now().checked_add(period) else {
            return;
        };
        let mut every = tokio::time::interval_at(first, period);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            registry.tick_health();
        }
    })
}

fn now_unix_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::protocol::ServerMessage;
    use crate::queue::{event_queue, EventQueue, QueueTotal};

    /// A queue of eight events on a daemon-wide total of its own.
    fn queue() -> (EventSink, EventQueue) {
        event_queue(8, usize::MAX, Arc::new(QueueTotal::default()), usize::MAX)
    }

    /// The notices waiting in `queue`, parsed.
    fn notices(queue: &mut EventQueue) -> Vec<ServerMessage> {
        std::iter::from_fn(|| queue.try_recv())
            .map(|n| serde_json::from_str(&format!("{}{}", n.head(), n.body())).unwrap())
            .collect()
    }

    /// The states of the notices about `canonical` in `notices`.
    fn states(notices: &[ServerMessage], canonical: &str) -> Vec<String> {
        notices
            .iter()
            .filter_map(|n| match n {
                ServerMessage::Health { node_id, state, .. } if node_id == canonical => {
                    Some(state.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn tracker() -> HealthTracker {
        HealthTracker::for_idle_timeout(Duration::from_secs(90)).unwrap()
    }

    #[test]
    fn the_cadence_is_a_tenth_of_the_idle_timeout_and_zero_turns_tracking_off() {
        assert!(HealthTracker::for_idle_timeout(Duration::ZERO).is_none());
        assert_eq!(tracker().period(), Duration::from_secs(9));
        let short = HealthTracker::for_idle_timeout(Duration::from_nanos(5)).unwrap();
        assert_eq!(short.period(), MIN_PERIOD, "never a zero period");
    }

    #[test]
    fn head_and_body_are_the_protocols_health_message() {
        let fields = NoticeFields {
            node_id: "a \"quoted\" name@3f9a0b1c",
            state: "warning",
            since_unix_nanos: 1_758_700_000_000_000_000,
        };
        let json = format!("{NOTICE_HEAD}{}", fields.body().unwrap());
        let message = ServerMessage::Health {
            node_id: "a \"quoted\" name@3f9a0b1c".into(),
            state: "warning".into(),
            since_unix_nanos: 1_758_700_000_000_000_000,
        };
        assert_eq!(json, serde_json::to_string(&message).unwrap());
    }

    #[test]
    fn a_silent_node_turns_warning_then_isolated_and_a_frame_makes_it_healthy() {
        let health = tracker();
        let (sink, mut queue) = queue();
        let (node, watcher) = (Origin::named("quiet"), ConnectionId(2));
        health.attach(&node, ConnectionId(1));
        health.watch(watcher, SubscriptionId("s".into()), &sink);
        // The attach spares the first tick; five misses after it, Warning.
        for _ in 0..6 {
            health.tick();
        }
        assert_eq!(health.count(NodeState::Warning), 1);
        for _ in 0..2 {
            health.tick();
        }
        assert_eq!(health.count(NodeState::Warning), 1, "seven misses");
        health.tick();
        assert_eq!(health.count(NodeState::Isolated), 1);
        assert_eq!(health.count(NodeState::Restarting), 0, "never entered");
        health.heard(node.node_id());
        health.heard(node.node_id());
        assert_eq!(health.count(NodeState::Healthy), 1);
        let got = notices(&mut queue);
        assert_eq!(
            states(&got, node.canonical()),
            ["warning", "isolated", "healthy"],
            "each change once"
        );
        assert!(matches!(
            &got[0],
            ServerMessage::Health { since_unix_nanos, .. } if *since_unix_nanos > 0
        ));
    }

    #[test]
    fn a_node_that_reports_degraded_stays_so_until_it_reports_otherwise() {
        let health = tracker();
        let (sink, mut queue) = queue();
        let node = Origin::named("busy");
        health.attach(&node, ConnectionId(1));
        health.watch(ConnectionId(2), SubscriptionId("s".into()), &sink);
        // The frame that reports it is a heartbeat first, as every frame is.
        health.heard(node.node_id());
        health.reported(node.node_id(), Some(DEGRADED));
        assert_eq!(health.count(NodeState::Degraded), 1);
        // Other frames keep it degraded, and so does a second report.
        for _ in 0..3 {
            health.heard(node.node_id());
            health.tick();
        }
        health.reported(node.node_id(), Some(DEGRADED));
        assert_eq!(health.count(NodeState::Degraded), 1);
        // Any other state, or none, makes it healthy again.
        health.heard(node.node_id());
        health.reported(node.node_id(), Some("ok"));
        assert_eq!(health.count(NodeState::Healthy), 1);
        health.reported(node.node_id(), None);
        assert_eq!(
            states(&notices(&mut queue), node.canonical()),
            ["degraded", "healthy"],
            "each change once"
        );
    }

    #[test]
    fn a_new_watcher_is_told_every_other_node_that_is_not_healthy() {
        let health = tracker();
        let (quiet, busy, fine, watcher) = (
            Origin::named("quiet"),
            Origin::named("busy"),
            Origin::named("fine"),
            Origin::named("watcher"),
        );
        health.attach(&quiet, ConnectionId(1));
        health.attach(&busy, ConnectionId(2));
        health.attach(&fine, ConnectionId(3));
        health.attach(&watcher, ConnectionId(4));
        health.reported(busy.node_id(), Some(DEGRADED));
        // Quiet misses enough ticks to be Warning; the others keep speaking.
        for _ in 0..6 {
            for heard in [&busy, &fine, &watcher] {
                health.heard(heard.node_id());
            }
            health.tick();
        }
        assert_eq!(health.count(NodeState::Warning), 1);
        let (sink, mut queue) = queue();
        health.watch(ConnectionId(4), SubscriptionId("s".into()), &sink);
        let got = notices(&mut queue);
        assert_eq!(states(&got, quiet.canonical()), ["warning"]);
        assert_eq!(states(&got, busy.canonical()), ["degraded"]);
        assert!(
            states(&got, fine.canonical()).is_empty(),
            "healthy nodes are not listed"
        );
        assert_eq!(got.len(), 2, "{got:?}");
        // A second subscription of the same connection asks for no snapshot.
        health.watch(ConnectionId(4), SubscriptionId("s2".into()), &sink);
        assert!(notices(&mut queue).is_empty());
    }

    #[test]
    fn a_node_heard_before_every_tick_produces_no_notice() {
        let health = tracker();
        let (sink, mut queue) = queue();
        let node = Origin::named("chatty");
        health.attach(&node, ConnectionId(1));
        health.watch(ConnectionId(2), SubscriptionId("s".into()), &sink);
        for _ in 0..30 {
            health.heard(node.node_id());
            health.tick();
        }
        assert!(notices(&mut queue).is_empty());
        assert_eq!(health.count(NodeState::Healthy), 1);
    }

    #[test]
    fn a_watcher_gets_one_notice_per_change_however_many_subscriptions_asked() {
        let health = tracker();
        let (sink, mut queue) = queue();
        let (node, watcher) = (Origin::named("leaving"), ConnectionId(2));
        health.attach(&node, ConnectionId(1));
        for sub in ["a", "b", "c"] {
            health.watch(watcher, SubscriptionId(sub.into()), &sink);
        }
        health.detach(ConnectionId(1), Some(&node));
        assert_eq!(states(&notices(&mut queue), node.canonical()), [DETACHED]);
        assert_eq!(health.count(NodeState::Healthy), 0, "unregistered");
        // Its last subscription that asked is what stops the notices.
        let other = Origin::named("other");
        health.attach(&other, ConnectionId(3));
        health.unwatch(watcher, &SubscriptionId("a".into()));
        health.unwatch(watcher, &SubscriptionId("b".into()));
        health.unwatch(watcher, &SubscriptionId("never-asked".into()));
        health.detach(ConnectionId(3), Some(&other));
        assert_eq!(states(&notices(&mut queue), other.canonical()), [DETACHED]);
        health.unwatch(watcher, &SubscriptionId("c".into()));
        let third = Origin::named("third");
        health.attach(&third, ConnectionId(4));
        health.detach(ConnectionId(4), Some(&third));
        assert!(notices(&mut queue).is_empty());
    }

    #[test]
    fn a_node_is_not_told_its_own_state_and_a_watchers_detach_ends_its_notices() {
        let health = tracker();
        let (own_sink, mut own_queue) = queue();
        let (other_sink, mut other_queue) = queue();
        let (a, b) = (Origin::named("a"), Origin::named("b"));
        health.attach(&a, ConnectionId(1));
        health.attach(&b, ConnectionId(2));
        health.watch(ConnectionId(1), SubscriptionId("s1".into()), &own_sink);
        health.watch(ConnectionId(2), SubscriptionId("s2".into()), &other_sink);
        health.detach(ConnectionId(1), Some(&a));
        assert!(notices(&mut own_queue).is_empty(), "not its own");
        assert_eq!(
            states(&notices(&mut other_queue), a.canonical()),
            [DETACHED]
        );
        // A's watcher went with its detach.
        health.detach(ConnectionId(2), Some(&b));
        assert!(notices(&mut own_queue).is_empty());
    }

    #[test]
    fn a_detach_by_a_connection_that_no_longer_holds_the_name_leaves_the_holder() {
        let health = tracker();
        let (sink, mut queue) = queue();
        let name = Origin::named("reused");
        health.watch(ConnectionId(9), SubscriptionId("s".into()), &sink);
        health.attach(&name, ConnectionId(1));
        health.attach(&name, ConnectionId(2));
        health.detach(ConnectionId(1), Some(&name));
        assert!(notices(&mut queue).is_empty());
        assert_eq!(health.count(NodeState::Healthy), 1, "the holder stays");
        health.detach(ConnectionId(2), Some(&name));
        assert_eq!(states(&notices(&mut queue), name.canonical()), [DETACHED]);
    }

    fn remote(name: &str) -> QualifiedOrigin {
        QualifiedOrigin::new(DaemonId::from_bytes([7; 8]), name).unwrap()
    }

    #[test]
    fn a_peers_report_is_one_notice_per_change_and_a_new_watcher_is_told_the_unhealthy() {
        let health = tracker();
        let (sink, mut watched) = queue();
        health.watch(ConnectionId(1), SubscriptionId("s".into()), &sink);
        let (far, fine) = (remote("far"), remote("fine"));
        let far_text = far.to_string();
        assert_eq!(far_text, "far@0707070707070707");
        health.remote(&far, HealthState::Warning);
        health.remote(&far, HealthState::Warning);
        health.remote(&fine, HealthState::Healthy);
        health.remote(&far, HealthState::Degraded);
        assert_eq!(
            states(&notices(&mut watched), &far_text),
            ["warning", "degraded"],
            "a repeat, and a healthy node reported healthy, are no change"
        );
        assert_eq!(health.remote_notices(), 2);
        assert_eq!(
            health.count(NodeState::Degraded),
            0,
            "the counts are of nodes here"
        );
        // A new watcher's first notices name the peer's unhealthy node.
        let (late, mut late_queue) = queue();
        health.watch(ConnectionId(2), SubscriptionId("t".into()), &late);
        assert_eq!(states(&notices(&mut late_queue), &far_text), ["degraded"]);
        assert_eq!(health.remote_notices(), 3);
        // Healthy again: both are told, and it is no longer listed.
        health.remote(&far, HealthState::Healthy);
        assert_eq!(states(&notices(&mut watched), &far_text), ["healthy"]);
        assert_eq!(states(&notices(&mut late_queue), &far_text), ["healthy"]);
        let (third, mut third_queue) = queue();
        health.watch(ConnectionId(3), SubscriptionId("u".into()), &third);
        assert!(notices(&mut third_queue).is_empty());
    }

    #[test]
    fn a_peers_nodes_gone_are_detached_once_and_forgotten_ones_silently() {
        let health = tracker();
        let (sink, mut watched) = queue();
        health.watch(ConnectionId(1), SubscriptionId("s".into()), &sink);
        let (a, b, other) = (
            remote("a"),
            remote("b"),
            QualifiedOrigin::new(DaemonId::from_bytes([9; 8]), "c").unwrap(),
        );
        health.remote(&b, HealthState::Isolated);
        health.remote(&other, HealthState::Warning);
        let _ = notices(&mut watched);
        // The announced `a`, and with the daemon given, the held `b`.
        health.remote_gone(Some(a.daemon()), [a.clone()]);
        let got = notices(&mut watched);
        assert_eq!(states(&got, &a.to_string()), [DETACHED]);
        assert_eq!(states(&got, &b.to_string()), [DETACHED]);
        assert!(
            states(&got, &other.to_string()).is_empty(),
            "another daemon's"
        );
        health.remote_gone(Some(a.daemon()), []);
        assert!(notices(&mut watched).is_empty(), "once");
        // Forgotten, of another daemon and of one it relays: nobody told.
        let relayed = QualifiedOrigin::new(DaemonId::from_bytes([5; 8]), "r").unwrap();
        let kept = QualifiedOrigin::new(DaemonId::from_bytes([6; 8]), "k").unwrap();
        health.remote(&relayed, HealthState::Degraded);
        health.remote(&kept, HealthState::Warning);
        let _ = notices(&mut watched);
        let mut held = Vec::new();
        health.with_remote_unhealthy(|node, state| held.push((node.clone(), state)));
        assert_eq!(held.len(), 3, "{held:?}");
        health.forget_remote(other.daemon(), &[relayed].into_iter().collect());
        assert!(notices(&mut watched).is_empty());
        let mut held = Vec::new();
        health.with_remote_unhealthy(|node, state| held.push((node.clone(), state)));
        assert_eq!(held, [(kept.clone(), HealthState::Warning)]);
        health.forget_remote(kept.daemon(), &BTreeSet::new());
        let (late, mut late_queue) = queue();
        health.watch(ConnectionId(2), SubscriptionId("t".into()), &late);
        assert!(notices(&mut late_queue).is_empty());
    }

    #[test]
    fn each_change_of_a_node_here_is_handed_on_and_the_unhealthy_are_listed() {
        let health = tracker();
        let changes = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&changes);
        health.watch_local(move |name, state| seen.lock().push((name.to_string(), state)));
        let (quiet, fine) = (Origin::named("quiet"), Origin::named("fine"));
        health.attach(&quiet, ConnectionId(1));
        health.attach(&fine, ConnectionId(2));
        for _ in 0..6 {
            health.heard(fine.node_id());
            health.tick();
        }
        health.reported(fine.node_id(), Some(DEGRADED));
        assert_eq!(
            *changes.lock(),
            [
                ("quiet".to_string(), NodeState::Warning),
                ("fine".to_string(), NodeState::Degraded)
            ]
        );
        let mut unhealthy = Vec::new();
        health.with_unhealthy(|name, state| unhealthy.push((name.to_string(), state)));
        unhealthy.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            unhealthy,
            [
                ("fine".to_string(), NodeState::Degraded),
                ("quiet".to_string(), NodeState::Warning)
            ]
        );
        // A detach is not a change handed on: the announcement carries it.
        health.detach(ConnectionId(1), Some(&quiet));
        assert_eq!(changes.lock().len(), 2);
    }

    #[test]
    fn a_notice_with_no_room_is_dropped_and_counted_and_a_closed_watcher_is_forgotten() {
        let health = tracker();
        let total = Arc::new(QueueTotal::default());
        // A queue with no bytes to hold anything.
        let (full, _full_queue) = event_queue(8, 0, Arc::clone(&total), usize::MAX);
        let (gone, gone_queue) = event_queue(8, usize::MAX, total, usize::MAX);
        health.watch(ConnectionId(2), SubscriptionId("s".into()), &full);
        health.watch(ConnectionId(3), SubscriptionId("s".into()), &gone);
        drop(gone_queue);
        let node = Origin::named("n");
        health.attach(&node, ConnectionId(1));
        health.detach(ConnectionId(1), Some(&node));
        assert_eq!(health.notices_dropped(), 1);
        assert_eq!(
            health.tracked.lock().watchers.len(),
            1,
            "the closed one went"
        );
    }
}
