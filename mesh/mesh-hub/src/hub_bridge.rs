// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's one [`HubBridge`] over the embedded `PulseHub`.
//!
//! The daemon's hub creates the ring and the store, so it is the ring's one
//! writer. A send is stored and signalled on the ring with a Data pulse that
//! names it, then encoded once and queued for every subscription whose filter
//! matches (`filter`), through the connections' event queues (`queue`). A
//! process attached to the hub by name polls the ring and fetches from the
//! store, and publishes by sending to the daemon.
//!
//! With links to other daemons (`crate::link`), a send is then forwarded, as
//! the hub stamped it, to the peers whose interest may match it, and an
//! envelope a peer forwards is queued for the subscriptions here that match
//! it ([`Subscribers::deliver`]), as a send here is, but is neither stored
//! nor signalled on the ring: see `crate::link` for why.
//!
//! A send with a destination ([`HubBridge::send_to`], the protocol's `to`)
//! goes to one node: to the subscriptions of that node's connection that
//! match it, when the node is attached here ([`Subscribers::deliver_to`]),
//! or forwarded to the peer daemon that announced it. The hub's schemas
//! check it (`PulseHub::send_envelope`), and it is neither stored, signalled
//! on the ring, captured into the basket nor forwarded by interest: it is
//! addressed to that node alone.
//!
//! The hub name is the bridge's only while its hub keeps it; a displaced hub
//! ([`HubBridge::is_displaced`]) is noticed within [`DISPLACEMENT_CHECK`].

use crate::filter::{Filter, Subject};
use crate::link::{BoundLinks, LinkSetupError, Links};
use crate::protocol::{base64, FilterSpec, MAX_CHANNEL_LEN, MAX_PATTERN_LEN};
use crate::queue::{event_head, EventFields, EventSink, Offer};
use crate::registry::{AttachedEntry, ConnectionId, Origin, Registry};
use mesh_hub_runtime::owner::{hub_lock_path, lock_holder, LockHolder};
use mesh_hub_runtime::{HubConfig, PulseHub};
use mesh_link::{DaemonId, Destination, Interest, QualifiedOrigin};
use parking_lot::{Mutex, RwLock};
use pulse_canon::{NodeId, PulseEnvelope, PulseEnvelopeId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use thiserror::Error;

/// How often a hub name is checked for another owner ([`HubBridge::displaced`],
/// and an [`crate::embed::EmbeddedMesh`]'s watch): a displaced daemon exits, or
/// a mesh stops serving, within about this of the new owner's mark.
pub const DISPLACEMENT_CHECK: Duration = Duration::from_secs(1);

/// Who holds `hub_name` now, in words for a displaced hub's log.
pub(crate) fn name_holder(hub_name: &str) -> String {
    let Ok(path) = hub_lock_path(hub_name) else {
        return format!("{hub_name} is not a hub name");
    };
    let at = path.display();
    match lock_holder(&path) {
        Ok(Some(LockHolder { pid: Some(pid) })) => format!("process {pid} holds its lock at {at}"),
        Ok(Some(LockHolder { pid: None })) => {
            format!("a process that recorded no id holds its lock at {at}")
        }
        Ok(None) => {
            format!("nobody holds its lock at {at} now, so the owner that took it has gone")
        }
        Err(e) => format!("its lock at {at} could not be read: {e}"),
    }
}

/// A unique identifier for a daemon-side subscription.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub String);

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What [`HubBridge::send`] did with one envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendReceipt {
    /// The envelope's content-addressed id.
    pub envelope_id: PulseEnvelopeId,
    /// Whether the store kept the envelope, `None` without a store: the send
    /// ack's `persisted`.
    pub persisted: Option<bool>,
}

/// What [`HubBridge::send_to`] did with one envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectedReceipt {
    /// The envelope's content-addressed id.
    pub envelope_id: PulseEnvelopeId,
    /// The ack's `delivered`: for a node attached here, whether one of its
    /// subscriptions matched; for a node of a peer daemon, whether the
    /// envelope was handed to the link to that peer.
    pub delivered: bool,
}

/// How the sends with a destination went, since the daemon started: a
/// snapshot ([`crate::embed::EmbeddedMesh::destination_sends`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DestinationSends {
    /// To a node attached to this daemon, delivered or not.
    pub local: u64,
    /// To a node a peer daemon announced, forwarded to that peer or not.
    pub forwarded: u64,
    /// Refused with `unknown_destination`.
    pub unknown: u64,
}

/// The counts behind [`DestinationSends`].
#[derive(Debug, Default)]
struct DestinationCounts {
    local: AtomicU64,
    forwarded: AtomicU64,
    unknown: AtomicU64,
}

/// Where a send with a destination goes.
enum Target {
    /// A node attached here.
    Local(AttachedEntry),
    /// A node the peer daemon announced.
    Peer(DaemonId, QualifiedOrigin),
}

/// One subscription, as the bridge routes to it.
struct Subscriber {
    id: SubscriptionId,
    /// The connection that holds it, which a send addressed to its node
    /// reaches alone.
    owner: ConnectionId,
    /// The filter as the client gave it, which the links' interest summary
    /// is made from.
    spec: FilterSpec,
    filter: Filter,
    /// `{"op":"event","subscription_id":"<id>",`, made once.
    head: Arc<str>,
    /// The owning connection's event queue.
    sink: EventSink,
    /// Events dropped for the subscription, refused or given up later.
    dropped: Arc<AtomicU64>,
}

/// What one delivery to the subscriptions is: the fields its events carry.
pub(crate) struct Delivery<'a> {
    /// The channel it was sent on.
    pub(crate) channel: &'a str,
    /// The envelope's type id.
    pub(crate) type_id: u16,
    /// The type name the send named, `None` when it named none; the event
    /// carries it as it was sent.
    pub(crate) type_name: Option<&'a str>,
    /// The envelope's type name: the send's, or the channel when it named
    /// none. Filters match it.
    pub(crate) resolved_type_name: &'a str,
    /// The sender as the event names it: a local origin, or a qualified one
    /// for an envelope a peer forwarded.
    pub(crate) origin: &'a str,
    /// The envelope's id.
    pub(crate) envelope_id: &'a PulseEnvelopeId,
    /// The payload's bytes.
    pub(crate) payload: &'a [u8],
}

/// The daemon's subscriptions, shared by the bridge and its links: the
/// bridge opens and closes them and queues its sends for them, and the links
/// summarise them for their peers and queue what the peers forward.
#[derive(Default)]
pub(crate) struct Subscribers {
    /// A delivery holds this lock only to copy the subscribers out.
    map: RwLock<HashMap<SubscriptionId, Arc<Subscriber>>>,
    /// Called after every change to the set, outside the lock, once the links
    /// watch it ([`Subscribers::watch`]).
    on_change: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl Subscribers {
    /// Call `f` after every change to the set from now on; a second watch is
    /// ignored.
    pub(crate) fn watch(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.on_change.set(Box::new(f));
    }

    fn changed(&self) {
        if let Some(f) = self.on_change.get() {
            f();
        }
    }

    fn insert(&self, subscriber: Subscriber) {
        self.map
            .write()
            .insert(subscriber.id.clone(), Arc::new(subscriber));
        self.changed();
    }

    /// Drop `id`, returning the events dropped for it, or `None` if it was
    /// not present.
    fn remove(&self, id: &SubscriptionId) -> Option<u64> {
        let removed = self.map.write().remove(id);
        let dropped = removed.map(|s| s.dropped.load(Ordering::Relaxed));
        if dropped.is_some() {
            self.changed();
        }
        dropped
    }

    /// Subscriptions routed now.
    pub(crate) fn len(&self) -> usize {
        self.map.read().len()
    }

    /// The summary of every subscription's filter that the links send their
    /// peers (`mesh_link::Interest::from_filters`).
    pub(crate) fn interest(&self) -> Interest {
        let map = self.map.read();
        Interest::from_filters(map.values().map(|s| &s.spec))
    }

    /// Queue `send` for every subscription whose filter matches it, one
    /// encoded event shared by all of them, and return how many matched. A
    /// queue without room drops the event and counts it for its
    /// subscription; a subscription whose connection went away without
    /// unsubscribing is dropped here.
    pub(crate) fn deliver(&self, send: &Delivery<'_>) -> usize {
        self.deliver_among(send, None)
    }

    /// Queue `send`, addressed to the node attached on the connection
    /// `owner`, for that connection's subscriptions whose filter matches it,
    /// as [`Subscribers::deliver`] does, and for no other; how many matched.
    pub(crate) fn deliver_to(&self, owner: ConnectionId, send: &Delivery<'_>) -> usize {
        self.deliver_among(send, Some(owner))
    }

    fn deliver_among(&self, send: &Delivery<'_>, owner: Option<ConnectionId>) -> usize {
        // Copy the subscribers out and let go of the lock before matching.
        let subscribers: Vec<Arc<Subscriber>> = self
            .map
            .read()
            .values()
            .filter(|s| owner.is_none_or(|owner| s.owner == owner))
            .cloned()
            .collect();
        let subject = Subject::new(
            send.channel,
            send.type_id,
            send.resolved_type_name,
            send.origin,
        );
        let mut scratch = Vec::new();
        let mut matched = Vec::new();
        // Subscriptions whose connection went away without unsubscribing.
        let mut closed = Vec::new();
        for sub in &subscribers {
            if sub.sink.is_closed() {
                closed.push(sub.id.clone());
            } else if sub.filter.matches(&subject, &mut scratch) {
                matched.push(sub);
            }
        }
        tracing::debug!(
            channel = %send.channel,
            origin = %send.origin,
            subscribers_total = subscribers.len(),
            subscribers_matched = matched.len(),
            "bridge.send dispatching"
        );
        let count = matched.len();

        if !matched.is_empty() {
            // One encoding for every subscription the send reaches.
            let payload_b64 = base64::encode(send.payload);
            let env_id_hex = hex_envelope_id(send.envelope_id);
            let fields = EventFields {
                envelope_id: &env_id_hex,
                channel: send.channel,
                type_id: send.type_id,
                type_name: send.type_name,
                origin: send.origin,
                captured_at_unix_nanos: now_unix_nanos() as u64,
                payload: &payload_b64,
            };
            match fields.body() {
                None => {
                    tracing::error!(channel = %send.channel, "an event could not be encoded; it was not delivered")
                }
                Some(body) => {
                    for sub in matched {
                        match sub.sink.offer(&sub.head, &body, &sub.dropped) {
                            Offer::Queued => {}
                            Offer::Dropped => {
                                // Logged at the first drop and at each
                                // doubling.
                                let n = sub.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                                if n.is_power_of_two() {
                                    tracing::warn!(
                                        sub = %sub.id,
                                        dropped = n,
                                        "event dropped: the subscriber's queue, or the daemon's budget, is full"
                                    );
                                }
                            }
                            Offer::Closed => closed.push(sub.id.clone()),
                        }
                    }
                }
            }
        }
        if !closed.is_empty() {
            {
                let mut map = self.map.write();
                for id in &closed {
                    map.remove(id);
                }
            }
            self.changed();
        }
        count
    }
}

/// The async-facing wrapper around `PulseHub`.
pub struct HubBridge {
    /// Behind a mutex, since `PulseHub` takes `&mut self`; held per operation.
    hub: Arc<Mutex<PulseHub>>,
    /// The subscriptions, shared with the links.
    subscribers: Arc<Subscribers>,
    next_sub: AtomicU64,
    /// Envelopes sent and published to the hub, for the metrics endpoint.
    sends: AtomicU64,
    /// The hub name, part of every subscription id.
    hub_name: String,
    /// The basket's thread, which every send is captured through, if any.
    #[cfg(feature = "basket")]
    capture: Option<crate::capture::Capture>,
    /// The links to other daemons, if any ([`HubBridge::with_links`]).
    links: Option<Links>,
    /// The sends with a destination, by where they went.
    destinations: DestinationCounts,
}

/// Why the bridge refused or failed a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// The hub could not be created; the message is the runtime's reason
    /// (see [`HubBridge::new`]).
    #[error("hub initialization failed: {0}")]
    Init(String),
    /// The hub's schema registry refused a send's envelope; the message is
    /// the underlying error.
    #[error("envelope dispatch failed: {0}")]
    Dispatch(String),
    /// A send's channel or type name longer than [`MAX_CHANNEL_LEN`], or a
    /// filter string longer than [`MAX_PATTERN_LEN`]; nothing was published or
    /// subscribed, and the daemon answers `bad_request`.
    #[error("{what} of {len} bytes is longer than the {max} bytes allowed")]
    TooLong {
        /// Which string: `channel` or `type_name` of a send, or `filter
        /// channel`, `filter type_name` or `filter origin`.
        what: &'static str,
        /// Its length in bytes.
        len: usize,
        /// The most the protocol allows.
        max: usize,
    },
    /// A send's destination is no node attached here, and none a linked
    /// peer announced; nothing was delivered, and the daemon answers
    /// `unknown_destination`.
    #[error("no node {node} is attached here or announced by a linked daemon")]
    UnknownDestination {
        /// The destination as the send named it.
        node: String,
    },
}

/// Refuse `value` when it is longer than `max` bytes.
fn check_len(what: &'static str, value: &str, max: usize) -> Result<(), BridgeError> {
    if value.len() > max {
        Err(BridgeError::TooLong {
            what,
            len: value.len(),
            max,
        })
    } else {
        Ok(())
    }
}

impl HubBridge {
    /// A bridge over a hub that owns `hub_name`, made by
    /// `mesh_hub_runtime::PulseHub::create_fresh` (which removes whatever an
    /// earlier owner left under the name) with the default configuration.
    ///
    /// # Errors
    ///
    /// [`BridgeError::Init`] with the runtime's `OwnerError` as text: a live
    /// owner holds the name, its lock file cannot be taken, the name is
    /// invalid, or the ring cannot be made.
    pub fn new(hub_name: &str) -> Result<Self, BridgeError> {
        Self::with_config(hub_name, HubConfig::default())
    }

    /// [`HubBridge::new`] with `config` instead of the default; a store that
    /// cannot be made leaves the hub without one ([`HubBridge::store_slots`]).
    ///
    /// # Errors
    ///
    /// As [`HubBridge::new`].
    pub fn with_config(hub_name: &str, config: HubConfig) -> Result<Self, BridgeError> {
        let hub = PulseHub::create_fresh(hub_name, config)
            .map_err(|e| BridgeError::Init(e.to_string()))?;

        Ok(Self {
            hub: Arc::new(Mutex::new(hub)),
            subscribers: Arc::default(),
            next_sub: AtomicU64::new(1),
            sends: AtomicU64::new(0),
            hub_name: hub_name.to_string(),
            #[cfg(feature = "basket")]
            capture: None,
            links: None,
            destinations: DestinationCounts::default(),
        })
    }

    /// Link to other daemons over `bound`'s socket (`crate::link`): start
    /// the links' threads, which watch this bridge's subscriptions for the
    /// summary they send and `registry`'s attached nodes for the
    /// announcement, and deliver what the peers forward to them. Every send
    /// is then forwarded to the peers whose interest may match it. Dropping
    /// the bridge stops the links and joins their threads.
    ///
    /// # Errors
    ///
    /// [`LinkSetupError::Thread`] when a thread cannot be started; nothing is
    /// left running.
    pub(crate) fn with_links(
        mut self,
        bound: BoundLinks,
        registry: &Arc<Registry>,
    ) -> Result<Self, LinkSetupError> {
        self.links = Some(bound.start(Arc::clone(&self.subscribers), Arc::clone(registry))?);
        Ok(self)
    }

    /// The links to other daemons, if any.
    pub(crate) fn links(&self) -> Option<&Links> {
        self.links.as_ref()
    }

    /// Capture every send into `basket` on a thread of the basket's own,
    /// which also sweeps it with the default retention policy every
    /// `sweep_every`. A send only queues its capture; a capture that finds
    /// the queue full is dropped and counted in the log. Dropping the bridge
    /// writes what is queued and joins the thread.
    ///
    /// # Errors
    ///
    /// The operating system's error when the thread cannot be started.
    #[cfg(feature = "basket")]
    pub fn with_basket(
        mut self,
        basket: mesh_basket::Basket,
        sweep_every: Duration,
    ) -> std::io::Result<Self> {
        self.capture = Some(crate::capture::Capture::start(basket, sweep_every)?);
        Ok(self)
    }

    /// Open a subscription of the connection `owner` delivering the sends
    /// `filter` matches into `sink`, the connection's event queue, and return
    /// its id; the caller unsubscribes it when the connection ends. A send
    /// addressed to `owner`'s node reaches its subscriptions alone.
    ///
    /// # Errors
    ///
    /// [`BridgeError::TooLong`] for a filter string longer than
    /// [`MAX_PATTERN_LEN`], with nothing opened.
    pub fn subscribe(
        &self,
        owner: ConnectionId,
        filter: FilterSpec,
        sink: EventSink,
    ) -> Result<SubscriptionId, BridgeError> {
        for (what, value) in [
            ("filter channel", &filter.channel),
            ("filter type_name", &filter.type_name),
            ("filter origin", &filter.origin),
        ] {
            if let Some(value) = value {
                check_len(what, value, MAX_PATTERN_LEN)?;
            }
        }
        let n = self.next_sub.fetch_add(1, Ordering::Relaxed);
        let id = SubscriptionId(format!("sub-{}-{:08x}", &self.hub_name, n));
        let subscriber = Subscriber {
            id: id.clone(),
            owner,
            filter: Filter::compile(&filter),
            spec: filter,
            head: event_head(&id.0),
            sink,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        self.subscribers.insert(subscriber);
        Ok(id)
    }

    /// Drop a subscription. Returns how many events were dropped for it
    /// while it existed, or `None` if it was not present.
    pub fn unsubscribe(&self, id: &SubscriptionId) -> Option<u64> {
        self.subscribers.remove(id)
    }

    /// Publish an envelope from `origin`: store it and signal it on the ring
    /// for the processes attached by name, then queue it for every subscription
    /// whose filter matches, one encoded event shared by all of them, and with
    /// links, forward it as the hub stamped it to the peers whose interest may
    /// match it. A store refusal does not stop the send, and the receipt says
    /// so; a queue without room drops the event and counts it for its
    /// subscription; a forward the links cannot make is counted and logged
    /// (`crate::link`), and does not fail the send.
    ///
    /// The send runs in a trace-level `send` span (channel, type id, payload
    /// bytes, origin, then the subscriptions matched and whether the store kept
    /// the envelope), which costs a level check unless a layer takes it
    /// (`crate::otel`): its fields are evaluated only then. A send refused for
    /// a name too long makes none.
    ///
    /// # Errors
    ///
    /// [`BridgeError::TooLong`], with nothing stored or signalled, when
    /// `channel` or `type_name` is longer than [`MAX_CHANNEL_LEN`];
    /// [`BridgeError::Dispatch`] when [`PulseHub::broadcast_envelope`] refuses
    /// the envelope.
    pub fn send(
        &self,
        channel: String,
        type_id: u16,
        type_name: Option<String>,
        payload: Vec<u8>,
        origin: &Origin,
    ) -> Result<SendReceipt, BridgeError> {
        check_len("channel", &channel, MAX_CHANNEL_LEN)?;
        if let Some(name) = &type_name {
            check_len("type_name", name, MAX_CHANNEL_LEN)?;
        }
        // Integers as i64, which OpenTelemetry keeps as numbers; tracing hands
        // an unsigned field to a layer as text. Recording on a disabled span
        // would still look its field up by name, hence the checks below.
        let span = tracing::trace_span!(
            "send",
            channel = channel.as_str(),
            type_id = i64::from(type_id),
            payload_bytes = i64::try_from(payload.len()).unwrap_or(i64::MAX),
            origin = origin.canonical(),
            matched = tracing::field::Empty,
            persisted = tracing::field::Empty,
        );
        let _in_send = span.enter();

        // The envelope has no channel field: it carries the client's type id,
        // and is named by the type name, or by the channel when the send
        // names none; the daemon routes by channel itself.
        let resolved_type_name = type_name.clone().unwrap_or_else(|| channel.clone());
        let envelope =
            PulseEnvelope::with_content(type_id, Some(resolved_type_name.clone()), payload.clone());
        let envelope_id = envelope.id();

        let (persisted, stamp) = {
            let mut hub = self.hub.lock();
            let outcome = hub
                .broadcast_envelope(envelope.clone(), &origin.node_id())
                .map_err(|e| BridgeError::Dispatch(format!("{:?}", e)))?;
            (outcome.persisted(), outcome.monotonic_nanos)
        };
        self.sends.fetch_add(1, Ordering::Relaxed);
        if !span.is_disabled() {
            // Nothing without a store.
            span.record("persisted", persisted);
        }

        // The peers get the copy the hub stamped, so that a peer's forward
        // cache tells this send from a later one of the same content.
        if let Some(links) = &self.links {
            links.forward(
                origin,
                &channel,
                type_id,
                type_name.as_deref(),
                &envelope,
                stamp,
            );
        }

        #[cfg(feature = "basket")]
        if let Some(capture) = &self.capture {
            let meta = mesh_basket::CaptureMeta {
                channel: channel.clone(),
                origin: origin.canonical().to_string(),
                captured_at_unix_nanos: Some(now_unix_nanos()),
            };
            capture.offer(envelope, meta);
        }

        let matched = self.subscribers.deliver(&Delivery {
            channel: &channel,
            type_id,
            type_name: type_name.as_deref(),
            resolved_type_name: &resolved_type_name,
            origin: origin.canonical(),
            envelope_id: &envelope_id,
            payload: &payload,
        });
        if !span.is_disabled() {
            span.record("matched", i64::try_from(matched).unwrap_or(i64::MAX));
        }
        Ok(SendReceipt {
            envelope_id,
            persisted,
        })
    }

    /// Send an envelope from `origin` to the node `to` names alone
    /// (`mesh_port_protocol`'s Destinations): a node attached here, named by
    /// its node id or, with links, by its qualified id under this daemon's;
    /// or a node a linked peer announced, or failing that one a relay this
    /// daemon trusts announced as reached through it, by its qualified id. The hub's
    /// schemas check it first (`PulseHub::send_envelope`), which neither
    /// stores nor signals it. A node here gets it on the subscriptions of its
    /// connection that match it; a peer's node, through a forward to that
    /// peer alone, stamped with the hub's clock so that the peer's forward
    /// cache tells it from a later send of the same content. The receipt's
    /// `delivered` says which subscriptions matched, or that the forward was
    /// made.
    ///
    /// # Errors
    ///
    /// [`BridgeError::TooLong`] as for [`HubBridge::send`];
    /// [`BridgeError::UnknownDestination`] when `to` names no node attached
    /// here or announced by a peer, with nothing delivered; and
    /// [`BridgeError::Dispatch`] when the hub's schemas refuse the envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn send_to(
        &self,
        channel: String,
        type_id: u16,
        type_name: Option<String>,
        payload: Vec<u8>,
        origin: &Origin,
        to: &str,
        registry: &Registry,
    ) -> Result<DirectedReceipt, BridgeError> {
        check_len("channel", &channel, MAX_CHANNEL_LEN)?;
        if let Some(name) = &type_name {
            check_len("type_name", name, MAX_CHANNEL_LEN)?;
        }
        let span = tracing::trace_span!(
            "send",
            channel = channel.as_str(),
            type_id = i64::from(type_id),
            payload_bytes = i64::try_from(payload.len()).unwrap_or(i64::MAX),
            origin = origin.canonical(),
            to = to,
            matched = tracing::field::Empty,
        );
        let _in_send = span.enter();
        let Some(target) = self.resolve(to, registry) else {
            self.destinations.unknown.fetch_add(1, Ordering::Relaxed);
            return Err(BridgeError::UnknownDestination {
                node: to.to_owned(),
            });
        };
        let resolved_type_name = type_name.clone().unwrap_or_else(|| channel.clone());
        let envelope =
            PulseEnvelope::with_content(type_id, Some(resolved_type_name.clone()), payload.clone());
        let envelope_id = envelope.id();
        let dest = match &target {
            Target::Local(entry) => entry.origin.node_id(),
            // The runtime does not route by its destination yet; the qualified
            // id's hash names the node.
            Target::Peer(_, node) => NodeId::from_name(&node.to_string()),
        };
        let stamp = {
            let mut hub = self.hub.lock();
            hub.send_envelope(envelope.clone(), &origin.node_id(), &dest)
                .map_err(|e| BridgeError::Dispatch(format!("{e:?}")))?;
            hub.monotonic_nanos()
        };
        let delivered = match target {
            Target::Local(entry) => {
                self.destinations.local.fetch_add(1, Ordering::Relaxed);
                let matched = self.subscribers.deliver_to(
                    entry.connection_id,
                    &Delivery {
                        channel: &channel,
                        type_id,
                        type_name: type_name.as_deref(),
                        resolved_type_name: &resolved_type_name,
                        origin: origin.canonical(),
                        envelope_id: &envelope_id,
                        payload: &payload,
                    },
                );
                if !span.is_disabled() {
                    span.record("matched", i64::try_from(matched).unwrap_or(i64::MAX));
                }
                matched > 0
            }
            Target::Peer(peer, node) => {
                self.destinations.forwarded.fetch_add(1, Ordering::Relaxed);
                self.links.as_ref().is_some_and(|links| {
                    links.forward_to(
                        peer,
                        node,
                        origin,
                        &channel,
                        type_name.as_deref(),
                        &envelope,
                        stamp,
                    )
                })
            }
        };
        Ok(DirectedReceipt {
            envelope_id,
            delivered,
        })
    }

    /// Where `to` is: a node attached here by its node id; with links, one
    /// attached here by its qualified id under this daemon's, or one a peer
    /// announced, or a trusted relay as reached through it; or nowhere
    /// known.
    fn resolve(&self, to: &str, registry: &Registry) -> Option<Target> {
        if let Some(entry) = registry.find_canonical(to) {
            return Some(Target::Local(entry));
        }
        let links = self.links.as_ref()?;
        let node = QualifiedOrigin::parse(to).ok()?;
        match links.route_to(&node) {
            Destination::Local => registry.find_link_name(node.name()).map(Target::Local),
            // A node of a peer's, or one a trusted relay reaches: the
            // forward goes to that peer.
            Destination::Peer(peer) | Destination::Relay(peer) => Some(Target::Peer(peer, node)),
            Destination::Unknown => None,
        }
    }

    /// How the sends with a destination went so far.
    pub fn destination_sends(&self) -> DestinationSends {
        let read = |n: &AtomicU64| n.load(Ordering::Relaxed);
        DestinationSends {
            local: read(&self.destinations.local),
            forwarded: read(&self.destinations.forwarded),
            unknown: read(&self.destinations.unknown),
        }
    }

    /// Run `f` on the hub, under its lock: for a test that registers a
    /// schema on it.
    #[cfg(test)]
    pub(crate) fn with_hub<R>(&self, f: impl FnOnce(&mut PulseHub) -> R) -> R {
        f(&mut self.hub.lock())
    }

    /// Envelopes sent through the bridge and published to the hub since it
    /// was made; a send the hub refused is not counted.
    pub fn sends(&self) -> u64 {
        self.sends.load(Ordering::Relaxed)
    }

    /// How many live subscriptions the daemon currently routes.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Envelopes the hub's store has refused ([`PulseHub::store_failures`]);
    /// each was still delivered.
    pub fn store_failures(&self) -> u64 {
        self.hub.lock().store_failures()
    }

    /// Slots in the hub's envelope store, or `None` when it runs without one
    /// ([`PulseHub::store_slots`]).
    pub fn store_slots(&self) -> Option<usize> {
        self.hub.lock().store_slots()
    }

    /// Whether another owner has taken the hub name from under the bridge
    /// ([`PulseHub::is_displaced`]); once `true`, it stays `true`.
    pub fn is_displaced(&self) -> bool {
        self.hub.lock().is_displaced()
    }

    /// Return once the hub is displaced, checking at once and then every
    /// [`DISPLACEMENT_CHECK`]. It needs a Tokio runtime with its timer, and may
    /// be cancelled at any await.
    pub async fn displaced(&self) {
        let mut every = tokio::time::interval(DISPLACEMENT_CHECK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            if self.is_displaced() {
                return;
            }
        }
    }
}

fn now_unix_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn hex_envelope_id(id: &PulseEnvelopeId) -> String {
    id.0.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod fanout_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::queue::{EventQueue, QueueTotal};

    /// A connection's event queue of `events` events and `bytes` bytes, on
    /// a daemon-wide total of its own with no budget to speak of.
    fn event_queue(events: usize, bytes: usize) -> (EventSink, EventQueue) {
        crate::queue::event_queue(events, bytes, Arc::new(QueueTotal::default()), usize::MAX)
    }

    /// A hub name private to this process, so parallel runs elsewhere do not
    /// share it.
    fn hub(tag: &str) -> String {
        format!("{tag}{:x}", std::process::id())
    }

    /// Slots in each bridge's store: the default's 16 MiB per parallel test
    /// does not fit Docker's 64 MB `/dev/shm`.
    const STORE_SLOTS: usize = 16;

    /// A bridge for the hub `name` whose store has [`STORE_SLOTS`] slots.
    fn small_bridge(name: &str) -> HubBridge {
        let config = HubConfig::default().with_store_slots(STORE_SLOTS);
        HubBridge::with_config(name, config).unwrap()
    }

    fn publish(bridge: &HubBridge, payload: u8) {
        publish_bytes(bridge, vec![payload]);
    }

    fn publish_bytes(bridge: &HubBridge, payload: Vec<u8>) {
        bridge
            .send("flood".into(), 0, None, payload, &Origin::named("origin"))
            .expect("send");
    }

    #[test]
    fn full_sink_drops_and_counts() {
        let bridge = small_bridge(&hub("hb-drop"));
        let (sink, mut queue) = event_queue(2, usize::MAX);
        let id = bridge
            .subscribe(ConnectionId(1), FilterSpec::default(), sink)
            .unwrap();
        for i in 0..5 {
            publish(&bridge, i);
        }
        let mut received = 0;
        while queue.try_recv().is_some() {
            received += 1;
        }
        assert_eq!(received, 2, "the queue holds what it was sized for");
        assert_eq!(
            bridge.unsubscribe(&id),
            Some(3),
            "the rest were counted as dropped"
        );
        assert_eq!(bridge.unsubscribe(&id), None);
    }

    #[test]
    fn a_stalled_subscriber_holds_at_most_its_bytes_and_the_rest_are_counted() {
        let bridge = small_bridge(&hub("hb-bytes"));
        let budget = 256 * 1024;
        // Room for 1,024 events: only the bytes can run out.
        let (sink, mut queue) = event_queue(1024, budget);
        let id = bridge
            .subscribe(ConnectionId(1), FilterSpec::default(), sink)
            .unwrap();
        // Forty envelopes of 48 KiB, 64 KiB of base64 in each event.
        for i in 0..40u8 {
            publish_bytes(&bridge, vec![i; 48 * 1024]);
            let held = queue.held_bytes();
            assert!(held <= budget, "{held} bytes held after send {i}");
        }
        let (mut queued, mut size) = (0u64, 0);
        while let Some(event) = queue.try_recv() {
            queued += 1;
            size = event.bytes();
        }
        assert_eq!(
            queue.held_bytes(),
            0,
            "an event taken and dropped holds nothing"
        );
        assert_eq!(queued, (budget / size) as u64, "as many as the bytes allow");
        assert_eq!(
            bridge.unsubscribe(&id),
            Some(40 - queued),
            "every other event was counted as dropped"
        );
    }

    #[test]
    fn every_subscription_a_send_reaches_shares_one_encoded_event() {
        let bridge = small_bridge(&hub("hb-share"));
        let (first, mut first_queue) = event_queue(8, usize::MAX);
        let (second, mut second_queue) = event_queue(8, usize::MAX);
        let first_id = bridge
            .subscribe(ConnectionId(1), FilterSpec::default(), first)
            .unwrap();
        let second_id = bridge
            .subscribe(ConnectionId(2), FilterSpec::default(), second)
            .unwrap();
        publish_bytes(&bridge, vec![9; 4096]);
        let (a, b) = (
            first_queue.try_recv().unwrap(),
            second_queue.try_recv().unwrap(),
        );
        assert!(
            std::ptr::eq(a.body().as_ptr(), b.body().as_ptr()),
            "one copy of the payload"
        );
        for (event, id) in [(a, first_id), (b, second_id)] {
            let json: serde_json::Value = serde_json::from_str(&event.to_json()).unwrap();
            assert_eq!(json["op"], "event");
            assert_eq!(json["subscription_id"], id.0.as_str());
            assert_eq!(json["payload"].as_str().unwrap().len(), 5464);
        }
    }

    #[test]
    fn a_send_to_a_node_reaches_its_connections_matching_subscriptions_alone() {
        let bridge = small_bridge(&hub("hb-to"));
        let registry = Registry::new();
        let (target, other) = (ConnectionId(1), ConnectionId(2));
        assert!(matches!(
            registry.attach("target", target),
            crate::registry::AttachResult::Attached(_)
        ));
        let (wanted, mut wanted_queue) = event_queue(8, usize::MAX);
        let (unwanted, mut unwanted_queue) = event_queue(8, usize::MAX);
        let (elsewhere, mut elsewhere_queue) = event_queue(8, usize::MAX);
        let on = |channel: &str| FilterSpec {
            channel: Some(channel.into()),
            ..FilterSpec::default()
        };
        bridge.subscribe(target, on("dm"), wanted).unwrap();
        bridge.subscribe(target, on("other"), unwanted).unwrap();
        bridge.subscribe(other, on("dm"), elsewhere).unwrap();
        let sender = Origin::named("sender");
        let to = Origin::named("target").canonical().to_string();
        let receipt = bridge
            .send_to(
                "dm".into(),
                0,
                None,
                b"hi".to_vec(),
                &sender,
                &to,
                &registry,
            )
            .unwrap();
        assert!(receipt.delivered);
        let event: serde_json::Value =
            serde_json::from_str(&wanted_queue.try_recv().unwrap().to_json()).unwrap();
        assert_eq!(event["origin"], sender.canonical());
        assert_eq!(event["envelope_id"], hex_envelope_id(&receipt.envelope_id));
        assert!(
            unwanted_queue.try_recv().is_none(),
            "its other subscription"
        );
        assert!(elsewhere_queue.try_recv().is_none(), "another connection's");
        assert_eq!(bridge.sends(), 0, "not published to the hub");
        // Matching none of its subscriptions: acknowledged, not delivered.
        let missed = bridge
            .send_to(
                "none".into(),
                0,
                None,
                b"hi".to_vec(),
                &sender,
                &to,
                &registry,
            )
            .unwrap();
        assert!(!missed.delivered);
        // A node no one has, or a qualified id without links: unknown.
        for ghost in ["ghost@00000000", "target@0011223344556677", "target"] {
            assert!(matches!(
                bridge.send_to("dm".into(), 0, None, vec![], &sender, ghost, &registry),
                Err(BridgeError::UnknownDestination { node }) if node == ghost
            ));
        }
        let sends = bridge.destination_sends();
        assert_eq!((sends.local, sends.forwarded, sends.unknown), (2, 0, 3));
    }

    #[test]
    fn a_send_to_a_node_is_checked_by_the_hubs_schemas() {
        let bridge = small_bridge(&hub("hb-to-acl"));
        let registry = Registry::new();
        let _ = registry.attach("target", ConnectionId(1));
        bridge.with_hub(|hub| {
            hub.register_schema(
                mesh_schema::SchemaEntry::new(0x0042, "only-producer")
                    .add_producer(Origin::named("producer").node_id()),
            )
            .unwrap();
        });
        let to = Origin::named("target").canonical().to_string();
        let send = |origin: &str| {
            bridge.send_to(
                "c".into(),
                0x0042,
                None,
                vec![1],
                &Origin::named(origin),
                &to,
                &registry,
            )
        };
        assert!(send("producer").is_ok());
        assert!(matches!(send("intruder"), Err(BridgeError::Dispatch(_))));
    }

    #[test]
    fn closed_sink_is_pruned_on_next_send() {
        let bridge = small_bridge(&hub("hb-prune"));
        let (sink, queue) = event_queue(2, usize::MAX);
        bridge
            .subscribe(ConnectionId(1), FilterSpec::default(), sink)
            .unwrap();
        drop(queue);
        assert_eq!(bridge.subscriber_count(), 1);
        publish(&bridge, 1);
        assert_eq!(bridge.subscriber_count(), 0);
    }

    /// The type id a client sends is the envelope's type: the basket files
    /// it under that type, and the id covers it beside the type name.
    #[cfg(feature = "basket")]
    #[test]
    fn the_senders_type_id_is_the_envelopes_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.db");
        let bridge = small_bridge(&hub("hb-type"))
            .with_basket(mesh_basket::Basket::open(&path).unwrap(), Duration::MAX)
            .unwrap();
        let receipt = bridge
            .send(
                "jobs".into(),
                7,
                Some("app/job".into()),
                vec![1, 2],
                &Origin::named("o"),
            )
            .unwrap();
        let expected = PulseEnvelope::with_content(7, Some("app/job".into()), vec![1, 2]);
        assert_eq!(receipt.envelope_id, expected.id());
        bridge.capture.as_ref().unwrap().flush();
        let found = mesh_basket::Basket::open(&path)
            .unwrap()
            .query(&mesh_basket::QuerySpec {
                envelope_type: Some(7),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(found.rows.len(), 1, "one row of type 7");
        assert_eq!(found.rows[0].id, hex_envelope_id(&expected.id()));
        assert_eq!(found.rows[0].type_name.as_deref(), Some("app/job"));
    }

    /// A send returns before its capture is written, and dropping the bridge
    /// writes every capture still queued.
    #[cfg(feature = "basket")]
    #[test]
    fn dropping_the_bridge_writes_the_queued_captures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.db");
        let bridge = small_bridge(&hub("hb-drain"))
            .with_basket(mesh_basket::Basket::open(&path).unwrap(), Duration::MAX)
            .unwrap();
        for i in 0..50u8 {
            publish(&bridge, i);
        }
        assert_eq!(bridge.capture.as_ref().unwrap().dropped(), 0);
        drop(bridge);
        let counted = mesh_basket::Basket::open(&path)
            .unwrap()
            .query(&mesh_basket::QuerySpec {
                aggregate: Some(mesh_basket::Aggregation::Count),
                ..Default::default()
            })
            .unwrap();
        assert!(
            matches!(
                counted.aggregate,
                Some(mesh_basket::AggregateResult::Count(50))
            ),
            "{:?}",
            counted.aggregate
        );
    }

    #[test]
    fn signals_carry_a_rising_monotonic_time_to_an_attached_hub() {
        let name = hub("hb-clock");
        let bridge = small_bridge(&name);
        // Attached by name with the default config, which asks for another
        // store size: the store is opened at the size its header records.
        let mut reader = PulseHub::open(&name, HubConfig::default()).unwrap();
        assert_eq!(reader.store_slots(), Some(STORE_SLOTS));
        assert_eq!(bridge.store_slots(), Some(STORE_SLOTS));
        let times = Arc::new(Mutex::new(Vec::new()));
        let sink = times.clone();
        reader.subscribe(move |event| sink.lock().push(event.monotonic_nanos));
        for i in 0..3 {
            publish(&bridge, i);
        }
        assert_eq!(reader.poll(), 3);
        let times = times.lock().clone();
        assert!(times.iter().all(|&t| t > 0), "{times:?}");
        assert!(times.windows(2).all(|w| w[0] <= w[1]), "{times:?}");
        assert_eq!(
            reader.publish(&pulse_canon::Pulse::zeroed()),
            Err(mesh_hub_runtime::HubError::ReadOnly),
            "a hub attached to the daemon's ring does not write it"
        );
    }
}
