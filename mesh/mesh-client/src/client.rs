// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The blocking client over the Universal Port Protocol v0, and what runs
//! behind it.
//!
//! Each connection has a two-thread tokio runtime of its own and a thread
//! for the subscription callbacks. On the runtime, the driver task owns the
//! connection's state: it takes the calls off the command queue, queues
//! their requests in the outbox, routes each message the reader hands it
//! (a reply to its call, an event to the callback thread's queue) and
//! decides how the connection's end is reported. A reader and a writer task
//! own the transport.

use crate::error::DevError;
use futures_util::{SinkExt, StreamExt};
use mesh_port_protocol::attach::{self, SigningKey};
use mesh_port_protocol::base64;
use mesh_port_protocol::framing::{encode_frame, FrameDecoder};
use mesh_port_protocol::{
    ClientMessage, ErrorCode, FilterSpec, ServerMessage, DEFAULT_UDS_PATH, DEFAULT_WS_BIND,
    PROTOCOL_VERSION, WS_SUBPROTOCOL,
};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{mpsc, oneshot, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::Message as WsMsg;

/// An opaque subscription handle; pass to `Mesh::unsubscribe`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub String);

/// An event delivered to a subscription callback.
#[derive(Debug, Clone)]
pub struct MeshEvent {
    /// The subscription the event matched.
    pub subscription_id: SubscriptionId,
    /// Content-addressed envelope id (hex), the same on every delivery.
    pub envelope_id: String,
    /// The channel the envelope was published on.
    pub channel: String,
    /// Numeric envelope type; `0` for a name-routed envelope.
    pub type_id: u16,
    /// The type name, when the publisher gave one ([`Mesh::send_typed`]).
    pub type_name: Option<String>,
    /// The publisher's node id, as `name@hex`.
    pub origin: String,
    /// When the daemon captured the envelope, in nanoseconds since the Unix
    /// epoch. A `u64`, because `serde_json` needs `arbitrary_precision` for
    /// a `u128`; it lasts until 2554.
    pub captured_at_unix_nanos: u64,
    /// The payload, decoded from the wire's base64.
    pub payload: Vec<u8>,
}

/// What the daemon said about one published envelope; see
/// [`Mesh::send_with_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendReceipt {
    /// Content-addressed envelope id (hex), the one [`Mesh::send`]
    /// returns.
    pub envelope_id: String,
    /// Whether the daemon's envelope store kept the envelope for the hub's
    /// shared-memory readers: `Some(false)` when it refused it (too large,
    /// or no slot free), `None` when the daemon runs without a store, and
    /// for a send to a node ([`Mesh::send_to`]), which is not stored.
    /// Delivery to subscribers does not depend on it.
    pub persisted: Option<bool>,
    /// For a send to a node ([`Mesh::send_to`]): to a node attached to the
    /// same daemon, whether one of its subscriptions matched and got the
    /// event; to a node of a linked daemon, whether the envelope was
    /// forwarded to that daemon, delivery there being remote and
    /// unconfirmed. `None` for a send to a channel's subscribers, and from a
    /// daemon that does not say.
    pub delivered: Option<bool>,
}

/// [`Mesh::tap`]'s filter: the protocol's [`FilterSpec`], whose fields
/// say what matches.
pub type TapFilter = FilterSpec;

/// The mesh handle. Cheap to clone (`Arc` internally).
///
/// # What keeps a connection open
///
/// A connection has three threads: two for its tokio runtime, one for the
/// subscription callbacks. It stays open while any `Mesh` of it exists,
/// until a [`Mesh::detach`] the daemon acknowledges, the daemon closes it, a
/// write to it fails, or the daemon goes silent
/// ([`MeshOptions::silence_limit`]). Dropping the last `Mesh`, on any
/// thread, the runtime's own included, closes it without a detach. Once it
/// has ended, the callback thread runs the events already queued, drops
/// every callback and ends; the runtime's threads end with the last `Mesh`.
///
/// A callback is kept until its subscription is unsubscribed or the
/// connection ends, so a `Mesh` it holds keeps the connection and its
/// threads alive after every other handle is dropped (the heartbeat keeps
/// the daemon from closing it as idle). A callback that calls back into the
/// mesh holds a [`WeakMesh`] instead. Checked by `tests/handle_lifetime.rs`.
#[derive(Clone)]
pub struct Mesh {
    inner: Arc<MeshInner>,
}

/// A handle that does not keep its connection open, for a subscription's
/// callback that calls back into the mesh. Made by [`Mesh::downgrade`];
/// cheap to clone.
///
/// Upgrade it for each call and let the [`Mesh`] go when the call returns:
/// an upgraded `Mesh` keeps the connection open like any other.
///
/// ```no_run
/// use mesh_client::Mesh;
///
/// let mesh = Mesh::attach("echo")?;
/// let weak = mesh.downgrade();
/// mesh.on("ask", move |event| {
///     // Fails once the program has dropped its `Mesh`, instead of keeping
///     // the connection open.
///     let _ = weak.upgrade().and_then(|mesh| mesh.send("answer", &event.payload));
/// })?;
/// mesh.run()?;
/// # Ok::<(), mesh_client::DevError>(())
/// ```
#[derive(Clone)]
pub struct WeakMesh {
    inner: Weak<MeshInner>,
}

impl WeakMesh {
    /// The mesh, for as long as a [`Mesh`] of it exists.
    ///
    /// # Errors
    ///
    /// [`DevError::MeshDropped`] once every `Mesh` of the connection has been
    /// dropped, which closed the connection.
    pub fn upgrade(&self) -> Result<Mesh, DevError> {
        self.inner
            .upgrade()
            .map(|inner| Mesh { inner })
            .ok_or(DevError::MeshDropped)
    }
}

/// How to attach: the endpoint, the timeouts, the event queue's bounds, and
/// the key the client proves, if any. Build it from [`MeshOptions::default`]
/// with the `with_*` methods.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MeshOptions {
    /// The daemon to attach to. `None` runs endpoint discovery (see
    /// [`Mesh::attach`]).
    pub endpoint: Option<Endpoint>,
    /// Each call's deadline: past it, a call still waiting for room in the
    /// queue fails with [`DevError::QueueFull`], and one waiting for its
    /// reply with [`DevError::Timeout`], cancelled (see
    /// [`Mesh::late_replies`]). Default 5 s; `Duration::MAX` waits as long as
    /// it takes.
    pub rpc_timeout: Duration,
    /// After this long without sending anything, the client sends a
    /// `health` frame, so the daemon's idle timeout does not drop it.
    /// Default 30 s; zero disables it, and a period past thirty years is
    /// thirty years.
    pub heartbeat_interval: Duration,
    /// How long the daemon may send nothing while the client waits for it
    /// before the client gives it up: the connection closes, and
    /// [`Mesh::wait`] and every call still waiting report
    /// [`DevError::Silent`]. Anything the daemon sends counts. Default 90 s,
    /// the daemon's own idle timeout, which a healthy daemon always meets;
    /// zero disables the limit.
    ///
    /// On a WebSocket the client pings a daemon silent for a third of the
    /// limit, so a stopped daemon is given up even while the connection is
    /// idle. The Unix socket has no ping, and an idle daemon sends nothing
    /// on it (a `health` frame gets no reply), so there the limit runs only
    /// while the daemon owes an answer to a request, a timed-out call's
    /// included. Checked by `tests/silent_daemon.rs`.
    pub silence_limit: Duration,
    /// How many events may wait for the callbacks, across all
    /// subscriptions, before a newer one is dropped and counted in
    /// [`Mesh::events_dropped`]. Default 1,024, the daemon's per-connection
    /// default; zero is treated as one.
    pub event_queue: usize,
    /// How many bytes the waiting events, and the one a callback is
    /// running, may hold before a newer one is dropped, as for
    /// [`Self::event_queue`]. An event counts its payload and its text
    /// fields. One larger than the budget is always dropped, and zero drops
    /// every event, as the daemon's `--subscriber-queue-bytes` does. Default
    /// 16 MiB, the daemon's per-connection default. Checked by
    /// `tests/event_memory.rs`.
    pub event_queue_bytes: usize,
    /// PEM certificates of the authorities a `wss://` endpoint's certificate
    /// may chain to, beside the roots of the Mozilla root program that the
    /// `webpki-roots` crate carries, which are always trusted; see
    /// [`MeshOptions::with_tls_root_pem`]. Nothing turns verification off.
    /// Unused on `unix://` and `ws://`.
    pub tls_roots: Vec<Vec<u8>>,
    /// The Ed25519 key the client attaches as, or `None` to attach by name
    /// alone. With one, the attach carries its public key, and the client
    /// answers the daemon's challenge with a proof of it
    /// (`mesh_port_protocol::attach`), bound on `wss://` to the TLS
    /// connection; the daemon then names the connection by the key, and a
    /// daemon that lists the keys it allows (`--attach-keys`) admits the
    /// client only if this one is listed, refusing it otherwise with
    /// [`DevError::AuthFailed`]. A daemon from before key-proof attach acks
    /// at once, by name. `Debug` shows the public key alone.
    pub identity: Option<SigningKey>,
}

impl Default for MeshOptions {
    fn default() -> Self {
        Self {
            endpoint: None,
            rpc_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(30),
            silence_limit: Duration::from_secs(90),
            event_queue: 1024,
            event_queue_bytes: 16 * 1024 * 1024,
            tls_roots: Vec::new(),
            identity: None,
        }
    }
}

impl MeshOptions {
    /// Attach to this endpoint instead of discovering one.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Give each call `timeout` (see [`MeshOptions::rpc_timeout`]).
    #[must_use]
    pub fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = timeout;
        self
    }

    /// Send a `health` frame after `interval` of silence; zero disables it.
    #[must_use]
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Give up a daemon that sends nothing for `limit` while the client
    /// waits for it (see [`MeshOptions::silence_limit`]); zero disables it.
    #[must_use]
    pub fn with_silence_limit(mut self, limit: Duration) -> Self {
        self.silence_limit = limit;
        self
    }

    /// Let at most `depth` events wait for the callbacks (see
    /// [`MeshOptions::event_queue`]).
    #[must_use]
    pub fn with_event_queue(mut self, depth: usize) -> Self {
        self.event_queue = depth;
        self
    }

    /// Let the waiting events hold at most `bytes` (see
    /// [`MeshOptions::event_queue_bytes`]).
    #[must_use]
    pub fn with_event_queue_bytes(mut self, bytes: usize) -> Self {
        self.event_queue_bytes = bytes;
        self
    }

    /// Trust the certificate authorities in `pem` (one or more PEM
    /// certificates) for a `wss://` endpoint, beside webpki-roots' roots: for
    /// a daemon whose certificate a private CA issued, or one self-signed
    /// certificate trusted as its own root. Each call adds to the last's. A
    /// `pem` that holds no certificate fails the attach with
    /// [`DevError::Tls`].
    #[must_use]
    pub fn with_tls_root_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.tls_roots.push(pem.into());
        self
    }

    /// Attach as `key` (see [`MeshOptions::identity`]).
    #[must_use]
    pub fn with_identity(mut self, key: SigningKey) -> Self {
        self.identity = Some(key);
        self
    }

    /// Attach as the key in the key file at `path`
    /// ([`crate::identity::read_key_file`]), read now.
    ///
    /// # Errors
    ///
    /// [`DevError::KeyFile`] when the file cannot be read, its group or
    /// others may read or write it, or it holds no key.
    pub fn with_identity_file(self, path: impl AsRef<Path>) -> Result<Self, DevError> {
        Ok(self.with_identity(crate::identity::read_key_file(path.as_ref())?))
    }
}

/// A subscription's callback, which the callback thread runs for each of
/// its events.
type SubscriptionCallback = Arc<dyn Fn(MeshEvent) + Send + Sync>;

/// The callbacks by subscription: the driver inserts, the handles remove,
/// the callback thread looks up.
type CallbackMap = Arc<Mutex<HashMap<SubscriptionId, SubscriptionCallback>>>;

/// An event on its way to the callback thread, with the bytes it holds
/// against the queue's budget.
struct Queued {
    event: MeshEvent,
    charge: Charge,
}

/// Bytes held against the event queue's budget, given back when dropped:
/// once the event's callback has run, or when the event is dropped unrun.
struct Charge {
    held: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.held.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// What an event counts against the queue's budget
/// ([`MeshOptions::event_queue_bytes`]).
fn event_bytes(event: &MeshEvent) -> usize {
    event.payload.len()
        + event.subscription_id.0.len()
        + event.envelope_id.len()
        + event.channel.len()
        + event.type_name.as_ref().map_or(0, String::len)
        + event.origin.len()
}

/// Messages the reader may queue for the driver, beside the bytes
/// [`INBOUND_QUEUE_BYTES`] allows.
const INBOUND_QUEUE: usize = 64;

/// Bytes of the daemon's messages, as they arrived, that may wait for the
/// connection's task, the one being routed included; at least
/// [`MAX_INBOUND_MESSAGE`]. While they hold this much the client reads
/// nothing more: a burst waits in the socket, and no reply is dropped.
/// Checked by the unit test
/// `a_burst_of_large_messages_holds_at_most_the_inbound_budget`.
pub const INBOUND_QUEUE_BYTES: usize = 16 * 1024 * 1024;

const _: () = assert!(INBOUND_QUEUE_BYTES >= MAX_INBOUND_MESSAGE);

/// The reader's end of the queue to the driver ([`inbound_queue`]), and
/// where it notes that the daemon was heard from.
struct InboundTx {
    queue: mpsc::Sender<Received>,
    /// One permit per byte the queue may hold.
    budget: Arc<Semaphore>,
    /// The size of `budget`: the most one message is charged.
    bytes: u32,
    /// When the daemon was last heard from.
    heard: Arc<Heard>,
}

/// When the daemon was last heard from, for [`Silence`]: the reader notes
/// every read that brings bytes, and every WebSocket frame, a ping or a
/// pong included.
struct Heard {
    /// The instant `at` counts from.
    base: tokio::time::Instant,
    /// Nanoseconds from `base` to the last time the daemon was heard from.
    at: AtomicU64,
}

impl Heard {
    /// Heard from now, as a connection's start counts.
    fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            at: AtomicU64::new(0),
        }
    }

    /// The daemon was heard from now.
    fn hear(&self) {
        let nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.at.fetch_max(nanos, Ordering::AcqRel);
    }

    /// When the daemon was last heard from.
    fn last(&self) -> tokio::time::Instant {
        self.base + Duration::from_nanos(self.at.load(Ordering::Acquire))
    }
}

/// A message on its way to the driver, with the bytes it holds against the
/// queue's budget until routed.
struct Received {
    message: ServerMessage,
    charge: OwnedSemaphorePermit,
}

/// A queue from the transport reader to the driver holding at most `count`
/// messages (zero is taken as one) and `bytes` bytes of them.
fn inbound_queue(count: usize, bytes: usize) -> (InboundTx, mpsc::Receiver<Received>) {
    let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
    let (queue, rx) = mpsc::channel(count.max(1));
    let tx = InboundTx {
        queue,
        budget: Arc::new(Semaphore::new(bytes as usize)),
        bytes,
        heard: Arc::new(Heard::new()),
    };
    (tx, rx)
}

impl InboundTx {
    /// The daemon was heard from: the reader got bytes, or a frame, from it.
    fn hear(&self) {
        self.heard.hear();
    }

    /// When the daemon was last heard from, which the driver reads.
    fn heard(&self) -> Arc<Heard> {
        Arc::clone(&self.heard)
    }

    /// Hand the driver one message, `len` bytes as it arrived, once the
    /// queue has room for it; one longer than the whole budget waits for the
    /// queue to empty and goes alone. `false` once the driver has gone.
    async fn send(&self, message: ServerMessage, len: usize) -> bool {
        self.hear();
        let charge = u32::try_from(len).unwrap_or(u32::MAX).min(self.bytes);
        let charge = tokio::select! {
            charge = Arc::clone(&self.budget).acquire_many_owned(charge) => charge,
            () = self.queue.closed() => return false,
        };
        // The semaphore is never closed.
        let Ok(charge) = charge else { return false };
        self.queue.send(Received { message, charge }).await.is_ok()
    }
}

/// The longest message the client takes from the daemon, on either
/// transport (a Unix-socket frame's announced length, a WebSocket message
/// or frame); a longer one ends the connection. Sixteen times the daemon's
/// default frame limit of 1 MiB, while a corrupt length prefix cannot make
/// the client buffer toward 4 GiB.
pub const MAX_INBOUND_MESSAGE: usize = 16 * 1024 * 1024;

/// Depth of the queue of calls between the calling threads and the task
/// that owns the connection, which takes a call off while fewer than
/// [`OUTBOUND_QUEUE`] requests wait for the writer. A call that finds it
/// full waits for room until its deadline, then fails with
/// [`DevError::QueueFull`], having sent nothing. Checked by
/// `tests/timeouts.rs`.
pub const COMMAND_QUEUE: usize = 64;

/// The queue of calls between the calling threads and the driver,
/// [`COMMAND_QUEUE`] deep.
fn command_queue() -> (mpsc::Sender<Cmd>, mpsc::Receiver<Cmd>) {
    mpsc::channel(COMMAND_QUEUE)
}

/// Depth of the queue of requests waiting for the transport's writer;
/// while this many wait, calls wait in the [`COMMAND_QUEUE`]. A daemon that
/// stops reading costs at most this many requests, [`COMMAND_QUEUE`] calls
/// and the frame being written. The client's own few frames (heartbeats,
/// releases) are not counted. Checked by `tests/stalled_memory.rs`.
pub const OUTBOUND_QUEUE: usize = 64;

/// Requests nobody waits on that the client remembers, so their replies
/// are known for late ones: timed-out calls already written, and its own
/// releases. Past this many the oldest is forgotten, and a reply to it
/// answers nothing.
const MAX_ABANDONED: usize = 4096;

/// The counts behind [`Mesh::events_dropped`] and
/// [`Mesh::events_malformed`].
#[derive(Default)]
struct EventCounts {
    /// Events the queue had no room for.
    dropped: AtomicU64,
    /// Events whose payload was not valid base64.
    malformed: AtomicU64,
}

/// The driver's end of the bounded queue to the callback thread, and the
/// counts. The driver holds its only sender, so the thread ends once the
/// driver has ended and the queue is empty.
struct Dispatch {
    queue: std::sync::mpsc::SyncSender<Queued>,
    counts: Arc<EventCounts>,
    /// Bytes of the events queued, and of the one a callback is running.
    held: Arc<AtomicUsize>,
    /// The most `held` may be.
    budget: usize,
}

impl Dispatch {
    /// A queue of at most `depth` events (zero is treated as one) holding at
    /// most `bytes`, and the receiving end the dispatch thread drains.
    fn new(depth: usize, bytes: usize) -> (Self, std::sync::mpsc::Receiver<Queued>) {
        let (queue, rx) = std::sync::mpsc::sync_channel(depth.max(1));
        let dispatch = Self {
            queue,
            counts: Arc::default(),
            held: Arc::default(),
            budget: bytes,
        };
        (dispatch, rx)
    }

    /// Count an event whose payload is not valid base64, logging at the
    /// first and at each doubling.
    fn reject_malformed(&self, sub: &str, envelope: &str, error: &base64::Base64Error) {
        let n = self.counts.malformed.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            tracing::error!(
                sub,
                envelope,
                %error,
                malformed = n,
                "event payload is not valid base64; event dropped"
            );
        }
    }

    /// Offer one event without waiting: past the queue's depth or byte
    /// budget it is dropped and counted, logged at the first and at each
    /// doubling. Not waiting, because a driver blocked on a full queue
    /// would stall every reply, and deadlock a callback waiting on one.
    fn offer(&self, event: MeshEvent) {
        let bytes = event_bytes(&event);
        let reserved = self
            .held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(bytes)
                    .filter(|&total| total <= self.budget)
            });
        if reserved.is_err() {
            self.count_dropped(&event.subscription_id);
            return;
        }
        let queued = Queued {
            event,
            charge: Charge {
                held: Arc::clone(&self.held),
                bytes,
            },
        };
        // A refused event is dropped here, and its charge with it.
        match self.queue.try_send(queued) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(queued)) => {
                self.count_dropped(&queued.event.subscription_id);
            }
            // The dispatch thread is gone, so no callback could run it.
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
        }
    }

    /// Count an event the queue had no room for.
    fn count_dropped(&self, sub: &SubscriptionId) {
        let n = self.counts.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            tracing::warn!(sub = %sub.0, dropped = n, "event queue full; event dropped");
        }
    }
}

struct MeshInner {
    /// The runtime the connection's tasks run on; `None` only once `Drop`
    /// has taken it to shut it down.
    runtime: Option<Runtime>,
    /// A handle to that runtime, which the blocking calls run on.
    handle: Handle,
    /// The calls on their way to the driver, at most [`COMMAND_QUEUE`].
    cmd_tx: mpsc::Sender<Cmd>,
    /// Rung by a call that timed out, so the driver drops what it left
    /// queued.
    cancelled: Arc<Doorbell>,
    /// Replies that came after their call had timed out.
    late_replies: Arc<AtomicU64>,
    /// Looked up by the dispatch thread for every event it delivers.
    callbacks: CallbackMap,
    /// The event counts; not the queue, whose one sender is the driver's.
    events: Arc<EventCounts>,
    /// Each call's deadline.
    rpc_timeout: Duration,
    /// Why the driver ended, once it has.
    outcome: Arc<Mutex<Option<Result<(), DevError>>>>,
    /// Flips to `true` when the driver ends; `wait` sleeps on it.
    done_rx: watch::Receiver<bool>,
}

impl MeshInner {
    /// Why the connection ended, for a call it found waiting: what
    /// [`Mesh::wait`] reports, or [`DevError::DisconnectedDuringRpc`] after
    /// a clean end. Called only as the driver ends, just before it records
    /// why, so the wait for that is short, and bounded by `deadline`.
    async fn end_reason(&self, deadline: tokio::time::Instant) -> DevError {
        let mut done = self.done_rx.clone();
        let _ = tokio::time::timeout_at(deadline, done.wait_for(|done| *done)).await;
        match self.outcome.lock().as_ref() {
            Some(Err(e)) => e.clone(),
            Some(Ok(())) | None => DevError::DisconnectedDuringRpc,
        }
    }
}

impl Drop for MeshInner {
    /// The last handle may be dropped on one of the runtime's own threads,
    /// where dropping a runtime panics (an abort in release), so it is shut
    /// down without waiting; its threads close the connection and end on
    /// their own. Checked by the unit test
    /// `the_last_handle_may_be_dropped_on_the_runtimes_own_thread`.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// The connection's attach: the name, the key it proves if any, and where
/// its answer goes.
struct AttachCall {
    name: String,
    identity: Option<SigningKey>,
    done: Reply<()>,
}

/// What the driver shares with every `Mesh` handle.
struct Shared {
    callbacks: CallbackMap,
    dispatch: Dispatch,
    /// Rung by a call that timed out.
    cancelled: Arc<Doorbell>,
    /// Replies that came after their call had timed out.
    late_replies: Arc<AtomicU64>,
}

/// How a call that timed out tells the driver to settle what it left
/// behind ([`Driver::settle`]) before taking another call. Its request is
/// withdrawn or taken by then ([`Ticket`]); the ring only frees what the
/// call held.
#[derive(Default)]
struct Doorbell {
    rung: AtomicBool,
    wake: Notify,
}

impl Doorbell {
    fn ring(&self) {
        self.rung.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// Whether it rang since it was last answered.
    fn answer(&self) -> bool {
        self.rung.swap(false, Ordering::AcqRel)
    }
}

/// Whether a call's request goes to the daemon, settled once through this
/// one atomic, by the writer taking it or its caller withdrawing it first,
/// whatever the driver is doing meanwhile. An unsubscribe's is pinned:
/// always written ([`Op::withdrawn_on_timeout`]). Checked in every
/// interleaving by the unit test
/// `a_request_whose_caller_gave_up_first_is_never_written_in_any_order`.
struct Ticket(AtomicU8);

impl Ticket {
    /// Waiting for the writer; either may settle it.
    const QUEUED: u8 = 0;
    /// Taken by the writer: it goes to the daemon.
    const TAKEN: u8 = 1;
    /// Withdrawn by its caller: it is never written.
    const WITHDRAWN: u8 = 2;
    /// An unsubscribe's: the writer takes it, and its caller cannot
    /// withdraw it.
    const PINNED: u8 = 3;

    /// A ticket for a request of `op`.
    fn new(op: Op) -> Self {
        Self(AtomicU8::new(if op.withdrawn_on_timeout() {
            Self::QUEUED
        } else {
            Self::PINNED
        }))
    }

    /// The writer takes the request: `false` when its caller withdrew it
    /// first, and it is not to be written.
    fn take(&self) -> bool {
        match self.0.compare_exchange(
            Self::QUEUED,
            Self::TAKEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(settled) => settled != Self::WITHDRAWN,
        }
    }

    /// The caller withdraws the request: `true` when the writer had not taken
    /// it, and now never will.
    fn withdraw(&self) -> bool {
        match self.0.compare_exchange(
            Self::QUEUED,
            Self::WITHDRAWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(settled) => settled == Self::WITHDRAWN,
        }
    }

    /// Whether the request was withdrawn.
    fn withdrawn(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::WITHDRAWN
    }
}

/// The driver's end of a call: where its answer goes, and the ticket its
/// request carries to the writer.
struct Reply<T> {
    tx: oneshot::Sender<Result<T, DevError>>,
    ticket: Arc<Ticket>,
}

/// The two ends of a call of `op`.
fn call_ends<T>(op: Op) -> (Reply<T>, Waiter<T>) {
    let (tx, rx) = oneshot::channel();
    let ticket = Arc::new(Ticket::new(op));
    let reply = Reply {
        tx,
        ticket: Arc::clone(&ticket),
    };
    (reply, Waiter { rx, ticket })
}

impl<T> Reply<T> {
    /// Answer the call; the answer back when its caller has gone.
    fn send(self, answer: Result<T, DevError>) -> Result<(), Result<T, DevError>> {
        self.tx.send(answer)
    }

    /// Whether the caller has stopped waiting.
    fn caller_gone(&self) -> bool {
        self.tx.is_closed()
    }

    /// Whether the call's request is not to be sent: its caller withdrew it,
    /// or has gone without doing so and the writer has not taken it, in which
    /// case it is withdrawn now.
    fn withdrawn(&self) -> bool {
        self.ticket.withdrawn() || (self.caller_gone() && self.ticket.withdraw())
    }
}

/// The caller's end of a call: where its answer arrives, and the ticket of
/// its request, which a caller that gives up settles. Public, and hidden
/// from the documentation, only for [`Router`]'s callers.
#[doc(hidden)]
pub struct Waiter<T> {
    rx: oneshot::Receiver<Result<T, DevError>>,
    ticket: Arc<Ticket>,
}

impl<T> Waiter<T> {
    /// The answer, once one has come; it is taken.
    pub fn try_answer(&mut self) -> Option<Result<T, DevError>> {
        self.rx.try_recv().ok()
    }

    /// Stop waiting, as a call that times out does. An answer already here
    /// is returned. Otherwise the request is withdrawn unless the writer has
    /// taken it, and the channel closed, so a later reply counts as late;
    /// an answer that raced this is still returned.
    pub fn give_up(&mut self) -> Option<Result<T, DevError>> {
        if let Ok(answer) = self.rx.try_recv() {
            return Some(answer);
        }
        self.ticket.withdraw();
        self.rx.close();
        self.rx.try_recv().ok()
    }

    /// Give up at the deadline ([`Waiter::give_up`]) and, when no answer
    /// had come, ring the driver's doorbell ([`Driver::settle`]).
    fn time_out(&mut self, doorbell: &Doorbell) -> Option<Result<T, DevError>> {
        let answer = self.give_up();
        if answer.is_none() {
            doorbell.ring();
        }
        answer
    }
}

enum Cmd {
    Send {
        channel: String,
        type_name: Option<String>,
        payload: Vec<u8>,
        /// The node it is addressed to, or `None` for the channel's
        /// subscribers.
        to: Option<String>,
        reply: Reply<SendReceipt>,
    },
    Subscribe {
        filter: TapFilter,
        /// Registered when the daemon's ack is routed, before any event for
        /// the subscription can be, and only if the caller still waits.
        /// Checked by the unit test
        /// `event_right_after_the_subscribe_ack_reaches_the_callback`.
        callback: SubscriptionCallback,
        reply: Reply<SubscriptionId>,
    },
    Unsubscribe {
        sub: SubscriptionId,
        /// Answered with the daemon's drop count for the subscription.
        reply: Reply<u64>,
    },
    Detach {
        reply: Reply<()>,
    },
}

impl Cmd {
    /// The call's operation.
    fn op(&self) -> Op {
        match self {
            Cmd::Send { .. } => Op::Send,
            Cmd::Subscribe { .. } => Op::Subscribe,
            Cmd::Unsubscribe { .. } => Op::Unsubscribe,
            Cmd::Detach { .. } => Op::Detach,
        }
    }

    /// Whether the call is not to be sent ([`Reply::withdrawn`]).
    fn withdrawn(&self) -> bool {
        match self {
            Cmd::Send { reply, .. } => reply.withdrawn(),
            Cmd::Subscribe { reply, .. } => reply.withdrawn(),
            Cmd::Unsubscribe { reply, .. } => reply.withdrawn(),
            Cmd::Detach { reply } => reply.withdrawn(),
        }
    }
}

/// A call's operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Attach,
    Send,
    Subscribe,
    Unsubscribe,
    Detach,
}

impl Op {
    /// What a call reports when the command queue is still full at its
    /// deadline.
    fn refused(self) -> DevError {
        DevError::QueueFull { op: self.name() }
    }

    /// The name [`DevError::Timeout`] and [`DevError::QueueFull`] report.
    fn name(self) -> &'static str {
        match self {
            Op::Attach => "attach",
            Op::Send => "send",
            Op::Subscribe => "subscribe",
            Op::Unsubscribe => "unsubscribe",
            Op::Detach => "detach",
        }
    }

    /// Whether a timed-out call's request is withdrawn when the writer has
    /// not taken it. Not an unsubscribe's: its caller drops the callback
    /// whatever the outcome, so the daemon must drop the subscription too,
    /// or go on sending events nobody runs.
    fn withdrawn_on_timeout(self) -> bool {
        self != Op::Unsubscribe
    }
}

impl Mesh {
    /// Attach to a running `mesh-hub` daemon under the given name, at the
    /// first endpoint of: the `PMS_DAEMON` variable (`unix:///path/sock`,
    /// `ws://host:port`, or `wss://host:port` for TLS 1.3, see
    /// [`Endpoint::Ws`]); the socket at [`DEFAULT_UDS_PATH`], if it exists;
    /// the WebSocket at [`DEFAULT_WS_BIND`].
    ///
    /// # Errors
    ///
    /// [`DevError::NoDaemon`] if `PMS_DAEMON` names neither a `unix://` path
    /// nor a `ws://` or `wss://` URL; [`DevError::Transport`] if the client
    /// cannot start or connect; [`DevError::Tls`] if a `wss://` endpoint's
    /// TLS handshake fails, its certificate not trusted say;
    /// [`DevError::Protocol`] if the WebSocket handshake does not
    /// accept the port subprotocol; [`DevError::Daemon`] when the daemon
    /// refuses the attach (`version_unsupported`, `name_in_use`, or
    /// `limit_exceeded` at its connection cap, say); [`DevError::AuthFailed`]
    /// when it refuses the attach's key, or requires one and
    /// [`MeshOptions::identity`] gave none; [`DevError::Timeout`]
    /// if it does not answer within [`MeshOptions::rpc_timeout`];
    /// [`DevError::ReentrantCall`] from inside an async runtime; and, if the
    /// connection ends first, [`DevError::Disconnected`], or
    /// [`DevError::DisconnectedDuringRpc`] if the connection's task stopped
    /// without answering.
    pub fn attach(name: &str) -> Result<Self, DevError> {
        Self::attach_with(name, MeshOptions::default())
    }

    /// Attach with explicit options; without an endpoint, discovery runs as
    /// for [`Mesh::attach`].
    ///
    /// # Errors
    ///
    /// As [`Mesh::attach`]; with an explicit endpoint, never
    /// [`DevError::NoDaemon`].
    pub fn attach_with(name: &str, options: MeshOptions) -> Result<Self, DevError> {
        let endpoint = match options.endpoint.clone() {
            Some(endpoint) => endpoint,
            None => discover_endpoint()?,
        };
        Self::start(name, &options, connect(endpoint, options.tls_roots.clone()))
    }

    /// Attach over the connection `link` brings up: `connect`'s, or in the
    /// tests a fake transport's.
    fn start(
        name: &str,
        options: &MeshOptions,
        link: impl Future<Output = Result<Link, DevError>> + Send + 'static,
    ) -> Result<Self, DevError> {
        ensure_not_in_runtime()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("dev-functions")
            .build()
            .map_err(|e| DevError::Transport(format!("runtime build: {}", e)))?;

        let (cmd_tx, cmd_rx) = command_queue();
        let callbacks: CallbackMap = Arc::new(Mutex::new(HashMap::new()));
        let cancelled = Arc::new(Doorbell::default());
        let late_replies = Arc::new(AtomicU64::new(0));
        let (attach_tx, attach_rx) = call_ends::<()>(Op::Attach);
        let (done_tx, done_rx) = watch::channel(false);
        let outcome: Arc<Mutex<Option<Result<(), DevError>>>> = Arc::new(Mutex::new(None));

        // Callbacks run on their own thread, outside every runtime, so a
        // callback may call back into the mesh and a slow one stalls no
        // reply; one consumer keeps the events in order.
        let (dispatch, dispatch_rx) = Dispatch::new(options.event_queue, options.event_queue_bytes);
        let events = Arc::clone(&dispatch.counts);
        let cb_for_dispatch = callbacks.clone();
        std::thread::Builder::new()
            .name("dev-hub-dispatch".into())
            .spawn(move || {
                for Queued { event, charge } in dispatch_rx {
                    let callback = cb_for_dispatch.lock().get(&event.subscription_id).cloned();
                    if let Some(callback) = callback {
                        let sub = event.subscription_id.clone();
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                callback(event)
                            }));
                        if outcome.is_err() {
                            tracing::error!(sub = %sub.0, "subscription callback panicked");
                        }
                    }
                    // The event's bytes count until its callback has run.
                    drop(charge);
                }
                // No callback can run again: drop them all, outside the
                // lock, so the handles they hold are let go.
                let released = std::mem::take(&mut *cb_for_dispatch.lock());
                drop(released);
            })
            .map_err(|e| DevError::Transport(format!("dispatch thread: {}", e)))?;

        let attach = AttachCall {
            name: name.to_string(),
            identity: options.identity.clone(),
            done: attach_tx,
        };
        let shared = Shared {
            callbacks: callbacks.clone(),
            dispatch,
            cancelled: cancelled.clone(),
            late_replies: late_replies.clone(),
        };
        let outcome_for_task = outcome.clone();
        let heartbeat_interval = options.heartbeat_interval;
        let silence_limit = options.silence_limit;
        runtime.spawn(async move {
            let result = match link.await {
                Ok(link) => {
                    drive(
                        attach,
                        link,
                        cmd_rx,
                        shared,
                        heartbeat_interval,
                        silence_limit,
                    )
                    .await
                }
                Err(e) => {
                    // The attach's answer, not an unexplained disconnect.
                    let _ = attach.done.send(Err(e.clone()));
                    Err(e)
                }
            };
            if let Err(ref e) = result {
                tracing::warn!(error = %e, "dev-hub connection ended");
            }
            *outcome_for_task.lock() = Some(result);
            let _ = done_tx.send(true);
        });

        // The deadline is made inside the runtime, whose clock it needs.
        let rpc_timeout = options.rpc_timeout;
        let attached = runtime.block_on(async {
            tokio::time::timeout_at(deadline_after(rpc_timeout), attach_rx.rx).await
        });
        match attached {
            Ok(Ok(reply)) => reply?,
            Ok(Err(_)) => return Err(DevError::DisconnectedDuringRpc),
            Err(_) => {
                return Err(DevError::Timeout {
                    op: "attach",
                    after: rpc_timeout,
                })
            }
        }

        Ok(Mesh {
            inner: Arc::new(MeshInner {
                handle: runtime.handle().clone(),
                runtime: Some(runtime),
                cmd_tx,
                cancelled,
                late_replies,
                callbacks,
                events,
                rpc_timeout,
                outcome,
                done_rx,
            }),
        })
    }

    /// A handle that does not keep the connection open ([`WeakMesh`]).
    #[must_use]
    pub fn downgrade(&self) -> WeakMesh {
        WeakMesh {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Wait for the connection to end, and say why; `Ok` only after a
    /// detach the daemon acknowledged.
    ///
    /// # Errors
    ///
    /// [`DevError::Daemon`] when the daemon's last word was an error that
    /// answered no request (`payload_too_large` after a frame over its
    /// limit, say); [`DevError::Disconnected`] when the daemon closed the
    /// connection without one, or a write failed; [`DevError::Silent`] when
    /// the daemon went silent; [`DevError::ReentrantCall`] from inside an
    /// async runtime; or the driver's own error.
    pub fn wait(&self) -> Result<(), DevError> {
        ensure_not_in_runtime()?;
        let mut done = self.inner.done_rx.clone();
        self.inner.handle.block_on(async move {
            while !*done.borrow() {
                if done.changed().await.is_err() {
                    break;
                }
            }
        });
        match self.inner.outcome.lock().as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.clone()),
            None => Err(DevError::Disconnected),
        }
    }

    /// Hand one call of `op` to the driver and wait for its reply, both
    /// within `rpc_timeout`: [`DevError::QueueFull`] if the command queue
    /// has no room by then, and a timeout cancels the call
    /// ([`Waiter::time_out`]). A call the connection's end finds waiting,
    /// wherever it waits, reports why it ended ([`MeshInner::end_reason`]).
    fn call<T>(&self, op: Op, make: impl FnOnce(Reply<T>) -> Cmd) -> Result<T, DevError> {
        ensure_not_in_runtime()?;
        if self.inner.cmd_tx.is_closed() {
            return Err(DevError::DisconnectedDuringRpc);
        }
        let (reply, mut waiter) = call_ends(op);
        let cmd = make(reply);
        let after = self.inner.rpc_timeout;
        // Made inside the runtime, whose clock the timers need.
        self.inner.handle.block_on(async {
            let deadline = deadline_after(after);
            match tokio::time::timeout_at(deadline, self.inner.cmd_tx.send(cmd)).await {
                Ok(Ok(())) => {}
                // The connection ended while the call waited for room.
                Ok(Err(_)) => return Err(self.inner.end_reason(deadline).await),
                // Dropped unsent: the driver never saw it.
                Err(_) => return Err(op.refused()),
            }
            match tokio::time::timeout_at(deadline, &mut waiter.rx).await {
                Ok(Ok(answer)) => answer,
                // The connection ended without answering the call: it was
                // still in the command queue, or behind an acknowledged
                // detach.
                Ok(Err(_)) => Err(self.inner.end_reason(deadline).await),
                Err(_) => match waiter.time_out(&self.inner.cancelled) {
                    Some(answer) => answer,
                    None => Err(DevError::Timeout {
                        op: op.name(),
                        after,
                    }),
                },
            }
        })
    }

    /// Publish an envelope to a channel and return its id.
    ///
    /// # Errors
    ///
    /// As [`Self::send_with_receipt`].
    pub fn send(&self, channel: &str, payload: &[u8]) -> Result<String, DevError> {
        self.send_typed(channel, None, payload)
    }

    /// Publish with an explicit type name and return the envelope's id.
    ///
    /// # Errors
    ///
    /// As [`Self::send_with_receipt`].
    pub fn send_typed(
        &self,
        channel: &str,
        type_name: Option<&str>,
        payload: &[u8],
    ) -> Result<String, DevError> {
        self.send_with_receipt(channel, type_name, payload)
            .map(|receipt| receipt.envelope_id)
    }

    /// Publish, with or without a type name, and return the daemon's
    /// receipt (see [`SendReceipt::persisted`]).
    ///
    /// # Errors
    ///
    /// [`DevError::Daemon`] when the daemon rejects the publish
    /// (`bad_request`, `not_attached`, or `payload_too_large` for a frame
    /// over its limit, after which it closes the connection); and the
    /// errors every call can meet: [`DevError::QueueFull`] and
    /// [`DevError::Timeout`] at the deadline, [`DevError::ReentrantCall`]
    /// from inside an async runtime, how the connection ended if it ends
    /// first (see [`Mesh::wait`]), and [`DevError::DisconnectedDuringRpc`]
    /// if it had already ended.
    pub fn send_with_receipt(
        &self,
        channel: &str,
        type_name: Option<&str>,
        payload: &[u8],
    ) -> Result<SendReceipt, DevError> {
        self.call(Op::Send, |reply| Cmd::Send {
            channel: channel.to_string(),
            type_name: type_name.map(String::from),
            payload: payload.to_vec(),
            to: None,
            reply,
        })
    }

    /// Send an envelope on `channel` to the node `dest` alone, and return
    /// the daemon's receipt, whose [`SendReceipt::delivered`] says how it
    /// went. `dest` is a node id as its attach was acked with
    /// (`name@hex`), for a node on the same daemon, or a node's qualified
    /// id across linked daemons, `name@` and the 16 hex digits of the daemon
    /// it is attached to. Only that node's subscriptions that match the send
    /// get it; no other subscriber does, and the daemon neither stores it nor
    /// forwards it to any daemon but the node's.
    ///
    /// # Errors
    ///
    /// [`DevError::Daemon`] with code `unknown_destination` when the daemon
    /// knows no such node (none attached to it, and none a linked daemon
    /// announced), and otherwise as [`Self::send_with_receipt`].
    pub fn send_to(
        &self,
        dest: &str,
        channel: &str,
        payload: &[u8],
    ) -> Result<SendReceipt, DevError> {
        self.send_typed_to(dest, channel, None, payload)
    }

    /// [`Self::send_to`] with a type name, or none.
    ///
    /// # Errors
    ///
    /// As [`Self::send_to`].
    pub fn send_typed_to(
        &self,
        dest: &str,
        channel: &str,
        type_name: Option<&str>,
        payload: &[u8],
    ) -> Result<SendReceipt, DevError> {
        self.call(Op::Send, |reply| Cmd::Send {
            channel: channel.to_string(),
            type_name: type_name.map(String::from),
            payload: payload.to_vec(),
            to: Some(dest.to_string()),
            reply,
        })
    }

    /// Subscribe to a channel, as [`Self::tap`].
    ///
    /// # Errors
    ///
    /// As [`Self::tap`].
    pub fn on<F>(&self, channel: &str, callback: F) -> Result<SubscriptionId, DevError>
    where
        F: Fn(MeshEvent) + Send + Sync + 'static,
    {
        self.tap(
            TapFilter {
                channel: Some(channel.to_string()),
                ..Default::default()
            },
            callback,
        )
    }

    /// Subscribe with a full filter. The callback runs for every matching
    /// event on the connection's callback thread, one event at a time and
    /// in order, and may call back into the mesh (through a [`WeakMesh`]).
    ///
    /// # Errors
    ///
    /// [`DevError::Daemon`] when the daemon rejects the subscription
    /// (`bad_filter`, or `limit_exceeded` past its per-connection cap);
    /// [`DevError::Timeout`], after which the callback never runs (see
    /// [`Mesh::late_replies`]); and the other errors every call can meet
    /// (see [`Self::send_with_receipt`]).
    pub fn tap<F>(&self, filter: TapFilter, callback: F) -> Result<SubscriptionId, DevError>
    where
        F: Fn(MeshEvent) + Send + Sync + 'static,
    {
        self.call(Op::Subscribe, |reply| Cmd::Subscribe {
            filter,
            callback: Arc::new(callback),
            reply,
        })
    }

    /// Drop a subscription, and return how many of its events the daemon
    /// dropped because this connection fell behind (the daemon's
    /// `--subscriber-queue`); the client's own drops are
    /// [`Mesh::events_dropped`].
    ///
    /// The callback is removed whatever the outcome, unless the call was
    /// refused before anything was sent ([`DevError::QueueFull`],
    /// [`DevError::ReentrantCall`]). An unsubscribe that times out is still
    /// sent, so the daemon drops the subscription too.
    ///
    /// # Errors
    ///
    /// [`DevError::Daemon`] when the daemon knows no such subscription; and
    /// the errors every call can meet (see [`Self::send_with_receipt`]).
    pub fn unsubscribe(&self, sub: SubscriptionId) -> Result<u64, DevError> {
        let result = self.call(Op::Unsubscribe, |reply| Cmd::Unsubscribe {
            sub: sub.clone(),
            reply,
        });
        if !matches!(
            result,
            Err(DevError::QueueFull { .. } | DevError::ReentrantCall)
        ) {
            // Dropped outside the lock, with whatever the callback holds.
            let removed = self.inner.callbacks.lock().remove(&sub);
            drop(removed);
        }
        result
    }

    /// How many events the daemon delivered and this client dropped, its
    /// event queue full ([`MeshOptions::event_queue`] and
    /// [`MeshOptions::event_queue_bytes`]), across every subscription and
    /// clone of this handle since attach. A callback slower than its events
    /// loses the newest ones; replies are never dropped. The daemon's own
    /// drops are [`Mesh::unsubscribe`]'s. Checked by `tests/event_queue.rs`.
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        self.inner.events.dropped.load(Ordering::Relaxed)
    }

    /// How many events this client dropped because their payload was not
    /// valid base64, across every subscription and clone of this handle
    /// since attach. A conforming daemon sends none; a callback never
    /// receives such bytes. Not in [`Mesh::events_dropped`].
    #[must_use]
    pub fn events_malformed(&self) -> u64 {
        self.inner.events.malformed.load(Ordering::Relaxed)
    }

    /// How many replies arrived after their call had timed out, across
    /// every clone of this handle since attach.
    ///
    /// A call that times out ([`DevError::Timeout`]) is cancelled. A request
    /// the transport had not begun to write is withdrawn: never written, and
    /// never answered. Otherwise the reply is dropped when it comes and
    /// counted here; for a subscribe, the subscription the daemon made is
    /// released at once, its callback never run. An unsubscribe is never
    /// withdrawn, so its reply is counted here. Checked by
    /// `tests/timeouts.rs`.
    #[must_use]
    pub fn late_replies(&self) -> u64 {
        self.inner.late_replies.load(Ordering::Relaxed)
    }

    /// Block until the connection ends, as [`Mesh::wait`]: the usual last
    /// call in `main` once subscriptions are registered.
    ///
    /// # Errors
    ///
    /// As [`Mesh::wait`].
    pub fn run(&self) -> Result<(), DevError> {
        self.wait()
    }

    /// Detach cleanly: the daemon releases this client's name and
    /// subscriptions, acknowledges and closes the connection, and
    /// [`Mesh::wait`] then returns `Ok`. The callbacks are dropped once the
    /// events already queued for them have run.
    ///
    /// Dropping the last `Mesh` instead closes the connection without a
    /// detach: requests not yet written are discarded, and the daemon
    /// releases the name when it sees the connection close.
    ///
    /// # Errors
    ///
    /// The errors every call can meet (see [`Self::send_with_receipt`]); a
    /// connection that ends before the daemon acknowledges is not a clean
    /// end. After [`DevError::Timeout`] a detach not yet written is
    /// withdrawn, and the connection stays attached.
    pub fn detach(&self) -> Result<(), DevError> {
        self.call(Op::Detach, |reply| Cmd::Detach { reply })
    }
}

// ---- Endpoint discovery ----------------------------------------------------

/// Where a `mesh-hub` daemon answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix-domain socket at this path.
    Uds(String),
    /// A WebSocket URL: `ws://host:port`, or `wss://host:port` for TLS 1.3,
    /// whose handshake verifies the daemon's certificate against the roots
    /// [`MeshOptions::tls_roots`] describes and the host, which it also
    /// indicates (SNI).
    Ws(String),
}

/// The instant `after` from now on tokio's clock, at most [`FAR_FUTURE`]
/// out. Every deadline the client sets is made so, or by [`later`]: one
/// near the end of `Instant`'s range, which tokio's timer rounds past the
/// end, aborts a release build. Checked by the unit test
/// `every_deadline_lies_well_inside_the_timers_range`.
fn deadline_after(after: Duration) -> tokio::time::Instant {
    later(tokio::time::Instant::now(), after)
}

/// The instant `after` past `from`, or [`FAR_FUTURE`] past it for a longer
/// span (see [`deadline_after`]).
fn later(from: tokio::time::Instant, after: Duration) -> tokio::time::Instant {
    from + after.min(FAR_FUTURE)
}

/// The furthest deadline the client sets: thirty years, tokio's own span
/// for a timer that never comes.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// Refuse a call from a thread in a runtime's context
/// ([`DevError::ReentrantCall`]).
fn ensure_not_in_runtime() -> Result<(), DevError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(DevError::ReentrantCall);
    }
    Ok(())
}

fn discover_endpoint() -> Result<Endpoint, DevError> {
    if let Ok(d) = std::env::var("PMS_DAEMON") {
        return named_endpoint(d);
    }
    if Path::new(DEFAULT_UDS_PATH).exists() {
        return Ok(Endpoint::Uds(DEFAULT_UDS_PATH.to_string()));
    }
    Ok(Endpoint::Ws(format!("ws://{DEFAULT_WS_BIND}")))
}

/// The endpoint `PMS_DAEMON` names: a `unix://` path, or a `ws://` or
/// `wss://` URL.
fn named_endpoint(d: String) -> Result<Endpoint, DevError> {
    if let Some(p) = d.strip_prefix("unix://") {
        return Ok(Endpoint::Uds(p.to_string()));
    }
    if d.starts_with("ws://") || d.starts_with("wss://") {
        return Ok(Endpoint::Ws(d));
    }
    Err(DevError::NoDaemon)
}

// ---- Outbox: frames on their way to the daemon -----------------------------

/// Frames on their way to the daemon, shared by the driver, which queues
/// them and removes the requests of calls that timed out, and the writer,
/// which takes them one at a time, skipping a request withdrawn first
/// ([`Ticket`]): every frame but the one being written can be withdrawn.
#[derive(Default)]
struct Outbox {
    state: Mutex<OutboxState>,
    /// Wakes the writer: a frame was queued, or the driver ended.
    wake_writer: Notify,
    /// Wakes the driver: the writer took a request off the queue, so there
    /// may be room for another call.
    room: Notify,
}

#[derive(Default)]
struct OutboxState {
    /// Frames waiting for the writer, oldest first.
    frames: VecDeque<Outgoing>,
    /// How many of `frames` carry a call's request: what
    /// [`OUTBOUND_QUEUE`] bounds.
    requests: usize,
    /// The driver has ended: the writer writes what is left, then stops.
    driver_gone: bool,
    /// The writer has stopped: nothing queued will be written.
    writer_gone: bool,
}

/// One frame for the daemon: the JSON the transport sends.
struct Outgoing {
    /// The number of the request a caller waits on, or `None` for the
    /// client's own frames, which are never withdrawn.
    request: Option<u64>,
    /// The request's ticket, which the writer settles when it takes the
    /// frame; `None` for the client's own frames.
    ticket: Option<Arc<Ticket>>,
    text: String,
}

/// The driver's end of the outbox. Dropping it lets the writer finish what
/// is queued and stop.
struct OutboxTx {
    shared: Arc<Outbox>,
    /// Completes when the writer's end is dropped; `None` once it has.
    writer_gone: Option<oneshot::Receiver<()>>,
}

/// The transport writer's end of the outbox. Dropping it discards what is
/// queued and tells the driver.
struct OutboxRx {
    shared: Arc<Outbox>,
    /// Dropped with this end, which completes the driver's `writer_gone`.
    _alive: oneshot::Sender<()>,
}

/// A new, empty outbox's two ends.
fn outbox() -> (OutboxTx, OutboxRx) {
    let shared = Arc::new(Outbox::default());
    let (alive, writer_gone) = oneshot::channel();
    (
        OutboxTx {
            shared: Arc::clone(&shared),
            writer_gone: Some(writer_gone),
        },
        OutboxRx {
            shared,
            _alive: alive,
        },
    )
}

impl OutboxTx {
    /// Queue a frame for the writer; `false` when the writer has stopped,
    /// so the frame would never be written.
    fn push(&self, frame: Outgoing) -> bool {
        {
            let mut state = self.shared.state.lock();
            if state.writer_gone {
                return false;
            }
            state.requests += usize::from(frame.request.is_some());
            state.frames.push_back(frame);
        }
        self.shared.wake_writer.notify_one();
        true
    }

    /// Whether no frame waits for the writer.
    fn is_empty(&self) -> bool {
        self.shared.state.lock().frames.is_empty()
    }

    /// How many requests wait for the writer.
    fn requests(&self) -> usize {
        self.shared.state.lock().requests
    }

    /// Whether fewer than [`OUTBOUND_QUEUE`] requests wait for the writer,
    /// so the driver may take another call.
    fn has_room(&self) -> bool {
        self.requests() < OUTBOUND_QUEUE
    }

    /// Complete when the writer next takes a request off the queue, or at
    /// once if it did since the last wake-up was taken. Borrows nothing, so
    /// it can wait beside the driver's other business.
    fn room(&self) -> impl Future<Output = ()> + Send + 'static {
        let shared = Arc::clone(&self.shared);
        async move { shared.room.notified().await }
    }

    /// Remove every waiting request that `pick` picks, so it holds no memory
    /// and no room in the queue.
    fn remove(&self, mut pick: impl FnMut(u64) -> bool) {
        let mut state = self.shared.state.lock();
        let before = state.frames.len();
        state
            .frames
            .retain(|frame| !frame.request.is_some_and(&mut pick));
        let removed = before - state.frames.len();
        state.requests -= removed;
    }

    /// Complete when the writer has stopped; at once if it already has.
    async fn closed(&mut self) {
        if let Some(gone) = self.writer_gone.as_mut() {
            let _ = gone.await;
            self.writer_gone = None;
        }
    }
}

impl Drop for OutboxTx {
    fn drop(&mut self) {
        self.shared.state.lock().driver_gone = true;
        self.shared.wake_writer.notify_one();
    }
}

impl OutboxRx {
    /// The next frame to write, once there is one; `None` when the driver
    /// has ended and nothing is left.
    async fn recv(&mut self) -> Option<String> {
        loop {
            match self.pop() {
                Popped::Frame(text) => return Some(text),
                Popped::Ended => return None,
                Popped::Empty => {}
            }
            // A frame queued since the check stored a permit, so this
            // cannot miss it.
            self.shared.wake_writer.notified().await;
        }
    }

    /// Take the oldest waiting frame, without waiting for one. A request
    /// whose caller withdrew it before this is skipped, never written.
    fn pop(&mut self) -> Popped {
        let mut took_request = false;
        let popped = {
            let mut state = self.shared.state.lock();
            loop {
                let Some(frame) = state.frames.pop_front() else {
                    break if state.driver_gone {
                        Popped::Ended
                    } else {
                        Popped::Empty
                    };
                };
                if frame.request.is_some() {
                    state.requests -= 1;
                    took_request = true;
                }
                if frame.ticket.as_ref().is_some_and(|ticket| !ticket.take()) {
                    continue;
                }
                break Popped::Frame(frame.text);
            }
        };
        if took_request {
            self.shared.room.notify_one();
        }
        popped
    }
}

/// What the writer found in the outbox.
enum Popped {
    /// The oldest waiting frame, now the writer's.
    Frame(String),
    /// Nothing waits, and the driver has ended.
    Ended,
    /// Nothing waits yet.
    Empty,
}

impl Drop for OutboxRx {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        state.writer_gone = true;
        state.frames.clear();
        state.requests = 0;
    }
}

// ---- Driver: one connection, one event loop --------------------------------

/// The driver's ends of one connection's transport: the messages its reader
/// decoded, and the outbox its writer writes from. The reader drops the far
/// end of the first when the connection ends, and the writer drops its end
/// of the outbox when a write fails.
struct Link {
    inbound: mpsc::Receiver<Received>,
    outbound: OutboxTx,
    /// When the reader last heard from the daemon.
    heard: Arc<Heard>,
    /// The transport's own ends.
    io: Io,
}

/// What the driver holds of a transport beside its queues: how to ping the
/// daemon, and the reader's and the writer's tasks, which it aborts when it
/// gives a silent daemon up, so the connection closes though neither will
/// ever finish.
#[derive(Default)]
struct Io {
    /// Wakes the writer to ping the daemon; `None` for a transport without
    /// a ping, the Unix socket.
    ping: Option<Arc<Notify>>,
    /// The reader's and the writer's tasks.
    tasks: Vec<tokio::task::AbortHandle>,
    /// What a proof of the client's key is bound to: on `wss://` the TLS
    /// exporter value, and zeros in plaintext ([`attach::NO_EXPORTER`]).
    exporter: [u8; attach::EXPORTER_LEN],
}

/// Connect to `endpoint` and start the connection's reader and writer; a
/// `wss://` endpoint's certificate may chain to `tls_roots` (PEM) as well as
/// to webpki-roots'.
async fn connect(endpoint: Endpoint, tls_roots: Vec<Vec<u8>>) -> Result<Link, DevError> {
    // The reader waits for room, so a flood waits in the socket. That cannot
    // deadlock only because routing never waits: an event goes to the
    // callback thread by `try_send`, a reply to its caller's oneshot, a
    // frame to the outbox.
    let (inbound_tx, inbound) = inbound_queue(INBOUND_QUEUE, INBOUND_QUEUE_BYTES);
    let heard = inbound_tx.heard();
    let (outbound, outbound_rx) = outbox();
    let io = match endpoint {
        Endpoint::Uds(path) => spawn_uds_io(path, inbound_tx, outbound_rx).await?,
        Endpoint::Ws(url) => spawn_ws_io(url, &tls_roots, inbound_tx, outbound_rx).await?,
    };
    Ok(Link {
        inbound,
        outbound,
        heard,
        io,
    })
}

/// How long the driver reads on after a write failed: a closing daemon's
/// reason (`payload_too_large`, say) is already in the socket and comes at
/// once; the bound is for a peer that stopped reading but not writing.
/// Checked by the unit test `the_daemons_reason_survives_a_failed_write`.
const DRAIN_AFTER_WRITE_FAILURE: Duration = Duration::from_millis(250);

/// The idle heartbeat's timer, ticking every `period` from one `period`
/// past `from`; `None` for a period of zero. The period is at most
/// [`FAR_FUTURE`]: tokio's interval adds it to the clock when a tick comes
/// late, which for `Duration::MAX` aborts a release build.
fn heartbeat_timer(from: tokio::time::Instant, period: Duration) -> Option<tokio::time::Interval> {
    let period = period.min(FAR_FUTURE);
    (!period.is_zero()).then(|| {
        let mut interval = tokio::time::interval_at(later(from, period), period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval
    })
}

/// The rule that gives up a daemon silent while the client waits for it
/// ([`MeshOptions::silence_limit`]), judged from when it was last heard
/// from ([`Heard`]): with a ping, one ping per silence at a third of the
/// limit and the daemon given up at the limit; without one, the limit runs
/// only while an answer is owed. Checked by the unit tests of `Silence`.
struct Silence {
    /// How long the daemon may be silent while the client waits for it.
    limit: Duration,
    /// How long after the daemon was last heard from the client pings it;
    /// `None` on a transport without a ping.
    ping_after: Option<Duration>,
    /// When the daemon had last been heard from as the client pinged it, so
    /// that it pings once per silence.
    pinged: Option<tokio::time::Instant>,
    /// When the client gives up a daemon it pinged.
    give_up: tokio::time::Instant,
    /// Since when the daemon has owed an answer, on a transport without a
    /// ping.
    owed_since: Option<tokio::time::Instant>,
}

/// What [`Silence::judge`] finds.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Nothing to do until this instant, or, with `None`, until something
    /// else happens.
    Until(Option<tokio::time::Instant>),
    /// Ping the daemon now, and look again at this instant.
    Ping(tokio::time::Instant),
    /// The daemon has been silent past the limit while the client waited
    /// for it.
    Silent,
}

impl Silence {
    /// The rule for `limit` on a transport that can ping the daemon or not;
    /// `None` for a limit of zero, which disables it. A limit too long for
    /// the clock is taken as [`FAR_FUTURE`], which no connection outlives.
    fn new(limit: Duration, can_ping: bool) -> Option<Self> {
        if limit.is_zero() {
            return None;
        }
        let limit = limit.min(FAR_FUTURE);
        Some(Self {
            limit,
            ping_after: can_ping.then(|| limit / 3),
            pinged: None,
            give_up: tokio::time::Instant::now(),
            owed_since: None,
        })
    }

    /// Judge the silence at `now`, the daemon last heard from at `heard`,
    /// owing the client an answer or not.
    fn judge(
        &mut self,
        now: tokio::time::Instant,
        heard: tokio::time::Instant,
        owed: bool,
    ) -> Verdict {
        let Some(ping_after) = self.ping_after else {
            // No ping: the limit runs only while the daemon owes an answer,
            // from when it came to owe one or was last heard from.
            if !owed {
                self.owed_since = None;
                return Verdict::Until(None);
            }
            let since = *self.owed_since.get_or_insert(now);
            let give_up = later(heard.max(since), self.limit);
            return if now < give_up {
                Verdict::Until(Some(give_up))
            } else {
                Verdict::Silent
            };
        };
        if self.pinged != Some(heard) {
            let ping_at = later(heard, ping_after);
            if now < ping_at {
                return Verdict::Until(Some(ping_at));
            }
            self.pinged = Some(heard);
            // However late the ping, the answer has the rest of the limit
            // from it: a client held up itself does not give the daemon up
            // without asking.
            self.give_up = later(heard, self.limit).max(later(now, self.limit - ping_after));
            return Verdict::Ping(self.give_up);
        }
        if now < self.give_up {
            Verdict::Until(Some(self.give_up))
        } else {
            Verdict::Silent
        }
    }
}

/// Drive one connection: attach, then carry the caller's commands out and
/// the daemon's messages in until the connection ends, which `conclude`
/// turns into the result `wait` reports, or until the daemon goes silent
/// past the limit while the client waits for it ([`Silence`]).
async fn drive(
    attach: AttachCall,
    link: Link,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    shared: Shared,
    heartbeat_interval: Duration,
    silence_limit: Duration,
) -> Result<(), DevError> {
    let Link {
        mut inbound,
        outbound,
        heard,
        io,
    } = link;
    let Shared {
        callbacks,
        dispatch,
        cancelled,
        late_replies,
    } = shared;
    let mut driver = Driver::new(
        outbound,
        callbacks,
        dispatch,
        late_replies,
        Arc::clone(&cancelled),
        MAX_ABANDONED,
    );
    driver.exporter = io.exporter;

    // Set once a write fails: the connection then ends when the reader has
    // delivered what the daemon sent, or at this deadline.
    let mut drain_until: Option<tokio::time::Instant> = None;
    let write_failed = || Some(tokio::time::Instant::now() + DRAIN_AFTER_WRITE_FAILURE);

    if !driver.attach(attach.name, attach.identity, attach.done)? {
        drain_until = write_failed();
    }

    let mut last_outbound = tokio::time::Instant::now();
    let heartbeat_period = heartbeat_interval.min(FAR_FUTURE);
    let mut heartbeat = heartbeat_timer(last_outbound, heartbeat_period);
    let mut silence = Silence::new(silence_limit, io.ping.is_some());
    // The silence rule's timer, set again rather than made anew each turn;
    // it is waited on only while `silence_due` is set.
    let silence_timer = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(silence_timer);
    let mut silence_due = false;
    loop {
        driver.settle();
        // Not judged after a failed write: the connection ends sooner.
        if let (Some(rule), None) = (silence.as_mut(), drain_until) {
            let now = tokio::time::Instant::now();
            let due = match rule.judge(now, heard.last(), driver.owes()) {
                Verdict::Until(due) => due,
                Verdict::Ping(due) => {
                    if let Some(ping) = &io.ping {
                        ping.notify_one();
                    }
                    Some(due)
                }
                Verdict::Silent => {
                    // Neither the reader nor the writer will finish against
                    // a daemon that stopped: close the connection under
                    // them.
                    for task in &io.tasks {
                        task.abort();
                    }
                    return driver.give_up(rule.limit);
                }
            };
            silence_due = due.is_some();
            if let Some(due) = due {
                if silence_timer.deadline() != due {
                    silence_timer.as_mut().reset(due);
                }
            }
        }
        let drain_deadline = drain_until;
        let room = driver.may_take();
        tokio::select! {
            cmd = cmd_rx.recv(), if drain_until.is_none() && room => {
                let Some(cmd) = cmd else {
                    // Every handle is gone, and with it anyone to tell:
                    // dropping the last one is the caller's own end.
                    return Ok(());
                };
                match driver.take(cmd)? {
                    Took::Queued => last_outbound = tokio::time::Instant::now(),
                    Took::Nothing => {}
                    Took::WriterGone => drain_until = write_failed(),
                }
            }
            // The writer took a request: there may be room for a call.
            () = driver.outbox.room(), if drain_until.is_none() && !room => {}
            // A call timed out while the driver waited: the sweep is at the
            // top of the loop.
            () = cancelled.wake.notified() => {}
            // The idle heartbeat, only when no frame waits: a waiting frame
            // is traffic the daemon will see, and a daemon that stopped
            // reading must not collect heartbeats.
            _ = async {
                match heartbeat.as_mut() {
                    Some(interval) => {
                        interval.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            }, if drain_until.is_none() => {
                if last_outbound.elapsed() >= heartbeat_period && driver.outbox.is_empty() {
                    let frame = serde_json::to_string(&ClientMessage::Health {
                        state: Some("ok".into()),
                    })
                    .map_err(|e| DevError::Protocol(e.to_string()))?;
                    let heartbeat = Outgoing {
                        request: None,
                        ticket: None,
                        text: frame,
                    };
                    if !driver.outbox.push(heartbeat) {
                        drain_until = write_failed();
                        continue;
                    }
                    last_outbound = tokio::time::Instant::now();
                }
            }
            // The writer stops only when a write fails.
            () = driver.outbox.closed(), if drain_until.is_none() => {
                drain_until = write_failed();
            }
            // A deadline of the silence limit: judged at the top of the loop.
            () = &mut silence_timer, if silence_due && drain_until.is_none() => {
                silence_due = false;
            }
            // A write failed a while ago, and the reader has had its chance.
            () = async move {
                match drain_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                return driver.conclude();
            }
            inbound_msg = inbound.recv() => {
                let Some(Received { message, charge }) = inbound_msg else {
                    // The reader ended with the connection.
                    return driver.conclude();
                };
                driver.route(message);
                // Its bytes count against the reader's budget until now.
                drop(charge);
            }
        }
    }
}

/// What the driver did with a call it took off the command queue.
enum Took {
    /// Its request waits in the outbox.
    Queued,
    /// Nothing was queued: its caller had given up, and its request is
    /// never sent.
    Nothing,
    /// The writer has stopped, so nothing more reaches the daemon.
    WriterGone,
}

/// The id a request carries on the wire.
fn request_id(request: u64) -> String {
    format!("req-{request}")
}

/// The number in an id this client gave a request; `None` for any other id.
fn request_number(id: &str) -> Option<u64> {
    id.strip_prefix("req-")?.parse().ok()
}

/// One connection's state, owned by the task that drives it.
struct Driver {
    /// The requests waiting for the daemon's reply, by the number their id
    /// carries, so the oldest come first.
    pending: BTreeMap<u64, OneOfPending>,
    /// How many of `pending` nobody waits on, abandoned calls and the
    /// client's own releases, at most `max_abandoned`.
    abandoned: usize,
    /// How many requests nobody waits on are kept: [`MAX_ABANDONED`] in a
    /// client.
    max_abandoned: usize,
    /// Rung by a call that timed out ([`Waiter::time_out`]); the driver
    /// answers it at the top of each turn ([`Driver::settle`]).
    cancelled: Arc<Doorbell>,
    /// The number the next request carries.
    next_request: u64,
    outbox: OutboxTx,
    callbacks: CallbackMap,
    dispatch: Dispatch,
    /// Replies that came after their call had timed out.
    late_replies: Arc<AtomicU64>,
    /// The daemon acknowledged the detach the caller asked for.
    detached: bool,
    /// An error that answered no request, while it is the last thing the
    /// daemon said: if the connection ends next, it is the reason.
    last_word: Option<DevError>,
    /// The key the attach proves, if it carries one, until its challenge
    /// is answered.
    identity: Option<Identity>,
    /// What a proof on this connection is bound to ([`Io::exporter`]).
    exporter: [u8; attach::EXPORTER_LEN],
}

/// The key a keyed attach proves, and the name the proof covers.
struct Identity {
    key: SigningKey,
    name: String,
    /// The attach's request number, which its challenge names.
    request: u64,
}

impl Driver {
    fn new(
        outbox: OutboxTx,
        callbacks: CallbackMap,
        dispatch: Dispatch,
        late_replies: Arc<AtomicU64>,
        cancelled: Arc<Doorbell>,
        max_abandoned: usize,
    ) -> Self {
        Self {
            pending: BTreeMap::new(),
            abandoned: 0,
            max_abandoned,
            cancelled,
            next_request: 1,
            outbox,
            callbacks,
            dispatch,
            late_replies,
            detached: false,
            last_word: None,
            identity: None,
            exporter: attach::NO_EXPORTER,
        }
    }

    /// Queue the attach under the client's `name`, the connection's first
    /// request, as one that `done` answers; with `identity`, it carries the
    /// key's public half, and the daemon's challenge to it is answered
    /// ([`Self::answer_challenge`]). `Ok(false)` when the writer has stopped,
    /// as [`Self::submit`] says.
    fn attach(
        &mut self,
        name: String,
        identity: Option<SigningKey>,
        done: Reply<()>,
    ) -> Result<bool, DevError> {
        let key = identity
            .as_ref()
            .map(|key| attach::encode_key(&key.verifying_key().to_bytes()));
        self.identity = identity.map(|key| Identity {
            key,
            name: name.clone(),
            request: self.next_request,
        });
        self.submit(OneOfPending::Attach(done), |id| ClientMessage::Attach {
            id,
            name,
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: vec!["send".into(), "subscribe".into(), "tap".into()],
            key,
        })
    }

    /// Answer the daemon's challenge to the keyed attach: queue the proof of
    /// the key, once, under the attach's id. A challenge that names no keyed
    /// attach still waited on, or comes a second time, is logged and left
    /// unanswered, for the daemon's deadline to settle; one whose nonce is
    /// not 32 bytes of base64 fails the attach with [`DevError::Protocol`].
    fn answer_challenge(&mut self, id: Option<&str>, nonce: &str) {
        let request = id.and_then(request_number);
        let waited_on = request
            .and_then(|request| self.pending.get(&request))
            .is_some_and(|waiting| matches!(waiting, OneOfPending::Attach(_)));
        let ours = self
            .identity
            .as_ref()
            .is_some_and(|identity| Some(identity.request) == request);
        if !(waited_on && ours) {
            tracing::warn!(
                id = ?id,
                "a challenge that names no keyed attach of this client waiting for one; left unanswered"
            );
            return;
        }
        let nonce = match attach::decode_nonce(nonce) {
            Ok(nonce) => nonce,
            Err(e) => {
                if let Some(waiting) = self.take_pending(id) {
                    let _ = waiting.fail(DevError::Protocol(format!(
                        "the daemon's challenge to the attach: {e}"
                    )));
                }
                return;
            }
        };
        let Some(identity) = self.identity.take() else {
            return;
        };
        let signature = attach::sign(&identity.key, &nonce, &identity.name, &self.exporter);
        let prove = ClientMessage::Prove {
            id: Some(request_id(identity.request)),
            signature: base64::encode(&signature),
        };
        let Ok(text) = serde_json::to_string(&prove) else {
            return;
        };
        // The client's own frame: never withdrawn, and the attach's reply
        // answers it. If the writer has stopped, the connection's end does.
        let _ = self.outbox.push(Outgoing {
            request: None,
            ticket: None,
            text,
        });
    }

    /// Queue the request `message` builds, under a new id, as one that
    /// `waiting` answers. `Ok(false)` when the writer has stopped: the
    /// request is never written, and waits for the connection's end, which
    /// answers it. An error, which ends the connection, only if the message
    /// cannot be serialised.
    fn submit(
        &mut self,
        waiting: OneOfPending,
        message: impl FnOnce(Option<String>) -> ClientMessage,
    ) -> Result<bool, DevError> {
        let request = self.next_request;
        self.next_request += 1;
        let text = serde_json::to_string(&message(Some(request_id(request))))
            .map_err(|e| DevError::Protocol(e.to_string()))?;
        // A caller's request counts against the outbox's depth and carries
        // its ticket, so it may be withdrawn; the client's own may not.
        let ticket = waiting.ticket().cloned();
        let call = waiting.op().is_some();
        self.pending.insert(request, waiting);
        Ok(self.outbox.push(Outgoing {
            request: call.then_some(request),
            ticket,
            text,
        }))
    }

    /// At the top of each turn: if a call timed out and rang the doorbell,
    /// settle what the calls that gave up left behind ([`Driver::sweep`]).
    fn settle(&mut self) {
        if self.cancelled.answer() {
            self.sweep();
        }
    }

    /// Whether the driver may take a call off the command queue: while the
    /// outbox has room ([`OutboxTx::has_room`]).
    fn may_take(&self) -> bool {
        self.outbox.has_room()
    }

    /// Take one call: queue its request, or drop it unsent when its caller
    /// gave up first (an unsubscribe excepted, [`Op::withdrawn_on_timeout`]).
    fn take(&mut self, cmd: Cmd) -> Result<Took, DevError> {
        if cmd.withdrawn() {
            return Ok(Took::Nothing);
        }
        let queued = match cmd {
            Cmd::Send {
                channel,
                type_name,
                payload,
                to,
                reply,
            } => self.submit(OneOfPending::Send(reply), |id| ClientMessage::Send {
                id,
                channel,
                type_id: 0,
                type_name,
                payload: base64::encode(&payload),
                flags: 0,
                to,
            })?,
            Cmd::Subscribe {
                filter,
                callback,
                reply,
            } => self.submit(OneOfPending::Subscribe(reply, callback), |id| {
                ClientMessage::Subscribe { id, filter }
            })?,
            Cmd::Unsubscribe { sub, reply } => {
                self.submit(OneOfPending::Unsubscribe(reply), |id| {
                    ClientMessage::Unsubscribe {
                        id,
                        subscription_id: sub.0,
                    }
                })?
            }
            Cmd::Detach { reply } => self.submit(OneOfPending::Detach(reply), |id| {
                ClientMessage::Detach { id }
            })?,
        };
        Ok(if queued {
            Took::Queued
        } else {
            Took::WriterGone
        })
    }

    /// Settle every call whose caller has given up, each by one look at its
    /// ticket ([`OneOfPending::fate`]); a caller that gives up after that
    /// look rings again. A call withdrawn before the writer took it is
    /// forgotten and its frame removed. One the writer took, or an
    /// unsubscribe, is abandoned, keeping nothing of its caller's, so its
    /// reply is known for a late one; at most `max_abandoned` are kept.
    fn sweep(&mut self) {
        let mut withdrawn = Vec::new();
        let mut abandon = Vec::new();
        for (&request, waiting) in &self.pending {
            match waiting.fate() {
                Fate::Waiting => {}
                Fate::Withdrawn => withdrawn.push(request),
                Fate::Abandoned => abandon.push(request),
            }
        }
        if !withdrawn.is_empty() {
            // In ascending order, as the map gave them.
            self.outbox
                .remove(|request| withdrawn.binary_search(&request).is_ok());
            for request in &withdrawn {
                self.pending.remove(request);
            }
        }
        let mut abandoned = 0;
        for request in abandon {
            if let Some(waiting) = self.pending.get_mut(&request) {
                if let Some(op) = waiting.op() {
                    *waiting = OneOfPending::Abandoned(op);
                    abandoned += 1;
                }
            }
        }
        self.abandoned += abandoned;
        self.forget_excess();
    }

    /// Forget the oldest requests nobody waits on, abandoned calls and
    /// releases alike, while there are more than `max_abandoned` of them
    /// ([`MAX_ABANDONED`] in a client).
    fn forget_excess(&mut self) {
        while self.abandoned > self.max_abandoned {
            let oldest = self
                .pending
                .iter()
                .find_map(|(&request, waiting)| waiting.unwaited().then_some(request));
            let Some(oldest) = oldest else { break };
            self.pending.remove(&oldest);
            self.abandoned -= 1;
        }
    }

    /// Remove and return the request a reply's id names, if this client
    /// gave that id and still waits on it.
    fn take_pending(&mut self, id: Option<&str>) -> Option<OneOfPending> {
        let waiting = self.pending.remove(&request_number(id?)?)?;
        if waiting.unwaited() {
            self.abandoned -= 1;
        }
        Some(waiting)
    }

    /// Count a reply that came after its call had timed out, logging at the
    /// first and at each doubling.
    fn count_late(&self, op: Op) {
        let n = self.late_replies.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            tracing::warn!(
                op = op.name(),
                late = n,
                "a reply arrived after its call had timed out; dropped"
            );
        }
    }

    /// Release a subscription whose subscribe timed out, with an
    /// unsubscribe of the client's own, whose reply goes nowhere; it counts
    /// with the abandoned calls against `max_abandoned`. If the writer has
    /// stopped, the subscription ends with the connection.
    fn release(&mut self, subscription_id: String) {
        let queued = self.submit(OneOfPending::Release, |id| ClientMessage::Unsubscribe {
            id,
            subscription_id,
        });
        if queued.is_ok() {
            self.abandoned += 1;
            self.forget_excess();
        }
    }

    /// Route one message from the daemon: a reply to the call waiting under
    /// its id, an event to the dispatch queue.
    fn route_inbound(&mut self, msg: ServerMessage) -> Routed {
        match msg {
            ServerMessage::Ack { id, fields } => {
                let Some(waiting) = self.take_pending(id.as_deref()) else {
                    return Routed::Nothing;
                };
                match waiting {
                    OneOfPending::Attach(tx) => {
                        if tx.send(Ok(())).is_err() {
                            self.count_late(Op::Attach);
                        }
                    }
                    OneOfPending::Send(tx) => {
                        let receipt = SendReceipt {
                            envelope_id: fields.envelope_id.unwrap_or_default(),
                            persisted: fields.persisted,
                            delivered: fields.delivered,
                        };
                        if tx.send(Ok(receipt)).is_err() {
                            self.count_late(Op::Send);
                        }
                    }
                    OneOfPending::Subscribe(tx, callback) => {
                        let made = fields.subscription_id;
                        let sub = SubscriptionId(made.clone().unwrap_or_default());
                        match tx.send(Ok(sub.clone())) {
                            Ok(()) => {
                                // A callback it displaces, under an id the
                                // daemon gave twice, is dropped outside the
                                // lock.
                                let displaced = self.callbacks.lock().insert(sub, callback);
                                drop(displaced);
                            }
                            // The caller timed out: release the subscription.
                            Err(_) => {
                                self.count_late(Op::Subscribe);
                                if let Some(made) = made {
                                    self.release(made);
                                }
                            }
                        }
                    }
                    OneOfPending::Unsubscribe(tx) => {
                        // The protocol requires the count only when events
                        // were dropped, so an absent one means none.
                        if tx.send(Ok(fields.events_dropped.unwrap_or(0))).is_err() {
                            self.count_late(Op::Unsubscribe);
                        }
                    }
                    OneOfPending::Detach(tx) => {
                        if tx.send(Ok(())).is_err() {
                            self.count_late(Op::Detach);
                        }
                        return Routed::Detached;
                    }
                    OneOfPending::Abandoned(op) => {
                        self.count_late(op);
                        match op {
                            Op::Subscribe => {
                                if let Some(sub) = fields.subscription_id {
                                    self.release(sub);
                                }
                            }
                            // The daemon detached the connection as asked,
                            // late or not, so the end that follows is clean.
                            Op::Detach => return Routed::Detached,
                            Op::Attach | Op::Send | Op::Unsubscribe => {}
                        }
                    }
                    OneOfPending::Release => {}
                }
                Routed::Nothing
            }
            ServerMessage::Error { id, code, message } => {
                let err = if ErrorCode::parse(&code) == Some(ErrorCode::AuthFailed) {
                    DevError::AuthFailed { message }
                } else {
                    DevError::Daemon { code, message }
                };
                match self.take_pending(id.as_deref()) {
                    Some(OneOfPending::Abandoned(op)) => self.count_late(op),
                    Some(OneOfPending::Release) => {
                        tracing::debug!(error = %err, "the daemon refused to release a subscription");
                    }
                    Some(waiting) => {
                        if let Some(op) = waiting.op() {
                            if !waiting.fail(err) {
                                self.count_late(op);
                            }
                        }
                    }
                    None => {
                        tracing::warn!(error = %err, "daemon error that answers no request");
                        return Routed::Unclaimed(err);
                    }
                }
                Routed::Nothing
            }
            ServerMessage::Event {
                subscription_id,
                envelope_id,
                channel,
                type_id,
                type_name,
                origin,
                captured_at_unix_nanos,
                payload,
            } => {
                // Anything but padded standard base64 is counted, never
                // delivered.
                let payload = match base64::decode(&payload) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        self.dispatch
                            .reject_malformed(&subscription_id, &envelope_id, &e);
                        return Routed::Nothing;
                    }
                };
                let event = MeshEvent {
                    subscription_id: SubscriptionId(subscription_id),
                    envelope_id,
                    channel,
                    type_id,
                    type_name,
                    origin,
                    captured_at_unix_nanos,
                    payload,
                };
                self.dispatch.offer(event);
                Routed::Nothing
            }
            ServerMessage::Health { node_id, state, .. } => {
                tracing::debug!(node = %node_id, state = %state, "peer health");
                Routed::Nothing
            }
            ServerMessage::Challenge { id, nonce } => {
                self.answer_challenge(id.as_deref(), &nonce);
                Routed::Nothing
            }
        }
    }

    /// Route one message from the daemon, and note what it means for how
    /// the connection ends: an acknowledged detach, or an error that
    /// answered no request, which stays the reason until another message
    /// follows it.
    fn route(&mut self, msg: ServerMessage) {
        match self.route_inbound(msg) {
            Routed::Nothing => self.last_word = None,
            Routed::Detached => {
                self.detached = true;
                self.last_word = None;
            }
            Routed::Unclaimed(err) => self.last_word = Some(err),
        }
    }

    /// How the connection ended, for `wait` and every call still waiting:
    /// cleanly only after a detach the daemon acknowledged, otherwise the
    /// daemon's parting error, or `Disconnected` without one.
    fn conclude(&mut self) -> Result<(), DevError> {
        if self.detached && self.last_word.is_none() {
            return Ok(());
        }
        let reason = self.last_word.clone().unwrap_or(DevError::Disconnected);
        self.fail_all(reason)
    }

    /// Whether the daemon owes the client an answer: a request, a call's
    /// or the client's own, waits for its reply.
    fn owes(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The daemon sent nothing for `after` while the client waited for it
    /// ([`Silence`]): the connection ends, and `wait` and every call still
    /// waiting report [`DevError::Silent`]. Whatever the daemon said last
    /// is not the reason: it carried on after it.
    fn give_up(&mut self, after: Duration) -> Result<(), DevError> {
        tracing::warn!(
            after = ?after,
            "the daemon sent nothing while the client waited for it; closing the connection"
        );
        self.fail_all(DevError::Silent { after })
    }

    /// End the connection with `reason`, which every call still waiting
    /// gets.
    fn fail_all(&mut self, reason: DevError) -> Result<(), DevError> {
        for waiting in std::mem::take(&mut self.pending).into_values() {
            let _ = waiting.fail(reason.clone());
        }
        self.abandoned = 0;
        Err(reason)
    }
}

// ---- The driver without the connection, for the fuzz harness ---------------

/// One call a client makes, as the driver takes it off the command queue:
/// what [`Mesh`]'s calls hand the connection's task. Public, and hidden
/// from the documentation, only for [`Router`].
#[doc(hidden)]
pub struct Call(Cmd);

impl Call {
    /// A send of `payload` on `channel`, and its caller's end.
    #[must_use]
    pub fn send(channel: &str, payload: &[u8]) -> (Self, Waiter<SendReceipt>) {
        let (reply, waiter) = call_ends(Op::Send);
        let cmd = Cmd::Send {
            channel: channel.to_owned(),
            type_name: None,
            payload: payload.to_vec(),
            to: None,
            reply,
        };
        (Self(cmd), waiter)
    }

    /// A subscribe with `filter`, whose events go nowhere, and its caller's
    /// end.
    #[must_use]
    pub fn subscribe(filter: TapFilter) -> (Self, Waiter<SubscriptionId>) {
        let (reply, waiter) = call_ends(Op::Subscribe);
        let callback: SubscriptionCallback = Arc::new(|_event: MeshEvent| {});
        let cmd = Cmd::Subscribe {
            filter,
            callback,
            reply,
        };
        (Self(cmd), waiter)
    }

    /// An unsubscribe of `sub`, and its caller's end.
    #[must_use]
    pub fn unsubscribe(sub: SubscriptionId) -> (Self, Waiter<u64>) {
        let (reply, waiter) = call_ends(Op::Unsubscribe);
        (Self(Cmd::Unsubscribe { sub, reply }), waiter)
    }

    /// A detach, and its caller's end.
    #[must_use]
    pub fn detach() -> (Self, Waiter<()>) {
        let (reply, waiter) = call_ends(Op::Detach);
        (Self(Cmd::Detach { reply }), waiter)
    }

    /// What the call's caller reports when the command queue is still full
    /// at its deadline, the call dropped unsent: [`DevError::QueueFull`].
    #[must_use]
    pub fn refused(&self) -> DevError {
        self.0.op().refused()
    }
}

/// The client's handling of one connection, without the connection: the
/// driver, with the far ends of its outbox and its dispatch queue in place
/// of the writer and the callback thread, and the command queue and the
/// doorbell between it and its callers ([`Router::offer`],
/// [`Router::time_out`], [`Router::turn`]).
///
/// Public, and hidden from the documentation, only so that the fuzz target
/// `fuzz/fuzz_targets/fuzz_client_routing.rs` can drive it with
/// any interleaving of calls, timeouts, writes and server messages. It is
/// not part of the crate's API.
#[doc(hidden)]
pub struct Router {
    driver: Driver,
    /// The transport writer's end of the outbox.
    writer: OutboxRx,
    /// The dispatch queue's receiving end, the dispatch thread's in a
    /// client.
    events: std::sync::mpsc::Receiver<Queued>,
    /// The callers' end of the command queue.
    calls: mpsc::Sender<Cmd>,
    /// The driver's end of the command queue.
    queue: mpsc::Receiver<Cmd>,
}

impl Router {
    /// A driver with no call and no subscription, whose dispatch queue holds
    /// at most `event_queue` events (zero is taken as one) and
    /// `event_queue_bytes` bytes of them, as [`MeshOptions`] says.
    #[must_use]
    pub fn new(event_queue: usize, event_queue_bytes: usize) -> Self {
        Self::with_max_abandoned(event_queue, event_queue_bytes, MAX_ABANDONED)
    }

    /// As [`Router::new`], keeping at most `max_abandoned` requests nobody
    /// waits on, abandoned calls and releases, where a client keeps 4,096:
    /// a harness reaches a small cap in a few steps.
    #[must_use]
    pub fn with_max_abandoned(
        event_queue: usize,
        event_queue_bytes: usize,
        max_abandoned: usize,
    ) -> Self {
        let (outbound, writer) = outbox();
        let (dispatch, events) = Dispatch::new(event_queue, event_queue_bytes);
        let driver = Driver::new(
            outbound,
            Arc::new(Mutex::new(HashMap::new())),
            dispatch,
            Arc::new(AtomicU64::new(0)),
            Arc::new(Doorbell::default()),
            max_abandoned,
        );
        let (calls, queue) = command_queue();
        Self {
            driver,
            writer,
            events,
            calls,
            queue,
        }
    }

    /// A caller hands its call to the command queue: `None` once it is in,
    /// or the call back while [`COMMAND_QUEUE`] calls wait there, for its
    /// caller to offer again until its deadline and then report
    /// [`Call::refused`].
    #[must_use]
    pub fn offer(&mut self, call: Call) -> Option<Call> {
        match self.calls.try_send(call.0) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(cmd) | mpsc::error::TrySendError::Closed(cmd)) => {
                Some(Call(cmd))
            }
        }
    }

    /// One turn of the driver's loop: settle what the calls that timed out
    /// left behind, if one rang the doorbell, then take the oldest call off
    /// the command queue if the outbox has room ([`Router::take`]). `true`
    /// when it took one.
    ///
    /// # Errors
    ///
    /// [`DevError::Protocol`] if the request cannot be serialised, which
    /// ends the connection.
    pub fn turn(&mut self) -> Result<bool, DevError> {
        self.driver.settle();
        if !self.driver.may_take() {
            return Ok(false);
        }
        match self.queue.try_recv() {
            Ok(cmd) => self.driver.take(cmd).map(|_| true),
            Err(_) => Ok(false),
        }
    }

    /// How many calls wait in the command queue for the driver.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.calls.max_capacity() - self.calls.capacity()
    }

    /// A caller times out, as a call does at its deadline: it gives up
    /// ([`Waiter::give_up`]) and, when no answer had come, rings the
    /// doorbell. An answer that raced the deadline is returned.
    pub fn time_out<T>(&self, waiter: &mut Waiter<T>) -> Option<Result<T, DevError>> {
        waiter.time_out(&self.driver.cancelled)
    }

    /// Queue the attach under `name`, as the connection's task does before
    /// anything else; the waiter gets its reply.
    ///
    /// # Errors
    ///
    /// [`DevError::Protocol`] if the request cannot be serialised, which
    /// ends the connection.
    pub fn attach(&mut self, name: &str) -> Result<Waiter<()>, DevError> {
        let (done, waiter) = call_ends(Op::Attach);
        self.driver.attach(name.to_owned(), None, done)?;
        Ok(waiter)
    }

    /// Whether fewer than [`OUTBOUND_QUEUE`] requests wait for the writer,
    /// so the driver may take a call.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.driver.may_take()
    }

    /// Take one call as the driver does, without the command queue: queue
    /// its request, or drop it when its caller gave up first (an
    /// unsubscribe excepted).
    ///
    /// # Errors
    ///
    /// [`DevError::Protocol`] if the request cannot be serialised, which
    /// ends the connection.
    pub fn take(&mut self, call: Call) -> Result<(), DevError> {
        self.driver.take(call.0).map(drop)
    }

    /// Settle what timed-out calls left behind, as [`Router::turn`] does
    /// after the doorbell rang: forget the requests withdrawn before the
    /// writer took them, removing their frames, and abandon the rest, so
    /// their replies count as late.
    pub fn sweep(&mut self) {
        self.driver.sweep();
    }

    /// Route one message from the daemon, as the driver routes each one its
    /// reader decodes.
    pub fn route(&mut self, msg: ServerMessage) {
        self.driver.route(msg);
    }

    /// Take the oldest frame waiting for the writer, as the transport's
    /// writer does, skipping requests whose callers withdrew them; `None`
    /// when none waits.
    pub fn write_next(&mut self) -> Option<String> {
        match self.writer.pop() {
            Popped::Frame(text) => Some(text),
            Popped::Ended | Popped::Empty => None,
        }
    }

    /// The frames waiting for the writer, oldest first, withdrawn ones not
    /// yet removed included.
    #[must_use]
    pub fn waiting(&self) -> Vec<String> {
        let state = self.writer.shared.state.lock();
        state
            .frames
            .iter()
            .map(|frame| frame.text.clone())
            .collect()
    }

    /// The events queued for the callbacks and not yet taken, oldest first,
    /// as the dispatch thread takes them and runs them, which gives their
    /// bytes back to the queue's budget.
    pub fn take_events(&self) -> Vec<MeshEvent> {
        self.events.try_iter().map(|queued| queued.event).collect()
    }

    /// The subscriptions whose callbacks are registered.
    #[must_use]
    pub fn subscriptions(&self) -> Vec<SubscriptionId> {
        self.driver.callbacks.lock().keys().cloned().collect()
    }

    /// Replies that came after their call had timed out.
    #[must_use]
    pub fn late_replies(&self) -> u64 {
        self.driver.late_replies.load(Ordering::Relaxed)
    }

    /// Events dropped because the dispatch queue was full.
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        self.driver.dispatch.counts.dropped.load(Ordering::Relaxed)
    }

    /// Events dropped because their payload was not valid base64.
    #[must_use]
    pub fn events_malformed(&self) -> u64 {
        self.driver
            .dispatch
            .counts
            .malformed
            .load(Ordering::Relaxed)
    }

    /// The connection ended: how `wait` reports it, every call still
    /// waiting answered with the same error.
    ///
    /// # Errors
    ///
    /// Anything but a detach the daemon acknowledged with no unanswered
    /// error after it: the daemon's parting error when its last message
    /// was one, [`DevError::Disconnected`] otherwise.
    pub fn conclude(&mut self) -> Result<(), DevError> {
        self.driver.conclude()
    }
}

// ---- UDS I/O ---------------------------------------------------------------

/// Refuse the socket at [`DEFAULT_UDS_PATH`] when another user serves it. The
/// path is in `/tmp`, where anyone may create it before the daemon does; the
/// daemon's own socket is its user's alone (mode 0600), so one another user
/// serves there is not this user's daemon. A path named in `PMS_DAEMON` is
/// the caller's choice and is not checked.
fn ensure_own_daemon(stream: &UnixStream, path: &str) -> Result<(), DevError> {
    let transport = |e: std::io::Error| DevError::Transport(format!("uds peer of {path}: {e}"));
    let peer = stream.peer_cred().map_err(transport)?.uid();
    same_user(path, peer, own_uid().map_err(transport)?)
}

/// The uid this process runs as, which the kernel reports as the peer of a
/// socket pair the process makes: std has no call for it, and this one needs
/// no unsafe code. Called on the runtime, which the pair registers with.
fn own_uid() -> std::io::Result<u32> {
    let (mine, _theirs) = UnixStream::pair()?;
    Ok(mine.peer_cred()?.uid())
}

/// [`DevError::ForeignDaemon`] unless the `peer` uid serving `path` is `own`.
fn same_user(path: &str, peer: u32, own: u32) -> Result<(), DevError> {
    if peer == own {
        Ok(())
    } else {
        Err(DevError::ForeignDaemon {
            path: path.to_string(),
            uid: peer,
        })
    }
}

/// Connect to the Unix socket at `path` and start the connection's reader
/// and writer. The socket has no ping.
async fn spawn_uds_io(
    path: String,
    inbound: InboundTx,
    mut outbound: OutboxRx,
) -> Result<Io, DevError> {
    let stream = UnixStream::connect(&path)
        .await
        .map_err(|e| DevError::Transport(format!("uds connect {}: {}", path, e)))?;
    if path == DEFAULT_UDS_PATH {
        ensure_own_daemon(&stream, &path)?;
    }
    let (reader, mut writer) = stream.into_split();

    let reading = tokio::spawn(read_uds(reader, inbound));

    // Writer task: one frame at a time from the outbox, so every frame
    // behind the one being written can still be withdrawn.
    let writing = tokio::spawn(async move {
        while let Some(text) = outbound.recv().await {
            let frame = match encode_frame(text.as_bytes()) {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dev-functions writer: message too long for a UDS frame — closing"
                    );
                    break;
                }
            };
            // The frame holds the bytes now: a writer stalled by a daemon
            // that stopped reading keeps one copy of them, not two.
            drop(text);
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    Ok(Io {
        ping: None,
        tasks: vec![reading.abort_handle(), writing.abort_handle()],
        exporter: attach::NO_EXPORTER,
    })
}

/// The Unix socket's reader: frames of a 4-byte big-endian length and UTF-8
/// JSON, each handed to the driver as the queue has room
/// ([`InboundTx::send`]). It hands on every frame a read completed before
/// it reads again, and the decoder holds only bytes that arrived, never the
/// length a prefix announces, so a flood waits in the socket.
async fn read_uds(mut reader: impl AsyncRead + Unpin, inbound: InboundTx) {
    let mut frames = FrameDecoder::new(MAX_INBOUND_MESSAGE);
    let mut chunk = [0u8; 8192];
    'read: loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Any bytes from the daemon say it is there, a part of a
                // long message included.
                inbound.hear();
                frames.push(&chunk[..n]);
            }
        }
        loop {
            let frame = match frames.pop() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dev-functions reader: UDS frame over the client's limit — closing"
                    );
                    break 'read;
                }
            };
            let text = match String::from_utf8(frame) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dev-functions reader: non-utf8 frame on UDS — closing"
                    );
                    break 'read;
                }
            };
            let msg = match serde_json::from_str::<ServerMessage>(&text) {
                Ok(m) => m,
                Err(e) => {
                    // Logged with a preview before it is skipped, or a
                    // frame the client cannot parse would vanish unseen.
                    let preview: String = text.chars().take(200).collect();
                    tracing::error!(
                        error = %e,
                        frame_len = text.len(),
                        frame_preview = %preview,
                        "dev-functions reader: failed to parse inbound frame as ServerMessage"
                    );
                    continue;
                }
            };
            // The message holds what the text did; a reader waiting for
            // room keeps one of them, not both.
            let len = text.len();
            drop(text);
            // Waits while the driver's queue is full.
            if !inbound.send(msg, len).await {
                break 'read;
            }
        }
    }
}

// ---- WS I/O ----------------------------------------------------------------

/// Open the WebSocket at `url` and start the connection's reader and
/// writer, which pings the daemon when the driver asks it to. A `wss://` URL
/// is TLS 1.3 first: its certificate is verified against webpki-roots' roots
/// and `tls_roots`, for the URL's host, which it indicates (SNI).
async fn spawn_ws_io(
    url: String,
    tls_roots: &[Vec<u8>],
    inbound: InboundTx,
    outbound: OutboxRx,
) -> Result<Io, DevError> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
    // The daemon requires the port subprotocol on the handshake and
    // echoes it back; a handshake without it is refused with 400.
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| DevError::Transport(format!("ws url {}: {}", url, e)))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    // The same limit as the socket's, where tungstenite's own would let a
    // message of 64 MiB through.
    let config = WebSocketConfig {
        max_message_size: Some(MAX_INBOUND_MESSAGE),
        max_frame_size: Some(MAX_INBOUND_MESSAGE),
        ..WebSocketConfig::default()
    };
    if request.uri().scheme_str() == Some("wss") {
        let stream = connect_tls(&url, request.uri(), tls_roots).await?;
        // What a proof of the client's key on this connection is bound to
        // (`mesh_port_protocol::attach`).
        let exporter = stream
            .get_ref()
            .1
            .export_keying_material(
                [0u8; attach::EXPORTER_LEN],
                attach::TLS_EXPORTER_LABEL,
                None,
            )
            .map_err(|e| DevError::Tls(format!("the TLS exporter for {url}: {e}")))?;
        let (ws, response) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                .await
                .map_err(|e| DevError::Transport(format!("ws connect {}: {}", url, e)))?;
        echoed_subprotocol(&response)?;
        return Ok(Io {
            exporter,
            ..start_ws_io(ws, inbound, outbound)
        });
    }
    let (ws, response) = tokio_tungstenite::connect_async_with_config(request, Some(config), false)
        .await
        .map_err(|e| DevError::Transport(format!("ws connect {}: {}", url, e)))?;
    echoed_subprotocol(&response)?;
    Ok(start_ws_io(ws, inbound, outbound))
}

/// [`DevError::Protocol`] unless the daemon's upgrade echoed the port
/// subprotocol.
fn echoed_subprotocol(
    response: &tokio_tungstenite::tungstenite::handshake::client::Response,
) -> Result<(), DevError> {
    let echoed = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == WS_SUBPROTOCOL);
    if !echoed {
        return Err(DevError::Protocol(format!(
            "daemon did not accept the {} subprotocol",
            WS_SUBPROTOCOL
        )));
    }
    Ok(())
}

/// The roots a `wss://` endpoint's certificate may chain to: webpki-roots'
/// copy of the Mozilla root program's, and every certificate in `extra`.
fn tls_root_store(extra: &[Vec<u8>]) -> Result<rustls::RootCertStore, DevError> {
    use rustls::pki_types::pem::PemObject;
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for pem in extra {
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DevError::Tls(format!("a root given with with_tls_root_pem: {e}")))?;
        if certs.is_empty() {
            return Err(DevError::Tls(
                "a root given with with_tls_root_pem holds no PEM certificate".into(),
            ));
        }
        for cert in certs {
            roots.add(cert).map_err(|e| {
                DevError::Tls(format!(
                    "a root given with with_tls_root_pem is not usable as one: {e}"
                ))
            })?;
        }
    }
    Ok(roots)
}

/// Connect to `uri`'s host and port (443 by default) and complete a TLS 1.3
/// handshake, verifying the daemon's certificate for the host against
/// [`tls_root_store`]`(tls_roots)`.
async fn connect_tls(
    url: &str,
    uri: &tokio_tungstenite::tungstenite::http::Uri,
    tls_roots: &[Vec<u8>],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, DevError> {
    let host = uri
        .host()
        .ok_or_else(|| DevError::Transport(format!("ws url {url}: no host")))?;
    // An IPv6 address comes bracketed in a URL and bare in a server name.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri.port_u16().unwrap_or(443);
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| {
        DevError::Tls(format!(
            "{host} is not a name a certificate can be checked against: {e}"
        ))
    })?;
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| DevError::Tls(e.to_string()))?
    .with_root_certificates(tls_root_store(tls_roots)?)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| DevError::Transport(format!("ws connect {url}: {e}")))?;
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(name, tcp)
        .await
        // TLS's own refusal comes through `io::Error`, and so does the end of a
        // daemon that does not speak TLS, which closes on the client's hello.
        .map_err(|e| DevError::Tls(format!("wss handshake with {host}:{port}: {e}")))
}

/// Start the reader and the writer of the upgraded WebSocket `ws`.
fn start_ws_io<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    inbound: InboundTx,
    mut outbound: OutboxRx,
) -> Io
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut writer, mut reader) = ws.split();

    let reading = tokio::spawn(async move {
        while let Some(frame) = reader.next().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::error!(error = %e, "dev-functions reader: ws frame error");
                    break;
                }
            };
            // Any frame from the daemon says it is there: a ping, a pong,
            // one the client has no use for.
            inbound.hear();
            let WsMsg::Text(t) = frame else {
                continue;
            };
            let msg = match serde_json::from_str::<ServerMessage>(&t) {
                Ok(m) => m,
                Err(e) => {
                    let preview: String = t.chars().take(200).collect();
                    tracing::error!(
                        error = %e,
                        frame_len = t.len(),
                        frame_preview = %preview,
                        "dev-functions reader: failed to parse inbound ws frame as ServerMessage"
                    );
                    continue;
                }
            };
            let len = t.len();
            drop(t);
            // Waits while the driver's queue is full.
            if !inbound.send(msg, len).await {
                break;
            }
        }
    });

    // Writer task: one frame at a time from the outbox, as for the socket,
    // and a ping when the driver asks for one. A ping asked for while a
    // frame is being written waits for it; a frame the ping comes before
    // stays in the outbox.
    let ping = Arc::new(Notify::new());
    let pinged = Arc::clone(&ping);
    let writing = tokio::spawn(async move {
        loop {
            let message = tokio::select! {
                () = pinged.notified() => WsMsg::Ping(Vec::new()),
                text = outbound.recv() => match text {
                    Some(text) => WsMsg::Text(text),
                    None => break,
                },
            };
            if writer.send(message).await.is_err() {
                break;
            }
        }
    });

    Io {
        ping: Some(ping),
        tasks: vec![reading.abort_handle(), writing.abort_handle()],
        exporter: attach::NO_EXPORTER,
    }
}

// ---- Inbound routing -------------------------------------------------------

/// What one message from the daemon means for how the connection ends.
enum Routed {
    /// Nothing: a reply, an event, a health notice.
    Nothing,
    /// The daemon acknowledged the detach the caller asked for, so the end
    /// that follows is clean.
    Detached,
    /// An error that answered no request (it had no id, or one nobody is
    /// waiting on): the daemon's reason if the connection ends next.
    Unclaimed(DevError),
}

/// A request waiting for the daemon's reply, by what the reply resolves.
enum OneOfPending {
    Attach(Reply<()>),
    Send(Reply<SendReceipt>),
    Subscribe(Reply<SubscriptionId>, SubscriptionCallback),
    Unsubscribe(Reply<u64>),
    Detach(Reply<()>),
    /// A call that timed out after the writer took its request: its reply,
    /// when it comes, is late.
    Abandoned(Op),
    /// The client's own unsubscribe, releasing a subscription whose
    /// subscribe timed out.
    Release,
}

/// What a sweep does with a request waiting for its reply.
enum Fate {
    /// Nothing: its caller still waits, or it has been settled already.
    Waiting,
    /// Forget it: its caller gave up before the writer took the request,
    /// which is never written.
    Withdrawn,
    /// Keep it as abandoned: its caller gave up, and the request is written
    /// or being written, so a reply is still to come.
    Abandoned,
}

impl OneOfPending {
    /// The call's operation; `None` for the client's own request.
    fn op(&self) -> Option<Op> {
        match self {
            OneOfPending::Attach(_) => Some(Op::Attach),
            OneOfPending::Send(_) => Some(Op::Send),
            OneOfPending::Subscribe(..) => Some(Op::Subscribe),
            OneOfPending::Unsubscribe(_) => Some(Op::Unsubscribe),
            OneOfPending::Detach(_) => Some(Op::Detach),
            OneOfPending::Abandoned(op) => Some(*op),
            OneOfPending::Release => None,
        }
    }

    /// The ticket of a call still waited on, and whether its caller has
    /// gone; `None` for an abandoned call or the client's own request.
    fn call(&self) -> Option<(&Arc<Ticket>, bool)> {
        match self {
            OneOfPending::Attach(reply) | OneOfPending::Detach(reply) => {
                Some((&reply.ticket, reply.caller_gone()))
            }
            OneOfPending::Send(reply) => Some((&reply.ticket, reply.caller_gone())),
            OneOfPending::Subscribe(reply, _) => Some((&reply.ticket, reply.caller_gone())),
            OneOfPending::Unsubscribe(reply) => Some((&reply.ticket, reply.caller_gone())),
            OneOfPending::Abandoned(_) | OneOfPending::Release => None,
        }
    }

    /// The ticket the request's frame carries; `None` for the client's own.
    fn ticket(&self) -> Option<&Arc<Ticket>> {
        self.call().map(|(ticket, _)| ticket)
    }

    /// Whether nobody waits for the reply: an abandoned call, or the
    /// client's own release. At most [`MAX_ABANDONED`] are kept.
    fn unwaited(&self) -> bool {
        matches!(self, OneOfPending::Abandoned(_) | OneOfPending::Release)
    }

    /// What a sweep does with this request, from one look at its caller
    /// and its ticket. A caller that has gone without withdrawing its
    /// request has it withdrawn here, unless the writer took it first.
    fn fate(&self) -> Fate {
        let Some((ticket, gone)) = self.call() else {
            return Fate::Waiting;
        };
        if ticket.withdrawn() {
            Fate::Withdrawn
        } else if !gone {
            Fate::Waiting
        } else if ticket.withdraw() {
            Fate::Withdrawn
        } else {
            Fate::Abandoned
        }
    }

    /// Answer the call with `err`. `false` when nobody was told: the caller
    /// had stopped waiting, or the request was the client's own.
    fn fail(self, err: DevError) -> bool {
        match self {
            OneOfPending::Attach(reply) | OneOfPending::Detach(reply) => {
                reply.send(Err(err)).is_ok()
            }
            OneOfPending::Send(reply) => reply.send(Err(err)).is_ok(),
            OneOfPending::Subscribe(reply, _callback) => reply.send(Err(err)).is_ok(),
            OneOfPending::Unsubscribe(reply) => reply.send(Err(err)).is_ok(),
            OneOfPending::Abandoned(_) | OneOfPending::Release => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mesh_port_protocol::{AckFields, ErrorCode};

    /// The uid a socket pair reports is the one files this process makes
    /// are owned by.
    #[test]
    fn own_uid_is_the_owner_of_what_this_process_creates() {
        use std::os::unix::fs::MetadataExt;
        let file = std::env::temp_dir().join(format!("pms-own-uid-{}", std::process::id()));
        std::fs::write(&file, b"").unwrap();
        let owner = std::fs::metadata(&file).unwrap().uid();
        std::fs::remove_file(&file).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        assert_eq!(runtime.block_on(async { own_uid() }).unwrap(), owner);
    }

    #[test]
    fn a_socket_another_user_serves_is_refused() {
        assert!(same_user(DEFAULT_UDS_PATH, 501, 501).is_ok());
        assert!(matches!(
            same_user(DEFAULT_UDS_PATH, 0, 501),
            Err(DevError::ForeignDaemon { uid: 0, .. })
        ));
    }

    #[test]
    fn endpoint_discovery_ws_fallback() {
        std::env::remove_var("PMS_DAEMON");
        // The well-known UDS may or may not exist depending on whether a daemon
        // is running locally during the test. Either way, the function should
        // return Ok with a valid endpoint shape.
        let ep = discover_endpoint().expect("discovery should succeed");
        match ep {
            Endpoint::Uds(_) | Endpoint::Ws(_) => {}
        }
    }

    /// `PMS_DAEMON` names a socket, a `ws://` URL or a `wss://` one, and
    /// nothing else.
    #[test]
    fn pms_daemon_names_a_socket_a_ws_url_or_a_wss_url() {
        assert_eq!(
            named_endpoint("unix:///tmp/my.sock".into()).unwrap(),
            Endpoint::Uds("/tmp/my.sock".into())
        );
        for url in [
            "ws://127.0.0.1:9876",
            "wss://mesh.example:9443",
            "wss://[::1]:9443",
        ] {
            assert_eq!(
                named_endpoint(url.into()).unwrap(),
                Endpoint::Ws(url.into())
            );
        }
        for not_one in ["http://mesh.example", "mesh.example:9443", "wss:/x", ""] {
            assert!(
                matches!(named_endpoint(not_one.into()), Err(DevError::NoDaemon)),
                "{not_one}"
            );
        }
    }

    /// `with_tls_root_pem` adds to webpki-roots' roots, each call to the
    /// last's, and a root that is not a PEM certificate is refused.
    #[test]
    fn tls_roots_add_to_webpki_roots() {
        let defaults = tls_root_store(&[]).unwrap().len();
        assert!(defaults > 0);
        let one = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let two = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let options = MeshOptions::default()
            .with_tls_root_pem(one.cert.pem())
            .with_tls_root_pem(two.cert.pem().into_bytes());
        assert_eq!(options.tls_roots.len(), 2);
        assert_eq!(
            tls_root_store(&options.tls_roots).unwrap().len(),
            defaults + 2
        );
        for bad in [&b"not pem"[..], one.signing_key.serialize_pem().as_bytes()] {
            assert!(
                matches!(tls_root_store(&[bad.to_vec()]), Err(DevError::Tls(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn tap_filter_serializes() {
        let f = TapFilter {
            channel: Some("db/*".into()),
            health: true,
            ..Default::default()
        };
        let j = serde_json::to_value(&f).unwrap();
        assert_eq!(j["channel"], "db/*");
        assert_eq!(j["health"], true);
        assert!(j.get("snapshot").is_none()); // omitted when false
    }

    /// A driver with an event queue `depth` deep and holding the default
    /// budget of bytes, and the far ends of its dispatch queue and of its
    /// outbox, which nothing drains unless a test does.
    fn test_driver(depth: usize) -> (Driver, std::sync::mpsc::Receiver<Queued>, OutboxRx) {
        test_driver_with(depth, MeshOptions::default().event_queue_bytes)
    }

    /// As [`test_driver`], with an event queue that holds at most `bytes`.
    fn test_driver_with(
        depth: usize,
        bytes: usize,
    ) -> (Driver, std::sync::mpsc::Receiver<Queued>, OutboxRx) {
        let (outbound, writer) = outbox();
        let (dispatch, dispatch_rx) = Dispatch::new(depth, bytes);
        let driver = Driver::new(
            outbound,
            Arc::new(Mutex::new(HashMap::new())),
            dispatch,
            Arc::new(AtomicU64::new(0)),
            Arc::new(Doorbell::default()),
            MAX_ABANDONED,
        );
        (driver, dispatch_rx, writer)
    }

    /// The frames waiting in a driver's outbox, parsed.
    fn waiting(driver: &Driver) -> Vec<serde_json::Value> {
        driver
            .outbox
            .shared
            .state
            .lock()
            .frames
            .iter()
            .map(|frame| serde_json::from_str(&frame.text).unwrap())
            .collect()
    }

    /// An event for subscription `sub`, carrying `"AA=="`.
    fn event(sub: &str, envelope: &str) -> ServerMessage {
        ServerMessage::Event {
            subscription_id: sub.into(),
            envelope_id: envelope.into(),
            channel: "c".into(),
            type_id: 0,
            type_name: None,
            origin: "o@1".into(),
            captured_at_unix_nanos: 0,
            payload: "AA==".into(),
        }
    }

    /// An ack of request `request` with `fields`.
    fn ack(request: u64, fields: AckFields) -> ServerMessage {
        ServerMessage::Ack {
            id: Some(request_id(request)),
            fields,
        }
    }

    /// A send, and its caller's end.
    fn send_cmd() -> (Cmd, Waiter<SendReceipt>) {
        let (reply, waiter) = call_ends(Op::Send);
        let cmd = Cmd::Send {
            channel: "c".into(),
            type_name: None,
            payload: b"x".to_vec(),
            to: None,
            reply,
        };
        (cmd, waiter)
    }

    #[test]
    fn event_right_after_the_subscribe_ack_reaches_the_callback() {
        let (mut driver, dispatch_rx, _writer) = test_driver(4);
        let hits = Arc::new(AtomicU64::new(0));
        let counted = hits.clone();
        let (tx, mut rx) = call_ends(Op::Subscribe);
        driver.pending.insert(
            1,
            OneOfPending::Subscribe(
                tx,
                Arc::new(move |_ev: MeshEvent| {
                    counted.fetch_add(1, Ordering::SeqCst);
                }),
            ),
        );
        driver.route_inbound(ack(
            1,
            AckFields {
                subscription_id: Some("s".into()),
                ..Default::default()
            },
        ));
        driver.route_inbound(event("s", "e"));
        let Queued { event, .. } = dispatch_rx.try_recv().expect("the event was dispatched");
        let sub = event.subscription_id.clone();
        assert_eq!(sub.0, "s");
        let callback = driver
            .callbacks
            .lock()
            .get(&sub)
            .cloned()
            .expect("registered at ack time");
        callback(event);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the event reached the callback"
        );
        assert!(matches!(rx.try_answer(), Some(Ok(SubscriptionId(s))) if s == "s"));
        assert_eq!(driver.late_replies.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_full_event_queue_drops_the_newest_event_but_never_a_reply() {
        let (mut driver, dispatch_rx, _writer) = test_driver(1);
        driver.route_inbound(event("s", "first"));
        driver.route_inbound(event("s", "second"));
        assert_eq!(driver.dispatch.counts.dropped.load(Ordering::Relaxed), 1);

        let (tx, mut rx) = call_ends(Op::Send);
        driver.pending.insert(7, OneOfPending::Send(tx));
        driver.route_inbound(ack(
            7,
            AckFields {
                envelope_id: Some("abc".into()),
                ..Default::default()
            },
        ));
        assert!(
            matches!(rx.try_answer(), Some(Ok(ref receipt)) if receipt.envelope_id == "abc"),
            "the reply reached its caller past the full queue"
        );
        assert_eq!(driver.dispatch.counts.dropped.load(Ordering::Relaxed), 1);

        let queued = dispatch_rx.try_recv().expect("the first event waits").event;
        assert_eq!(queued.envelope_id, "first", "the newest event is dropped");
        assert!(dispatch_rx.try_recv().is_err(), "nothing else was queued");
    }

    /// The event queue holds at most its budget in bytes, the event a
    /// callback is running included: an event that would take it past the
    /// budget is dropped and counted as one past the depth is, and once a
    /// callback has run its event, the bytes make room again. An event
    /// larger than the budget is always dropped, and a budget of zero drops
    /// every event.
    #[test]
    fn the_event_queue_holds_at_most_its_budget_in_bytes() {
        // One byte of payload, and "s", "eN", "c" and "o@1".
        const EVENT: usize = 8;
        let dropped = |driver: &Driver| driver.dispatch.counts.dropped.load(Ordering::Relaxed);
        let (mut driver, dispatch_rx, _writer) = test_driver_with(16, 3 * EVENT);
        for n in 0..5 {
            driver.route_inbound(event("s", &format!("e{n}")));
        }
        assert_eq!(dropped(&driver), 2, "three events fit the budget");

        // The dispatch thread takes the oldest and runs its callback.
        let running = dispatch_rx.try_recv().expect("the oldest event");
        assert_eq!(running.event.envelope_id, "e0");
        driver.route_inbound(event("s", "e5"));
        assert_eq!(dropped(&driver), 3, "a running event still counts");
        drop(running);
        driver.route_inbound(event("s", "e6"));
        assert_eq!(dropped(&driver), 3, "its bytes made room");
        let queued: Vec<String> = dispatch_rx
            .try_iter()
            .map(|queued| queued.event.envelope_id)
            .collect();
        assert_eq!(queued, ["e1", "e2", "e6"], "in order");

        let (mut driver, dispatch_rx, _writer) = test_driver_with(16, EVENT - 1);
        driver.route_inbound(event("s", "e0"));
        assert_eq!(
            dropped(&driver),
            1,
            "larger than the budget, though none waits"
        );
        assert!(dispatch_rx.try_recv().is_err());

        let (mut driver, dispatch_rx, _writer) = test_driver_with(16, 0);
        driver.route_inbound(event("s", "e0"));
        assert_eq!(dropped(&driver), 1, "a budget of zero");
        assert!(dispatch_rx.try_recv().is_err());
    }

    #[test]
    fn the_unsubscribe_ack_carries_the_daemons_drop_count() {
        let (mut driver, _dispatch_rx, _writer) = test_driver(1);
        for (reported, expected) in [(Some(5), 5), (None, 0)] {
            let (tx, mut rx) = call_ends(Op::Unsubscribe);
            driver.pending.insert(9, OneOfPending::Unsubscribe(tx));
            driver.route_inbound(ack(
                9,
                AckFields {
                    events_dropped: reported,
                    ..Default::default()
                },
            ));
            assert!(
                matches!(rx.try_answer(), Some(Ok(n)) if n == expected),
                "an ack reporting {reported:?} answers {expected}"
            );
        }
    }

    /// A subscribe ack whose caller has timed out registers no callback: the
    /// reply is counted as late, and the client releases the subscription
    /// the daemon made. The daemon's answer to the release is the client's
    /// own business, neither late nor the daemon's last word.
    #[test]
    fn a_late_subscribe_ack_registers_nothing_and_releases_the_subscription() {
        let (mut driver, dispatch_rx, _writer) = test_driver(4);
        let (tx, rx) = call_ends::<SubscriptionId>(Op::Subscribe);
        let ran = Arc::new(AtomicU64::new(0));
        let counted = ran.clone();
        driver.pending.insert(
            1,
            OneOfPending::Subscribe(
                tx,
                Arc::new(move |_ev: MeshEvent| {
                    counted.fetch_add(1, Ordering::SeqCst);
                }),
            ),
        );
        drop(rx); // the caller timed out
        let routed = driver.route_inbound(ack(
            1,
            AckFields {
                subscription_id: Some("late".into()),
                ..Default::default()
            },
        ));
        assert!(matches!(routed, Routed::Nothing));
        assert!(driver.callbacks.lock().is_empty(), "no callback registered");
        assert_eq!(driver.late_replies.load(Ordering::Relaxed), 1);

        let queued = waiting(&driver);
        assert_eq!(queued.len(), 1, "{queued:?}");
        assert_eq!(queued[0]["op"], "unsubscribe");
        assert_eq!(queued[0]["subscription_id"], "late");
        assert_eq!(
            driver.outbox.requests(),
            0,
            "the release does not count against the callers' depth"
        );

        // An event for the released subscription finds no callback.
        driver.route_inbound(event("late", "e"));
        let sub = dispatch_rx
            .try_recv()
            .expect("dispatched")
            .event
            .subscription_id;
        assert!(driver.callbacks.lock().get(&sub).is_none());
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        let release = queued[0]["id"].as_str().map(String::from);
        let routed = driver.route_inbound(ServerMessage::error(
            release,
            ErrorCode::UnknownSubscription,
            "already gone",
        ));
        assert!(
            matches!(routed, Routed::Nothing),
            "not the daemon's last word"
        );
        assert!(driver.pending.is_empty());
        assert_eq!(driver.late_replies.load(Ordering::Relaxed), 1);
    }

    /// A request whose caller timed out before the writer took it is
    /// withdrawn: the daemon never sees it, and no reply is expected. One
    /// the writer took is abandoned, and its reply counted as late.
    #[test]
    fn a_timed_out_request_is_withdrawn_unless_the_writer_took_it() {
        let (mut driver, _dispatch_rx, mut writer) = test_driver(1);
        let (taken, mut taken_rx) = send_cmd();
        let (queued, mut queued_rx) = send_cmd();
        assert!(matches!(driver.take(taken).unwrap(), Took::Queued));
        assert!(matches!(driver.take(queued).unwrap(), Took::Queued));
        // The writer takes the first request and is writing it.
        let written = next_frame(&mut writer).expect("the first request");
        assert!(written.contains(r#""id":"req-1""#), "{written}");

        assert!(taken_rx.give_up().is_none());
        assert!(queued_rx.give_up().is_none());
        driver.sweep();
        assert!(
            waiting(&driver).is_empty(),
            "the second request was withdrawn"
        );
        assert_eq!(driver.outbox.requests(), 0);
        assert_eq!(
            driver.pending.len(),
            1,
            "only the written one is remembered"
        );
        assert!(matches!(
            driver.pending.get(&1),
            Some(OneOfPending::Abandoned(Op::Send))
        ));
        assert_eq!(driver.abandoned, 1);

        let routed = driver.route_inbound(ack(1, AckFields::default()));
        assert!(matches!(routed, Routed::Nothing));
        assert!(driver.pending.is_empty());
        assert_eq!(driver.abandoned, 0);
        assert_eq!(driver.late_replies.load(Ordering::Relaxed), 1);

        // A late error is counted too, and is not the daemon's last word. A
        // caller that goes without giving up, its end dropped, is settled
        // by the sweep the same way.
        let (third, third_rx) = send_cmd();
        assert!(matches!(driver.take(third).unwrap(), Took::Queued));
        next_frame(&mut writer).expect("the third request");
        drop(third_rx);
        driver.sweep();
        let routed = driver.route_inbound(ServerMessage::error(
            Some(request_id(3)),
            ErrorCode::BadRequest,
            "late",
        ));
        assert!(matches!(routed, Routed::Nothing));
        assert_eq!(driver.late_replies.load(Ordering::Relaxed), 2);
    }

    /// The writer is writing one request, two more wait behind it, and all
    /// three callers give up, while the driver sweeps twice and the writer
    /// takes two more frames, in every order those seven steps can come. A
    /// request whose caller gave up before the writer took it is never
    /// written, whether or not a sweep came between; and the last sweep
    /// leaves exactly the calls whose requests were written, abandoned.
    #[test]
    fn a_request_whose_caller_gave_up_first_is_never_written_in_any_order() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum Step {
            GiveUp(usize),
            Sweep,
            Write,
        }
        fn orders(left: &mut Vec<Step>, order: &mut Vec<Step>, all: &mut HashSet<Vec<Step>>) {
            if left.is_empty() {
                all.insert(order.clone());
                return;
            }
            for i in 0..left.len() {
                let step = left.remove(i);
                order.push(step);
                orders(left, order, all);
                order.pop();
                left.insert(i, step);
            }
        }
        use std::collections::HashSet;
        let mut all = HashSet::new();
        let mut steps = vec![
            Step::GiveUp(0),
            Step::GiveUp(1),
            Step::GiveUp(2),
            Step::Sweep,
            Step::Sweep,
            Step::Write,
            Step::Write,
        ];
        orders(&mut steps, &mut Vec::new(), &mut all);
        assert_eq!(all.len(), 1260);

        for order in all {
            let (mut driver, _dispatch_rx, mut writer) = test_driver(1);
            let mut callers: Vec<_> = (0..3)
                .map(|_| {
                    let (cmd, waiter) = send_cmd();
                    assert!(matches!(driver.take(cmd).unwrap(), Took::Queued));
                    waiter
                })
                .collect();
            let mut gave_up = [false; 3];
            let mut written = Vec::new();
            let mut write = |gave_up: &[bool; 3], written: &mut Vec<u64>| {
                if let Popped::Frame(text) = writer.pop() {
                    let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let request = request_number(frame["id"].as_str().unwrap()).unwrap();
                    assert!(
                        !gave_up[request as usize - 1],
                        "{order:?}: req-{request} written after its caller gave up"
                    );
                    written.push(request);
                }
            };
            // The first request is being written.
            write(&gave_up, &mut written);
            for &step in &order {
                match step {
                    Step::GiveUp(call) => {
                        assert!(callers[call].give_up().is_none());
                        gave_up[call] = true;
                    }
                    Step::Sweep => driver.sweep(),
                    Step::Write => write(&gave_up, &mut written),
                }
            }
            driver.sweep();
            let remembered: Vec<u64> = driver.pending.keys().copied().collect();
            written.sort_unstable();
            assert_eq!(remembered, written, "{order:?}: the calls still remembered");
            assert!(
                driver
                    .pending
                    .values()
                    .all(|waiting| matches!(waiting, OneOfPending::Abandoned(Op::Send))),
                "{order:?}: every one of them abandoned"
            );
            assert_eq!(driver.abandoned, written.len(), "{order:?}");
            assert!(
                waiting(&driver).is_empty(),
                "{order:?}: nothing left queued"
            );
            assert_eq!(driver.outbox.requests(), 0, "{order:?}");
        }
    }

    /// A call whose caller timed out before the driver took it sends
    /// nothing, except an unsubscribe, which is always carried out.
    #[test]
    fn a_call_whose_caller_has_gone_sends_nothing_but_an_unsubscribe() {
        let (mut driver, _dispatch_rx, _writer) = test_driver(1);
        let (send, mut send_rx) = send_cmd();
        assert!(send_rx.give_up().is_none());
        assert!(matches!(driver.take(send).unwrap(), Took::Nothing));
        assert!(waiting(&driver).is_empty());
        assert!(driver.pending.is_empty());

        let (reply, mut rx) = call_ends::<u64>(Op::Unsubscribe);
        assert!(rx.give_up().is_none());
        let unsubscribe = Cmd::Unsubscribe {
            sub: SubscriptionId("s".into()),
            reply,
        };
        assert!(matches!(driver.take(unsubscribe).unwrap(), Took::Queued));
        driver.sweep();
        let queued = waiting(&driver);
        assert_eq!(queued.len(), 1, "the unsubscribe is not withdrawn");
        assert_eq!(queued[0]["op"], "unsubscribe");
        assert!(matches!(
            driver.pending.values().next(),
            Some(OneOfPending::Abandoned(Op::Unsubscribe))
        ));
    }

    /// The driver takes a call only while fewer than `OUTBOUND_QUEUE`
    /// requests wait for the writer, and the client's own frames do not
    /// count. A sweep that removes a withdrawn request makes room, and so
    /// does the writer taking one, which wakes a driver waiting for room.
    #[test]
    fn the_outbox_has_room_for_outbound_queue_requests() {
        let (mut driver, _dispatch_rx, mut writer) = test_driver(1);
        let mut callers = Vec::new();
        for _ in 0..OUTBOUND_QUEUE {
            assert!(driver.outbox.has_room());
            let (cmd, waiter) = send_cmd();
            assert!(matches!(driver.take(cmd).unwrap(), Took::Queued));
            callers.push(waiter);
        }
        assert!(!driver.outbox.has_room(), "full at OUTBOUND_QUEUE requests");
        driver.release("s".into());
        assert_eq!(
            waiting(&driver).len(),
            OUTBOUND_QUEUE + 1,
            "a release is queued past the depth"
        );

        let mut last = callers.pop().unwrap();
        assert!(last.give_up().is_none());
        assert!(!driver.outbox.has_room(), "not until the sweep removes it");
        driver.sweep();
        assert!(
            driver.outbox.has_room(),
            "a withdrawn request frees its place"
        );
        let (cmd, _waiter) = send_cmd();
        assert!(matches!(driver.take(cmd).unwrap(), Took::Queued));
        assert!(!driver.outbox.has_room());

        let room = driver.outbox.room();
        assert!(matches!(writer.pop(), Popped::Frame(_)));
        assert!(driver.outbox.has_room(), "the writer took a request");
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), room)
                    .await
                    .expect("the writer's take wakes a driver waiting for room");
            });
    }

    /// At most `MAX_ABANDONED` timed-out calls are remembered, the oldest
    /// forgotten first.
    #[test]
    fn abandoned_calls_are_capped_oldest_first() {
        let (mut driver, _dispatch_rx, _writer) = test_driver(1);
        for request in 1..=MAX_ABANDONED as u64 + 2 {
            let (tx, mut rx) = call_ends(Op::Send);
            // Written, then given up on.
            assert!(tx.ticket.take());
            assert!(rx.give_up().is_none());
            driver.pending.insert(request, OneOfPending::Send(tx));
        }
        driver.sweep();
        assert_eq!(driver.abandoned, MAX_ABANDONED);
        assert_eq!(driver.pending.len(), MAX_ABANDONED);
        assert_eq!(
            driver.pending.keys().next(),
            Some(&3),
            "the oldest two went"
        );
    }

    /// Releases the daemon never answers are kept with the abandoned calls,
    /// at most `MAX_ABANDONED` of the two together, the oldest forgotten
    /// first. A reply to a forgotten request answers nothing, and is not
    /// late.
    #[test]
    fn releases_the_daemon_never_answers_are_capped_with_the_abandoned_calls() {
        let (mut driver, _dispatch_rx, mut writer) = test_driver(1);
        // Two calls whose requests were written, then given up on.
        for _ in 0..2 {
            let (cmd, mut waiter) = send_cmd();
            assert!(matches!(driver.take(cmd).unwrap(), Took::Queued));
            assert!(matches!(writer.pop(), Popped::Frame(_)));
            assert!(waiter.give_up().is_none());
        }
        driver.sweep();
        assert_eq!(driver.abandoned, 2);
        // A release for each late subscribe ack, none of them answered.
        for n in 0..MAX_ABANDONED {
            driver.release(format!("s{n}"));
            assert!(matches!(writer.pop(), Popped::Frame(_)));
        }
        assert_eq!(driver.abandoned, MAX_ABANDONED);
        assert_eq!(driver.pending.len(), MAX_ABANDONED);
        assert_eq!(
            driver.pending.keys().next(),
            Some(&3),
            "the abandoned calls, the oldest, went first"
        );
        driver.release("last".into());
        assert_eq!(driver.pending.len(), MAX_ABANDONED);
        assert_eq!(
            driver.pending.keys().next(),
            Some(&4),
            "then the oldest release"
        );

        let routed = driver.route_inbound(ack(1, AckFields::default()));
        assert!(matches!(routed, Routed::Nothing), "forgotten");
        let routed = driver.route_inbound(ack(4, AckFields::default()));
        assert!(matches!(routed, Routed::Nothing), "a release's answer");
        assert_eq!(driver.pending.len(), MAX_ABANDONED - 1);
        assert_eq!(driver.abandoned, MAX_ABANDONED - 1);
        assert_eq!(
            driver.late_replies.load(Ordering::Relaxed),
            0,
            "neither is late"
        );
    }

    /// The longest span the clock can add to `now`, the end of `Instant`'s
    /// range: whole seconds, then nanoseconds, by bisection.
    fn clock_reach(now: std::time::Instant) -> Duration {
        let (mut secs, mut over) = (0u64, u64::MAX);
        while secs < over {
            let mid = secs + (over - secs).div_ceil(2);
            if now.checked_add(Duration::from_secs(mid)).is_some() {
                secs = mid;
            } else {
                over = mid - 1;
            }
        }
        let (mut nanos, mut over) = (0u32, 999_999_999u32);
        while nanos < over {
            let mid = nanos + (over - nanos).div_ceil(2);
            if now.checked_add(Duration::new(secs, mid)).is_some() {
                nanos = mid;
            } else {
                over = mid - 1;
            }
        }
        Duration::new(secs, nanos)
    }

    /// Every deadline the client sets, and the heartbeat's first tick, lies
    /// at most thirty years out, far inside what tokio's timer represents,
    /// even for a timeout that ends in the last millisecond of `Instant`'s
    /// range.
    #[test]
    fn every_deadline_lies_well_inside_the_timers_range() {
        use futures_util::FutureExt;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let reach = clock_reach(std::time::Instant::now());
            // In the clock's last millisecond, with half of it to get there.
            let edge = reach.saturating_sub(Duration::from_micros(500));
            for after in [
                edge,
                reach,
                FAR_FUTURE + Duration::from_nanos(1),
                Duration::MAX,
            ] {
                let now = tokio::time::Instant::now();
                let deadline = deadline_after(after);
                assert!(deadline >= now + FAR_FUTURE, "{after:?}");
                assert!(
                    deadline <= tokio::time::Instant::now() + FAR_FUTURE,
                    "{after:?}"
                );
                // The timer takes it: set up, and polled once.
                let sleep = tokio::time::sleep_until(deadline);
                tokio::pin!(sleep);
                assert!(sleep.as_mut().now_or_never().is_none(), "{after:?}");
                let mut heartbeat = heartbeat_timer(now, after).expect("a heartbeat");
                assert!(heartbeat.tick().now_or_never().is_none(), "{after:?}");
            }
            assert!(heartbeat_timer(tokio::time::Instant::now(), Duration::ZERO).is_none());
        });
    }

    /// The command queue, the doorbell and the cap as the `Router` drives
    /// them for the fuzz harness: a call past `COMMAND_QUEUE` comes back to
    /// its caller, to report `QueueFull` if the queue is still full at its
    /// deadline; a turn takes calls only while the outbox has room; a caller
    /// that times out rings the doorbell, and the next turn withdraws its
    /// request, which makes room; and a cap of zero forgets an abandoned call
    /// at once, so its reply comes to nothing.
    #[test]
    fn the_router_refuses_past_the_queue_and_settles_what_timed_out_at_its_turn() {
        let mut router = Router::with_max_abandoned(1, usize::MAX, 0);
        let offer = |router: &mut Router, n: usize| {
            let (call, waiter) = Call::send(&format!("c{n}"), b"x");
            (router.offer(call), waiter)
        };
        let mut callers = Vec::new();
        for n in 0..OUTBOUND_QUEUE + COMMAND_QUEUE {
            let (refused, waiter) = offer(&mut router, n);
            assert!(refused.is_none(), "call {n} was refused");
            callers.push(waiter);
            if n < OUTBOUND_QUEUE {
                assert!(router.turn().unwrap(), "call {n} was not taken");
            }
        }
        assert_eq!(router.queued(), COMMAND_QUEUE);
        assert!(!router.has_room());
        assert!(!router.turn().unwrap(), "no room: nothing is taken");
        let (refused, _late) = offer(&mut router, 999);
        let refused = refused.expect("a call past the command queue comes back");
        assert!(matches!(
            refused.refused(),
            DevError::QueueFull { op: "send" }
        ));

        // The writer takes the first request; the first two callers time out.
        let first = router.write_next().expect("the first request");
        assert!(first.contains(r#""id":"req-1""#), "{first}");
        for caller in &mut callers[..2] {
            assert!(router.time_out(caller).is_none());
        }
        assert_eq!(router.waiting().len(), OUTBOUND_QUEUE - 1, "not swept yet");
        assert!(router.turn().unwrap(), "the turn swept, and took a call");
        assert_eq!(router.waiting().len(), OUTBOUND_QUEUE - 1);
        assert_eq!(router.queued(), COMMAND_QUEUE - 1);
        assert!(
            router.offer(refused).is_none(),
            "the room goes to the caller"
        );

        // The written request's caller was abandoned, and with a cap of
        // zero forgotten: its reply comes to nothing, and is not late.
        router.route(ServerMessage::ack(Some(request_id(1))));
        assert_eq!(router.late_replies(), 0);
    }

    /// A fake transport: the driver's `Link`, and the far ends a test holds
    /// in place of the connection's reader and writer.
    fn fake_link() -> (Link, InboundTx, OutboxRx) {
        let (reader, inbound) = inbound_queue(INBOUND_QUEUE, INBOUND_QUEUE_BYTES);
        let (outbound, writer) = outbox();
        let link = Link {
            inbound,
            outbound,
            heard: reader.heard(),
            io: Io::default(),
        };
        (link, reader, writer)
    }

    /// Hand the driver one message, as the transport's reader does.
    fn deliver(reader: &InboundTx, message: ServerMessage) {
        let delivered = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(reader.send(message, 0));
        assert!(delivered, "the driver has gone");
    }

    /// The next frame the client queued for the daemon, as the transport's
    /// writer takes it; `None` once the driver has ended.
    fn next_frame(writer: &mut OutboxRx) -> Option<String> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(writer.recv())
    }

    /// Take the attach the client wrote and acknowledge it, as a daemon.
    fn ack_attach(reader: &InboundTx, writer: &mut OutboxRx) {
        let attach: serde_json::Value =
            serde_json::from_str(&next_frame(writer).expect("the attach")).unwrap();
        assert_eq!(attach["op"], "attach");
        deliver(
            reader,
            ServerMessage::ack(attach["id"].as_str().map(String::from)),
        );
    }

    /// A write that fails ends the connection with an error though the
    /// reader is still up: the call whose frame it was and `wait` both get
    /// `Disconnected`, and neither waits on the reader.
    #[test]
    fn a_failed_write_is_an_error_for_the_waiting_call_and_for_wait() {
        let (link, reader, mut writer) = fake_link();
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            let send = next_frame(&mut writer).expect("the send reached the writer");
            assert!(send.contains(r#""op":"send""#), "{send}");
            // Writing it fails, and the writer stops; the reader stays up.
            drop(writer);
            reader
        });
        let mesh =
            Mesh::start("w", &MeshOptions::default(), async move { Ok(link) }).expect("attach");
        let started = std::time::Instant::now();
        let sent = mesh.send("c", b"x");
        assert!(matches!(sent, Err(DevError::Disconnected)), "{sent:?}");
        let ended = mesh.wait();
        assert!(matches!(ended, Err(DevError::Disconnected)), "{ended:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the reader, still up, is not waited on"
        );
        drop(daemon.join().unwrap());
    }

    /// A daemon that refuses a frame says why and closes; a write failing
    /// meanwhile does not hide the reason.
    #[test]
    fn the_daemons_reason_survives_a_failed_write() {
        let (link, reader, mut writer) = fake_link();
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            let _send = next_frame(&mut writer).expect("the send reached the writer");
            drop(writer);
            deliver(
                &reader,
                ServerMessage::error(
                    None,
                    ErrorCode::PayloadTooLarge,
                    "frame of 9 bytes exceeds the 8 byte limit",
                ),
            );
        });
        let mesh =
            Mesh::start("r", &MeshOptions::default(), async move { Ok(link) }).expect("attach");
        let sent = mesh.send("c", b"x");
        assert!(
            matches!(sent, Err(DevError::Daemon { ref code, .. }) if code == "payload_too_large"),
            "{sent:?}"
        );
        let ended = mesh.wait();
        assert!(
            matches!(ended, Err(DevError::Daemon { ref code, .. }) if code == "payload_too_large"),
            "{ended:?}"
        );
        daemon.join().unwrap();
    }

    /// Every call the connection's end finds waiting reports the daemon's
    /// parting reason, wherever it waits: taken by the driver, its request
    /// in the outbox; in the command queue behind a full outbox; or waiting
    /// for room there. A call made after the end finds nothing to wait on,
    /// and reports `DisconnectedDuringRpc`.
    #[test]
    fn every_call_still_waiting_gets_the_daemons_parting_reason() {
        const EXTRA: usize = 8;
        fn is_reason<T>(result: &Result<T, DevError>) -> bool {
            matches!(result, Err(DevError::Daemon { code, .. }) if code == "payload_too_large")
        }
        let (link, reader, mut writer) = fake_link();
        let options = MeshOptions::default()
            .with_rpc_timeout(Duration::from_secs(60))
            .with_heartbeat_interval(Duration::ZERO);
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            (reader, writer)
        });
        let mesh = Mesh::start("parting", &options, async move { Ok(link) }).expect("attach");
        // The writer takes nothing more.
        let (reader, writer) = daemon.join().unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let call = |n: usize| {
            let mesh = mesh.clone();
            let started = Arc::clone(&started);
            std::thread::spawn(move || {
                started.fetch_add(1, Ordering::SeqCst);
                mesh.send(&format!("c{n}"), b"x")
            })
        };
        let mut callers: Vec<_> = (0..OUTBOUND_QUEUE + COMMAND_QUEUE).map(call).collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while writer.shared.state.lock().requests < OUTBOUND_QUEUE
            || mesh.inner.cmd_tx.capacity() > 0
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the outbox and the command queue did not fill"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        callers.extend((0..EXTRA).map(|n| call(OUTBOUND_QUEUE + COMMAND_QUEUE + n)));
        while started.load(Ordering::SeqCst) < callers.len() {
            assert!(
                std::time::Instant::now() < deadline,
                "a caller never started"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Long enough for the last callers to wait for room.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(writer.shared.state.lock().requests, OUTBOUND_QUEUE);
        assert_eq!(mesh.inner.cmd_tx.capacity(), 0, "the command queue is full");
        assert!(
            callers.iter().all(|caller| !caller.is_finished()),
            "every call waits"
        );

        // The daemon says why, unprompted, and closes.
        deliver(
            &reader,
            ServerMessage::error(
                None,
                ErrorCode::PayloadTooLarge,
                "frame of 99 bytes exceeds the 1 byte limit",
            ),
        );
        drop(reader);
        for caller in callers {
            let sent = caller.join().unwrap();
            assert!(is_reason(&sent), "{sent:?}");
        }
        let ended = mesh.wait();
        assert!(is_reason(&ended), "{ended:?}");
        let after = mesh.send("c", b"x");
        assert!(
            matches!(after, Err(DevError::DisconnectedDuringRpc)),
            "{after:?}"
        );
        drop(writer);
    }

    /// On a transport with a ping, the client pings a daemon silent for a
    /// third of the limit, once per silence, and gives it up at the limit,
    /// whether or not it owes an answer; anything heard from it starts the
    /// count again, and a ping the client itself was late to send leaves
    /// the answer the rest of the limit.
    #[test]
    fn with_a_ping_the_client_pings_once_per_silence_and_gives_up_at_the_limit() {
        let t0 = tokio::time::Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let limit = Duration::from_millis(900);

        let mut rule = Silence::new(limit, true).unwrap();
        assert_eq!(
            rule.judge(at(0), at(0), false),
            Verdict::Until(Some(at(300)))
        );
        assert_eq!(
            rule.judge(at(299), at(0), true),
            Verdict::Until(Some(at(300)))
        );
        assert_eq!(rule.judge(at(300), at(0), false), Verdict::Ping(at(900)));
        assert_eq!(
            rule.judge(at(600), at(0), false),
            Verdict::Until(Some(at(900))),
            "once per silence"
        );
        assert_eq!(rule.judge(at(900), at(0), false), Verdict::Silent);

        let mut rule = Silence::new(limit, true).unwrap();
        assert_eq!(rule.judge(at(300), at(0), false), Verdict::Ping(at(900)));
        assert_eq!(
            rule.judge(at(850), at(800), false),
            Verdict::Until(Some(at(1100))),
            "heard from again: the count starts over"
        );
        assert_eq!(
            rule.judge(at(1100), at(800), false),
            Verdict::Ping(at(1700))
        );

        let mut rule = Silence::new(limit, true).unwrap();
        assert_eq!(
            rule.judge(at(5000), at(0), true),
            Verdict::Ping(at(5600)),
            "a late ping leaves the answer the rest of the limit"
        );
    }

    /// Without a ping, the limit runs only while the daemon owes an answer:
    /// an idle daemon is never given up, however long its silence, and the
    /// count runs from when it came to owe one, or was last heard from.
    #[test]
    fn without_a_ping_the_limit_runs_only_while_an_answer_is_owed() {
        let t0 = tokio::time::Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut rule = Silence::new(Duration::from_millis(900), false).unwrap();
        assert_eq!(rule.judge(at(10_000), at(0), false), Verdict::Until(None));
        assert_eq!(
            rule.judge(at(10_000), at(0), true),
            Verdict::Until(Some(at(10_900)))
        );
        assert_eq!(
            rule.judge(at(10_500), at(0), true),
            Verdict::Until(Some(at(10_900)))
        );
        assert_eq!(
            rule.judge(at(10_700), at(10_600), true),
            Verdict::Until(Some(at(11_500))),
            "heard from while it owes"
        );
        assert_eq!(rule.judge(at(11_500), at(10_600), true), Verdict::Silent);

        let mut rule = Silence::new(Duration::from_millis(900), false).unwrap();
        assert_eq!(
            rule.judge(at(0), at(0), true),
            Verdict::Until(Some(at(900)))
        );
        assert_eq!(rule.judge(at(100), at(50), false), Verdict::Until(None));
        assert_eq!(
            rule.judge(at(5000), at(50), true),
            Verdict::Until(Some(at(5900))),
            "a later request counts from itself"
        );
    }

    /// A limit of zero disables the rule, and one too long for the clock is
    /// thirty years, which no connection outlives and the clock can add.
    #[test]
    fn a_silence_limit_of_zero_or_past_the_clock_never_gives_up() {
        assert!(Silence::new(Duration::ZERO, true).is_none());
        assert!(Silence::new(Duration::ZERO, false).is_none());
        let now = tokio::time::Instant::now();
        let mut rule = Silence::new(Duration::MAX, true).unwrap();
        assert_eq!(
            rule.judge(now, now, true),
            Verdict::Until(Some(now + FAR_FUTURE / 3))
        );
        let mut rule = Silence::new(Duration::MAX, false).unwrap();
        assert_eq!(
            rule.judge(now, now, true),
            Verdict::Until(Some(now + FAR_FUTURE))
        );
    }

    /// Without a ping, a daemon that answers nothing is given up once a
    /// call waits for it, and not while the connection is idle; the call
    /// and `wait` report `Silent`, and the connection is over.
    #[test]
    fn a_daemon_silent_while_a_call_waits_is_given_up() {
        const LIMIT: Duration = Duration::from_millis(300);
        let (link, reader, mut writer) = fake_link();
        let options = MeshOptions::default()
            .with_rpc_timeout(Duration::from_secs(30))
            .with_heartbeat_interval(Duration::ZERO)
            .with_silence_limit(LIMIT);
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            (reader, writer)
        });
        let mesh = Mesh::start("silent", &options, async move { Ok(link) }).expect("attach");
        let (_reader, _writer) = daemon.join().unwrap();
        let waiting = {
            let mesh = mesh.clone();
            std::thread::spawn(move || mesh.wait())
        };
        std::thread::sleep(LIMIT * 3);
        assert!(!waiting.is_finished(), "an idle daemon is not given up");

        let started = std::time::Instant::now();
        let sent = mesh.send("c", b"x");
        let took = started.elapsed();
        assert!(
            matches!(sent, Err(DevError::Silent { after }) if after == LIMIT),
            "{sent:?}"
        );
        assert!(took >= LIMIT && took < Duration::from_secs(10), "{took:?}");
        let ended = waiting.join().unwrap();
        assert!(matches!(ended, Err(DevError::Silent { .. })), "{ended:?}");
        let after = mesh.send("c", b"x");
        assert!(
            matches!(after, Err(DevError::DisconnectedDuringRpc)),
            "{after:?}"
        );
    }

    /// With a ping, an idle daemon is pinged after a third of the limit of
    /// silence; one that answers, with anything, is kept, and pinged again
    /// after the next silence, and one that answers nothing is given up at
    /// the limit.
    #[test]
    fn a_daemon_that_answers_the_ping_is_kept_and_one_that_does_not_is_given_up() {
        const LIMIT: Duration = Duration::from_secs(3);
        let (mut link, reader, mut writer) = fake_link();
        let ping = Arc::new(Notify::new());
        link.io.ping = Some(Arc::clone(&ping));
        let options = MeshOptions::default()
            .with_heartbeat_interval(Duration::ZERO)
            .with_silence_limit(LIMIT);
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            (reader, writer)
        });
        // Before the attach: the silence that leads to the ping is counted
        // from the attach's ack, so a clock started after the attach and the
        // thread joins, which a loaded machine can delay, reads short.
        let started = std::time::Instant::now();
        let mesh = Mesh::start("pinged", &options, async move { Ok(link) }).expect("attach");
        let (reader, _writer) = daemon.join().unwrap();
        let waiting = {
            let mesh = mesh.clone();
            std::thread::spawn(move || mesh.wait())
        };
        let pinged = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
                .block_on(async { tokio::time::timeout(LIMIT, ping.notified()).await })
                .is_ok()
        };
        assert!(pinged(), "an idle daemon is pinged");
        assert!(started.elapsed() >= LIMIT / 3, "{:?}", started.elapsed());
        deliver(
            &reader,
            ServerMessage::Health {
                node_id: "n@1".into(),
                state: "ok".into(),
                since_unix_nanos: 0,
            },
        );
        let answered = std::time::Instant::now();
        assert!(pinged(), "and pinged again after the next silence");
        assert!(answered.elapsed() >= LIMIT / 3, "{:?}", answered.elapsed());
        let ended = waiting.join().unwrap();
        assert!(
            matches!(ended, Err(DevError::Silent { after }) if after == LIMIT),
            "{ended:?}"
        );
        assert!(
            answered.elapsed() >= LIMIT,
            "given up at the limit: {:?}",
            answered.elapsed()
        );
    }

    /// Only a detach the daemon acknowledged ends the connection cleanly: a
    /// connection that ends before the acknowledgement is an error for the
    /// detach and for `wait`.
    #[test]
    fn a_detach_the_daemon_never_acknowledged_is_not_a_clean_end() {
        let (link, reader, mut writer) = fake_link();
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            let detach = next_frame(&mut writer).expect("the detach");
            assert!(detach.contains(r#""op":"detach""#), "{detach}");
            // The connection ends here, unacknowledged.
        });
        let mesh =
            Mesh::start("d", &MeshOptions::default(), async move { Ok(link) }).expect("attach");
        let detached = mesh.detach();
        assert!(
            matches!(detached, Err(DevError::Disconnected)),
            "{detached:?}"
        );
        let ended = mesh.wait();
        assert!(matches!(ended, Err(DevError::Disconnected)), "{ended:?}");
        daemon.join().unwrap();
    }

    /// The last handle may be dropped on one of the runtime's own threads,
    /// as it is when the driver drops a timed-out subscribe's callback that
    /// held a `Mesh`: nothing panics, and the connection's task ends.
    #[test]
    fn the_last_handle_may_be_dropped_on_the_runtimes_own_thread() {
        let (link, reader, mut writer) = fake_link();
        let daemon = std::thread::spawn(move || {
            ack_attach(&reader, &mut writer);
            // `None` once the driver has ended.
            next_frame(&mut writer)
        });
        let mesh =
            Mesh::start("own", &MeshOptions::default(), async move { Ok(link) }).expect("attach");
        let runtime = mesh.inner.handle.clone();
        let dropped = runtime.spawn(async move { drop(mesh) });
        let joined = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(dropped);
        assert!(
            joined.is_ok(),
            "dropped on the runtime's thread: {joined:?}"
        );
        assert_eq!(
            daemon.join().unwrap(),
            None,
            "the connection's task ended, having queued nothing more"
        );
    }

    /// The queue from the reader holds at most its budget in bytes, the
    /// message being routed included: the reader waits, nothing is dropped,
    /// and a message's bytes come back once the driver has routed it. A
    /// message longer than the whole budget waits for the queue to empty and
    /// goes alone; and a reader waiting for room stops once the driver has
    /// gone.
    #[test]
    fn the_reader_waits_while_the_queue_holds_its_budget_in_bytes() {
        use futures_util::FutureExt;
        let health = || ServerMessage::Health {
            node_id: "n@1".into(),
            state: "ok".into(),
            since_unix_nanos: 0,
        };
        let (reader, mut queue) = inbound_queue(INBOUND_QUEUE, 3000);
        for _ in 0..3 {
            assert_eq!(reader.send(health(), 1000).now_or_never(), Some(true));
        }
        let mut fourth = Box::pin(reader.send(health(), 1000));
        assert_eq!((&mut fourth).now_or_never(), None, "the budget is spent");
        let routing = queue.try_recv().expect("the oldest message");
        assert_eq!(
            (&mut fourth).now_or_never(),
            None,
            "a message being routed still counts"
        );
        drop(routing);
        assert_eq!(
            (&mut fourth).now_or_never(),
            Some(true),
            "its bytes came back"
        );

        let mut long = Box::pin(reader.send(health(), 10_000));
        assert_eq!(
            (&mut long).now_or_never(),
            None,
            "waits for the queue to empty"
        );
        for _ in 0..3 {
            drop(queue.try_recv().expect("a message"));
        }
        assert_eq!((&mut long).now_or_never(), Some(true), "then goes alone");
        let mut behind = Box::pin(reader.send(health(), 1));
        assert_eq!((&mut behind).now_or_never(), None, "alone");

        drop(queue);
        assert_eq!(
            (&mut behind).now_or_never(),
            Some(false),
            "the driver has gone"
        );
    }

    /// A burst of large messages from the daemon while the driver takes
    /// none: the reader queues as many as the byte budget holds, far fewer
    /// than the 64 the count allows, then stops reading, which leaves the
    /// rest in the socket and stalls the daemon's writes. Nothing is dropped:
    /// once the driver takes them, every message arrives, in order.
    #[test]
    fn a_burst_of_large_messages_holds_at_most_the_inbound_budget() {
        const FRAMES: usize = 48;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (ours, theirs) = {
            let _entered = runtime.enter();
            tokio::net::UnixStream::pair().unwrap()
        };
        let (reader, mut queue) = inbound_queue(INBOUND_QUEUE, INBOUND_QUEUE_BYTES);
        runtime.spawn(read_uds(ours, reader));

        // Events of about 1 MiB each, their payload a run of base64.
        let event = |n: usize| {
            let payload = "A".repeat(1 << 20);
            format!(
                r#"{{"op":"event","subscription_id":"s","envelope_id":"e{n:02}","channel":"c","type_id":0,"origin":"o@1","captured_at_unix_nanos":0,"payload":"{payload}"}}"#
            )
        };
        let frame_len = event(0).len();
        let fit = INBOUND_QUEUE_BYTES / frame_len;
        assert!(fit < INBOUND_QUEUE, "the bytes, not the count, bound these");
        let written = Arc::new(AtomicU64::new(0));
        let daemon = {
            let written = Arc::clone(&written);
            let mut socket = theirs.into_std().unwrap();
            socket.set_nonblocking(false).unwrap();
            std::thread::spawn(move || {
                use std::io::Write;
                for n in 0..FRAMES {
                    let body = event(n);
                    socket
                        .write_all(&(body.len() as u32).to_be_bytes())
                        .unwrap();
                    socket.write_all(body.as_bytes()).unwrap();
                    written.fetch_add(1, Ordering::SeqCst);
                }
                socket
            })
        };

        // The reader fills the queue to its budget, and never past it.
        let held = |queue: &mpsc::Receiver<Received>| queue.len() * frame_len;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while queue.len() < fit {
            assert!(held(&queue) <= INBOUND_QUEUE_BYTES);
            assert!(
                std::time::Instant::now() < deadline,
                "the reader queued only {} messages",
                queue.len()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(queue.len(), fit, "no more than the budget holds");
        assert!(held(&queue) <= INBOUND_QUEUE_BYTES);
        assert!(
            (written.load(Ordering::SeqCst) as usize) < FRAMES,
            "the rest wait in the socket: the daemon's writes stall"
        );

        // The driver takes them: every message arrives, in order.
        for n in 0..FRAMES {
            assert!(held(&queue) <= INBOUND_QUEUE_BYTES);
            let received = runtime
                .block_on(queue.recv())
                .expect("every message arrives");
            match received.message {
                ServerMessage::Event { envelope_id, .. } => {
                    assert_eq!(envelope_id, format!("e{n:02}"));
                }
                other => panic!("an event was expected, got {other:?}"),
            }
        }
        drop(daemon.join().unwrap());
        assert_eq!(written.load(Ordering::SeqCst) as usize, FRAMES);
    }
}
