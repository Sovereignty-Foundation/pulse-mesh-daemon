// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The per-connection loop both transports run ([`handle_connection`]), and the
//! [`ConnectionPolicy`] it serves under.
//!
//! The loop makes trace-level spans, which cost a level check unless a layer
//! takes them (`crate::otel`): `attach`, `detach` (a detach message, or an
//! attached connection closing), `subscribe` and `unsubscribe` around their
//! messages, and `deliver` around each event or health notice written to the
//! connection. A message's send is spanned by the bridge (`HubBridge::send`);
//! a `prove` runs in an `attach` span too.
//!
//! An attach that carries a key is answered with a challenge, and the
//! connection is attached once its proof verifies (`mesh_port_protocol::
//! attach`): the loop keeps the challenge, its nonce and its deadline, the
//! policy's handshake timeout, until a `prove` answers it. While one is
//! pending, a `health` frame is read and a `detach` acknowledged as ever, and
//! anything else is refused with `auth_failed`; a refused proof, a refused
//! key and an unanswered challenge are too, and each closes the connection.

use crate::attach_keys::AttachKeys;
use crate::hub_bridge::{BridgeError, HubBridge, SubscriptionId};
use crate::origin::AllowedOrigin;
use crate::protocol::{
    attach, base64, AckFields, ClientMessage, ErrorCode, ServerMessage, MAX_NAME_LEN,
    PROTOCOL_VERSION,
};
use crate::queue::{event_queue, EventSink};
use crate::registry::{AttachResult, AttachedEntry, ConnectionId, Origin, Registry};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, warn, Instrument as _};

/// The default of [`ConnectionPolicy::total_queue_bytes`] and the daemon's
/// `--total-queue-bytes`: 256 MiB.
pub const DEFAULT_TOTAL_QUEUE_BYTES: usize = 256 * 1024 * 1024;

/// The most bytes of a client's string, or of the JSON parser's message about
/// its text, that an error message quotes.
pub const MAX_QUOTED: usize = 128;

/// `text` as an error message quotes it: whole when it is at most
/// [`MAX_QUOTED`] bytes, otherwise cut there, at a character boundary, and
/// marked with an ellipsis and the length it had.
#[must_use]
pub fn quoted(text: &str) -> Cow<'_, str> {
    if text.len() <= MAX_QUOTED {
        return Cow::Borrowed(text);
    }
    let mut end = MAX_QUOTED;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}… ({} bytes)", &text[..end], text.len()))
}

/// How the daemon serves connections: liveness timers, per-connection caps, the
/// caps on connections and on the event bytes queued across them, the web
/// origins whose pages may open the WebSocket, and the keys a client may prove
/// at attach.
///
/// The daemon and an embedded mesh take the same policy and hand it to every
/// connection, which is why the attach keys are here, beside the origins,
/// rather than in `DaemonConfig` alone: a host that embeds a mesh sets them as
/// the command line does.
///
/// No value aborts the daemon: a timer too long for the clock never fires, and
/// a queue asked for more than [`crate::MAX_QUEUE_EVENTS`] events holds that
/// many.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionPolicy {
    /// How often a WebSocket client is pinged; zero disables pings. The Unix
    /// socket has no ping, so its clients' own frames keep them alive against
    /// [`Self::idle_timeout`].
    pub ping_interval: Duration,
    /// Silence (no inbound frame and no pong) after which the connection is
    /// closed. Zero disables the idle check.
    ///
    /// It also paces the daemon's record of each attached connection's
    /// health, ticked every tenth of it: a connection silent for half of it
    /// is `warning`, and one silent for the whole of it is closed, which ends
    /// its record as `detached`. A client whose subscription sets
    /// `FilterSpec::health` is told of every such change of its peers'. Zero
    /// turns the record off too. Checked by `tests/liveness.rs`.
    pub idle_timeout: Duration,
    /// How long one outbound write may take before the connection is
    /// closed as unreadable. Zero waits forever.
    pub write_timeout: Duration,
    /// How long a WebSocket upgrade may take before the TCP connection is
    /// dropped.
    pub handshake_timeout: Duration,
    /// Largest message accepted on either transport, in bytes: a Unix-socket
    /// frame, or a WebSocket message however many frames it comes in. A larger
    /// one is refused with `payload_too_large` at the header that declares it,
    /// and the connection closes. While a connection reads a message it holds
    /// at most about this much (the Unix socket's decoder up to twice it), and
    /// nothing of it once it is handled (`tests/connection_memory.rs`).
    pub max_message_bytes: usize,
    /// Events queued for one connection before newer ones are dropped and
    /// counted in the unsubscribe ack; zero is taken as one, and more than
    /// [`crate::MAX_QUEUE_EVENTS`] as that many.
    pub subscriber_queue: usize,
    /// Bytes of event JSON queued for one connection, the event being written
    /// included, before newer events are dropped and counted: the most a
    /// subscriber that stops reading makes the daemon hold
    /// (`tests/event_memory.rs`). Each connection counts an event's whole size,
    /// though its JSON is shared; zero drops every event.
    pub subscriber_queue_bytes: usize,
    /// Bytes of event JSON queued across all connections, which share it by
    /// longest-queue drop: with `k` connections holding events, one whose
    /// queue, the new event included, stays within `total_queue_bytes / k` is
    /// given room by the connection holding the most, which drops its newest
    /// waiting events, and one over its share gets only what is free. A reader
    /// that keeps up holds at most two events, so it loses none to this budget
    /// while `k` stays under `total_queue_bytes / (2 * max_message_bytes)`,
    /// about 128 at the defaults. Every drop is counted for its subscription
    /// and in the daemon's exit line; zero drops every event. Checked by
    /// `tests/fanout.rs`.
    pub total_queue_bytes: usize,
    /// Subscriptions one connection may hold at once; a subscribe beyond it is
    /// refused with `limit_exceeded` until an unsubscribe frees a place, and
    /// zero refuses every subscribe.
    pub max_subscriptions: usize,
    /// Connections the daemon holds at once, across both transports, from
    /// accept to close. One beyond it is refused before anything it sends is
    /// read (a `limit_exceeded` frame on the Unix socket, HTTP 503 on the
    /// WebSocket) and closed; zero refuses every connection. Checked by
    /// `tests/connections.rs`.
    pub max_connections: usize,
    /// Web origins, besides the loopback ones (`http` or `https` on
    /// `localhost`, `127.0.0.1` or `[::1]`, any port), whose pages may open the
    /// WebSocket: an upgrade from any other page is refused with 403, and one
    /// without an `Origin` header, from a client that is not a page, is
    /// admitted. Checked by `tests/origin.rs`.
    pub allowed_origins: Vec<AllowedOrigin>,
    /// The Ed25519 public keys a client may prove at attach (ADR-0018 item
    /// 6), or `None` to keep no list. With a list, an attach on the WebSocket
    /// must carry a listed key and prove it, and one without a key is refused
    /// with `auth_failed`; the Unix socket, which the operating system keeps
    /// to the daemon's user, still admits an attach without a key unless
    /// [`Self::attach_keys_uds`]. On either transport an attach that carries a
    /// key proves it, and with a list the key must be on it. Without a list
    /// every attach is admitted as before, and one that carries a key proves
    /// it and is named by it. A challenge is answered within
    /// [`Self::handshake_timeout`]. Checked by `tests/attach_keys.rs`.
    pub attach_keys: Option<AttachKeys>,
    /// With [`Self::attach_keys`], require a proven, listed key on the Unix
    /// socket too; without a list it changes nothing.
    pub attach_keys_uds: bool,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            write_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            max_message_bytes: 1024 * 1024,
            subscriber_queue: 1024,
            subscriber_queue_bytes: 16 * 1024 * 1024,
            total_queue_bytes: DEFAULT_TOTAL_QUEUE_BYTES,
            max_subscriptions: 64,
            max_connections: 256,
            allowed_origins: Vec::new(),
            attach_keys: None,
            attach_keys_uds: false,
        }
    }
}

impl ConnectionPolicy {
    /// This policy with the given ping interval (zero disables pings).
    #[must_use]
    pub fn with_ping_interval(mut self, ping_interval: Duration) -> Self {
        self.ping_interval = ping_interval;
        self
    }

    /// This policy with the given idle timeout (zero disables the check).
    #[must_use]
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// This policy with the given write timeout (zero waits forever).
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// This policy with the given WebSocket handshake timeout.
    #[must_use]
    pub fn with_handshake_timeout(mut self, handshake_timeout: Duration) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// This policy with the largest message accepted, in bytes.
    #[must_use]
    pub fn with_max_message_bytes(mut self, max_message_bytes: usize) -> Self {
        self.max_message_bytes = max_message_bytes;
        self
    }

    /// This policy with the events queued for one connection.
    #[must_use]
    pub fn with_subscriber_queue(mut self, subscriber_queue: usize) -> Self {
        self.subscriber_queue = subscriber_queue;
        self
    }

    /// This policy with the event bytes queued for one connection.
    #[must_use]
    pub fn with_subscriber_queue_bytes(mut self, subscriber_queue_bytes: usize) -> Self {
        self.subscriber_queue_bytes = subscriber_queue_bytes;
        self
    }

    /// This policy with the event bytes queued across all connections.
    #[must_use]
    pub fn with_total_queue_bytes(mut self, total_queue_bytes: usize) -> Self {
        self.total_queue_bytes = total_queue_bytes;
        self
    }

    /// This policy with the subscriptions one connection may hold.
    #[must_use]
    pub fn with_max_subscriptions(mut self, max_subscriptions: usize) -> Self {
        self.max_subscriptions = max_subscriptions;
        self
    }

    /// This policy with the connections the daemon admits at once.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// This policy with the web origins whose pages may open the
    /// WebSocket.
    #[must_use]
    pub fn with_allowed_origins(mut self, allowed_origins: Vec<AllowedOrigin>) -> Self {
        self.allowed_origins = allowed_origins;
        self
    }

    /// This policy with the keys a client may prove at attach, or with none
    /// ([`Self::attach_keys`]).
    #[must_use]
    pub fn with_attach_keys(mut self, attach_keys: Option<AttachKeys>) -> Self {
        self.attach_keys = attach_keys;
        self
    }

    /// This policy requiring, or not, a proven key on the Unix socket too
    /// ([`Self::attach_keys_uds`]).
    #[must_use]
    pub fn with_attach_keys_uds(mut self, attach_keys_uds: bool) -> Self {
        self.attach_keys_uds = attach_keys_uds;
        self
    }
}

/// What a connection runs over, as the attach rules see it: which transport,
/// and on `wss://` the value a proof made on the connection binds it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// The Unix socket, which the operating system keeps to the daemon's
    /// user.
    UnixSocket,
    /// A WebSocket in plaintext, `ws://`.
    WebSocket,
    /// A WebSocket over TLS, `wss://`.
    SecureWebSocket {
        /// The connection's TLS exporter value for
        /// [`attach::TLS_EXPORTER_LABEL`].
        exporter: [u8; attach::EXPORTER_LEN],
    },
}

impl Link {
    /// The bytes a proof on this link is bound to: the TLS exporter value,
    /// or [`attach::NO_EXPORTER`] in plaintext.
    #[must_use]
    pub fn exporter(&self) -> [u8; attach::EXPORTER_LEN] {
        match self {
            Self::SecureWebSocket { exporter } => *exporter,
            Self::UnixSocket | Self::WebSocket => attach::NO_EXPORTER,
        }
    }
}

/// The attach rules for one connection, from the policy and its link.
struct Admission {
    /// The keys a proof may prove, when the daemon keeps a list.
    keys: Option<AttachKeys>,
    /// Whether an attach without a key is refused here.
    keyless_refused: bool,
    /// What a proof here is bound to ([`Link::exporter`]).
    exporter: [u8; attach::EXPORTER_LEN],
    /// How long a challenge waits for its proof.
    window: Duration,
}

impl Admission {
    fn new(policy: &ConnectionPolicy, link: Link) -> Self {
        let keyless_refused = policy.attach_keys.is_some()
            && match link {
                Link::UnixSocket => policy.attach_keys_uds,
                Link::WebSocket | Link::SecureWebSocket { .. } => true,
            };
        Self {
            keys: policy.attach_keys.clone(),
            keyless_refused,
            exporter: link.exporter(),
            window: policy.handshake_timeout,
        }
    }
}

/// An attach whose key the daemon has challenged, waiting for its proof.
struct Challenge {
    /// The attach's id, which the proof carries too.
    id: Option<String>,
    name: String,
    capabilities: Vec<String>,
    key: [u8; attach::PUBLIC_KEY_LEN],
    nonce: [u8; attach::NONCE_LEN],
    /// When it is refused unanswered; `None` past what the clock holds.
    deadline: Option<Instant>,
}

/// A connection's state between messages.
struct Session {
    subs: Subscriptions,
    attached: Option<AttachedEntry>,
    /// The keyed attach waiting for its proof, if one is.
    challenge: Option<Challenge>,
}

/// What the connection does after a message: write the reply, if there is
/// one, and close or carry on.
struct Reply {
    message: Option<ServerMessage>,
    close: bool,
}

impl Reply {
    /// No reply, and the connection carries on.
    fn none() -> Self {
        Self {
            message: None,
            close: false,
        }
    }

    /// `message`, and the connection carries on.
    fn send(message: ServerMessage) -> Self {
        Self {
            message: Some(message),
            close: false,
        }
    }

    /// `message`, the connection's last.
    fn last(message: ServerMessage) -> Self {
        Self {
            message: Some(message),
            close: true,
        }
    }

    /// An `auth_failed` refusal answering `id`, the connection's last.
    fn auth_failed(id: Option<String>, why: impl Into<String>) -> Self {
        Self::last(ServerMessage::error(id, ErrorCode::AuthFailed, why))
    }
}

/// A connection's subscriptions, and how many it may hold.
struct Subscriptions {
    ids: HashSet<SubscriptionId>,
    limit: usize,
}

/// What a transport yields from one receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// One JSON message.
    Frame(String),
    /// A liveness signal that carries no message (a WebSocket pong).
    Pong,
    /// The peer announced a frame larger than the policy allows.
    Oversized {
        /// The announced length in bytes.
        len: usize,
    },
    /// The peer closed the connection, or the transport failed.
    Closed,
}

/// A connection's transport: JSON text frames in and out, as WebSocket text
/// frames or length-prefixed Unix-socket frames.
#[async_trait::async_trait]
pub trait Transport: Send {
    /// Wait for the next frame, a pong, or the end of the connection.
    async fn recv(&mut self) -> Inbound;
    /// Write one frame.
    async fn send(&mut self, msg: &str) -> std::io::Result<()>;
    /// Write one frame of `head` followed by `body`. The daemon's transports
    /// write the two where they are, since a copy would escape the queue
    /// budgets that count them; the default joins them, which suits a test's
    /// transport.
    async fn send_event(&mut self, head: &str, body: &str) -> std::io::Result<()> {
        let mut text = String::with_capacity(head.len() + body.len());
        text.push_str(head);
        text.push_str(body);
        self.send(&text).await
    }
    /// What the connection runs over, for the attach rules.
    fn link(&self) -> Link;
    /// Whether the transport has a liveness probe of its own.
    fn supports_ping(&self) -> bool {
        false
    }
    /// Send a liveness probe; a transport without one does nothing.
    async fn ping(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    /// Close the connection.
    async fn close(self: Box<Self>);
}

/// Run one write under the policy's write deadline. `false` means it
/// failed, or the peer is not reading, and the connection must be closed.
async fn within_write_deadline(
    policy: &ConnectionPolicy,
    write: impl std::future::Future<Output = std::io::Result<()>>,
) -> bool {
    if policy.write_timeout.is_zero() {
        write.await.is_ok()
    } else {
        matches!(
            tokio::time::timeout(policy.write_timeout, write).await,
            Ok(Ok(()))
        )
    }
}

/// Write one frame under the policy's write deadline. `false` means the
/// peer is not reading and the connection must be closed.
async fn send_bounded(
    transport: &mut Box<dyn Transport>,
    policy: &ConnectionPolicy,
    text: &str,
) -> bool {
    within_write_deadline(policy, transport.send(text)).await
}

/// Count an attach refused with `auth_failed` and log it: at warn on the
/// first refusal and at each doubling of the count, at debug otherwise, so a
/// flood of bad attaches is visible without filling the log.
fn log_attach_refused(registry: &Registry, connection_id: ConnectionId, reason: &str) {
    let refused = registry.refuse_attach();
    if refused.is_power_of_two() {
        warn!(conn = %connection_id, refused, reason, "attach refused (auth_failed); closing");
    } else {
        debug!(conn = %connection_id, refused, reason, "attach refused (auth_failed); closing");
    }
}

/// Serve one connection from accept to close under `policy`, releasing its
/// subscriptions and its registry entry at the end.
pub async fn handle_connection(
    mut transport: Box<dyn Transport>,
    bridge: Arc<HubBridge>,
    registry: Arc<Registry>,
    policy: ConnectionPolicy,
) {
    let connection_id = registry.next_connection_id();
    let link = transport.link();
    info!(conn = %connection_id, ?link, "accepted");
    let admission = Admission::new(&policy, link);

    // The bridge offers this connection's events here; replies are written
    // inline.
    let (events, mut queue) = event_queue(
        policy.subscriber_queue,
        policy.subscriber_queue_bytes,
        Arc::clone(registry.queue_total()),
        policy.total_queue_bytes,
    );

    let mut session = Session {
        subs: Subscriptions {
            ids: HashSet::new(),
            limit: policy.max_subscriptions,
        },
        attached: None,
        challenge: None,
    };

    // Any inbound frame or pong is activity, and the attached node's
    // heartbeat. A period or timeout too long for the clock never fires,
    // rather than overflowing it.
    let mut last_activity = Instant::now();
    let mut ping = (transport.supports_ping() && !policy.ping_interval.is_zero())
        .then(|| Instant::now().checked_add(policy.ping_interval))
        .flatten()
        .map(|first| {
            let mut interval = tokio::time::interval_at(first, policy.ping_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval
        });
    let idle_timeout = (!policy.idle_timeout.is_zero()).then_some(policy.idle_timeout);

    loop {
        let idle_deadline = idle_timeout.and_then(|limit| last_activity.checked_add(limit));
        let challenge_deadline = session.challenge.as_ref().and_then(|c| c.deadline);
        tokio::select! {
            inbound = transport.recv() => {
                let text = match inbound {
                    Inbound::Frame(text) => {
                        last_activity = Instant::now();
                        if let Some(entry) = &session.attached {
                            registry.heard(&entry.origin);
                        }
                        text
                    }
                    Inbound::Pong => {
                        last_activity = Instant::now();
                        if let Some(entry) = &session.attached {
                            registry.heard(&entry.origin);
                        }
                        continue;
                    }
                    Inbound::Oversized { len } => {
                        warn!(conn = %connection_id, len, cap = policy.max_message_bytes, "frame over the cap; closing");
                        let err = ServerMessage::error(
                            None,
                            ErrorCode::PayloadTooLarge,
                            format!("frame of {len} bytes exceeds the {} byte limit", policy.max_message_bytes),
                        );
                        let txt = serde_json::to_string(&err).unwrap_or_else(|_| "{}".to_string());
                        let _ = send_bounded(&mut transport, &policy, &txt).await;
                        break;
                    }
                    Inbound::Closed => {
                        debug!(conn = %connection_id, "client disconnected");
                        break;
                    }
                };

                let parsed: Result<ClientMessage, _> = serde_json::from_str(&text);
                // Freed before the reply's write, which may wait on the peer.
                drop(text);
                let reply = match parsed {
                    Err(e) => Reply::send(ServerMessage::error(
                        None,
                        ErrorCode::BadRequest,
                        format!("malformed JSON: {}", quoted(&e.to_string())),
                    )),
                    Ok(msg) => handle_message(
                        msg,
                        connection_id,
                        &bridge,
                        &registry,
                        &events,
                        &mut session,
                        &admission,
                    ),
                };

                if let Some(resp) = reply.message {
                    if let ServerMessage::Error { code, message, .. } = &resp {
                        if code == ErrorCode::AuthFailed.as_str() {
                            log_attach_refused(&registry, connection_id, message);
                        }
                    }
                    let txt = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
                    drop(resp);
                    if !send_bounded(&mut transport, &policy, &txt).await {
                        warn!(conn = %connection_id, "reply could not be written; closing");
                        break;
                    }
                }
                // A detach's ack, or an auth_failed refusal, is the last
                // thing written.
                if reply.close {
                    break;
                }
            }

            outbound = queue.recv() => {
                let Some(event) = outbound else { break; };
                // The subscription is absent for a health notice.
                let deliver = tracing::trace_span!(
                    "deliver",
                    subscription_id = event.subscription_id(),
                    bytes = i64::try_from(event.bytes()).unwrap_or(i64::MAX),
                );
                let written = within_write_deadline(
                    &policy,
                    transport.send_event(event.head(), event.body()),
                )
                .instrument(deliver.clone())
                .await;
                if !written {
                    let _in_deliver = deliver.enter();
                    warn!(conn = %connection_id, "event could not be written within the deadline; closing");
                    break;
                }
                // Gives its bytes back to the budgets.
                drop(event);
            }

            _ = async {
                match ping.as_mut() {
                    Some(interval) => {
                        interval.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if !within_write_deadline(&policy, transport.ping()).await {
                    warn!(conn = %connection_id, "ping could not be written; closing");
                    break;
                }
            }

            () = async {
                match idle_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                info!(conn = %connection_id, idle = ?policy.idle_timeout, "silent past the idle timeout; closing");
                break;
            }

            () = async {
                match challenge_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let id = session.challenge.take().and_then(|c| c.id);
                log_attach_refused(
                    &registry,
                    connection_id,
                    &format!("challenge unanswered within {:?}", admission.window),
                );
                let err = ServerMessage::error(
                    id,
                    ErrorCode::AuthFailed,
                    format!(
                        "the challenge was not answered within {:?} (--handshake-timeout-secs)",
                        admission.window
                    ),
                );
                let txt = serde_json::to_string(&err).unwrap_or_else(|_| "{}".to_string());
                let _ = send_bounded(&mut transport, &policy, &txt).await;
                break;
            }
        }
    }

    for id in session.subs.ids.drain() {
        bridge.unsubscribe(&id);
    }
    if let Some(entry) = session.attached {
        let _detach = tracing::trace_span!("detach", name = entry.name.as_str()).entered();
        registry.detach(entry.connection_id);
    } else {
        registry.detach(connection_id);
    }
    transport.close().await;
    info!(conn = %connection_id, "closed");
}

/// The id a request carries; `None` for one without, and for `health`.
fn request_id(msg: &ClientMessage) -> Option<String> {
    match msg {
        ClientMessage::Attach { id, .. }
        | ClientMessage::Prove { id, .. }
        | ClientMessage::Detach { id }
        | ClientMessage::Send { id, .. }
        | ClientMessage::Subscribe { id, .. }
        | ClientMessage::Unsubscribe { id, .. } => id.clone(),
        ClientMessage::Health { .. } => None,
    }
}

/// The ack of an attach that registered as `entry`, granting what of
/// `capabilities` the daemon serves.
fn attach_ack(
    id: Option<String>,
    entry: AttachedEntry,
    capabilities: &[String],
    attached: &mut Option<AttachedEntry>,
) -> Reply {
    let fields = AckFields {
        node_id: Some(entry.origin.canonical().to_string()),
        protocol_version: Some(PROTOCOL_VERSION.to_string()),
        granted_capabilities: Some(filter_supported_capabilities(capabilities)),
        ..Default::default()
    };
    *attached = Some(entry);
    Reply::send(ServerMessage::Ack { id, fields })
}

/// The refusal of an attach under `name` whose name, or whose node, another
/// attached connection holds.
fn in_use(id: Option<String>, name: &str, result: &AttachResult) -> Reply {
    let message = match result {
        AttachResult::NodeInUse { holder } => format!(
            "the key is attached already, as '{}'; a key is one attached connection at a time",
            quoted(holder)
        ),
        _ => format!("name '{}' is already attached", name),
    };
    Reply::send(ServerMessage::error(id, ErrorCode::NameInUse, message))
}

/// Answer the proof of the challenge pending on the connection: attach as the
/// key when the proof verifies and the key is allowed, and refuse with
/// `auth_failed` otherwise.
fn prove(
    id: Option<String>,
    signature: &str,
    connection_id: ConnectionId,
    registry: &Arc<Registry>,
    session: &mut Session,
    admission: &Admission,
) -> Reply {
    let Some(challenge) = session.challenge.take() else {
        return Reply::auth_failed(
            id,
            "no challenge is pending on this connection: `prove` answers the challenge \
             to an attach that carried a `key`",
        );
    };
    let _attach = tracing::trace_span!(
        "attach",
        name = tracing::field::display(quoted(&challenge.name))
    )
    .entered();
    if id != challenge.id {
        return Reply::auth_failed(id, "the proof's id is not the id of the attach it answers");
    }
    let proved = attach::decode_signature(signature).and_then(|signature| {
        attach::verify(
            &challenge.key,
            &challenge.nonce,
            &challenge.name,
            &admission.exporter,
            &signature,
        )
    });
    if let Err(e) = proved {
        return Reply::auth_failed(id, e.to_string());
    }
    if let Some(keys) = &admission.keys {
        if !keys.contains(&challenge.key) {
            return Reply::auth_failed(id, "the key is not one this daemon allows (--attach-keys)");
        }
    }
    let origin = Origin::keyed(&challenge.name, &challenge.key);
    match registry.attach_as(&challenge.name, origin, connection_id) {
        AttachResult::Attached(entry) => {
            attach_ack(id, entry, &challenge.capabilities, &mut session.attached)
        }
        refused => in_use(id, &challenge.name, &refused),
    }
}

/// What the connection does with one message.
fn handle_message(
    msg: ClientMessage,
    connection_id: ConnectionId,
    bridge: &Arc<HubBridge>,
    registry: &Arc<Registry>,
    events: &EventSink,
    session: &mut Session,
    admission: &Admission,
) -> Reply {
    // While a challenge is pending only its proof is a request; a `health`
    // frame is read and a `detach` acknowledged as ever.
    if session.challenge.is_some()
        && !matches!(
            msg,
            ClientMessage::Prove { .. }
                | ClientMessage::Health { .. }
                | ClientMessage::Detach { .. }
        )
    {
        return Reply::auth_failed(
            request_id(&msg),
            "a challenge to this connection's attach is pending: answer it with `prove` \
             before anything else",
        );
    }
    let Session {
        subs,
        attached,
        challenge,
    } = session;
    match msg {
        ClientMessage::Attach {
            id,
            name,
            protocol_version,
            capabilities,
            key,
        } => {
            // Quoted as an error quotes it, since a refused name may be long.
            let _attach =
                tracing::trace_span!("attach", name = tracing::field::display(quoted(&name)))
                    .entered();
            if protocol_version != PROTOCOL_VERSION {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::VersionUnsupported,
                    format!(
                        "expected '{}', got '{}'",
                        PROTOCOL_VERSION,
                        quoted(&protocol_version)
                    ),
                ));
            }
            if attached.is_some() {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::BadRequest,
                    "already attached on this connection",
                ));
            }
            if name.len() > MAX_NAME_LEN {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::BadRequest,
                    format!(
                        "name of {} bytes is longer than the {MAX_NAME_LEN} bytes allowed",
                        name.len()
                    ),
                ));
            }
            if mesh_port_protocol::name_mimics_node_id(&name) {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::BadRequest,
                    format!(
                        "name {} ends as a node id does (an `@` and 8, 16 or 32 hex digits), \
                         which would let it pass for another node; choose another name",
                        quoted(&name)
                    ),
                ));
            }
            let Some(key) = key else {
                if admission.keyless_refused {
                    return Reply::auth_failed(
                        id,
                        "this daemon admits an attach here only as a key it allows \
                         (--attach-keys): attach with `key` and prove it",
                    );
                }
                return match registry.attach(&name, connection_id) {
                    AttachResult::Attached(entry) => attach_ack(id, entry, &capabilities, attached),
                    refused => in_use(id, &name, &refused),
                };
            };
            let key = match attach::decode_key(&key) {
                Ok(key) => key,
                Err(e) => {
                    return Reply::send(ServerMessage::error(
                        id,
                        ErrorCode::BadRequest,
                        e.to_string(),
                    ))
                }
            };
            let mut nonce = [0u8; attach::NONCE_LEN];
            if let Err(e) = getrandom::getrandom(&mut nonce) {
                return Reply::last(ServerMessage::error(
                    id,
                    ErrorCode::Internal,
                    format!("no random bytes for the attach's challenge: {e}"),
                ));
            }
            *challenge = Some(Challenge {
                id: id.clone(),
                name,
                capabilities,
                key,
                nonce,
                deadline: Instant::now().checked_add(admission.window),
            });
            Reply::send(ServerMessage::Challenge {
                id,
                nonce: base64::encode(&nonce),
            })
        }

        ClientMessage::Prove { id, signature } => {
            prove(id, &signature, connection_id, registry, session, admission)
        }

        ClientMessage::Detach { id } => {
            let entry = attached.take();
            let _detach = tracing::trace_span!(
                "detach",
                name = entry.as_ref().map(|entry| entry.name.as_str())
            )
            .entered();
            if let Some(entry) = entry {
                registry.detach(entry.connection_id);
            }
            // The ack says so, and the connection closes after it.
            let mut fields = AckFields::default();
            fields
                .extra
                .insert("__detach".into(), serde_json::Value::Bool(true));
            Reply::last(ServerMessage::Ack { id, fields })
        }

        ClientMessage::Send {
            id,
            channel,
            type_id,
            type_name,
            payload,
            flags: _,
            to,
        } => {
            let Some(entry) = attached.as_ref() else {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::NotAttached,
                    "attach before send",
                ));
            };
            let bytes = match base64::decode(&payload) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Reply::send(ServerMessage::error(
                        id,
                        ErrorCode::BadRequest,
                        format!("payload was not valid base64: {e}"),
                    ));
                }
            };
            if let Some(to) = to {
                return match bridge.send_to(
                    channel,
                    type_id,
                    type_name,
                    bytes,
                    &entry.origin,
                    &to,
                    registry,
                ) {
                    Ok(receipt) => {
                        let fields = AckFields {
                            envelope_id: Some(hex(&receipt.envelope_id.0)),
                            delivered: Some(receipt.delivered),
                            ..Default::default()
                        };
                        Reply::send(ServerMessage::Ack { id, fields })
                    }
                    Err(e) => Reply::send(bridge_refusal(id, &e, "send")),
                };
            }
            match bridge.send(channel, type_id, type_name, bytes, &entry.origin) {
                Ok(receipt) => {
                    let fields = AckFields {
                        envelope_id: Some(hex(&receipt.envelope_id.0)),
                        persisted: receipt.persisted,
                        ..Default::default()
                    };
                    Reply::send(ServerMessage::Ack { id, fields })
                }
                Err(e) => Reply::send(bridge_refusal(id, &e, "send")),
            }
        }

        ClientMessage::Subscribe { id, filter } => {
            let span = tracing::trace_span!("subscribe", subscription_id = tracing::field::Empty);
            let _in_subscribe = span.enter();
            if attached.is_none() {
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::NotAttached,
                    "attach before subscribe",
                ));
            }
            if subs.ids.len() >= subs.limit {
                debug!(conn = %connection_id, limit = subs.limit, "subscribe refused: limit reached");
                return Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::LimitExceeded,
                    format!(
                        "subscription limit reached: a connection may hold {} \
                         (--max-subscriptions); unsubscribe one first",
                        subs.limit
                    ),
                ));
            }
            let health = filter.health;
            let sub_id = match bridge.subscribe(connection_id, filter, events.clone()) {
                Ok(sub_id) => sub_id,
                Err(e) => return Reply::send(bridge_refusal(id, &e, "subscribe")),
            };
            span.record("subscription_id", sub_id.0.as_str());
            debug!(conn = %connection_id, sub = %sub_id, health, "subscribe registered");
            subs.ids.insert(sub_id.clone());
            if health {
                // Peer state changes reach this connection's queue too, once
                // however many of its subscriptions ask.
                registry.watch_health(connection_id, sub_id.clone(), events);
            }

            let fields = AckFields {
                subscription_id: Some(sub_id.0),
                ..Default::default()
            };
            Reply::send(ServerMessage::Ack { id, fields })
        }

        ClientMessage::Unsubscribe {
            id,
            subscription_id,
        } => {
            let span = tracing::trace_span!(
                "unsubscribe",
                subscription_id = tracing::field::display(quoted(&subscription_id)),
                events_dropped = tracing::field::Empty,
            );
            let _in_unsubscribe = span.enter();
            let key = SubscriptionId(subscription_id.clone());
            if subs.ids.remove(&key) {
                registry.unwatch_health(connection_id, &key);
                let dropped = bridge.unsubscribe(&key).unwrap_or(0);
                span.record("events_dropped", i64::try_from(dropped).unwrap_or(i64::MAX));
                let fields = AckFields {
                    events_dropped: Some(dropped),
                    ..Default::default()
                };
                Reply::send(ServerMessage::Ack { id, fields })
            } else {
                Reply::send(ServerMessage::error(
                    id,
                    ErrorCode::UnknownSubscription,
                    format!("no such subscription '{}'", quoted(&subscription_id)),
                ))
            }
        }

        ClientMessage::Health { state } => {
            // Its arrival was the heartbeat (`Registry::heard`), as any
            // frame's is; its state says whether the client counts itself
            // degraded. No reply: section 4.7 makes one optional.
            debug!(conn = %connection_id, ?state, "health");
            if let Some(entry) = attached.as_ref() {
                registry.reported_health(&entry.origin, state.as_deref());
            }
            Reply::none()
        }
    }
}

/// An envelope id in lowercase hex, as an ack carries it.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The reply to a refused request: `bad_request` for a string over its cap,
/// which the client can fix, `unknown_destination` for a destination no
/// node answers to, quoting it as an error quotes a client's string, and
/// `internal` otherwise.
fn bridge_refusal(id: Option<String>, error: &BridgeError, op: &str) -> ServerMessage {
    match error {
        BridgeError::TooLong { .. } => {
            ServerMessage::error(id, ErrorCode::BadRequest, error.to_string())
        }
        BridgeError::UnknownDestination { node } => ServerMessage::error(
            id,
            ErrorCode::UnknownDestination,
            format!(
                "no node {} is attached here or announced by a linked daemon",
                quoted(node)
            ),
        ),
        BridgeError::Init(_) | BridgeError::Dispatch(_) => {
            ServerMessage::error(id, ErrorCode::Internal, format!("{op} failed: {error}"))
        }
    }
}

fn filter_supported_capabilities(requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|c| matches!(c.as_str(), "send" | "subscribe" | "tap"))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A scripted transport: yields its script, then either hangs or closes;
    /// its writes either succeed at once or hang forever.
    struct Mock {
        script: Vec<Inbound>,
        hang_recv: bool,
        hang_send: bool,
        pong_every: Option<Duration>,
        pongs_left: u32,
    }

    #[async_trait::async_trait]
    impl Transport for Mock {
        async fn recv(&mut self) -> Inbound {
            if let Some(next) = self.script.pop() {
                return next;
            }
            if let Some(every) = self.pong_every {
                if self.pongs_left > 0 {
                    self.pongs_left -= 1;
                    tokio::time::sleep(every).await;
                    return Inbound::Pong;
                }
                return Inbound::Closed;
            }
            if self.hang_recv {
                std::future::pending::<()>().await;
            }
            Inbound::Closed
        }
        fn link(&self) -> Link {
            Link::UnixSocket
        }
        async fn send(&mut self, _msg: &str) -> std::io::Result<()> {
            if self.hang_send {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
        async fn close(self: Box<Self>) {}
    }

    fn attach_frame() -> Inbound {
        Inbound::Frame(r#"{"op":"attach","id":"1","name":"mock","protocol_version":"v0"}"#.into())
    }

    fn policy(idle_ms: u64, write_ms: u64) -> ConnectionPolicy {
        ConnectionPolicy {
            ping_interval: Duration::ZERO,
            idle_timeout: Duration::from_millis(idle_ms),
            write_timeout: Duration::from_millis(write_ms),
            handshake_timeout: Duration::from_secs(5),
            max_message_bytes: 1024,
            subscriber_queue: 8,
            ..ConnectionPolicy::default()
        }
    }

    /// A hub name private to this process, so parallel runs elsewhere do not
    /// share it.
    fn hub(tag: &str) -> String {
        format!("{tag}{:x}", std::process::id())
    }

    /// A bridge for `hub(tag)` with a 16-slot store: the default's 16 MiB per
    /// parallel test does not fit Docker's 64 MB `/dev/shm`.
    fn small_bridge(tag: &str) -> Arc<HubBridge> {
        let config = mesh_hub_runtime::HubConfig::default().with_store_slots(16);
        Arc::new(HubBridge::with_config(&hub(tag), config).unwrap())
    }

    #[tokio::test]
    async fn transport_end_unsubscribes_at_the_bridge() {
        let bridge = small_bridge("cx-unsub");
        // The mock pops from the back: attach first, then subscribe.
        let mock = Box::new(Mock {
            script: vec![
                Inbound::Frame(r#"{"op":"subscribe","id":"2","filter":{}}"#.into()),
                attach_frame(),
            ],
            hang_recv: false,
            hang_send: false,
            pong_every: None,
            pongs_left: 0,
        });
        handle_connection(mock, bridge.clone(), Registry::new(), policy(0, 1000)).await;
        assert_eq!(
            bridge.subscriber_count(),
            0,
            "released when the transport ended"
        );
    }

    #[tokio::test]
    async fn write_timeout_closes_a_connection_whose_peer_never_reads() {
        let bridge = small_bridge("cx-write");
        let mock = Box::new(Mock {
            script: vec![attach_frame()],
            hang_recv: true,
            hang_send: true,
            pong_every: None,
            pongs_left: 0,
        });
        let started = Instant::now();
        handle_connection(mock, bridge, Registry::new(), policy(0, 200)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the stuck write was abandoned"
        );
    }

    #[tokio::test]
    async fn idle_timeout_closes_a_silent_connection() {
        let bridge = small_bridge("cx-idle");
        let mock = Box::new(Mock {
            script: vec![],
            hang_recv: true,
            hang_send: false,
            pong_every: None,
            pongs_left: 0,
        });
        let started = Instant::now();
        handle_connection(mock, bridge, Registry::new(), policy(200, 1000)).await;
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(150) && took < Duration::from_secs(2),
            "{took:?}"
        );
    }

    /// A transport that pings: it gives the frames of its script, then
    /// ends.
    struct Pinging(Vec<Inbound>);

    #[async_trait::async_trait]
    impl Transport for Pinging {
        async fn recv(&mut self) -> Inbound {
            self.0.pop().unwrap_or(Inbound::Closed)
        }
        fn link(&self) -> Link {
            Link::WebSocket
        }
        async fn send(&mut self, _msg: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn supports_ping(&self) -> bool {
            true
        }
        async fn close(self: Box<Self>) {}
    }

    #[tokio::test]
    async fn limits_past_the_clock_or_the_channel_never_abort_a_connection() {
        // Timers past what the clock can add, and a queue past its maximum.
        let bridge = small_bridge("cx-max");
        let policy = ConnectionPolicy {
            ping_interval: Duration::MAX,
            idle_timeout: Duration::MAX,
            write_timeout: Duration::MAX,
            subscriber_queue: usize::MAX,
            ..ConnectionPolicy::default()
        };
        let transport = Box::new(Pinging(vec![
            Inbound::Frame(r#"{"op":"subscribe","id":"2","filter":{}}"#.into()),
            attach_frame(),
        ]));
        let registry = Registry::new();
        handle_connection(transport, bridge.clone(), registry.clone(), policy).await;
        assert_eq!(bridge.subscriber_count(), 0, "it ran and ended cleanly");
        assert_eq!(registry.connections(), 0);
    }

    #[test]
    fn a_clients_string_is_quoted_whole_or_in_part_at_a_character_boundary() {
        assert_eq!(quoted("v1"), "v1");
        let at_limit = "x".repeat(MAX_QUOTED);
        assert_eq!(quoted(&at_limit), at_limit.as_str());
        // Three-byte characters: the cut falls back to the boundary below.
        let long = "€".repeat(100);
        let cut = quoted(&long);
        assert_eq!(cut, format!("{}… (300 bytes)", "€".repeat(MAX_QUOTED / 3)));
    }

    /// A transport that yields its script, records what the connection
    /// writes, and then ends.
    struct Recording {
        script: Vec<Inbound>,
        written: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Transport for Recording {
        async fn recv(&mut self) -> Inbound {
            self.script.pop().unwrap_or(Inbound::Closed)
        }
        fn link(&self) -> Link {
            Link::UnixSocket
        }
        async fn send(&mut self, msg: &str) -> std::io::Result<()> {
            self.written.lock().push(msg.to_string());
            Ok(())
        }
        async fn close(self: Box<Self>) {}
    }

    #[tokio::test]
    async fn errors_quote_what_a_client_sent_only_in_part() {
        let bridge = small_bridge("cx-quote");
        let huge = "z".repeat(1 << 20);
        let written = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let transport = Box::new(Recording {
            // Popped from the back: a version, then an operation, then a
            // subscription id, each a mebibyte long.
            script: vec![
                Inbound::Frame(format!(
                    r#"{{"op":"unsubscribe","id":"3","subscription_id":"{huge}"}}"#
                )),
                Inbound::Frame(format!(r#"{{"op":"{huge}"}}"#)),
                attach_frame(),
                Inbound::Frame(format!(
                    r#"{{"op":"attach","id":"1","name":"q","protocol_version":"{huge}"}}"#
                )),
            ],
            written: Arc::clone(&written),
        });
        let policy = ConnectionPolicy {
            max_message_bytes: 2 << 20,
            ..policy(0, 1000)
        };
        handle_connection(transport, bridge, Registry::new(), policy).await;
        let written = written.lock();
        let codes: Vec<String> = written
            .iter()
            .map(|reply| {
                let reply: serde_json::Value = serde_json::from_str(reply).unwrap();
                reply["code"].as_str().unwrap_or("ack").to_string()
            })
            .collect();
        assert_eq!(
            codes,
            [
                "version_unsupported",
                "ack",
                "bad_request",
                "unknown_subscription"
            ]
        );
        for reply in written.iter() {
            assert!(
                reply.len() < 2 * MAX_QUOTED + 200,
                "{} bytes: {reply:.300}",
                reply.len()
            );
        }
        assert!(
            written[3].contains(&format!("… ({} bytes)", 1 << 20)),
            "{}",
            written[3]
        );
    }

    /// A transport the test drives: what it receives comes from a channel,
    /// and it ends when the channel does; what the connection writes goes to
    /// another.
    struct Driven {
        inbound: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
        outbound: tokio::sync::mpsc::UnboundedSender<String>,
        link: Link,
    }

    #[async_trait::async_trait]
    impl Transport for Driven {
        async fn recv(&mut self) -> Inbound {
            self.inbound.recv().await.unwrap_or(Inbound::Closed)
        }
        fn link(&self) -> Link {
            self.link
        }
        async fn send(&mut self, msg: &str) -> std::io::Result<()> {
            let _ = self.outbound.send(msg.to_string());
            Ok(())
        }
        async fn close(self: Box<Self>) {}
    }

    /// The next frame the connection writes, parsed.
    async fn written(out: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> serde_json::Value {
        let frame = tokio::time::timeout(Duration::from_secs(2), out.recv())
            .await
            .expect("a frame in time")
            .expect("the connection is open");
        serde_json::from_str(&frame).unwrap()
    }

    #[tokio::test]
    async fn a_connection_watching_health_is_told_of_peers_until_it_unsubscribes() {
        let bridge = small_bridge("cx-health");
        // Ticked by hand here: no task ticks this registry.
        let policy = policy(60_000, 1000);
        let registry = Registry::for_policy(&policy);
        let peer = ConnectionId(u64::MAX);
        assert!(matches!(
            registry.attach("peer", peer),
            AttachResult::Attached(_)
        ));
        let (to_conn, inbound) = tokio::sync::mpsc::unbounded_channel();
        let (outbound, mut out) = tokio::sync::mpsc::unbounded_channel();
        let conn = tokio::spawn(handle_connection(
            Box::new(Driven {
                inbound,
                outbound,
                link: Link::UnixSocket,
            }),
            Arc::clone(&bridge),
            Arc::clone(&registry),
            policy,
        ));
        let frame = |json: &str| Inbound::Frame(json.to_string());
        to_conn.send(attach_frame()).unwrap();
        assert_eq!(written(&mut out).await["op"], "ack");
        to_conn
            .send(frame(
                r#"{"op":"subscribe","id":"2","filter":{"health":true}}"#,
            ))
            .unwrap();
        let ack = written(&mut out).await;
        let sub = ack["subscription_id"].as_str().unwrap().to_string();
        assert_eq!(registry.nodes_healthy(), 2, "the peer and this connection");

        // The peer falls silent: five misses after the tick its attach
        // spared, it is Warning. So is this connection, of which it is not
        // told; a pong is its heartbeat, and its next frame its reply.
        for _ in 0..6 {
            registry.tick_health();
        }
        let notice = written(&mut out).await;
        assert_eq!(notice["op"], "health");
        assert_eq!(
            notice["node_id"],
            crate::registry::Origin::named("peer").canonical()
        );
        assert_eq!(notice["state"], "warning");
        assert_eq!(registry.nodes_warning(), 2);
        to_conn.send(Inbound::Pong).unwrap();
        to_conn
            .send(frame(
                r#"{"op":"unsubscribe","id":"3","subscription_id":"none"}"#,
            ))
            .unwrap();
        assert_eq!(written(&mut out).await["code"], "unknown_subscription");
        assert_eq!((registry.nodes_healthy(), registry.nodes_warning()), (1, 1));

        // The peer's detach is told, once.
        registry.detach(peer);
        let notice = written(&mut out).await;
        assert_eq!(
            (notice["op"].as_str(), notice["state"].as_str()),
            (Some("health"), Some("detached"))
        );

        // Unsubscribed, the connection hears of no other peer.
        to_conn
            .send(frame(&format!(
                r#"{{"op":"unsubscribe","id":"4","subscription_id":"{sub}"}}"#
            )))
            .unwrap();
        assert_eq!(written(&mut out).await["id"], "4");
        let other = ConnectionId(u64::MAX - 1);
        assert!(matches!(
            registry.attach("other", other),
            AttachResult::Attached(_)
        ));
        registry.detach(other);
        to_conn
            .send(frame(
                r#"{"op":"unsubscribe","id":"5","subscription_id":"none"}"#,
            ))
            .unwrap();
        assert_eq!(
            written(&mut out).await["id"],
            "5",
            "the reply, and no notice before it"
        );

        // Its end unregisters it.
        drop(to_conn);
        conn.await.unwrap();
        assert_eq!(registry.nodes_healthy() + registry.nodes_warning(), 0);
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn pong_counts_as_activity() {
        let bridge = small_bridge("cx-pong");
        let mock = Box::new(Mock {
            script: vec![],
            hang_recv: false,
            hang_send: false,
            pong_every: Some(Duration::from_millis(50)),
            pongs_left: 12,
        });
        let started = Instant::now();
        handle_connection(mock, bridge, Registry::new(), policy(200, 1000)).await;
        // Twelve pongs 50 ms apart keep a 200 ms idle limit at bay for 600 ms;
        // the loop ends only when the mock closes.
        assert!(
            started.elapsed() >= Duration::from_millis(550),
            "{:?}",
            started.elapsed()
        );
    }

    // ---- Key-proof attach ----------------------------------------------

    use crate::attach_keys::AttachKeys;
    use attach::SigningKey;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    /// One connection the test drives over `link`: its inbound end, what it
    /// writes, and its task.
    struct Conn {
        to: tokio::sync::mpsc::UnboundedSender<Inbound>,
        out: tokio::sync::mpsc::UnboundedReceiver<String>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Conn {
        fn open(
            bridge: &Arc<HubBridge>,
            registry: &Arc<Registry>,
            policy: &ConnectionPolicy,
            link: Link,
        ) -> Self {
            let (to, inbound) = tokio::sync::mpsc::unbounded_channel();
            let (outbound, out) = tokio::sync::mpsc::unbounded_channel();
            let task = tokio::spawn(handle_connection(
                Box::new(Driven {
                    inbound,
                    outbound,
                    link,
                }),
                Arc::clone(bridge),
                Arc::clone(registry),
                policy.clone(),
            ));
            Self { to, out, task }
        }

        fn send(&self, frame: serde_json::Value) {
            self.to.send(Inbound::Frame(frame.to_string())).unwrap();
        }

        async fn reply(&mut self) -> serde_json::Value {
            written(&mut self.out).await
        }

        /// Attach as `name` with `key`, and the challenge's nonce.
        async fn challenged(&mut self, name: &str, key: &SigningKey) -> [u8; 32] {
            self.send(serde_json::json!({
                "op": "attach", "id": "a1", "name": name, "protocol_version": "v0",
                "capabilities": ["send", "subscribe"],
                "key": attach::encode_key(&public(key)),
            }));
            let challenge = self.reply().await;
            assert_eq!(challenge["op"], "challenge", "{challenge}");
            assert_eq!(challenge["id"], "a1");
            attach::decode_nonce(challenge["nonce"].as_str().unwrap()).unwrap()
        }

        fn prove(&self, signature: &[u8; 64]) {
            self.send(serde_json::json!({
                "op": "prove", "id": "a1", "signature": base64::encode(signature),
            }));
        }

        /// The next reply is `auth_failed` answering `id`, and the connection
        /// then ends.
        async fn refused(mut self, id: Option<&str>) -> String {
            let reply = self.reply().await;
            assert_eq!(reply["code"], "auth_failed", "{reply}");
            assert_eq!(reply["id"].as_str(), id, "{reply}");
            tokio::time::timeout(Duration::from_secs(2), self.task)
                .await
                .expect("the connection closed after auth_failed")
                .unwrap();
            assert!(self.out.recv().await.is_none(), "nothing after auth_failed");
            reply["message"].as_str().unwrap().to_string()
        }
    }

    fn keyed_policy(keys: Option<AttachKeys>) -> ConnectionPolicy {
        policy(60_000, 1000).with_attach_keys(keys)
    }

    /// A client proving a listed key is attached as the key, over ws and
    /// over wss, where the proof signs the connection's exporter value.
    #[tokio::test]
    async fn a_listed_key_proved_attaches_as_the_key() {
        let bridge = small_bridge("cxkok");
        let registry = Registry::new();
        let key = signing_key(1);
        let policy = keyed_policy(Some(AttachKeys::new([public(&key)])));
        for (name, link) in [
            ("w-ws", Link::WebSocket),
            ("w-wss", Link::SecureWebSocket { exporter: [7; 32] }),
        ] {
            let mut conn = Conn::open(&bridge, &registry, &policy, link);
            let nonce = conn.challenged(name, &key).await;
            conn.prove(&attach::sign(&key, &nonce, name, &link.exporter()));
            let ack = conn.reply().await;
            assert_eq!(ack["op"], "ack", "{ack}");
            assert_eq!(ack["id"], "a1");
            assert_eq!(ack["node_id"], attach::keyed_node_id(name, &public(&key)));
            assert_eq!(
                ack["granted_capabilities"],
                serde_json::json!(["send", "subscribe"])
            );
            assert_eq!(registry.len(), 1);
            conn.send(serde_json::json!({"op": "detach", "id": "d"}));
            assert_eq!(conn.reply().await["__detach"], true);
            conn.task.await.unwrap();
        }
        assert!(registry.is_empty());
    }

    /// A wrong signature, a key not listed, a proof replayed on another
    /// connection, a proof for the plaintext exporter on wss, a keyless
    /// attach on the WebSocket, a request while a challenge is pending, a
    /// proof under another id, a malformed signature and a `prove` with no
    /// challenge are each refused with `auth_failed`, closing the
    /// connection.
    #[tokio::test]
    async fn every_failed_proof_is_auth_failed_and_closes_the_connection() {
        let bridge = small_bridge("cxkno");
        let registry = Registry::new();
        let (key, other) = (signing_key(2), signing_key(3));
        let policy = keyed_policy(Some(AttachKeys::new([public(&key)])));
        let open = |link| Conn::open(&bridge, &registry, &policy, link);

        // Signed by another key.
        let mut conn = open(Link::WebSocket);
        let nonce = conn.challenged("w", &key).await;
        conn.prove(&attach::sign(&other, &nonce, "w", &attach::NO_EXPORTER));
        assert!(conn.refused(Some("a1")).await.contains("signature"));

        // A good proof of a key that is not listed.
        let mut conn = open(Link::WebSocket);
        let nonce = conn.challenged("w", &other).await;
        conn.prove(&attach::sign(&other, &nonce, "w", &attach::NO_EXPORTER));
        assert!(conn.refused(Some("a1")).await.contains("--attach-keys"));

        // A good proof replayed on a second connection, whose nonce differs.
        let mut first = open(Link::WebSocket);
        let nonce = first.challenged("w", &key).await;
        let proof = attach::sign(&key, &nonce, "w", &attach::NO_EXPORTER);
        let mut second = open(Link::WebSocket);
        let second_nonce = second.challenged("w", &key).await;
        assert_ne!(nonce, second_nonce, "each challenge has a nonce of its own");
        second.prove(&proof);
        second.refused(Some("a1")).await;
        first.prove(&proof);
        assert_eq!(
            first.reply().await["op"],
            "ack",
            "the proof is good where it was made"
        );
        drop(first);

        // On wss, a proof that signs the plaintext exporter, as one relayed
        // from another connection would.
        let mut conn = open(Link::SecureWebSocket { exporter: [9; 32] });
        let nonce = conn.challenged("w2", &key).await;
        conn.prove(&attach::sign(&key, &nonce, "w2", &attach::NO_EXPORTER));
        conn.refused(Some("a1")).await;

        // A keyless attach on the WebSocket, on ws and on wss.
        for link in [Link::WebSocket, Link::SecureWebSocket { exporter: [1; 32] }] {
            let conn = open(link);
            conn.send(serde_json::json!({"op": "attach", "id": "k", "name": "nokey", "protocol_version": "v0"}));
            assert!(conn.refused(Some("k")).await.contains("--attach-keys"));
        }

        // Anything but the proof while the challenge is pending; a health
        // frame is read and answered with nothing first.
        let mut conn = open(Link::WebSocket);
        conn.challenged("w3", &key).await;
        conn.send(serde_json::json!({"op": "health", "state": "ok"}));
        conn.send(serde_json::json!({"op": "send", "id": "s", "channel": "c", "payload": "aGk="}));
        assert!(conn.refused(Some("s")).await.contains("pending"));

        // The proof under another id, and a signature that is not one.
        let mut conn = open(Link::WebSocket);
        let nonce = conn.challenged("w4", &key).await;
        let proof = attach::sign(&key, &nonce, "w4", &attach::NO_EXPORTER);
        conn.send(
            serde_json::json!({"op": "prove", "id": "zz", "signature": base64::encode(&proof)}),
        );
        conn.refused(Some("zz")).await;
        let mut conn = open(Link::WebSocket);
        conn.challenged("w5", &key).await;
        conn.send(serde_json::json!({"op": "prove", "id": "a1", "signature": "AAAA"}));
        assert!(conn.refused(Some("a1")).await.contains("`signature`"));

        // A prove with no challenge pending.
        let conn = open(Link::UnixSocket);
        conn.send(serde_json::json!({"op": "prove", "id": "p", "signature": "AAAA"}));
        assert!(conn.refused(Some("p")).await.contains("no challenge"));

        // A key that is not padded base64 of 32 bytes is a bad request, and
        // the connection carries on.
        let mut conn = open(Link::WebSocket);
        conn.send(serde_json::json!({"op": "attach", "id": "b", "name": "w6", "protocol_version": "v0", "key": "AAAA"}));
        let reply = conn.reply().await;
        assert_eq!(
            (reply["code"].as_str(), reply["id"].as_str()),
            (Some("bad_request"), Some("b"))
        );
        let nonce = conn.challenged("w6", &key).await;
        conn.prove(&attach::sign(&key, &nonce, "w6", &attach::NO_EXPORTER));
        assert_eq!(conn.reply().await["op"], "ack");
        drop(conn);
    }

    /// A challenge unanswered within the handshake timeout is refused with
    /// `auth_failed` under the attach's id, and the connection closed.
    #[tokio::test]
    async fn a_challenge_unanswered_in_time_is_refused() {
        let bridge = small_bridge("cxklate");
        let registry = Registry::new();
        let key = signing_key(4);
        let policy = keyed_policy(Some(AttachKeys::new([public(&key)])))
            .with_handshake_timeout(Duration::from_millis(150));
        let mut conn = Conn::open(&bridge, &registry, &policy, Link::WebSocket);
        let started = Instant::now();
        conn.challenged("slow", &key).await;
        let message = conn.refused(Some("a1")).await;
        assert!(message.contains("not answered within"), "{message}");
        assert!(started.elapsed() >= Duration::from_millis(140));
        assert!(registry.is_empty());
    }

    /// Without a list, an attach without a key attaches by name as before,
    /// and one with a key proves it and is named by it; any key will do,
    /// but the proof must hold. The Unix socket admits an attach without a
    /// key under a list unless `attach_keys_uds`, and proves a key it is
    /// given against the list either way.
    #[tokio::test]
    async fn the_rules_by_list_and_transport() {
        let bridge = small_bridge("cxkrule");
        let registry = Registry::new();
        let (key, other) = (signing_key(5), signing_key(6));

        let open_policy = keyed_policy(None);
        let mut conn = Conn::open(&bridge, &registry, &open_policy, Link::WebSocket);
        conn.send(serde_json::json!({"op": "attach", "id": "1", "name": "plain", "protocol_version": "v0"}));
        assert_eq!(
            conn.reply().await["node_id"],
            Origin::named("plain").canonical()
        );
        drop(conn);
        let mut conn = Conn::open(&bridge, &registry, &open_policy, Link::WebSocket);
        let nonce = conn.challenged("anykey", &other).await;
        conn.prove(&attach::sign(
            &other,
            &nonce,
            "anykey",
            &attach::NO_EXPORTER,
        ));
        assert_eq!(
            conn.reply().await["node_id"],
            attach::keyed_node_id("anykey", &public(&other))
        );
        drop(conn);
        let mut conn = Conn::open(&bridge, &registry, &open_policy, Link::WebSocket);
        let nonce = conn.challenged("forged", &key).await;
        conn.prove(&attach::sign(
            &other,
            &nonce,
            "forged",
            &attach::NO_EXPORTER,
        ));
        conn.refused(Some("a1")).await;

        let listed = keyed_policy(Some(AttachKeys::new([public(&key)])));
        let mut conn = Conn::open(&bridge, &registry, &listed, Link::UnixSocket);
        conn.send(serde_json::json!({"op": "attach", "id": "1", "name": "owner", "protocol_version": "v0"}));
        assert_eq!(
            conn.reply().await["node_id"],
            Origin::named("owner").canonical()
        );
        drop(conn);
        let mut conn = Conn::open(&bridge, &registry, &listed, Link::UnixSocket);
        let nonce = conn.challenged("owner2", &other).await;
        conn.prove(&attach::sign(
            &other,
            &nonce,
            "owner2",
            &attach::NO_EXPORTER,
        ));
        conn.refused(Some("a1")).await;

        let strict = listed.clone().with_attach_keys_uds(true);
        let conn = Conn::open(&bridge, &registry, &strict, Link::UnixSocket);
        conn.send(serde_json::json!({"op": "attach", "id": "1", "name": "owner3", "protocol_version": "v0"}));
        conn.refused(Some("1")).await;
        let mut conn = Conn::open(&bridge, &registry, &strict, Link::UnixSocket);
        let nonce = conn.challenged("owner4", &key).await;
        conn.prove(&attach::sign(&key, &nonce, "owner4", &attach::NO_EXPORTER));
        assert_eq!(conn.reply().await["op"], "ack");
        drop(conn);

        // A key is one attached connection at a time.
        let mut a = Conn::open(&bridge, &registry, &listed, Link::WebSocket);
        let nonce = a.challenged("one", &key).await;
        a.prove(&attach::sign(&key, &nonce, "one", &attach::NO_EXPORTER));
        assert_eq!(a.reply().await["op"], "ack");
        let mut b = Conn::open(&bridge, &registry, &listed, Link::WebSocket);
        let nonce = b.challenged("two", &key).await;
        b.prove(&attach::sign(&key, &nonce, "two", &attach::NO_EXPORTER));
        let reply = b.reply().await;
        assert_eq!(reply["code"], "name_in_use", "{reply}");
        assert!(
            reply["message"].as_str().unwrap().contains("'one'"),
            "{reply}"
        );
        drop((a, b));
    }

    /// A schema's producer list naming a key, by the node id the key
    /// derives, admits the sends of the connection that proved it and
    /// refuses another key's; a custom validator registered on the hub runs
    /// on them and can refuse.
    #[tokio::test]
    async fn a_producer_list_naming_a_key_admits_that_keys_sends_alone() {
        let bridge = small_bridge("cxkacl");
        let registry = Registry::new();
        let (key, other) = (signing_key(7), signing_key(8));
        bridge.with_hub(|hub| {
            let node = pulse_canon::NodeId::from_bytes(attach::key_node_id(&public(&key)));
            hub.register_schema(
                mesh_schema::SchemaEntry::new(0x0042, "keyed")
                    .with_validation(mesh_schema::ValidationMode::Custom)
                    .add_producer(node),
            )
            .unwrap();
            hub.register_validator(0x0042, |envelope, _| {
                if envelope.payload().to_bytes() == b"no" {
                    Err(mesh_schema::SchemaError::ValidationFailed(
                        "refused by the validator".into(),
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        });
        let policy = keyed_policy(None);
        let mut sent = Vec::new();
        for (name, signer) in [("producer", &key), ("intruder", &other)] {
            let mut conn = Conn::open(&bridge, &registry, &policy, Link::WebSocket);
            let nonce = conn.challenged(name, signer).await;
            conn.prove(&attach::sign(signer, &nonce, name, &attach::NO_EXPORTER));
            assert_eq!(conn.reply().await["op"], "ack");
            for payload in [&b"yes"[..], b"no"] {
                conn.send(serde_json::json!({
                    "op": "send", "id": "s", "channel": "c", "type_id": 0x0042,
                    "payload": base64::encode(payload),
                }));
                let reply = conn.reply().await;
                sent.push((name, payload, reply));
            }
            drop(conn);
        }
        let outcome: Vec<(&str, &[u8], Option<&str>)> = sent
            .iter()
            .map(|(name, payload, reply)| (*name, *payload, reply["code"].as_str()))
            .collect();
        assert_eq!(
            outcome,
            [
                ("producer", &b"yes"[..], None),
                ("producer", b"no", Some("internal")),
                ("intruder", b"yes", Some("internal")),
                ("intruder", b"no", Some("internal")),
            ]
        );
        assert!(sent[1].2["message"]
            .as_str()
            .unwrap()
            .contains("refused by the validator"));
        assert!(sent[2].2["message"]
            .as_str()
            .unwrap()
            .contains("ProducerNotAllowed"));
    }
}
