// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Hosting a mesh inside another process: an [`EmbeddedMesh`] is named, told
//! where to answer, listening when it returns, and stopped when dropped.
//!
//! ```no_run
//! use mesh_hub::embed::{Bind, EmbeddedMesh};
//! # fn main() -> Result<(), mesh_hub::embed::EmbedError> {
//! let mesh = EmbeddedMesh::start("my-hub", Bind::Uds("/tmp/my.sock".into()))?;
//! // The socket is bound and accepting before this line runs.
//! # let _ = mesh;
//! # Ok(())
//! # }
//! ```

use crate::connection::ConnectionPolicy;
use crate::health;
use crate::hub_bridge::{name_holder, DestinationSends, HubBridge, DISPLACEMENT_CHECK};
use crate::link::{DaemonId, LinkConfig, LinkSetupError, LinkStats};
use crate::registry::Registry;
use crate::server::{bind_ws, claim_uds, serve_ws_task, ServedSocket, UdsClaim};
use crate::tls::WsTls;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// How long stopping a mesh waits for its runtime's worker threads to drop
/// the tasks that serve it; see [`EmbeddedMesh::shutdown`].
const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// A place a mesh answers, claimed before its hub is created and served
/// once the hub exists.
enum Claimed {
    /// A Unix socket path whose lock is held.
    Uds(UdsClaim),
    /// A bound WebSocket listener, and its TLS for `wss://`.
    Ws(tokio::net::TcpListener, Option<WsTls>),
}

/// The hub's configuration, which [`EmbeddedMesh::start_with_config`] takes.
pub use mesh_hub_runtime::HubConfig;

/// Where an embedded mesh answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    /// A Unix-domain socket at this path.
    Uds(PathBuf),
    /// A WebSocket listener on this address, in plaintext (`ws://`).
    Ws(SocketAddr),
    /// A WebSocket listener on this address that completes a TLS 1.3
    /// handshake with [`WsTls`]'s certificate before each upgrade (`wss://`).
    /// TLS authenticates the mesh, not its clients: anything that reaches the
    /// address can attach, as on [`Bind::Ws`], unless the policy's attach keys
    /// (`ConnectionPolicy::attach_keys`) admit only the clients that prove a
    /// listed key, each proof bound to its TLS connection.
    Wss(SocketAddr, WsTls),
}

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uds(p) => write!(f, "unix://{}", p.display()),
            Self::Ws(a) => write!(f, "ws://{a}"),
            Self::Wss(a, _) => write!(f, "wss://{a}"),
        }
    }
}

/// Why a mesh could not be hosted here.
#[derive(Debug)]
#[non_exhaustive]
pub enum EmbedError {
    /// The async runtime could not be built, or the thread that watches the
    /// hub's name for another owner could not be started.
    Runtime(std::io::Error),
    /// The hub itself could not be created; the string is the bridge's reason.
    Hub(String),
    /// The listener could not bind, with the address it was asked for.
    Bind(Bind, std::io::Error),
    /// No bind was given, so there would have been nowhere to answer.
    Nowhere,
    /// The links to other daemons could not be started: their configuration
    /// was refused, their address could not be bound, or a thread could not
    /// start.
    Links(LinkSetupError),
}

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "the mesh's runtime could not start: {e}"),
            Self::Hub(e) => write!(f, "the hub could not be created: {e}"),
            Self::Bind(b, e) => write!(f, "the mesh could not answer at {b}: {e}"),
            Self::Nowhere => f.write_str("a mesh was asked for with nowhere to answer"),
            Self::Links(e) => write!(f, "the mesh's links to other daemons could not start: {e}"),
        }
    }
}

impl std::error::Error for EmbedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(e) | Self::Bind(_, e) => Some(e),
            Self::Links(e) => Some(e),
            _ => None,
        }
    }
}

/// What serves an embedded mesh while it runs; [`Serving::stop`] ends it.
struct Serving {
    runtime: tokio::runtime::Runtime,
    /// Each WebSocket listener's accept task, which holds the listener.
    listeners: Vec<JoinHandle<()>>,
    /// Each Unix socket, whose claim on its path is kept here rather than
    /// in its accept task, so that stopping removes the socket itself.
    sockets: Vec<ServedSocket>,
}

impl Serving {
    /// Stop serving: shut the runtime down, wait, at most [`RELEASE_WAIT`],
    /// until every accept task has ended ([`JoinHandle::is_finished`]) and no
    /// task still holds the hub (`hub_held_elsewhere`), then remove each socket
    /// file its path still names and release the lock beside it.
    ///
    /// The runtime is shut down in the background, not dropped, since dropping
    /// one inside another runtime panics and a host may drop its mesh there.
    /// The sockets are removed here rather than by the tasks, whose values drop
    /// in no fixed order.
    fn stop(self, hub_held_elsewhere: impl Fn() -> bool) {
        let Self {
            runtime,
            listeners,
            sockets,
        } = self;
        runtime.shutdown_background();
        let ended = || {
            listeners.iter().all(JoinHandle::is_finished)
                && sockets.iter().all(ServedSocket::is_finished)
                && !hub_held_elsewhere()
        };
        let deadline = Instant::now() + RELEASE_WAIT;
        while !ended() {
            if Instant::now() >= deadline {
                tracing::warn!(
                    waited = ?RELEASE_WAIT,
                    "the mesh's tasks had not all ended when its stop gave up waiting: its sockets \
                     are removed all the same, and its hub goes when the last task lets go of it"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        for socket in sockets {
            socket.release();
        }
    }
}

/// The thread that watches an embedded mesh's hub name for another owner,
/// and stops the mesh if one takes it ([`EmbeddedMesh::is_displaced`]).
struct Watch {
    /// Dropped to tell the thread to finish.
    finish: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Watch {
    /// Watch `bridge`'s hub every [`DISPLACEMENT_CHECK`], and once it is
    /// displaced, log it and stop `serving`. The bridge is held weakly, so the
    /// watch is never a holder a stop waits for.
    fn start(
        hub_name: &str,
        bridge: Weak<HubBridge>,
        serving: Arc<Mutex<Option<Serving>>>,
    ) -> std::io::Result<Self> {
        let (finish, finished) = mpsc::channel::<()>();
        let hub = hub_name.to_string();
        let thread = std::thread::Builder::new()
            .name(format!("mesh-watch-{hub_name}"))
            .spawn(move || loop {
                match finished.recv_timeout(DISPLACEMENT_CHECK) {
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                }
                let Some(held) = bridge.upgrade() else {
                    return;
                };
                let displaced = held.is_displaced();
                drop(held);
                if !displaced {
                    continue;
                }
                tracing::error!(
                    hub = %hub,
                    "this mesh's hub was displaced: its lock file was removed while the mesh ran, \
                     and another owner took the hub name, marking the mesh's ring and replacing \
                     its shared memory ({}). Processes attached to the hub by name follow that \
                     owner and receive nothing this mesh's guests send, so the mesh stops \
                     serving: its connections close, and its sockets are removed while their \
                     paths still name them. Its host should drop it (EmbeddedMesh::is_displaced \
                     says so) and start another under a name nobody holds, or under this one \
                     once that owner has gone; and find what removed the lock file",
                    name_holder(&hub)
                );
                let taken = serving
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(serving) = taken {
                    serving.stop(|| bridge.strong_count() > 1);
                }
                return;
            })?;
        Ok(Self { finish, thread })
    }

    /// Tell the thread to finish, and wait until it has: at once, unless it
    /// is stopping a displaced mesh, which takes at most [`RELEASE_WAIT`].
    fn finish(self) {
        let Self { finish, thread } = self;
        drop(finish);
        // A panic in the thread has been reported by the panic hook, and
        // leaves the mesh for the stop that follows.
        let _ = thread.join();
    }
}

/// A mesh running inside this process: listening when [`EmbeddedMesh::start`]
/// returns, and stopped, its socket files removed, when dropped.
///
/// It owns its hub name and its sockets as the daemon does, claiming them
/// before its hub is created, so a second mesh or daemon on the same name,
/// socket or port is refused before it touches anything; should another owner
/// take the name all the same, the mesh stops serving
/// ([`EmbeddedMesh::is_displaced`]). Checked by `tests/embed.rs` and
/// `tests/one_owner.rs`.
pub struct EmbeddedMesh {
    hub_name: String,
    binds: Vec<Bind>,
    /// What serves the mesh until it stops, shared with the watch.
    serving: Arc<Mutex<Option<Serving>>>,
    /// The thread that watches the hub name, until the mesh stops.
    watch: Option<Watch>,
    /// The hub behind every listener, kept for its counters.
    bridge: Arc<HubBridge>,
    /// The registry every listener shares, kept for its connection counts.
    registry: Arc<Registry>,
}

impl fmt::Debug for EmbeddedMesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedMesh")
            .field("hub", &self.hub_name)
            .field("binds", &self.binds)
            .finish_non_exhaustive()
    }
}

impl EmbeddedMesh {
    /// Start a hub answering at one place.
    ///
    /// # Errors
    /// [`EmbedError`] naming which of the runtime, the hub or the listener
    /// refused. Nothing is left running in any of those cases.
    pub fn start(hub_name: &str, bind: Bind) -> Result<Self, EmbedError> {
        Self::start_at(hub_name, std::slice::from_ref(&bind))
    }

    /// Start one hub answering at every place in `binds`.
    ///
    /// # Errors
    ///
    /// [`EmbedError::Nowhere`] when `binds` is empty, and otherwise as
    /// [`EmbeddedMesh::start`]; one failed bind fails the whole start.
    pub fn start_at(hub_name: &str, binds: &[Bind]) -> Result<Self, EmbedError> {
        Self::start_with(hub_name, binds, ConnectionPolicy::default())
    }

    /// [`EmbeddedMesh::start_at`] under `policy` instead of the default.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedMesh::start_at`].
    pub fn start_with(
        hub_name: &str,
        binds: &[Bind],
        policy: ConnectionPolicy,
    ) -> Result<Self, EmbedError> {
        Self::start_with_config(hub_name, binds, policy, HubConfig::default())
    }

    /// [`EmbeddedMesh::start_with`] with `config` for the hub instead of the
    /// default, such as a smaller store ([`HubConfig::store_slots`]); a store
    /// that does not fit leaves the mesh without one
    /// ([`EmbeddedMesh::store_slots`]).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedMesh::start_at`].
    pub fn start_with_config(
        hub_name: &str,
        binds: &[Bind],
        policy: ConnectionPolicy,
        config: HubConfig,
    ) -> Result<Self, EmbedError> {
        Self::start_inner(hub_name, binds, policy, config, None)
    }

    /// [`EmbeddedMesh::start_with_config`], linked to other daemons by
    /// `links` ([`crate::link`]): its link address is bound with its other
    /// places, before its hub is created, and its clients' sends are
    /// forwarded to the peers whose subscribers may want them.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedMesh::start_at`], and [`EmbedError::Links`] when the
    /// links' configuration is refused, their address cannot be bound or
    /// their threads cannot start.
    pub fn start_with_links(
        hub_name: &str,
        binds: &[Bind],
        policy: ConnectionPolicy,
        config: HubConfig,
        links: LinkConfig,
    ) -> Result<Self, EmbedError> {
        Self::start_inner(hub_name, binds, policy, config, Some(links))
    }

    fn start_inner(
        hub_name: &str,
        binds: &[Bind],
        policy: ConnectionPolicy,
        config: HubConfig,
        links: Option<LinkConfig>,
    ) -> Result<Self, EmbedError> {
        if binds.is_empty() {
            return Err(EmbedError::Nowhere);
        }
        let runtime = tokio::runtime::Runtime::new().map_err(EmbedError::Runtime)?;
        // Claimed before the hub is created, which replaces the name's shared
        // memory; on an error, the claims drop before the runtime.
        let mut claimed = Vec::with_capacity(binds.len());
        for bind in binds {
            let claim = match bind {
                Bind::Uds(path) => runtime.block_on(claim_uds(path.clone())).map(Claimed::Uds),
                Bind::Ws(addr) => runtime
                    .block_on(bind_ws(*addr, false, policy.attach_keys.is_some()))
                    .map(|listener| Claimed::Ws(listener, None)),
                Bind::Wss(addr, tls) => runtime
                    .block_on(bind_ws(*addr, true, policy.attach_keys.is_some()))
                    .map(|listener| Claimed::Ws(listener, Some(tls.clone()))),
            };
            match claim {
                Ok(claim) => claimed.push(claim),
                Err(e) => {
                    drop(claimed);
                    return Err(EmbedError::Bind(bind.clone(), e));
                }
            }
        }
        let links = match links.map(crate::link::bind).transpose() {
            Ok(links) => links,
            Err(e) => {
                drop(claimed);
                return Err(EmbedError::Links(e));
            }
        };
        let bridge = match HubBridge::with_config(hub_name, config) {
            Ok(bridge) => bridge,
            Err(e) => {
                drop(claimed);
                return Err(EmbedError::Hub(e.to_string()));
            }
        };
        // The registry before the links, which announce its nodes.
        let registry = Registry::for_policy(&policy);
        let bridge = match links {
            Some(bound) => match bridge.with_links(bound, &registry) {
                Ok(bridge) => Arc::new(bridge),
                Err(e) => {
                    drop(claimed);
                    return Err(EmbedError::Links(e));
                }
            },
            None => Arc::new(bridge),
        };
        let mut serving = Serving {
            runtime,
            listeners: Vec::with_capacity(binds.len()),
            sockets: Vec::with_capacity(binds.len()),
        };
        let mut resolved: Vec<Bind> = Vec::with_capacity(binds.len());
        let mut claimed = claimed.into_iter();
        for bind in binds {
            let (shared, registry) = (Arc::clone(&bridge), Arc::clone(&registry));
            let result = match claimed.next() {
                Some(Claimed::Uds(claim)) => serving
                    .runtime
                    .block_on(claim.serve_held(shared, registry, policy.clone()))
                    .map(|socket| {
                        serving.sockets.push(socket);
                        bind.clone()
                    }),
                Some(Claimed::Ws(listener, tls)) => {
                    let _entered = serving.runtime.enter();
                    serve_ws_task(listener, shared, registry, policy.clone(), tls.clone()).map(
                        |(bound, accept)| {
                            serving.listeners.push(accept);
                            match tls {
                                Some(tls) => Bind::Wss(bound, tls),
                                None => Bind::Ws(bound),
                            }
                        },
                    )
                }
                None => Err(std::io::Error::other("a bind was claimed for no place")),
            };
            match result {
                Err(e) => {
                    // The places already served go too: stopping removes their
                    // sockets.
                    drop(claimed);
                    serving.stop(|| Arc::strong_count(&bridge) > 1);
                    return Err(EmbedError::Bind(bind.clone(), e));
                }
                Ok(actual) => resolved.push(actual),
            }
        }
        // The attached connections' liveness, unless the idle timeout is zero;
        // the task goes when the runtime stops, and holds no hub.
        if let Some(ticks) = health::ticks(&registry) {
            drop(serving.runtime.spawn(ticks));
        }
        let serving = Arc::new(Mutex::new(Some(serving)));
        let watch = match Watch::start(hub_name, Arc::downgrade(&bridge), Arc::clone(&serving)) {
            Ok(watch) => watch,
            Err(e) => {
                let taken = serving
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(serving) = taken {
                    serving.stop(|| Arc::strong_count(&bridge) > 1);
                }
                return Err(EmbedError::Runtime(e));
            }
        };
        Ok(Self {
            hub_name: hub_name.to_string(),
            binds: resolved,
            serving,
            watch: Some(watch),
            bridge,
            registry,
        })
    }

    /// The hub this mesh was created under.
    #[must_use]
    pub fn hub_name(&self) -> &str {
        &self.hub_name
    }

    /// Where it answers. A WebSocket bind asked for with port 0 is reported
    /// with the port actually bound.
    #[must_use]
    pub fn binds(&self) -> &[Bind] {
        &self.binds
    }

    /// The first WebSocket address it answers on, `ws://` or `wss://`, if
    /// any, as actually bound.
    #[must_use]
    pub fn ws_addr(&self) -> Option<SocketAddr> {
        self.binds.iter().find_map(|b| match b {
            Bind::Ws(a) | Bind::Wss(a, _) => Some(*a),
            Bind::Uds(_) => None,
        })
    }

    /// The first Unix-domain socket it answers on, if any.
    #[must_use]
    pub fn socket(&self) -> Option<&Path> {
        self.binds.iter().find_map(|b| match b {
            Bind::Uds(p) => Some(p.as_path()),
            Bind::Ws(_) | Bind::Wss(..) => None,
        })
    }

    /// How many envelopes the hub's store has refused since the mesh started;
    /// each was still delivered.
    #[must_use]
    pub fn store_failures(&self) -> u64 {
        self.bridge.store_failures()
    }

    /// Slots in the hub's envelope store, or `None` when the mesh runs without
    /// one.
    #[must_use]
    pub fn store_slots(&self) -> Option<usize> {
        self.bridge.store_slots()
    }

    /// How many connections hold a place now, on every listener together:
    /// accepted and not yet closed, a WebSocket still upgrading included.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.registry.connections()
    }

    /// How many connections were refused since the mesh started because it
    /// already held its policy's `max_connections`.
    #[must_use]
    pub fn connections_refused(&self) -> u64 {
        self.registry.connections_refused()
    }

    /// How many WebSocket upgrades were refused since the mesh started for an
    /// `Origin` naming another site's page.
    #[must_use]
    pub fn origins_refused(&self) -> u64 {
        self.registry.origins_refused()
    }

    /// Bytes of event JSON queued now across all the mesh's connections,
    /// which its policy's `total_queue_bytes` bounds.
    #[must_use]
    pub fn queued_event_bytes(&self) -> usize {
        self.registry.queue_total().held_bytes()
    }

    /// How many events were dropped at its policy's `total_queue_bytes` since
    /// the mesh started, refused or given up to make room; each also counts for
    /// its subscription.
    #[must_use]
    pub fn events_dropped_at_total_queue_bytes(&self) -> u64 {
        self.registry.queue_total().events_dropped()
    }

    /// How many attached connections are in good health now: heard from
    /// within about half the policy's `idle_timeout`, a tick being a tenth of
    /// it. This and the other counts of nodes are 0 when that timeout is zero,
    /// which turns the tracking off.
    #[must_use]
    pub fn nodes_healthy(&self) -> usize {
        self.registry.nodes_healthy()
    }

    /// How many attached connections are silent for half the policy's
    /// `idle_timeout` or more, and not yet for the whole of it.
    #[must_use]
    pub fn nodes_warning(&self) -> usize {
        self.registry.nodes_warning()
    }

    /// How many attached connections are silent for the policy's whole
    /// `idle_timeout`, which closes them as their state changes: rarely more
    /// than 0, for a moment.
    #[must_use]
    pub fn nodes_isolated(&self) -> usize {
        self.registry.nodes_isolated()
    }

    /// How many attached connections are degraded: drift is recorded for
    /// them. The mesh records none yet, so this is 0.
    #[must_use]
    pub fn nodes_degraded(&self) -> usize {
        self.registry.nodes_degraded()
    }

    /// How many `health` notices, the peer state changes sent to the
    /// connections whose subscriptions asked for them, were dropped since the
    /// mesh started for want of room in a queue or in `total_queue_bytes`.
    #[must_use]
    pub fn health_notices_dropped(&self) -> u64 {
        self.registry.health_notices_dropped()
    }

    /// What its links to other daemons have done so far, or `None` when it
    /// runs without links.
    #[must_use]
    pub fn link_stats(&self) -> Option<LinkStats> {
        self.bridge.links().map(crate::link::Links::stats)
    }

    /// How its sends with a destination (the protocol's `to`) went so far:
    /// to its own nodes, forwarded to a peer's, or refused as unknown.
    #[must_use]
    pub fn destination_sends(&self) -> DestinationSends {
        self.bridge.destination_sends()
    }

    /// The id its peers name it by across links, or `None` without links.
    #[must_use]
    pub fn daemon_id(&self) -> Option<DaemonId> {
        self.bridge.links().map(crate::link::Links::daemon_id)
    }

    /// The UDP address its links are bound to, as actually bound, or `None`
    /// without links.
    #[must_use]
    pub fn link_addr(&self) -> Option<SocketAddr> {
        self.bridge.links().map(crate::link::Links::local_addr)
    }

    /// Whether another owner has taken this mesh's hub name from under it (its
    /// lock file was removed while the mesh ran); once `true`, it stays `true`.
    ///
    /// Within [`DISPLACEMENT_CHECK`] of that, the mesh logs it and stops
    /// serving as [`Self::shutdown`] would; its counters still read, and
    /// dropping it leaves the new owner's names alone. Checked by
    /// `tests/one_owner.rs`.
    #[must_use]
    pub fn is_displaced(&self) -> bool {
        self.bridge.is_displaced()
    }

    /// Stop it now rather than on drop. When this returns, its sockets are
    /// removed, its hub's shared memory is unlinked and every lock is released,
    /// so a mesh started next on the same name or socket starts; a task that
    /// does not end delays this at most two seconds. Checked by
    /// `tests/embed.rs`.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        // The watch first, so nothing else stops the mesh meanwhile.
        if let Some(watch) = self.watch.take() {
            watch.finish();
        }
        let serving = self
            .serving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(serving) = serving {
            // Waits for the tasks to let go of the hub, so this mesh's handle
            // is its last.
            serving.stop(|| Arc::strong_count(&self.bridge) > 1);
        }
    }
}

impl Drop for EmbeddedMesh {
    fn drop(&mut self) {
        self.stop();
    }
}
