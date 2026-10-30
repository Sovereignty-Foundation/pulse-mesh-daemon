// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! WebSocket + UDS accept loops + transport adapters.

use crate::connection::{handle_connection, ConnectionPolicy, Inbound, Link, Transport};
use crate::hub_bridge::HubBridge;
use crate::origin::{self, Verdict};
use crate::protocol::framing::{FrameDecoder, FrameError, MAX_FRAME_LEN};
use crate::protocol::{attach, ErrorCode, ServerMessage};
use crate::registry::{AtCapacity, ConnectionSlot, Registry};
use crate::tls::WsTls;
use crate::ws::{self, FrameReader, Incoming, ReadError, UpgradeStream};
use mesh_hub_runtime::owner::{socket_lock_path, LockError, OwnerLock};
use std::io::IoSlice;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio_tungstenite::tungstenite::error::Error as WsError;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, StatusCode};
use tracing::{error, info, warn};

use crate::protocol::WS_SUBPROTOCOL;

/// How long turning a connection away may take, whatever the policy's write
/// deadline.
const REFUSE_DEADLINE: Duration = Duration::from_secs(1);

/// What a connection refused at the cap is told: the limit, and the flag
/// that sets it.
fn at_capacity_message(max_connections: usize) -> String {
    format!(
        "connection limit reached: the daemon holds at most {max_connections} connections \
         (--max-connections); try again later"
    )
}

/// Log a connection refused at the cap, at the first refusal and at each
/// doubling.
fn log_refusal(transport: &'static str, at: AtCapacity, max_connections: usize) {
    if at.refused.is_power_of_two() {
        warn!(
            transport,
            refused = at.refused,
            max_connections,
            "connection refused: the daemon is at its connection limit"
        );
    }
}

/// What an upgrade refused for its `Origin` is told: the rule, not the reason.
const ORIGIN_REFUSED: &str =
    "this daemon admits WebSocket upgrades from pages on loopback origins \
     (http or https on localhost, 127.0.0.1 or [::1]) and on the origins it was given with \
     --allow-origin, and from clients that send no Origin header";

/// The longest `Origin` value a refusal logs, in characters.
const ORIGIN_LOG_CHARS: usize = 120;

/// Log an upgrade refused for its `Origin`, as [`log_refusal`] does; the origin
/// is escaped and cut short, since the page chose it.
fn log_origin_refusal(peer: std::net::SocketAddr, req: &Request, reason: &str, refused: u64) {
    if refused.is_power_of_two() {
        let origin: String = req
            .headers()
            .get_all(http::header::ORIGIN)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(", ")
            .chars()
            .take(ORIGIN_LOG_CHARS)
            .collect();
        warn!(
            peer = %peer,
            origin = ?origin,
            reason,
            refused,
            "websocket upgrade refused: a web page from another site (--allow-origin admits one)"
        );
    }
}

/// The HTTP 503 a WebSocket connection refused at the cap is sent before its
/// request is read.
fn at_capacity_response(max_connections: usize) -> String {
    let reason = at_capacity_message(max_connections);
    format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{reason}",
        reason.len()
    )
}

/// Turn a WebSocket connection away at the cap: the 503 at once, without
/// reading the upgrade (on `wss://`, once the TLS handshake is done), so a
/// flood past the cap holds each descriptor at most [`REFUSE_DEADLINE`].
async fn refuse_ws(mut stream: tokio::net::TcpStream, max_connections: usize, tls: Option<WsTls>) {
    let response = at_capacity_response(max_connections);
    let _ = tokio::time::timeout(REFUSE_DEADLINE, async {
        match &tls {
            None => {
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await
            }
            Some(tls) => {
                let mut stream = tls.acceptor().accept(&mut stream).await?;
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await
            }
        }
    })
    .await;
    // Discard what has arrived: closing with bytes unread sends a reset, which
    // can destroy the refusal before the client reads it.
    let mut discard = [0u8; 4096];
    while matches!(stream.try_read(&mut discard), Ok(n) if n > 0) {}
}

/// Turn a Unix-socket connection away: one `limit_exceeded` error frame,
/// unprompted and without an id, then close.
async fn refuse_uds(stream: UnixStream, max_connections: usize, max_frame: usize) {
    let mut transport = UdsTransport::new(stream, max_frame);
    let err = ServerMessage::error(
        None,
        ErrorCode::LimitExceeded,
        at_capacity_message(max_connections),
    );
    let text = serde_json::to_string(&err).unwrap_or_else(|_| "{}".to_string());
    let _ = tokio::time::timeout(REFUSE_DEADLINE, transport.send(&text)).await;
    Box::new(transport).close().await;
}

/// A Unix socket path claimed and not yet bound: its lock is held and the path
/// is clear. Dropping it lets the path go.
#[derive(Debug)]
pub(crate) struct UdsClaim {
    path: PathBuf,
    lock: OwnerLock,
}

/// Claim `path` for a listener: take the lock beside it
/// ([`mesh_hub_runtime::owner::socket_lock_path`]), held until the listener
/// ends, then remove a socket file there that nobody answers, left by a daemon
/// that died. The lock decides first, since on macOS a live listener with a
/// full backlog refuses connections as a dead one does. A socket that answers,
/// or does not answer within a second, is left alone, and so is anything that
/// is not a socket. Checked by `tests/one_daemon.rs` and `tests/one_owner.rs`.
///
/// # Errors
///
/// `AddrInUse` when a live daemon holds the lock or answers at the path,
/// `AlreadyExists` when the path holds something other than a socket, and the
/// lock file's errors (`EACCES`, or `ENOENT` for a missing directory).
pub(crate) async fn claim_uds(path: PathBuf) -> std::io::Result<UdsClaim> {
    let lock = claim_socket_path(&path).await?;
    Ok(UdsClaim { path, lock })
}

impl UdsClaim {
    /// Bind the claimed path and serve it from a detached accept task that
    /// holds the claim: as the task ends it removes its socket, if the path
    /// still names it, and then lets the lock go. (An embedded mesh uses
    /// [`Self::serve_held`] instead.) A connection past
    /// `policy.max_connections` gets a `limit_exceeded` frame and is closed.
    ///
    /// # Errors
    ///
    /// The error of [`UnixListener::bind`], with the claim let go.
    pub(crate) async fn serve(
        self,
        bridge: Arc<HubBridge>,
        registry: Arc<Registry>,
        policy: ConnectionPolicy,
    ) -> std::io::Result<()> {
        let (listener, claim) = self.bind()?;
        drop(serve_uds(listener, Some(claim), bridge, registry, policy));
        Ok(())
    }

    /// [`Self::serve`], but the returned [`ServedSocket`] keeps the claim, so
    /// the socket goes when the caller says ([`ServedSocket::release`]).
    ///
    /// # Errors
    ///
    /// As [`Self::serve`].
    pub(crate) async fn serve_held(
        self,
        bridge: Arc<HubBridge>,
        registry: Arc<Registry>,
        policy: ConnectionPolicy,
    ) -> std::io::Result<ServedSocket> {
        let (listener, claim) = self.bind()?;
        let accept = serve_uds(listener, None, bridge, registry, policy);
        Ok(ServedSocket { claim, accept })
    }

    /// Bind the claimed path, restrict the socket to its owner, and record
    /// the socket file bound in the claim that will remove it.
    fn bind(self) -> std::io::Result<(UnixListener, SocketClaim)> {
        let Self { path, lock } = self;
        let listener = UnixListener::bind(&path)?;
        // Owner-only, whatever the umask.
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            warn!(path = %path.display(), error = %e, "could not restrict uds permissions");
        }
        info!(path = %path.display(), "uds listening");
        Ok((listener, SocketClaim::new(path, lock)))
    }
}

/// A served Unix socket whose claim the caller keeps
/// ([`UdsClaim::serve_held`]), to remove the socket with [`Self::release`], or
/// by dropping it, once [`Self::is_finished`] says the accept task has ended.
pub(crate) struct ServedSocket {
    claim: SocketClaim,
    accept: tokio::task::JoinHandle<()>,
}

impl ServedSocket {
    /// Whether the accept task has ended: its future has been dropped, and
    /// the listener with it, so nothing accepts at the socket any more.
    pub(crate) fn is_finished(&self) -> bool {
        self.accept.is_finished()
    }

    /// Remove the socket, if the path still names it, and then release its lock
    /// (see [`SocketClaim`]).
    pub(crate) fn release(self) {
        let Self { mut claim, accept } = self;
        claim.remove_socket();
        // The lock goes as `claim` drops, after the removal.
        drop(accept);
    }
}

/// Spawn the accept loop of [`UdsClaim::serve`] and
/// [`UdsClaim::serve_held`]. `claim`, when given, is the accept task's to
/// hold until it is dropped.
fn serve_uds(
    listener: UnixListener,
    claim: Option<SocketClaim>,
    bridge: Arc<HubBridge>,
    registry: Arc<Registry>,
    policy: ConnectionPolicy,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // The path is this listener's while the task lives; see SocketClaim.
        let _claim = claim;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => match registry.admit(policy.max_connections) {
                    Ok(slot) => {
                        let transport: Box<dyn Transport> =
                            Box::new(UdsTransport::new(stream, policy.max_message_bytes));
                        let bridge = bridge.clone();
                        let registry = registry.clone();
                        let policy = policy.clone();
                        tokio::spawn(async move {
                            handle_connection(transport, bridge, registry, policy).await;
                            // The place is the connection's until it has closed.
                            drop(slot);
                        });
                    }
                    Err(at) => {
                        log_refusal("uds", at, policy.max_connections);
                        tokio::spawn(refuse_uds(
                            stream,
                            policy.max_connections,
                            policy.max_message_bytes,
                        ));
                    }
                },
                Err(e) => {
                    error!("uds accept failed: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    })
}

/// Take the lock beside `path` and make `path` safe to bind, as [`claim_uds`]
/// describes; the caller holds the lock while it listens.
async fn claim_socket_path(path: &Path) -> std::io::Result<OwnerLock> {
    let lock = match OwnerLock::acquire(&socket_lock_path(path)) {
        Ok(lock) => lock,
        Err(LockError::Held { pid, .. }) => {
            let holder = pid.map_or_else(String::new, |pid| format!(" (process {pid})"));
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another daemon{holder} is live at {}", path.display()),
            ));
        }
        Err(e) => return Err(std::io::Error::other(e)),
    };
    reclaim_stale_socket(path).await?;
    Ok(lock)
}

/// Make `path` safe to bind, under its lock: nothing there, or a socket
/// file nobody answers, which is removed; see [`claim_socket_path`].
async fn reclaim_stale_socket(path: &Path) -> std::io::Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(md) if !md.file_type().is_socket() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Ok(_) => {}
    }
    match tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(path)).await {
        Ok(Ok(_live)) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("another daemon is live at {}", path.display()),
        )),
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            info!(path = %path.display(), "removing stale uds");
            tokio::fs::remove_file(path).await
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "the socket at {} did not answer the probe in 1 s; assuming live",
                path.display()
            ),
        )),
    }
}

/// A listener's hold on its socket path: the lock beside it and the identity of
/// the socket file bound. Dropping it removes the socket, if the path still
/// names it, and then releases the lock, in that order: the next daemon never
/// finds the lock free while this socket is there, and a successor's socket is
/// never removed (`tests/one_daemon.rs`, and the tests below).
struct SocketClaim {
    path: PathBuf,
    /// Device and inode of the socket file bound, until
    /// [`Self::remove_socket`] has dealt with it; `None` from the start if
    /// they could not be read (the file is then left for the next daemon to
    /// reclaim).
    bound: Option<(u64, u64)>,
    /// Released after the body of `drop`, which removes the socket first.
    _lock: OwnerLock,
}

impl SocketClaim {
    fn new(path: PathBuf, lock: OwnerLock) -> Self {
        let bound = std::fs::symlink_metadata(&path)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()));
        Self {
            path,
            bound,
            _lock: lock,
        }
    }

    /// Remove the socket if the path still names it, and log what was done; a
    /// second call does nothing. The lock is held, so only a removed lock file
    /// lets a successor in between the check and the removal.
    fn remove_socket(&mut self) {
        let Some(bound) = self.bound.take() else {
            return;
        };
        let still_ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|meta| (meta.dev(), meta.ino()) == bound);
        if still_ours {
            match std::fs::remove_file(&self.path) {
                Ok(()) => info!(path = %self.path.display(), "removed uds socket"),
                Err(e) => {
                    warn!(path = %self.path.display(), error = %e, "could not remove the uds socket");
                }
            }
        } else {
            info!(
                path = %self.path.display(),
                "left the path alone: it no longer names the socket this listener bound"
            );
        }
    }
}

impl Drop for SocketClaim {
    fn drop(&mut self) {
        self.remove_socket();
    }
}

/// Bind the WebSocket's listener without accepting yet: connections wait in the
/// backlog until [`serve_ws`]. An address other than loopback is logged: at
/// info when `tls` encrypts the WebSocket and `keys`, the policy's attach keys,
/// authenticate its clients, and as a warning, naming what is missing,
/// otherwise. The command line refuses the second without `--ws-allow-remote`,
/// and a host embedding the daemon gets the warning.
///
/// # Errors
///
/// The error of [`TcpListener::bind`] (`EADDRINUSE` when another daemon holds
/// the port).
pub(crate) async fn bind_ws(
    bind: std::net::SocketAddr,
    tls: bool,
    keys: bool,
) -> std::io::Result<TcpListener> {
    if !bind.ip().is_loopback() {
        match (tls, keys) {
            (true, true) => info!(
                addr = %bind,
                "websocket (wss) bound to an address other than loopback: TLS 1.3 \
                 encrypts it, and every attach on it proves a key the attach keys list"
            ),
            (true, false) => warn!(
                addr = %bind,
                "websocket (wss) bound to an address other than loopback: TLS encrypts \
                 it but authenticates no client, so anything that can reach it can \
                 still attach, send and subscribe; --attach-keys would admit only the \
                 clients that prove a listed key at attach"
            ),
            (false, true) => warn!(
                addr = %bind,
                "websocket bound to an address other than loopback in plaintext: every \
                 attach proves a listed key, but anything on the path can read and \
                 change what follows, and relay a proof as it is made; TLS \
                 (--ws-tls-cert, --ws-tls-key) would encrypt it and bind each proof \
                 to its connection"
            ),
            (false, false) => warn!(
                addr = %bind,
                "websocket bound to an address other than loopback: it has no \
                 authentication and no encryption, so anything that can reach it \
                 can attach, send and subscribe; TLS (--ws-tls-cert, --ws-tls-key) \
                 would encrypt it, and --attach-keys would admit only the clients \
                 that prove a listed key at attach"
            ),
        }
    }
    TcpListener::bind(bind).await
}

/// Serve the WebSocket from a detached accept task on a listener from
/// [`bind_ws`], and return its address (the port a bind to port 0 got); call it
/// within a Tokio runtime. With `tls`, each connection completes a TLS 1.3
/// handshake before its upgrade, the two within `policy.handshake_timeout`
/// together (`wss://`). A connection past `policy.max_connections` is answered
/// 503 before anything it sends is read (on `wss://`, after the handshake), and
/// an upgrade from a page `policy.allowed_origins` does not admit is answered
/// 403 and counted in [`Registry::origins_refused`].
///
/// # Errors
///
/// The error of reading the listener's address.
pub(crate) fn serve_ws(
    listener: TcpListener,
    bridge: Arc<HubBridge>,
    registry: Arc<Registry>,
    policy: ConnectionPolicy,
    tls: Option<WsTls>,
) -> std::io::Result<std::net::SocketAddr> {
    serve_ws_task(listener, bridge, registry, policy, tls).map(|(bound, _detached)| bound)
}

/// [`serve_ws`], returning the accept task's handle too, for a caller that
/// must know when the task has ended and its listener has closed
/// ([`tokio::task::JoinHandle::is_finished`]).
///
/// # Errors
///
/// As [`serve_ws`].
pub(crate) fn serve_ws_task(
    listener: TcpListener,
    bridge: Arc<HubBridge>,
    registry: Arc<Registry>,
    policy: ConnectionPolicy,
    tls: Option<WsTls>,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let bound = listener.local_addr()?;
    if tls.is_some() {
        info!(addr = %bound, scheme = "wss", "websocket listening, TLS 1.3");
    } else {
        info!(addr = %bound, scheme = "ws", "websocket listening, plaintext");
    }

    let accept = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let slot = match registry.admit(policy.max_connections) {
                        Ok(slot) => slot,
                        Err(at) => {
                            log_refusal("ws", at, policy.max_connections);
                            tokio::spawn(refuse_ws(stream, policy.max_connections, tls.clone()));
                            continue;
                        }
                    };
                    let accepted = Accepted {
                        peer,
                        bridge: bridge.clone(),
                        registry: registry.clone(),
                        policy: policy.clone(),
                        slot,
                    };
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        // A peer that connects and never completes the
                        // handshakes would otherwise park this task forever;
                        // the TLS handshake and the upgrade share the one
                        // deadline.
                        let deadline =
                            tokio::time::Instant::now() + accepted.policy.handshake_timeout;
                        let Some(tls) = tls else {
                            accepted.upgrade(stream, deadline, Link::WebSocket).await;
                            return;
                        };
                        let handshake =
                            tokio::time::timeout_at(deadline, tls.acceptor().accept(stream)).await;
                        match handshake {
                            Ok(Ok(stream)) => {
                                // What a key proved on this connection is bound
                                // to (`mesh_port_protocol::attach`).
                                let exported = stream.get_ref().1.export_keying_material(
                                    [0u8; attach::EXPORTER_LEN],
                                    attach::TLS_EXPORTER_LABEL,
                                    None,
                                );
                                match exported {
                                    Ok(exporter) => {
                                        let link = Link::SecureWebSocket { exporter };
                                        accepted.upgrade(stream, deadline, link).await;
                                    }
                                    Err(e) => {
                                        warn!(peer = %peer, "websocket TLS exporter refused: {}", e);
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                warn!(peer = %peer, "websocket TLS handshake failed: {}", e);
                            }
                            Err(_) => warn!(peer = %peer, "websocket TLS handshake timed out"),
                        }
                    });
                }
                Err(e) => {
                    error!("ws accept failed: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    });
    Ok((bound, accept))
}

/// A WebSocket connection admitted under the cap, before its upgrade: what
/// serving it takes, and its place, which is the connection's until it has
/// closed.
struct Accepted {
    peer: std::net::SocketAddr,
    bridge: Arc<HubBridge>,
    registry: Arc<Registry>,
    policy: ConnectionPolicy,
    slot: ConnectionSlot,
}

impl Accepted {
    /// Upgrade `stream`, a TCP connection or a TLS stream over one, by
    /// `deadline`, and serve the connection, which runs over `link`, until it
    /// closes.
    async fn upgrade<S>(self, stream: S, deadline: tokio::time::Instant, link: Link)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Self {
            peer,
            bridge,
            registry,
            policy,
            slot,
        } = self;
        let allowed_origins = policy.allowed_origins.clone();
        let origins = registry.clone();
        // The `Callback` trait fixes the large `ErrorResponse` error type.
        // tungstenite does the upgrade alone (see `crate::ws`).
        #[allow(clippy::result_large_err)]
        let handshake = tokio_tungstenite::accept_hdr_async(
            UpgradeStream::new(stream),
            move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                // A page from another site is refused before anything about
                // the protocol is checked or said.
                let verdict = origin::judge(
                    req.headers()
                        .get_all(http::header::ORIGIN)
                        .iter()
                        .map(HeaderValue::as_bytes),
                    &allowed_origins,
                );
                if let Verdict::Refused(reason) = verdict {
                    let refused = origins.refuse_origin();
                    log_origin_refusal(peer, req, reason, refused);
                    let mut err: ErrorResponse =
                        http::Response::new(Some(ORIGIN_REFUSED.to_string()));
                    *err.status_mut() = StatusCode::FORBIDDEN;
                    return Err(err);
                }
                // UPP v0 §2.1: the client announces the subprotocol and the
                // daemon echoes it, which RFC 6455 §4.1 clients require.
                let announced_v0 = req
                    .headers()
                    .get_all("Sec-WebSocket-Protocol")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|s| s.split(','))
                    .any(|p| p.trim() == WS_SUBPROTOCOL);
                if !announced_v0 {
                    let mut err: ErrorResponse = http::Response::new(Some(format!(
                        "client must request the '{}' subprotocol",
                        WS_SUBPROTOCOL
                    )));
                    *err.status_mut() = StatusCode::BAD_REQUEST;
                    return Err(err);
                }
                resp.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    HeaderValue::from_static(WS_SUBPROTOCOL),
                );
                Ok(resp)
            },
        );
        let mut upgraded = match tokio::time::timeout_at(deadline, handshake).await {
            Ok(Ok(s)) => s,
            // Refused for its origin, and logged then.
            Ok(Err(WsError::Http(response))) if response.status() == StatusCode::FORBIDDEN => {
                return;
            }
            Ok(Err(e)) => {
                warn!(peer = %peer, "websocket handshake failed: {}", e);
                return;
            }
            Err(_) => {
                warn!(peer = %peer, "websocket handshake timed out");
                return;
            }
        };
        let Some((stream, already)) = upgraded.get_mut().take_parts() else {
            warn!(peer = %peer, "websocket upgrade finished off the end of its request; closing");
            return;
        };
        drop(upgraded);
        let transport: Box<dyn Transport> = Box::new(WsTransport::new(
            stream,
            &already,
            policy.max_message_bytes,
            link,
        ));
        handle_connection(transport, bridge, registry, policy).await;
        // The place is the connection's until it has closed.
        drop(slot);
    }
}

/// Write all of `parts` in order with vectored writes, without joining them;
/// cancelled, it leaves the stream part-way through them.
async fn write_all_parts<W>(stream: &mut W, parts: [&[u8]; 3]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut slices = parts.map(IoSlice::new);
    let mut remaining = &mut slices[..];
    IoSlice::advance_slices(&mut remaining, 0);
    while !remaining.is_empty() {
        let written = stream.write_vectored(remaining).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

/// Write one Unix-socket frame of `head` then `body`, without joining them.
async fn write_uds_frame<W>(stream: &mut W, head: &[u8], body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let len = head.len() + body.len();
    let prefix = u32::try_from(len).map(u32::to_be_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            FrameError::Oversized {
                len,
                max: MAX_FRAME_LEN,
            },
        )
    })?;
    write_all_parts(stream, [&prefix, head, body]).await?;
    stream.flush().await
}

/// Write one final, unmasked WebSocket text frame of `head` then `body`.
async fn write_ws_text<W>(stream: &mut W, head: &[u8], body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let (header, used) = ws::frame_header(ws::TEXT, head.len() + body.len());
    write_all_parts(stream, [&header[..used], head, body]).await?;
    stream.flush().await
}

struct UdsTransport {
    stream: UnixStream,
    /// Bytes read and not yet returned. `recv` may be cancelled at any await,
    /// so every byte read goes into the decoder before the next one.
    frames: FrameDecoder,
}

impl UdsTransport {
    fn new(stream: UnixStream, max_frame: usize) -> Self {
        Self {
            stream,
            frames: FrameDecoder::new(max_frame),
        }
    }
}

#[async_trait::async_trait]
impl Transport for UdsTransport {
    async fn recv(&mut self) -> Inbound {
        loop {
            match self.frames.pop() {
                Ok(Some(frame)) => {
                    return match String::from_utf8(frame) {
                        Ok(text) => Inbound::Frame(text),
                        Err(e) => {
                            warn!(error = %e, "uds frame is not utf-8; closing");
                            Inbound::Closed
                        }
                    };
                }
                Ok(None) => {}
                Err(FrameError::Oversized { len, .. }) => return Inbound::Oversized { len },
                // A refusal a later framer adds: nothing to resynchronise on,
                // so close.
                Err(e) => {
                    warn!(error = %e, "uds frame refused; closing");
                    return Inbound::Closed;
                }
            }
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return Inbound::Closed,
                Ok(n) => self.frames.push(&chunk[..n]),
            }
        }
    }

    fn link(&self) -> Link {
        Link::UnixSocket
    }

    async fn send(&mut self, msg: &str) -> std::io::Result<()> {
        write_uds_frame(&mut self.stream, msg.as_bytes(), b"").await
    }

    async fn send_event(&mut self, head: &str, body: &str) -> std::io::Result<()> {
        write_uds_frame(&mut self.stream, head.as_bytes(), body.as_bytes()).await
    }

    async fn close(mut self: Box<Self>) {
        let _ = self.stream.shutdown().await;
    }
}

/// Control frames waiting to be written (a pong, a ping, a close). They go out
/// before any other frame, so one cut short is finished first and the stream
/// stays whole.
#[derive(Debug, Default)]
struct ControlOut {
    bytes: Vec<u8>,
    /// How many of `bytes` are written.
    written: usize,
    /// Where the last frame queued begins, while it is a pong none of which
    /// is written: a newer pong replaces it, as RFC 6455 allows, so pings
    /// that come faster than their pongs can be written queue one pong.
    unsent_pong: Option<usize>,
}

impl ControlOut {
    /// Queue a control frame of `opcode` carrying `payload`, at most
    /// [`ws::MAX_CONTROL_PAYLOAD`] bytes.
    fn queue(&mut self, opcode: u8, payload: &[u8]) {
        if opcode == ws::PONG {
            if let Some(at) = self.unsent_pong.filter(|&at| at >= self.written) {
                self.bytes.truncate(at);
            }
        }
        let at = self.bytes.len();
        let (header, used) = ws::frame_header(opcode, payload.len());
        self.bytes.extend_from_slice(&header[..used]);
        self.bytes.extend_from_slice(payload);
        self.unsent_pong = (opcode == ws::PONG).then_some(at);
    }

    /// The bytes queued and not yet written.
    fn pending(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    /// Record that `n` of the pending bytes were written.
    fn wrote(&mut self, n: usize) {
        self.written += n;
        if self.written >= self.bytes.len() {
            self.bytes.clear();
            self.written = 0;
            self.unsent_pong = None;
        }
    }
}

/// The daemon's end of an upgraded WebSocket, framed by the daemon itself (see
/// `ws`).
struct WsTransport<S> {
    stream: S,
    frames: FrameReader,
    control: ControlOut,
    /// A text frame was begun on the socket and not finished (its write ran
    /// out of time): the stream ends mid-frame, so no frame may follow it.
    torn: bool,
    /// A close frame is queued, the daemon's own or its answer to the
    /// client's: the connection's last frame.
    close_queued: bool,
    /// `ws://` or `wss://`, with the TLS exporter value.
    link: Link,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WsTransport<S> {
    /// The daemon's end of an upgraded WebSocket on `stream`, whose first
    /// bytes, read with the upgrade request, are `already`; messages are
    /// capped at `max_message` bytes, and it runs over `link`.
    fn new(stream: S, already: &[u8], max_message: usize, link: Link) -> Self {
        Self {
            stream,
            frames: FrameReader::new(max_message, already),
            control: ControlOut::default(),
            torn: false,
            close_queued: false,
            link,
        }
    }

    /// Queue the connection's close frame, carrying `status` if there is
    /// one: the client's own code when it closed first, and nothing when
    /// the daemon ends the connection or the client's close gave no code.
    fn queue_close(&mut self, status: Option<u16>) {
        if !self.close_queued {
            let payload = status.map(u16::to_be_bytes);
            self.control.queue(
                ws::CLOSE,
                payload.as_ref().map_or(&[][..], |code| &code[..]),
            );
            self.close_queued = true;
        }
    }

    /// Write out the control frames queued, whole; a call cancelled part-way
    /// leaves the rest queued.
    async fn flush_control(&mut self) -> std::io::Result<()> {
        while !self.control.pending().is_empty() {
            let n = self.stream.write(self.control.pending()).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            self.control.wrote(n);
        }
        self.stream.flush().await
    }

    /// Write one text frame whose payload is `head` then `body`, after the
    /// control frames queued, so that it starts where a frame may.
    async fn write_text(&mut self, head: &[u8], body: &[u8]) -> std::io::Result<()> {
        self.flush_control().await?;
        self.torn = true;
        write_ws_text(&mut self.stream, head, body).await?;
        self.torn = false;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Transport for WsTransport<S> {
    async fn recv(&mut self) -> Inbound {
        loop {
            // A pong an earlier call queued and could not finish goes out
            // before anything more is read.
            if !self.control.pending().is_empty() && self.flush_control().await.is_err() {
                return Inbound::Closed;
            }
            match self.frames.pop() {
                Ok(Some(Incoming::Text(text))) => return Inbound::Frame(text),
                Ok(Some(Incoming::Ping(payload))) => {
                    // Answered at once, as RFC 6455 asks, and queued before
                    // it is written: a call cancelled mid-write still sends
                    // it, whole, before anything else.
                    self.control.queue(ws::PONG, &payload);
                    if self.flush_control().await.is_err() {
                        return Inbound::Closed;
                    }
                    return Inbound::Pong;
                }
                Ok(Some(Incoming::Pong)) => return Inbound::Pong,
                Ok(Some(Incoming::Close(status))) => {
                    // RFC 6455 §5.5.1: answer with a close echoing the client's
                    // code; `close` then ends the TCP connection.
                    self.queue_close(status);
                    return Inbound::Closed;
                }
                Ok(None) => {}
                Err(ReadError::Oversized { len }) => return Inbound::Oversized { len },
                Err(ReadError::Protocol(reason)) => {
                    warn!(reason, "websocket frames refused; closing");
                    return Inbound::Closed;
                }
            }
            // The reader keeps what it has been given, so a read cancelled
            // here loses nothing.
            match self.stream.read(self.frames.space()).await {
                Ok(0) | Err(_) => return Inbound::Closed,
                Ok(n) => self.frames.filled(n),
            }
        }
    }

    fn link(&self) -> Link {
        self.link
    }

    fn supports_ping(&self) -> bool {
        true
    }

    async fn ping(&mut self) -> std::io::Result<()> {
        self.control.queue(ws::PING, &[]);
        self.flush_control().await
    }

    async fn send(&mut self, msg: &str) -> std::io::Result<()> {
        self.write_text(msg.as_bytes(), b"").await
    }

    async fn send_event(&mut self, head: &str, body: &str) -> std::io::Result<()> {
        self.write_text(head.as_bytes(), body.as_bytes()).await
    }

    async fn close(mut self: Box<Self>) {
        // A close frame for a clean end, unless a frame was left torn. Then
        // drain what the peer still sends, since closing with bytes unread
        // sends a reset that can destroy the frames just written; a second in
        // all.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            if !self.torn {
                self.queue_close(None);
                let _ = self.flush_control().await;
            }
            let _ = self.stream.shutdown().await;
            let mut discard = [0u8; 8192];
            while matches!(self.stream.read(&mut discard).await, Ok(n) if n > 0) {}
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::AsyncReadExt;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    /// A socket path private to this process and this test: runs of the
    /// same test in other worktrees share the temporary directory.
    fn socket_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("mesh-sv-{tag}-{pid}-{nanos}.sock"))
    }

    /// A bridge for a hub private to this process, `tag` and the process
    /// id, whose store has sixteen slots.
    fn small_bridge(tag: &str) -> Arc<HubBridge> {
        let config = mesh_hub_runtime::HubConfig::default().with_store_slots(16);
        let name = format!("{tag}{:x}", std::process::id());
        Arc::new(HubBridge::with_config(&name, config).unwrap())
    }

    /// Serve a claim on `path` for a hub of its own, keeping the claim.
    async fn serve_held(path: &Path, hub: &str) -> ServedSocket {
        claim_uds(path.to_path_buf())
            .await
            .unwrap()
            .serve_held(
                small_bridge(hub),
                Registry::new(),
                ConnectionPolicy::default(),
            )
            .await
            .unwrap()
    }

    fn inode(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().ino()
    }

    #[tokio::test]
    async fn a_held_socket_goes_when_released_while_its_accept_task_still_runs() {
        let path = socket_path("held");
        let served = serve_held(&path, "sv-held").await;
        UnixStream::connect(&path).await.expect("it answers");
        assert!(!served.is_finished(), "its accept task still runs");
        // The release removes the socket and then lets the lock go itself,
        // without waiting for the accept task to be dropped.
        served.release();
        assert!(!path.exists(), "the socket is gone");
        assert!(!socket_lock_path(&path).exists(), "and its lock let go");
        drop(
            claim_uds(path.clone())
                .await
                .expect("the path can be claimed again at once"),
        );
    }

    #[tokio::test]
    async fn a_held_socket_leaves_a_successors_socket_and_lock_alone() {
        let path = socket_path("succ");
        let served = serve_held(&path, "sv-succ").await;
        // Its socket and lock file are removed from under it, and a
        // successor takes the path.
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(socket_lock_path(&path)).unwrap();
        let successor = serve_held(&path, "sv-succn").await;
        let successors = inode(&path);
        served.release();
        assert_eq!(inode(&path), successors, "the successor's socket stays");
        assert!(socket_lock_path(&path).exists(), "and so does its lock");
        UnixStream::connect(&path)
            .await
            .expect("the successor still answers");
        successor.release();
        assert!(!path.exists(), "the successor removes its own");
        assert!(!socket_lock_path(&path).exists());
    }

    #[tokio::test]
    async fn uds_recv_survives_being_cancelled_mid_header() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 1 << 20);
        let f = frame(br#"{"op":"health"}"#);
        peer.write_all(&f[..2]).await.unwrap();
        let early = tokio::time::timeout(Duration::from_millis(20), t.recv()).await;
        assert!(early.is_err(), "no frame is complete yet");
        peer.write_all(&f[2..]).await.unwrap();
        assert_eq!(t.recv().await, Inbound::Frame(r#"{"op":"health"}"#.into()));
    }

    #[tokio::test]
    async fn uds_recv_splits_two_frames_from_one_read() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 1 << 20);
        let mut both = frame(b"one");
        both.extend(frame(b"two"));
        peer.write_all(&both).await.unwrap();
        assert_eq!(t.recv().await, Inbound::Frame("one".into()));
        assert_eq!(t.recv().await, Inbound::Frame("two".into()));
    }

    #[tokio::test]
    async fn uds_recv_rejects_a_frame_over_the_cap() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 8);
        peer.write_all(&frame(&[b'x'; 16])).await.unwrap();
        assert_eq!(t.recv().await, Inbound::Oversized { len: 16 });
    }

    #[tokio::test]
    async fn uds_recv_rejects_non_utf8() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 1 << 20);
        peer.write_all(&frame(&[0xff, 0xfe])).await.unwrap();
        assert_eq!(t.recv().await, Inbound::Closed);
    }

    #[tokio::test]
    async fn uds_send_prefixes_big_endian_length() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 1 << 20);
        t.send("hi").await.unwrap();
        let mut got = [0u8; 6];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0, 0, 0, 2, b'h', b'i']);
    }

    #[tokio::test]
    async fn uds_send_event_writes_one_frame_of_both_parts() {
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let mut t = UdsTransport::new(ours, 1 << 20);
        // Larger than the socket's buffer, so that it takes several writes.
        let body = format!("{}\"}}", "x".repeat(300 * 1024));
        let reader = tokio::spawn(async move {
            let mut len = [0u8; 4];
            peer.read_exact(&mut len).await.unwrap();
            let mut text = vec![0u8; u32::from_be_bytes(len) as usize];
            peer.read_exact(&mut text).await.unwrap();
            String::from_utf8(text).unwrap()
        });
        t.send_event("{\"x\":\"", &body).await.unwrap();
        assert_eq!(reader.await.unwrap(), format!("{{\"x\":\"{body}"));
    }

    /// The daemon's end of a WebSocket, upgraded as the accept loop
    /// upgrades one, and a client's.
    async fn ws_pair() -> (
        WsTransport<tokio::net::TcpStream>,
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio_tungstenite::client_async(format!("ws://{addr}"), stream)
                .await
                .unwrap()
                .0
        });
        let (stream, _) = listener.accept().await.unwrap();
        let mut upgraded = tokio_tungstenite::accept_async(UpgradeStream::new(stream))
            .await
            .unwrap();
        let (stream, already) = upgraded.get_mut().take_parts().unwrap();
        (
            WsTransport::new(stream, &already, 1 << 20, Link::WebSocket),
            client.await.unwrap(),
        )
    }

    #[tokio::test]
    async fn ws_writes_each_frame_whole_after_the_control_frames_queued() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        let (mut daemon, mut client) = ws_pair().await;
        // A ping the daemon answers as it reads it, and a pong queued and
        // not yet written: both go out before the events, whole.
        client
            .send(WsMsg::Ping(b"are you there".to_vec()))
            .await
            .unwrap();
        assert_eq!(daemon.recv().await, Inbound::Pong);
        daemon.control.queue(ws::PONG, b"queued");
        // Each form of the length, and an event larger than the socket's
        // buffers, which takes many writes.
        let sizes = [1usize, 125, 126, 65_535, 65_536, 700 * 1024];
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < 2 + sizes.len() + 1 {
                match client.next().await.unwrap().unwrap() {
                    WsMsg::Pong(p) => got.push(format!("pong {}", String::from_utf8(p).unwrap())),
                    WsMsg::Text(t) => got.push(t),
                    other => panic!("unexpected {other:?}"),
                }
            }
            got
        });
        let mut expected = vec!["pong are you there".to_string(), "pong queued".to_string()];
        for size in sizes {
            let body = format!("{}\"}}", "y".repeat(size));
            daemon.send_event("{\"x\":\"", &body).await.unwrap();
            expected.push(format!("{{\"x\":\"{body}"));
        }
        // A reply goes out the same way.
        daemon.send(r#"{"op":"ack"}"#).await.unwrap();
        expected.push(r#"{"op":"ack"}"#.to_string());
        assert_eq!(reader.await.unwrap(), expected);
        assert!(!daemon.torn);
        assert!(daemon.control.pending().is_empty());
    }

    #[tokio::test]
    async fn ws_reads_messages_and_answers_pings_between_their_fragments() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
        use tokio_tungstenite::tungstenite::protocol::frame::Frame;
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        let (mut daemon, mut client) = ws_pair().await;
        client.send(WsMsg::Text("one".into())).await.unwrap();
        // A message in three fragments with a ping between them.
        for frame in [
            Frame::message(b"t".to_vec(), OpCode::Data(Data::Text), false),
            Frame::ping(b"p".to_vec()),
            Frame::message(b"w".to_vec(), OpCode::Data(Data::Continue), false),
            Frame::message(b"o".to_vec(), OpCode::Data(Data::Continue), true),
        ] {
            client.send(WsMsg::Frame(frame)).await.unwrap();
        }
        client.send(WsMsg::Binary(vec![1, 2, 3])).await.unwrap();
        client.send(WsMsg::Text("three".into())).await.unwrap();
        assert_eq!(daemon.recv().await, Inbound::Frame("one".into()));
        assert_eq!(daemon.recv().await, Inbound::Pong, "the ping");
        assert_eq!(daemon.recv().await, Inbound::Frame("two".into()));
        // The binary message is read and let go.
        assert_eq!(daemon.recv().await, Inbound::Frame("three".into()));
        assert_eq!(daemon.frames.holding(), 0);
        drop(client);
        assert_eq!(daemon.recv().await, Inbound::Closed);
    }

    #[tokio::test]
    async fn ws_answers_a_clients_close_with_its_code_and_then_ends_the_stream() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        for code in [CloseCode::Normal, CloseCode::Away, CloseCode::Library(4321)] {
            let (mut daemon, mut client) = ws_pair().await;
            client
                .send(WsMsg::Close(Some(CloseFrame {
                    code,
                    reason: "bye".into(),
                })))
                .await
                .unwrap();
            assert_eq!(daemon.recv().await, Inbound::Closed);
            let closing = tokio::spawn(Box::new(daemon).close());
            match client.next().await {
                Some(Ok(WsMsg::Close(Some(frame)))) => assert_eq!(frame.code, code),
                other => panic!("{code}: {other:?}, expected the close echoed"),
            }
            assert!(client.next().await.is_none(), "then the stream ends");
            drop(client);
            closing.await.unwrap();
        }
    }

    #[tokio::test]
    async fn ws_answers_a_malformed_close_with_the_code_that_says_why() {
        use tokio::io::AsyncWriteExt;
        // A close without a code, with a code no close may carry, and with
        // a reason that is not UTF-8, from a client that writes raw frames.
        for (payload, answer) in [
            (&[][..], &[0x88, 0][..]),
            (&[0x03, 0xed][..], &[0x88, 2, 0x03, 0xea][..]),
            (&[0x03, 0xe8, 0xff][..], &[0x88, 2, 0x03, 0xef][..]),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut daemon = WsTransport::new(stream, &[], 1024, Link::WebSocket);
            let mut frame = vec![0x88, 0x80 | payload.len() as u8, 0, 0, 0, 0];
            frame.extend_from_slice(payload);
            client.write_all(&frame).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(daemon.recv().await, Inbound::Closed);
            Box::new(daemon).close().await;
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, answer, "{payload:?}");
        }
    }

    #[tokio::test]
    async fn ws_close_sends_a_close_frame_and_ends_the_stream() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        let (daemon, mut client) = ws_pair().await;
        let closing = tokio::spawn(Box::new(daemon).close());
        assert!(matches!(client.next().await, Some(Ok(WsMsg::Close(None)))));
        assert!(client.next().await.is_none(), "then the stream ends");
        drop(client);
        closing.await.unwrap();
    }

    #[test]
    fn a_newer_pong_replaces_one_not_yet_written_and_nothing_else() {
        let mut control = ControlOut::default();
        control.queue(ws::PONG, b"one");
        control.queue(ws::PONG, b"two");
        assert_eq!(control.pending(), [&[0x8a, 3][..], b"two"].concat());
        // Once a pong has begun, it is finished before the next.
        control.wrote(1);
        control.queue(ws::PONG, b"three");
        assert_eq!(
            control.pending(),
            [&[3][..], b"two", &[0x8a, 5], b"three"].concat()
        );
        // A pong queued after another frame replaces nothing before it.
        control.queue(ws::PING, b"");
        control.queue(ws::PONG, b"four");
        assert_eq!(
            control.pending(),
            [
                &[3][..],
                b"two",
                &[0x8a, 5],
                b"three",
                &[0x89, 0],
                &[0x8a, 4],
                b"four"
            ]
            .concat()
        );
        let all = control.pending().len();
        control.wrote(all);
        assert!(control.pending().is_empty());
        assert_eq!(control.unsent_pong, None);
    }
}
