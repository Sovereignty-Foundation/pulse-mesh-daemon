// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The client's error type, [`DevError`].

use thiserror::Error;

/// Errors the client's calls return.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum DevError {
    /// `PMS_DAEMON` names neither a `unix://` path nor a `ws://` or `wss://`
    /// URL.
    #[error("no mesh-hub daemon found (set PMS_DAEMON or run `pms start`)")]
    NoDaemon,

    /// The socket at the default path, `/tmp/pms.sock`, is served by another
    /// user. Anyone may create that path before the daemon does, and a client
    /// connected to it would hand that user everything it sends, so the
    /// client does not use it.
    #[error("the socket at {path} is served by user {uid}, not by this user; remove it, or set PMS_DAEMON to your daemon's socket")]
    ForeignDaemon {
        /// The socket's path.
        path: String,
        /// The uid of the process that serves it.
        uid: u32,
    },

    /// The protocol version the daemon speaks is not supported by this client.
    #[error("protocol version mismatch: expected v0, daemon said {0}")]
    VersionMismatch(String),

    /// The client could not connect, or start its runtime or threads.
    #[error("transport error: {0}")]
    Transport(String),

    /// The TLS handshake of a `wss://` endpoint failed: the daemon's
    /// certificate chains to none of the roots the client trusts
    /// (webpki-roots' and those given with `MeshOptions::with_tls_root_pem`)
    /// or does not name the host, the daemon does not speak TLS, or a root
    /// given is not a PEM certificate. Nothing was sent.
    #[error("TLS: {0}")]
    Tls(String),

    /// A request could not be serialized, or the WebSocket handshake did not
    /// accept the port subprotocol.
    #[error("protocol parse error: {0}")]
    Protocol(String),

    /// The daemon returned an `error` op: in reply to a request, or
    /// unprompted just before it closed the connection (`limit_exceeded`
    /// at its connection cap, `payload_too_large` after a frame over its
    /// limit), which every call still waiting and `Mesh::wait` then report.
    /// Every code but `auth_failed`, which is [`DevError::AuthFailed`].
    #[error("daemon error [{code}]: {message}")]
    Daemon {
        /// The daemon's typed error code (e.g. `"limit_exceeded"`).
        /// Stable across protocol versions; downstream code may match on this.
        code: String,
        /// Human-readable detail. Not stable; intended for logs, not branching.
        message: String,
    },

    /// The daemon refused the attach with `auth_failed` and closed the
    /// connection: it allows only the keys it lists and this key is not
    /// one, or it requires a key (`MeshOptions::with_identity`) and the
    /// attach carried none, or the proof did not verify, or it came too
    /// late. `Mesh::wait` and every call still waiting report it too.
    #[error("the daemon refused the attach (auth_failed): {message}")]
    AuthFailed {
        /// The daemon's reason. Not stable; intended for logs.
        message: String,
    },

    /// A key file could not be made, read or used
    /// (`MeshOptions::with_identity_file`, `identity`): it cannot be opened,
    /// its group or others may read or write it, or it holds no key. `path`
    /// is empty when no random bytes could be had for a new key.
    #[error("key file {path}: {reason}")]
    KeyFile {
        /// The file.
        path: String,
        /// What is wrong.
        reason: String,
    },

    /// Called before `attach` succeeded.
    #[error("not attached — call Mesh::attach first")]
    NotAttached,

    /// The call got no answer: the connection had already ended when it
    /// was made, or ended without answering it.
    #[error("unexpected disconnect while waiting for reply")]
    DisconnectedDuringRpc,

    /// The daemon did not answer within `MeshOptions::rpc_timeout`, and the
    /// call was cancelled (see `Mesh::late_replies`).
    #[error("the daemon did not answer `{op}` within {after:?}")]
    Timeout {
        /// The operation that was waiting (`attach`, `send`, ...).
        op: &'static str,
        /// How long it waited.
        after: std::time::Duration,
    },

    /// The call was refused, having sent nothing, because the client's
    /// queue toward the daemon stayed full until its deadline (see
    /// `client::COMMAND_QUEUE`): the daemon reads more slowly than calls
    /// are made, or has stopped. The call may be retried.
    #[error("`{op}` was not sent: the client's queue toward the daemon stayed full")]
    QueueFull {
        /// The operation that was refused (`send`, `subscribe`, ...).
        op: &'static str,
    },

    /// A blocking call was made on a thread in an async runtime's context (a
    /// task's, or a `spawn_blocking` or `block_in_place` closure's), where
    /// blocking would deadlock or panic. Call from a plain `std::thread`, or
    /// from a subscription callback, which runs on one.
    #[error("Mesh calls are refused in async runtimes, spawn_blocking too; use a std::thread")]
    ReentrantCall,

    /// The connection ended, not by a detach the daemon acknowledged and
    /// with no error from the daemon: it closed the connection, or a write
    /// failed. `Mesh::wait` and every call still waiting report it.
    #[error("the daemon connection ended without a detach")]
    Disconnected,

    /// The daemon sent nothing for `MeshOptions::silence_limit` while the
    /// client waited for it, and the client closed the connection;
    /// `Mesh::wait` and every call still waiting report it. A stopped
    /// daemon or host looks like this.
    #[error("the daemon sent nothing for {after:?} while the client waited for it")]
    Silent {
        /// The silence limit it went past.
        after: std::time::Duration,
    },

    /// A `WeakMesh` was upgraded after every `Mesh` of its connection had
    /// been dropped, which closed the connection. Nothing was sent.
    #[error("every Mesh of this connection was dropped, which closed it")]
    MeshDropped,
}
