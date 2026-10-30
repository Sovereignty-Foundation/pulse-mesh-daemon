// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh_client`: the Rust client for the daemon, tier 2.
//!
//! [`Mesh`] is a small synchronous client of the Universal Port Protocol,
//! so application code attaches to a running `mesh-hub` without touching
//! transports, framing, base64 or an async runtime. It is the daemon's peer:
//! it speaks the wire types `mesh-port-protocol` defines and `mesh-hub`
//! terminates, and depends on nothing of any ring (ADR-0012).
//!
//! ```no_run
//! use mesh_client::Mesh;
//!
//! let mesh = Mesh::attach("worker")?;
//! mesh.send("queue/jobs", b"hello")?;
//! mesh.on("queue/results", |env| {
//!     println!("got: {:?} on {}", env.payload, env.channel);
//! })?;
//! mesh.run()?;
//! # Ok::<(), mesh_client::DevError>(())
//! ```
//!
//! Where each rule is stated: endpoint discovery at [`Mesh::attach`]; the
//! timeouts, the heartbeat, the silence limit and the event queue's bounds
//! at [`MeshOptions`]; what keeps a connection open at [`Mesh`]; what a
//! call that times out leaves behind at [`Mesh::late_replies`]; the memory
//! a daemon that stops reading, or floods the client, can cost at
//! [`client::OUTBOUND_QUEUE`], [`client::COMMAND_QUEUE`],
//! [`client::INBOUND_QUEUE_BYTES`] and [`client::MAX_INBOUND_MESSAGE`];
//! how each failure is reported at [`DevError`]. The tests in `tests/`
//! check them against a daemon, real or faked.
//!
//! A client may attach as an Ed25519 key ([`MeshOptions::with_identity`],
//! [`MeshOptions::with_identity_file`]): it then answers the daemon's
//! challenge with a proof of the key, bound on `wss://` to the TLS
//! connection, and the daemon names it by the key
//! (`mesh_port_protocol::attach`). [`identity`] makes and reads key files.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/reference/rust.html> and
//! <https://pulse-mesh.net/docs/daemon/reference/spec/07-port-protocol.html>.
#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod identity;

pub use client::{
    Endpoint, Mesh, MeshEvent, MeshOptions, SendReceipt, SubscriptionId, TapFilter, WeakMesh,
};
pub use error::DevError;
/// An Ed25519 secret key, a client's identity at attach
/// ([`MeshOptions::with_identity`]).
pub use mesh_port_protocol::attach::SigningKey;
