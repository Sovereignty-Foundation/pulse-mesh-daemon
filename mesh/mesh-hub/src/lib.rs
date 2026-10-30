// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh-hub`: the Pulse Mesh™ daemon, tier 2.
//!
//! Terminates the Universal Port Protocol (`protocol`, from
//! `mesh-port-protocol`) over a WebSocket and a Unix socket, and bridges every
//! connection to the embedded hub runtime, `mesh_hub_runtime::PulseHub`.
//!
//! - [`run`] serves a daemon from a [`DaemonConfig`] until a signal or a
//!   displacement; the binary (`src/main.rs`) only parses its flags into one.
//! - [`embed::EmbeddedMesh`] hosts the same daemon inside another process.
//! - [`ConnectionPolicy`] says how connections are served: timers, caps, the
//!   event queue budgets, and the web origins ([`AllowedOrigin`]) whose pages
//!   may open the WebSocket.
//! - [`WsTls`], the certificate chain and key that make the WebSocket
//!   `wss://`: TLS 1.3 on rustls, which encrypts the WebSocket and
//!   authenticates the daemon to its clients (ADR-0018).
//! - [`AttachKeys`], the Ed25519 public keys a client may prove at attach
//!   (`--attach-keys`), which authenticate the clients: a client that proves
//!   a key is named by it (`mesh_port_protocol::attach`), and with a list the
//!   WebSocket admits no other.
//! - [`link`], the daemon's links to other daemons over sealed UDP
//!   ([`LinkConfig`], ADR-0021): configured peers, found by their
//!   announcements on a LAN ([`AnnounceConfig`]) when named by key alone,
//!   interest summaries, and
//!   each client send forwarded one hop to the peers whose subscribers may
//!   want it; the attached nodes announced to the peers, so that a send
//!   with a destination (the protocol's `to`) reaches a node of another
//!   daemon; and the nodes' health reported across links.
//! - [`cli_docs`] renders the binary's command line as its reference page.
//! - `otel`, with the `otel` feature, exports the daemon's spans (`send`,
//!   `deliver`, `attach`, `detach`, `subscribe`, `unsubscribe`) as
//!   OpenTelemetry traces over OTLP/HTTP; without a layer that takes them, the
//!   spans cost a level check.
//!
//! The private modules: `hub_bridge` (the runtime and the subscriber map),
//! `attach_keys` ([`AttachKeys`]),
//! `registry` (attached names, connection counts), `health` (the attached
//! connections' liveness and the `health` notices about it), `connection` (the
//! per-connection loop), `queue` (event queues and their shared budget),
//! `filter` (subscription matching), `origin` (the `Origin` check), `server`
//! (the accept loops and transports), `tls` ([`WsTls`]) and `ws` (WebSocket
//! framing).
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/reference/spec/07-port-protocol.html> and
//! <https://pulse-mesh.net/docs/daemon/explanation/daemon-design.html>.
#![forbid(unsafe_code)]

mod attach_keys;
#[cfg(feature = "basket")]
mod capture;
pub mod cli_docs;
pub(crate) mod connection;
mod daemon;
pub mod embed;
mod filter;
mod health;
pub(crate) mod hub_bridge;
pub mod link;
mod metrics;
pub(crate) mod origin;
#[cfg(feature = "otel")]
pub mod otel;
pub(crate) mod queue;
/// The Universal Port Protocol v0 wire types (`mesh-port-protocol`).
pub use mesh_port_protocol as protocol;
pub(crate) mod registry;
pub(crate) mod server;
mod tls;
pub(crate) mod ws;

pub use attach_keys::{AttachKeys, AttachKeysError};
pub use connection::{ConnectionPolicy, DEFAULT_TOTAL_QUEUE_BYTES};
#[cfg(feature = "basket")]
pub use daemon::BasketConfig;
pub use daemon::{run, DaemonConfig, DaemonError, DaemonExit};
pub use hub_bridge::{DestinationSends, DISPLACEMENT_CHECK};
pub use link::{AnnounceConfig, LinkConfig, LinkPeer, LinkPeerError, LinkSetupError, LinkStats};
/// The hub's configuration and its store's default size, re-exported so a host
/// can size the hub without depending on the runtime crate.
pub use mesh_hub_runtime::{HubConfig, DEFAULT_STORE_SLOTS};
pub use origin::{AllowedOrigin, InvalidOrigin};
pub use queue::MAX_QUEUE_EVENTS;
pub use tls::{WsTls, WsTlsError};

/// For the fuzz targets and the crate's tests; not API, and not stable.
#[doc(hidden)]
pub mod internals {
    pub use crate::connection::{handle_connection, quoted, Inbound, Link, Transport, MAX_QUOTED};
    pub use crate::hub_bridge::HubBridge;
    pub use crate::origin::{judge, Verdict};
    pub use crate::registry::{ConnectionId, Registry};

    /// The link datagrams' encoding and decoding (`crate::link`), for the
    /// `fuzz_link_wire` target and the link tests.
    pub mod link_wire {
        pub use crate::link::wire::{
            control, decode, forward, hello, max_control_bytes, max_interest_bytes, read_hello,
            Datagram, DatagramError, HelloFlags, LinkForward, Message, CONTROL_TYPE, FORWARD_TYPE,
            FORWARD_VERSION, LINK_HELLO_BYTES,
        };
    }

    /// The LAN announcement's encoding and decoding (`crate::link`, "Finding
    /// peers on a LAN"), for the `fuzz_link_announce` target and the link
    /// tests.
    pub mod link_announce {
        pub use crate::link::announce::{
            decode, encode, pulse, AnnounceError, LanAnnouncement, ANNOUNCE_BYTES, ANNOUNCE_MAGIC,
            ANNOUNCE_VERSION,
        };
    }
}

/// The status the daemon exits with when displaced ([`DaemonExit::Displaced`]):
/// distinct from 1 (a failed start) and 2 (a refused command line), so a
/// supervisor can tell not to restart it.
pub const DISPLACED_EXIT_STATUS: u8 = 3;
