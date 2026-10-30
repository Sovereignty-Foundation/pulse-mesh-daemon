// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! dev_ring: the `hub` layer, the ring's one import point.
//!
//! Re-exports the ring's `core`, `functions` and `stages` layers and registers
//! them with `register_stages!`. It also re-exports the daemon's Rust client,
//! `mesh_client`, so that `dev_hub::Mesh` paths keep working (ADR-0012); new
//! code names `mesh_client` directly.
//!
//! ```no_run
//! use dev_hub::Mesh;
//!
//! let mesh = Mesh::attach("worker")?;
//! mesh.send("queue/jobs", b"hello")?;
//! # Ok::<(), dev_hub::DevError>(())
//! ```
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/rings/dev_ring.html>.
#![forbid(unsafe_code)]

/// The Rust client for the daemon, re-exported from `mesh_client`.
pub use mesh_client::{
    client, error, DevError, Endpoint, Mesh, MeshEvent, MeshOptions, SendReceipt, SubscriptionId,
    TapFilter, WeakMesh,
};

/// The ring's `core` layer, empty by design.
pub use dev_core as core;
/// The ring's `functions` layer.
pub use dev_functions as functions;
/// The ring's `stages` layer.
pub use dev_stages as stages;

// `RING_MANIFEST`, which `tests/manifest.rs` checks.
mesh_stage_registry::register_stages! {
    functions: [
        dev_functions::basket,
        dev_functions::core_ops,
    ],
    stages: [
        dev_stages::conflation,
    ],
}
