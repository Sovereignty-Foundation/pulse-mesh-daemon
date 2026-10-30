// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! dev_ring: the `functions` layer, stateless primitives the stages and hub consume.
//!
//! - `basket`: the SQLite capture of published envelopes, the tier-2
//!   `mesh-basket` crate re-exported at the path its callers use.
//! - `core_ops`: the operations the `pms` command line and the MCP server
//!   share.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/rings/dev_ring.html>.
#![forbid(unsafe_code)]

pub use mesh_basket as basket;
pub mod core_ops;
