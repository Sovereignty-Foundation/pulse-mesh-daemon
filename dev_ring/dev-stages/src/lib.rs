// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! dev_ring: the `stages` layer, stateful primitives with invariants on the hot path.
//!
//! - `conflation`: a symbol-keyed, last-write-wins conflation router over a
//!   `PulseRing`.
//!
//! Imports come through the hub: `dev_hub::stages::conflation`.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/rings/dev_ring.html>.
#![forbid(unsafe_code)]

pub mod conflation;
