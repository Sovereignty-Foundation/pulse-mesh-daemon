// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! dev_ring: the `core` layer, empty by design.
//!
//! The dev ring has no types that its functions and stages share. The crate
//! stays so that the four-crate shape reads the same in every ring, and it is
//! where such types land when the ring gains some. In the book:
//! <https://pulse-mesh.net/docs/daemon/architecture/rings/dev_ring.html>.
#![forbid(unsafe_code)]
#![no_std]
