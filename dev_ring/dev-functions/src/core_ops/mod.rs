// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The dev ring's typed operations, shared by the `pms` command line and
//! the `pms-mcp` server, both thin shells over them: the ring inspector and
//! the module table. The codec, UDP, version and bench operations are the
//! standard's and live in `pulse-cli` (`pulse_cli::ops`).

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod modules;
pub mod ring;
