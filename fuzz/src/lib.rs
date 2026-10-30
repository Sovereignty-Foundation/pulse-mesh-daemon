// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What the fuzz targets share: oracles written from the specification
//! rather than from the code under test, and fixtures that put arbitrary
//! bytes where the code under test reads them.
//!
//! - [`canonical`] reads the canonical envelope layout and computes the
//!   content id from chapter 3 of the specification
//!   (`book/src/reference/spec/03-envelope.md`), with its own parser and
//!   its own BLAKE3 preimage, so a target can judge `pulse-canon`'s codec
//!   and the envelope store's reader without asking them.
//! - [`shm`] makes POSIX shared-memory objects by hand, under names unique
//!   to the process, writes arbitrary headers and slots into them, and
//!   unlinks them when dropped, so a target can open them with the ring's
//!   and the store's own constructors.
//! - [`udp`] reads the UDP transport's data frames and parity datagrams
//!   from chapter 6 of the specification, with its own CRC32C, so a target
//!   can judge what the receiver makes of a datagram without asking it.

pub mod canonical;
pub mod shm;
pub mod udp;

use libfuzzer_sys::arbitrary::{Result, Unstructured};

/// Up to `max` bytes of input, as many as the input chooses, fewer when it
/// runs out.
///
/// # Errors
///
/// When the input cannot say how many.
pub fn take<'a>(u: &mut Unstructured<'a>, max: usize) -> Result<&'a [u8]> {
    let len = u.int_in_range(0..=max)?;
    u.bytes(len.min(u.len()))
}

/// True about once in `one_in` inputs, and false when the input has run
/// out, so that a short input takes the common path. For choices whose
/// rare side is slow, such as a header an open waits 50 ms on.
///
/// # Errors
///
/// When the input cannot say.
pub fn rarely(u: &mut Unstructured<'_>, one_in: u8) -> Result<bool> {
    let top = one_in.max(1) - 1;
    Ok(top > 0 && u.int_in_range(0..=top)? == top)
}
