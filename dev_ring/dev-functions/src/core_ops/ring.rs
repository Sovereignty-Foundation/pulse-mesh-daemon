// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Read-only inspection of a shared-memory [`core_ring::PulseRing`], behind
//! `pms ring inspect`: it never moves the ring's cursor.

use core_ring::{PulseRing, RingError};
use serde::Serialize;

/// Per-slot summary of a recent pulse in the ring.
#[derive(Debug, Clone, Serialize)]
pub struct SlotPreview {
    /// Logical slot index (wrap around capacity).
    pub slot: u64,
    /// Instruction opcode at that slot, as a human-readable string.
    pub instruction: String,
    /// `monotonic_nanos` field from the pulse.
    pub monotonic_nanos: u64,
    /// Whether the pulse references a non-zero envelope id.
    pub has_envelope: bool,
}

/// Aggregate ring inspection result.
#[derive(Debug, Clone, Serialize)]
pub struct RingPeek {
    /// SHM name (POSIX shm_open name, including leading `/`).
    pub name: String,
    /// Slot capacity, as the ring's header records it.
    pub capacity: u64,
    /// Current writer cursor position (next slot to publish into).
    pub cursor_position: u64,
    /// Total writes since this ring was created.
    pub write_count: u64,
    /// Up to `count` most-recent slot previews.
    pub recent: Vec<SlotPreview>,
}

/// Map a ring argument to the shared-memory name to open: a hub name such as
/// `default_hub` becomes the daemon's ring for that hub
/// ([`mesh_hub_runtime::hub_shm_names`]), and a name with a leading `/` is
/// used as given.
///
/// # Errors
///
/// [`RingError::InvalidName`] or [`RingError::NameTooLong`] when a hub
/// name is not valid.
pub fn resolve_ring_name(name: &str) -> Result<String, RingError> {
    if name.starts_with('/') {
        return Ok(name.to_string());
    }
    Ok(mesh_hub_runtime::hub_shm_names(name)?.ring)
}

/// Snapshot the ring at the shared-memory `name` (see [`resolve_ring_name`]):
/// its header, then up to `count` of its most recent slots, oldest first. The
/// ring's size comes from its header.
///
/// # Errors
///
/// Propagates [`RingError`] when the ring cannot be opened or mapped, or
/// its header does not describe a ring of this layout.
pub fn ring_peek(name: &str, count: usize) -> Result<RingPeek, RingError> {
    let ring = PulseRing::open_existing(name)?;
    let cursor = ring.cursor_position();
    let writes = ring.write_count();
    let cap = ring.capacity();

    let mut recent = Vec::with_capacity(count);
    let lookback = (writes.min(count as u64)).min(cap);
    for i in 0..lookback {
        let slot = cursor.saturating_sub(lookback - i);
        if let Some(pulse) = ring.read_slot(slot) {
            recent.push(SlotPreview {
                slot,
                instruction: pulse.instruction_code().to_string(),
                monotonic_nanos: pulse.monotonic_nanos,
                has_envelope: pulse.has_envelope(),
            });
        }
    }

    Ok(RingPeek {
        name: name.to_string(),
        capacity: cap,
        cursor_position: cursor,
        write_count: writes,
        recent,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pulse_canon::{Instruction, Pulse};

    #[test]
    fn hub_names_resolve_to_the_daemon_ring() {
        assert_eq!(
            resolve_ring_name("default_hub").unwrap(),
            "/pms-default_hub"
        );
        assert_eq!(resolve_ring_name("/raw-name").unwrap(), "/raw-name");
        assert!(resolve_ring_name("bad name").is_err());
    }

    #[test]
    fn ring_peek_reads_recent_pulses() {
        let name = format!("/pms-core-ops-ring-test-{}", std::process::id());
        let capacity = 16u64;
        let mut ring = PulseRing::create_or_open(&name, capacity).expect("create ring");
        for i in 0..5u32 {
            let mut p = Pulse::zeroed();
            p.instruction = Instruction::Data as u16;
            p.monotonic_nanos = 1000 + u64::from(i);
            p.scope = i;
            ring.publish(&p);
        }
        // No capacity is passed: 16 is neither the daemon's ring size nor
        // any default, so the peek can only have read it from the header.
        let peek = ring_peek(&name, 8).expect("peek ok");
        assert_eq!(peek.capacity, capacity);
        assert_eq!(peek.write_count, 5);
        assert_eq!(peek.cursor_position, 5);
        assert_eq!(peek.recent.len(), 5);
        for (i, r) in peek.recent.iter().enumerate() {
            assert_eq!(r.instruction, "DATA");
            assert_eq!(r.monotonic_nanos, 1000 + i as u64);
        }
    }
}
