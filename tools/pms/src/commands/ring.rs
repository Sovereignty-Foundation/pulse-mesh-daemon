// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms ring inspect` — read-only SHM-ring snapshot.

use std::process::ExitCode;

use anyhow::Context;

/// Implementation of `pms ring inspect`. `name` is a hub name or a raw
/// SHM name; see `dev_hub::functions::core_ops::ring::resolve_ring_name`. The
/// ring's capacity comes from its header, so none is asked for.
///
/// # Errors
/// Propagates [`core_ring::RingError`] via anyhow if the name is not a
/// valid hub name, if `shm_open` or `mmap` fails (typically the ring
/// doesn't exist), or if the object's header does not describe a ring.
pub(crate) fn run_inspect(name: &str, count: usize, json: bool) -> anyhow::Result<ExitCode> {
    let shm_name = dev_hub::functions::core_ops::ring::resolve_ring_name(name)
        .with_context(|| format!("{name} is not a hub name or a raw SHM name"))?;
    let peek = dev_hub::functions::core_ops::ring::ring_peek(&shm_name, count)
        .with_context(|| format!("failed to open SHM ring {shm_name}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&peek)?);
    } else {
        println!("ring          {}", peek.name);
        println!("capacity      {} slots", peek.capacity);
        println!("write_count   {}", peek.write_count);
        println!("cursor        {}", peek.cursor_position);
        if peek.recent.is_empty() {
            println!("recent        (ring is empty)");
        } else {
            println!("recent        {} pulse(s):", peek.recent.len());
            for r in &peek.recent {
                println!(
                    "  slot={:>6}  inst={:<10}  mono_ns={:>20}  has_envelope={}",
                    r.slot, r.instruction, r.monotonic_nanos, r.has_envelope
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
