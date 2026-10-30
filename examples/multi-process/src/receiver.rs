// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Template: a receiver process subscribing to channel `jobs`.
//!
//! Pairs with `sender.rs` — see that file's docs for the run order.

#![allow(clippy::print_stdout, clippy::print_stderr)] // an example prints what it does

use mesh_client::Mesh;

fn main() {
    if let Err(e) = receive() {
        eprintln!("receiver: {e}");
        std::process::exit(1);
    }
}

fn receive() -> Result<(), Box<dyn std::error::Error>> {
    let mesh = Mesh::attach("multi-process-receiver")?;
    mesh.on("jobs", |ev| {
        let payload = String::from_utf8_lossy(&ev.payload);
        println!(
            "receiver: got '{}' (envelope {}, {} bytes)",
            payload,
            &ev.envelope_id[..ev.envelope_id.len().min(8)],
            ev.payload.len()
        );
    })?;
    println!("receiver: attached and subscribed to 'jobs' (Ctrl-C to stop)");
    // Returns only when the connection ends; a lost daemon is an error here.
    mesh.run()?;
    Ok(())
}
