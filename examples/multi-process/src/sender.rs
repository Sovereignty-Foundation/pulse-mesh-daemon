// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Template: a sender process publishing to channel `jobs` once per second.
//!
//! Run with the daemon already running:
//!
//!     # Terminal 1
//!     cargo run -p mesh-hub --release
//!
//!     # Terminal 2
//!     cargo run -p multi-process --bin receiver
//!
//!     # Terminal 3
//!     cargo run -p multi-process --bin sender

#![allow(clippy::print_stdout, clippy::print_stderr)] // an example prints what it does

use mesh_client::Mesh;
use std::thread;
use std::time::Duration;

fn main() {
    if let Err(e) = send_jobs() {
        eprintln!("sender: {e}");
        std::process::exit(1);
    }
}

fn send_jobs() -> Result<(), Box<dyn std::error::Error>> {
    let mesh = Mesh::attach("multi-process-sender")?;
    println!("sender: attached");
    for i in 0..10 {
        let payload = format!("job-{i}");
        let env_id = mesh.send("jobs", payload.as_bytes())?;
        println!(
            "sender: sent '{}' as envelope {}",
            payload,
            &env_id[..env_id.len().min(8)]
        );
        thread::sleep(Duration::from_millis(1000));
    }
    println!("sender: done");
    Ok(())
}
