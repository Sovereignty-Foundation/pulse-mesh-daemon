// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An attached hub learns that its writer was killed and replaced.
//!
//! The test runs twice. As the writer, a child process, it owns a hub,
//! publishes three pulses, says so and waits to be killed. As the reader,
//! the parent attaches to that hub, reads the three pulses and kills the
//! writer with SIGKILL, so no destructor runs: the ring stays named and
//! unmarked, and only the owner lock goes with the process. A restarted
//! writer then takes the name and publishes eight pulses into a new ring.
//! The reader, still mapped to the old ring, is told the ring was
//! superseded, and after reopening it receives the eight pulses, and the
//! envelopes the restarted writer broadcasts from its store, never the
//! killed writer's store. The variable `MESH_HUB_RUNTIME_WRITER_HUB`
//! carries the hub's name to the child and selects the writer's role.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use mesh_broadcast::ListenFilter;
use mesh_hub_runtime::{HubConfig, PulseHub, ValidationMode};
use pulse_canon::{Instruction, NodeId, Pulse, PulseEnvelope};

/// Names the hub in the writer's environment; its presence makes the test
/// run as the writer.
const WRITER_HUB: &str = "MESH_HUB_RUNTIME_WRITER_HUB";
/// This test, which the writer runs alone.
const TEST: &str = "an_attached_hub_is_told_when_a_killed_writer_is_replaced";
/// What the writer prints once its pulses are in the ring.
const PUBLISHED: &str = "writer: published";

fn config() -> HubConfig {
    HubConfig::default()
        .with_ring_size(16)
        .with_validation(ValidationMode::Passthrough)
        .with_store_slots(4)
}

/// The restarted writer's config: a store of another size than the killed
/// writer's, so the reader's store size says whose store it holds.
fn restarted_config() -> HubConfig {
    config().with_store_slots(8)
}

/// A Data pulse carrying `step` in its chain step.
fn marked(step: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.chain_step = step;
    pulse
}

#[test]
fn an_attached_hub_is_told_when_a_killed_writer_is_replaced() {
    match std::env::var(WRITER_HUB) {
        Ok(hub) => writer(&hub),
        Err(_) => reader(),
    }
}

fn writer(hub: &str) {
    let mut hub = PulseHub::create_fresh(hub, config()).expect("the first writer owns the hub");
    for step in 0..3 {
        hub.publish(&marked(step)).unwrap();
    }
    hub.broadcast_envelope(
        PulseEnvelope::typed("app/killed", vec![1]),
        &NodeId::from_name("w"),
    )
    .unwrap();
    let mut out = std::io::stdout().lock();
    writeln!(out, "{PUBLISHED}").unwrap();
    out.flush().unwrap();
    drop(out);
    // Killed here; never returns.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn reader() {
    // At most fifteen characters, and unique to this process.
    let hub = format!("wr{:08x}", std::process::id());
    let mut child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", TEST, "--nocapture"])
        .env(WRITER_HUB, &hub)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the writer");
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(line) if line.contains(PUBLISHED) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = child.kill();
                panic!("the writer never published: {e}");
            }
        }
    }

    let mut reader = PulseHub::open(&hub, config()).expect("attach to the writer's hub");
    assert_eq!(reader.store_slots(), Some(4), "the killed writer's store");
    let steps = Arc::new(Mutex::new(Vec::new()));
    let sink = steps.clone();
    reader.subscribe(move |event| sink.lock().unwrap().push(event.chain_step));
    let envelopes = Arc::new(Mutex::new(Vec::new()));
    let sink = envelopes.clone();
    reader.listen(NodeId::from_name("r"), ListenFilter::All, move |envelope| {
        sink.lock().unwrap().push(envelope.effective_type_name())
    });
    assert_eq!(reader.poll(), 4, "three pulses and an envelope's signal");
    assert_eq!(*envelopes.lock().unwrap(), ["app/killed"]);
    assert_eq!(steps.lock().unwrap().pop(), Some(0), "the signal");

    // SIGKILL: no destructor runs, so nothing marks or unlinks the ring.
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(reader.poll(), 0);
    assert!(
        !reader.ring_superseded(),
        "a killed writer leaves its ring unmarked"
    );

    // The restarted writer reclaims the name and publishes eight pulses.
    let mut restarted = PulseHub::create_fresh(&hub, restarted_config())
        .expect("the restarted writer owns the hub");
    for step in 3..11 {
        restarted.publish(&marked(step)).unwrap();
    }
    assert_eq!(reader.poll(), 0, "the old ring holds none of them");
    assert!(reader.ring_superseded(), "the reader is told");
    assert_eq!(reader.lost_pulses(), 0);
    assert!(reader.reopen().expect("the new ring is named"));
    assert_eq!(
        reader.store_slots(),
        Some(8),
        "the restarted writer's store, not the killed one's"
    );
    assert_eq!(reader.poll(), 8);
    assert_eq!(*steps.lock().unwrap(), (0..11).collect::<Vec<u64>>());
    assert_eq!(reader.lost_pulses(), 0);
    restarted
        .broadcast_envelope(
            PulseEnvelope::typed("app/restarted", vec![2]),
            &NodeId::from_name("w"),
        )
        .unwrap();
    assert_eq!(reader.poll(), 1);
    assert_eq!(*envelopes.lock().unwrap(), ["app/killed", "app/restarted"]);
    assert_eq!(reader.unfetched_envelopes(), 0);
}
