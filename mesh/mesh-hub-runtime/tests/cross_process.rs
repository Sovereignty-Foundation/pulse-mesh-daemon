// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Envelopes cross processes through shared memory.
//!
//! The test runs twice. As the parent it creates a hub, starts this test
//! binary again as a child and broadcasts one envelope. As the child it
//! attaches to the parent's hub by name, listens for envelopes and polls
//! until the parent's arrives, and finds that it cannot publish into the
//! parent's ring; its exit status is the verdict. The variable
//! `MESH_HUB_RUNTIME_CHILD_HUB` carries the hub's name to the child and
//! selects the child's role.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mesh_broadcast::ListenFilter;
use mesh_hub_runtime::{HubConfig, HubError, PulseHub, ValidationMode, DEFAULT_STORE_SLOTS};
use pulse_canon::{Instruction, NodeId, Pulse, PulseEnvelope};

/// Names the parent's hub in the child's environment; its presence makes
/// the test run as the child.
const CHILD_HUB: &str = "MESH_HUB_RUNTIME_CHILD_HUB";
/// This test, which the child runs alone.
const TEST: &str = "a_child_process_receives_the_envelope_its_parent_broadcast";
/// The type name of the envelope the parent broadcasts.
const TOPIC: &str = "app/cross-process";
/// Slots in the parent's envelope store: one envelope needs no more than a
/// few, and the child is not told the number.
const STORE_SLOTS: usize = 8;

fn config() -> HubConfig {
    HubConfig::default()
        .with_ring_size(64)
        .with_validation(ValidationMode::Passthrough)
        .with_store_slots(STORE_SLOTS)
}

/// The parent's payload: its hub's name, so the child knows the envelope
/// it receives is this parent's.
fn payload(hub: &str) -> Vec<u8> {
    hub.as_bytes().to_vec()
}

#[test]
fn a_child_process_receives_the_envelope_its_parent_broadcast() {
    match std::env::var(CHILD_HUB) {
        Ok(hub) => child(&hub),
        Err(_) => parent(),
    }
}

fn parent() {
    // At most fifteen characters, and unique to this process.
    let hub_name = format!("xp{:08x}", std::process::id());
    let mut hub = PulseHub::create_fresh(&hub_name, config()).expect("the parent's hub");
    let delivered = Arc::new(AtomicU64::new(0));
    let count = delivered.clone();
    hub.listen(NodeId::from_name("parent"), ListenFilter::All, move |_| {
        count.fetch_add(1, Ordering::SeqCst);
    });

    let mut child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", TEST, "--nocapture"])
        .env(CHILD_HUB, &hub_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the child");
    let outcome = hub
        .broadcast_envelope(
            PulseEnvelope::typed(TOPIC, payload(&hub_name)),
            &NodeId::from_name("parent"),
        )
        .expect("broadcast");
    assert_eq!(
        outcome.persisted(),
        Some(true),
        "the store kept the envelope"
    );

    let status = wait_for(&mut child, Duration::from_secs(60));
    let (stdout, stderr) = output_of(&mut child);
    // A filter that matched nothing would also exit 0, so the child must
    // report that it ran this one test.
    assert!(
        status.is_some_and(|s| s.success()) && stdout.contains("1 passed"),
        "the child did not receive the envelope ({status:?})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The parent's listener had the envelope when it was broadcast; the
    // parent polling its own signal does not deliver it again, and the
    // child's refused publishes left nothing else in the ring.
    assert_eq!(hub.ring().cursor_position(), 1);
    assert_eq!(hub.poll(), 1);
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
}

fn child(hub_name: &str) {
    // Attached by name with the default store size in its config: the
    // parent's store is opened at the size its header records.
    let child_config = config().with_store_slots(DEFAULT_STORE_SLOTS);
    let mut hub =
        PulseHub::open(hub_name, child_config).expect("attach to the parent's hub by name");
    assert_eq!(hub.store_slots(), Some(STORE_SLOTS));
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    hub.listen(
        NodeId::from_name("child"),
        ListenFilter::TypeName(TOPIC.into()),
        move |envelope| sink.lock().unwrap().push(envelope.payload().to_bytes()),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while received.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "no envelope from the parent within 20 s"
        );
        hub.poll();
        std::thread::sleep(Duration::from_millis(1));
    }
    hub.poll();
    assert_eq!(
        *received.lock().unwrap(),
        vec![payload(hub_name)],
        "the parent's envelope, once"
    );
    assert_eq!(hub.unfetched_envelopes(), 0);
    assert_eq!(hub.lost_pulses(), 0);

    // The parent's hub created the ring and is its one writer.
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    assert_eq!(hub.publish(&pulse), Err(HubError::ReadOnly));
    assert!(matches!(
        hub.broadcast_envelope(
            PulseEnvelope::typed(TOPIC, vec![0]),
            &NodeId::from_name("child")
        ),
        Err(HubError::ReadOnly)
    ));
}

/// Wait up to `limit` for `child` to exit, and kill it past that. `None`
/// when it had to be killed.
fn wait_for(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// What the child wrote, for the failure message.
fn output_of(child: &mut Child) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    (stdout, stderr)
}
