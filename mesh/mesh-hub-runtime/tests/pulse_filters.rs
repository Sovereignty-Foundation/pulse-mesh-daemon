// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A hub that polls a Pulse naming an envelope dispatches the envelope with
//! that Pulse's instruction and scope, so a listener's `Instruction` and
//! `Scope` filters match on them; before, every dispatch passed neither, and
//! those filters never matched anything.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::EnvelopeStore;
use mesh_broadcast::ListenFilter;
use mesh_hub_runtime::{hub_shm_names, HubConfig, PulseHub};
use pulse_canon::{Instruction, NodeId, Pulse, PulseEnvelope};
use std::sync::{Arc, Mutex};

/// A hub name of at most fifteen characters, unique per test and process.
fn hub_name(tag: &str) -> String {
    format!("{tag}{:08x}", std::process::id())
}

fn config() -> HubConfig {
    HubConfig::default().with_ring_size(64).with_store_slots(8)
}

#[test]
fn a_polled_pulse_gives_its_instruction_and_scope_to_the_filters() {
    let name = hub_name("pfilt");
    let names = hub_shm_names(&name).unwrap();
    let mut writer = PulseHub::create_fresh(&name, config()).expect("the writing hub");
    let mut reader = PulseHub::open(&name, config()).expect("a second hub on the same ring");

    let heard: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    for (label, filter) in [
        ("scope 7", ListenFilter::Scope(7)),
        ("scope 8", ListenFilter::Scope(8)),
        ("data", ListenFilter::Instruction(Instruction::Data)),
        (
            "heartbeat",
            ListenFilter::Instruction(Instruction::Heartbeat),
        ),
        (
            "data in scope 7",
            ListenFilter::And(vec![
                ListenFilter::Instruction(Instruction::Data),
                ListenFilter::Scope(7),
            ]),
        ),
    ] {
        let sink = Arc::clone(&heard);
        reader.listen(NodeId::from_name("reader"), filter, move |_| {
            sink.lock().unwrap().push(label);
        });
    }

    // Another writer of the store keeps the envelope; the ring's writer
    // signals it with a Data Pulse in scope 7.
    let store = EnvelopeStore::open_existing(&names.store).unwrap();
    let envelope = PulseEnvelope::typed("filters.scoped", b"hello".to_vec());
    let cursor = store.store(&envelope).unwrap();
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.scope = 7;
    pulse.set_envelope_id(&envelope.id());
    pulse.set_store_cursor(cursor);
    writer.publish(&pulse).unwrap();

    reader.poll();
    let mut got = heard.lock().unwrap().clone();
    got.sort_unstable();
    assert_eq!(got, vec!["data", "data in scope 7", "scope 7"]);
    assert_eq!(reader.unfetched_envelopes(), 0);
}

#[test]
fn an_envelope_broadcast_by_the_hub_itself_has_no_pulse_context() {
    let name = hub_name("pnone");
    let mut hub = PulseHub::create_fresh(&name, config()).expect("a hub");
    let heard: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    for (label, filter) in [
        ("all", ListenFilter::All),
        ("scope 0", ListenFilter::Scope(0)),
        ("data", ListenFilter::Instruction(Instruction::Data)),
    ] {
        let sink = Arc::clone(&heard);
        hub.listen(NodeId::from_name("local"), filter, move |_| {
            sink.lock().unwrap().push(label);
        });
    }
    hub.broadcast_envelope(
        PulseEnvelope::typed("filters.local", b"x".to_vec()),
        &NodeId::from_name("local"),
    )
    .unwrap();
    assert_eq!(*heard.lock().unwrap(), vec!["all"]);
}
