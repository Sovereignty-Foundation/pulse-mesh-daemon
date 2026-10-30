// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The hub's envelope store has the size its configuration gives it: the
//! daemon's `--store-slots`, or `HubConfig::store_slots` for a mesh started
//! with `EmbeddedMesh::start_with_config`. A process attached to the hub by
//! name finds the store at that size without being told it; a hub given no
//! slots runs without a store, and its send acks carry no `persisted`; the
//! constructors that take no configuration keep the default size; and a
//! daemon asked for a store it cannot make refuses to start.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use mesh_hub_runtime::{PulseHub, DEFAULT_STORE_SLOTS};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);

/// A mesh on a private socket whose store has `store_slots` slots.
fn mesh_with_store(tag: &str, store_slots: usize) -> (EmbeddedMesh, std::path::PathBuf) {
    let path = socket_path(tag);
    let config = HubConfig::default().with_store_slots(store_slots);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name(tag),
        &[Bind::Uds(path.clone())],
        ConnectionPolicy::default(),
        config,
    )
    .expect("daemon");
    (mesh, path)
}

/// Send one small envelope on `store`, its payload `payload` (base64),
/// and return the ack. Envelopes are content-addressed, so envelopes meant
/// to be told apart carry different payloads.
fn send(client: &mut Upp, id: &str, payload: &str) -> serde_json::Value {
    client.send(&format!(
        r#"{{"op":"send","id":"{id}","channel":"store","payload":"{payload}"}}"#
    ));
    let ack = client.recv_json(TIMEOUT);
    assert_eq!(ack["op"], "ack", "{ack}");
    ack
}

#[test]
fn the_store_has_the_configured_slots_and_a_hub_attached_by_name_finds_them() {
    let (mesh, path) = mesh_with_store("st-two", 2);
    assert_eq!(mesh.store_slots(), Some(2));

    // A process attached by name, whose own config asks for the default
    // size: the store is opened at the size its header records.
    let mut attached =
        PulseHub::open(mesh.hub_name(), HubConfig::default()).expect("attach by name");
    assert_eq!(attached.store_slots(), Some(2));

    let mut client = Upp::connect(&path);
    client.attach("writer");
    // "one", "two" and "three", in base64.
    for (id, payload) in [("one", "b25l"), ("two", "dHdv"), ("three", "dGhyZWU=")] {
        assert_eq!(send(&mut client, id, payload)["persisted"], true);
    }
    // Three envelopes through two slots: every signal is polled, the two
    // newest envelopes are fetched from the store, and the oldest, which
    // the third overwrote, is counted.
    assert_eq!(attached.poll(), 3);
    assert_eq!(attached.unfetched_envelopes(), 1);
    assert_eq!(mesh.store_failures(), 0);
    mesh.shutdown();
}

#[test]
fn a_mesh_given_no_store_slots_acks_sends_without_persisted() {
    let (mesh, path) = mesh_with_store("st-none", 0);
    assert_eq!(mesh.store_slots(), None);
    let mut client = Upp::connect(&path);
    client.attach("writer");
    let ack = send(&mut client, "unkept", "aGVsbG8=");
    assert!(ack.get("persisted").is_none(), "{ack}");
    assert_eq!(mesh.store_failures(), 0, "no store refused anything");
    let attached = PulseHub::open(mesh.hub_name(), HubConfig::default()).expect("attach");
    assert_eq!(attached.store_slots(), None, "there is no store to open");
    mesh.shutdown();
}

#[test]
fn the_constructors_that_take_no_config_keep_the_default_store() {
    let path = socket_path("st-default");
    let mesh = EmbeddedMesh::start(&hub_name("st-dflt"), Bind::Uds(path)).expect("the mesh starts");
    assert_eq!(mesh.store_slots(), Some(DEFAULT_STORE_SLOTS));
    mesh.shutdown();
}

/// Run the daemon for hub `tag` on a private socket with `--store-slots
/// slots`, and return its exit status and what it logged, once it exits
/// (it must, within ten seconds), with the socket path.
fn daemon_with_store_slots(
    tag: &str,
    slots: &str,
) -> (std::process::ExitStatus, String, std::path::PathBuf) {
    let path = socket_path(tag);
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name(tag), "--store-slots", slots])
        .arg("--uds-path")
        .arg(&path)
        .arg("--no-ws")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon runs");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = daemon.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("the daemon started without the store it was asked for");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut log = String::new();
    daemon
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    daemon
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    (status, log, path)
}

#[test]
fn a_daemon_asked_for_a_store_it_cannot_make_refuses_to_start() {
    // As many slots as the store's header can count, which no shared
    // memory has room for (281 TB): the daemon tries, and refuses to run
    // without the store.
    let (status, log, path) = daemon_with_store_slots("st-bad", "4294967295");
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(
        log.contains("refusing to start: --store-slots 4294967295"),
        "the refusal names the flag: {log}"
    );
    assert!(
        log.contains("envelope store unavailable"),
        "and the store's reason is logged: {log}"
    );
    assert!(!path.exists(), "nothing was bound");
}

#[test]
fn a_store_count_the_header_cannot_hold_is_refused_as_the_flags_are_read() {
    let (status, log, path) = daemon_with_store_slots("st-cnt", "5000000000");
    assert_eq!(status.code(), Some(2), "a usage error: {log}");
    assert!(
        log.contains("--store-slots") && log.contains("0..=4294967295"),
        "the refusal names the flag and its range: {log}"
    );
    assert!(!path.exists(), "nothing was bound");
}
