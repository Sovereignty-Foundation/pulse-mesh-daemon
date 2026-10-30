// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms hello` passes only when its envelope arrives. Against a daemon that
//! delivers it, it exits 0; against one that drops every event, as a daemon
//! whose subscriber queues may hold no bytes does, it exits 1 and says so.
//! Each run has a private daemon, which `PMS_DAEMON` names as it does for
//! any client.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;

/// A hub name unique to this process and test, at most 15 characters.
fn hub(tag: char) -> String {
    format!("ph{tag}{:x}", std::process::id())
}

/// `pms hello`, run in a temporary directory against a private daemon for
/// the hub `hub(tag)` that answers at a socket of its own under `policy`.
/// Its envelope store has sixteen slots, enough for the one envelope.
fn hello(tag: char, policy: ConnectionPolicy) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pms.sock");
    let config = HubConfig::default().with_store_slots(16);
    let daemon =
        EmbeddedMesh::start_with_config(&hub(tag), &[Bind::Uds(sock.clone())], policy, config)
            .expect("daemon");
    let out = Command::new(env!("CARGO_BIN_EXE_pms"))
        .arg("hello")
        .env("PMS_DAEMON", format!("unix://{}", sock.display()))
        .current_dir(dir.path())
        .output()
        .expect("run pms hello");
    daemon.shutdown();
    out
}

#[test]
fn hello_exits_zero_when_its_envelope_arrives() {
    let out = hello('o', ConnectionPolicy::default());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert!(
        stdout.contains("[recv] got: hello from pms"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn hello_exits_one_when_its_envelope_is_lost() {
    // A subscriber queue that may hold no bytes drops every event.
    let policy = ConnectionPolicy::default().with_subscriber_queue_bytes(0);
    let out = hello('l', policy);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("[recv] timeout"), "stdout:\n{stdout}");
    assert!(
        stderr.contains("the envelope did not arrive within 2 s"),
        "stderr:\n{stderr}"
    );
}
