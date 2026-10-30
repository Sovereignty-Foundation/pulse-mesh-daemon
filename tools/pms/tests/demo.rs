// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms demo` passes only when every row it sends arrives. Against a daemon
//! that delivers them it exits 0; against one that drops every event, as a
//! daemon whose subscriber queues may hold no bytes does, it exits 1 and
//! says how many arrived. Each run has a private daemon, which `PMS_DAEMON`
//! names as it does for any client, so the demo starts no daemon of its
//! own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;

/// A hub name unique to this process and test, at most 15 characters.
fn hub(tag: char) -> String {
    format!("pd{tag}{:x}", std::process::id())
}

/// `pms demo`, run in a temporary directory against a private daemon for
/// the hub `hub(tag)` that answers at a socket of its own under `policy`.
/// Its envelope store has sixteen slots (about 1 MiB of shared memory): the
/// demo stores five small envelopes, and a container's `/dev/shm` is small.
fn demo(tag: char, policy: ConnectionPolicy) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pms.sock");
    let config = HubConfig::default().with_store_slots(16);
    let daemon =
        EmbeddedMesh::start_with_config(&hub(tag), &[Bind::Uds(sock.clone())], policy, config)
            .expect("daemon");
    let out = Command::new(env!("CARGO_BIN_EXE_pms"))
        .arg("demo")
        .env("PMS_DAEMON", format!("unix://{}", sock.display()))
        .current_dir(dir.path())
        .output()
        .expect("run pms demo");
    daemon.shutdown();
    out
}

#[test]
fn the_demo_exits_zero_when_every_row_arrives() {
    let out = demo('o', ConnectionPolicy::default());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(stdout.matches("got: row").count(), 5, "stdout:\n{stdout}");
    assert!(stderr.contains("5/5 received"), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("starting mesh-hub"),
        "the demo used the daemon PMS_DAEMON names:\n{stderr}"
    );
}

#[test]
fn the_demo_exits_one_and_says_how_many_arrived_when_rows_are_lost() {
    // A subscriber queue that may hold no bytes drops every event.
    let policy = ConnectionPolicy::default().with_subscriber_queue_bytes(0);
    let out = demo('l', policy);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("only 0 of 5 rows arrived"),
        "stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Next steps"),
        "a failed demo suggests nothing further:\n{stderr}"
    );
}
