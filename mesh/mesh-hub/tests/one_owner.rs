// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A second mesh can never harm the first.
//!
//! A hub name and a socket path each have one owner at a time. A second
//! embedded mesh for a live hub is refused before it touches the first one's
//! shared memory or socket, and so is one asked to answer on a live daemon's
//! socket, even when a connect to that socket is refused (as a live listener
//! with a full backlog refuses on macOS), or one asked to answer on a live
//! mesh's socket after its lock files were removed: the socket is claimed
//! before the hub. Once the first has stopped, the next one starts. A mesh
//! whose hub name another owner takes all the same (displaced) says so and
//! stops serving. `tests/one_daemon.rs` does the same with the daemon
//! binary, `kill -9` included; it is a test binary of its own because it
//! starts processes, and a process started while a test here holds a
//! listener open would hold that listener open too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, start_small, Recv, Upp};
use mesh_hub::embed::{Bind, EmbedError, HubConfig};
use mesh_hub_runtime::owner::{hub_lock_path, socket_lock_path, OwnerLock};
use mesh_hub_runtime::PulseHub;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Send one envelope through the daemon at `socket` and return its ack.
fn send_one(socket: &Path, payload_b64: &str) -> serde_json::Value {
    let mut client = Upp::connect(socket);
    client.attach("writer");
    client.send(&format!(
        r#"{{"op":"send","id":"one","channel":"owner","payload":"{payload_b64}"}}"#
    ));
    let ack = client.recv_json(TIMEOUT);
    assert_eq!(ack["op"], "ack", "{ack}");
    ack
}

/// The inode of the file at `path`.
fn inode(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).unwrap().ino()
}

#[test]
fn a_second_mesh_for_a_live_hub_is_refused_and_the_first_keeps_serving() {
    let hub = hub_name("own-emb");
    let (first_path, second_path) = (socket_path("own-emb-a"), socket_path("own-emb-b"));
    let first = start_small(&hub, &[Bind::Uds(first_path.clone())]).expect("the first starts");
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("attach by name");

    match start_small(&hub, &[Bind::Uds(second_path.clone())]) {
        Err(EmbedError::Hub(reason)) => {
            assert!(reason.contains("already has an owner"), "{reason}");
            assert!(
                reason.contains(&format!("process {}", std::process::id())),
                "{reason}"
            );
        }
        Err(other) => panic!("expected the hub refused, got {other}"),
        Ok(_) => panic!("a second mesh for a live hub must be refused"),
    }
    assert!(!second_path.exists(), "the refused mesh bound nothing");

    // The first mesh's socket, ring and store are the ones it made, and
    // they serve: an envelope sent through its socket is stored, signalled
    // and fetched by the hub attached before the refusal.
    assert_eq!(
        send_one(&first_path, "b25l")["persisted"],
        true,
        "stored in the first mesh's store"
    );
    assert_eq!(attached.poll(), 1);
    assert_eq!(attached.unfetched_envelopes(), 0);
    assert_eq!(attached.store_slots(), first.store_slots());
    first.shutdown();
}

#[test]
fn a_second_mesh_on_a_live_socket_stops_before_its_hub_even_with_the_lock_files_gone() {
    let hub = hub_name("own-gone");
    let path = socket_path("own-gone");
    let first = start_small(&hub, &[Bind::Uds(path.clone())]).expect("the first starts");
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("attach by name");
    // Something removes both lock files from under the live mesh (a
    // cleaner of /tmp, say): until the mesh puts them back, neither turns a
    // second owner away.
    std::fs::remove_file(hub_lock_path(&hub).unwrap()).unwrap();
    std::fs::remove_file(socket_lock_path(&path)).unwrap();

    match start_small(&hub, &[Bind::Uds(path.clone())]) {
        Err(EmbedError::Bind(_, e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "{e}");
            assert!(e.to_string().contains("is live at"), "{e}");
        }
        Err(other) => panic!("expected the socket refused, got {other}"),
        Ok(_) => panic!("a second mesh on a live socket must be refused"),
    }
    // It stopped at the socket, before its hub could replace the first
    // one's ring and store.
    assert_eq!(attached.poll(), 0);
    assert!(
        !attached.ring_superseded(),
        "nobody replaced the first ring"
    );
    assert_eq!(send_one(&path, "Z29uZQ==")["persisted"], true);
    assert_eq!(attached.poll(), 1);
    assert_eq!(attached.unfetched_envelopes(), 0);
    first.shutdown();
}

#[test]
fn a_socket_whose_lock_is_held_is_never_replaced() {
    let path = socket_path("own-held");
    let hub = hub_name("own-held");
    // A live daemon's socket as a starting one finds it on macOS when the
    // live listener's backlog is full: its lock held, and every connect
    // refused. A listener that has closed refuses connects on every
    // platform, so it stands in for the full backlog.
    let lock = OwnerLock::acquire(&socket_lock_path(&path)).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(UnixStream::connect(&path).is_err(), "connects are refused");
    let before = inode(&path);
    match start_small(&hub, &[Bind::Uds(path.clone())]) {
        Err(EmbedError::Bind(_, e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "{e}");
            assert!(
                e.to_string()
                    .contains(&format!("process {}", std::process::id())),
                "{e}"
            );
        }
        Err(other) => panic!("expected the socket refused, got {other}"),
        Ok(_) => panic!("a socket whose lock is held must not be replaced"),
    }
    assert_eq!(inode(&path), before, "the socket file was left alone");

    // With the lock let go, the same file is what a dead daemon leaves, and
    // the next mesh reclaims it.
    drop(lock);
    let mesh =
        start_small(&hub, &[Bind::Uds(path.clone())]).expect("the stale socket is reclaimed");
    UnixStream::connect(&path).expect("a new socket answers in its place");
    mesh.shutdown();
    assert!(!path.exists());
    assert!(!socket_lock_path(&path).exists());
}

#[test]
fn after_a_mesh_stops_a_new_one_starts_on_its_hub_and_socket() {
    let hub = hub_name("own-rst");
    let path = socket_path("own-rst");
    for round in 0..3 {
        let mesh = start_small(&hub, &[Bind::Uds(path.clone())])
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert_eq!(send_one(&path, "dHdv")["persisted"], true, "round {round}");
        mesh.shutdown();
        // Stopping leaves nothing that would turn the next one away.
        assert!(!path.exists(), "round {round}: the socket");
        assert!(!socket_lock_path(&path).exists(), "round {round}");
        assert!(!hub_lock_path(&hub).unwrap().exists(), "round {round}");
    }
}

#[test]
fn a_mesh_that_stops_leaves_a_successors_socket_alone() {
    let path = socket_path("own-succ");
    let first =
        start_small(&hub_name("own-succ"), &[Bind::Uds(path.clone())]).expect("the first starts");
    // Its socket and lock file are removed from under it, and another mesh
    // answers at the path.
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(socket_lock_path(&path)).unwrap();
    let next =
        start_small(&hub_name("own-sucn"), &[Bind::Uds(path.clone())]).expect("the next starts");
    let successors = inode(&path);

    first.shutdown();
    assert_eq!(
        inode(&path),
        successors,
        "the successor's socket is left alone"
    );
    assert!(socket_lock_path(&path).exists(), "and so is its lock");
    assert_eq!(send_one(&path, "bmV4dA==")["persisted"], true);
    next.shutdown();
    assert!(!path.exists(), "the successor removes its own");
    assert!(!socket_lock_path(&path).exists());
}

#[test]
fn a_mesh_whose_hub_is_displaced_says_so_and_stops_serving() {
    let hub = hub_name("own-dspm");
    let path = socket_path("own-dspm");
    let mesh = start_small(&hub, &[Bind::Uds(path.clone())]).expect("the mesh starts");
    let mut guest = Upp::connect(&path);
    guest.attach("guest");
    assert!(!mesh.is_displaced());

    // The displacement, as tests/one_daemon.rs does it to the daemon: the hub's
    // lock file is removed from under the live mesh, and another owner takes
    // the name, marking the mesh's ring as it replaces its shared memory.
    std::fs::remove_file(hub_lock_path(&hub).unwrap()).unwrap();
    let owner = PulseHub::create_fresh(&hub, HubConfig::default().with_store_slots(6))
        .expect("the lock file was gone");
    assert!(mesh.is_displaced(), "said at once");

    // Within its check the mesh stops serving on its own: the guest's
    // connection closes, and the socket and the lock beside it go.
    assert!(
        matches!(guest.recv(Duration::from_secs(10)), Recv::Eof),
        "the guest's connection was closed"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while path.exists() || socket_lock_path(&path).exists() {
        assert!(
            Instant::now() < deadline,
            "the displaced mesh kept its socket"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(UnixStream::connect(&path).is_err());
    assert!(mesh.is_displaced());

    // The owner that took the name keeps its lock file, its ring and its
    // store, and dropping the displaced mesh leaves them alone.
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("the new owner's ring");
    assert_eq!(attached.store_slots(), Some(6), "and its store");
    mesh.shutdown();
    assert!(
        hub_lock_path(&hub).unwrap().exists(),
        "the new owner's lock"
    );
    assert_eq!(attached.poll(), 0);
    assert!(!attached.ring_superseded(), "and its ring");
    // The socket path is free for the next mesh.
    let next =
        start_small(&hub_name("own-dspn"), &[Bind::Uds(path.clone())]).expect("the path is free");
    next.shutdown();
    drop(attached);
    drop(owner);
    assert!(!hub_lock_path(&hub).unwrap().exists());
}
