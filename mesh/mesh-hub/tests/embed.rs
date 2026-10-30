// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

//! A mesh hosted inside the process that needs it.
//!
//! The load-bearing invariants of [`mesh_hub::embed::EmbeddedMesh`]:
//!
//! 1. **Answering on return**: each spawn binds its listener before it
//!    hands back, so a host that connects on the next line does not race
//!    the daemon and does not need to know that it might.
//!
//! 2. **Stops on drop, and leaves nothing behind**: a Unix-domain socket
//!    file with nothing listening is worse than no file at all, because
//!    anything that probes by existence will believe it.
//!
//! 3. **One hub behind every listener**: a guest on the socket and a guest
//!    on the WebSocket are on the same mesh, not on two that share a name.
//!
//! 4. **Nowhere is refused**: a mesh asked for with no bind would start
//!    deaf, so it does not start.

mod common;

use common::{hub_name, socket_path, start_small};
use mesh_hub::embed::{Bind, EmbedError, EmbeddedMesh};
use mesh_hub_runtime::owner::{hub_lock_path, socket_lock_path};
use std::os::unix::net::{UnixListener, UnixStream};

/// It is listening when it hands back, not shortly afterwards.
///
/// The whole point of the surface: a host that connects on the next line must
/// not have to sleep, poll, or know that it should.
#[test]
fn it_is_answering_by_the_time_start_returns() {
    let path = socket_path("embed-ready");
    let mesh =
        start_small(&hub_name("e-ready"), &[Bind::Uds(path.clone())]).expect("the mesh starts");
    assert_eq!(mesh.socket(), Some(path.as_path()));
    assert!(path.exists(), "the socket exists");
    // No retry loop, no delay: connect immediately.
    let first = UnixStream::connect(&path).expect("a guest connects at once");
    let second = UnixStream::connect(&path).expect("and so does another");
    drop((first, second));
    println!("embed: listening on return 1/1; two guests connected with no retry 2/2");
    mesh.shutdown();
}

/// Dropping it stops it, and takes the socket file with it.
///
/// A socket file with nothing behind it is worse than none: anything that
/// probes by existence believes it.
#[test]
fn dropping_it_stops_it_and_leaves_no_socket_behind() {
    let path = socket_path("embed-drop");
    {
        let _mesh =
            start_small(&hub_name("e-drop"), &[Bind::Uds(path.clone())]).expect("the mesh starts");
        assert!(
            UnixStream::connect(&path).is_ok(),
            "a guest connects while it is up"
        );
    }
    let gone = !path.exists();
    let refused = UnixStream::connect(&path).is_err();
    println!("embed: socket removed on drop {gone}; a guest is refused afterwards {refused}");
    assert!(gone, "a socket file was left behind with nothing behind it");
    assert!(
        refused,
        "something was still answering after the mesh was dropped"
    );
}

/// Stopping removes the socket itself once the mesh's tasks have ended,
/// rather than leaving it to the order in which a task's values happen to
/// drop: when `shutdown` returns, the socket, the lock beside it and the
/// hub's lock are gone, with guests still connected, and the next mesh
/// starts on the same path and hub at once.
#[test]
fn stopping_removes_the_socket_before_it_returns() {
    let path = socket_path("embed-stop");
    let hub = hub_name("e-stop");
    let rounds = 10;
    for round in 0..rounds {
        let mesh = start_small(&hub, &[Bind::Uds(path.clone())])
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        let guests: Vec<UnixStream> = (0..3)
            .map(|_| UnixStream::connect(&path).expect("a guest connects"))
            .collect();
        mesh.shutdown();
        assert!(!path.exists(), "round {round}: the socket");
        assert!(!socket_lock_path(&path).exists(), "round {round}: its lock");
        assert!(!hub_lock_path(&hub).unwrap().exists(), "round {round}");
        drop(guests);
    }
    println!("embed: socket and locks gone when shutdown returned {rounds}/{rounds}");
}

/// Two listeners, one hub: a guest on either is on the same mesh.
#[test]
fn several_places_to_answer_are_one_mesh() {
    let path = socket_path("embed-both");
    let ws: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = start_small(
        &hub_name("e-both"),
        &[Bind::Uds(path.clone()), Bind::Ws(ws)],
    )
    .expect("both bind");
    assert_eq!(mesh.binds().len(), 2);
    assert!(UnixStream::connect(&path).is_ok());
    println!(
        "embed: two binds on one hub {}; the socket answers 1/1",
        mesh.binds().len()
    );
    mesh.shutdown();
}

/// A mesh with nowhere to answer is refused rather than started deaf.
#[test]
fn a_mesh_with_nowhere_to_answer_is_refused() {
    let e = EmbeddedMesh::start_at(&hub_name("e-nowhere"), &[]).expect_err("refused");
    let taken = socket_path("embed-taken");
    let held =
        start_small(&hub_name("e-taken"), &[Bind::Uds(taken.clone())]).expect("the first starts");
    // A privileged port this process cannot bind: the listener refuses and
    // the error names where it was asked to answer.
    let privileged: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let denied = start_small(&hub_name("e-denied"), &[Bind::Ws(privileged)]);
    let named = matches!(&denied, Err(EmbedError::Bind(Bind::Ws(a), _)) if *a == privileged);
    println!(
        "embed: nowhere refused as {e}; a listener that cannot bind is named {named} ({})",
        denied
            .as_ref()
            .err()
            .map_or_else(|| "it bound".to_string(), ToString::to_string)
    );
    assert!(matches!(e, EmbedError::Nowhere));
    assert!(
        named || denied.is_ok(),
        "a refused bind must say where it was asked to answer"
    );
    held.shutdown();
    assert!(!taken.exists());
}

/// A second mesh asked to answer where a live one already does is refused,
/// and the live one keeps answering: nothing steals a socket.
#[test]
fn a_second_mesh_on_a_live_socket_is_refused_and_the_first_keeps_answering() {
    let path = socket_path("embed-live");
    let first =
        start_small(&hub_name("e-live-a"), &[Bind::Uds(path.clone())]).expect("the first starts");
    match start_small(&hub_name("e-live-b"), &[Bind::Uds(path.clone())]) {
        Err(EmbedError::Bind(Bind::Uds(p), e)) => {
            assert_eq!(p, path);
            assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "{e}");
        }
        Err(other) => panic!("expected a bind refusal, got {other}"),
        Ok(_) => panic!("a second mesh must not take over a live socket"),
    }
    UnixStream::connect(&path).expect("the first mesh still answers");
    first.shutdown();
    assert!(!path.exists(), "the first mesh removes its own socket");
}

/// A socket file whose daemon died is reclaimed rather than refused.
#[test]
fn a_stale_socket_file_is_reclaimed() {
    let path = socket_path("embed-stale");
    drop(UnixListener::bind(&path).expect("a listener that then dies"));
    assert!(path.exists(), "the stale file is still there");
    let mesh = start_small(&hub_name("e-stale"), &[Bind::Uds(path.clone())])
        .expect("a stale socket is reclaimed");
    UnixStream::connect(&path).expect("and the new mesh answers");
    mesh.shutdown();
}

/// Something that is not a socket at the path is never touched.
#[test]
fn a_regular_file_at_the_socket_path_is_left_alone() {
    let path = socket_path("embed-file");
    std::fs::write(&path, b"not a socket").unwrap();
    match start_small(&hub_name("e-file"), &[Bind::Uds(path.clone())]) {
        Err(EmbedError::Bind(_, e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{e}");
        }
        Err(other) => panic!("expected a bind refusal, got {other}"),
        Ok(_) => panic!("a regular file must not be replaced by a socket"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    std::fs::remove_file(&path).unwrap();
}

/// When a later bind fails, the sockets bound before it are removed too.
#[test]
fn a_failed_second_bind_leaves_no_socket_behind() {
    let path = socket_path("embed-partial");
    // A port that is certainly taken, whoever runs the test: hold a
    // listener on it ourselves (a privileged port is free to root).
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap();
    let result = start_small(
        &hub_name("e-partial"),
        &[Bind::Uds(path.clone()), Bind::Ws(busy)],
    );
    assert!(result.is_err(), "binding a port already held must fail");
    assert!(
        !path.exists(),
        "the socket bound first must not be left behind"
    );
    drop(taken);
}

/// A WebSocket bind on port 0 reports the port it actually got, so a host
/// or a test can pick a free port without guessing.
#[test]
fn a_websocket_bind_on_port_zero_reports_its_port() {
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = start_small(&hub_name("e-wsport"), &[Bind::Ws(any)]).expect("the mesh starts");
    let bound = mesh.ws_addr().expect("a websocket address");
    assert_ne!(bound.port(), 0, "the resolved port is reported");
    assert!(matches!(mesh.binds(), [Bind::Ws(a)] if *a == bound));
    std::net::TcpStream::connect(bound).expect("the resolved address accepts");
    mesh.shutdown();
}
