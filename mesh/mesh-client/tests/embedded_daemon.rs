// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The client against an in-process daemon: attach, publish, subscribe,
//! attach over WebSocket with the subprotocol, name release on detach, the
//! send receipt, a send to one node, and a tap that asks for peer health
//! notices.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{DevError, Endpoint, Mesh, MeshOptions, TapFilter};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use std::sync::mpsc;
use std::time::Duration;

/// A hub name unique to this process and short enough for every SHM name
/// derived from it.
fn hub(tag: &str) -> String {
    format!("dh-{tag}-{:04x}", std::process::id() & 0xffff)
}

/// A socket path private to this process and test: the clock alone can
/// repeat across processes started in the same microsecond.
fn sock(tag: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("dev-hub-{tag}-{pid}-{unique}.sock"))
}

/// The daemon's hub configuration: a store of sixteen slots (about 1 MiB of
/// shared memory) is all these tests need, and the default's 16 MiB for each
/// daemon the tests start in parallel does not fit the 64 MB `/dev/shm`
/// Docker gives a container.
fn small_store() -> HubConfig {
    HubConfig::default().with_store_slots(16)
}

fn uds_daemon(tag: &str) -> (EmbeddedMesh, MeshOptions) {
    let path = sock(tag);
    let daemon = EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Uds(path.clone())],
        ConnectionPolicy::default(),
        small_store(),
    )
    .expect("daemon");
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    (daemon, options)
}

#[test]
fn attach_send_and_on_round_trip_over_uds() {
    let (_daemon, options) = uds_daemon("rt");
    let a = Mesh::attach_with("rt-a", options.clone()).expect("attach a");
    let b = Mesh::attach_with("rt-b", options).expect("attach b");
    let (tx, rx) = mpsc::channel();
    a.on("jobs", move |ev| {
        let _ = tx.send(ev.payload);
    })
    .expect("subscribe");
    let id = b.send("jobs", b"hi").expect("send");
    assert_eq!(id.len(), 32, "envelope id is 16 bytes of hex: {id}");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).expect("event"),
        b"hi"
    );
    a.detach().expect("detach a");
    b.detach().expect("detach b");
}

#[test]
fn attach_over_websocket_announces_the_subprotocol() {
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let daemon = EmbeddedMesh::start_with_config(
        &hub("ws"),
        &[Bind::Ws(any)],
        ConnectionPolicy::default(),
        small_store(),
    )
    .expect("daemon");
    let url = format!("ws://{}", daemon.ws_addr().expect("a websocket address"));
    let options = MeshOptions::default().with_endpoint(Endpoint::Ws(url));
    let mesh = Mesh::attach_with("ws-a", options).expect("attach over websocket");
    let id = mesh.send("jobs", b"over ws").expect("send");
    assert_eq!(id.len(), 32);
    mesh.detach().expect("detach");
}

#[test]
fn detach_releases_the_name() {
    let (_daemon, options) = uds_daemon("name");
    let first = Mesh::attach_with("taken", options.clone()).expect("first attach");
    first.detach().expect("detach");
    let again = Mesh::attach_with("taken", options).expect("the name is free again");
    again.detach().expect("detach again");
}

/// A callback may call back into the mesh: it runs on the dispatch thread,
/// outside every runtime, so the blocking call is legal there.
#[test]
fn a_callback_may_call_back_into_the_mesh() {
    let (_daemon, options) = uds_daemon("cb");
    let a = Mesh::attach_with("cb-a", options.clone()).expect("attach a");
    let b = Mesh::attach_with("cb-b", options).expect("attach b");
    let replier = a.clone();
    a.on("ask", move |ev| {
        replier
            .send("answer", &ev.payload)
            .expect("a callback can publish");
    })
    .expect("subscribe ask");
    let (tx, rx) = mpsc::channel();
    b.on("answer", move |ev| {
        let _ = tx.send(ev.payload);
    })
    .expect("subscribe answer");
    b.send("ask", b"42").expect("send");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).expect("answer"),
        b"42"
    );
    a.detach().expect("detach a");
    b.detach().expect("detach b");
}

/// A slow callback delays nothing but its own subscription's events.
#[test]
fn a_slow_callback_does_not_stall_rpcs() {
    let (_daemon, options) = uds_daemon("slow");
    let a = Mesh::attach_with("slow-a", options.clone()).expect("attach a");
    let b = Mesh::attach_with("slow-b", options).expect("attach b");
    a.on("slow", |_ev| std::thread::sleep(Duration::from_secs(2)))
        .expect("subscribe");
    b.send("slow", b"tick").expect("send");
    std::thread::sleep(Duration::from_millis(100));
    let started = std::time::Instant::now();
    a.send("other", b"still responsive")
        .expect("send while a callback sleeps");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the reply was not held up"
    );
    b.detach().expect("detach b");
}

/// Events reach a callback in the order they were published.
#[test]
fn events_are_delivered_in_order() {
    let (_daemon, options) = uds_daemon("order");
    let a = Mesh::attach_with("order-a", options.clone()).expect("attach a");
    let b = Mesh::attach_with("order-b", options).expect("attach b");
    let (tx, rx) = mpsc::channel();
    a.on("seq", move |ev| {
        let _ = tx.send(ev.payload);
    })
    .expect("subscribe");
    for i in 0..50u64 {
        b.send("seq", &i.to_le_bytes()).expect("send");
    }
    for i in 0..50u64 {
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("event");
        assert_eq!(got, i.to_le_bytes(), "event {i} arrived out of order");
    }
    a.detach().expect("detach a");
    b.detach().expect("detach b");
}

/// The receipt says whether the daemon's store kept the envelope: a small
/// one is kept, one larger than a store entry (64 KiB) is refused, and the
/// send succeeds either way. `send` returns the receipt's id.
#[test]
fn a_send_receipt_says_whether_the_store_kept_the_envelope() {
    let (_daemon, options) = uds_daemon("rcpt");
    let mesh = Mesh::attach_with("rcpt", options).expect("attach");
    let small = mesh
        .send_with_receipt("jobs", None, b"small")
        .expect("send small");
    assert_eq!(small.persisted, Some(true), "{small:?}");
    assert_eq!(
        mesh.send("jobs", b"small").expect("send"),
        small.envelope_id,
        "the same content, the same id"
    );
    let big = mesh
        .send_with_receipt("jobs", None, &vec![7u8; 64 * 1024 + 1])
        .expect("a store's refusal does not fail the send");
    assert_eq!(big.persisted, Some(false), "{big:?}");
    assert_eq!(big.envelope_id.len(), 32);
    mesh.detach().expect("detach");
}

/// A tap whose filter sets `health` is sent the daemon's notices of peer
/// state changes beside its events. The client logs a notice and goes on:
/// none reaches the callback, which receives the events after it as before,
/// and the connection ends cleanly.
#[test]
fn a_tap_asking_for_health_notices_keeps_its_events_and_its_clean_end() {
    let (daemon, options) = uds_daemon("hl");
    let watcher = Mesh::attach_with("hl-watch", options.clone()).expect("attach the watcher");
    let (tx, rx) = mpsc::channel();
    let filter = TapFilter {
        channel: Some("jobs".into()),
        health: true,
        ..TapFilter::default()
    };
    watcher
        .tap(filter, move |ev| {
            let _ = tx.send((ev.channel, ev.payload));
        })
        .expect("tap");
    // A peer's detach is a notice to the watcher's connection.
    let peer = Mesh::attach_with("hl-peer", options.clone()).expect("attach the peer");
    assert_eq!(daemon.nodes_healthy(), 2);
    peer.detach().expect("detach the peer");
    let sender = Mesh::attach_with("hl-send", options).expect("attach the sender");
    sender.send("jobs", b"after").expect("send");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).expect("the event"),
        ("jobs".to_string(), b"after".to_vec())
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "nothing but the event reached the callback"
    );
    assert_eq!(watcher.events_dropped(), 0);
    sender.detach().expect("detach the sender");
    watcher.detach().expect("the watcher ends cleanly");
    assert_eq!(daemon.health_notices_dropped(), 0);
}

/// A send to one node reaches that node's matching subscription alone, and
/// its receipt says whether one matched; a node the daemon does not know is
/// refused with `unknown_destination`.
#[test]
fn a_send_to_a_node_reaches_it_alone() {
    let (daemon, options) = uds_daemon("to");
    let sender = Mesh::attach_with("to-send", options.clone()).expect("attach the sender");
    let target = Mesh::attach_with("to-target", options.clone()).expect("attach the target");
    let other = Mesh::attach_with("to-other", options).expect("attach the other");
    let (tx, rx) = mpsc::channel();
    let to_target = tx.clone();
    target
        .on("dm", move |ev| {
            let _ = to_target.send(("target", ev.origin, ev.payload));
        })
        .expect("the target subscribes");
    other
        .on("dm", move |ev| {
            let _ = tx.send(("other", ev.origin, ev.payload));
        })
        .expect("the other subscribes");
    // The target's node id, as the events of its sends carry it.
    target.send("dm", b"hello").expect("the target says hello");
    let (_, target_id, _) = rx.recv_timeout(Duration::from_secs(5)).expect("hello");
    let (_, again, _) = rx.recv_timeout(Duration::from_secs(5)).expect("hello");
    assert_eq!(target_id, again);

    let receipt = sender
        .send_to(&target_id, "dm", b"for you")
        .expect("send to");
    assert_eq!(receipt.delivered, Some(true), "{receipt:?}");
    assert_eq!(receipt.persisted, None, "a send to a node is not stored");
    assert_eq!(receipt.envelope_id.len(), 32);
    let (who, origin, payload) = rx.recv_timeout(Duration::from_secs(5)).expect("the event");
    assert_eq!((who, payload.as_slice()), ("target", &b"for you"[..]));
    assert!(origin.starts_with("to-send@"), "{origin}");
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "the other subscriber got nothing"
    );

    let missed = sender
        .send_typed_to(&target_id, "elsewhere", Some("app/x"), b"unwanted")
        .expect("send to, unmatched");
    assert_eq!(missed.delivered, Some(false), "{missed:?}");
    match sender.send_to("ghost@00000000", "dm", b"lost") {
        Err(DevError::Daemon { code, message }) => {
            assert_eq!(code, "unknown_destination");
            assert!(message.contains("ghost@00000000"), "{message}");
        }
        other => panic!("expected unknown_destination, got {other:?}"),
    }
    // A send to the channel's subscribers is as it was.
    let plain = sender
        .send_with_receipt("dm", None, b"to all")
        .expect("send");
    assert_eq!(plain.delivered, None);
    let mut got: Vec<&str> = (0..2)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("the event")
                .0
        })
        .collect();
    got.sort_unstable();
    assert_eq!(got, ["other", "target"]);
    let sends = daemon.destination_sends();
    assert_eq!((sends.local, sends.unknown), (2, 1));
    for mesh in [sender, target, other] {
        mesh.detach().expect("detach");
    }
}
