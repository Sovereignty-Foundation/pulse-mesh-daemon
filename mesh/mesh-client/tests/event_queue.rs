// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The client's event queue is bounded: a callback slower than its events
//! loses the newest ones, counted, instead of holding memory without limit;
//! a callback that keeps up loses nothing; replies still arrive while the
//! queue is full; and the events the daemon dropped reach the caller in
//! what `unsubscribe` returns.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{DevError, Endpoint, Mesh, MeshOptions, SubscriptionId};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Events a flood publishes.
const PUBLISHED: u64 = 2_000;

/// A daemon queue deeper than any flood here, so the daemon never drops and
/// every drop a test sees is the client's.
const DEEP: usize = 2 * PUBLISHED as usize;

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

/// A daemon whose per-connection event queue holds `subscriber_queue`
/// events.
fn uds_daemon(tag: &str, subscriber_queue: usize) -> (EmbeddedMesh, MeshOptions) {
    let path = sock(tag);
    let policy = ConnectionPolicy::default().with_subscriber_queue(subscriber_queue);
    let daemon = EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    (daemon, options)
}

/// The sequence number a test event carries as its payload.
fn seq(payload: &[u8]) -> u64 {
    u64::from_le_bytes(payload.try_into().expect("an eight-byte sequence number"))
}

/// A callback that sleeps 50 ms per event behind a queue of 16 while 2,000
/// events arrive: most are dropped and counted, and the rest arrive in
/// publish order.
#[test]
fn a_slow_callback_loses_events_counted_and_in_order() {
    let (_daemon, options) = uds_daemon("flood", DEEP);
    let slow = Mesh::attach_with("flood-sub", options.clone().with_event_queue(16))
        .expect("attach subscriber");
    let publisher = Mesh::attach_with("flood-pub", options).expect("attach publisher");
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&delivered);
    slow.on("flood", move |ev| {
        std::thread::sleep(Duration::from_millis(50));
        log.lock().unwrap().push(seq(&ev.payload));
    })
    .expect("subscribe");

    for i in 0..PUBLISHED {
        publisher.send("flood", &i.to_le_bytes()).expect("send");
    }

    // Once the queue has drained, every event was delivered or counted.
    let deadline = Instant::now() + Duration::from_secs(30);
    while delivered.lock().unwrap().len() as u64 + slow.events_dropped() < PUBLISHED {
        assert!(
            Instant::now() < deadline,
            "the queue did not drain: {} delivered, {} dropped",
            delivered.lock().unwrap().len(),
            slow.events_dropped()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let delivered = delivered.lock().unwrap().clone();
    let dropped = slow.events_dropped();
    assert!(dropped > 0, "a callback this slow must lose events");
    assert_eq!(
        delivered.len() as u64 + dropped,
        PUBLISHED,
        "every event was either delivered or counted"
    );
    assert!(
        delivered.windows(2).all(|pair| pair[0] < pair[1]),
        "delivered out of publish order: {delivered:?}"
    );
    slow.detach().expect("detach subscriber");
    publisher.detach().expect("detach publisher");
}

/// A callback that keeps up, at the default depth, loses nothing.
#[test]
fn a_callback_that_keeps_up_loses_nothing() {
    let (_daemon, options) = uds_daemon("keepup", DEEP);
    let sub = Mesh::attach_with("keep-sub", options.clone()).expect("attach subscriber");
    let publisher = Mesh::attach_with("keep-pub", options).expect("attach publisher");
    let (tx, rx) = mpsc::channel();
    sub.on("steady", move |ev| {
        let _ = tx.send(seq(&ev.payload));
    })
    .expect("subscribe");

    for i in 0..PUBLISHED {
        publisher.send("steady", &i.to_le_bytes()).expect("send");
    }
    for i in 0..PUBLISHED {
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("event");
        assert_eq!(got, i, "event {i} was lost or reordered");
    }
    assert_eq!(sub.events_dropped(), 0, "nothing was dropped");
    sub.detach().expect("detach subscriber");
    publisher.detach().expect("detach publisher");
}

/// With the callback held and its queue full, the same handle's calls still
/// get their replies, acknowledgements and errors alike. The queue holds
/// exactly its depth and every later event is counted.
#[test]
fn replies_arrive_while_the_event_queue_is_full() {
    const DEPTH: usize = 16;
    const FLOOD: u64 = 200;
    let (_daemon, options) = uds_daemon("full", DEEP);
    let sub = Mesh::attach_with("full-sub", options.clone().with_event_queue(DEPTH))
        .expect("attach subscriber");
    let publisher = Mesh::attach_with("full-pub", options).expect("attach publisher");

    // The callback reports each event, then holds the dispatch thread until
    // the gate opens, which dropping its sender does for good.
    let (entered_tx, entered_rx) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate = Mutex::new(gate_rx);
    let held = sub
        .on("held", move |ev| {
            let _ = entered_tx.send(seq(&ev.payload));
            let _ = gate.lock().unwrap().recv();
        })
        .expect("subscribe");

    // Event 0 occupies the callback, so the queue starts empty; events 1 to
    // DEPTH fill it and every later one is dropped.
    publisher.send("held", &0u64.to_le_bytes()).expect("send");
    let first = entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the first event reaches the callback");
    assert_eq!(first, 0);
    for i in 1..FLOOD {
        publisher.send("held", &i.to_le_bytes()).expect("send");
    }
    let expected_drops = FLOOD - 1 - DEPTH as u64;
    let deadline = Instant::now() + Duration::from_secs(10);
    while sub.events_dropped() < expected_drops {
        assert!(
            Instant::now() < deadline,
            "only {} of {expected_drops} drops were counted",
            sub.events_dropped()
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    sub.send("elsewhere", b"still answered")
        .expect("a send gets its reply");
    let extra = sub.on("other", |_| {}).expect("a subscribe gets its reply");
    assert_eq!(
        sub.unsubscribe(extra)
            .expect("an unsubscribe gets its reply"),
        0,
        "the daemon dropped nothing for a quiet subscription"
    );
    match sub.unsubscribe(SubscriptionId("no-such-subscription".into())) {
        Err(DevError::Daemon { code, .. }) => assert_eq!(code, "unknown_subscription"),
        other => panic!("the daemon's error reply must arrive too, got {other:?}"),
    }
    assert_eq!(
        sub.events_dropped(),
        expected_drops,
        "the queue held exactly its depth"
    );

    drop(gate_tx);
    for i in 1..=DEPTH as u64 {
        let got = entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a queued event");
        assert_eq!(got, i, "queued events arrive in publish order");
    }
    assert!(
        entered_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "only the queued events were delivered"
    );
    assert_eq!(
        1 + DEPTH as u64 + sub.events_dropped(),
        FLOOD,
        "every event was either delivered or counted"
    );
    assert_eq!(
        sub.unsubscribe(held).expect("unsubscribe"),
        0,
        "the client dropped those events; the daemon dropped none"
    );
    sub.detach().expect("detach subscriber");
    publisher.detach().expect("detach publisher");
}

/// The daemon's own drops reach the caller through `unsubscribe`.
///
/// The client reads promptly whatever its callbacks do, so holding a
/// callback shut makes only the client drop; the daemon drops when it
/// cannot hand events to the connection. Publishing from the subscribing
/// handle itself makes that certain: two subscriptions share the
/// connection's one-deep queue, and the daemon offers both copies of each
/// publish while that connection's task is busy handling the publish, so at
/// most one copy fits.
#[test]
fn unsubscribe_returns_the_daemons_drop_count() {
    const PUBLISHES: u64 = 20;
    let (_daemon, options) = uds_daemon("ddrop", 1);
    let mesh = Mesh::attach_with("ddrop", options).expect("attach");
    let delivered = Arc::new(AtomicU64::new(0));
    let (to_first, to_second) = (Arc::clone(&delivered), Arc::clone(&delivered));
    let first = mesh
        .on("echo", move |_| {
            to_first.fetch_add(1, Ordering::SeqCst);
        })
        .expect("subscribe");
    let second = mesh
        .on("echo", move |_| {
            to_second.fetch_add(1, Ordering::SeqCst);
        })
        .expect("subscribe");

    for i in 0..PUBLISHES {
        mesh.send("echo", &i.to_le_bytes()).expect("send");
    }
    // Let the copies that fitted arrive before the callbacks go away: the
    // count must hold still for 200 ms.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = delivered.load(Ordering::SeqCst);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let now = delivered.load(Ordering::SeqCst);
        if now == seen {
            break;
        }
        assert!(Instant::now() < deadline, "deliveries never settled");
        seen = now;
    }

    let daemon_dropped = mesh.unsubscribe(first).expect("unsubscribe")
        + mesh.unsubscribe(second).expect("unsubscribe");
    assert!(
        daemon_dropped >= PUBLISHES,
        "at least one copy of each publish was dropped by the daemon, got {daemon_dropped}"
    );
    assert_eq!(mesh.events_dropped(), 0, "the client dropped nothing");
    assert_eq!(
        delivered.load(Ordering::SeqCst) + daemon_dropped,
        2 * PUBLISHES,
        "every copy was either delivered or counted by the daemon"
    );
    mesh.detach().expect("detach");
}
