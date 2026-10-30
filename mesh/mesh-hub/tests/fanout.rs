// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A subscriber that stops reading loses events, not the daemon: the queue
//! is bounded in events and in bytes, all the queues together in bytes, the
//! drops are counted, and the count comes back in the unsubscribe ack.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, small_store, socket_path, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::ConnectionPolicy;
use std::time::Duration;

/// The write timeout for tests whose subscriber reads nothing for a while:
/// past it the daemon closes the connection as unreadable, and the test's
/// later unsubscribe would meet a closed socket. Long enough that a loaded
/// machine's slow flood does not reach it; these tests are about what the
/// queues hold and count, not the write timeout.
const SLOW_READER_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

#[test]
fn slow_subscriber_sees_events_dropped_in_the_unsubscribe_ack() {
    let path = socket_path("fan-slow");
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(SLOW_READER_WRITE_TIMEOUT)
        .with_handshake_timeout(Duration::from_secs(5))
        .with_max_message_bytes(1024 * 1024)
        .with_subscriber_queue(4);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("fan-slow"),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");

    let mut slow = Upp::connect(&path);
    slow.send(r#"{"op":"attach","id":"1","name":"slow","protocol_version":"v0"}"#);
    assert_eq!(slow.recv_json(Duration::from_secs(2))["op"], "ack");
    slow.send(r#"{"op":"subscribe","id":"2","filter":{"channel":"flood"}}"#);
    let ack = slow.recv_json(Duration::from_secs(2));
    let sub = ack["subscription_id"]
        .as_str()
        .expect("subscription id")
        .to_string();

    // A publisher floods 40 events of ~64 KiB while the subscriber reads
    // nothing: the socket buffer fills, then the bounded queue, then the
    // bridge starts dropping.
    let mut publisher = Upp::connect(&path);
    publisher.send(r#"{"op":"attach","id":"1","name":"flood","protocol_version":"v0"}"#);
    assert_eq!(publisher.recv_json(Duration::from_secs(2))["op"], "ack");
    let payload = "AAAA".repeat(21_840); // base64 of 65 520 zero bytes
    let total = 40u64;
    for i in 0..total {
        publisher.send(&format!(
            r#"{{"op":"send","id":"s{i}","channel":"flood","payload":"{payload}"}}"#
        ));
        assert_eq!(
            publisher.recv_json(Duration::from_secs(5))["op"],
            "ack",
            "send {i}"
        );
    }

    // Now drain: everything the daemon managed to write, until it goes quiet.
    let mut received = 0u64;
    while let Some(frame) = slow.frame(Duration::from_millis(500)) {
        if frame.contains(r#""op":"event""#) {
            received += 1;
        }
    }
    slow.send(&format!(
        r#"{{"op":"unsubscribe","id":"9","subscription_id":"{sub}"}}"#
    ));
    let ack = slow.recv_json(Duration::from_secs(2));
    assert_eq!(ack["op"], "ack");
    let dropped = ack["events_dropped"]
        .as_u64()
        .expect("events_dropped on the ack");
    assert!(
        dropped >= 1,
        "a reader that stopped must have lost events: {ack}"
    );
    assert_eq!(
        received + dropped,
        total,
        "every event was either delivered or counted"
    );
    mesh.shutdown();
}

#[test]
fn a_slow_subscriber_is_bounded_in_bytes_and_its_drops_are_counted() {
    let path = socket_path("fan-bytes");
    let budget = 1024 * 1024;
    // Room for 1,024 events: only the bytes can run out.
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(SLOW_READER_WRITE_TIMEOUT)
        .with_subscriber_queue(1024)
        .with_subscriber_queue_bytes(budget);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("fan-bytes"),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");

    let mut slow = Upp::connect(&path);
    slow.attach("slow");
    slow.send(r#"{"op":"subscribe","id":"2","filter":{"channel":"flood"}}"#);
    let ack = slow.recv_json(Duration::from_secs(2));
    let sub = ack["subscription_id"].as_str().unwrap().to_string();

    // 64 events of about 87 KB, 5.6 MB in all, while the subscriber reads
    // nothing: a queue bounded only in events would hold every one.
    let mut publisher = Upp::connect(&path);
    publisher.attach("flood");
    let payload = "AAAA".repeat(21_840); // base64 of 65 520 zero bytes
    let total = 64u64;
    for i in 0..total {
        publisher.send(&format!(
            r#"{{"op":"send","id":"s{i}","channel":"flood","payload":"{payload}"}}"#
        ));
        assert_eq!(
            publisher.recv_json(Duration::from_secs(5))["op"],
            "ack",
            "send {i}"
        );
    }

    let (mut received, mut event_len) = (0u64, 0usize);
    while let Some(frame) = slow.frame(Duration::from_millis(500)) {
        if frame.contains(r#""op":"event""#) {
            received += 1;
            event_len = frame.len();
        }
    }
    slow.send(&format!(
        r#"{{"op":"unsubscribe","id":"9","subscription_id":"{sub}"}}"#
    ));
    let ack = slow.recv_json(Duration::from_secs(2));
    let dropped = ack["events_dropped"].as_u64().expect("events_dropped");
    assert_eq!(
        received + dropped,
        total,
        "every event delivered or counted"
    );
    // What the budget holds, and at most a few more that had already left
    // the queue for the socket's buffers when the subscriber stalled.
    let held = (budget / event_len) as u64;
    assert!(
        received <= held + 4,
        "{received} events of {event_len} bytes got through a {budget}-byte budget"
    );
    mesh.shutdown();
}

#[test]
fn stalled_subscribers_together_hold_at_most_the_daemon_wide_budget() {
    let path = socket_path("fan-total");
    // Each connection may hold 16 MiB; all of them together, 1 MiB.
    let total_budget = 1024 * 1024;
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(SLOW_READER_WRITE_TIMEOUT)
        .with_subscriber_queue(1024)
        .with_subscriber_queue_bytes(16 * 1024 * 1024)
        .with_total_queue_bytes(total_budget);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("fan-total"),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");

    // Four subscribers that stop reading, each on a connection of its own:
    // under the per-connection budget alone they would hold 4 x 5.6 MB.
    let mut stalled: Vec<(Upp, String)> = (0..4)
        .map(|i| {
            let mut client = Upp::connect(&path);
            client.attach(&format!("stalled{i}"));
            client.send(r#"{"op":"subscribe","id":"2","filter":{"channel":"flood"}}"#);
            let ack = client.recv_json(Duration::from_secs(2));
            let sub = ack["subscription_id"].as_str().unwrap().to_string();
            (client, sub)
        })
        .collect();

    // 64 events of about 87 KB each, 5.6 MB in all.
    let mut publisher = Upp::connect(&path);
    publisher.attach("flood");
    let payload = "AAAA".repeat(21_840); // base64 of 65 520 zero bytes
    let total = 64u64;
    for i in 0..total {
        publisher.send(&format!(
            r#"{{"op":"send","id":"s{i}","channel":"flood","payload":"{payload}"}}"#
        ));
        assert_eq!(
            publisher.recv_json(Duration::from_secs(5))["op"],
            "ack",
            "send {i}"
        );
    }
    let dropped_at_total = mesh.events_dropped_at_total_queue_bytes();
    assert!(dropped_at_total > 0, "the daemon-wide budget was reached");

    let (mut received_all, mut event_len, mut dropped_all) = (0u64, 0usize, 0u64);
    for (client, sub) in &mut stalled {
        let mut received = 0u64;
        while let Some(frame) = client.frame(Duration::from_millis(500)) {
            if frame.contains(r#""op":"event""#) {
                received += 1;
                event_len = frame.len();
            }
        }
        client.send(&format!(
            r#"{{"op":"unsubscribe","id":"9","subscription_id":"{sub}"}}"#
        ));
        let ack = client.recv_json(Duration::from_secs(2));
        let dropped = ack["events_dropped"].as_u64().expect("events_dropped");
        assert_eq!(
            received + dropped,
            total,
            "every event delivered or counted"
        );
        received_all += received;
        dropped_all += dropped;
    }
    // What the daemon-wide budget holds, and at most a few more for each
    // subscriber that had already left the queue for the socket's buffers.
    let held = (total_budget / event_len) as u64;
    assert!(
        received_all <= held + 4 * 4,
        "{received_all} events of {event_len} bytes got through a {total_budget}-byte budget"
    );
    assert!(
        dropped_all >= dropped_at_total,
        "each drop at the total is counted for its subscription"
    );
    assert_eq!(
        mesh.queued_event_bytes(),
        0,
        "the drained queues hold nothing"
    );
    mesh.shutdown();
}

#[test]
fn a_subscriber_that_keeps_up_gets_every_event_while_stalled_ones_hold_the_budget() {
    let path = socket_path("fan-fair");
    // Each connection may hold 1 MiB; all of them together, 4 MiB. Nothing
    // is ever closed for not reading.
    let total_budget = 4 * 1024 * 1024;
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(Duration::ZERO)
        .with_subscriber_queue(1024)
        .with_subscriber_queue_bytes(1024 * 1024)
        .with_total_queue_bytes(total_budget);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("fan-fair"),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");

    // Eight subscribers that stop reading, each on a channel of its own,
    // and twelve events of about 128 KiB for each: 12 MiB offered to a
    // budget of 4.
    let stalled_count = 8;
    let per_stalled = 12u64;
    let mut stalled: Vec<(Upp, String)> = (0..stalled_count)
        .map(|i| {
            let mut client = Upp::connect(&path);
            client.attach(&format!("stalled{i}"));
            client.send(&format!(
                r#"{{"op":"subscribe","id":"2","filter":{{"channel":"stall{i}"}}}}"#
            ));
            let ack = client.recv_json(Duration::from_secs(2));
            (client, ack["subscription_id"].as_str().unwrap().to_string())
        })
        .collect();
    let mut publisher = Upp::connect(&path);
    publisher.attach("publisher");
    let payload = "AAAA".repeat(24_576); // base64 of 73 728 zero bytes, 96 KiB
    let mut send = |channel: &str, i: u64| {
        publisher.send(&format!(
            r#"{{"op":"send","id":"s{i}","channel":"{channel}","payload":"{payload}"}}"#
        ));
        assert_eq!(
            publisher.recv_json(Duration::from_secs(5))["op"],
            "ack",
            "send {i} to {channel}"
        );
    };
    for i in 0..stalled_count {
        for k in 0..per_stalled {
            send(&format!("stall{i}"), k);
        }
    }
    assert!(
        mesh.events_dropped_at_total_queue_bytes() > 0,
        "the stalled subscribers have filled the daemon-wide budget"
    );

    // A subscriber that keeps up: taken first come, first served, the
    // budget left it nothing, and it lost every event.
    let mut reader = Upp::connect(&path);
    reader.attach("keeps-up");
    reader.send(r#"{"op":"subscribe","id":"2","filter":{"channel":"keep"}}"#);
    let ack = reader.recv_json(Duration::from_secs(2));
    let sub = ack["subscription_id"].as_str().unwrap().to_string();
    let reading = std::thread::spawn(move || {
        let mut received = 0u64;
        while let Some(frame) = reader.frame(Duration::from_secs(2)) {
            if frame.contains(r#""op":"event""#) {
                received += 1;
            }
            if received == 30 {
                break;
            }
        }
        (reader, received)
    });
    for k in 0..30 {
        send("keep", k);
        assert!(mesh.queued_event_bytes() <= total_budget);
    }
    let (mut reader, received) = reading.join().unwrap();
    reader.send(&format!(
        r#"{{"op":"unsubscribe","id":"9","subscription_id":"{sub}"}}"#
    ));
    let ack = reader.recv_json(Duration::from_secs(2));
    assert_eq!(
        (received, ack["events_dropped"].as_u64()),
        (30, Some(0)),
        "a subscriber within its share loses nothing to the budget: {ack}"
    );

    // What the stalled ones gave up to make room was counted for them:
    // each receives what it still holds once it reads, and the rest is in
    // its unsubscribe ack.
    for (client, sub) in &mut stalled {
        let mut received = 0u64;
        while let Some(frame) = client.frame(Duration::from_millis(500)) {
            if frame.contains(r#""op":"event""#) {
                received += 1;
            }
        }
        client.send(&format!(
            r#"{{"op":"unsubscribe","id":"9","subscription_id":"{sub}"}}"#
        ));
        let ack = client.recv_json(Duration::from_secs(2));
        let dropped = ack["events_dropped"].as_u64().expect("events_dropped");
        assert_eq!(
            received + dropped,
            per_stalled,
            "every event delivered or counted"
        );
    }
    assert_eq!(mesh.queued_event_bytes(), 0);
    mesh.shutdown();
}
