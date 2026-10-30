// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The event budgets count what the daemon holds for its subscribers: an event
//! being written to a subscriber that has stopped reading is held once, in the
//! queued bytes the budgets count, on either transport. A counting allocator
//! measures the heap, so this file holds one test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod heap;

use common::{hub_name, small_store, socket_path, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::protocol::WS_SUBPROTOCOL;
use mesh_hub::ConnectionPolicy;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::stream::MaybeTlsStream;
use tokio_tungstenite::tungstenite::{self, Message, WebSocket};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Heap bytes the process holds: the daemon's, and the test's own.
fn live() -> usize {
    heap::LIVE.load(Ordering::Relaxed)
}

/// A WebSocket subscriber to `channel`, which reads its acks and nothing
/// after them.
fn ws_subscriber(
    addr: std::net::SocketAddr,
    name: &str,
    channel: &str,
) -> WebSocket<MaybeTlsStream<TcpStream>> {
    let mut request = format!("ws://{addr}").into_client_request().unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    let (mut ws, _) = tungstenite::connect(request).unwrap();
    for (request, reply) in [
        (
            format!(r#"{{"op":"attach","id":"1","name":"{name}","protocol_version":"v0"}}"#),
            "node_id",
        ),
        (
            format!(r#"{{"op":"subscribe","id":"2","filter":{{"channel":"{channel}"}}}}"#),
            "subscription_id",
        ),
    ] {
        ws.send(Message::Text(request)).unwrap();
        match ws.read().unwrap() {
            Message::Text(text) => assert!(text.contains(reply), "{text}"),
            other => panic!("unexpected {other:?}"),
        }
    }
    ws
}

#[test]
fn an_event_written_to_a_stalled_subscriber_is_held_once_and_counted() {
    let path = socket_path("mem-held");
    // Nothing is closed for not reading: every stalled subscriber keeps
    // the event it is being written.
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(Duration::ZERO)
        .with_subscriber_queue_bytes(1024 * 1024)
        .with_total_queue_bytes(16 * 1024 * 1024);
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("mem-held"),
        &[Bind::Uds(path.clone()), Bind::Ws(any)],
        policy,
        small_store(),
    )
    .expect("daemon");

    // Subscribers that stop reading once subscribed, each on a channel of
    // its own, on both transports.
    let uds: Vec<Upp> = (0..24)
        .map(|i| {
            let mut client = Upp::connect(&path);
            client.attach(&format!("uds{i}"));
            client.send(&format!(
                r#"{{"op":"subscribe","id":"2","filter":{{"channel":"u{i}"}}}}"#
            ));
            assert!(client.recv_json(TIMEOUT)["subscription_id"].is_string());
            client
        })
        .collect();
    let ws: Vec<_> = (0..8)
        .map(|i| ws_subscriber(mesh.ws_addr().unwrap(), &format!("ws{i}"), &format!("w{i}")))
        .collect();
    let mut publisher = Upp::connect(&path);
    publisher.attach("publisher");
    let payload = "AAAA".repeat(87_381); // base64 of 262 143 zero bytes
    std::thread::sleep(Duration::from_millis(200));
    let before = live();

    // One event of about 350 KB for each: more than a socket's buffers
    // take, so each Unix-socket subscriber has its event part-written.
    let channels = (0..24)
        .map(|i| format!("u{i}"))
        .chain((0..8).map(|i| format!("w{i}")));
    for (i, channel) in channels.enumerate() {
        publisher.send(&format!(
            r#"{{"op":"send","id":"s{i}","channel":"{channel}","payload":"{payload}"}}"#
        ));
        assert_eq!(publisher.recv_json(TIMEOUT)["op"], "ack", "send {i}");
    }
    std::thread::sleep(Duration::from_secs(1));
    let grown = live().saturating_sub(before);
    let queued = mesh.queued_event_bytes();
    assert_eq!(
        mesh.events_dropped_at_total_queue_bytes(),
        0,
        "every event was queued"
    );
    assert!(
        queued >= 24 * payload.len(),
        "each Unix-socket subscriber holds its event: {queued} bytes queued"
    );
    // What is held besides the queued events does not grow with them.
    let slack = 1024 * 1024;
    assert!(
        grown <= queued + slack,
        "the heap grew by {grown} bytes while the budgets count {queued}"
    );
    drop((uds, ws));
    mesh.shutdown();
}
