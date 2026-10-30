// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A send whose envelope the hub's store cannot keep is reported, not
//! swallowed: the ack says `persisted: false`, the hub counts the refusal,
//! and the subscribers still receive the envelope. A send the store keeps
//! acks `persisted: true`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, start_small, Upp};
use mesh_hub::embed::Bind;
use mesh_hub::ConnectionPolicy;
use std::time::Duration;

/// The envelope store's entry limit (`core_store::MAX_ENTRY_SIZE`, 64 KiB):
/// an envelope whose canonical encoding is larger cannot be stored.
const STORE_ENTRY_LIMIT: usize = 64 * 1024;

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn a_send_the_store_refuses_is_acked_unpersisted_counted_and_delivered() {
    let path = socket_path("persist");
    let mesh = start_small(&hub_name("persist"), &[Bind::Uds(path.clone())]).expect("daemon");

    let mut subscriber = Upp::connect(&path);
    subscriber.attach("reader");
    subscriber.send(r#"{"op":"subscribe","id":"sub","filter":{"channel":"persist"}}"#);
    assert_eq!(subscriber.recv_json(TIMEOUT)["op"], "ack");

    let mut publisher = Upp::connect(&path);
    publisher.attach("writer");

    // An envelope the store keeps.
    publisher.send(r#"{"op":"send","id":"small","channel":"persist","payload":"aGVsbG8="}"#);
    let kept = publisher.recv_json(TIMEOUT);
    assert_eq!(kept["op"], "ack", "{kept}");
    assert_eq!(kept["persisted"], true, "{kept}");
    assert_eq!(mesh.store_failures(), 0);

    // An envelope whose payload alone is larger than a store entry, so its
    // canonical encoding cannot fit one, in a frame within the daemon's cap.
    let payload = "AAAA".repeat(STORE_ENTRY_LIMIT / 3 + 1);
    let frame = format!(r#"{{"op":"send","id":"big","channel":"persist","payload":"{payload}"}}"#);
    assert!(frame.len() < ConnectionPolicy::default().max_message_bytes);
    publisher.send(&frame);
    let refused = publisher.recv_json(TIMEOUT);
    assert_eq!(
        refused["op"], "ack",
        "a refusal by the store does not fail the send: {refused}"
    );
    assert_eq!(refused["persisted"], false, "{refused}");
    assert_eq!(mesh.store_failures(), 1, "the refusal is counted");

    // Both reached the subscriber, persisted or not.
    for ack in [&kept, &refused] {
        let event = subscriber.recv_json(TIMEOUT);
        assert_eq!(event["op"], "event");
        assert_eq!(event["envelope_id"], ack["envelope_id"]);
    }
    mesh.shutdown();
}
