// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A `send` payload is padded standard base64 or it is refused: the daemon
//! answers `bad_request` saying what is wrong and where, publishes nothing,
//! and keeps the connection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, start_small, Upp};
use mesh_hub::embed::Bind;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn a_payload_that_is_not_strict_base64_is_refused_and_not_published() {
    let path = socket_path("strict");
    let mesh = start_small(&hub_name("strict"), &[Bind::Uds(path.clone())]).expect("daemon");

    let mut subscriber = Upp::connect(&path);
    subscriber.attach("reader");
    subscriber.send(r#"{"op":"subscribe","id":"sub","filter":{"channel":"strict"}}"#);
    assert_eq!(subscriber.recv_json(TIMEOUT)["op"], "ack");

    let mut writer = Upp::connect(&path);
    writer.attach("writer");
    for (payload, says) in [
        // Padding in mid-string: two texts run together, "hi" and "hi".
        ("aGk=aGk=", "offset 3"),
        // No padding.
        ("aGVsbG8", "length 7"),
        // The URL-safe alphabet.
        ("aGVsbG8-", "0x2d"),
        // A line break inside the text (JSON escapes, so CR LF on the wire).
        (r"aG\r\nbG8=", "whitespace"),
        // "Zg==" with a bit set after its last byte.
        ("Zh==", "offset 1"),
    ] {
        writer.send(&format!(
            r#"{{"op":"send","id":"bad","channel":"strict","payload":"{payload}"}}"#
        ));
        let reply = writer.recv_json(TIMEOUT);
        assert_eq!(reply["op"], "error", "{payload}: {reply}");
        assert_eq!(reply["code"], "bad_request", "{payload}: {reply}");
        let message = reply["message"].as_str().unwrap();
        assert!(
            message.starts_with("payload was not valid base64: ") && message.contains(says),
            "{payload}: {reply}"
        );
    }

    writer.send(r#"{"op":"send","id":"good","channel":"strict","payload":"aGVsbG8="}"#);
    let ack = writer.recv_json(TIMEOUT);
    assert_eq!(
        ack["op"], "ack",
        "the connection outlives the refusals: {ack}"
    );
    let event = subscriber.recv_json(TIMEOUT);
    assert_eq!(
        event["envelope_id"], ack["envelope_id"],
        "the first event is the good send's: {event}"
    );
    assert_eq!(event["payload"], "aGVsbG8=");
    assert!(
        subscriber.frame(Duration::from_millis(200)).is_none(),
        "nothing else was published"
    );
    mesh.shutdown();
}

/// A send's acknowledged envelope id is the content id of spec section 3.2,
/// which hashes the send's numeric type with its routing name and payload: a
/// `type_id` changes it, and the event carries the same id and type. (The
/// fuzz model of the protocol once hashed every send as type 0; this pins the
/// daemon's side.)
#[test]
fn a_sends_envelope_id_hashes_its_type_id_name_and_payload() {
    use pulse_canon::PulseEnvelope;
    let path = socket_path("typeid");
    let mesh = start_small(&hub_name("typeid"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut subscriber = Upp::connect(&path);
    subscriber.attach("reader");
    subscriber.send(r#"{"op":"subscribe","id":"sub","filter":{"channel":"typed"}}"#);
    assert_eq!(subscriber.recv_json(TIMEOUT)["op"], "ack");
    let mut writer = Upp::connect(&path);
    writer.attach("writer");

    let id_of = |type_id: u16, name: &str| -> String {
        PulseEnvelope::with_content(type_id, Some(name.to_string()), b"hello".to_vec())
            .id()
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    for (type_id, type_name, routing) in [
        (0u16, None, "typed"),
        (7, None, "typed"),
        (7, Some("orders/fill"), "orders/fill"),
        (65535, Some("orders/fill"), "orders/fill"),
    ] {
        let name_field = type_name
            .map(|n| format!(r#","type_name":"{n}""#))
            .unwrap_or_default();
        writer.send(&format!(
            r#"{{"op":"send","id":"s","channel":"typed","type_id":{type_id}{name_field},"payload":"aGVsbG8="}}"#
        ));
        let ack = writer.recv_json(TIMEOUT);
        assert_eq!(ack["op"], "ack", "{ack}");
        assert_eq!(
            ack["envelope_id"].as_str(),
            Some(id_of(type_id, routing).as_str()),
            "type {type_id}, name {type_name:?}"
        );
        let event = subscriber.recv_json(TIMEOUT);
        assert_eq!(event["envelope_id"], ack["envelope_id"]);
        assert_eq!(event["type_id"], type_id);
    }
    assert_ne!(id_of(0, "typed"), id_of(7, "typed"));
    mesh.shutdown();
}

/// An attach name that ends as a node id does is refused, so no client can
/// pass for another node, here or on a linked daemon; the connection stays
/// open and a plain name then attaches.
#[test]
fn an_attach_name_that_mimics_a_node_id_is_refused() {
    let path = socket_path("mimic");
    let mesh = start_small(&hub_name("mimic"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut client = Upp::connect(&path);
    for name in [
        "x@0123456789abcdef0123456789abcdef",
        "x@0123456789abcdef",
        "x@0123abcd",
    ] {
        client.send(&format!(
            r#"{{"op":"attach","id":"a","name":"{name}","protocol_version":"v0"}}"#
        ));
        let reply = client.recv_json(TIMEOUT);
        assert_eq!(reply["code"], "bad_request", "{name}: {reply}");
    }
    client.attach("x");
    mesh.shutdown();
}
