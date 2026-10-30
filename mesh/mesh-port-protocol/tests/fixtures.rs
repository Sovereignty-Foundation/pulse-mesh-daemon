// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The port protocol's golden frames: every client and server message,
//! with its optional fields present and absent, as JSON under `fixtures/`.
//!
//! The Rust types are the source. `PMS_REGENERATE_FIXTURES=1 cargo test -p
//! mesh-port-protocol --test fixtures the_fixtures_are_what_the_types_serialize`
//! rewrites the files from the lists below; otherwise the test checks that
//! the files are current, and the other tests here that every frame in them
//! round-trips through the types unchanged. The Python
//! and Node thin clients read the same files in their own tests, so the
//! three implementations are held to one set of frames.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use mesh_port_protocol::{AckFields, ClientMessage, ErrorCode, FilterSpec, ServerMessage};
use serde::Serialize;
use serde_json::{json, Value};

const ENVELOPE_ID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const ORIGIN: &str = "worker@1a2b3c4d";
const NANOS: u64 = 1_700_000_000_000_000_000;
/// The base64 of a public key, a nonce and a signature: fixed bytes, since
/// a fixture is a frame's shape, not a proof that verifies.
const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const NONCE: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";
const SIGNATURE: &str =
    "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw==";
/// A keyed attach's node id: `name@` and 32 hex digits.
const KEYED_ORIGIN: &str = "worker@0123456789abcdef0123456789abcdef";
/// A node of another daemon: `name@` and that daemon's 16 hex digits.
const QUALIFIED_ORIGIN: &str = "worker@00112233445566ff";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Every client message, each optional field present in one frame and
/// absent in another. The thin clients write the `minimal` and `named`
/// forms; the Rust client writes the `full` ones.
fn client_frames() -> Vec<(&'static str, ClientMessage)> {
    let s = |t: &str| t.to_string();
    vec![
        (
            "attach.minimal",
            ClientMessage::Attach {
                id: None,
                name: s("worker"),
                protocol_version: s("v0"),
                capabilities: vec![],
                key: None,
            },
        ),
        (
            "attach.full",
            ClientMessage::Attach {
                id: Some(s("1")),
                name: s("worker"),
                protocol_version: s("v0"),
                capabilities: vec![s("send"), s("subscribe"), s("tap")],
                key: None,
            },
        ),
        (
            "attach.with_key",
            ClientMessage::Attach {
                id: Some(s("1")),
                name: s("worker"),
                protocol_version: s("v0"),
                capabilities: vec![s("send"), s("subscribe"), s("tap")],
                key: Some(s(KEY)),
            },
        ),
        (
            "prove",
            ClientMessage::Prove {
                id: Some(s("1")),
                signature: s(SIGNATURE),
            },
        ),
        ("detach.minimal", ClientMessage::Detach { id: None }),
        ("detach.with_id", ClientMessage::Detach { id: Some(s("9")) }),
        (
            "send.minimal",
            ClientMessage::Send {
                id: None,
                channel: s("c"),
                type_id: 0,
                type_name: None,
                payload: s("aGk="),
                flags: 0,
                to: None,
            },
        ),
        (
            "send.named",
            ClientMessage::Send {
                id: Some(s("2")),
                channel: s("c"),
                type_id: 0,
                type_name: Some(s("app/hi")),
                payload: s("aGk="),
                flags: 0,
                to: None,
            },
        ),
        (
            "send.full",
            ClientMessage::Send {
                id: Some(s("3")),
                channel: s("c"),
                type_id: 7,
                type_name: Some(s("app/hi")),
                payload: s("aGk="),
                flags: 1,
                to: None,
            },
        ),
        (
            "send.to_local",
            ClientMessage::Send {
                id: Some(s("8")),
                channel: s("c"),
                type_id: 0,
                type_name: None,
                payload: s("aGk="),
                flags: 0,
                to: Some(s(ORIGIN)),
            },
        ),
        (
            "send.to_qualified",
            ClientMessage::Send {
                id: Some(s("9")),
                channel: s("c"),
                type_id: 0,
                type_name: Some(s("app/hi")),
                payload: s("aGk="),
                flags: 0,
                to: Some(s(QUALIFIED_ORIGIN)),
            },
        ),
        (
            "subscribe.empty_filter",
            ClientMessage::Subscribe {
                id: Some(s("4")),
                filter: FilterSpec::default(),
            },
        ),
        (
            "subscribe.full_filter",
            ClientMessage::Subscribe {
                id: Some(s("5")),
                filter: FilterSpec {
                    channel: Some(s("c")),
                    type_id: Some(7),
                    type_name: Some(s("app/*")),
                    origin: Some(s(ORIGIN)),
                    health: true,
                    snapshot: true,
                },
            },
        ),
        (
            "unsubscribe",
            ClientMessage::Unsubscribe {
                id: Some(s("6")),
                subscription_id: s("sub-1"),
            },
        ),
        ("health.minimal", ClientMessage::Health { state: None }),
        (
            "health.with_state",
            ClientMessage::Health {
                state: Some(s("ok")),
            },
        ),
    ]
}

/// Every server message, each optional field present in one frame and
/// absent in another.
fn server_frames() -> Vec<(&'static str, ServerMessage)> {
    let s = |t: &str| t.to_string();
    let ack = |id: &str, fields: AckFields| ServerMessage::Ack {
        id: Some(s(id)),
        fields,
    };
    vec![
        ("ack.minimal", ServerMessage::ack(None)),
        (
            "ack.attach",
            ack(
                "1",
                AckFields {
                    node_id: Some(s(ORIGIN)),
                    protocol_version: Some(s("v0")),
                    granted_capabilities: Some(vec![s("send"), s("subscribe"), s("tap")]),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "challenge",
            ServerMessage::Challenge {
                id: Some(s("1")),
                nonce: s(NONCE),
            },
        ),
        (
            "ack.attach.keyed",
            ack(
                "1",
                AckFields {
                    node_id: Some(s(KEYED_ORIGIN)),
                    protocol_version: Some(s("v0")),
                    granted_capabilities: Some(vec![s("send"), s("subscribe"), s("tap")]),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.send",
            ack(
                "2",
                AckFields {
                    envelope_id: Some(s(ENVELOPE_ID)),
                    persisted: Some(true),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.send.not_persisted",
            ack(
                "2",
                AckFields {
                    envelope_id: Some(s(ENVELOPE_ID)),
                    persisted: Some(false),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.send.no_store",
            ack(
                "2",
                AckFields {
                    envelope_id: Some(s(ENVELOPE_ID)),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.send.delivered",
            ack(
                "8",
                AckFields {
                    envelope_id: Some(s(ENVELOPE_ID)),
                    delivered: Some(true),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.send.not_delivered",
            ack(
                "8",
                AckFields {
                    envelope_id: Some(s(ENVELOPE_ID)),
                    delivered: Some(false),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.subscribe",
            ack(
                "4",
                AckFields {
                    subscription_id: Some(s("sub-1")),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.unsubscribe",
            ack(
                "6",
                AckFields {
                    events_dropped: Some(3),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "ack.with_extension",
            ack(
                "7",
                AckFields {
                    extra: [(s("lease_ms"), json!(1500))].into_iter().collect(),
                    ..AckFields::default()
                },
            ),
        ),
        (
            "error.minimal",
            ServerMessage::error(
                None,
                ErrorCode::LimitExceeded,
                "at most 256 connections (--max-connections)",
            ),
        ),
        (
            "error.with_id",
            ServerMessage::error(
                Some(s("2")),
                ErrorCode::PayloadTooLarge,
                "payload exceeds 1048576 bytes",
            ),
        ),
        (
            "error.auth_failed",
            ServerMessage::error(
                Some(s("1")),
                ErrorCode::AuthFailed,
                "the signature does not prove the key for this challenge, name and connection",
            ),
        ),
        (
            "error.unknown_destination",
            ServerMessage::error(
                Some(s("9")),
                ErrorCode::UnknownDestination,
                "no node worker@00112233445566ff is attached here or announced by a linked daemon",
            ),
        ),
        (
            "event.minimal",
            ServerMessage::Event {
                subscription_id: s("sub-1"),
                envelope_id: s(ENVELOPE_ID),
                channel: s("c"),
                type_id: 0,
                type_name: None,
                origin: s(ORIGIN),
                captured_at_unix_nanos: NANOS,
                payload: s("aGk="),
            },
        ),
        (
            "event.full",
            ServerMessage::Event {
                subscription_id: s("sub-1"),
                envelope_id: s(ENVELOPE_ID),
                channel: s("c"),
                type_id: 7,
                type_name: Some(s("app/hi")),
                origin: s(ORIGIN),
                captured_at_unix_nanos: NANOS,
                payload: s("aGk="),
            },
        ),
        (
            "health.minimal",
            ServerMessage::Health {
                node_id: s(ORIGIN),
                state: s("degraded"),
                since_unix_nanos: 0,
            },
        ),
        (
            "health.with_since",
            ServerMessage::Health {
                node_id: s(ORIGIN),
                state: s("healthy"),
                since_unix_nanos: NANOS,
            },
        ),
    ]
}

/// The fixture file's content: an array of `{"name", "frame"}` entries.
fn entries<T: Serialize>(frames: Vec<(&'static str, T)>) -> Value {
    Value::Array(
        frames
            .into_iter()
            .map(|(name, message)| json!({ "name": name, "frame": serde_json::to_value(message).unwrap() }))
            .collect(),
    )
}

fn files() -> [(&'static str, Value); 2] {
    [
        ("client.json", entries(client_frames())),
        ("server.json", entries(server_frames())),
    ]
}

fn read(file: &str) -> Value {
    let path = fixtures_dir().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; regenerate with PMS_REGENERATE_FIXTURES=1 cargo test -p mesh-port-protocol --test fixtures the_fixtures_are_what_the_types_serialize",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("a fixture file is JSON")
}

#[test]
fn the_fixtures_are_what_the_types_serialize() {
    if std::env::var_os("PMS_REGENERATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixtures_dir()).unwrap();
        for (file, value) in files() {
            let text = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
            std::fs::write(fixtures_dir().join(file), text).unwrap();
        }
        return;
    }
    for (file, want) in files() {
        assert_eq!(
            read(file),
            want,
            "fixtures/{file} is stale: regenerate with PMS_REGENERATE_FIXTURES=1 cargo test -p mesh-port-protocol --test fixtures the_fixtures_are_what_the_types_serialize"
        );
    }
}

#[test]
fn every_client_frame_round_trips_through_the_type() {
    for entry in read("client.json").as_array().unwrap() {
        let (name, frame) = (&entry["name"], &entry["frame"]);
        let message: ClientMessage =
            serde_json::from_value(frame.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(&serde_json::to_value(&message).unwrap(), frame, "{name}");
    }
}

#[test]
fn every_server_frame_round_trips_through_the_type() {
    for entry in read("server.json").as_array().unwrap() {
        let (name, frame) = (&entry["name"], &entry["frame"]);
        let message: ServerMessage =
            serde_json::from_value(frame.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(&serde_json::to_value(&message).unwrap(), frame, "{name}");
    }
}

#[test]
fn every_message_kind_has_a_fixture() {
    let ops = |file: &str| -> Vec<String> {
        let mut ops: Vec<String> = read(file)
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["frame"]["op"].as_str().unwrap().to_string())
            .collect();
        ops.sort();
        ops.dedup();
        ops
    };
    assert_eq!(
        ops("client.json"),
        [
            "attach",
            "detach",
            "health",
            "prove",
            "send",
            "subscribe",
            "unsubscribe"
        ]
    );
    assert_eq!(
        ops("server.json"),
        ["ack", "challenge", "error", "event", "health"]
    );
}

/// A name that ends as a node id ends is one the daemon refuses at attach,
/// and nothing else is.
#[test]
fn names_that_mimic_node_ids_are_recognised() {
    use mesh_port_protocol::name_mimics_node_id as mimics;
    for name in [
        "x@0123abcd",
        "x@0123456789abcdef",
        "alice@0123456789abcdef0123456789abcdef",
        "a@b@deadbeef",
    ] {
        assert!(mimics(name), "{name}");
    }
    for name in [
        "x",
        "x@",
        "worker@host",
        "x@0123abc",
        "x@0123ABCD",
        "x@0123abcde",
        "x@0123456789abcdef0",
        "deadbeef",
        "x@0123abcd-1",
    ] {
        assert!(!mimics(name), "{name}");
    }
}
