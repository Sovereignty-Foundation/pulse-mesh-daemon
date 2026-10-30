// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh-port-protocol`: the Universal Port Protocol, version 0, tier 2.
//!
//! The wire types the daemon (`mesh-hub`) and its Rust client (`mesh-client`)
//! share, so the protocol is defined once. Two transports carry the same
//! messages: WebSocket text frames ([`WS_SUBPROTOCOL`], default bind
//! [`DEFAULT_WS_BIND`]) and a Unix socket ([`framing`], default path
//! [`DEFAULT_UDS_PATH`]). Every message is a JSON object whose `op` names the
//! variant, and every type both serialises and deserialises.
//!
//! - [`ClientMessage`] and [`ServerMessage`]: the messages each way.
//! - Destinations: a `send` with `to` goes to one node rather than to the
//!   subscribers of its channel; see [Destinations](#destinations).
//! - [`attach`]: key-proof attach (ADR-0018 item 6), the `key` an attach
//!   may carry, the `challenge` and `prove` that follow it, the bytes a
//!   proof signs and the node id a proven key is given.
//! - [`base64`]: the strict codec of the `payload` that `send` and `event`
//!   carry, and of the key, nonce and signature of an attach proof.
//! - [`framing`]: the Unix socket's length prefix, sans-IO.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/reference/spec/07-port-protocol.html>.
//!
//! # Destinations
//!
//! A `send` names its destination with `to`, the node id of one attached
//! client: the `node_id` its attach was acked with (`name@` and 8 hex
//! digits, or 32 for a client that proved a key), which only its own
//! daemon knows, or its qualified form across linked daemons, `name@` and
//! the 16 hex digits of the daemon it is attached to (`mesh-link`'s
//! `QualifiedOrigin`; for a client that proved a key, the name is its
//! `name@` and 32 hex digits). The daemon resolves it:
//!
//! - **A node attached to this daemon**, by either form: the envelope goes
//!   to that node's connection alone. Each subscription the connection
//!   holds whose filter matches the send, on its channel, type id, type
//!   name and origin as any send is matched, gets the event; no other
//!   subscription, of that connection or any other, does. The ack carries
//!   `delivered`: true when at least one subscription got the event, and
//!   false, which is no error, when the node holds none that matches.
//! - **A node a linked peer daemon announced**: the envelope is forwarded
//!   to that peer alone, which delivers it to its node by the same rule and
//!   forwards it no further. The ack's `delivered` is true when the
//!   envelope was handed to the link to that peer: delivery there is
//!   remote and is not confirmed, so true means forwarded. It is false when
//!   the forward could not be made (too long for a link datagram, or the
//!   link's queue full).
//! - **Any other node**: the send is refused with `unknown_destination`,
//!   whose message names the node, and nothing is delivered.
//!
//! A send with `to` is not stored in the daemon's envelope store, not
//! signalled on its hub's ring, and not forwarded by interest to any other
//! daemon, so its ack carries no `persisted`; the hub's schemas still
//! check it, as they check every send. A send without `to` is a send to the
//! channel's subscribers as before, and its ack carries no `delivered`.
//! A client that does not know `delivered` ignores it, as every client
//! ignores an ack field it does not know.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod attach;
pub mod base64;
pub mod framing;

/// The wire protocol version this daemon speaks.
pub const PROTOCOL_VERSION: &str = "v0";

/// The subprotocol clients should announce in `Sec-WebSocket-Protocol`.
pub const WS_SUBPROTOCOL: &str = "pms-universal-port-v0";

/// Default WebSocket bind address.
pub const DEFAULT_WS_BIND: &str = "127.0.0.1:9876";

/// Default Unix-domain socket path.
pub const DEFAULT_UDS_PATH: &str = "/tmp/pms.sock";

/// The longest `channel` or `type_name` a `send` may carry, in bytes; the
/// daemon refuses a longer one with `bad_request` and publishes nothing. With
/// [`MAX_PATTERN_LEN`] it bounds what matching one send costs.
pub const MAX_CHANNEL_LEN: usize = 256;

/// The longest `channel`, `type_name` or `origin` a subscribe filter may
/// carry, in bytes. The daemon refuses a longer one with `bad_request` and
/// opens no subscription.
pub const MAX_PATTERN_LEN: usize = 256;

/// The longest `name` an `attach` may carry, in bytes; the daemon refuses a
/// longer one with `bad_request`, since every event carries the name.
pub const MAX_NAME_LEN: usize = 128;

/// Whether `name` ends as a node id the daemon writes ends: an `@` followed
/// by exactly 8, 16 or 32 lowercase hexadecimal digits, the suffixes of a
/// name-derived node id, a daemon-qualified origin and a key-derived node id.
/// The daemon refuses such a name at attach with `bad_request`: without the
/// rule, a client could attach by name as `x@<32 hex>` and appear, to
/// subscribers on linked daemons, as the client that proved the key behind
/// those digits.
#[must_use]
pub fn name_mimics_node_id(name: &str) -> bool {
    name.rsplit_once('@').is_some_and(|(_, suffix)| {
        matches!(suffix.len(), 8 | 16 | 32)
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A message from a client to the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Register the connection as a named participant in the mesh.
    Attach {
        /// Echoed back on the corresponding `ack` / `error`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Process-visible name for this client, at most [`MAX_NAME_LEN`]
        /// bytes; unique among the clients attached at once.
        name: String,
        /// Always `"v0"` for this revision.
        protocol_version: String,
        /// Optional surfaces the client wants. `v0` recognizes `send`, `subscribe`, `tap`.
        #[serde(default)]
        capabilities: Vec<String>,
        /// The client's Ed25519 public key, in standard base64
        /// ([`attach::encode_key`]), when it attaches as that key: the daemon
        /// answers with a `challenge` the client must `prove`
        /// ([`attach`]). Absent for an attach by name alone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    /// Answer the `challenge` to a keyed attach ([`attach`]).
    Prove {
        /// The attach's id, which the challenge echoed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// The Ed25519 signature of [`attach::signed_bytes`], in standard
        /// base64 (64 bytes).
        signature: String,
    },
    /// Cleanly leave the mesh.
    Detach {
        /// Echoed back on the corresponding `ack` / `error`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Publish an envelope to a channel.
    Send {
        /// Echoed back on the corresponding `ack` / `error`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Routing key the envelope is published on, at most
        /// [`MAX_CHANNEL_LEN`] bytes.
        channel: String,
        /// Numeric envelope type; `0` for name-routed envelopes.
        #[serde(default)]
        type_id: u16,
        /// Human-readable envelope type, when the envelope is name-routed,
        /// at most [`MAX_CHANNEL_LEN`] bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_name: Option<String>,
        /// Base64-encoded payload bytes.
        payload: String,
        /// Envelope flags; `0` unless a later revision defines them.
        #[serde(default)]
        flags: u16,
        /// The node to deliver the envelope to, and to it alone: an
        /// attached client's node id, or its qualified form
        /// (`name@` and its daemon's 16 hex digits); see
        /// [Destinations](crate#destinations). Absent for a send to the
        /// channel's subscribers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<String>,
    },
    /// Open a server-pushed event stream matching the filter.
    Subscribe {
        /// Echoed back on the corresponding `ack` / `error`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// What the stream should carry; an empty filter matches everything.
        #[serde(default)]
        filter: FilterSpec,
    },
    /// Stop a subscription.
    Unsubscribe {
        /// Echoed back on the corresponding `ack` / `error`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// The id the subscribe `ack` returned.
        subscription_id: String,
    },
    /// Liveness signal.
    Health {
        /// Free-form client state (`"ok"`, `"degraded"`, ...); informational.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
    },
}

/// The filter a subscribe carries: its fields AND-combine, and an unset one
/// admits everything and is omitted on the wire (a default filter is `{}`).
///
/// In `channel` and `type_name`, `*` matches any run of characters other than
/// `/`, `**` any run, and every other character itself. Each string is at most
/// [`MAX_PATTERN_LEN`] bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSpec {
    /// Exact channel name, or glob (`db/*`, `**/foo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Exact type-id match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<u16>,
    /// Exact or glob type-name match; a send that names no type name is
    /// matched on its channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    /// Exact origin match: a producer's [`AckFields::node_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Include peer-state-change `health` events in this subscription's stream.
    #[serde(default, skip_serializing_if = "is_false")]
    pub health: bool,
    /// Replay matching envelopes from the basket before the live stream;
    /// reserved, and ignored by the v0 daemon.
    #[serde(default, skip_serializing_if = "is_false")]
    pub snapshot: bool,
}

/// A message from the daemon to a client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Generic success reply, echoing the request's `id` with op-specific fields.
    Ack {
        /// The request id this answers, when the request carried one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Op-specific reply fields, flattened into the same object.
        #[serde(flatten)]
        fields: AckFields,
    },
    /// Generic failure reply.
    Error {
        /// The request id this answers, when the request carried one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// One of the [`ErrorCode`] wire strings.
        code: String,
        /// Human-readable detail.
        message: String,
    },
    /// Daemon-originated envelope delivery to a subscriber.
    Event {
        /// The subscription this event belongs to.
        subscription_id: String,
        /// Content-addressed envelope id (hex).
        envelope_id: String,
        /// Routing key the envelope was published on.
        channel: String,
        /// Numeric envelope type; `0` for name-routed envelopes.
        #[serde(default)]
        type_id: u16,
        /// Human-readable envelope type, when name-routed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_name: Option<String>,
        /// The producer's node id, as its attach ack's [`AckFields::node_id`]
        /// gave it.
        origin: String,
        /// Daemon-side capture time, nanoseconds since the Unix epoch: `u64`,
        /// since serde_json does not round-trip `u128`, and good until 2554.
        captured_at_unix_nanos: u64,
        /// Base64-encoded payload bytes.
        payload: String,
    },
    /// The daemon's answer to an attach that carried a `key`, in place of
    /// the ack: the client signs `nonce` and answers with `prove`
    /// ([`attach`]).
    Challenge {
        /// The attach's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// [`attach::NONCE_LEN`] random bytes, in standard base64.
        nonce: String,
    },
    /// Peer state-change notification.
    Health {
        /// The peer whose state changed.
        node_id: String,
        /// Its new state.
        state: String,
        /// When that state was last observed, nanoseconds since the unix epoch.
        #[serde(default)]
        since_unix_nanos: u64,
    },
}

/// Op-specific fields on a successful `ack`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AckFields {
    /// Attach: the connection's node id. Attached by name, `name@` and the
    /// first four bytes of the id the daemon derives from the name, in hex;
    /// attached as a key it proved, `name@` and the 16 bytes of
    /// [`attach::key_node_id`], in hex ([`attach::keyed_node_id`]). Its events
    /// carry it as `origin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Attach: the protocol version the daemon speaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// Attach: the subset of requested capabilities the daemon granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_capabilities: Option<Vec<String>>,
    /// Send: the content-addressed id of the published envelope (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_id: Option<String>,
    /// Send: whether the daemon's envelope store kept the envelope for the
    /// processes attached to the hub by name; absent when the daemon runs
    /// without a store, and for a send with `to`. Subscribers receive the
    /// envelope either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    /// Send with `to`: for a node attached to this daemon, whether one of
    /// its subscriptions matched and got the event; for a node of a linked
    /// daemon, whether the envelope was forwarded to that daemon, delivery
    /// there being remote. Absent for a send without `to`. See
    /// [Destinations](crate#destinations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
    /// Subscribe: the id of the new subscription.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// Unsubscribe: events dropped for this subscription because its
    /// connection's queue, or the daemon's queue budget, was full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_dropped: Option<u64>,
    /// Catch-all for op-specific extensions.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ServerMessage {
    /// Convenience: build a minimal `ack` with just an id echo.
    pub fn ack(id: Option<String>) -> Self {
        ServerMessage::Ack {
            id,
            fields: AckFields::default(),
        }
    }

    /// Build a typed error reply.
    pub fn error(id: Option<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        ServerMessage::Error {
            id,
            code: code.as_str().to_string(),
            message: message.into(),
        }
    }
}

/// Canonical error codes (matches §4.9 of the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The client announced a protocol version this daemon does not speak.
    VersionUnsupported,
    /// The operation needs an attached connection.
    NotAttached,
    /// Another attached connection already holds that name.
    NameInUse,
    /// The subscribe filter could not be understood.
    BadFilter,
    /// The subscription id is unknown or belongs to another connection.
    UnknownSubscription,
    /// The payload exceeds what the daemon accepts.
    PayloadTooLarge,
    /// A limit of the daemon's connection policy was reached; the message names
    /// the limit and the flag that sets it. A Unix-socket connection past the
    /// connection cap gets it unprompted, without an id, and is closed.
    LimitExceeded,
    /// The message is not a valid request: malformed JSON, a field missing or
    /// malformed, or a string longer than its cap.
    BadRequest,
    /// The daemon failed internally; the message carries detail.
    Internal,
    /// A key-proof attach failed ([`attach`]): the proof did not verify, the
    /// key is not one the daemon allows, a `prove` came with no challenge
    /// pending or another request while one was, the challenge went
    /// unanswered past the daemon's handshake timeout, or the daemon requires
    /// a key and the attach carried none. The daemon closes the connection
    /// after it.
    AuthFailed,
    /// A `send`'s `to` names no node this daemon can deliver to: none of
    /// its own attached clients, and none a linked peer daemon announced.
    /// The message names the node; nothing was delivered.
    UnknownDestination,
}

impl ErrorCode {
    /// Wire-string for the error code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::VersionUnsupported => "version_unsupported",
            ErrorCode::NotAttached => "not_attached",
            ErrorCode::NameInUse => "name_in_use",
            ErrorCode::BadFilter => "bad_filter",
            ErrorCode::UnknownSubscription => "unknown_subscription",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::LimitExceeded => "limit_exceeded",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
            ErrorCode::AuthFailed => "auth_failed",
            ErrorCode::UnknownDestination => "unknown_destination",
        }
    }

    /// The code for a wire string, or `None` for one this build does not know,
    /// which a client keeps as text.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "version_unsupported" => ErrorCode::VersionUnsupported,
            "not_attached" => ErrorCode::NotAttached,
            "name_in_use" => ErrorCode::NameInUse,
            "bad_filter" => ErrorCode::BadFilter,
            "unknown_subscription" => ErrorCode::UnknownSubscription,
            "payload_too_large" => ErrorCode::PayloadTooLarge,
            "limit_exceeded" => ErrorCode::LimitExceeded,
            "bad_request" => ErrorCode::BadRequest,
            "internal" => ErrorCode::Internal,
            "auth_failed" => ErrorCode::AuthFailed,
            "unknown_destination" => ErrorCode::UnknownDestination,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn every_error_code_round_trips_and_an_unknown_one_stays_text() {
        for code in [
            ErrorCode::VersionUnsupported,
            ErrorCode::NotAttached,
            ErrorCode::NameInUse,
            ErrorCode::BadFilter,
            ErrorCode::UnknownSubscription,
            ErrorCode::PayloadTooLarge,
            ErrorCode::LimitExceeded,
            ErrorCode::BadRequest,
            ErrorCode::Internal,
            ErrorCode::AuthFailed,
            ErrorCode::UnknownDestination,
        ] {
            assert_eq!(ErrorCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(ErrorCode::parse("quota_exhausted"), None);
        // A code this build does not know still arrives as text.
        let frame = r#"{"op":"error","id":"7","code":"quota_exhausted","message":"later"}"#;
        match serde_json::from_str::<ServerMessage>(frame).unwrap() {
            ServerMessage::Error { code, .. } => assert_eq!(code, "quota_exhausted"),
            other => panic!("expected an error frame, got {other:?}"),
        }
    }

    #[test]
    fn parses_attach() {
        let j = r#"{"op":"attach","name":"x","protocol_version":"v0"}"#;
        let m: ClientMessage = serde_json::from_str(j).unwrap();
        match m {
            ClientMessage::Attach {
                name,
                protocol_version,
                ..
            } => {
                assert_eq!(name, "x");
                assert_eq!(protocol_version, "v0");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn a_keyed_attach_and_its_challenge_and_proof_have_their_wire_shapes() {
        let key = attach::encode_key(&[7; 32]);
        let attach = ClientMessage::Attach {
            id: Some("1".into()),
            name: "w".into(),
            protocol_version: PROTOCOL_VERSION.into(),
            capabilities: vec![],
            key: Some(key.clone()),
        };
        assert_eq!(
            serde_json::to_value(&attach).unwrap(),
            json!({"op": "attach", "id": "1", "name": "w", "protocol_version": "v0", "capabilities": [], "key": key})
        );
        // Without a key, the attach is the one the protocol always had.
        let plain: ClientMessage =
            serde_json::from_str(r#"{"op":"attach","name":"w","protocol_version":"v0"}"#).unwrap();
        assert!(matches!(plain, ClientMessage::Attach { key: None, .. }));
        assert!(!serde_json::to_string(&plain).unwrap().contains("key"));

        let challenge: ServerMessage =
            serde_json::from_str(r#"{"op":"challenge","id":"1","nonce":"AA=="}"#).unwrap();
        assert_eq!(
            challenge,
            ServerMessage::Challenge {
                id: Some("1".into()),
                nonce: "AA==".into()
            }
        );
        let prove = ClientMessage::Prove {
            id: Some("1".into()),
            signature: "AA==".into(),
        };
        assert_eq!(
            serde_json::to_value(&prove).unwrap(),
            json!({"op": "prove", "id": "1", "signature": "AA=="})
        );
        assert!(
            serde_json::from_str::<ClientMessage>(r#"{"op":"prove","id":"1"}"#).is_err(),
            "a proof without a signature is no proof"
        );
        assert_eq!(
            serde_json::to_value(ServerMessage::error(None, ErrorCode::AuthFailed, "no")).unwrap(),
            json!({"op": "error", "code": "auth_failed", "message": "no"})
        );
    }

    #[test]
    fn parses_subscribe_with_filter() {
        let j = r#"{"op":"subscribe","filter":{"channel":"db/rows","health":true}}"#;
        let m: ClientMessage = serde_json::from_str(j).unwrap();
        match m {
            ClientMessage::Subscribe { filter, .. } => {
                assert_eq!(filter.channel.as_deref(), Some("db/rows"));
                assert!(filter.health);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serializes_event() {
        let e = ServerMessage::Event {
            subscription_id: "sub-1".into(),
            envelope_id: "env-1".into(),
            channel: "test".into(),
            type_id: 0,
            type_name: None,
            origin: "node@1".into(),
            captured_at_unix_nanos: 0,
            payload: "AAA=".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"op\":\"event\""));
        assert!(s.contains("\"channel\":\"test\""));
    }

    fn keys(v: &Value) -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    #[test]
    fn client_messages_round_trip() {
        let msgs = vec![
            ClientMessage::Attach {
                id: Some("1".into()),
                name: "n".into(),
                protocol_version: PROTOCOL_VERSION.into(),
                capabilities: vec!["send".into()],
                key: None,
            },
            ClientMessage::Attach {
                id: Some("1".into()),
                name: "n".into(),
                protocol_version: PROTOCOL_VERSION.into(),
                capabilities: vec![],
                key: Some(attach::encode_key(&[7; 32])),
            },
            ClientMessage::Prove {
                id: Some("1".into()),
                signature: base64::encode(&[9; 64]),
            },
            ClientMessage::Prove {
                id: None,
                signature: String::new(),
            },
            ClientMessage::Detach { id: None },
            ClientMessage::Send {
                id: Some("2".into()),
                channel: "c".into(),
                type_id: 7,
                type_name: Some("t".into()),
                payload: "AA==".into(),
                flags: 1,
                to: None,
            },
            ClientMessage::Send {
                id: Some("2".into()),
                channel: "c".into(),
                type_id: 0,
                type_name: None,
                payload: "AA==".into(),
                flags: 0,
                to: Some("worker@0001020304050607".into()),
            },
            ClientMessage::Subscribe {
                id: Some("3".into()),
                filter: FilterSpec {
                    channel: Some("db/*".into()),
                    health: true,
                    ..Default::default()
                },
            },
            ClientMessage::Unsubscribe {
                id: None,
                subscription_id: "s".into(),
            },
            ClientMessage::Health {
                state: Some("ok".into()),
            },
        ];
        for m in msgs {
            let v = serde_json::to_value(&m).unwrap();
            let back: ClientMessage = serde_json::from_value(v).unwrap();
            assert_eq!(back, m);
        }
    }

    #[test]
    fn server_messages_round_trip() {
        let mut extra = HashMap::new();
        extra.insert("__detach".to_string(), json!(true));
        let msgs = vec![
            ServerMessage::Ack {
                id: Some("1".into()),
                fields: AckFields {
                    node_id: Some("n@1".into()),
                    granted_capabilities: Some(vec!["send".into()]),
                    extra,
                    ..Default::default()
                },
            },
            ServerMessage::ack(None),
            ServerMessage::error(Some("2".into()), ErrorCode::NameInUse, "taken"),
            ServerMessage::Event {
                subscription_id: "s".into(),
                envelope_id: "e".into(),
                channel: "c".into(),
                type_id: 0,
                type_name: None,
                origin: "o@1".into(),
                captured_at_unix_nanos: 5,
                payload: "AA==".into(),
            },
            ServerMessage::Health {
                node_id: "n@1".into(),
                state: "alive".into(),
                since_unix_nanos: 9,
            },
            ServerMessage::Challenge {
                id: Some("1".into()),
                nonce: base64::encode(&[3; 32]),
            },
            ServerMessage::Challenge {
                id: None,
                nonce: String::new(),
            },
            ServerMessage::error(Some("1".into()), ErrorCode::AuthFailed, "no"),
        ];
        for m in msgs {
            let v = serde_json::to_value(&m).unwrap();
            let back: ServerMessage = serde_json::from_value(v).unwrap();
            assert_eq!(back, m);
            if let ServerMessage::Ack { fields, .. } = &back {
                assert!(!fields.extra.contains_key("op"), "tag leaked into extra");
                assert!(!fields.extra.contains_key("id"), "id leaked into extra");
            }
        }
    }

    #[test]
    fn a_float_in_an_ack_extension_round_trips_exactly() {
        // Without serde_json's `float_roundtrip`, this parses one unit in the
        // last place off.
        let text = r#"{"op":"ack","k":-7.730584014224125e139}"#;
        let msg: ServerMessage = serde_json::from_str(text).unwrap();
        match &msg {
            ServerMessage::Ack { fields, .. } => {
                assert_eq!(fields.extra["k"], json!(-7.730584014224125e139));
            }
            other => panic!("parsed as {other:?}"),
        }
        let back: ServerMessage =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn ack_wire_shape_is_flat() {
        let mut extra = HashMap::new();
        extra.insert("k".to_string(), json!(1));
        let m = ServerMessage::Ack {
            id: Some("1".into()),
            fields: AckFields {
                node_id: Some("n@1".into()),
                extra,
                ..Default::default()
            },
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(keys(&v), vec!["id", "k", "node_id", "op"]);
    }

    #[test]
    fn send_ack_carries_persisted_only_when_the_daemon_knows_it() {
        for persisted in [Some(true), Some(false), None] {
            let m = ServerMessage::Ack {
                id: Some("3".into()),
                fields: AckFields {
                    envelope_id: Some("9c1d".into()),
                    persisted,
                    ..Default::default()
                },
            };
            let v = serde_json::to_value(&m).unwrap();
            match persisted {
                Some(p) => {
                    assert_eq!(keys(&v), vec!["envelope_id", "id", "op", "persisted"]);
                    assert_eq!(v["persisted"], json!(p));
                }
                None => assert_eq!(keys(&v), vec!["envelope_id", "id", "op"]),
            }
            let back: ServerMessage = serde_json::from_value(v).unwrap();
            assert_eq!(back, m, "persisted is a field, not an extension key");
        }
    }

    #[test]
    fn a_send_to_a_node_carries_to_and_its_ack_delivered() {
        let send: ClientMessage = serde_json::from_str(
            r#"{"op":"send","id":"1","channel":"c","payload":"AA==","to":"w@0001020304050607"}"#,
        )
        .unwrap();
        assert!(
            matches!(&send, ClientMessage::Send { to: Some(to), .. } if to == "w@0001020304050607")
        );
        let plain: ClientMessage =
            serde_json::from_str(r#"{"op":"send","channel":"c","payload":"AA=="}"#).unwrap();
        assert!(matches!(plain, ClientMessage::Send { to: None, .. }));
        assert!(!serde_json::to_string(&plain).unwrap().contains("\"to\""));
        for delivered in [true, false] {
            let ack = ServerMessage::Ack {
                id: Some("1".into()),
                fields: AckFields {
                    envelope_id: Some("9c1d".into()),
                    delivered: Some(delivered),
                    ..Default::default()
                },
            };
            let v = serde_json::to_value(&ack).unwrap();
            assert_eq!(keys(&v), vec!["delivered", "envelope_id", "id", "op"]);
            assert_eq!(v["delivered"], json!(delivered));
            let back: ServerMessage = serde_json::from_value(v).unwrap();
            assert_eq!(back, ack, "delivered is a field, not an extension key");
        }
        assert_eq!(
            serde_json::to_value(ServerMessage::error(
                Some("1".into()),
                ErrorCode::UnknownDestination,
                "no node w@0001020304050607"
            ))
            .unwrap(),
            json!({"op": "error", "id": "1", "code": "unknown_destination", "message": "no node w@0001020304050607"})
        );
    }

    #[test]
    fn limit_exceeded_has_its_wire_code() {
        let m = ServerMessage::error(Some("9".into()), ErrorCode::LimitExceeded, "at most 64");
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            json!({"op": "error", "id": "9", "code": "limit_exceeded", "message": "at most 64"})
        );
    }

    #[test]
    fn filter_omits_defaults() {
        let f = FilterSpec {
            channel: Some("db/*".into()),
            health: true,
            ..Default::default()
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(keys(&v), vec!["channel", "health"]);
        assert_eq!(
            serde_json::to_value(FilterSpec::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn client_send_omits_none_type_name() {
        let m = ClientMessage::Send {
            id: Some("1".into()),
            channel: "c".into(),
            type_id: 0,
            type_name: None,
            payload: "AA==".into(),
            flags: 0,
            to: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            keys(&v),
            vec!["channel", "flags", "id", "op", "payload", "type_id"]
        );
    }
}
