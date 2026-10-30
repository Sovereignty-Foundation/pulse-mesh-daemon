// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the port protocol's messages, `mesh_port_protocol::
// ClientMessage` and `ServerMessage`, parsed from text; and the daemon's
// handling of a connection's messages, `mesh_hub::internals::
// handle_connection`, past parsing into its validation of each message.
//
// The first byte picks the mode.
//
// Round trip (bit 2 clear). The daemon parses every frame a client sends as
// a `ClientMessage` (`serde_json::from_str` on the frame's text), and the
// Rust client parses every frame the daemon sends as a `ServerMessage`.
// Whatever either parses must survive the trip back: it serialises, the
// serialisation parses, and the result equals what was parsed. For
// `ClientMessage` the serialisation is also a fixed point, so a proxy or a
// recorder that re-serialises a message sends the same bytes each time;
// `ServerMessage`'s ack carries a map whose key order varies between
// serialisations, so for it the fixed point is the JSON value. A `send`'s
// payload that decodes as base64 is the encoding of the bytes it decodes
// to, since the codec is strict. Bit 0 picks where the text comes from:
// the rest of the input as it stands, or a JSON object built from it out of
// the protocol's own operations and keys, with values of the field's type
// or of any JSON type, so the parsed path is reached at once rather than
// after the fuzzer has rediscovered the protocol's vocabulary. The
// vocabulary includes key-proof attach: an attach's `key`, the `prove`
// that answers a challenge with its `signature`, and the `challenge` with
// its `nonce`; and a send's destination, `to`, with its ack's `delivered`.
//
// Daemon (bit 2 set). A connection's inbound stream, built from the input
// (requests shaped by the protocol, with names, channels, filters and
// payloads now and then over the protocol's caps or not base64, attaches
// with a key of three the input holds, with any 32 bytes or with text that
// is no key, proofs of the challenge the daemon last sent, signed by the
// attach's key or another, over its name or another, bound to the link or
// not, or a signature that is none, raw text, pongs, a frame over the size
// cap, unsubscribes naming a subscription the daemon granted earlier or
// another), is driven through the daemon's own connection loop over a
// scripted transport, against a hub this process owns under a name unique
// to it (`HubBridge`, with a 16-slot store), with a policy the input picks
// (subscription cap, event queue depth and bytes, an allowlist of two of
// the three keys or none, whether the Unix socket requires a key) and a
// link it picks (the Unix socket, `ws://`, or `wss://` with an exporter
// value of its own, never zeros). That reaches the parse, `handle_message`
// with every check it makes (protocol version, a second attach, the name
// cap, a name in use, a keyless attach the link refuses, a key that is no
// key, the challenge, its proof's id, signature, key and list, a request
// while a challenge is pending, attach before send and subscribe, strict
// base64, the channel and type-name caps, the subscription cap, the filter
// caps, unknown subscriptions, detach, a send's destination: the
// connection's own node, the other attached node, or one no one has), the
// registry, the bridge's send and send to a node, subscribe and
// unsubscribe, the filter compiler and matcher, and the event queue; it
// does not reach the accept loops, the framing
// (fuzz_uds_framing), the WebSocket upgrade, the TLS handshake whose
// exporter the link stands in for, or the challenge's deadline: the
// scripted stream never waits, so the deadline (the handshake timeout, set
// to an hour here) never comes; the unit tests in `connection.rs` and
// `tests/attach_keys.rs` hold it.
//
// Invariants in daemon mode, against a model of the protocol:
// - every frame gets exactly the reply the protocol gives it, in order:
//   `bad_request` without an id for text that is not a client message;
//   for each request, the ack with its fields (the attach's node id: by
//   name, `name@` and the first four bytes of BLAKE3 of the name in hex;
//   by a proven key, `name@` and the 32 hex digits of the key's node id;
//   the version and the capabilities granted; the send's envelope id, the
//   content id section 3.2 gives a raw payload under the type name or the
//   channel, and `persisted`, or for a send to a node `delivered` and no
//   `persisted` (false for the other attached node, which subscribes to
//   nothing), or `unknown_destination` for a node no one has; the
//   subscription's id, new each time; the
//   unsubscribe's drop count), a keyed attach's challenge under its id,
//   with a nonce of 32 bytes no other challenge of the run had, or the
//   error with the code the first failed check names; nothing for `health`
//   and pongs;
// - a proof is accepted exactly when it answers the pending challenge
//   under the attach's id with the signature the attach's key makes over
//   the nonce, the attach's name and the link's exporter value (zeros in
//   plaintext), and the key is listed when there is a list;
// - a frame over the cap is answered `payload_too_large` and ends the
//   connection, and so does an acknowledged detach, and so does every
//   `auth_failed`: nothing after any of them is read;
// - every event the daemon writes belongs to a subscription it granted on
//   this connection and carries a payload, channel and envelope id that a
//   send it acknowledged carried, and the node id the attach was acked
//   with;
// - when the connection ends, every subscription it held is released at
//   the bridge;
// - nothing panics, and the connection loop ends when the stream does.

#![no_main]

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_hub::internals::{
    handle_connection, ConnectionId, HubBridge, Inbound, Link, Registry, Transport,
};
use mesh_hub::{AttachKeys, ConnectionPolicy};
use mesh_hub_runtime::HubConfig;
use mesh_port_protocol::attach::{self, SigningKey};
use mesh_port_protocol::{
    base64, ClientMessage, ServerMessage, MAX_CHANNEL_LEN, MAX_NAME_LEN, MAX_PATTERN_LEN,
    PROTOCOL_VERSION,
};
use pulse_mesh_fuzz::canonical;
use pulse_mesh_fuzz::take;
use serde_json::{json, Map, Number, Value};

/// Every `op` of both directions, with the fields it requires (for
/// `health`, the server's; the client's requires none).
const OPS: &[(&str, &[&str])] = &[
    ("attach", &["name", "protocol_version"]),
    ("detach", &[]),
    ("send", &["channel", "payload"]),
    ("subscribe", &[]),
    ("unsubscribe", &["subscription_id"]),
    ("prove", &["signature"]),
    ("health", &["node_id", "state"]),
    ("challenge", &["nonce"]),
    ("ack", &[]),
    ("error", &["code", "message"]),
    (
        "event",
        &[
            "subscription_id",
            "envelope_id",
            "channel",
            "origin",
            "captured_at_unix_nanos",
            "payload",
        ],
    ),
];

/// The keys the messages know, with the type of value each takes.
const KEYS: &[(&str, Kind)] = &[
    ("id", Kind::Text),
    ("name", Kind::Text),
    ("protocol_version", Kind::Text),
    ("capabilities", Kind::Texts),
    ("key", Kind::Base64),
    ("signature", Kind::Base64),
    ("nonce", Kind::Base64),
    ("channel", Kind::Text),
    ("type_id", Kind::Int),
    ("type_name", Kind::Text),
    ("payload", Kind::Base64),
    ("flags", Kind::Int),
    ("to", Kind::Text),
    ("filter", Kind::Filter),
    ("subscription_id", Kind::Text),
    ("state", Kind::Text),
    ("node_id", Kind::Text),
    ("granted_capabilities", Kind::Texts),
    ("envelope_id", Kind::Text),
    ("persisted", Kind::Bool),
    ("delivered", Kind::Bool),
    ("events_dropped", Kind::Int),
    ("code", Kind::Text),
    ("message", Kind::Text),
    ("origin", Kind::Text),
    ("captured_at_unix_nanos", Kind::Int),
    ("since_unix_nanos", Kind::Int),
];

/// The keys of a subscribe filter.
const FILTER_KEYS: &[(&str, Kind)] = &[
    ("channel", Kind::Text),
    ("type_id", Kind::Int),
    ("type_name", Kind::Text),
    ("origin", Kind::Text),
    ("health", Kind::Bool),
    ("snapshot", Kind::Bool),
];

/// The type of value a field takes.
#[derive(Clone, Copy)]
enum Kind {
    Text,
    Texts,
    Int,
    Bool,
    Base64,
    Filter,
    Any,
}

/// Deepest nesting of a built value.
const MAX_DEPTH: usize = 4;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 4 != 0 {
        let _ = daemon(&mut Unstructured::new(rest));
        return;
    }
    if mode & 1 == 0 {
        // Both ends parse a frame only once it is valid UTF-8.
        if let Ok(text) = std::str::from_utf8(rest) {
            round_trip(text);
        }
    } else if let Ok(object) = message(&mut Unstructured::new(rest)) {
        let text = if mode & 2 == 0 {
            serde_json::to_string(&object)
        } else {
            serde_json::to_string_pretty(&object)
        };
        round_trip(&text.expect("a JSON value serialises"));
    }
});

/// Whatever `text` parses as must come back from its serialisation.
fn round_trip(text: &str) {
    if let Ok(msg) = serde_json::from_str::<ClientMessage>(text) {
        let json = serde_json::to_string(&msg).expect("a parsed client message serialises");
        let back: ClientMessage = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("the serialisation {json} does not parse: {e}"));
        assert_eq!(
            back, msg,
            "the round trip through {json} changed the message"
        );
        assert_eq!(
            serde_json::to_string(&back).expect("serialises"),
            json,
            "re-serialising gives other text"
        );
        if let ClientMessage::Send { payload, .. } = &msg {
            if let Ok(bytes) = base64::decode(payload) {
                assert_eq!(
                    &base64::encode(&bytes),
                    payload,
                    "a payload decodes from a second text"
                );
            }
        }
    }

    if let Ok(msg) = serde_json::from_str::<ServerMessage>(text) {
        let value = serde_json::to_value(&msg).expect("a parsed server message serialises");
        let json = serde_json::to_string(&msg).expect("a parsed server message serialises");
        let back: ServerMessage = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("the serialisation {json} does not parse: {e}"));
        assert_eq!(
            back, msg,
            "the round trip through {json} changed the message"
        );
        assert_eq!(
            serde_json::to_value(&back).expect("serialises"),
            value,
            "re-serialising gives another value"
        );
    }
}

/// A JSON object with an `op` and fields, mostly the protocol's own.
fn message(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut object = Map::new();
    if u.ratio(15, 16)? {
        let &(op, required) = u.choose(OPS)?;
        object.insert("op".to_owned(), Value::from(op));
        // Half the time every field the op requires, so each variant parses.
        if u.arbitrary()? {
            for &key in required {
                object.insert(key.to_owned(), value(u, kind_of(key), 1)?);
            }
        }
    } else {
        object.insert("op".to_owned(), value(u, Kind::Any, 1)?);
    }
    fields(u, KEYS, &mut object, 1)?;
    Ok(Value::Object(object))
}

/// The type of value a known key takes.
fn kind_of(key: &str) -> Kind {
    KEYS.iter()
        .find(|&&(k, _)| k == key)
        .map_or(Kind::Any, |&(_, kind)| kind)
}

/// Add fields to `object`: mostly known keys, now and then any key; mostly
/// of the key's type, now and then of any type.
fn fields(
    u: &mut Unstructured<'_>,
    keys: &[(&str, Kind)],
    object: &mut Map<String, Value>,
    depth: usize,
) -> Result<()> {
    for _ in 0..u.int_in_range(0..=6)? {
        let (key, kind) = if u.ratio(7, 8)? {
            let &(key, kind) = u.choose(keys)?;
            (key.to_owned(), kind)
        } else {
            (u.arbitrary::<&str>()?.to_owned(), Kind::Any)
        };
        let kind = if u.ratio(1, 4)? { Kind::Any } else { kind };
        object.insert(key, value(u, kind, depth + 1)?);
    }
    Ok(())
}

/// A value of the given kind.
fn value(u: &mut Unstructured<'_>, kind: Kind, depth: usize) -> Result<Value> {
    Ok(match kind {
        Kind::Text => Value::from(u.arbitrary::<&str>()?),
        Kind::Texts => {
            let mut texts = Vec::new();
            for _ in 0..u.int_in_range(0..=3)? {
                texts.push(Value::from(u.arbitrary::<&str>()?));
            }
            Value::Array(texts)
        }
        // Every magnitude, from those a u16 field holds to past it.
        Kind::Int => Value::from(u.arbitrary::<u64>()? >> u.int_in_range(0..=63u32)?),
        Kind::Bool => Value::from(u.arbitrary::<bool>()?),
        Kind::Base64 => {
            if u.arbitrary()? {
                let len = u.int_in_range(0..=48)?;
                Value::from(base64::encode(u.bytes(len.min(u.len()))?))
            } else {
                Value::from(u.arbitrary::<&str>()?)
            }
        }
        Kind::Filter => {
            let mut filter = Map::new();
            fields(u, FILTER_KEYS, &mut filter, depth)?;
            Value::Object(filter)
        }
        Kind::Any => any(u, depth)?,
    })
}

/// A value of any JSON type.
fn any(u: &mut Unstructured<'_>, depth: usize) -> Result<Value> {
    let kinds = if depth < MAX_DEPTH { 7 } else { 5 };
    Ok(match u.int_in_range(0..=kinds)? {
        0 => Value::Null,
        1 => Value::from(u.arbitrary::<bool>()?),
        2 => Value::from(u.arbitrary::<u64>()?),
        3 => Value::from(u.arbitrary::<i64>()?),
        4 => Number::from_f64(u.arbitrary()?).map_or(Value::Null, Value::Number),
        5 => Value::from(u.arbitrary::<&str>()?),
        6 => {
            let mut items = Vec::new();
            for _ in 0..u.int_in_range(0..=3)? {
                items.push(any(u, depth + 1)?);
            }
            Value::Array(items)
        }
        _ => {
            let mut object = Map::new();
            for _ in 0..u.int_in_range(0..=3)? {
                object.insert(u.arbitrary::<&str>()?.to_owned(), any(u, depth + 1)?);
            }
            Value::Object(object)
        }
    })
}

// =============================================================================
// Daemon mode
// =============================================================================

/// Most frames in one connection's stream.
const MAX_FRAMES: usize = 48;
/// A name no request can hold, registered before the connection starts so
/// that an attach under it meets a name in use.
const TAKEN: &str = "taken";
/// How long a challenge waits for its proof: past any run, since the
/// scripted stream never waits.
const CHALLENGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

/// The seeds of the keys a run's attaches and proofs use; with a list, the
/// first two keys are on it.
const SEEDS: [u8; 3] = [0x11, 0x22, 0x33];

fn signer(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[SEEDS[i % SEEDS.len()]; 32])
}

fn public(i: usize) -> [u8; 32] {
    signer(i).verifying_key().to_bytes()
}

/// The hub every daemon-mode input talks to: one per process, under a name
/// unique to it, released at exit.
static BRIDGE: Mutex<Option<Arc<HubBridge>>> = Mutex::new(None);

/// The runtime the connection loop runs on.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

extern "C" fn release_bridge() {
    if let Ok(mut bridge) = BRIDGE.lock() {
        // Dropping the last handle unlinks the hub's shared memory and
        // releases its lock file.
        bridge.take();
    }
}

/// The process's hub, and its name.
fn bridge() -> (Arc<HubBridge>, String) {
    let hub = format!("fzd{:x}", std::process::id());
    let mut slot = BRIDGE.lock().expect("the bridge lock");
    if let Some(bridge) = slot.as_ref() {
        return (Arc::clone(bridge), hub);
    }
    let config = HubConfig::default().with_store_slots(16);
    let bridge = Arc::new(HubBridge::with_config(&hub, config).expect("the fuzzing hub starts"));
    // SAFETY: `release_bridge` takes no arguments, returns nothing and
    // unwinds nowhere (it only drops the bridge), as `atexit(3)` requires.
    unsafe { libc::atexit(release_bridge) };
    *slot = Some(Arc::clone(&bridge));
    (bridge, hub)
}

/// One element of a connection's inbound stream.
enum Step {
    /// Yielded as it is.
    Ready(Inbound),
    /// An unsubscribe naming the `nth` subscription the daemon has granted
    /// on this connection so far (modulo their number), resolved when the
    /// daemon reads it.
    Unsubscribe { id: Option<String>, nth: usize },
    /// A proof of the challenge the daemon sent last (of zeros when it sent
    /// none), resolved when the daemon reads it.
    Prove(Proof),
}

/// How a [`Step::Prove`] is made.
struct Proof {
    /// The id it carries, in place of the challenge's.
    id: Option<Option<String>>,
    /// The key that signs it, of [`SEEDS`].
    signer: usize,
    /// The name it signs, in place of the last keyed attach's.
    name: Option<String>,
    /// Whether it signs the link's exporter value, or zeros.
    bound: bool,
    /// A signature text in place of the signature.
    raw: Option<String>,
}

/// What passed over the connection, in order.
#[derive(Default)]
struct Log {
    inbound: Vec<Inbound>,
    outbound: Vec<String>,
}

/// A transport that yields a script and records everything.
struct Scripted {
    steps: VecDeque<Step>,
    log: Arc<Mutex<Log>>,
    link: Link,
}

impl Scripted {
    /// The `prove` frame `proof` makes from what the connection has seen.
    fn prove(&self, proof: Proof) -> String {
        let log = self.log.lock().expect("the log lock");
        let challenge =
            log.outbound
                .iter()
                .rev()
                .find_map(
                    |text| match serde_json::from_str::<ServerMessage>(text).ok()? {
                        ServerMessage::Challenge { id, nonce } => Some((id, nonce)),
                        _ => None,
                    },
                );
        let (challenge_id, nonce) = match challenge {
            Some((id, nonce)) => (id, attach::decode_nonce(&nonce).unwrap_or([0; 32])),
            None => (None, [0; 32]),
        };
        let attached_name = log.inbound.iter().rev().find_map(|inbound| match inbound {
            Inbound::Frame(text) => match serde_json::from_str::<ClientMessage>(text).ok()? {
                ClientMessage::Attach {
                    name, key: Some(_), ..
                } => Some(name),
                _ => None,
            },
            _ => None,
        });
        let name = proof
            .name
            .or(attached_name)
            .unwrap_or_else(|| "x".to_owned());
        let exporter = if proof.bound {
            self.link.exporter()
        } else {
            attach::NO_EXPORTER
        };
        let signature = proof.raw.unwrap_or_else(|| {
            base64::encode(&attach::sign(
                &signer(proof.signer),
                &nonce,
                &name,
                &exporter,
            ))
        });
        let mut frame = json!({"op": "prove", "signature": signature});
        if let Some(id) = proof.id.unwrap_or(challenge_id) {
            frame["id"] = Value::from(id);
        }
        frame.to_string()
    }
}

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn recv(&mut self) -> Inbound {
        let next = match self.steps.pop_front() {
            None => Inbound::Closed,
            Some(Step::Ready(inbound)) => inbound,
            Some(Step::Prove(proof)) => Inbound::Frame(self.prove(proof)),
            Some(Step::Unsubscribe { id, nth }) => {
                let log = self.log.lock().expect("the log lock");
                let granted: Vec<String> = log
                    .outbound
                    .iter()
                    .filter_map(|text| granted_subscription(text))
                    .collect();
                let sub = if granted.is_empty() {
                    "sub-none".to_owned()
                } else {
                    granted[nth % granted.len()].clone()
                };
                let mut frame = json!({"op": "unsubscribe", "subscription_id": sub});
                if let Some(id) = id {
                    frame["id"] = Value::from(id);
                }
                Inbound::Frame(frame.to_string())
            }
        };
        self.log
            .lock()
            .expect("the log lock")
            .inbound
            .push(next.clone());
        next
    }

    fn link(&self) -> Link {
        self.link
    }

    async fn send(&mut self, msg: &str) -> std::io::Result<()> {
        self.log
            .lock()
            .expect("the log lock")
            .outbound
            .push(msg.to_owned());
        Ok(())
    }

    async fn close(self: Box<Self>) {}
}

/// The subscription id a subscribe ack grants, if `text` is one.
fn granted_subscription(text: &str) -> Option<String> {
    match serde_json::from_str::<ServerMessage>(text).ok()? {
        ServerMessage::Ack { fields, .. } => fields.subscription_id,
        _ => None,
    }
}

/// The attach rules the model holds the run to.
struct Rules {
    /// The keys listed, when there is a list.
    keys: Option<Vec<[u8; 32]>>,
    /// Whether an attach without a key is refused on this link.
    keyless_refused: bool,
    /// What a proof on this link signs.
    exporter: [u8; 32],
}

/// One connection's stream through the daemon's own loop, judged against
/// the protocol.
fn daemon(u: &mut Unstructured<'_>) -> Result<()> {
    let listed = u.arbitrary::<bool>()?.then(|| vec![public(0), public(1)]);
    let uds_strict = u.arbitrary::<bool>()?;
    let link = match u.int_in_range(0..=2u8)? {
        0 => Link::UnixSocket,
        1 => Link::WebSocket,
        // One byte of input, never zero, so that a proof signing the
        // plaintext zeros is always the wrong one here.
        _ => Link::SecureWebSocket {
            exporter: [u.arbitrary::<u8>()? | 1; 32],
        },
    };
    let policy = ConnectionPolicy::default()
        .with_ping_interval(std::time::Duration::ZERO)
        .with_idle_timeout(std::time::Duration::ZERO)
        .with_write_timeout(std::time::Duration::ZERO)
        .with_handshake_timeout(CHALLENGE_WINDOW)
        .with_subscriber_queue(u.int_in_range(1..=4)?)
        .with_subscriber_queue_bytes(if u.arbitrary()? {
            u.int_in_range(0..=4096)?
        } else {
            16 << 20
        })
        .with_max_subscriptions(u.int_in_range(0..=3)?)
        .with_attach_keys(listed.clone().map(AttachKeys::new))
        .with_attach_keys_uds(uds_strict);
    let rules = Rules {
        keyless_refused: listed.is_some() && (link != Link::UnixSocket || uds_strict),
        keys: listed,
        exporter: link.exporter(),
    };
    let mut steps = VecDeque::new();
    for _ in 0..u.int_in_range(1..=MAX_FRAMES)? {
        if u.is_empty() {
            break;
        }
        steps.push_back(match u.int_in_range(0..=25u8)? {
            0 => Step::Ready(Inbound::Pong),
            1 => Step::Ready(Inbound::Oversized {
                len: u.arbitrary()?,
            }),
            2 => Step::Ready(Inbound::Frame(u.arbitrary::<&str>()?.to_owned())),
            3 | 4 => Step::Unsubscribe {
                id: request_id(u)?,
                nth: u.arbitrary::<u8>()?.into(),
            },
            5..=7 => Step::Prove(proof(u)?),
            _ => Step::Ready(Inbound::Frame(request(u)?.to_string())),
        });
    }

    let (bridge, hub) = bridge();
    let registry = Registry::new();
    let _ = registry.attach(TAKEN, ConnectionId(u64::MAX));
    let log = Arc::new(Mutex::new(Log::default()));
    let transport = Box::new(Scripted {
        steps,
        log: Arc::clone(&log),
        link,
    });
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
    });
    runtime.block_on(handle_connection(
        transport,
        Arc::clone(&bridge),
        registry,
        policy.clone(),
    ));
    assert_eq!(
        bridge.subscriber_count(),
        0,
        "the connection left subscriptions behind"
    );

    let log = log.lock().expect("the log lock");
    judge(&log, &policy, &rules, &hub);
    Ok(())
}

/// How the next proof is made: mostly a good one, now and then wrong in one
/// way.
fn proof(u: &mut Unstructured<'_>) -> Result<Proof> {
    Ok(Proof {
        id: if u.ratio(1, 8)? {
            Some(request_id(u)?)
        } else {
            None
        },
        signer: u.int_in_range(0..=2)?,
        name: if u.ratio(1, 8)? {
            Some(format!("node{}", u.int_in_range(0..=2u8)?))
        } else {
            None
        },
        bound: u.ratio(7, 8)?,
        raw: if u.ratio(1, 8)? {
            Some(if u.arbitrary()? {
                base64::encode(take(u, 64)?)
            } else {
                u.arbitrary::<&str>()?.to_owned()
            })
        } else {
            None
        },
    })
}

/// A request's `id`: mostly one, now and then none.
fn request_id(u: &mut Unstructured<'_>) -> Result<Option<String>> {
    Ok(if u.ratio(7, 8)? {
        Some(format!("r{}", u.arbitrary::<u8>()?))
    } else {
        None
    })
}

/// A string of about `cap` bytes: under it, at it, or just over it.
fn sized(u: &mut Unstructured<'_>, cap: usize) -> Result<String> {
    Ok(match u.int_in_range(0..=15u8)? {
        0 => "a".repeat(cap),
        1 => "b".repeat(cap + 1),
        2 => "é".repeat(cap / 2 + 1),
        _ => u.arbitrary::<&str>()?.chars().take(24).collect(),
    })
}

/// An attach's `key`: mostly one of the run's three, now and then any 32
/// bytes, or text that is no key.
fn key(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(match u.int_in_range(0..=7u8)? {
        0 => base64::encode(&u.arbitrary::<[u8; 32]>()?),
        1 => u.arbitrary::<&str>()?.to_owned(),
        i => attach::encode_key(&public(usize::from(i))),
    })
}

/// A request shaped by the protocol, with values the daemon checks now and
/// then out of bounds.
fn request(u: &mut Unstructured<'_>) -> Result<Value> {
    let id = request_id(u)?;
    let mut frame = match u.int_in_range(0..=9u8)? {
        0 | 1 => {
            let name = match u.int_in_range(0..=7u8)? {
                0 => TAKEN.to_owned(),
                1 => sized(u, MAX_NAME_LEN)?,
                _ => format!("node{}", u.int_in_range(0..=2u8)?),
            };
            let version = if u.ratio(7, 8)? {
                PROTOCOL_VERSION.to_owned()
            } else {
                u.arbitrary::<&str>()?.to_owned()
            };
            let mut caps = Vec::new();
            for _ in 0..u.int_in_range(0..=4)? {
                const CAPS: [&str; 5] = ["send", "subscribe", "tap", "admin", ""];
                caps.push(CAPS[u.choose_index(CAPS.len())?]);
            }
            let mut frame = json!({"op": "attach", "name": name, "protocol_version": version, "capabilities": caps});
            if u.arbitrary()? {
                frame["key"] = Value::from(key(u)?);
            }
            frame
        }
        2 => json!({"op": "detach"}),
        3..=5 => {
            let channel = if u.ratio(7, 8)? {
                format!("ch/{}", u.int_in_range(0..=2u8)?)
            } else {
                sized(u, MAX_CHANNEL_LEN)?
            };
            let payload = if u.ratio(7, 8)? {
                base64::encode(take(u, 32)?)
            } else {
                u.arbitrary::<&str>()?.to_owned()
            };
            let mut frame = json!({"op": "send", "channel": channel, "payload": payload});
            if u.ratio(1, 4)? {
                frame["type_name"] = Value::from(sized(u, MAX_CHANNEL_LEN)?);
            }
            if u.ratio(1, 4)? {
                frame["type_id"] = Value::from(u.arbitrary::<u16>()?);
            }
            if u.ratio(1, 4)? {
                // A destination: one of the names an attach takes, as its
                // node id, the other attached node's, or text that names
                // no node.
                frame["to"] = Value::from(match u.int_in_range(0..=3u8)? {
                    0 => node_id(TAKEN),
                    1 => u.arbitrary::<&str>()?.to_owned(),
                    _ => node_id(&format!("node{}", u.int_in_range(0..=2u8)?)),
                });
            }
            frame
        }
        6 | 7 => {
            let mut filter = Map::new();
            for key in ["channel", "type_name", "origin"] {
                if u.ratio(1, 3)? {
                    let value = match u.int_in_range(0..=3u8)? {
                        0 => sized(u, MAX_PATTERN_LEN)?,
                        1 => "**".to_owned(),
                        _ => format!("ch/{}", u.int_in_range(0..=2u8)?),
                    };
                    filter.insert(key.to_owned(), Value::from(value));
                }
            }
            if u.ratio(1, 4)? {
                filter.insert("type_id".to_owned(), Value::from(u.arbitrary::<u16>()?));
            }
            json!({"op": "subscribe", "filter": filter})
        }
        8 => json!({"op": "health", "state": "ok"}),
        _ => message(u)?,
    };
    if let (Some(id), Some(object)) = (id, frame.as_object_mut()) {
        object.entry("id").or_insert(Value::from(id));
    }
    Ok(frame)
}

/// What the protocol says the daemon answers.
#[derive(Debug)]
enum Want {
    Nothing,
    Error {
        id: Option<String>,
        code: &'static str,
    },
    Attached {
        id: Option<String>,
        node_id: String,
        granted: Vec<String>,
    },
    Challenged {
        id: Option<String>,
    },
    Detached {
        id: Option<String>,
    },
    Sent {
        id: Option<String>,
        envelope: [u8; 16],
        channel: String,
        payload: Vec<u8>,
    },
    /// A send to a node attached here: the connection's own (whose
    /// subscriptions may match it), or the other one, which holds none.
    SentTo {
        id: Option<String>,
        envelope: [u8; 16],
        channel: String,
        payload: Vec<u8>,
        to_self: bool,
    },
    Subscribed {
        id: Option<String>,
    },
    Unsubscribed {
        id: Option<String>,
        sub: String,
    },
}

/// A keyed attach the model has seen challenged, waiting for its proof.
struct Pending {
    id: Option<String>,
    name: String,
    key: [u8; 32],
    capabilities: Vec<String>,
    /// The challenge's nonce, once its reply has been read.
    nonce: Option<[u8; 32]>,
}

/// What the model keeps between frames.
#[derive(Default)]
struct State {
    /// The node id the connection was acked with.
    attached: Option<String>,
    pending: Option<Pending>,
    held: Vec<String>,
    granted_ever: HashSet<String>,
    sent: Vec<(String, Vec<u8>, String)>,
    nonces: HashSet<[u8; 32]>,
}

/// The model: replay the stream the daemon read, predict each reply, and
/// hold the daemon's writes to it.
fn judge(log: &Log, policy: &ConnectionPolicy, rules: &Rules, hub: &str) {
    let outbound: Vec<ServerMessage> = log
        .outbound
        .iter()
        .map(|text| {
            serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("the daemon wrote {text}, not a server message: {e}"))
        })
        .collect();
    let (events, mut replies): (Vec<&ServerMessage>, VecDeque<&ServerMessage>) = {
        let (e, r): (Vec<&ServerMessage>, Vec<&ServerMessage>) = outbound
            .iter()
            .partition(|m| matches!(m, ServerMessage::Event { .. }));
        (e, r.into())
    };

    let mut state = State::default();
    let mut ended = false;
    for inbound in &log.inbound {
        assert!(
            !ended,
            "the daemon read {inbound:?} after it ended the connection"
        );
        let want = match inbound {
            Inbound::Closed => {
                ended = true;
                Want::Nothing
            }
            Inbound::Pong => Want::Nothing,
            Inbound::Oversized { .. } => {
                ended = true;
                Want::Error {
                    id: None,
                    code: "payload_too_large",
                }
            }
            Inbound::Frame(text) => match serde_json::from_str::<ClientMessage>(text) {
                Err(_) => Want::Error {
                    id: None,
                    code: "bad_request",
                },
                Ok(msg) => expect(msg, &mut state, policy, rules),
            },
        };
        if matches!(
            want,
            Want::Detached { .. }
                | Want::Error {
                    code: "auth_failed",
                    ..
                }
        ) {
            ended = true;
        }
        if matches!(want, Want::Nothing) {
            continue;
        }
        let got = replies
            .pop_front()
            .unwrap_or_else(|| panic!("no reply where the protocol wants {want:?}"));
        check_reply(got, &want, hub, &mut state);
    }
    assert!(replies.is_empty(), "replies to nothing: {replies:?}");

    for event in events {
        let ServerMessage::Event {
            subscription_id,
            envelope_id,
            channel,
            origin,
            payload,
            ..
        } = event
        else {
            unreachable!("partitioned on events");
        };
        assert!(
            state.granted_ever.contains(subscription_id),
            "an event for {subscription_id}, never granted here"
        );
        let bytes = base64::decode(payload).expect("an event's payload is base64");
        assert!(
            state
                .sent
                .iter()
                .any(|(c, p, e)| c == channel && *p == bytes && e == envelope_id),
            "an event no acknowledged send carried"
        );
        let attached = state
            .attached
            .as_deref()
            .expect("events only after an attach");
        assert_eq!(origin, attached, "an event from another origin");
    }
}

/// The id a request carries; none for `health`.
fn id_of(msg: &ClientMessage) -> Option<String> {
    match msg {
        ClientMessage::Attach { id, .. }
        | ClientMessage::Prove { id, .. }
        | ClientMessage::Detach { id }
        | ClientMessage::Send { id, .. }
        | ClientMessage::Subscribe { id, .. }
        | ClientMessage::Unsubscribe { id, .. } => id.clone(),
        ClientMessage::Health { .. } => None,
    }
}

/// The capabilities of `requested` the daemon grants.
fn granted(requested: Vec<String>) -> Vec<String> {
    requested
        .into_iter()
        .filter(|c| matches!(c.as_str(), "send" | "subscribe" | "tap"))
        .collect()
}

/// The 32 bytes `text` holds as padded standard base64, if it holds them.
fn bytes32(text: &str) -> Option<[u8; 32]> {
    base64::decode(text).ok()?.try_into().ok()
}

/// The reply the protocol gives `msg`, and the state it leaves.
fn expect(msg: ClientMessage, state: &mut State, policy: &ConnectionPolicy, rules: &Rules) -> Want {
    // While a challenge is pending, only its proof is a request.
    if state.pending.is_some()
        && !matches!(
            msg,
            ClientMessage::Prove { .. }
                | ClientMessage::Health { .. }
                | ClientMessage::Detach { .. }
        )
    {
        return Want::Error {
            id: id_of(&msg),
            code: "auth_failed",
        };
    }
    match msg {
        ClientMessage::Attach {
            id,
            name,
            protocol_version,
            capabilities,
            key,
        } => {
            let code = if protocol_version != PROTOCOL_VERSION {
                Some("version_unsupported")
            } else if state.attached.is_some()
                || name.len() > MAX_NAME_LEN
                || mesh_port_protocol::name_mimics_node_id(&name)
            {
                Some("bad_request")
            } else {
                None
            };
            if let Some(code) = code {
                return Want::Error { id, code };
            }
            let Some(key) = key else {
                if rules.keyless_refused {
                    return Want::Error {
                        id,
                        code: "auth_failed",
                    };
                }
                if name == TAKEN {
                    return Want::Error {
                        id,
                        code: "name_in_use",
                    };
                }
                let node_id = node_id(&name);
                state.attached = Some(node_id.clone());
                return Want::Attached {
                    id,
                    node_id,
                    granted: granted(capabilities),
                };
            };
            let Some(key) = bytes32(&key) else {
                return Want::Error {
                    id,
                    code: "bad_request",
                };
            };
            state.pending = Some(Pending {
                id: id.clone(),
                name,
                key,
                capabilities,
                nonce: None,
            });
            Want::Challenged { id }
        }
        ClientMessage::Prove { id, signature } => {
            let refused = Want::Error {
                id: id.clone(),
                code: "auth_failed",
            };
            let Some(pending) = state.pending.take() else {
                return refused;
            };
            if id != pending.id {
                return refused;
            }
            let nonce = pending.nonce.expect("the challenge's reply was read");
            // A signature only one of the run's keys can make: the one the
            // attach named, over this challenge, name and link.
            let proved = base64::decode(&signature).ok().is_some_and(|signature| {
                (0..SEEDS.len()).any(|i| {
                    public(i) == pending.key
                        && signature[..]
                            == attach::sign(&signer(i), &nonce, &pending.name, &rules.exporter)[..]
                })
            });
            let listed = rules
                .keys
                .as_ref()
                .is_none_or(|keys| keys.contains(&pending.key));
            if !(proved && listed) {
                return refused;
            }
            if pending.name == TAKEN {
                return Want::Error {
                    id,
                    code: "name_in_use",
                };
            }
            let node_id = attach::keyed_node_id(&pending.name, &pending.key);
            state.attached = Some(node_id.clone());
            Want::Attached {
                id,
                node_id,
                granted: granted(pending.capabilities),
            }
        }
        ClientMessage::Detach { id } => Want::Detached { id },
        ClientMessage::Send {
            id,
            channel,
            type_id,
            type_name,
            payload,
            to,
            ..
        } => {
            if state.attached.is_none() {
                return Want::Error {
                    id,
                    code: "not_attached",
                };
            }
            let Ok(bytes) = base64::decode(&payload) else {
                return Want::Error {
                    id,
                    code: "bad_request",
                };
            };
            if channel.len() > MAX_CHANNEL_LEN
                || type_name
                    .as_ref()
                    .is_some_and(|t| t.len() > MAX_CHANNEL_LEN)
            {
                return Want::Error {
                    id,
                    code: "bad_request",
                };
            }
            let routing = type_name.unwrap_or_else(|| channel.clone());
            // The content id hashes the send's numeric type with its name
            // (spec 3.2), so a send with a type id has an id of its own.
            let envelope = canonical::raw_id(type_id, Some(&routing), &bytes);
            match to {
                None => Want::Sent {
                    id,
                    envelope,
                    channel,
                    payload: bytes,
                },
                // The daemon runs without links, so a node is one attached
                // here, by the node id its attach was acked with.
                Some(to)
                    if state.attached.as_deref() == Some(to.as_str()) || to == node_id(TAKEN) =>
                {
                    Want::SentTo {
                        id,
                        envelope,
                        channel,
                        payload: bytes,
                        to_self: state.attached.as_deref() == Some(to.as_str()),
                    }
                }
                Some(_) => Want::Error {
                    id,
                    code: "unknown_destination",
                },
            }
        }
        ClientMessage::Subscribe { id, filter } => {
            if state.attached.is_none() {
                return Want::Error {
                    id,
                    code: "not_attached",
                };
            }
            if state.held.len() >= policy.max_subscriptions {
                return Want::Error {
                    id,
                    code: "limit_exceeded",
                };
            }
            let long = [&filter.channel, &filter.type_name, &filter.origin]
                .into_iter()
                .flatten()
                .any(|s| s.len() > MAX_PATTERN_LEN);
            if long {
                return Want::Error {
                    id,
                    code: "bad_request",
                };
            }
            Want::Subscribed { id }
        }
        ClientMessage::Unsubscribe {
            id,
            subscription_id,
        } => {
            if state.held.contains(&subscription_id) {
                Want::Unsubscribed {
                    id,
                    sub: subscription_id,
                }
            } else {
                Want::Error {
                    id,
                    code: "unknown_subscription",
                }
            }
        }
        ClientMessage::Health { .. } => Want::Nothing,
    }
}

/// Hold one reply to what the protocol wants, and record what it grants.
fn check_reply(got: &ServerMessage, want: &Want, hub: &str, state: &mut State) {
    match (got, want) {
        (
            ServerMessage::Error { id, code, .. },
            Want::Error {
                id: want_id,
                code: want_code,
            },
        ) => {
            assert_eq!((id, code.as_str()), (want_id, *want_code), "the error");
        }
        (
            ServerMessage::Ack { id, fields },
            Want::Attached {
                id: want_id,
                node_id,
                granted,
            },
        ) => {
            assert_eq!(id, want_id);
            assert_eq!(
                fields.node_id.as_deref(),
                Some(node_id.as_str()),
                "the node id"
            );
            assert_eq!(fields.protocol_version.as_deref(), Some(PROTOCOL_VERSION));
            assert_eq!(
                fields.granted_capabilities.as_ref(),
                Some(granted),
                "the capabilities granted"
            );
        }
        (ServerMessage::Challenge { id, nonce }, Want::Challenged { id: want_id }) => {
            assert_eq!(id, want_id, "the challenge's id");
            let nonce = bytes32(nonce).expect("a challenge's nonce is 32 bytes of base64");
            assert!(
                state.nonces.insert(nonce),
                "a challenge repeated an earlier nonce"
            );
            state
                .pending
                .as_mut()
                .expect("a challenge answers a keyed attach")
                .nonce = Some(nonce);
        }
        (ServerMessage::Ack { id, fields }, Want::Detached { id: want_id }) => {
            assert_eq!(id, want_id);
            assert_eq!(
                fields.extra.get("__detach"),
                Some(&Value::Bool(true)),
                "the detach ack"
            );
        }
        (
            ServerMessage::Ack { id, fields },
            Want::Sent {
                id: want_id,
                envelope,
                channel,
                payload,
            },
        ) => {
            assert_eq!(id, want_id);
            let hex: String = envelope.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                fields.envelope_id.as_deref(),
                Some(hex.as_str()),
                "the envelope id"
            );
            assert_eq!(
                fields.persisted,
                Some(true),
                "a small envelope was not stored"
            );
            assert_eq!(fields.delivered, None, "a send to subscribers");
            state.sent.push((channel.clone(), payload.clone(), hex));
        }
        (
            ServerMessage::Ack { id, fields },
            Want::SentTo {
                id: want_id,
                envelope,
                channel,
                payload,
                to_self,
            },
        ) => {
            assert_eq!(id, want_id);
            let hex: String = envelope.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                fields.envelope_id.as_deref(),
                Some(hex.as_str()),
                "the envelope id"
            );
            assert_eq!(fields.persisted, None, "a send to a node is not stored");
            let delivered = fields
                .delivered
                .expect("a send to a node says if it was delivered");
            assert!(
                *to_self || !delivered,
                "the other node holds no subscription to deliver to"
            );
            if *to_self {
                state.sent.push((channel.clone(), payload.clone(), hex));
            }
        }
        (ServerMessage::Ack { id, fields }, Want::Subscribed { id: want_id }) => {
            assert_eq!(id, want_id);
            let sub = fields
                .subscription_id
                .clone()
                .expect("a subscribe ack names the subscription");
            assert!(
                sub.starts_with(&format!("sub-{hub}-")),
                "subscription id {sub}"
            );
            assert!(
                state.granted_ever.insert(sub.clone()),
                "subscription id {sub} granted twice"
            );
            state.held.push(sub);
        }
        (ServerMessage::Ack { id, fields }, Want::Unsubscribed { id: want_id, sub }) => {
            assert_eq!(id, want_id);
            assert!(
                fields.events_dropped.is_some(),
                "an unsubscribe ack without its drop count"
            );
            state.held.retain(|h| h != sub);
        }
        (got, want) => panic!("the daemon answered {got:?} where the protocol wants {want:?}"),
    }
}

/// The node id the daemon gives a name: `name@` and the first four bytes
/// of `BLAKE3(name)` in hex.
fn node_id(name: &str) -> String {
    let hash = blake3::hash(name.as_bytes());
    let suffix: String = hash.as_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{name}@{suffix}")
}
