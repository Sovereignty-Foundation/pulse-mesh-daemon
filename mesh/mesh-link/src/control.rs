// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The link's control messages (ADR-0021, items 1, 4, 6, 7 and 9) and
//! their encoding.

use std::collections::BTreeSet;

use mesh_health::NodeState;
use mesh_port_protocol::MAX_NAME_LEN;

use crate::codec::{self, Reader};
use crate::{
    CodecError, DaemonId, Interest, QualifiedOrigin, MAX_ANNOUNCE_PARTS, MAX_CONTROL_BYTES,
};

/// The newest version of [`Control`]'s encoding: 2. This build writes and
/// reads it and version 1, writing each message in the oldest version that
/// carries it: version 1 for every message but a relay's announcement that
/// names nodes reached through it, which version 2 adds. A build that reads
/// version 1 alone so reads everything but that.
pub const CONTROL_VERSION: u8 = 2;

/// The version of every message but an announcement that names nodes
/// reached through its sender.
const VERSION_1: u8 = 1;

/// The longest Hello a control message carries, in bytes. The capability
/// Hello (`mesh-capability`) is 48.
pub const MAX_HELLO_BYTES: usize = 1024;

const HELLO: u8 = 1;
const INTEREST: u8 = 2;
const NODES_ANNOUNCED: u8 = 3;
const HEALTH: u8 = 4;
const HEARTBEAT: u8 = 5;

/// A node's state as a health notice names it across a link: the states
/// of `mesh-health`, and `detached`, which a daemon reports for each node
/// of a peer whose link has closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthState {
    /// `healthy`.
    Healthy,
    /// `warning`.
    Warning,
    /// `restarting`.
    Restarting,
    /// `isolated`.
    Isolated,
    /// `degraded`.
    Degraded,
    /// `detached`: gone, or out of reach.
    Detached,
}

impl HealthState {
    /// The state's name in a `health` notice.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Restarting => "restarting",
            Self::Isolated => "isolated",
            Self::Degraded => "degraded",
            Self::Detached => "detached",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Warning => 1,
            Self::Restarting => 2,
            Self::Isolated => 3,
            Self::Degraded => 4,
            Self::Detached => 5,
        }
    }

    fn from_code(code: u8) -> Result<Self, CodecError> {
        Ok(match code {
            0 => Self::Healthy,
            1 => Self::Warning,
            2 => Self::Restarting,
            3 => Self::Isolated,
            4 => Self::Degraded,
            5 => Self::Detached,
            _ => return Err(CodecError::UnknownState(code)),
        })
    }
}

impl From<NodeState> for HealthState {
    fn from(state: NodeState) -> Self {
        match state {
            NodeState::Healthy => Self::Healthy,
            NodeState::Warning => Self::Warning,
            NodeState::Restarting => Self::Restarting,
            NodeState::Isolated => Self::Isolated,
            NodeState::Degraded => Self::Degraded,
        }
    }
}

/// What a link carries besides envelopes.
///
/// # Encoding
///
/// Integers little-endian, at most [`MAX_CONTROL_BYTES`] bytes in all:
///
/// ```text
/// u8  version: 1, or 2 for an announcement that names nodes through
///     its sender
/// u8  kind: 1 Hello, 2 Interest, 3 NodesAnnounced, 4 Health, 5 Heartbeat
/// then by kind:
///   Hello           u16 length, then that many bytes (at most 1,024)
///   Interest        the summary's encoding (Interest), to the end
///   NodesAnnounced  u64 generation, u16 part, u16 parts, then u32
///                   count, then each origin, ascending; parts is 1 to
///                   MAX_ANNOUNCE_PARTS (64) and part is below it; in
///                   version 2, then u32 count, at least 1, then each
///                   origin reached through the sender, ascending, none
///                   among the first
///   Health          an origin, then u8 state: 0 healthy, 1 warning,
///                   2 restarting, 3 isolated, 4 degraded, 5 detached
///   Heartbeat       nothing
/// origin: the daemon id's 8 bytes, then the name as a u16 length and its
///         UTF-8 bytes (at most MAX_NAME_LEN, 128)
/// ```
///
/// Version 2 is version 1 with the second list of an announcement, and is
/// written only for an announcement whose second list is not empty: every
/// other message is written, and read, as version 1 alone. So each value
/// has one encoding, and decoding refuses every other byte string, so
/// decoding and encoding are inverses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// The first message of a session, opaque here: the capability Hello
    /// (`mesh-capability`), which rides inside the authenticated session
    /// (ADR-0018, item 8). A Hello starts the session afresh: the receiver
    /// forgets the summary and the nodes the peer sent before
    /// ([`Router::remove_peer`], then [`Router::add_peer`]).
    ///
    /// [`Router::remove_peer`]: crate::Router::remove_peer
    /// [`Router::add_peer`]: crate::Router::add_peer
    Hello(Vec<u8>),
    /// The sender's interest summary, replacing the one before.
    Interest(Interest),
    /// The sender's clients, replacing those it announced before: all of
    /// them, or one part of an announcement too long for one message
    /// ([`Announcement::messages`]); and, from a relay, the clients of its
    /// other peers, reached through it.
    ///
    /// [`Announcement::messages`]: crate::Announcement::messages
    NodesAnnounced {
        /// The sender's count of announcements in this session, from 1,
        /// so a receiver keeps the newest of announcements that arrive out
        /// of order ([`Router::announce_part`]), as it does summaries. Every
        /// part of one announcement carries its generation.
        ///
        /// [`Router::announce_part`]: crate::Router::announce_part
        generation: u64,
        /// Which part this is, from 0.
        part: u16,
        /// How many parts the announcement has: 1 when this message carries
        /// it whole, and at most [`MAX_ANNOUNCE_PARTS`]. The receiver takes
        /// the announcement once each of its parts has arrived.
        parts: u16,
        /// The sender's own clients in this part. An announcement's parts
        /// hold consecutive runs of its clients in their order.
        nodes: BTreeSet<QualifiedOrigin>,
        /// The clients in this part that are reached through the sender, a
        /// relay: its other peers' (ADR-0021, item 9), none of them among
        /// `nodes`. They follow the sender's own in an announcement's
        /// parts, in their order. Not empty only in version 2.
        via: BTreeSet<QualifiedOrigin>,
    },
    /// A node's state changed: the sending daemon's own, or one of its
    /// clients', for a receiver whose summary [`Interest::wants_health`];
    /// from a relay, also one of the clients it announces as reached
    /// through it.
    Health {
        /// The node.
        node: QualifiedOrigin,
        /// Its new state.
        state: HealthState,
    },
    /// The link is alive; one that falls silent past its limit is closed.
    Heartbeat,
}

impl Control {
    fn kind(&self) -> u8 {
        match self {
            Self::Hello(_) => HELLO,
            Self::Interest(_) => INTEREST,
            Self::NodesAnnounced { .. } => NODES_ANNOUNCED,
            Self::Health { .. } => HEALTH,
            Self::Heartbeat => HEARTBEAT,
        }
    }

    /// The length of [`Control::encode`]'s bytes, whether or not they fit
    /// the cap.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let body = match self {
            Self::Hello(bytes) => 2 + bytes.len(),
            Self::Interest(interest) => interest.encoded_len(),
            Self::NodesAnnounced { nodes, via, .. } => {
                let through = if via.is_empty() {
                    0
                } else {
                    4 + via.iter().map(origin_len).sum::<usize>()
                };
                8 + 2 + 2 + 4 + nodes.iter().map(origin_len).sum::<usize>() + through
            }
            Self::Health { node, .. } => origin_len(node) + 1,
            Self::Heartbeat => 0,
        };
        crate::CONTROL_HEADER_BYTES + body
    }

    /// The version this message is written in: 2 for an announcement that
    /// names nodes reached through its sender, and 1 for every other.
    #[must_use]
    pub fn version(&self) -> u8 {
        match self {
            Self::NodesAnnounced { via, .. } if !via.is_empty() => CONTROL_VERSION,
            _ => VERSION_1,
        }
    }

    /// The message's canonical bytes.
    ///
    /// # Errors
    ///
    /// [`CodecError::TooLarge`] for a Hello longer than
    /// [`MAX_HELLO_BYTES`], or a message longer than [`MAX_CONTROL_BYTES`],
    /// as an announcement of very many nodes can be (which
    /// [`Announcement::messages`] splits into parts that fit);
    /// [`CodecError::BadPart`] for an announcement's part outside its
    /// parts; and [`CodecError::NotCanonical`] for an announcement that
    /// names a node both as the sender's and as reached through it. An
    /// interest summary always fits.
    ///
    /// [`Announcement::messages`]: crate::Announcement::messages
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::Hello(bytes) if bytes.len() > MAX_HELLO_BYTES => {
                return Err(CodecError::TooLarge {
                    what: "a Hello",
                    len: bytes.len(),
                    max: MAX_HELLO_BYTES,
                });
            }
            Self::NodesAnnounced {
                part,
                parts,
                nodes,
                via,
                ..
            } => {
                check_part(*part, *parts)?;
                if via.iter().any(|node| nodes.contains(node)) {
                    return Err(CodecError::NotCanonical(BOTH_LISTS));
                }
            }
            _ => {}
        }
        let len = self.encoded_len();
        if len > MAX_CONTROL_BYTES {
            return Err(CodecError::TooLarge {
                what: "a control message",
                len,
                max: MAX_CONTROL_BYTES,
            });
        }
        let mut out = Vec::with_capacity(len);
        out.push(self.version());
        out.push(self.kind());
        match self {
            Self::Hello(bytes) => {
                // At most MAX_HELLO_BYTES, checked above.
                codec::put_u16(&mut out, u16::try_from(bytes.len()).unwrap_or(u16::MAX));
                out.extend_from_slice(bytes);
            }
            Self::Interest(interest) => interest.encode_into(&mut out),
            Self::NodesAnnounced {
                generation,
                part,
                parts,
                nodes,
                via,
            } => {
                out.extend_from_slice(&generation.to_le_bytes());
                codec::put_u16(&mut out, *part);
                codec::put_u16(&mut out, *parts);
                codec::put_count(&mut out, nodes.len());
                for node in nodes {
                    put_origin(&mut out, node);
                }
                if !via.is_empty() {
                    codec::put_count(&mut out, via.len());
                    for node in via {
                        put_origin(&mut out, node);
                    }
                }
            }
            Self::Health { node, state } => {
                put_origin(&mut out, node);
                out.push(state.code());
            }
            Self::Heartbeat => {}
        }
        Ok(out)
    }

    /// Read a message from exactly `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::TooLarge`] for more than [`MAX_CONTROL_BYTES`] bytes,
    /// and otherwise the error naming the first field that is not a
    /// message's canonical form: a version other than 1 and
    /// [`CONTROL_VERSION`], an unknown kind or health state, bytes that end
    /// early or run on, a text that is not UTF-8 or is too long, an
    /// announcement's part outside its parts, nodes out of order or
    /// repeated, a version 2 message that is not an announcement naming
    /// nodes through its sender, one of those that is also among the
    /// sender's, or a summary [`Interest::decode`] refuses. Any bytes give
    /// a message or an error; none panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(CodecError::TooLarge {
                what: "a control message",
                len: bytes.len(),
                max: MAX_CONTROL_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != VERSION_1 && version != CONTROL_VERSION {
            return Err(CodecError::UnknownVersion(version));
        }
        let kind = r.u8()?;
        if version == CONTROL_VERSION && kind != NODES_ANNOUNCED {
            return Err(CodecError::NotCanonical(ONLY_VIA));
        }
        let message = match kind {
            HELLO => {
                let len = usize::from(r.u16()?);
                if len > MAX_HELLO_BYTES {
                    return Err(CodecError::TooLarge {
                        what: "a Hello",
                        len,
                        max: MAX_HELLO_BYTES,
                    });
                }
                Self::Hello(r.take(len)?.to_vec())
            }
            INTEREST => Self::Interest(Interest::decode_from(&mut r)?),
            NODES_ANNOUNCED => {
                let generation = r.u64()?;
                let part = r.u16()?;
                let parts = r.u16()?;
                check_part(part, parts)?;
                let nodes = read_origins(&mut r)?;
                let via = if version == CONTROL_VERSION {
                    let via = read_origins(&mut r)?;
                    if via.is_empty() {
                        return Err(CodecError::NotCanonical(ONLY_VIA));
                    }
                    if via.iter().any(|node| nodes.contains(node)) {
                        return Err(CodecError::NotCanonical(BOTH_LISTS));
                    }
                    via
                } else {
                    BTreeSet::new()
                };
                Self::NodesAnnounced {
                    generation,
                    part,
                    parts,
                    nodes,
                    via,
                }
            }
            HEALTH => {
                let node = read_origin(&mut r)?;
                let state = HealthState::from_code(r.u8()?)?;
                Self::Health { node, state }
            }
            HEARTBEAT => Self::Heartbeat,
            kind => return Err(CodecError::UnknownKind(kind)),
        };
        r.finish()?;
        Ok(message)
    }
}

/// Why a version 2 message is refused when it is not an announcement that
/// names nodes through its sender.
const ONLY_VIA: &str =
    "version 2 carries an announcement naming nodes through its sender, and only that";

/// Why an announcement that names a node in both its lists is refused.
const BOTH_LISTS: &str = "a node both the sender's and reached through it";

/// A count of origins, then each, ascending.
fn read_origins(r: &mut Reader<'_>) -> Result<BTreeSet<QualifiedOrigin>, CodecError> {
    let mut nodes = BTreeSet::new();
    for _ in 0..r.count(DaemonId::LEN + 2)? {
        let node = read_origin(r)?;
        if nodes.last().is_some_and(|last| &node <= last) {
            return Err(CodecError::NotCanonical("nodes out of order or repeated"));
        }
        nodes.insert(node);
    }
    Ok(nodes)
}

/// Refuse an announcement's part that is not below its count of parts, or
/// a count of none or more than [`MAX_ANNOUNCE_PARTS`].
fn check_part(part: u16, parts: u16) -> Result<(), CodecError> {
    if parts == 0 || parts > MAX_ANNOUNCE_PARTS || part >= parts {
        return Err(CodecError::BadPart { part, parts });
    }
    Ok(())
}

/// The bytes `origin` takes in a message: the daemon id, the name's length
/// and the name.
pub(crate) fn origin_len(origin: &QualifiedOrigin) -> usize {
    DaemonId::LEN + 2 + origin.name().len()
}

fn put_origin(out: &mut Vec<u8>, origin: &QualifiedOrigin) {
    out.extend_from_slice(origin.daemon().as_bytes());
    codec::put_text(out, origin.name());
}

fn read_origin(r: &mut Reader<'_>) -> Result<QualifiedOrigin, CodecError> {
    let daemon = DaemonId::from_bytes(r.array()?);
    let name = r.text("a node's name", MAX_NAME_LEN)?;
    Ok(QualifiedOrigin {
        daemon,
        name: name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_port_protocol::FilterSpec;

    fn node(daemon: u8, name: &str) -> QualifiedOrigin {
        QualifiedOrigin::new(DaemonId::from_bytes([daemon; 8]), name).unwrap()
    }

    fn every_kind() -> Vec<Control> {
        let interest = Interest::from_filters(&[FilterSpec {
            channel: Some("jobs/*".into()),
            health: true,
            ..FilterSpec::default()
        }])
        .with_generation(3);
        vec![
            Control::Hello(vec![0x50, 0x4d, 0x53, 0x48]),
            Control::Hello(Vec::new()),
            Control::Interest(interest),
            Control::Interest(Interest::nothing()),
            Control::NodesAnnounced {
                generation: 7,
                part: 0,
                parts: 1,
                nodes: [node(2, "b"), node(1, "z"), node(2, "a")]
                    .into_iter()
                    .collect(),
                via: BTreeSet::new(),
            },
            Control::NodesAnnounced {
                generation: u64::MAX,
                part: MAX_ANNOUNCE_PARTS - 1,
                parts: MAX_ANNOUNCE_PARTS,
                nodes: BTreeSet::new(),
                via: BTreeSet::new(),
            },
            Control::NodesAnnounced {
                generation: 2,
                part: 1,
                parts: 2,
                nodes: [node(2, "a")].into_iter().collect(),
                via: [node(3, "c"), node(1, "a")].into_iter().collect(),
            },
            Control::NodesAnnounced {
                generation: 3,
                part: 0,
                parts: 1,
                nodes: BTreeSet::new(),
                via: [node(3, "c")].into_iter().collect(),
            },
            Control::Health {
                node: node(1, "worker"),
                state: HealthState::Detached,
            },
            Control::Heartbeat,
        ]
    }

    #[test]
    fn every_kind_round_trips() {
        for message in every_kind() {
            let bytes = message.encode().unwrap();
            assert_eq!(bytes.len(), message.encoded_len());
            assert_eq!(Control::decode(&bytes), Ok(message));
        }
    }

    #[test]
    fn the_encoding_is_the_documented_layout() {
        assert_eq!(Control::Heartbeat.encode().unwrap(), [1, 5]);
        assert_eq!(
            Control::Hello(vec![9, 8]).encode().unwrap(),
            [1, 1, 2, 0, 9, 8]
        );
        let health = Control::Health {
            node: node(7, "w"),
            state: HealthState::Warning,
        };
        assert_eq!(
            health.encode().unwrap(),
            [1, 4, 7, 7, 7, 7, 7, 7, 7, 7, 1, 0, b'w', 1]
        );
        let nodes = Control::NodesAnnounced {
            generation: 0x0201,
            part: 1,
            parts: 3,
            nodes: [node(2, "a"), node(1, "b")].into_iter().collect(),
            via: BTreeSet::new(),
        };
        assert_eq!(
            nodes.encode().unwrap(),
            [
                1, 3, 1, 2, 0, 0, 0, 0, 0, 0, 1, 0, 3, 0, 2, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
                b'b', 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, b'a'
            ]
        );
        // A relay's: version 2, the nodes through it after its own.
        let relayed = Control::NodesAnnounced {
            generation: 1,
            part: 0,
            parts: 1,
            nodes: [node(2, "a")].into_iter().collect(),
            via: [node(3, "c")].into_iter().collect(),
        };
        assert_eq!(relayed.version(), 2);
        assert_eq!(
            relayed.encode().unwrap(),
            [
                2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0,
                b'a', 1, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 1, 0, b'c'
            ]
        );
        let interest = Interest::everything();
        let mut want = vec![1, 2];
        want.extend_from_slice(&interest.encode());
        assert_eq!(Control::Interest(interest).encode().unwrap(), want);
    }

    #[test]
    fn decoding_refuses_what_is_not_a_message() {
        assert!(matches!(
            Control::decode(&[]),
            Err(CodecError::Truncated { .. })
        ));
        assert_eq!(Control::decode(&[3, 5]), Err(CodecError::UnknownVersion(3)));
        assert_eq!(Control::decode(&[0, 5]), Err(CodecError::UnknownVersion(0)));
        // Version 2 carries a relay's announcement alone.
        assert!(matches!(
            Control::decode(&[2, 5]),
            Err(CodecError::NotCanonical(_))
        ));
        let mut v1 = Control::NodesAnnounced {
            generation: 1,
            part: 0,
            parts: 1,
            nodes: [node(1, "a")].into_iter().collect(),
            via: BTreeSet::new(),
        }
        .encode()
        .unwrap();
        v1[0] = 2;
        assert!(
            matches!(Control::decode(&v1), Err(CodecError::Truncated { .. })),
            "a version 2 announcement without its second count"
        );
        v1.extend_from_slice(&[0, 0, 0, 0]);
        assert!(
            matches!(Control::decode(&v1), Err(CodecError::NotCanonical(_))),
            "a version 2 announcement naming none through its sender"
        );
        let both = Control::NodesAnnounced {
            generation: 1,
            part: 0,
            parts: 1,
            nodes: [node(1, "a")].into_iter().collect(),
            via: [node(1, "a")].into_iter().collect(),
        };
        assert!(matches!(both.encode(), Err(CodecError::NotCanonical(_))));
        let mut twice = v1.clone();
        twice.truncate(twice.len() - 4);
        twice.extend_from_slice(&[1, 0, 0, 0]);
        twice.extend_from_slice(&[1; 8]);
        twice.extend_from_slice(&[1, 0, b'a']);
        assert!(
            matches!(Control::decode(&twice), Err(CodecError::NotCanonical(_))),
            "a node in both lists"
        );
        assert_eq!(Control::decode(&[1, 0]), Err(CodecError::UnknownKind(0)));
        assert_eq!(Control::decode(&[1, 6]), Err(CodecError::UnknownKind(6)));
        assert_eq!(
            Control::decode(&[1, 5, 0]),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
        let mut bad_state = Control::Health {
            node: node(1, "w"),
            state: HealthState::Healthy,
        }
        .encode()
        .unwrap();
        *bad_state.last_mut().unwrap() = 6;
        assert_eq!(
            Control::decode(&bad_state),
            Err(CodecError::UnknownState(6))
        );
        // Generation 1, part 0 of 1, two nodes, the second before the first.
        let mut unsorted = vec![1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0];
        for daemon in [2u8, 1] {
            unsorted.extend_from_slice(&[daemon; 8]);
            unsorted.extend_from_slice(&[1, 0, b'a']);
        }
        assert!(matches!(
            Control::decode(&unsorted),
            Err(CodecError::NotCanonical(_))
        ));
        // A part outside its announcement's parts, which are 1 to 64.
        for (part, parts) in [(0, 0), (1, 1), (5, 3), (0, MAX_ANNOUNCE_PARTS + 1)] {
            let mut bad = vec![1, 3, 1, 0, 0, 0, 0, 0, 0, 0];
            bad.extend_from_slice(&u16::to_le_bytes(part));
            bad.extend_from_slice(&u16::to_le_bytes(parts));
            bad.extend_from_slice(&[0, 0, 0, 0]);
            assert_eq!(
                Control::decode(&bad),
                Err(CodecError::BadPart { part, parts }),
                "part {part} of {parts}"
            );
            let message = Control::NodesAnnounced {
                generation: 1,
                part,
                parts,
                nodes: BTreeSet::new(),
                via: BTreeSet::new(),
            };
            assert_eq!(message.encode(), Err(CodecError::BadPart { part, parts }));
        }
        let mut long_hello = vec![1, 1];
        long_hello.extend_from_slice(&u16::try_from(MAX_HELLO_BYTES + 1).unwrap().to_le_bytes());
        long_hello.resize(long_hello.len() + MAX_HELLO_BYTES + 1, 0);
        assert!(matches!(
            Control::decode(&long_hello),
            Err(CodecError::TooLarge {
                what: "a Hello",
                ..
            })
        ));
        assert!(matches!(
            Control::decode(&vec![1; MAX_CONTROL_BYTES + 1]),
            Err(CodecError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_message_past_its_cap_is_not_encoded() {
        assert!(matches!(
            Control::Hello(vec![0; MAX_HELLO_BYTES + 1]).encode(),
            Err(CodecError::TooLarge {
                what: "a Hello",
                ..
            })
        ));
        let many: BTreeSet<_> = (0..600u32)
            .map(|n| node(1, &format!("{n:0>120}")))
            .collect();
        let message = Control::NodesAnnounced {
            generation: 1,
            part: 0,
            parts: 1,
            nodes: many,
            via: BTreeSet::new(),
        };
        assert!(message.encoded_len() > MAX_CONTROL_BYTES);
        assert!(matches!(
            message.encode(),
            Err(CodecError::TooLarge {
                what: "a control message",
                ..
            })
        ));
    }

    #[test]
    fn a_health_state_names_itself_as_a_notice_does() {
        assert_eq!(HealthState::from(NodeState::Isolated).as_str(), "isolated");
        for state in [
            HealthState::Healthy,
            HealthState::Warning,
            HealthState::Restarting,
            HealthState::Isolated,
            HealthState::Degraded,
            HealthState::Detached,
        ] {
            assert_eq!(HealthState::from_code(state.code()), Ok(state));
        }
    }
}
