// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The clients a daemon announces to its peers (ADR-0021, item 6), those a
//! relay announces as reached through it (item 9), and the parts an
//! announcement too long for one control message is split into.

use std::collections::BTreeSet;

use crate::control::origin_len;
use crate::{CodecError, Control, QualifiedOrigin, CONTROL_HEADER_BYTES, MAX_CONTROL_BYTES};

/// The most parts an announcement is split into: 64. Each part is one
/// control message, so an announcement holds at least 64 times the
/// clients one message of the link's carries: some 30,000 at the longest
/// names, many more at common ones.
pub const MAX_ANNOUNCE_PARTS: u16 = 64;

/// The bytes a [`Control::NodesAnnounced`] spends before its nodes: the
/// header, the generation, the part, the count of parts and the count of
/// nodes. One that names nodes reached through its sender spends four more,
/// the count of those.
pub const ANNOUNCE_FIXED_BYTES: usize = CONTROL_HEADER_BYTES + 8 + 2 + 2 + 4;

/// The bytes the count of the nodes reached through the sender takes, in a
/// message that names any.
const VIA_COUNT_BYTES: usize = 4;

/// The clients attached to a daemon, as it announces them to its peers so
/// that they can address its clients ([`Router::route_to`]); and, from a
/// relay, the clients of its other peers, reached through it (its `via`).
///
/// An announcement replaces the one before it whole. Its generation is
/// the sender's count of announcements, which [`SummaryPacer`] stamps as it
/// does a summary's, so that a receiver keeps the newest. It goes as one
/// [`Control::NodesAnnounced`] when one fits the link's messages, and is
/// otherwise split into parts ([`Announcement::messages`]), each a run of
/// its clients in their order, its own first and then those reached
/// through it, and each naming the count of parts; the receiver takes it
/// once every part of its generation has arrived
/// ([`Router::announce_part`]).
///
/// [`Router::route_to`]: crate::Router::route_to
/// [`Router::announce_part`]: crate::Router::announce_part
/// [`SummaryPacer`]: crate::SummaryPacer
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Announcement {
    generation: u64,
    nodes: BTreeSet<QualifiedOrigin>,
    via: BTreeSet<QualifiedOrigin>,
}

impl Announcement {
    /// The announcement of `nodes`, the sender's own clients, at generation
    /// 0, naming none reached through the sender.
    #[must_use]
    pub fn new(nodes: BTreeSet<QualifiedOrigin>) -> Self {
        Self {
            generation: 0,
            nodes,
            via: BTreeSet::new(),
        }
    }

    /// The same announcement naming `via` as reached through its sender: a
    /// relay's other peers' clients ([`Router::via_for`]). A node among the
    /// sender's own is left out of them.
    ///
    /// [`Router::via_for`]: crate::Router::via_for
    #[must_use]
    pub fn with_via(mut self, mut via: BTreeSet<QualifiedOrigin>) -> Self {
        via.retain(|node| !self.nodes.contains(node));
        self.via = via;
        self
    }

    /// The same announcement at `generation`.
    #[must_use]
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// The sender's count of announcements when it sent this one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The sender's own clients it names.
    #[must_use]
    pub fn nodes(&self) -> &BTreeSet<QualifiedOrigin> {
        &self.nodes
    }

    /// The clients it names as reached through its sender.
    #[must_use]
    pub fn via(&self) -> &BTreeSet<QualifiedOrigin> {
        &self.via
    }

    /// Whether `other` names the same clients, its own and through it,
    /// whatever its generation.
    #[must_use]
    pub fn same_nodes(&self, other: &Self) -> bool {
        self.nodes == other.nodes && self.via == other.via
    }

    /// The control messages that carry it, each encoding to at most
    /// `max_bytes` (and never more than [`MAX_CONTROL_BYTES`]): one when it
    /// fits, and otherwise the fewest parts that do, filled in order, each
    /// a run of its clients in their order, its own before those through
    /// it, numbered from 0.
    ///
    /// # Errors
    ///
    /// [`CodecError::TooLarge`] when one client alone does not fit
    /// `max_bytes`, or the parts would number more than
    /// [`MAX_ANNOUNCE_PARTS`].
    pub fn messages(&self, max_bytes: usize) -> Result<Vec<Control>, CodecError> {
        let max_bytes = max_bytes.min(MAX_CONTROL_BYTES);
        let mut runs = Vec::new();
        let mut run = (BTreeSet::new(), BTreeSet::new());
        let mut len = ANNOUNCE_FIXED_BYTES;
        let entries = self
            .nodes
            .iter()
            .map(|node| (false, node))
            .chain(self.via.iter().map(|node| (true, node)));
        for (through, node) in entries {
            let size = origin_len(node);
            // The first node through the sender in a message brings the
            // count of them.
            let count = |run: &(BTreeSet<_>, BTreeSet<_>)| {
                if through && run.1.is_empty() {
                    VIA_COUNT_BYTES
                } else {
                    0
                }
            };
            let alone = ANNOUNCE_FIXED_BYTES + if through { VIA_COUNT_BYTES } else { 0 } + size;
            if alone > max_bytes {
                return Err(CodecError::TooLarge {
                    what: "a node in an announcement",
                    len: alone,
                    max: max_bytes,
                });
            }
            if len + count(&run) + size > max_bytes {
                runs.push(std::mem::take(&mut run));
                len = ANNOUNCE_FIXED_BYTES;
            }
            len += count(&run) + size;
            if through {
                run.1.insert(node.clone());
            } else {
                run.0.insert(node.clone());
            }
        }
        runs.push(run);
        let parts = u16::try_from(runs.len())
            .ok()
            .filter(|&parts| parts <= MAX_ANNOUNCE_PARTS)
            .ok_or_else(|| CodecError::TooLarge {
                what: "an announcement",
                len: self
                    .nodes
                    .iter()
                    .chain(&self.via)
                    .map(origin_len)
                    .sum::<usize>(),
                max: usize::from(MAX_ANNOUNCE_PARTS) * (max_bytes - ANNOUNCE_FIXED_BYTES),
            })?;
        Ok(runs
            .into_iter()
            .zip(0..)
            .map(|((nodes, via), part)| Control::NodesAnnounced {
                generation: self.generation,
                part,
                parts,
                nodes,
                via,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::DaemonId;

    fn nodes(n: usize, name_len: usize) -> BTreeSet<QualifiedOrigin> {
        (0..n)
            .map(|i| {
                let name = format!("{i:0>width$}", width = name_len);
                QualifiedOrigin::new(DaemonId::from_bytes([3; 8]), name).unwrap()
            })
            .collect()
    }

    fn parts_of(messages: &[Control]) -> Vec<(u64, u16, u16, usize)> {
        messages
            .iter()
            .map(|m| match m {
                Control::NodesAnnounced {
                    generation,
                    part,
                    parts,
                    nodes,
                    via,
                } => (*generation, *part, *parts, nodes.len() + via.len()),
                other => panic!("not an announcement: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn an_announcement_that_fits_is_one_message() {
        let announcement = Announcement::new(nodes(3, 5)).with_generation(9);
        let messages = announcement.messages(MAX_CONTROL_BYTES).unwrap();
        assert_eq!(parts_of(&messages), [(9, 0, 1, 3)]);
        assert_eq!(
            Announcement::default().messages(100).map(|m| parts_of(&m)),
            Ok(vec![(0, 0, 1, 0)]),
            "no clients is one empty message"
        );
    }

    #[test]
    fn a_longer_one_is_split_into_runs_that_each_fit() {
        // Each node: 8 bytes of id, 2 of length and 10 of name.
        let all = nodes(25, 10);
        let announcement = Announcement::new(all.clone()).with_generation(4);
        let max = ANNOUNCE_FIXED_BYTES + 10 * 20;
        let messages = announcement.messages(max).unwrap();
        assert_eq!(
            parts_of(&messages),
            [(4, 0, 3, 10), (4, 1, 3, 10), (4, 2, 3, 5)]
        );
        let mut joined = BTreeSet::new();
        let mut last = None;
        for message in &messages {
            assert!(message.encoded_len() <= max);
            assert_eq!(
                Control::decode(&message.encode().unwrap()).as_ref(),
                Ok(message)
            );
            let Control::NodesAnnounced { nodes, .. } = message else {
                unreachable!()
            };
            assert!(last < nodes.first().cloned(), "runs in order");
            last = nodes.last().cloned();
            joined.extend(nodes.iter().cloned());
        }
        assert_eq!(joined, all);
    }

    #[test]
    fn what_no_part_or_no_count_of_parts_can_carry_is_refused() {
        let one = Announcement::new(nodes(1, 30));
        assert!(matches!(
            one.messages(ANNOUNCE_FIXED_BYTES + 39),
            Err(CodecError::TooLarge { .. })
        ));
        assert!(one.messages(ANNOUNCE_FIXED_BYTES + 40).is_ok());
        let max = ANNOUNCE_FIXED_BYTES + 20;
        let fits = Announcement::new(nodes(usize::from(MAX_ANNOUNCE_PARTS), 10));
        assert_eq!(fits.messages(max).unwrap().len(), 64);
        let over = Announcement::new(nodes(usize::from(MAX_ANNOUNCE_PARTS) + 1, 10));
        assert!(matches!(
            over.messages(max),
            Err(CodecError::TooLarge {
                what: "an announcement",
                ..
            })
        ));
    }

    #[test]
    fn same_nodes_ignores_the_generation() {
        let a = Announcement::new(nodes(2, 3));
        assert!(a.same_nodes(&a.clone().with_generation(5)));
        assert!(!a.same_nodes(&Announcement::new(nodes(3, 3))));
        let through = a.clone().with_via(far(1, 3));
        assert!(!a.same_nodes(&through), "the nodes through it count");
        assert!(through.same_nodes(&through.clone().with_generation(2)));
    }

    /// `n` clients of another daemon's, named `name_len` bytes each.
    fn far(n: usize, name_len: usize) -> BTreeSet<QualifiedOrigin> {
        (0..n)
            .map(|i| {
                let name = format!("{i:0>width$}", width = name_len);
                QualifiedOrigin::new(DaemonId::from_bytes([9; 8]), name).unwrap()
            })
            .collect()
    }

    #[test]
    fn a_relays_announcement_carries_its_own_nodes_then_those_through_it() {
        let own = nodes(2, 4);
        let through = far(3, 4);
        let mut with_own = through.clone();
        with_own.extend(own.iter().cloned());
        let announcement = Announcement::new(own.clone())
            .with_via(with_own)
            .with_generation(6);
        assert_eq!(announcement.via(), &through, "its own are not through it");
        let messages = announcement.messages(MAX_CONTROL_BYTES).unwrap();
        assert_eq!(
            messages,
            [Control::NodesAnnounced {
                generation: 6,
                part: 0,
                parts: 1,
                nodes: own.clone(),
                via: through.clone(),
            }]
        );
        // Each node: 8 bytes of id, 2 of length and 4 of name, 14 in all;
        // room for three in a part with the 4 bytes the count of nodes
        // through the sender takes in a part that names any.
        let max = ANNOUNCE_FIXED_BYTES + VIA_COUNT_BYTES + 3 * 14;
        let messages = announcement.messages(max).unwrap();
        let mut got = (BTreeSet::new(), BTreeSet::new());
        for message in &messages {
            assert!(message.encoded_len() <= max, "{message:?}");
            assert_eq!(
                Control::decode(&message.encode().unwrap()).as_ref(),
                Ok(message)
            );
            let Control::NodesAnnounced { nodes, via, .. } = message else {
                unreachable!()
            };
            got.0.extend(nodes.iter().cloned());
            got.1.extend(via.iter().cloned());
        }
        assert_eq!(parts_of(&messages), [(6, 0, 2, 3), (6, 1, 2, 2)]);
        assert_eq!(got, (own, through));
        let lone = Announcement::new(BTreeSet::new()).with_via(far(1, 30));
        assert!(matches!(
            lone.messages(ANNOUNCE_FIXED_BYTES + 40 + 3),
            Err(CodecError::TooLarge { .. })
        ));
        assert!(lone.messages(ANNOUNCE_FIXED_BYTES + 40 + 4).is_ok());
    }
}
