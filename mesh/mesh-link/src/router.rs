// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The forwarding decision (ADR-0021, items 4 to 6 and 9).

use std::collections::{BTreeMap, BTreeSet};

use crate::{DaemonId, Interest, QualifiedOrigin, MAX_ANNOUNCE_PARTS};

/// Where a destination send goes ([`Router::route_to`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// The node is qualified by this daemon: the daemon delivers to its own
    /// client of that name, or refuses the send when none is attached.
    Local,
    /// The node is a client of this peer, which announced it.
    Peer(DaemonId),
    /// The node is a client of a daemon this one has no direct route to,
    /// and this peer, a relay this daemon trusts, announced it as reached
    /// through itself: the send goes to the relay, which forwards it to the
    /// node's daemon.
    Relay(DaemonId),
    /// No peer has announced the node: the daemon refuses the send with an
    /// error naming it.
    Unknown,
}

/// What a daemon knows of one peer.
#[derive(Debug, Clone, Default)]
struct Peer {
    /// Whether the peer says it relays (its Hello).
    relay: bool,
    /// The newest summary the peer sent, or `None` before its first.
    interest: Option<Interest>,
    /// The generation of the newest announcement the peer sent, or `None`
    /// before its first.
    nodes_generation: Option<u64>,
    /// The clients that announcement named as the peer's own.
    nodes: BTreeSet<QualifiedOrigin>,
    /// The clients it named as reached through the peer, a relay this
    /// daemon trusts; none for a peer it does not trust as one.
    via: BTreeSet<QualifiedOrigin>,
    /// The parts of a newer announcement that have arrived, until its last
    /// one does.
    gathering: Option<Gathering>,
}

/// The nodes of one part of an announcement: the sender's own, and those
/// through it.
type Part = (BTreeSet<QualifiedOrigin>, BTreeSet<QualifiedOrigin>);

/// The parts of one announcement gathered so far.
#[derive(Debug, Clone)]
struct Gathering {
    generation: u64,
    parts: u16,
    got: BTreeMap<u16, Part>,
}

/// A daemon's forwarding decisions: the peers it links to, the newest
/// interest summary each has sent, the clients its newest announcement
/// names, and which peers relay and which it trusts as relays.
///
/// [`Router::route_send`] is asked about a send of one of the daemon's own
/// clients, and names the peers to forward it to. A daemon that is not a
/// relay delivers what a peer forwards to its own subscribers and forwards
/// it no further. A relay also forwards it once more, to its other peers
/// whose summaries may match it ([`Router::route_relayed`]), and summarises
/// and announces its other peers to each of its peers
/// ([`Router::summary_for`], [`Router::via_for`]), so that a send crosses at
/// most one relay (the hop limit, [`ORIGIN_HOP_LIMIT`], holds it to that).
/// A peer is sent nothing until its first summary arrives, and envelopes
/// sent before then do not reach it, as none reach a peer whose link is
/// down.
///
/// # Relays and trust
///
/// A peer says in its Hello whether it relays ([`Router::set_relay`]),
/// which decides only whether a relay here sums its summaries up for its
/// other peers: relays do not aggregate one another's. Which peers' relayed
/// traffic the daemon accepts is its own configuration
/// ([`Router::trust_relay`]): the nodes a peer announces as reached through
/// it are taken from a trusted relay alone, and ignored from any other
/// peer. A trusted relay is authenticated as itself by its link, but what
/// it says of the daemons behind it is only as trustworthy as the relay:
/// nothing signs an envelope, an origin or an announcement end to end.
///
/// Peers are kept in the order of their ids, so every answer is the same
/// for the same state.
///
/// [`ORIGIN_HOP_LIMIT`]: crate::ORIGIN_HOP_LIMIT
#[derive(Debug, Clone)]
pub struct Router {
    local: DaemonId,
    peers: BTreeMap<DaemonId, Peer>,
    /// The peers trusted as relays, linked or not.
    trusted: BTreeSet<DaemonId>,
}

impl Router {
    /// A router for the daemon `local`, linked to no peer and trusting none
    /// as a relay.
    #[must_use]
    pub fn new(local: DaemonId) -> Self {
        Self {
            local,
            peers: BTreeMap::new(),
            trusted: BTreeSet::new(),
        }
    }

    /// The daemon this router decides for.
    #[must_use]
    pub fn local(&self) -> DaemonId {
        self.local
    }

    /// Trust `peer` as a relay from now on, whether it is linked or not:
    /// take the nodes it announces as reached through it, and let the
    /// daemon accept the forwards it relays for other daemons' clients.
    /// Returns false when it was trusted already.
    ///
    /// # Errors
    ///
    /// [`RouteError::LocalDaemon`] when `peer` is this daemon.
    pub fn trust_relay(&mut self, peer: DaemonId) -> Result<bool, RouteError> {
        if peer == self.local {
            return Err(RouteError::LocalDaemon);
        }
        Ok(self.trusted.insert(peer))
    }

    /// Whether `peer` is trusted as a relay.
    #[must_use]
    pub fn trusts_relay(&self, peer: DaemonId) -> bool {
        self.trusted.contains(&peer)
    }

    /// A link to `peer` is up: it starts with no summary and no nodes, not
    /// a relay until it says so. Returns false when the peer was linked
    /// already, which changes nothing.
    ///
    /// # Errors
    ///
    /// [`RouteError::LocalDaemon`] when `peer` is this daemon.
    pub fn add_peer(&mut self, peer: DaemonId) -> Result<bool, RouteError> {
        if peer == self.local {
            return Err(RouteError::LocalDaemon);
        }
        if self.peers.contains_key(&peer) {
            return Ok(false);
        }
        self.peers.insert(peer, Peer::default());
        Ok(true)
    }

    /// The link to `peer` is down, or a new session with it starts (its
    /// Hello): forget its summary and its nodes, and return those of the
    /// nodes it announced, its own and through it, that no other peer
    /// announces, which the daemon reports `detached`. `None` when the peer
    /// was not linked.
    pub fn remove_peer(&mut self, peer: DaemonId) -> Option<BTreeSet<QualifiedOrigin>> {
        let state = self.peers.remove(&peer)?;
        Some(
            state
                .nodes
                .into_iter()
                .chain(state.via)
                .filter(|node| !self.reaches(node))
                .collect(),
        )
    }

    /// The peers linked, in the order of their ids.
    pub fn peers(&self) -> impl Iterator<Item = DaemonId> + '_ {
        self.peers.keys().copied()
    }

    /// Whether `peer` is linked.
    #[must_use]
    pub fn has_peer(&self, peer: DaemonId) -> bool {
        self.peers.contains_key(&peer)
    }

    /// Record whether `peer` relays, as its Hello says. Returns whether
    /// that changed what was held.
    ///
    /// # Errors
    ///
    /// [`RouteError::UnknownPeer`] when `peer` is not linked.
    pub fn set_relay(&mut self, peer: DaemonId, relay: bool) -> Result<bool, RouteError> {
        let state = self
            .peers
            .get_mut(&peer)
            .ok_or(RouteError::UnknownPeer(peer))?;
        let changed = state.relay != relay;
        state.relay = relay;
        Ok(changed)
    }

    /// Whether `peer` is linked and says it relays.
    #[must_use]
    pub fn is_relay(&self, peer: DaemonId) -> bool {
        self.peers.get(&peer).is_some_and(|state| state.relay)
    }

    /// Take `interest` as `peer`'s summary when it is newer than the one
    /// held: its generation is higher, or none is held. Returns whether it
    /// was taken; an older or repeated summary, as a lossy link reorders or
    /// a refresh resends them, is not.
    ///
    /// # Errors
    ///
    /// [`RouteError::UnknownPeer`] when `peer` is not linked.
    pub fn update_interest(
        &mut self,
        peer: DaemonId,
        interest: Interest,
    ) -> Result<bool, RouteError> {
        let state = self
            .peers
            .get_mut(&peer)
            .ok_or(RouteError::UnknownPeer(peer))?;
        if state
            .interest
            .as_ref()
            .is_some_and(|held| interest.generation() <= held.generation())
        {
            return Ok(false);
        }
        state.interest = Some(interest);
        Ok(true)
    }

    /// The summary held for `peer`, if it has sent one.
    #[must_use]
    pub fn interest(&self, peer: DaemonId) -> Option<&Interest> {
        self.peers.get(&peer)?.interest.as_ref()
    }

    /// Take `nodes` as `peer`'s clients, replacing those it announced
    /// before, when the announcement is newer than the one held: its
    /// `generation` is higher, or none is held. Returns whether it was
    /// taken; an older or repeated announcement, as a lossy link reorders
    /// them, is not. This is [`Router::announce_part`] for an announcement
    /// of one part that names no node through the peer.
    ///
    /// # Errors
    ///
    /// As [`Router::announce_part`].
    pub fn announce_nodes(
        &mut self,
        peer: DaemonId,
        generation: u64,
        nodes: BTreeSet<QualifiedOrigin>,
    ) -> Result<bool, RouteError> {
        self.announce_part(peer, generation, 0, 1, nodes, BTreeSet::new())
    }

    /// Take `nodes`, the peer's own clients, and `via`, those it reaches as
    /// a relay, as part `part` of the `parts` that `peer`'s announcement
    /// `generation` has. Once every part of a generation newer than the one
    /// held has arrived, their clients together replace those held, and
    /// this returns true; it returns false for every other part. The
    /// clients through the peer are kept only when this daemon trusts the
    /// peer as a relay ([`Router::trust_relay`]), and are otherwise
    /// ignored.
    ///
    /// A part of the generation held, or of an older one, is ignored, as a
    /// refresh or a reordering link brings them; so is one of a generation
    /// older than the one being gathered. A part of a newer generation than
    /// the one being gathered drops the parts gathered, so that a lost part
    /// holds up only its own announcement: the sender's refresh sends every
    /// part again.
    ///
    /// # Errors
    ///
    /// [`RouteError::UnknownPeer`] when `peer` is not linked;
    /// [`RouteError::ForeignNode`] when one of `nodes` is not qualified by
    /// `peer`, since a peer's own clients are its own;
    /// [`RouteError::ViaNode`] when one of `via` is qualified by `peer` or
    /// by this daemon, which no relay reaches through itself; and
    /// [`RouteError::BadPart`] when `part` is not below `parts`, `parts` is
    /// 0 or above [`MAX_ANNOUNCE_PARTS`], or another part of the same
    /// generation gave another count. In every case the nodes held and the
    /// parts gathered stay as they were.
    pub fn announce_part(
        &mut self,
        peer: DaemonId,
        generation: u64,
        part: u16,
        parts: u16,
        nodes: BTreeSet<QualifiedOrigin>,
        via: BTreeSet<QualifiedOrigin>,
    ) -> Result<bool, RouteError> {
        let local = self.local;
        let trusted = self.trusted.contains(&peer);
        let state = self
            .peers
            .get_mut(&peer)
            .ok_or(RouteError::UnknownPeer(peer))?;
        if parts == 0 || parts > MAX_ANNOUNCE_PARTS || part >= parts {
            return Err(RouteError::BadPart { part, parts });
        }
        if let Some(node) = nodes.iter().find(|node| node.daemon() != peer) {
            return Err(RouteError::ForeignNode {
                peer,
                node: node.clone(),
            });
        }
        if let Some(node) = via
            .iter()
            .find(|node| node.daemon() == peer || node.daemon() == local)
        {
            return Err(RouteError::ViaNode {
                peer,
                node: node.clone(),
            });
        }
        if state
            .nodes_generation
            .is_some_and(|held| generation <= held)
        {
            return Ok(false);
        }
        match &mut state.gathering {
            Some(gathering) if gathering.generation > generation => return Ok(false),
            Some(gathering) if gathering.generation == generation => {
                if gathering.parts != parts {
                    return Err(RouteError::BadPart { part, parts });
                }
                gathering.got.insert(part, (nodes, via));
            }
            _ => {
                state.gathering = Some(Gathering {
                    generation,
                    parts,
                    got: BTreeMap::from([(part, (nodes, via))]),
                });
            }
        }
        let complete = state
            .gathering
            .as_ref()
            .is_some_and(|g| g.got.len() == usize::from(g.parts));
        if !complete {
            return Ok(false);
        }
        let Some(gathering) = state.gathering.take() else {
            return Ok(false);
        };
        state.nodes_generation = Some(gathering.generation);
        let (mut own, mut through) = (BTreeSet::new(), BTreeSet::new());
        for (nodes, via) in gathering.got.into_values() {
            own.extend(nodes);
            if trusted {
                through.extend(via);
            }
        }
        state.nodes = own;
        state.via = through;
        Ok(true)
    }

    /// The clients `peer` last announced as its own.
    #[must_use]
    pub fn nodes(&self, peer: DaemonId) -> Option<&BTreeSet<QualifiedOrigin>> {
        self.peers.get(&peer).map(|state| &state.nodes)
    }

    /// The clients `peer` last announced as reached through it, held when
    /// this daemon trusts it as a relay.
    #[must_use]
    pub fn via(&self, peer: DaemonId) -> Option<&BTreeSet<QualifiedOrigin>> {
        self.peers.get(&peer).map(|state| &state.via)
    }

    /// Whether some peer announces `node`, as its own or through it.
    #[must_use]
    pub fn reaches(&self, node: &QualifiedOrigin) -> bool {
        self.peers
            .values()
            .any(|state| state.nodes.contains(node) || state.via.contains(node))
    }

    /// Whether some peer announces a client of `daemon` as reached through
    /// it.
    #[must_use]
    pub fn relays_for(&self, daemon: DaemonId) -> bool {
        self.peers
            .values()
            .any(|state| state.via.iter().any(|node| node.daemon() == daemon))
    }

    /// The peers to forward a send of one of this daemon's clients to: each
    /// whose summary may match it ([`Interest::may_match`]), in the order of
    /// their ids. `type_name` is the send's type name, `None` when it names
    /// none.
    #[must_use]
    pub fn route_send(
        &self,
        channel: &str,
        type_id: u16,
        type_name: Option<&str>,
    ) -> Vec<DaemonId> {
        self.route_except(&[], channel, type_id, type_name)
    }

    /// The peers a relay forwards once more a send that the peer `from`
    /// forwarded it, a send of a client of the daemon `origin`: each whose
    /// summary may match it, but `from` and `origin`, in the order of their
    /// ids.
    #[must_use]
    pub fn route_relayed(
        &self,
        from: DaemonId,
        origin: DaemonId,
        channel: &str,
        type_id: u16,
        type_name: Option<&str>,
    ) -> Vec<DaemonId> {
        self.route_except(&[from, origin], channel, type_id, type_name)
    }

    fn route_except(
        &self,
        except: &[DaemonId],
        channel: &str,
        type_id: u16,
        type_name: Option<&str>,
    ) -> Vec<DaemonId> {
        self.peers
            .iter()
            .filter(|(peer, _)| !except.contains(peer))
            .filter(|(_, state)| {
                state
                    .interest
                    .as_ref()
                    .is_some_and(|interest| interest.may_match(channel, type_id, type_name))
            })
            .map(|(&peer, _)| peer)
            .collect()
    }

    /// Where a send to `dest` goes: this daemon, when `dest` is qualified
    /// by it; the peer that announced `dest` as its own; failing that, the
    /// first relay, in the order of their ids, that announced it as reached
    /// through it; or nowhere known. A direct route is always preferred.
    #[must_use]
    pub fn route_to(&self, dest: &QualifiedOrigin) -> Destination {
        if dest.daemon() == self.local {
            return Destination::Local;
        }
        if self
            .peers
            .get(&dest.daemon())
            .is_some_and(|state| state.nodes.contains(dest))
        {
            return Destination::Peer(dest.daemon());
        }
        self.peers
            .iter()
            .find(|(_, state)| state.via.contains(dest))
            .map_or(Destination::Unknown, |(&relay, _)| {
                Destination::Relay(relay)
            })
    }

    /// What a relay summarises to `peer` (ADR-0021, item 9): `local`, the
    /// summary of its own subscribers, together with the summaries of its
    /// other peers that are not relays ([`Interest::union`]), so that
    /// `peer` forwards it what those peers want. A peer's own summary is
    /// left out of what it is sent, and relays' summaries out of every
    /// one, so that a summary covers one relay's neighbourhood and no loop
    /// feeds a peer's interest back to it. At generation 0, and admitting
    /// everything when it would pass [`crate::MAX_INTEREST_BYTES`].
    #[must_use]
    pub fn summary_for(&self, peer: DaemonId, local: &Interest) -> Interest {
        self.peers
            .iter()
            .filter(|(&other, state)| other != peer && !state.relay)
            .filter_map(|(_, state)| state.interest.as_ref())
            .fold(local.union(&Interest::nothing()), |sum, interest| {
                sum.union(interest)
            })
    }

    /// The clients a relay announces to `peer` as reached through it
    /// (ADR-0021, item 9): those its other peers announced as their own.
    /// Not those they announced through them, which a send could reach only
    /// across a second relay, and not `peer`'s own.
    #[must_use]
    pub fn via_for(&self, peer: DaemonId) -> BTreeSet<QualifiedOrigin> {
        self.peers
            .iter()
            .filter(|(&other, _)| other != peer)
            .flat_map(|(_, state)| state.nodes.iter().cloned())
            .collect()
    }
}

/// Why a router refused what a link reported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// The daemon is not linked to this peer.
    #[error("no link to daemon {0}")]
    UnknownPeer(DaemonId),
    /// A daemon is not its own peer.
    #[error("a daemon does not link to itself")]
    LocalDaemon,
    /// A peer announced as its own a node another daemon qualifies.
    #[error("daemon {peer} announced {node}, a client of another daemon, as its own")]
    ForeignNode {
        /// The peer that announced it.
        peer: DaemonId,
        /// The node.
        node: QualifiedOrigin,
    },
    /// A peer announced as reached through it a node of its own, or of this
    /// daemon.
    #[error("daemon {peer} announced {node} as reached through it, a client of its own or of this daemon")]
    ViaNode {
        /// The peer that announced it.
        peer: DaemonId,
        /// The node.
        node: QualifiedOrigin,
    },
    /// A part of an announcement outside its parts, or whose count of parts
    /// is not its generation's.
    #[error("part {part} of {parts} is no part of an announcement this router gathers")]
    BadPart {
        /// The part.
        part: u16,
        /// The count of parts it gave.
        parts: u16,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_port_protocol::FilterSpec;

    fn id(n: u8) -> DaemonId {
        DaemonId::from_bytes([n; 8])
    }

    fn on(channel: &str) -> Interest {
        Interest::from_filters(&[FilterSpec {
            channel: Some(channel.into()),
            ..FilterSpec::default()
        }])
    }

    fn node(daemon: u8, name: &str) -> QualifiedOrigin {
        QualifiedOrigin::new(id(daemon), name).unwrap()
    }

    #[test]
    fn a_send_goes_to_the_peers_whose_summary_may_match_it() {
        let mut router = Router::new(id(0));
        for peer in [3, 1, 2] {
            assert_eq!(router.add_peer(id(peer)), Ok(true));
        }
        assert_eq!(router.add_peer(id(1)), Ok(false));
        assert_eq!(router.add_peer(id(0)), Err(RouteError::LocalDaemon));
        assert!(
            router.route_send("jobs/new", 0, None).is_empty(),
            "no summary yet"
        );
        router.update_interest(id(1), on("jobs/*")).unwrap();
        router.update_interest(id(2), on("metrics")).unwrap();
        router
            .update_interest(id(3), Interest::everything())
            .unwrap();
        assert_eq!(router.route_send("jobs/new", 0, None), [id(1), id(3)]);
        assert_eq!(router.route_send("metrics", 0, None), [id(2), id(3)]);
        assert_eq!(router.peers().collect::<Vec<_>>(), [id(1), id(2), id(3)]);
        assert_eq!(
            router.update_interest(id(9), on("x")),
            Err(RouteError::UnknownPeer(id(9)))
        );
    }

    #[test]
    fn an_older_or_repeated_summary_is_not_taken() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        assert_eq!(
            router.update_interest(id(1), on("a").with_generation(5)),
            Ok(true)
        );
        assert_eq!(
            router.update_interest(id(1), on("b").with_generation(4)),
            Ok(false)
        );
        assert_eq!(
            router.update_interest(id(1), on("b").with_generation(5)),
            Ok(false)
        );
        assert_eq!(router.route_send("a", 0, None), [id(1)]);
        assert_eq!(
            router.update_interest(id(1), on("b").with_generation(6)),
            Ok(true)
        );
        assert!(router.route_send("a", 0, None).is_empty());
        assert_eq!(router.interest(id(1)).unwrap().generation(), 6);
    }

    #[test]
    fn a_destination_is_local_announced_or_unknown() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        router.add_peer(id(2)).unwrap();
        router
            .announce_nodes(id(1), 1, [node(1, "worker")].into_iter().collect())
            .unwrap();
        assert_eq!(router.route_to(&node(0, "anyone")), Destination::Local);
        assert_eq!(
            router.route_to(&node(1, "worker")),
            Destination::Peer(id(1))
        );
        assert_eq!(router.route_to(&node(2, "worker")), Destination::Unknown);
        assert_eq!(router.route_to(&node(1, "other")), Destination::Unknown);
        assert_eq!(router.route_to(&node(7, "worker")), Destination::Unknown);
    }

    #[test]
    fn a_peer_announces_only_its_own_clients() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        let mine = [node(1, "a")].into_iter().collect();
        router.announce_nodes(id(1), 1, mine).unwrap();
        let foreign = [node(1, "b"), node(2, "c")].into_iter().collect();
        assert_eq!(
            router.announce_nodes(id(1), 2, foreign),
            Err(RouteError::ForeignNode {
                peer: id(1),
                node: node(2, "c")
            })
        );
        assert_eq!(
            router.nodes(id(1)).unwrap().iter().collect::<Vec<_>>(),
            [&node(1, "a")],
            "a refused announcement changes nothing"
        );
        let replaced = [node(1, "b")].into_iter().collect();
        assert_eq!(router.announce_nodes(id(1), 2, replaced), Ok(true));
        assert_eq!(router.route_to(&node(1, "a")), Destination::Unknown);
        assert_eq!(router.route_to(&node(1, "b")), Destination::Peer(id(1)));
    }

    #[test]
    fn an_older_or_repeated_announcement_is_not_taken() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        // Announced in the order 1, 2, 3; arriving as 1, 3, 2, 3.
        let first = [node(1, "a")].into_iter().collect::<BTreeSet<_>>();
        let second = [node(1, "a"), node(1, "b")]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let third = [node(1, "b")].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(router.announce_nodes(id(1), 1, first), Ok(true));
        assert_eq!(router.announce_nodes(id(1), 3, third.clone()), Ok(true));
        assert_eq!(router.announce_nodes(id(1), 2, second), Ok(false));
        assert_eq!(router.announce_nodes(id(1), 3, BTreeSet::new()), Ok(false));
        assert_eq!(router.nodes(id(1)), Some(&third));
        assert_eq!(
            router.route_to(&node(1, "a")),
            Destination::Unknown,
            "a left at 3"
        );
        assert_eq!(router.route_to(&node(1, "b")), Destination::Peer(id(1)));
    }

    #[test]
    fn an_announcement_in_parts_is_taken_once_every_part_has_arrived() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        let part = |names: &[&str]| names.iter().map(|n| node(1, n)).collect::<BTreeSet<_>>();
        assert_eq!(
            router.announce_part(id(1), 3, 1, 3, part(&["c", "d"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(
            router.announce_part(id(1), 3, 0, 3, part(&["a", "b"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(
            router.route_to(&node(1, "a")),
            Destination::Unknown,
            "not yet"
        );
        // A part of an older generation is ignored while 3 is gathered.
        assert_eq!(
            router.announce_part(id(1), 2, 0, 1, part(&["z"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(
            router.announce_part(id(1), 3, 2, 4, part(&["e"]), BTreeSet::new()),
            Err(RouteError::BadPart { part: 2, parts: 4 }),
            "another count for the same generation"
        );
        assert_eq!(
            router.announce_part(id(1), 3, 2, 3, part(&["e"]), BTreeSet::new()),
            Ok(true)
        );
        assert_eq!(router.nodes(id(1)), Some(&part(&["a", "b", "c", "d", "e"])));
        // Its parts again, as a refresh sends them, change nothing.
        assert_eq!(
            router.announce_part(id(1), 3, 0, 3, part(&["x"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(router.nodes(id(1)).unwrap().len(), 5);
    }

    #[test]
    fn a_newer_generation_drops_the_parts_gathered_of_an_older_one() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        let part = |names: &[&str]| names.iter().map(|n| node(1, n)).collect::<BTreeSet<_>>();
        router.announce_nodes(id(1), 1, part(&["held"])).unwrap();
        // Generation 2 loses its second part; generation 3 arrives whole.
        assert_eq!(
            router.announce_part(id(1), 2, 0, 2, part(&["a"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(
            router.announce_part(id(1), 3, 0, 1, part(&["b"]), BTreeSet::new()),
            Ok(true)
        );
        assert_eq!(
            router.announce_part(id(1), 2, 1, 2, part(&["c"]), BTreeSet::new()),
            Ok(false)
        );
        assert_eq!(router.nodes(id(1)), Some(&part(&["b"])));
        for (p, n) in [(0, 0), (1, 1), (0, MAX_ANNOUNCE_PARTS + 1)] {
            assert_eq!(
                router.announce_part(id(1), 9, p, n, BTreeSet::new(), BTreeSet::new()),
                Err(RouteError::BadPart { part: p, parts: n })
            );
        }
    }

    fn set<const N: usize>(nodes: [QualifiedOrigin; N]) -> BTreeSet<QualifiedOrigin> {
        nodes.into_iter().collect()
    }

    #[test]
    fn nodes_through_a_peer_are_taken_from_a_trusted_relay_alone() {
        let mut router = Router::new(id(0));
        for peer in [1, 2] {
            router.add_peer(id(peer)).unwrap();
        }
        assert_eq!(router.trust_relay(id(1)), Ok(true));
        assert_eq!(router.trust_relay(id(1)), Ok(false));
        assert_eq!(router.trust_relay(id(0)), Err(RouteError::LocalDaemon));
        assert!(router.trusts_relay(id(1)) && !router.trusts_relay(id(2)));
        let far = node(5, "far");
        let taken = router.announce_part(id(1), 1, 0, 1, set([node(1, "r")]), set([far.clone()]));
        assert_eq!(taken, Ok(true));
        assert_eq!(router.via(id(1)), Some(&set([far.clone()])));
        assert_eq!(router.route_to(&far), Destination::Relay(id(1)));
        // From a peer not trusted as a relay, its own nodes are taken and
        // those through it ignored.
        let other = node(6, "other");
        let taken = router.announce_part(id(2), 1, 0, 1, set([node(2, "b")]), set([other.clone()]));
        assert_eq!(taken, Ok(true));
        assert_eq!(router.via(id(2)), Some(&BTreeSet::new()));
        assert_eq!(router.route_to(&other), Destination::Unknown);
        assert_eq!(router.route_to(&node(2, "b")), Destination::Peer(id(2)));
        // No relay reaches its own clients, or this daemon's, through itself.
        for bad in [node(1, "own"), node(0, "here")] {
            assert_eq!(
                router.announce_part(id(1), 2, 0, 1, BTreeSet::new(), set([bad.clone()])),
                Err(RouteError::ViaNode {
                    peer: id(1),
                    node: bad
                })
            );
        }
        assert_eq!(
            router.via(id(1)),
            Some(&set([far])),
            "a refusal changes nothing"
        );
        assert!(router.relays_for(id(5)) && !router.relays_for(id(6)));
    }

    #[test]
    fn a_direct_route_is_preferred_and_a_node_another_peer_reaches_is_not_gone() {
        let mut router = Router::new(id(0));
        for peer in [1, 2, 3] {
            router.add_peer(id(peer)).unwrap();
            router.trust_relay(id(peer)).unwrap();
        }
        let c = node(3, "c");
        router.announce_nodes(id(3), 1, set([c.clone()])).unwrap();
        for relay in [2, 1] {
            router
                .announce_part(id(relay), 1, 0, 1, BTreeSet::new(), set([c.clone()]))
                .unwrap();
        }
        assert_eq!(router.route_to(&c), Destination::Peer(id(3)), "direct");
        assert_eq!(
            router.remove_peer(id(3)),
            Some(BTreeSet::new()),
            "still reached"
        );
        assert_eq!(
            router.route_to(&c),
            Destination::Relay(id(1)),
            "the first relay"
        );
        assert_eq!(router.remove_peer(id(1)), Some(BTreeSet::new()));
        assert_eq!(router.route_to(&c), Destination::Relay(id(2)));
        assert_eq!(
            router.remove_peer(id(2)),
            Some(set([c.clone()])),
            "gone now"
        );
        assert_eq!(router.route_to(&c), Destination::Unknown);
        assert!(!router.reaches(&c));
    }

    #[test]
    fn a_relay_passes_a_send_on_to_its_other_peers_alone() {
        let mut router = Router::new(id(0));
        for peer in [1, 2, 3] {
            router.add_peer(id(peer)).unwrap();
            router.update_interest(id(peer), on("jobs/*")).unwrap();
        }
        assert_eq!(router.route_send("jobs/x", 0, None), [id(1), id(2), id(3)]);
        assert_eq!(
            router.route_relayed(id(1), id(1), "jobs/x", 0, None),
            [id(2), id(3)],
            "never back to the peer it came from"
        );
        assert_eq!(
            router.route_relayed(id(1), id(3), "jobs/x", 0, None),
            [id(2)],
            "nor to its origin's daemon"
        );
        assert!(router
            .route_relayed(id(1), id(1), "other", 0, None)
            .is_empty());
    }

    #[test]
    fn a_relay_summarises_its_other_peers_that_are_not_relays_to_each() {
        let mut router = Router::new(id(0));
        for peer in [1, 2, 3] {
            router.add_peer(id(peer)).unwrap();
        }
        router.update_interest(id(1), on("one")).unwrap();
        router.update_interest(id(2), on("two")).unwrap();
        router.update_interest(id(3), on("three")).unwrap();
        assert_eq!(router.set_relay(id(3), true), Ok(true));
        assert_eq!(router.set_relay(id(3), true), Ok(false));
        assert!(router.is_relay(id(3)) && !router.is_relay(id(1)));
        assert_eq!(
            router.set_relay(id(9), true),
            Err(RouteError::UnknownPeer(id(9)))
        );
        let local = on("here").with_generation(7);
        let channels = |i: Interest| i.exact_channels().map(str::to_owned).collect::<Vec<_>>();
        // Split horizon: a peer's own summary is not sent back to it; and
        // the relay's is aggregated into none.
        assert_eq!(channels(router.summary_for(id(1), &local)), ["here", "two"]);
        assert_eq!(channels(router.summary_for(id(2), &local)), ["here", "one"]);
        assert_eq!(
            channels(router.summary_for(id(3), &local)),
            ["here", "one", "two"]
        );
        assert_eq!(router.summary_for(id(1), &local).generation(), 0);
        let health = Interest::from_filters(&[FilterSpec {
            health: true,
            channel: Some("h".into()),
            ..FilterSpec::default()
        }]);
        router
            .update_interest(id(2), health.with_generation(2))
            .unwrap();
        assert!(router.summary_for(id(1), &local).wants_health());
        assert!(!router.summary_for(id(2), &local).wants_health());
    }

    /// Two relays linked to each other, each with a peer that is not one:
    /// each tells the other what its own peer wants, and neither passes on
    /// what the other told it, so no summary carries a second relay's
    /// neighbourhood.
    #[test]
    fn relays_do_not_aggregate_one_anothers_summaries() {
        let (r1, r2, a, d) = (id(1), id(2), id(10), id(20));
        let mut one = Router::new(r1);
        let mut two = Router::new(r2);
        for (router, relay, peer, wants) in [(&mut one, r2, a, "a/x"), (&mut two, r1, d, "d/x")] {
            router.add_peer(relay).unwrap();
            router.add_peer(peer).unwrap();
            router.set_relay(relay, true).unwrap();
            router.update_interest(peer, on(wants)).unwrap();
        }
        let local = Interest::nothing();
        // Each relay's summary to the other: its own peer's interest.
        let from_one = one.summary_for(r2, &local).with_generation(1);
        let from_two = two.summary_for(r1, &local).with_generation(1);
        assert!(from_one.may_match("a/x", 0, None) && !from_one.may_match("d/x", 0, None));
        two.update_interest(r1, from_one).unwrap();
        one.update_interest(r2, from_two).unwrap();
        // What each tells its own peer leaves the other relay's out.
        let to_a = one.summary_for(a, &local);
        let to_d = two.summary_for(d, &local);
        assert!(!to_a.may_match("d/x", 0, None), "{to_a:?}");
        assert!(!to_d.may_match("a/x", 0, None), "{to_d:?}");
        assert_eq!(to_a, Interest::nothing());
        // And what each tells the other is unchanged by what it heard.
        assert!(!one.summary_for(r2, &local).may_match("d/x", 0, None));
        assert!(!two.summary_for(r1, &local).may_match("a/x", 0, None));
        // A relay still forwards to the other what the other's summary
        // admits: one relay's hop, which the hop limit ends there.
        assert_eq!(one.route_relayed(a, a, "d/x", 0, None), [r2]);
    }

    #[test]
    fn a_relay_announces_its_other_peers_own_nodes_through_it() {
        let mut router = Router::new(id(0));
        for peer in [1, 2, 3] {
            router.add_peer(id(peer)).unwrap();
        }
        router.trust_relay(id(3)).unwrap();
        router
            .announce_nodes(id(1), 1, set([node(1, "a")]))
            .unwrap();
        router
            .announce_nodes(id(2), 1, set([node(2, "b")]))
            .unwrap();
        router
            .announce_part(id(3), 1, 0, 1, set([node(3, "c")]), set([node(7, "far")]))
            .unwrap();
        assert_eq!(router.via_for(id(1)), set([node(2, "b"), node(3, "c")]));
        assert_eq!(
            router.via_for(id(3)),
            set([node(1, "a"), node(2, "b")]),
            "not what it reaches through another relay"
        );
    }

    #[test]
    fn a_peer_removed_takes_its_nodes_and_its_summary_with_it() {
        let mut router = Router::new(id(0));
        router.add_peer(id(1)).unwrap();
        router
            .update_interest(id(1), on("a").with_generation(3))
            .unwrap();
        let nodes: BTreeSet<_> = [node(1, "x"), node(1, "y")].into_iter().collect();
        router.announce_nodes(id(1), 4, nodes.clone()).unwrap();
        assert_eq!(router.remove_peer(id(1)), Some(nodes.clone()));
        assert_eq!(router.remove_peer(id(1)), None);
        assert!(router.route_send("a", 0, None).is_empty());
        assert_eq!(router.route_to(&node(1, "x")), Destination::Unknown);
        // A new session starts afresh: generation 1 is taken again.
        router.add_peer(id(1)).unwrap();
        assert_eq!(
            router.update_interest(id(1), on("a").with_generation(1)),
            Ok(true)
        );
        assert_eq!(router.announce_nodes(id(1), 1, nodes), Ok(true));
    }
}
