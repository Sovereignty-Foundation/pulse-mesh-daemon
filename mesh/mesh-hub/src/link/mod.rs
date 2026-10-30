// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Links to other daemons (ADR-0021): daemons that link to each other over
//! sealed UDP (ADR-0018) and forward their clients' sends one hop, to the
//! peers whose subscribers may want them, or two through a relay
//! ([Relays](#relays)); announce their clients to each other, so that a send
//! addressed to one client reaches it on whichever daemon it is attached
//! to; and report their clients' health to each other's watchers. Off
//! unless configured ([`LinkConfig`]).
//!
//! **A relayed origin is only as trustworthy as its relay.** A link
//! authenticates the daemon at its other end and nothing more: no envelope,
//! origin or announcement is signed end to end. A daemon takes a forward of
//! another daemon's client, the nodes announced as reached through a peer,
//! and their health, only from a peer it trusts as a relay
//! (`--link-trust-relay`), and the origin such a forward carries is what
//! that relay says it is.
//!
//! # Configuration
//!
//! A daemon links when it is given three things: its node key, an X25519 key
//! pair ([`NodeKey`], `--node-key`, loaded or generated into a file of mode
//! `0o600`); the UDP address its links use (`--link-bind`); and its peers,
//! each named by the public half of its node key, as 64 hex digits, and
//! either by the address its links use too (`--link-peer ADDR=PUBKEY`,
//! [`LinkPeer`]) or by its key alone (`--link-peer-key PUBKEY`,
//! [`LinkConfig::peer_keys`]), its address then learned from its
//! announcements on a LAN ([Finding peers on a LAN](#finding-peers-on-a-lan)).
//! Only the configured peers' keys are admitted, so a daemon whose key is
//! not configured cannot link (its handshakes are refused, and counted).
//! The two kinds of peer are trusted differently: one named with an address
//! is admitted only from that address's IP, and one named by its key alone
//! from any address its handshake comes from, its key authenticated by the
//! handshake as any peer's is. A daemon is named across links by its
//! [`DaemonId`], the fingerprint of its public key that `mesh-link` defines;
//! it is logged at startup with the link address and the peers.
//!
//! # Transport
//!
//! One sealed UDP endpoint (`pulse_wire_udp::bind_sealed_pair` on the link
//! address, its allowlist the peers' keys) carries every link: one Noise IK
//! session per peer, each datagram sealed. Fragmentation and reassembly are
//! on, so a datagram's envelope may be up to `pulse_wire_udp::MAX_MESSAGE`
//! long, sent as a run of sealed fragments; a control message is held to
//! `mesh_link::MAX_CONTROL_BYTES` besides, whatever that allows. Three threads drive it,
//! so that the daemon's async code never waits on UDP: one sends (forwards,
//! summaries, announcements, health reports, heartbeats and Hellos, from a
//! bounded queue), one receives, and one makes the sealed sessions
//! ([Connecting](#connecting)); with LAN announcement a fourth, on sockets
//! of its own, sends and hears the announcements
//! ([Finding peers on a LAN](#finding-peers-on-a-lan)). A datagram is the
//! peer's whose sealed session opened
//! it, as the transport reports it (`pulse_wire_udp::RecvMeta::sealed_by`),
//! never the peer's whose address it came from, since a peer can forge a
//! source address; one whose Pulse claims another daemon than that key's,
//! or that forwards another daemon's client from a peer not trusted as a
//! relay, is refused and counted.
//! Backpressure, NACK, FEC and
//! the transport's in-order delivery are not enabled: a link delivers at most
//! once (the sealed replay window drops a repeated datagram), summaries and
//! announcements carry their generation so that an older one is ignored, and
//! a forward needs no order.
//!
//! # Datagrams
//!
//! Each datagram is a data frame (or a run of fragments) of the UDP
//! transport: a Data pulse, its `origin_id` the sending daemon's id in its
//! first eight bytes, its envelope reference the id of the envelope it
//! carries, its `chain_step` on a forward the hops it may still take (2,
//! `mesh_link::ORIGIN_HOP_LIMIT`, from its origin's daemon, 1 from a relay;
//! 0 from a build before relays, and on a control message), and that
//! envelope's canonical bytes. The envelope has type 0, a zero origin and
//! time, a raw payload, and one of two type names:
//!
//! - `pms.link/v0/control`: the payload is a control message in
//!   `mesh_link::Control`'s canonical encoding (a Hello, an interest
//!   summary, an announcement or a part of one, a health report, a
//!   heartbeat): version 1, or version 2 for a relay's announcement that
//!   names nodes reached through it, which a build before relays refuses.
//! - `pms.link/v0/forward`: the payload is a forwarded envelope, integers
//!   little-endian:
//!
//! ```text
//! u8   version (1)
//! u8   flags: bit 0 set when the send named its type name, bit 1 when it
//!      is addressed to one node; others zero
//! [8]  the origin's daemon id
//! u16  the origin's name length, then its UTF-8 (at most 128 bytes)
//! u16  the channel's length, then its UTF-8 (at most 256 bytes)
//! with bit 1:
//!   [8]  the destination's daemon id, the receiver's
//!   u16  the destination's name length, then its UTF-8 (at most 128)
//! ...  the forwarded envelope's canonical bytes, to the end
//! ```
//!
//! The forwarded envelope is the copy the sending daemon's hub stamped: its
//! canonical `mono_ns` is the hub's `monotonic_nanos`, which, with its id and
//! its qualified origin, is the key the receiver's forward cache knows a
//! send by (`mesh_link::ForwardKey`). The link envelope around it costs 73
//! bytes and the header above 14 more and the two texts (and an addressed
//! one 10 more and the destination's name), so the largest envelope a
//! forward carries is that much short of `pulse_wire_udp::MAX_MESSAGE`; a
//! longer one is not forwarded, and is counted.
//!
//! A Hello's bytes (inside `Control::Hello`) are `mesh-capability`'s 48-byte
//! Hello, then a flags byte whose bit 0 says that it answers one and bit 1
//! that its sender relays (`--link-relay`). A Hello that does not answer is
//! answered.
//!
//! # A link's life
//!
//! The first control message on a link is a Hello, sent inside the sealed
//! session (ADR-0018, item 8). A daemon that holds a sealed session to a peer
//! whose link is not up sends it a Hello, again with a backoff from 250 ms to
//! 5 s until one comes back. A Hello received starts the link afresh: the
//! peer's summary and announced nodes are forgotten
//! (`mesh_link::Router::remove_peer`, then `add_peer`), those nodes reported
//! `detached` to the watchers here, the negotiated capabilities are
//! recorded, the link is up, and the receiver answers (unless the Hello was
//! an answer) and sends its latest summary and announcement at once. An
//! answer that arrives once the link is up resets nothing: it completes the
//! start this daemon asked for, and a summary the peer sent after it may
//! have overtaken it on the way. A link that hears nothing from its peer for
//! the silence limit (5 s by default) goes down: its peer is forwarded
//! nothing until the next Hello, and its announced nodes are reported
//! `detached` and forgotten. While up, a link that has sent nothing for the
//! heartbeat interval (1 s by default) sends a heartbeat.
//!
//! # Connecting
//!
//! The connect thread keeps a sealed session to every peer. One attempt
//! sends an initiation and waits 250 ms for the response; a peer that does
//! not answer is tried again after a backoff from 100 ms to 5 s. When two
//! nodes' initiations cross, the lower key's stands while it is fresh, a
//! second old at most (the sealed transport's resend interval,
//! `CONNECT_RESEND`), and the higher key's is refused. So a daemon whose
//! key is the lower starts its attempts to a peer at least two seconds
//! apart: each of its unanswered initiations blocks the peer's for its first
//! second and leaves the peer the next, in which the peer's own handshake
//! is answered. A peer that reaches this daemon from where this daemon does
//! not reach it (its configured IP but another port, say) then makes its
//! session within about a second of trying, where back-to-back attempts
//! here kept it waiting for several. A daemon whose key is the higher keeps
//! the plain backoff, since its initiations never block the lower key's.
//! A peer named by its key alone is tried only once its address is known
//! (below).
//!
//! # Finding peers on a LAN
//!
//! With an [`AnnounceConfig`] (`--link-announce GROUP:PORT`, an IPv4
//! multicast group; off by default), a daemon announces where its links
//! are, at startup and every [`ANNOUNCE_INTERVAL`] (5 s), and hears the other
//! daemons' announcements on the same group. An announcement is one
//! plaintext data frame of the UDP transport (`pulse_wire_udp::multicast`)
//! sent to the group with a TTL of 1 by default (`--link-announce-ttl`), so
//! that it stays on the local network, and looped back to the daemons on
//! this host. Its Pulse is a Data pulse whose `origin_id` begins with the
//! daemon's id; its envelope is the announcement, 47 bytes, integers
//! little-endian:
//!
//! ```text
//! [4]  magic: PMLA
//! u8   version (1)
//! [32] the public half of the daemon's node key
//! u16  the port of its link address, not zero
//! [8]  its daemon id: the fingerprint of that key
//! ```
//!
//! The address is the datagram's source: the announcement's sender is bound
//! to the link address's IP, and sends and joins on that IP's interface
//! when it is not the wildcard. Bytes on the group that are not an
//! announcement are dropped; this daemon's own announcement, looped back,
//! is passed over; one from a key that is not a configured peer's is
//! ignored, and counted; and a repeat (a network may deliver a multicast
//! datagram twice) changes nothing.
//!
//! An announcement is a hint of where a peer's links are, not a credential,
//! and is not signed: a node key is an X25519 key, which agrees secrets and
//! cannot sign (ADR-0018, item 6). It is acted on only for a configured key
//! to which no sealed session exists, and then asks the connect thread for
//! one handshake: at the announced address for a peer named by its key
//! alone, or at the fixed address of a peer named with one, which no
//! announcement changes. Announcements make at most one handshake per key
//! every [`ANNOUNCE_INTERVAL`], so that forged ones cannot make a daemon
//! flood handshakes, and the handshake authenticates the key: an
//! announcement that names a configured key at an address where that key is
//! not costs one handshake that fails. A key-only peer's address is taken
//! from a handshake made there that succeeded, or from where the datagrams
//! its sealed session opens come from (as when the peer, hearing this
//! daemon's announcement, makes the session itself, or comes back at another
//! port), and never when another peer's link uses that address. What a
//! forger on the LAN can still do is spend each key's handshake on a wrong
//! address every 5 s, and so delay the finding of a peer that has no session
//! yet, or prevent it: a denial of service, which ADR-0018 does not defend
//! against.
//!
//! # Interest and forwarding
//!
//! Whenever the daemon's subscriptions change (a subscribe, an unsubscribe,
//! a connection's close), the links recompute the interest summary from
//! every subscription's filter and hand it to each peer's
//! `mesh_link::SummaryPacer`, which sends it to the peer at most four times
//! a second, and again every 5 s while it does not change. A summary longer
//! than a control datagram carries is sent coarsened, admitting everything.
//! A relay's summary to each peer covers its other peers too
//! ([Relays](#relays)).
//!
//! After a client's send is published here, it is forwarded, as the hub
//! stamped it, to each peer whose summary may match it
//! (`mesh_link::Router::route_send`), with the sender's qualified origin:
//! this daemon's id and the client's attach name, or, for a client that
//! proved a key at attach, the name the key gives it (`name@` and the key's
//! 32 hex digits). A peer whose summary cannot match is sent nothing.
//!
//! An envelope a peer forwards goes through the forward cache, which drops
//! an exact duplicate (as a copy that arrives directly and another through a
//! relay are), and is then queued for this daemon's subscriptions that
//! match it as an event whose `origin` is the qualified origin's text. A
//! daemon that does not relay forwards it no further, so that without
//! relays the configured daemons form a full mesh of direct links.
//!
//! It is not published into this daemon's hub either: neither stored nor
//! signalled on its ring, so processes attached to the hub by name see this
//! host's sends alone. A peer forwards only what this daemon's subscriptions
//! ask for, and the processes attached by name state no interest, so what
//! they would see of other hosts would depend on what the socket clients
//! happen to subscribe to; a process that wants other hosts' sends
//! subscribes through the daemon.
//!
//! Delivery across a link is what the transport gives (ADR-0021, item 8): at
//! most once, in no promised order, and nothing sent while a link is down
//! reaches its peer later.
//!
//! # Announcements
//!
//! Each daemon announces its attached clients to every peer whose link is
//! up (`mesh_link::Control::NodesAnnounced`), each by its qualified origin as
//! its sends carry it: this daemon's id and the client's attach name, or,
//! for a client that proved a key, `name@` and the key's 32 hex digits (a
//! client whose qualified name would pass 128 bytes is left out, as its
//! sends are not forwarded). The announcement is paced like the interest
//! summary: on an attach or a detach it is remade and handed to a pacer of
//! its own (`mesh_link::SummaryPacer`, by the same `PacerConfig`), which
//! sends it at most four times a second, and again every 5 s while it does
//! not change; a peer whose link starts is sent the latest at once. Each
//! announcement carries the next generation, and the receiver keeps the
//! newest (`mesh_link::Router::announce_part`). One too long for a control
//! datagram is split rather than coarsened: into the fewest parts that fit,
//! each a run of the clients in their order naming its part and the count
//! of parts (at most 64, `mesh_link::MAX_ANNOUNCE_PARTS`), and the receiver
//! takes it once every part of its generation has arrived; a part lost
//! holds up only its own generation, which the refresh sends again. The
//! nodes an announcement drops are reported `detached` to the watchers here.
//!
//! # Destinations
//!
//! A send whose `to` names a node a peer announced (`HubBridge::send_to`) is
//! forwarded to that peer alone, addressed (bit 1 above), stamped with the
//! hub's clock as a forward by interest is, and never to another peer; one
//! whose node only a trusted relay announced, as reached through it, goes
//! to that relay ([Relays](#relays)). The receiver checks that the
//! destination is its own client and that the sender is the peer's, or a
//! trusted relay's, passes it through the forward cache, and delivers it to
//! that client's connection alone, on its subscriptions that match it, with
//! the qualified origin; a daemon that does not relay refuses one addressed
//! to another daemon's client. A forward addressed to a client no longer
//! attached there is dropped, and counted.
//!
//! # Health across links
//!
//! A peer that watches health is one whose summary says so
//! (`mesh_link::Interest::wants_health`: one of its subscriptions sets
//! `health`). Each change of an attached node's state here (the
//! `HealthTracker`'s, not a detach, which the next announcement carries) is
//! reported to every such peer whose link is up as a
//! `mesh_link::Control::Health` naming the node by its qualified origin; and
//! a peer whose newer summary watches health is sent the state of every
//! node here that is not healthy, so that it starts from what this daemon
//! knows, at link start and after. The reports are made in the order the
//! states changed. A report received from a peer, about one of the peer's
//! own clients, or from a trusted relay about a node it relays (any other is
//! refused, and counted), is handed to this daemon's `HealthTracker`, which
//! tells its watchers in the same `health` notices as for its own nodes,
//! with the qualified node id, and lists the remote nodes that are not
//! healthy in a new watcher's first notices. While the summary this daemon
//! last sent a peer does not watch health, it takes no report from that
//! peer and forgets those it held of the peer's nodes and of those it
//! relays: the peer has stopped sending them.
//!
//! # Relays
//!
//! A daemon started with `--link-relay` ([`LinkConfig::relay`]) relays for
//! its peers (ADR-0021, item 9), so that daemons that are not linked to one
//! another reach each other through it. It says so in its Hello.
//!
//! - **Forwarding.** A forward a peer P sent it, of a client of P's own,
//!   with a hop left once it spends one (`mesh_link::next_hop`), is
//!   delivered here and passed on, with that hop spent, to its other peers
//!   whose summaries may match it (`mesh_link::Router::route_relayed`),
//!   never back to P and never to its origin's daemon, as the relay's own
//!   datagram whose origin is still the sending client's qualified id. A
//!   forward that came through a relay already, whatever its hop limit
//!   says, and one with no hop left, goes no further; so does any forward a
//!   daemon that is not a relay receives. A send therefore crosses at most
//!   one relay. The relay passes each send on once, from the first copy
//!   with a hop to spare, which may follow one with none, as the forward
//!   cache delivers it once.
//! - **Interest.** Its summary to each peer Q is its own subscribers'
//!   summary together with the latest summaries of its other peers that are
//!   not relays, Q's own left out (`mesh_link::Router::summary_for`, a split
//!   horizon), remade whenever any of them changes, paced and coarsened as
//!   any summary is. It tells relays from the other peers by their Hellos,
//!   and does not sum relays' summaries up, so that no summary carries more
//!   than one relay's neighbourhood and no loop feeds a peer's interest back
//!   to it. A daemon that is not a relay sends its own subscribers' summary
//!   alone.
//! - **Announcements and destinations.** Its announcement to Q names its own
//!   clients and, as reached through it, the clients its other peers
//!   announced as their own, Q's left out (`mesh_link::Router::via_for`;
//!   control version 2). A receiver that trusts it takes those, and a send
//!   whose `to` names one goes to the peer that announced the node as its
//!   own when there is one, and otherwise to the relay
//!   (`mesh_link::Destination::Relay`), which forwards it, a hop spent, to
//!   the node's daemon alone; one that names no node any peer announced is
//!   refused with `unknown_destination` as before. A node that no peer
//!   announces any longer, as when the relay's link to the node's daemon
//!   goes down, is reported `detached`.
//! - **Health.** A report from P about one of P's own nodes is passed on to
//!   every other peer whose summary watches health, and a peer whose newer
//!   summary watches health is sent, besides the nodes here, the nodes of
//!   the other peers held not healthy. A receiver takes a report about a
//!   node of a daemon it links to directly from that daemon alone.
//!
//! **Trust.** A forward whose origin is not the sending peer's own daemon's
//! client, a node announced as reached through a peer, and a health report
//! about such a node, are taken only from a peer this daemon trusts as a
//! relay (`--link-trust-relay`, [`LinkConfig::trusted_relays`], each a
//! configured peer's key); from any other peer the forward and the report
//! are refused and counted (`relayed_refused`, and `datagrams_refused`),
//! and the announced nodes ignored. Whether a peer says it relays changes
//! none of this. The sealed session authenticates the relay itself, but
//! nothing signs an envelope end to end: the origin a relay reports for
//! what it relays, and the nodes it says it reaches, are only as
//! trustworthy as the relay.

pub(crate) mod announce;
pub(crate) mod wire;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::{SocketAddr, SocketAddrV4};
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mesh_capability::{CapabilityFlags, CapabilityNegotiator, Hello, NegotiationOutcome};
use mesh_health::NodeState;
use mesh_link::{
    hops_left, next_hop, with_hop_limit, Announcement, Control, Destination, ForwardCache,
    ForwardKey, HealthState, Interest, QualifiedOrigin, Router, SummaryPacer, ORIGIN_HOP_LIMIT,
};
use parking_lot::Mutex;
use pulse_canon::{Pulse, PulseEnvelope};
use pulse_wire_udp::{
    bind_sealed_pair_with, Allowlist, ReassemblyConfig, Receiver, RecvMeta, SealError, Sealing,
    Sender, SenderError,
};
use tracing::{debug, info, warn};

use crate::hub_bridge::{Delivery, Subscribers};
use crate::registry::{Origin, Registry};
use wire::{Datagram, HelloFlags, LinkForward, Message};

pub use mesh_link::{DaemonId, PacerConfig};
pub use pulse_wire_udp::{NodeKey, PublicKey, SealingConfig};

/// How long a link may send nothing before it sends a heartbeat, by default:
/// one second.
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(1);

/// How long a link may hear nothing from its peer before it goes down, by
/// default: five seconds.
pub const DEFAULT_SILENCE: Duration = Duration::from_secs(5);

/// How long one attempt to make a sealed session waits for its response.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

/// The first and the longest wait between attempts to make a session.
const CONNECT_BACKOFF: (Duration, Duration) = (Duration::from_millis(100), Duration::from_secs(5));

/// The sealed transport's resend interval: how long an unanswered
/// initiation of the lower key's counts as crossing the peer's. A daemon
/// whose key is the lower starts its attempts to a peer at least twice this
/// apart ([`next_attempt`]).
const CONNECT_RESEND: Duration = Duration::from_secs(1);

/// The first and the longest wait between Hellos to a peer whose link is
/// not up.
const HELLO_BACKOFF: (Duration, Duration) = (Duration::from_millis(250), Duration::from_secs(5));

/// The receive thread's read timeout, which bounds how long it takes to
/// notice a stop.
const RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// The longest the send thread waits before it looks at its timers again.
const MAX_TICK: Duration = Duration::from_millis(100);

/// Items the send thread's queue holds; a forward that finds it full is
/// dropped and counted.
const OUTBOUND_QUEUE: usize = 4096;

/// The most queued items the send thread takes between two looks at its
/// timers.
const BATCH: usize = 256;

/// How often a daemon announces itself on its LAN group, and the least
/// time between two handshakes that announcements make with one peer: five
/// seconds.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

/// The TTL of a LAN announcement by default: 1, the local network.
pub const DEFAULT_ANNOUNCE_TTL: u32 = 1;

/// Where a daemon announces its link endpoint on a LAN, and hears the other
/// daemons' announcements ([Finding peers on a LAN](crate::link#finding-peers-on-a-lan)):
/// an IPv4 multicast group and port (`--link-announce`), and how far the
/// announcements travel (`--link-announce-ttl`). Build it with
/// [`AnnounceConfig::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnounceConfig {
    /// The multicast group, its first byte 224 to 239, and the port; a
    /// group whose first byte is 239, the administratively scoped range,
    /// suits a deployment's own use.
    pub group: SocketAddrV4,
    /// The announcements' TTL, 1 to 255; [`DEFAULT_ANNOUNCE_TTL`], the
    /// local network, by default.
    pub ttl: u32,
}

impl AnnounceConfig {
    /// Announcements on `group`, with the default TTL.
    #[must_use]
    pub fn new(group: SocketAddrV4) -> Self {
        Self {
            group,
            ttl: DEFAULT_ANNOUNCE_TTL,
        }
    }

    /// These announcements with the TTL `ttl`.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Refuse a group that is not one, or a TTL out of range.
    fn check(&self) -> Result<(), LinkSetupError> {
        if !self.group.ip().is_multicast() || self.group.port() == 0 {
            return Err(LinkSetupError::AnnounceGroup { group: self.group });
        }
        if !(1..=255).contains(&self.ttl) {
            return Err(LinkSetupError::AnnounceTtl { ttl: self.ttl });
        }
        Ok(())
    }
}

/// A daemon to link to: the address its links use and the public half of
/// its node key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkPeer {
    /// The peer's link address (its `--link-bind`), as this daemon reaches
    /// it.
    pub addr: SocketAddr,
    /// The public half of the peer's node key.
    pub key: PublicKey,
}

impl LinkPeer {
    /// The daemon at `addr` whose node key's public half is `key`.
    #[must_use]
    pub fn new(addr: SocketAddr, key: PublicKey) -> Self {
        Self { addr, key }
    }

    /// The id the peer is named by across links.
    #[must_use]
    pub fn daemon_id(&self) -> DaemonId {
        DaemonId::from_public_key(self.key.as_bytes())
    }
}

impl fmt::Display for LinkPeer {
    /// `ADDR=PUBKEY`, as `--link-peer` takes it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.addr, self.key)
    }
}

impl FromStr for LinkPeer {
    type Err = LinkPeerError;

    /// `ADDR=PUBKEY`: an IP address and port, `=`, and 64 hex digits.
    fn from_str(text: &str) -> Result<Self, LinkPeerError> {
        let (addr, key) = text.rsplit_once('=').ok_or(LinkPeerError::NoKey)?;
        let addr = addr
            .parse()
            .map_err(|_| LinkPeerError::Address(addr.to_string()))?;
        let key = PublicKey::from_hex(key).map_err(|e| LinkPeerError::Key(e.to_string()))?;
        Ok(Self { addr, key })
    }
}

/// Why a text is not a [`LinkPeer`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkPeerError {
    /// The text has no `=` between an address and a key.
    #[error("a link peer is ADDR=PUBKEY, and this has no '='")]
    NoKey,
    /// What comes before the `=` is not an IP address and port.
    #[error("{0:?} is not an IP address and port, such as 192.0.2.7:7400 or [2001:db8::7]:7400")]
    Address(String),
    /// What comes after the `=` is not 64 hex digits.
    #[error("the peer's public key is not 64 hex digits: {0}")]
    Key(String),
}

/// How a daemon links to other daemons: its node key, the address its links
/// use, its peers, its announcements on a LAN, whether it relays and which
/// peers it trusts as relays, and the links' timing. Build it with
/// [`LinkConfig::new`] and the `with_*` methods.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkConfig {
    /// The daemon's node key, whose public half its peers configure.
    pub node_key: NodeKey,
    /// The UDP address every link is sent from and received on.
    pub bind: SocketAddr,
    /// The daemons to link to at a fixed address (`--link-peer`); with
    /// [`Self::peer_keys`], at least one.
    pub peers: Vec<LinkPeer>,
    /// The daemons to link to named by their key alone
    /// (`--link-peer-key`), each admitted from any address and found by its
    /// announcements, so they need [`Self::announce`].
    pub peer_keys: Vec<PublicKey>,
    /// Where this daemon announces its link endpoint and hears the other
    /// daemons'; `None`, announcing nothing, by default.
    pub announce: Option<AnnounceConfig>,
    /// Whether this daemon relays (`--link-relay`, [Relays](crate::link#relays)):
    /// it forwards once more what one peer sent it to its other peers whose
    /// interest may match it, and its summaries and announcements to each
    /// peer cover its other peers. Off by default.
    pub relay: bool,
    /// The peers whose relayed traffic this daemon accepts
    /// (`--link-trust-relay`): their forwards of other daemons' clients,
    /// the nodes they announce as reached through them, and health reports
    /// about those. Each is a configured peer's key. None by default, so
    /// that a forward is taken only from its origin's own daemon.
    pub trusted_relays: Vec<PublicKey>,
    /// How often the interest summary is sent, and the announcement of the
    /// attached nodes by a pacer of its own: each at most four a second,
    /// and again every 5 s while it does not change, by default.
    pub pacer: PacerConfig,
    /// How long a link may send nothing before it sends a heartbeat;
    /// [`DEFAULT_HEARTBEAT`] by default.
    pub heartbeat: Duration,
    /// How long a link may hear nothing before it goes down;
    /// [`DEFAULT_SILENCE`] by default.
    pub silence: Duration,
    /// How the sealed sessions run (rekeying, the old session's grace).
    pub sealing: SealingConfig,
}

impl LinkConfig {
    /// Links from `bind`, under `node_key`, to no peer yet.
    #[must_use]
    pub fn new(node_key: NodeKey, bind: SocketAddr) -> Self {
        Self {
            node_key,
            bind,
            peers: Vec::new(),
            peer_keys: Vec::new(),
            announce: None,
            relay: false,
            trusted_relays: Vec::new(),
            pacer: PacerConfig::default(),
            heartbeat: DEFAULT_HEARTBEAT,
            silence: DEFAULT_SILENCE,
            sealing: SealingConfig::default(),
        }
    }

    /// This configuration linking to `peer` too.
    #[must_use]
    pub fn with_peer(mut self, peer: LinkPeer) -> Self {
        self.peers.push(peer);
        self
    }

    /// This configuration linking too to the daemon whose node key's public
    /// half is `key`, wherever its announcements say it is.
    #[must_use]
    pub fn with_peer_key(mut self, key: PublicKey) -> Self {
        self.peer_keys.push(key);
        self
    }

    /// This configuration announcing its link endpoint, and hearing the
    /// other daemons', as `announce` says.
    #[must_use]
    pub fn with_announce(mut self, announce: AnnounceConfig) -> Self {
        self.announce = Some(announce);
        self
    }

    /// This configuration relaying ([Relays](crate::link#relays)).
    #[must_use]
    pub fn with_relay(mut self) -> Self {
        self.relay = true;
        self
    }

    /// This configuration trusting as a relay the peer whose node key's
    /// public half is `key`, which must be a configured peer's.
    #[must_use]
    pub fn with_trusted_relay(mut self, key: PublicKey) -> Self {
        self.trusted_relays.push(key);
        self
    }

    /// The ids of the peers trusted as relays.
    fn trusted_ids(&self) -> BTreeSet<DaemonId> {
        self.trusted_relays
            .iter()
            .map(|key| DaemonId::from_public_key(key.as_bytes()))
            .collect()
    }

    /// This configuration pacing summaries and announcements by `pacer`.
    #[must_use]
    pub fn with_pacer(mut self, pacer: PacerConfig) -> Self {
        self.pacer = pacer;
        self
    }

    /// This configuration sending a heartbeat after `every` without a send.
    #[must_use]
    pub fn with_heartbeat(mut self, every: Duration) -> Self {
        self.heartbeat = every;
        self
    }

    /// This configuration taking a link down after `limit` of silence.
    #[must_use]
    pub fn with_silence(mut self, limit: Duration) -> Self {
        self.silence = limit;
        self
    }

    /// This configuration running its sealed sessions by `sealing`.
    #[must_use]
    pub fn with_sealing(mut self, sealing: SealingConfig) -> Self {
        self.sealing = sealing;
        self
    }

    /// The public half of the node key, which the peers configure.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.node_key.public_key()
    }

    /// The id this daemon is named by across links.
    #[must_use]
    pub fn daemon_id(&self) -> DaemonId {
        DaemonId::from_public_key(self.public_key().as_bytes())
    }

    /// Refuse a configuration the links cannot run.
    fn check(&self) -> Result<(), LinkSetupError> {
        if self.peers.is_empty() && self.peer_keys.is_empty() {
            return Err(LinkSetupError::NoPeers);
        }
        let own = self.daemon_id();
        let mut ids = BTreeSet::new();
        let mut addrs = BTreeMap::new();
        for peer in &self.peers {
            let id = peer.daemon_id();
            if id == own {
                return Err(LinkSetupError::OwnKey { addr: peer.addr });
            }
            if !ids.insert(id) {
                return Err(LinkSetupError::DuplicatePeer { daemon: id });
            }
            if addrs.insert(peer.addr, id).is_some() {
                return Err(LinkSetupError::DuplicateAddress { addr: peer.addr });
            }
        }
        for key in &self.peer_keys {
            let id = DaemonId::from_public_key(key.as_bytes());
            if id == own {
                return Err(LinkSetupError::OwnPeerKey);
            }
            if !ids.insert(id) {
                return Err(LinkSetupError::DuplicatePeer { daemon: id });
            }
        }
        if let Some(key) = self
            .trusted_relays
            .iter()
            .find(|key| !ids.contains(&DaemonId::from_public_key(key.as_bytes())))
        {
            return Err(LinkSetupError::TrustedRelayNotPeer { key: *key });
        }
        match &self.announce {
            None if !self.peer_keys.is_empty() => {
                return Err(LinkSetupError::PeerKeysWithoutAnnounce);
            }
            None => {}
            Some(announce) => {
                announce.check()?;
                if !self.bind.is_ipv4() {
                    return Err(LinkSetupError::AnnounceBind { bind: self.bind });
                }
            }
        }
        if self.heartbeat.is_zero() || self.silence <= self.heartbeat {
            return Err(LinkSetupError::Timing {
                heartbeat: self.heartbeat,
                silence: self.silence,
            });
        }
        Ok(())
    }
}

/// Why links could not be started; nothing is left running behind any of
/// these.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkSetupError {
    /// The configuration names no peer.
    #[error("links need at least one peer (--link-peer or --link-peer-key)")]
    NoPeers,
    /// A peer has this daemon's own key.
    #[error(
        "the link peer at {addr} has this daemon's own node key; a daemon does not link to itself"
    )]
    OwnKey {
        /// The peer's address.
        addr: SocketAddr,
    },
    /// A peer named by its key alone has this daemon's own key.
    #[error("a --link-peer-key is this daemon's own node key; a daemon does not link to itself")]
    OwnPeerKey,
    /// Peers are named by their key alone, and nothing announces where they
    /// are.
    #[error("a peer named by its key alone (--link-peer-key) is found by its announcements, which need --link-announce")]
    PeerKeysWithoutAnnounce,
    /// The announcement group is not an IPv4 multicast address, or its port
    /// is zero.
    #[error("{group} is not an IPv4 multicast group (its first byte 224 to 239) and a port other than 0")]
    AnnounceGroup {
        /// The group asked for.
        group: SocketAddrV4,
    },
    /// The announcements' TTL is not 1 to 255.
    #[error("a LAN announcement's TTL is 1 to 255, not {ttl}")]
    AnnounceTtl {
        /// The TTL asked for.
        ttl: u32,
    },
    /// LAN announcement is asked for links bound to an IPv6 address, which
    /// an IPv4 announcement cannot give.
    #[error("LAN announcement is IPv4, and the link address {bind} is not")]
    AnnounceBind {
        /// The link address.
        bind: SocketAddr,
    },
    /// The announcement group could not be joined, or its sender set up.
    #[error(
        "the LAN announcement group {group} could not be joined, or its sender set up: {source}"
    )]
    Announce {
        /// The group.
        group: SocketAddrV4,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// Two peers have one key, or keys with one daemon id.
    #[error("two link peers are the daemon {daemon}")]
    DuplicatePeer {
        /// Their daemon id.
        daemon: DaemonId,
    },
    /// A key trusted as a relay is not a configured peer's.
    #[error("--link-trust-relay {key} is not a configured peer's key: a relay is trusted only as a peer (--link-peer or --link-peer-key)")]
    TrustedRelayNotPeer {
        /// The key.
        key: PublicKey,
    },
    /// Two peers have one address.
    #[error("two link peers are at {addr}")]
    DuplicateAddress {
        /// The address.
        addr: SocketAddr,
    },
    /// The heartbeat interval is zero, or not shorter than the silence
    /// limit, so a link that works would be taken down.
    #[error("a link's heartbeat ({heartbeat:?}) must be above zero and shorter than its silence limit ({silence:?})")]
    Timing {
        /// The heartbeat interval.
        heartbeat: Duration,
        /// The silence limit.
        silence: Duration,
    },
    /// The link address could not be bound, or its socket set up.
    #[error("the link address {addr} could not be bound: {source}")]
    Bind {
        /// The address asked for.
        addr: SocketAddr,
        /// Why.
        #[source]
        source: SealError,
    },
    /// A link thread could not be started.
    #[error("a link thread could not be started: {0}")]
    Thread(#[source] std::io::Error),
}

/// What the links have done, since they started; a snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkStats {
    /// Peers configured.
    pub configured: usize,
    /// Links up now: a Hello heard from the peer, and the peer not silent
    /// past the limit since.
    pub up: usize,
    /// Envelopes forwarded to peers, one for each peer a send went to,
    /// relayed ones included.
    pub forwards_sent: u64,
    /// Envelopes peers forwarded here, duplicates and relayed ones
    /// included.
    pub forwards_received: u64,
    /// Of the forwards sent, those a relay passed on: sends of another
    /// daemon's clients, one for each peer they went to.
    pub relayed_sent: u64,
    /// Of the forwards received, those of another daemon's clients than
    /// the sending peer's, from a peer trusted as a relay, duplicates
    /// included.
    pub relayed_received: u64,
    /// Relayed traffic refused because its peer is not trusted as a relay
    /// (`--link-trust-relay`): forwards of another daemon's clients, and
    /// health reports about them. Each is counted in `datagrams_refused`
    /// too.
    pub relayed_refused: u64,
    /// For a relay, the encoded bytes of the largest interest summary it
    /// gives a peer now, its other peers' summaries summed up in it; 0 for
    /// a daemon that does not relay.
    pub relay_interest_bytes: usize,
    /// Forwarded envelopes dropped as duplicates by the forward cache.
    pub duplicates_dropped: u64,
    /// Forwards not made: too long for a link datagram, the send queue
    /// full, or refused by the socket; one for each peer it was for.
    pub forwards_dropped: u64,
    /// Interest summaries sent, one for each peer.
    pub summaries_sent: u64,
    /// Interest summaries received.
    pub summaries_received: u64,
    /// Handshakes refused by the sealed transport: from a key not
    /// configured, or from the wrong address for one that is.
    pub handshakes_refused: u64,
    /// Datagrams refused after the transport opened them: not sealed by a
    /// configured peer's session, claiming another daemon than the one whose
    /// key opened them, naming or addressing another daemon's client, or not
    /// a link message.
    pub datagrams_refused: u64,
    /// Nodes the peers' announcements name now, every peer's together,
    /// those trusted relays name as reached through them included.
    pub peer_nodes: usize,
    /// Announcement messages sent, each part counted, one for each peer.
    pub announcements_sent: u64,
    /// Announcement messages received, each part counted.
    pub announcements_received: u64,
    /// Health reports about nodes here sent, one for each peer.
    pub health_sent: u64,
    /// Health reports about peers' nodes received and taken.
    pub health_received: u64,
    /// Health notices about peers' nodes queued for the watchers here, one
    /// for each watcher: the changes peers reported, their nodes `detached`,
    /// and those a new watcher was told first.
    pub remote_health_notices: u64,
    /// Forwards addressed to a node here that arrived, duplicates excepted.
    pub addressed_received: u64,
    /// Of those, the ones whose node was not attached here when they
    /// arrived, which were dropped.
    pub addressed_missing: u64,
    /// Announcements of this daemon's link endpoint sent to its LAN group.
    pub lan_announcements_sent: u64,
    /// Announcements heard on the LAN group from other daemons, repeats
    /// included; this daemon's own, looped back, are not counted.
    pub lan_announcements_received: u64,
    /// Of those, the ones ignored: from a key that is not a configured
    /// peer's.
    pub lan_announcements_ignored: u64,
    /// Handshakes with configured peers that announcements asked for: at
    /// most one per peer every [`ANNOUNCE_INTERVAL`], and none while a
    /// sealed session to the peer exists.
    pub lan_connects_triggered: u64,
}

/// The counts behind [`LinkStats`].
#[derive(Debug, Default)]
struct Counts {
    lan_announcements_sent: AtomicU64,
    lan_announcements_received: AtomicU64,
    lan_announcements_ignored: AtomicU64,
    lan_connects: AtomicU64,
    lan_send_errors: AtomicU64,
    lan_malformed: AtomicU64,
    forwards_sent: AtomicU64,
    forwards_received: AtomicU64,
    relayed_sent: AtomicU64,
    relayed_received: AtomicU64,
    relayed_refused: AtomicU64,
    duplicates_dropped: AtomicU64,
    forwards_dropped: AtomicU64,
    summaries_sent: AtomicU64,
    summaries_received: AtomicU64,
    datagrams_refused: AtomicU64,
    send_errors: AtomicU64,
    announcements_sent: AtomicU64,
    announcements_received: AtomicU64,
    announcements_unsent: AtomicU64,
    health_sent: AtomicU64,
    health_received: AtomicU64,
    addressed_received: AtomicU64,
    addressed_missing: AtomicU64,
}

/// Add `n` to `count`, and return the new total when it reached or passed a
/// power of two, which marks the refusals to log.
fn bump(count: &AtomicU64, n: u64) -> Option<u64> {
    let before = count.fetch_add(n, Ordering::Relaxed);
    let after = before.saturating_add(n);
    (after > before && (before == 0 || after.ilog2() > before.ilog2())).then_some(after)
}

/// A configured peer: its key, and where its links are.
#[derive(Debug)]
struct Peer {
    /// The public half of its node key, which its sessions are opened with.
    key: PublicKey,
    /// The address `--link-peer` gives it, which nothing changes; `None`
    /// for a peer named by its key alone.
    fixed: Option<SocketAddr>,
    /// Where its links are sent: the fixed address, or, for a peer named by
    /// its key alone, the last address a handshake made there or the
    /// datagrams its session opened proved; `None` until one does.
    addr: Mutex<Option<SocketAddr>>,
    /// The handshake its announcements asked for.
    found: Mutex<Found>,
}

impl Peer {
    fn new(key: PublicKey, fixed: Option<SocketAddr>) -> Self {
        Self {
            key,
            fixed,
            addr: Mutex::new(fixed),
            found: Mutex::new(Found::default()),
        }
    }

    /// Where its links are sent now, if that is known.
    fn addr(&self) -> Option<SocketAddr> {
        *self.addr.lock()
    }
}

/// What a peer's announcements asked of the connect thread.
#[derive(Debug, Default)]
struct Found {
    /// When an announcement last asked for a handshake.
    triggered: Option<Instant>,
    /// Where that handshake goes, until the connect thread makes it.
    candidate: Option<SocketAddr>,
}

/// A link to one peer, as the send and receive threads share it, and what
/// this daemon tells the peer.
#[derive(Debug)]
struct PeerLink {
    /// A Hello has been heard, and the peer has not been silent past the
    /// limit since.
    up: bool,
    /// When anything last arrived from the peer.
    heard: Option<Instant>,
    /// When the next Hello goes, while the link is not up.
    hello_due: Instant,
    /// The wait after that one.
    hello_backoff: Duration,
    /// When the last Hello went.
    hello_sent: Option<Instant>,
    /// What the peer's Hello and this daemon's agreed.
    outcome: Option<NegotiationOutcome>,
    /// The pacer of the summaries this daemon sends the peer: of its own
    /// subscribers, and for a relay its other peers' too.
    pacer: SummaryPacer,
    /// The summary last sent the peer, which it is sent at once when its
    /// link starts.
    summary: Option<Interest>,
    /// The pacer of the announcements this daemon sends the peer.
    announcer: SummaryPacer<Announcement>,
    /// The announcement last sent the peer, which it is sent at once when
    /// its link starts.
    announced: Option<Announcement>,
}

impl PeerLink {
    fn new(now: Instant, pacing: &PacerConfig) -> Self {
        Self {
            up: false,
            heard: None,
            hello_due: now,
            hello_backoff: HELLO_BACKOFF.0,
            hello_sent: None,
            outcome: None,
            pacer: SummaryPacer::new(pacing),
            summary: None,
            announcer: SummaryPacer::new(pacing),
            announced: None,
        }
    }

    /// Whether the summary last sent the peer watches health, so that it
    /// reports its nodes' states.
    fn watching_health(&self) -> bool {
        self.summary.as_ref().is_some_and(Interest::wants_health)
    }

    /// Something arrived from the peer at `now`. A link that is not up then
    /// sends its next Hello soon: the peer is there.
    fn heard(&mut self, now: Instant) {
        self.heard = Some(now);
        if !self.up {
            self.hello_backoff = HELLO_BACKOFF.0;
            let soonest = self.hello_sent.map_or(now, |at| at + HELLO_BACKOFF.0);
            self.hello_due = self.hello_due.min(soonest.max(now));
        }
    }
}

/// What the threads share under one lock.
struct State {
    router: Router,
    links: BTreeMap<DaemonId, PeerLink>,
    /// The sends delivered here lately.
    cache: ForwardCache,
    /// For a relay, the sends it passed on lately: a copy that arrives with
    /// a hop to spare after one that had none is passed on all the same.
    passed_on: ForwardCache,
    /// The summary of this daemon's subscriptions, as last made.
    local_interest: Interest,
    /// The nodes attached here, as last listed.
    local_nodes: BTreeSet<QualifiedOrigin>,
    /// For a relay, the encoded bytes of the largest summary its peers are
    /// given now.
    relay_interest_bytes: usize,
}

impl State {
    /// Hand each peer's summary pacer what the peer is to be told now: the
    /// local summary, and for a relay the summaries of its other peers that
    /// are not relays with it ([`Router::summary_for`]), coarsened to fit a
    /// control datagram.
    fn summaries_changed(&mut self, relay: bool) {
        let max = wire::max_interest_bytes();
        let mut largest = 0;
        for (&peer, link) in &mut self.links {
            let summary = if relay {
                self.router.summary_for(peer, &self.local_interest)
            } else {
                self.local_interest.clone()
            }
            .coarsened(max);
            largest = largest.max(summary.encoded_len());
            link.pacer.changed(summary);
        }
        self.relay_interest_bytes = if relay { largest } else { 0 };
    }

    /// Hand each peer's announcement pacer what the peer is to be told now:
    /// the nodes attached here, and for a relay its other peers' own nodes
    /// as reached through it ([`Router::via_for`]).
    fn announcements_changed(&mut self, relay: bool) {
        for (&peer, link) in &mut self.links {
            let mut announcement = Announcement::new(self.local_nodes.clone());
            if relay {
                announcement = announcement.with_via(self.router.via_for(peer));
            }
            link.announcer.changed(announcement);
        }
    }

    /// The nodes `peer` announced, its own and through it.
    fn announced_by(&self, peer: DaemonId) -> BTreeSet<QualifiedOrigin> {
        let own = self.router.nodes(peer).into_iter().flatten();
        let via = self.router.via(peer).into_iter().flatten();
        own.chain(via).cloned().collect()
    }
}

/// What the send thread is asked to send.
enum Outbound {
    /// An envelope to forward to these peers, with `hops` left, passed on
    /// as a relay when `relayed`.
    Forward {
        peers: Vec<DaemonId>,
        forward: Box<LinkForward>,
        hops: u64,
        relayed: bool,
    },
    /// A forward addressed to one of this peer's clients, made already,
    /// passed on as a relay when `relayed`.
    Addressed {
        peer: DaemonId,
        datagram: Box<Datagram>,
        relayed: bool,
    },
    /// A control message to one peer.
    Control { peer: DaemonId, message: Control },
    /// A node changed its state: tell every peer that watches health but
    /// `except`. A node here, or for a relay a node of the peer `except`,
    /// which reported it.
    Health {
        node: QualifiedOrigin,
        state: HealthState,
        except: Option<DaemonId>,
    },
    /// Nothing to send: look at the timers and the subscriptions again.
    Wake,
}

/// What the links of a daemon share among their threads and with the
/// bridge.
struct Shared {
    local: DaemonId,
    public_key: PublicKey,
    addr: SocketAddr,
    peers: BTreeMap<DaemonId, Peer>,
    /// Each peer by the public key its sessions are opened with.
    by_key: HashMap<PublicKey, DaemonId>,
    hello: Hello,
    heartbeat: Duration,
    silence: Duration,
    sealing: Sealing,
    /// Whether this daemon relays (`--link-relay`).
    relay: bool,
    /// The peers trusted as relays (`--link-trust-relay`).
    trusted: BTreeSet<DaemonId>,
    state: Mutex<State>,
    counts: Counts,
    stop: AtomicBool,
    /// The subscriptions changed since the send thread last looked.
    dirty: AtomicBool,
    /// The attached nodes changed since the send thread last looked.
    nodes_dirty: AtomicBool,
    /// For a relay, what its peers said changed since the send thread last
    /// looked: a summary, an announcement, a link's start or end.
    relay_dirty: AtomicBool,
    outbound: SyncSender<Outbound>,
    /// The daemon's attached nodes and their health.
    registry: Arc<Registry>,
}

impl Shared {
    /// The peer whose session opened a datagram: the daemon of the key
    /// that opened it, and never the one of the address it came from.
    fn sealed_by(&self, meta: &RecvMeta) -> Option<DaemonId> {
        meta.sealed_by
            .and_then(|key| self.by_key.get(&key).copied())
    }

    /// Whether `addr` is this daemon's link address, or where a peer other
    /// than `peer` has its links: an address no handshake or datagram may
    /// give `peer`, since a handshake there would send the other peer's
    /// datagrams to `peer`'s sessions.
    fn taken(&self, peer: DaemonId, addr: SocketAddr) -> bool {
        addr == self.addr
            || self
                .peers
                .iter()
                .any(|(&id, other)| id != peer && other.addr() == Some(addr))
    }

    /// The peer `peer`, named by its key alone, is proved at `addr`: send
    /// its links there from now on. A peer with a fixed address keeps it.
    fn learned(&self, peer: DaemonId, addr: SocketAddr) {
        let Some(entry) = self.peers.get(&peer).filter(|p| p.fixed.is_none()) else {
            return;
        };
        let before = entry.addr.lock().replace(addr);
        if before != Some(addr) {
            info!(
                peer = %peer,
                %addr,
                before = ?before,
                "the peer daemon named by its key is reached at a new address"
            );
        }
    }

    /// Wake the send thread; a full queue wakes it anyway.
    fn wake(&self) {
        let _ = self.outbound.try_send(Outbound::Wake);
    }

    /// For a relay, what a peer said changed: remake the summaries and the
    /// announcements it gives its peers.
    fn relay_changed(&self) {
        if self.relay {
            self.relay_dirty.store(true, Ordering::Release);
            self.wake();
        }
    }

    /// Whether `peer` is trusted as a relay.
    fn trusts_relay(&self, peer: DaemonId) -> bool {
        self.trusted.contains(&peer)
    }

    /// Queue `message` for `peer`, dropping it when the queue is full.
    fn queue(&self, peer: DaemonId, message: Control) {
        if let Err(TrySendError::Full(_)) =
            self.outbound.try_send(Outbound::Control { peer, message })
        {
            debug!(peer = %peer, "a control message was dropped: the link send queue is full");
        }
    }

    /// Count `n` forwards not made, logging at the first and each doubling.
    fn dropped(&self, n: usize, why: &dyn fmt::Display) {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        if let Some(total) = bump(&self.counts.forwards_dropped, n) {
            warn!(
                dropped = total,
                "a forward to a peer daemon was not made: {why}"
            );
        }
    }

    /// Count a datagram refused, logging at the first and each doubling.
    fn refused(&self, from: SocketAddr, why: &dyn fmt::Display) {
        if let Some(total) = bump(&self.counts.datagrams_refused, 1) {
            warn!(%from, refused = total, "a link datagram was refused: {why}");
        }
    }

    /// Count relayed traffic refused from a peer not trusted as a relay,
    /// and the datagram refused.
    fn relayed_refused(&self, from: SocketAddr, why: &dyn fmt::Display) {
        self.counts.relayed_refused.fetch_add(1, Ordering::Relaxed);
        self.refused(from, why);
    }

    /// A Hello in this daemon's name, answering one or not, saying whether
    /// it relays.
    fn hello_bytes(&self, answer: bool) -> Control {
        let flags = HelloFlags {
            answer,
            relay: self.relay,
        };
        Control::Hello(wire::hello(&self.hello, flags))
    }

    /// A node here, `link_name` across links, is now in `state`: queue the
    /// report for the peers that watch health. Called under the health
    /// tracker's lock, so the reports are queued in the order of the
    /// changes; it takes no other lock.
    fn local_health(&self, link_name: &str, state: NodeState) {
        let Ok(node) = QualifiedOrigin::new(self.local, link_name) else {
            return;
        };
        let item = Outbound::Health {
            node,
            state: state.into(),
            except: None,
        };
        if let Err(TrySendError::Full(_)) = self.outbound.try_send(item) {
            debug!("a health report was dropped: the link send queue is full");
        }
    }

    /// Queue for `peer` the state of every node here that is not healthy,
    /// under the health tracker's lock, so that a change made meanwhile is
    /// queued after them; and for a relay, the state of every node of its
    /// other peers it holds not healthy, which it announces to `peer` as
    /// reached through it.
    fn send_unhealthy(&self, peer: DaemonId) {
        let Some(health) = self.registry.health_tracker() else {
            return;
        };
        health.with_unhealthy(|link_name, state| {
            if let Ok(node) = QualifiedOrigin::new(self.local, link_name) {
                self.queue(
                    peer,
                    Control::Health {
                        node,
                        state: state.into(),
                    },
                );
            }
        });
        if self.relay {
            // Read before the tracker's lock is taken, which is never taken
            // under the state's.
            let others: BTreeSet<DaemonId> = self
                .state
                .lock()
                .router
                .peers()
                .filter(|&other| other != peer)
                .collect();
            health.with_remote_unhealthy(|node, state| {
                if others.contains(&node.daemon()) {
                    self.queue(
                        peer,
                        Control::Health {
                            node: node.clone(),
                            state,
                        },
                    );
                }
            });
        }
    }

    /// The peer's nodes `nodes` are gone, and with `daemon` every node of it
    /// the health tracker holds: tell the watchers here they are detached.
    fn nodes_gone(&self, daemon: Option<DaemonId>, nodes: BTreeSet<QualifiedOrigin>) {
        if let Some(health) = self.registry.health_tracker() {
            health.remote_gone(daemon, nodes);
        }
    }

    /// The control messages that carry `announcement`, or none, logged,
    /// when it does not fit the parts a link sends.
    fn announcement_messages(&self, announcement: &Announcement) -> Vec<Control> {
        match announcement.messages(wire::max_control_bytes()) {
            Ok(messages) => messages,
            Err(e) => {
                if let Some(total) = bump(&self.counts.announcements_unsent, 1) {
                    warn!(
                        nodes = announcement.nodes().len(),
                        unsent = total,
                        error = %e,
                        "the attached nodes were not announced to the peer daemons: too many for one announcement"
                    );
                }
                Vec::new()
            }
        }
    }

    /// Send the next Hello to `peer` now: a session to it was just made.
    fn hello_now(&self, peer: DaemonId) {
        let now = Instant::now();
        if let Some(link) = self.state.lock().links.get_mut(&peer) {
            if !link.up {
                link.hello_backoff = HELLO_BACKOFF.0;
                link.hello_due = now;
            }
        }
        self.wake();
    }
}

/// Links bound to their address and not yet running: [`bind`], then
/// [`BoundLinks::start`].
pub(crate) struct BoundLinks {
    config: LinkConfig,
    tx: Sender,
    rx: Receiver,
    sealing: Sealing,
    addr: SocketAddr,
    announce: Option<announce::AnnounceSockets>,
}

/// Check `config` and bind its link address, sealed with its node key and
/// admitting its peers' keys, each named with an address from that
/// address's IP and each named by its key alone from any; and join its
/// announcement group, if it has one.
///
/// # Errors
///
/// A [`LinkSetupError`] naming what is wrong with the configuration,
/// [`LinkSetupError::Bind`], or [`LinkSetupError::Announce`].
pub(crate) fn bind(config: LinkConfig) -> Result<BoundLinks, LinkSetupError> {
    config.check()?;
    let bind_error = |source| LinkSetupError::Bind {
        addr: config.bind,
        source,
    };
    let mut allowlist = Allowlist::new();
    for peer in &config.peers {
        allowlist.allow_at(peer.key, peer.addr);
    }
    for key in &config.peer_keys {
        allowlist.allow(*key);
    }
    let (mut tx, mut rx) = bind_sealed_pair_with(
        config.bind,
        config.node_key.clone(),
        allowlist,
        config.sealing.clone(),
    )
    .map_err(bind_error)?;
    tx.enable_fragmentation();
    rx.enable_reassembly(ReassemblyConfig::default());
    rx.set_read_timeout(Some(RECV_TIMEOUT))
        .map_err(|e| bind_error(SealError::Io(e)))?;
    let addr = rx.local_addr().map_err(|e| bind_error(SealError::Io(e)))?;
    let sealing = tx.sealing().cloned().ok_or_else(|| {
        bind_error(SealError::Crypto(
            "the socket was bound without sealing".into(),
        ))
    })?;
    let announce = config
        .announce
        .as_ref()
        .map(|announce| announce::bind(announce, addr))
        .transpose()?;
    Ok(BoundLinks {
        config,
        tx,
        rx,
        sealing,
        addr,
        announce,
    })
}

impl BoundLinks {
    /// Start the links' threads, which summarise `subscribers` for the peers
    /// and deliver what the peers forward to them.
    ///
    /// # Errors
    ///
    /// [`LinkSetupError::Thread`] when a thread cannot be started; the ones
    /// started are stopped first.
    pub(crate) fn start(
        self,
        subscribers: Arc<Subscribers>,
        registry: Arc<Registry>,
    ) -> Result<Links, LinkSetupError> {
        let Self {
            config,
            tx,
            rx,
            sealing,
            addr,
            announce,
        } = self;
        let local = config.daemon_id();
        let now = Instant::now();
        let fixed = config
            .peers
            .iter()
            .map(|p| (p.daemon_id(), Peer::new(p.key, Some(p.addr))));
        let by_key_alone = config.peer_keys.iter().map(|&key| {
            (
                DaemonId::from_public_key(key.as_bytes()),
                Peer::new(key, None),
            )
        });
        let peers: BTreeMap<DaemonId, Peer> = fixed.chain(by_key_alone).collect();
        let by_key = peers.iter().map(|(&id, p)| (p.key, id)).collect();
        let trusted = config.trusted_ids();
        let mut router = Router::new(local);
        for &relay in &trusted {
            // Each is a configured peer, which is not this daemon (checked).
            let _ = router.trust_relay(relay);
        }
        let (outbound, queued) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let shared = Arc::new(Shared {
            local,
            public_key: config.public_key(),
            addr,
            by_key,
            hello: Hello {
                version: mesh_capability::MAX_VERSION,
                // The links run on sealed UDP alone, so none of the upgrades
                // the bits name is offered, and no context registry is shared.
                capabilities: CapabilityFlags::default(),
                registry_hash: [0; 32],
            },
            heartbeat: config.heartbeat,
            silence: config.silence,
            sealing,
            relay: config.relay,
            trusted,
            state: Mutex::new(State {
                router,
                links: peers
                    .keys()
                    .map(|&id| (id, PeerLink::new(now, &config.pacer)))
                    .collect(),
                cache: ForwardCache::default(),
                passed_on: ForwardCache::default(),
                local_interest: Interest::nothing(),
                local_nodes: BTreeSet::new(),
                relay_interest_bytes: 0,
            }),
            peers,
            counts: Counts::default(),
            stop: AtomicBool::new(false),
            // The first summary and announcement are made at once, of
            // whatever is subscribed and attached.
            dirty: AtomicBool::new(true),
            nodes_dirty: AtomicBool::new(true),
            relay_dirty: AtomicBool::new(false),
            outbound,
            registry: Arc::clone(&registry),
        });
        let watching: Weak<Shared> = Arc::downgrade(&shared);
        subscribers.watch(move || {
            if let Some(shared) = watching.upgrade() {
                shared.dirty.store(true, Ordering::Release);
                shared.wake();
            }
        });
        let watching: Weak<Shared> = Arc::downgrade(&shared);
        registry.watch_nodes(move || {
            if let Some(shared) = watching.upgrade() {
                shared.nodes_dirty.store(true, Ordering::Release);
                shared.wake();
            }
        });
        if let Some(health) = registry.health_tracker() {
            let watching: Weak<Shared> = Arc::downgrade(&shared);
            health.watch_local(move |link_name, state| {
                if let Some(shared) = watching.upgrade() {
                    shared.local_health(link_name, state);
                }
            });
        }

        let mut links = Links {
            shared: Arc::clone(&shared),
            threads: Vec::with_capacity(4),
        };
        let sender = SendThread {
            shared: Arc::clone(&shared),
            tx,
            queued,
            subscribers: Arc::clone(&subscribers),
            registry,
            last_sent: BTreeMap::new(),
        };
        links.spawn("mesh-link-send", move || sender.run())?;
        let receiving = Arc::clone(&shared);
        links.spawn("mesh-link-recv", move || {
            receive(&receiving, rx, &subscribers)
        })?;
        let connecting = Arc::clone(&shared);
        links.spawn("mesh-link-connect", move || connect(&connecting))?;
        // Last, so that a peer the first announcement brings finds the
        // receive thread answering its handshake.
        let group = announce.as_ref().map(|sockets| sockets.group);
        if let Some(sockets) = announce {
            let announcing = Arc::clone(&shared);
            links.spawn("mesh-link-announce", move || {
                announce::run(&announcing, sockets);
            })?;
        }

        let peers: Vec<String> = shared
            .peers
            .iter()
            .map(|(id, peer)| match peer.fixed {
                Some(at) => format!("{id} at {at}"),
                None => format!("{id} by its key ({})", peer.key),
            })
            .collect();
        let trusted: Vec<String> = shared.trusted.iter().map(ToString::to_string).collect();
        info!(
            daemon_id = %local,
            public_key = %shared.public_key,
            link_bind = %addr,
            peers = %peers.join(", "),
            announce = ?group,
            relay = shared.relay,
            trusted_relays = %trusted.join(", "),
            "links to other daemons configured"
        );
        Ok(links)
    }
}

/// A daemon's running links: forwarding its sends, and stopped, their
/// threads joined and their socket closed, when dropped.
pub(crate) struct Links {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Links {
    fn spawn(
        &mut self,
        name: &str,
        run: impl FnOnce() + Send + 'static,
    ) -> Result<(), LinkSetupError> {
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(run)
            .map_err(LinkSetupError::Thread)?;
        self.threads.push(thread);
        Ok(())
    }

    /// Forward a send of `origin`'s, published here on `channel`, to the
    /// peers whose summaries may match it, as the hub stamped it with
    /// `stamp`. Routing is in memory; the datagrams go from the send thread.
    pub(crate) fn forward(
        &self,
        origin: &Origin,
        channel: &str,
        type_id: u16,
        type_name: Option<&str>,
        envelope: &PulseEnvelope,
        stamp: u64,
    ) {
        let peers = self
            .shared
            .state
            .lock()
            .router
            .route_send(channel, type_id, type_name);
        if peers.is_empty() {
            return;
        }
        let origin = match QualifiedOrigin::new(self.shared.local, origin.link_name()) {
            Ok(origin) => origin,
            Err(e) => {
                self.shared.dropped(peers.len(), &e);
                return;
            }
        };
        let mut envelope = envelope.clone();
        envelope.monotonic_nanos = stamp;
        let item = Outbound::Forward {
            peers,
            forward: Box::new(LinkForward {
                origin,
                channel: channel.to_owned(),
                named_type: type_name.is_some(),
                envelope,
                dest: None,
            }),
            hops: ORIGIN_HOP_LIMIT,
            relayed: false,
        };
        match self.shared.outbound.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(Outbound::Forward { peers, .. })) => {
                self.shared
                    .dropped(peers.len(), &"the link send queue is full");
            }
            Err(_) => {}
        }
    }

    /// Forward a send of `origin`'s, addressed to `dest`, a client the peer
    /// `peer` announced, or that the relay `peer` announced as reached
    /// through it, to that peer alone, as the hub stamped it with `stamp`;
    /// whether it was handed to the link. One too long for a link datagram,
    /// or that finds the send queue full, is not, and is counted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn forward_to(
        &self,
        peer: DaemonId,
        dest: QualifiedOrigin,
        origin: &Origin,
        channel: &str,
        type_name: Option<&str>,
        envelope: &PulseEnvelope,
        stamp: u64,
    ) -> bool {
        let origin = match QualifiedOrigin::new(self.shared.local, origin.link_name()) {
            Ok(origin) => origin,
            Err(e) => {
                self.shared.dropped(1, &e);
                return false;
            }
        };
        let mut envelope = envelope.clone();
        envelope.monotonic_nanos = stamp;
        let forward = LinkForward {
            origin,
            channel: channel.to_owned(),
            named_type: type_name.is_some(),
            envelope,
            dest: Some(dest),
        };
        let mut datagram = match wire::forward(&forward, self.shared.local) {
            Ok(datagram) => datagram,
            Err(e) => {
                self.shared.dropped(1, &e);
                return false;
            }
        };
        datagram.pulse = with_hop_limit(datagram.pulse, ORIGIN_HOP_LIMIT);
        let item = Outbound::Addressed {
            peer,
            datagram: Box::new(datagram),
            relayed: false,
        };
        match self.shared.outbound.try_send(item) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.shared.dropped(1, &"the link send queue is full");
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Where a send addressed to `node` goes: this daemon, the peer that
    /// announced it, the relay that announced it as reached through it, or
    /// nowhere known.
    pub(crate) fn route_to(&self, node: &QualifiedOrigin) -> Destination {
        self.shared.state.lock().router.route_to(node)
    }

    /// What the links have done so far.
    pub(crate) fn stats(&self) -> LinkStats {
        let shared = &self.shared;
        let (up, peer_nodes, relay_interest_bytes) = {
            let state = shared.state.lock();
            let up = state.links.values().filter(|l| l.up).count();
            let held = |nodes: Option<&BTreeSet<QualifiedOrigin>>| nodes.map_or(0, BTreeSet::len);
            let nodes = state
                .router
                .peers()
                .map(|peer| held(state.router.nodes(peer)) + held(state.router.via(peer)))
                .sum();
            (up, nodes, state.relay_interest_bytes)
        };
        let c = &shared.counts;
        let read = |n: &AtomicU64| n.load(Ordering::Relaxed);
        LinkStats {
            configured: shared.peers.len(),
            up,
            forwards_sent: read(&c.forwards_sent),
            forwards_received: read(&c.forwards_received),
            relayed_sent: read(&c.relayed_sent),
            relayed_received: read(&c.relayed_received),
            relayed_refused: read(&c.relayed_refused),
            relay_interest_bytes,
            duplicates_dropped: read(&c.duplicates_dropped),
            forwards_dropped: read(&c.forwards_dropped),
            summaries_sent: read(&c.summaries_sent),
            summaries_received: read(&c.summaries_received),
            handshakes_refused: shared.sealing.counts().handshakes_refused,
            datagrams_refused: read(&c.datagrams_refused),
            peer_nodes,
            announcements_sent: read(&c.announcements_sent),
            announcements_received: read(&c.announcements_received),
            health_sent: read(&c.health_sent),
            health_received: read(&c.health_received),
            remote_health_notices: shared
                .registry
                .health_tracker()
                .map_or(0, |health| health.remote_notices()),
            addressed_received: read(&c.addressed_received),
            addressed_missing: read(&c.addressed_missing),
            lan_announcements_sent: read(&c.lan_announcements_sent),
            lan_announcements_received: read(&c.lan_announcements_received),
            lan_announcements_ignored: read(&c.lan_announcements_ignored),
            lan_connects_triggered: read(&c.lan_connects),
        }
    }

    /// The id this daemon is named by across links.
    pub(crate) fn daemon_id(&self) -> DaemonId {
        self.shared.local
    }

    /// The address the links are bound to.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.shared.addr
    }
}

impl Drop for Links {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake();
        for thread in self.threads.drain(..) {
            // A panic in a thread has been reported by the panic hook.
            let _ = thread.join();
        }
    }
}

/// The send thread: the one owner of the socket's sending half.
struct SendThread {
    shared: Arc<Shared>,
    tx: Sender,
    queued: mpsc::Receiver<Outbound>,
    subscribers: Arc<Subscribers>,
    registry: Arc<Registry>,
    /// When each peer was last sent anything, for its heartbeat.
    last_sent: BTreeMap<DaemonId, Instant>,
}

impl SendThread {
    fn run(mut self) {
        let mut wait = Duration::ZERO;
        while !self.shared.stop.load(Ordering::Acquire) {
            match self.queued.recv_timeout(wait) {
                Ok(item) => self.send(item),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            for _ in 0..BATCH {
                match self.queued.try_recv() {
                    Ok(item) => self.send(item),
                    Err(_) => break,
                }
            }
            self.remake();
            wait = self.tick(Instant::now());
        }
    }

    /// Remake what the peers are told, from what changed since the last
    /// look: the subscriptions here, the nodes attached here, and for a
    /// relay what its peers said.
    fn remake(&mut self) {
        let local_changed = self.shared.dirty.swap(false, Ordering::AcqRel);
        let nodes_changed = self.shared.nodes_dirty.swap(false, Ordering::AcqRel);
        let relay = self.shared.relay;
        let peers_changed = relay && self.shared.relay_dirty.swap(false, Ordering::AcqRel);
        if !(local_changed || nodes_changed || peers_changed) {
            return;
        }
        // Outside the state's lock: the subscriptions and the registry take
        // their own.
        let interest = local_changed.then(|| {
            self.subscribers
                .interest()
                .coarsened(wire::max_interest_bytes())
        });
        let local = self.shared.local;
        let nodes = nodes_changed.then(|| {
            self.registry
                .link_names()
                .into_iter()
                .filter_map(|name| QualifiedOrigin::new(local, name).ok())
                .collect()
        });
        let mut state = self.shared.state.lock();
        if let Some(interest) = interest {
            state.local_interest = interest;
        }
        if let Some(nodes) = nodes {
            state.local_nodes = nodes;
        }
        if local_changed || peers_changed {
            state.summaries_changed(relay);
        }
        if nodes_changed || peers_changed {
            state.announcements_changed(relay);
        }
    }

    /// Count a forward sent, and for a relay one it passed on.
    fn forwarded(&self, relayed: bool) {
        let counts = &self.shared.counts;
        counts.forwards_sent.fetch_add(1, Ordering::Relaxed);
        if relayed {
            counts.relayed_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn send(&mut self, item: Outbound) {
        match item {
            Outbound::Forward {
                peers,
                forward,
                hops,
                relayed,
            } => {
                let mut datagram = match wire::forward(&forward, self.shared.local) {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        self.shared.dropped(peers.len(), &e);
                        return;
                    }
                };
                datagram.pulse = with_hop_limit(datagram.pulse, hops);
                for peer in peers {
                    if self.send_to(peer, &datagram) {
                        self.forwarded(relayed);
                    } else {
                        self.shared
                            .dropped(1, &"no sealed session, or the socket refused it");
                    }
                }
            }
            Outbound::Addressed {
                peer,
                datagram,
                relayed,
            } => {
                if self.send_to(peer, &datagram) {
                    self.forwarded(relayed);
                } else {
                    self.shared
                        .dropped(1, &"no sealed session, or the socket refused it");
                }
            }
            Outbound::Control { peer, message } => self.control(peer, &message),
            Outbound::Health {
                node,
                state,
                except,
            } => {
                let peers: Vec<DaemonId> = {
                    let guard = self.shared.state.lock();
                    guard
                        .links
                        .iter()
                        .filter(|(&peer, link)| {
                            link.up
                                && except != Some(peer)
                                && guard
                                    .router
                                    .interest(peer)
                                    .is_some_and(Interest::wants_health)
                        })
                        .map(|(&peer, _)| peer)
                        .collect()
                };
                let message = Control::Health { node, state };
                for peer in peers {
                    self.control(peer, &message);
                }
            }
            Outbound::Wake => {}
        }
    }

    fn control(&mut self, peer: DaemonId, message: &Control) {
        match wire::control(message, self.shared.local) {
            Ok(datagram) => {
                if self.send_to(peer, &datagram) {
                    let counts = &self.shared.counts;
                    let count = match message {
                        Control::Interest(_) => Some(&counts.summaries_sent),
                        Control::NodesAnnounced { .. } => Some(&counts.announcements_sent),
                        Control::Health { .. } => Some(&counts.health_sent),
                        Control::Hello(_) | Control::Heartbeat => None,
                    };
                    if let Some(count) = count {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => warn!(peer = %peer, error = %e, "a link control message was not sent"),
        }
    }

    /// Send `datagram` to `peer`; whether it went.
    fn send_to(&mut self, peer: DaemonId, datagram: &Datagram) -> bool {
        let Some(addr) = self.shared.peers.get(&peer).and_then(Peer::addr) else {
            return false;
        };
        let sent = self.tx.send_to(
            datagram.pulse.monotonic_nanos,
            &datagram.pulse,
            &datagram.bytes,
            addr,
        );
        match sent {
            Ok(_) => {
                self.last_sent.insert(peer, Instant::now());
                true
            }
            Err(SenderError::Seal(_)) => false,
            Err(e) => {
                if let Some(total) = bump(&self.shared.counts.send_errors, 1) {
                    warn!(peer = %peer, %addr, errors = total, error = %e, "a link datagram was not sent");
                }
                false
            }
        }
    }

    /// Send what the timers say is due at `now`, and return how long until
    /// they next need a look.
    fn tick(&mut self, now: Instant) -> Duration {
        let shared = Arc::clone(&self.shared);
        let mut out: Vec<(DaemonId, Control)> = Vec::new();
        let mut gone: Vec<(Option<DaemonId>, BTreeSet<QualifiedOrigin>)> = Vec::new();
        // The peers whose summary from here does not watch health, so that
        // they report nothing, and the nodes they relay.
        let mut unwatched: Vec<(DaemonId, BTreeSet<QualifiedOrigin>)> = Vec::new();
        let mut next = MAX_TICK;
        let mut until = |at: Instant| next = next.min(at.saturating_duration_since(now));
        {
            let mut guard = shared.state.lock();
            let state = &mut *guard;
            for (&peer, link) in &mut state.links {
                if let Some(due) = link.pacer.poll(now) {
                    if link.up {
                        out.push((peer, Control::Interest(due.clone())));
                    }
                    if !due.wants_health() {
                        let via = state.router.via(peer).cloned().unwrap_or_default();
                        unwatched.push((peer, via));
                    }
                    link.summary = Some(due);
                }
                if let Some(due) = link.pacer.next_due(now) {
                    until(due);
                }
                if let Some(due) = link.announcer.poll(now) {
                    if link.up {
                        let messages = shared.announcement_messages(&due);
                        out.extend(messages.into_iter().map(|m| (peer, m)));
                    }
                    link.announced = Some(due);
                }
                if let Some(due) = link.announcer.next_due(now) {
                    until(due);
                }
            }
            for (&peer, link) in &mut state.links {
                if link.up {
                    let heard = link.heard.unwrap_or(now);
                    if now.saturating_duration_since(heard) >= shared.silence {
                        link.up = false;
                        let nodes = state.router.remove_peer(peer).unwrap_or_default();
                        let daemon = (!state.router.relays_for(peer)).then_some(peer);
                        gone.push((daemon, nodes));
                        link.hello_due = now;
                        link.hello_backoff = HELLO_BACKOFF.0;
                        info!(
                            peer = %peer,
                            silent = ?now.saturating_duration_since(heard),
                            "link down: the peer daemon fell silent past the limit"
                        );
                    } else {
                        until(heard + shared.silence);
                        match self.last_sent.get(&peer) {
                            Some(&sent)
                                if now.saturating_duration_since(sent) < shared.heartbeat =>
                            {
                                until(sent + shared.heartbeat);
                            }
                            _ => out.push((peer, Control::Heartbeat)),
                        }
                    }
                }
                if !link.up {
                    if now >= link.hello_due {
                        let key = shared.peers.get(&peer).map(|p| p.key);
                        if key.is_some_and(|key| shared.sealing.has_session(&key)) {
                            out.push((peer, shared.hello_bytes(false)));
                            link.hello_sent = Some(now);
                            link.hello_due = now + link.hello_backoff;
                            link.hello_backoff = (link.hello_backoff * 2).min(HELLO_BACKOFF.1);
                        } else {
                            // No session yet: the connect thread makes one and
                            // says so; until then, look again at each tick.
                            link.hello_due = now + MAX_TICK;
                        }
                    }
                    until(link.hello_due);
                }
            }
        }
        // Outside the state's lock: the health tracker takes its own.
        if let Some(health) = shared.registry.health_tracker() {
            for (peer, via) in &unwatched {
                health.forget_remote(*peer, via);
            }
        }
        if !gone.is_empty() {
            shared.relay_changed();
        }
        for (daemon, nodes) in gone {
            shared.nodes_gone(daemon, nodes);
        }
        for (peer, message) in out {
            self.control(peer, &message);
        }
        next.max(Duration::from_millis(1))
    }
}

/// The receive thread: open each datagram, and act on it.
fn receive(shared: &Shared, mut rx: Receiver, subscribers: &Subscribers) {
    while !shared.stop.load(Ordering::Acquire) {
        match rx.recv() {
            Ok((pulse, bytes, meta)) => take(shared, &pulse, &bytes, &meta, subscribers),
            Err(e) if e.is_timeout() => {}
            Err(e) => shared.refused(shared.addr, &e),
        }
    }
}

/// Act on one datagram, which `meta` says who sealed.
fn take(
    shared: &Shared,
    pulse: &pulse_canon::Pulse,
    bytes: &[u8],
    meta: &RecvMeta,
    subscribers: &Subscribers,
) {
    let src = meta.peer;
    let Some(peer) = shared.sealed_by(meta) else {
        shared.refused(src, &"no configured peer's session sealed it");
        return;
    };
    let message = match wire::decode(pulse, bytes, peer) {
        Ok(message) => message,
        Err(e) => {
            shared.refused(src, &e);
            return;
        }
    };
    // A peer named by its key alone is reached where its session's
    // datagrams come from, once that address seals to a session and no
    // other peer's links use it.
    if shared
        .peers
        .get(&peer)
        .is_some_and(|p| p.fixed.is_none() && p.addr() != Some(src))
        && shared.sealing.can_seal_to(src)
        && !shared.taken(peer, src)
    {
        shared.learned(peer, src);
    }
    let now = Instant::now();
    match message {
        Message::Forward(forward) => {
            shared
                .counts
                .forwards_received
                .fetch_add(1, Ordering::Relaxed);
            let origin = forward.origin.daemon();
            if origin == shared.local {
                shared.refused(src, &"a forward of this daemon's own client");
                return;
            }
            // A forward of another daemon's client than the peer's own is
            // relayed, and taken only from a peer trusted as a relay.
            let relayed = origin != peer;
            if relayed {
                if !shared.trusts_relay(peer) {
                    shared.relayed_refused(
                        src,
                        &"a forward of another daemon's client, from a peer not trusted as a relay (--link-trust-relay)",
                    );
                    return;
                }
                shared
                    .counts
                    .relayed_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            let onward = forward
                .dest
                .as_ref()
                .is_some_and(|dest| dest.daemon() != shared.local);
            if onward && !shared.relay {
                shared.refused(
                    src,
                    &"a forward addressed to another daemon's client, to a daemon that does not relay",
                );
                return;
            }
            let key = ForwardKey::new(
                &forward.envelope.id(),
                &forward.origin,
                forward.envelope.monotonic_nanos,
            );
            // A relay passes a send on once, from the first copy that has
            // a hop to spare, which may come after a copy that had none (one
            // through another relay): what it delivered and what it passed on
            // are held apart.
            let hops = if shared.relay {
                onward_hops(pulse, relayed)
            } else {
                None
            };
            let (seen, pass_on) = {
                let mut state = shared.state.lock();
                if let Some(link) = state.links.get_mut(&peer) {
                    link.heard(now);
                }
                let seen = state.cache.seen_or_insert(key);
                let pass_on = hops.filter(|_| !state.passed_on.seen_or_insert(key));
                (seen, pass_on)
            };
            if seen {
                shared
                    .counts
                    .duplicates_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
            if onward {
                match pass_on {
                    Some(hops) => relay_addressed(shared, peer, hops, forward),
                    None if !seen => shared.dropped(
                        1,
                        &"a forward addressed to another daemon's client has no hop left to take",
                    ),
                    None => {}
                }
                return;
            }
            if !seen {
                deliver(shared, subscribers, &forward);
            }
            if let Some(hops) = pass_on {
                relay_on(shared, peer, hops, forward);
            }
        }
        Message::Control(control) => on_control(shared, peer, control, now, src),
    }
}

/// The hops a relay passes a forward on with, when it passes it on at all:
/// one fewer than the hop limit `pulse` arrived with, when one is still
/// left after that, and only for a forward that came from its origin's own
/// daemon (`relayed` false). A forward that has crossed a relay already
/// goes no further, whatever its hop limit says, so that a send crosses one
/// relay at most even when a relay sets a limit too high.
fn onward_hops(pulse: &Pulse, relayed: bool) -> Option<NonZeroU64> {
    if relayed {
        return None;
    }
    hops_left(&next_hop(pulse)?)
}

/// As a relay, pass a forward that `from` sent on to the other peers whose
/// summaries may match it, never back to `from` or to its origin's daemon,
/// with `hops` left ([`onward_hops`]).
fn relay_on(shared: &Shared, from: DaemonId, hops: NonZeroU64, forward: LinkForward) {
    let envelope = &forward.envelope;
    let type_name = if forward.named_type {
        envelope.type_name()
    } else {
        None
    };
    let peers = shared.state.lock().router.route_relayed(
        from,
        forward.origin.daemon(),
        &forward.channel,
        envelope.envelope_type(),
        type_name,
    );
    if peers.is_empty() {
        return;
    }
    let item = Outbound::Forward {
        peers,
        forward: Box::new(forward),
        hops: hops.get(),
        relayed: true,
    };
    if let Err(TrySendError::Full(Outbound::Forward { peers, .. })) = shared.outbound.try_send(item)
    {
        shared.dropped(peers.len(), &"the link send queue is full");
    }
}

/// As a relay, pass a forward that `from` sent, addressed to another
/// daemon's client, on to that daemon with `hops` left
/// ([`onward_hops`]), when that daemon announced the node to this one;
/// otherwise drop it, counted.
fn relay_addressed(shared: &Shared, from: DaemonId, hops: NonZeroU64, forward: LinkForward) {
    let Some(dest) = &forward.dest else {
        return;
    };
    let to = match shared.state.lock().router.route_to(dest) {
        Destination::Peer(to) if to != from && to != forward.origin.daemon() => to,
        _ => {
            shared.dropped(
                1,
                &"no peer announced the node a forward to relay is addressed to",
            );
            return;
        }
    };
    let mut datagram = match wire::forward(&forward, shared.local) {
        Ok(datagram) => datagram,
        Err(e) => {
            shared.dropped(1, &e);
            return;
        }
    };
    datagram.pulse = with_hop_limit(datagram.pulse, hops.get());
    let item = Outbound::Addressed {
        peer: to,
        datagram: Box::new(datagram),
        relayed: true,
    };
    if let Err(TrySendError::Full(_)) = shared.outbound.try_send(item) {
        shared.dropped(1, &"the link send queue is full");
    }
}

/// Queue a forwarded envelope for the subscriptions here that match it: all
/// of them, or for an addressed one, those of its node's connection, when
/// the node is attached here.
fn deliver(shared: &Shared, subscribers: &Subscribers, forward: &LinkForward) {
    let owner = match &forward.dest {
        None => None,
        Some(dest) => {
            shared
                .counts
                .addressed_received
                .fetch_add(1, Ordering::Relaxed);
            match shared.registry.find_link_name(dest.name()) {
                Some(entry) => Some(entry.connection_id),
                None => {
                    if let Some(total) = bump(&shared.counts.addressed_missing, 1) {
                        debug!(
                            node = %dest,
                            missing = total,
                            "a forward addressed to a node no longer attached here was dropped"
                        );
                    }
                    return;
                }
            }
        }
    };
    let envelope = &forward.envelope;
    let resolved = envelope.type_name().unwrap_or(&forward.channel);
    let payload = envelope.payload();
    let bytes;
    let payload = match payload.as_raw() {
        Some(raw) => raw,
        None => {
            bytes = payload.to_bytes();
            bytes.as_slice()
        }
    };
    let origin = forward.origin.to_string();
    let delivery = Delivery {
        channel: &forward.channel,
        type_id: envelope.envelope_type(),
        type_name: forward.named_type.then_some(resolved),
        resolved_type_name: resolved,
        origin: &origin,
        envelope_id: &envelope.id(),
        payload,
    };
    match owner {
        None => subscribers.deliver(&delivery),
        Some(owner) => subscribers.deliver_to(owner, &delivery),
    };
}

/// Act on a control message from `peer`, which came from `src`. Whatever
/// it is, it counts as hearing from the peer; a link not up then sends its
/// next Hello soon. The health tracker is called once the state's lock is
/// released.
fn on_control(shared: &Shared, peer: DaemonId, control: Control, now: Instant, src: SocketAddr) {
    if let Control::Hello(bytes) = control {
        on_hello(shared, peer, &bytes, now);
        return;
    }
    let mut guard = shared.state.lock();
    let up = guard.links.get_mut(&peer).is_some_and(|link| {
        link.heard(now);
        link.up
    });
    let watching = guard
        .links
        .get(&peer)
        .is_some_and(PeerLink::watching_health);
    let mut send_unhealthy = false;
    let mut relay_changed = false;
    let mut dropped = BTreeSet::new();
    let mut report = None;
    let mut pass_on = false;
    match control {
        Control::Hello(_) | Control::Heartbeat => {}
        Control::Interest(interest) => {
            shared
                .counts
                .summaries_received
                .fetch_add(1, Ordering::Relaxed);
            if up {
                let wants_health = interest.wants_health();
                // An older or repeated summary is not taken, which is as it
                // should be; a newer one that watches health is answered with
                // the nodes here that are not healthy.
                let taken = guard.router.update_interest(peer, interest) == Ok(true);
                send_unhealthy = taken && wants_health;
                relay_changed = taken && !guard.router.is_relay(peer);
            }
        }
        Control::NodesAnnounced {
            generation,
            part,
            parts,
            nodes,
            via,
        } => {
            shared
                .counts
                .announcements_received
                .fetch_add(1, Ordering::Relaxed);
            if up {
                let before = guard.announced_by(peer);
                match guard
                    .router
                    .announce_part(peer, generation, part, parts, nodes, via)
                {
                    Ok(true) => {
                        let after = guard.announced_by(peer);
                        // Gone are the nodes no peer announces now.
                        dropped = before
                            .difference(&after)
                            .filter(|node| !guard.router.reaches(node))
                            .cloned()
                            .collect();
                        relay_changed = true;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        drop(guard);
                        shared.refused(src, &e);
                        return;
                    }
                }
            }
        }
        Control::Health { node, state } => {
            let daemon = node.daemon();
            // A report about another daemon's node than the peer's own is
            // relayed, and taken only from a peer trusted as a relay, and
            // then only while no link to that daemon reports it directly.
            let about_peer = daemon == peer;
            let mut reported_directly = false;
            if !about_peer {
                if daemon == shared.local {
                    drop(guard);
                    shared.refused(src, &"a health report about this daemon's own client");
                    return;
                }
                if !shared.trusts_relay(peer) {
                    drop(guard);
                    shared.relayed_refused(
                        src,
                        &"a health report about another daemon's client, from a peer not trusted as a relay (--link-trust-relay)",
                    );
                    return;
                }
                reported_directly = guard.router.has_peer(daemon);
            }
            if up && watching && !reported_directly {
                shared
                    .counts
                    .health_received
                    .fetch_add(1, Ordering::Relaxed);
                // A relay passes its peers' own nodes' reports on.
                pass_on = shared.relay && about_peer;
                report = Some((node, state));
            }
        }
    }
    drop(guard);
    if !up {
        shared.wake();
        return;
    }
    if relay_changed {
        shared.relay_changed();
    }
    if send_unhealthy {
        shared.send_unhealthy(peer);
    }
    if !dropped.is_empty() {
        shared.nodes_gone(None, dropped);
    }
    if let Some((node, state)) = report {
        if pass_on {
            let item = Outbound::Health {
                node: node.clone(),
                state,
                except: Some(peer),
            };
            if let Err(TrySendError::Full(_)) = shared.outbound.try_send(item) {
                debug!("a health report to relay was dropped: the link send queue is full");
            }
        }
        if let Some(health) = shared.registry.health_tracker() {
            health.remote(&node, state);
        }
    }
}

/// A Hello from `peer`: the link starts afresh.
fn on_hello(shared: &Shared, peer: DaemonId, bytes: &[u8], now: Instant) {
    let addr = shared.peers.get(&peer).and_then(Peer::addr);
    let (remote, flags) = match wire::read_hello(bytes) {
        Ok(hello) => hello,
        Err(e) => {
            shared.refused(addr.unwrap_or(shared.addr), &e);
            return;
        }
    };
    let outcome = match CapabilityNegotiator::new(shared.hello).observe_remote(remote) {
        Ok(outcome) => outcome,
        Err(e) => {
            shared.refused(addr.unwrap_or(shared.addr), &e);
            return;
        }
    };
    let answer = flags.answer;
    let mut replies = Vec::with_capacity(3);
    let mut gone = BTreeSet::new();
    let mut daemon = None;
    let mut relay_changed = false;
    {
        let mut guard = shared.state.lock();
        let State { router, links, .. } = &mut *guard;
        let Some(link) = links.get_mut(&peer) else {
            return;
        };
        let was_up = link.up;
        // A Hello that asks starts the session afresh, as one from a peer
        // that restarted does: its summaries and announcements count from 1
        // again, and the nodes it announced before are gone. An answer only
        // completes a start this daemon asked for, so once the link is up it
        // keeps what the peer sent since, which may have overtaken it.
        if !answer || !was_up {
            gone = router.remove_peer(peer).unwrap_or_default();
            daemon = (!router.relays_for(peer)).then_some(peer);
            if router.add_peer(peer).is_err() {
                return;
            }
            relay_changed = true;
        }
        relay_changed |= router.set_relay(peer, flags.relay) == Ok(true);
        link.up = true;
        link.heard = Some(now);
        link.hello_backoff = HELLO_BACKOFF.0;
        link.outcome = Some(outcome);
        if !answer {
            replies.push(shared.hello_bytes(true));
        }
        if let Some(summary) = &link.summary {
            replies.push(Control::Interest(summary.clone()));
        }
        if let Some(announced) = &link.announced {
            replies.extend(shared.announcement_messages(announced));
        }
        if !was_up {
            info!(
                peer = %peer,
                addr = ?addr,
                version = outcome.agreed_version,
                capabilities = outcome.agreed.bits(),
                registry_match = outcome.registry_match,
                relays = flags.relay,
                trusted_as_relay = shared.trusts_relay(peer),
                "link up"
            );
        } else if !answer {
            info!(peer = %peer, "link restarted: the peer daemon began a new session");
        }
    }
    if relay_changed {
        shared.relay_changed();
    }
    if !gone.is_empty() {
        shared.nodes_gone(daemon, gone);
    }
    for reply in replies {
        shared.queue(peer, reply);
    }
}

/// When to try a peer again after an attempt that began at `began` failed
/// at `ended`: after `backoff`, and, when this daemon's key is the lower
/// (`lower`), no sooner than twice [`CONNECT_RESEND`] after the attempt
/// began. The lower key's unanswered initiation counts as crossing the
/// peer's for its first [`CONNECT_RESEND`], during which the peer's own is
/// refused; the spacing leaves the peer at least as long again in which its
/// own is answered. The higher key's initiations never block the lower's,
/// which it always yields to, so it keeps its backoff and tries often.
fn next_attempt(began: Instant, ended: Instant, backoff: Duration, lower: bool) -> Instant {
    let after = ended + backoff;
    if lower {
        after.max(began + 2 * CONNECT_RESEND)
    } else {
        after
    }
}

/// When the connect thread next tries a peer at its known address, and
/// when it last tried it at all.
struct Attempts {
    /// When the next attempt at the known address is due.
    at: Instant,
    /// The wait after that attempt, should it fail.
    backoff: Duration,
    /// When the last attempt, at any address, began.
    began: Option<Instant>,
}

/// The connect thread: keep a sealed session to every peer whose address is
/// known, retrying one that is down with a backoff ([`next_attempt`]); and
/// make the handshake a peer's announcement asks for, as soon as a lower
/// key's spacing allows, at an address no other peer's links use.
fn connect(shared: &Shared) {
    let start = Instant::now();
    let mut due: BTreeMap<DaemonId, Attempts> = shared
        .peers
        .keys()
        .map(|&id| {
            let first = Attempts {
                at: start,
                backoff: CONNECT_BACKOFF.0,
                began: None,
            };
            (id, first)
        })
        .collect();
    while !shared.stop.load(Ordering::Acquire) {
        let mut next = Instant::now() + Duration::from_millis(50);
        for (&id, peer) in &shared.peers {
            let Some(due) = due.get_mut(&id) else {
                continue;
            };
            if shared.sealing.has_session(&peer.key) {
                due.backoff = CONNECT_BACKOFF.0;
                peer.found.lock().candidate = None;
                continue;
            }
            let lower = shared.public_key < peer.key;
            let now = Instant::now();
            let spaced = !lower || due.began.is_none_or(|b| now >= b + 2 * CONNECT_RESEND);
            let announced = if spaced {
                peer.found.lock().candidate.take()
            } else {
                None
            };
            let target = match announced {
                Some(addr) if shared.taken(id, addr) => {
                    debug!(peer = %id, %addr, "an announced address another peer's links use was not tried");
                    None
                }
                Some(addr) => Some((addr, true)),
                None if now >= due.at => peer.addr().map(|addr| (addr, false)),
                None => None,
            };
            if let Some((addr, announced)) = target {
                let began = Instant::now();
                due.began = Some(began);
                match shared.sealing.connect(addr, &peer.key, CONNECT_TIMEOUT) {
                    Ok(()) => {
                        due.backoff = CONNECT_BACKOFF.0;
                        shared.learned(id, addr);
                        debug!(peer = %id, %addr, announced, "sealed session to the peer daemon made");
                        shared.hello_now(id);
                    }
                    Err(e) => {
                        due.at = next_attempt(began, Instant::now(), due.backoff, lower);
                        due.backoff = (due.backoff * 2).min(CONNECT_BACKOFF.1);
                        debug!(peer = %id, %addr, announced, error = %e, retry_in = ?due.backoff, "the peer daemon did not answer the handshake");
                    }
                }
                if shared.stop.load(Ordering::Acquire) {
                    return;
                }
            }
            if peer.addr().is_some() {
                next = next.min(due.at);
            }
        }
        let wait = next.saturating_duration_since(Instant::now());
        std::thread::sleep(wait.min(Duration::from_millis(50)));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> NodeKey {
        NodeKey::generate().unwrap()
    }

    fn any() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn a_peer_is_written_addr_equals_key() {
        let public = key().public_key();
        let text = format!("192.0.2.7:7400={public}");
        let peer: LinkPeer = text.parse().unwrap();
        assert_eq!(peer.addr, "192.0.2.7:7400".parse().unwrap());
        assert_eq!(peer.key, public);
        assert_eq!(peer.to_string(), text);
        assert_eq!(
            peer.daemon_id(),
            DaemonId::from_public_key(public.as_bytes())
        );
        let v6: LinkPeer = format!("[2001:db8::7]:7400={public}").parse().unwrap();
        assert_eq!(v6.addr.port(), 7400);
        assert_eq!("no-key".parse::<LinkPeer>(), Err(LinkPeerError::NoKey));
        assert!(matches!(
            format!("host:7400={public}").parse::<LinkPeer>(),
            Err(LinkPeerError::Address(_))
        ));
        assert!(matches!(
            "192.0.2.7:7400=abcd".parse::<LinkPeer>(),
            Err(LinkPeerError::Key(_))
        ));
    }

    #[test]
    fn a_configuration_the_links_cannot_run_is_refused() {
        let own = key();
        let base = LinkConfig::new(own.clone(), any());
        assert!(matches!(base.check(), Err(LinkSetupError::NoPeers)));
        let peer = LinkPeer::new("127.0.0.1:7001".parse().unwrap(), key().public_key());
        assert!(base.clone().with_peer(peer).check().is_ok());
        let me = LinkPeer::new("127.0.0.1:7002".parse().unwrap(), own.public_key());
        assert!(matches!(
            base.clone().with_peer(peer).with_peer(me).check(),
            Err(LinkSetupError::OwnKey { .. })
        ));
        let again = LinkPeer::new("127.0.0.1:7003".parse().unwrap(), peer.key);
        assert!(matches!(
            base.clone().with_peer(peer).with_peer(again).check(),
            Err(LinkSetupError::DuplicatePeer { .. })
        ));
        let there = LinkPeer::new(peer.addr, key().public_key());
        assert!(matches!(
            base.clone().with_peer(peer).with_peer(there).check(),
            Err(LinkSetupError::DuplicateAddress { .. })
        ));
        assert!(matches!(
            base.clone()
                .with_peer(peer)
                .with_heartbeat(Duration::from_secs(5))
                .check(),
            Err(LinkSetupError::Timing { .. })
        ));
    }

    #[test]
    fn a_relay_is_trusted_only_as_a_configured_peer() {
        let own = key();
        let fixed = LinkPeer::new("127.0.0.1:7001".parse().unwrap(), key().public_key());
        let alone = key().public_key();
        let group = AnnounceConfig::new(SocketAddrV4::new(Ipv4Addr::new(239, 255, 80, 1), 7401));
        let base = LinkConfig::new(own.clone(), any())
            .with_peer(fixed)
            .with_peer_key(alone)
            .with_announce(group);
        assert!(
            !base.relay && base.trusted_relays.is_empty(),
            "off by default"
        );
        let trusting = base
            .clone()
            .with_relay()
            .with_trusted_relay(fixed.key)
            .with_trusted_relay(alone);
        assert!(trusting.check().is_ok());
        assert_eq!(
            trusting.trusted_ids(),
            [
                fixed.daemon_id(),
                DaemonId::from_public_key(alone.as_bytes())
            ]
            .into_iter()
            .collect()
        );
        for stranger in [key().public_key(), own.public_key()] {
            assert!(matches!(
                base.clone().with_trusted_relay(stranger).check(),
                Err(LinkSetupError::TrustedRelayNotPeer { key }) if key == stranger
            ));
        }
    }

    #[test]
    fn a_relay_passes_on_once_what_came_from_its_origin_with_a_hop_to_spare() {
        let limit = |hops| with_hop_limit(Pulse::zeroed(), hops);
        let onward = |hops, relayed| onward_hops(&limit(hops), relayed).map(NonZeroU64::get);
        assert_eq!(onward(ORIGIN_HOP_LIMIT, false), Some(1), "from its origin");
        assert_eq!(onward(1, false), None, "no hop left after this one");
        assert_eq!(onward(0, false), None, "from a build before relays");
        assert_eq!(
            onward(ORIGIN_HOP_LIMIT, true),
            None,
            "relayed once already, whatever its limit says"
        );
        assert_eq!(onward(9, true), None);
    }

    #[test]
    fn peers_named_by_key_alone_need_an_announcement_group_that_is_one() {
        let own = key();
        let base = LinkConfig::new(own.clone(), any());
        let alone = key().public_key();
        let group = AnnounceConfig::new(SocketAddrV4::new(Ipv4Addr::new(239, 255, 80, 1), 7401));
        assert!(matches!(
            base.clone().with_peer_key(alone).check(),
            Err(LinkSetupError::PeerKeysWithoutAnnounce)
        ));
        assert!(base
            .clone()
            .with_peer_key(alone)
            .with_announce(group)
            .check()
            .is_ok());
        assert!(matches!(
            base.clone()
                .with_peer_key(own.public_key())
                .with_announce(group)
                .check(),
            Err(LinkSetupError::OwnPeerKey)
        ));
        let peer = LinkPeer::new("127.0.0.1:7001".parse().unwrap(), alone);
        assert!(matches!(
            base.clone()
                .with_peer(peer)
                .with_peer_key(alone)
                .with_announce(group)
                .check(),
            Err(LinkSetupError::DuplicatePeer { .. })
        ));
        // A fixed peer may be announced too.
        assert!(base
            .clone()
            .with_peer(peer)
            .with_announce(group)
            .check()
            .is_ok());
        for bad in [
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 7401),
            SocketAddrV4::new(Ipv4Addr::new(239, 255, 80, 1), 0),
        ] {
            let announce = AnnounceConfig::new(bad);
            assert!(
                matches!(
                    base.clone().with_peer(peer).with_announce(announce).check(),
                    Err(LinkSetupError::AnnounceGroup { .. })
                ),
                "{bad}"
            );
        }
        for ttl in [0, 256] {
            assert!(matches!(
                base.clone()
                    .with_peer(peer)
                    .with_announce(group.with_ttl(ttl))
                    .check(),
                Err(LinkSetupError::AnnounceTtl { .. })
            ));
        }
        assert!(base
            .clone()
            .with_peer(peer)
            .with_announce(group.with_ttl(255))
            .check()
            .is_ok());
        let v6 = LinkConfig::new(own, "[::1]:0".parse().unwrap()).with_peer(peer);
        assert!(matches!(
            v6.with_announce(group).check(),
            Err(LinkSetupError::AnnounceBind { .. })
        ));
    }

    #[test]
    fn a_count_asks_to_be_logged_at_each_power_of_two() {
        let count = AtomicU64::new(0);
        let logged: Vec<_> = (0..9).filter_map(|_| bump(&count, 1)).collect();
        assert_eq!(logged, [1, 2, 4, 8]);
        assert_eq!(bump(&count, 10), Some(19));
    }

    #[test]
    fn the_lower_key_starts_its_attempts_two_seconds_apart_and_the_higher_backs_off() {
        let began = Instant::now();
        let ended = began + CONNECT_TIMEOUT;
        let short = CONNECT_BACKOFF.0;
        assert_eq!(
            next_attempt(began, ended, short, true),
            began + 2 * CONNECT_RESEND
        );
        assert_eq!(next_attempt(began, ended, short, false), ended + short);
        let long = CONNECT_BACKOFF.1;
        assert_eq!(next_attempt(began, ended, long, true), ended + long);
    }

    #[test]
    fn a_link_not_up_that_hears_its_peer_says_hello_soon_but_not_at_once_again() {
        let now = Instant::now();
        let mut link = PeerLink::new(now, &PacerConfig::default());
        link.hello_sent = Some(now);
        link.hello_due = now + Duration::from_secs(5);
        link.hello_backoff = Duration::from_secs(5);
        link.heard(now + Duration::from_millis(10));
        assert_eq!(link.hello_due, now + HELLO_BACKOFF.0);
        assert_eq!(link.hello_backoff, HELLO_BACKOFF.0);
    }
}
