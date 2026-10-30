// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Links between daemons, tier 2: the part of the multi-host mesh that
//! needs no transport (ADR-0021). The daemon (`mesh-hub`) drives it over
//! ADR-0018's sealed UDP: its links carry these control messages and
//! forward its clients' sends by these summaries, through this router and
//! this cache, to its peers and, through a relay, one hop further.
//!
//! Everything here is plain logic with no socket, clock or thread of its
//! own: a daemon drives it, passing in what arrived and what time it is,
//! and the tests run it deterministically.
//!
//! - [`DaemonId`] and [`QualifiedOrigin`]: a daemon named by the
//!   fingerprint of its public key, and a client across links as
//!   `name@` and that fingerprint in 16 hex digits, apart from the
//!   `name@` and 8 hex digits its own daemon gives it (32 for a client that
//!   proved a key at attach).
//! - [`Interest`]: the summary of a daemon's subscriptions that its peers
//!   forward by. It never refuses a send that one of the subscriptions
//!   would take, and it has a canonical encoding; [`Interest::union`] sums
//!   two up, as a relay does. [`SummaryPacer`] bounds how often it is sent.
//! - [`Router`]: which peers a send goes to, and where a destination is,
//!   by the clients each peer announces ([`Announcement`], paced by a
//!   [`SummaryPacer`] of its own and split into parts when one message
//!   cannot carry it), its own and, from a relay, those reached through it;
//!   and what a relay summarises and announces to each peer.
//! - [`ForwardCache`]: the sends delivered lately, each by its
//!   [`ForwardKey`] (content id, origin and send stamp), so that one
//!   arriving twice, directly and through a relay, is delivered once and
//!   two sends of the same content both are. [`hops_left`] and
//!   [`next_hop`] read and spend the hop limit a forwarded pulse carries,
//!   [`ORIGIN_HOP_LIMIT`] as it leaves its origin.
//! - [`Control`]: the messages a link carries besides envelopes, with
//!   their canonical encoding; [`Link`], what a link does; and
//!   [`link_pair`], two ends joined in memory, for tests.
//!
//! # One hop, or two through a relay
//!
//! A daemon forwards its own clients' sends to the peers whose interest
//! may match them, with a hop limit of [`ORIGIN_HOP_LIMIT`]. A daemon that
//! is not a relay delivers what a peer forwards to its own subscribers
//! only, and forwards it no further. A relay (ADR-0021, item 9) also
//! forwards it once more, to its other peers whose interest may match it,
//! never back to the peer it came from or to its origin's daemon, spending
//! a hop ([`next_hop`]); and it tells each peer the interest of its other
//! peers that are not relays ([`Router::summary_for`]) and their clients
//! ([`Router::via_for`]), so that what those peers want reaches it. Relays
//! do not sum one another's interest up, and what a relay passes on has no
//! hop left, so a send crosses at most one relay. Forwarding through any
//! number of hops is not decided here.
//!
//! # A relayed origin is only as trustworthy as its relay
//!
//! A link authenticates the daemon at its other end, and nothing more:
//! nothing signs an envelope, its origin or an announcement end to end.
//! The origin a relay reports for a send it passes on, and the clients it
//! says it reaches, are what the relay says they are. A daemon takes such
//! traffic only from a peer it trusts as a relay ([`Router::trust_relay`],
//! the daemon's `--link-trust-relay`), and refuses it from every other;
//! trusting a relay is trusting it to speak for the daemons behind it.
#![forbid(unsafe_code)]

mod announce;
mod cache;
mod codec;
mod control;
mod hop;
mod interest;
mod link;
mod origin;
mod pacer;
mod router;

pub use announce::{Announcement, ANNOUNCE_FIXED_BYTES, MAX_ANNOUNCE_PARTS};
pub use cache::{ForwardCache, ForwardKey, DEFAULT_FORWARD_CACHE};
pub use codec::CodecError;
pub use control::{Control, HealthState, CONTROL_VERSION, MAX_HELLO_BYTES};
pub use hop::{hops_left, next_hop, with_hop_limit, ORIGIN_HOP_LIMIT};
pub use interest::{Interest, INTEREST_VERSION};
pub use link::{link_pair, Forwarded, Link, LinkError, LinkItem, MemoryLink};
pub use origin::{DaemonId, OriginError, QualifiedOrigin};
pub use pacer::{Paced, PacerConfig, SummaryPacer, DEFAULT_REFRESH, DEFAULT_SUMMARIES_PER_SECOND};
pub use router::{Destination, RouteError, Router};

/// The longest control message a link carries, in bytes: 64 KiB.
///
/// It bounds what one message from a peer can make the receiver read and
/// hold. A link may carry less: the daemon's link over sealed UDP carries a
/// control message in one run of fragments, whose 64 KiB its own framing
/// shares, and sends an [`Interest`] longer than what is left as
/// [`Interest::coarsened`] to it.
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;

/// The bytes a control message spends before its body: its version and
/// its kind.
pub const CONTROL_HEADER_BYTES: usize = 2;

/// The longest [`Interest`] encoding, in bytes: what a control message has
/// room for after its header, so that every interest fits in one.
pub const MAX_INTEREST_BYTES: usize = MAX_CONTROL_BYTES - CONTROL_HEADER_BYTES;
