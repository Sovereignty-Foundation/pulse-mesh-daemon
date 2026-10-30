// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Two and three daemons in memory, end to end. Each is a small harness
//! that owns what a daemon would: a [`Router`], a [`ForwardCache`], a
//! [`SummaryPacer`], its clients and their subscriptions, matched with the
//! reference matcher in `common`. They are joined in a full mesh by
//! [`link_pair`]s, and every step runs on one thread at made-up times, so
//! each test is deterministic.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use mesh_link::{
    link_pair, Announcement, Control, DaemonId, Destination, ForwardCache, ForwardKey, Forwarded,
    Interest, Link, LinkItem, MemoryLink, PacerConfig, QualifiedOrigin, Router, SummaryPacer,
    MAX_CONTROL_BYTES,
};
use mesh_port_protocol::FilterSpec;
use pulse_canon::{NodeId, PulseEnvelope, PulseEnvelopeId};

/// What a client received.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Delivery {
    client: String,
    origin: String,
    channel: String,
    id: PulseEnvelopeId,
}

/// A client's origin on its own daemon, as `mesh-hub` writes it.
fn local_origin(name: &str) -> String {
    let suffix: String = NodeId::from_name(name).as_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{name}@{suffix}")
}

fn on(channel: &str) -> FilterSpec {
    FilterSpec {
        channel: Some(channel.into()),
        ..FilterSpec::default()
    }
}

struct Daemon {
    id: DaemonId,
    router: Router,
    cache: ForwardCache,
    pacer: SummaryPacer,
    clients: BTreeSet<String>,
    subscriptions: Vec<(String, FilterSpec)>,
    links: BTreeMap<DaemonId, MemoryLink>,
    delivered: Vec<Delivery>,
    /// Envelopes that arrived from each peer, copies included.
    received: BTreeMap<DaemonId, usize>,
    /// The hub's clock, which stamps each send's `monotonic_nanos`.
    clock: u64,
    /// Announcements of this daemon's clients sent so far.
    announcements: u64,
}

impl Daemon {
    fn new(key: u8) -> Self {
        let id = DaemonId::from_public_key(&[key; 32]);
        Self {
            id,
            router: Router::new(id),
            cache: ForwardCache::default(),
            pacer: SummaryPacer::new(&PacerConfig::default()),
            clients: BTreeSet::new(),
            subscriptions: Vec::new(),
            links: BTreeMap::new(),
            delivered: Vec::new(),
            received: BTreeMap::new(),
            clock: 0,
            announcements: 0,
        }
    }

    /// The hub's stamp for a send: later than every one before.
    fn stamp(&mut self) -> u64 {
        self.clock += 1_000;
        self.clock
    }

    fn node(&self, name: &str) -> QualifiedOrigin {
        QualifiedOrigin::new(self.id, name).unwrap()
    }

    /// A link to `peer` is up: the session opens with a Hello.
    fn link(&mut self, peer: DaemonId, mut link: MemoryLink) {
        self.router.add_peer(peer).unwrap();
        link.send_control(&Control::Hello(b"PMSH".to_vec()))
            .unwrap();
        self.links.insert(peer, link);
    }

    /// The link to `peer` is down; returns the nodes reported `detached`.
    fn unlink(&mut self, peer: DaemonId) -> BTreeSet<QualifiedOrigin> {
        self.links.remove(&peer);
        self.router.remove_peer(peer).unwrap()
    }

    fn attach(&mut self, name: &str) {
        self.clients.insert(name.into());
        let nodes: BTreeSet<_> = self.clients.iter().map(|c| self.node(c)).collect();
        self.announcements += 1;
        let announcement = Announcement::new(nodes).with_generation(self.announcements);
        for message in announcement.messages(MAX_CONTROL_BYTES).unwrap() {
            for link in self.links.values_mut() {
                link.send_control(&message).unwrap();
            }
        }
    }

    fn subscribe(&mut self, client: &str, filter: FilterSpec, now: Instant) {
        self.subscriptions.push((client.into(), filter));
        self.interest_changed(now);
    }

    fn unsubscribe(&mut self, client: &str, now: Instant) {
        self.subscriptions.retain(|(c, _)| c != client);
        self.interest_changed(now);
    }

    fn interest_changed(&mut self, now: Instant) {
        let filters = self.subscriptions.iter().map(|(_, f)| f);
        self.pacer.changed(Interest::from_filters(filters));
        self.flush(now);
    }

    /// Send the summary to every peer if one is due at `now`.
    fn flush(&mut self, now: Instant) {
        if let Some(summary) = self.pacer.poll(now) {
            let message = Control::Interest(summary);
            for link in self.links.values_mut() {
                link.send_control(&message).unwrap();
            }
        }
    }

    /// A send by `client`, which names no type name: delivered to the
    /// subscriptions here, and forwarded to the peers that may want it.
    /// Returns the envelope as it was forwarded.
    fn send(&mut self, client: &str, channel: &str, payload: &[u8]) -> Forwarded {
        // As the daemon builds it: named by the channel when the send
        // names no type name, and stamped by the hub.
        let mut envelope = PulseEnvelope::with_content(0, Some(channel.into()), payload.to_vec());
        envelope.monotonic_nanos = self.stamp();
        self.deliver(&local_origin(client), channel, &envelope);
        let forwarded = Forwarded::new(self.node(client), channel, envelope);
        for peer in self.router.route_send(channel, 0, None) {
            self.links
                .get_mut(&peer)
                .unwrap()
                .send_envelope(&forwarded)
                .unwrap();
        }
        forwarded
    }

    /// A send by `client` to the node `dest`.
    fn send_to(
        &mut self,
        client: &str,
        dest: &QualifiedOrigin,
        channel: &str,
        payload: &[u8],
    ) -> Result<PulseEnvelopeId, String> {
        let mut envelope = PulseEnvelope::with_content(0, Some(channel.into()), payload.to_vec());
        envelope.monotonic_nanos = self.stamp();
        let id = envelope.id();
        match self.router.route_to(dest) {
            Destination::Local if self.clients.contains(dest.name()) => {
                self.delivered.push(Delivery {
                    client: dest.name().into(),
                    origin: local_origin(client),
                    channel: channel.into(),
                    id,
                });
            }
            Destination::Local => return Err(format!("no client is attached as {dest}")),
            Destination::Peer(peer) => {
                let forwarded =
                    Forwarded::new(self.node(client), channel, envelope).addressed_to(dest.clone());
                self.links
                    .get_mut(&peer)
                    .unwrap()
                    .send_envelope(&forwarded)
                    .unwrap();
            }
            // No daemon here relays.
            Destination::Relay(_) | Destination::Unknown => {
                return Err(format!("no daemon has announced {dest}"))
            }
        }
        Ok(id)
    }

    /// Deliver to every subscription here that admits the envelope.
    fn deliver(&mut self, origin: &str, channel: &str, envelope: &PulseEnvelope) {
        for (client, filter) in &self.subscriptions {
            if common::admits(
                filter,
                channel,
                envelope.envelope_type(),
                envelope.type_name(),
                origin,
            ) {
                self.delivered.push(Delivery {
                    client: client.clone(),
                    origin: origin.into(),
                    channel: channel.into(),
                    id: envelope.id(),
                });
            }
        }
    }

    /// Handle everything waiting on the links; returns how many items.
    fn pump(&mut self) -> usize {
        let mut handled = 0;
        let peers: Vec<_> = self.links.keys().copied().collect();
        for peer in peers {
            while let Some(item) = self
                .links
                .get_mut(&peer)
                .unwrap()
                .recv_timeout(Duration::ZERO)
                .unwrap()
            {
                handled += 1;
                self.handle(peer, item);
            }
        }
        handled
    }

    fn handle(&mut self, peer: DaemonId, item: LinkItem) {
        match item {
            LinkItem::Control(Control::Hello(_)) => {
                // A new session: forget what the peer said before.
                self.router.remove_peer(peer);
                self.router.add_peer(peer).unwrap();
            }
            LinkItem::Control(Control::Interest(interest)) => {
                self.router.update_interest(peer, interest).unwrap();
            }
            LinkItem::Control(Control::NodesAnnounced {
                generation,
                part,
                parts,
                nodes,
                via,
            }) => {
                self.router
                    .announce_part(peer, generation, part, parts, nodes, via)
                    .unwrap();
            }
            LinkItem::Control(Control::Health { .. } | Control::Heartbeat) => {}
            LinkItem::Envelope(forwarded) => {
                *self.received.entry(peer).or_default() += 1;
                if self.cache.seen_or_insert(ForwardKey::of(&forwarded)) {
                    return;
                }
                let origin = forwarded.origin.to_string();
                match &forwarded.dest {
                    Some(dest)
                        if dest.daemon() == self.id && self.clients.contains(dest.name()) =>
                    {
                        self.delivered.push(Delivery {
                            client: dest.name().into(),
                            origin,
                            channel: forwarded.channel.clone(),
                            id: forwarded.envelope.id(),
                        });
                    }
                    Some(_) => {}
                    None => self.deliver(&origin, &forwarded.channel, &forwarded.envelope),
                }
                // One hop: what a peer forwarded goes no further.
            }
        }
    }

    fn deliveries_to(&self, client: &str) -> Vec<&Delivery> {
        self.delivered
            .iter()
            .filter(|d| d.client == client)
            .collect()
    }

    fn received_from(&self, peer: DaemonId) -> usize {
        self.received.get(&peer).copied().unwrap_or(0)
    }
}

/// Daemons linked to one another, and the time they share.
struct Mesh {
    daemons: Vec<Daemon>,
    now: Instant,
}

impl Mesh {
    /// `n` daemons, each linked to every other.
    fn full(n: u8) -> Self {
        let mut daemons: Vec<Daemon> = (1..=n).map(Daemon::new).collect();
        for i in 0..daemons.len() {
            for j in i + 1..daemons.len() {
                let (a, b) = link_pair();
                let (a_id, b_id) = (daemons[i].id, daemons[j].id);
                daemons[i].link(b_id, a);
                daemons[j].link(a_id, b);
            }
        }
        let mut mesh = Self {
            daemons,
            now: Instant::now(),
        };
        mesh.settle();
        mesh
    }

    /// Pump every daemon until nothing is in flight.
    fn settle(&mut self) {
        while self.daemons.iter_mut().map(Daemon::pump).sum::<usize>() > 0 {}
    }

    /// Let `by` pass: each daemon sends the summary due by then.
    fn advance(&mut self, by: Duration) {
        self.now += by;
        let now = self.now;
        for daemon in &mut self.daemons {
            daemon.flush(now);
        }
        self.settle();
    }
}

#[test]
fn a_send_reaches_only_the_daemons_whose_subscribers_match() {
    let mut mesh = Mesh::full(3);
    let now = mesh.now;
    let [a, b, c] = &mut mesh.daemons[..] else {
        unreachable!()
    };
    a.attach("producer");
    a.attach("audit");
    a.subscribe("audit", on("jobs/**"), now);
    b.attach("jobs");
    b.subscribe("jobs", on("jobs/*"), now);
    c.attach("metrics");
    c.subscribe("metrics", on("metrics/**"), now);
    let (a_id, c_id) = (a.id, c.id);
    mesh.settle();

    let job = mesh.daemons[0]
        .send("producer", "jobs/new", b"1")
        .envelope
        .id();
    let cpu = mesh.daemons[0]
        .send("producer", "metrics/cpu/0", b"2")
        .envelope
        .id();
    mesh.daemons[0].send("producer", "elsewhere", b"3");
    mesh.settle();
    let [a, b, c] = &mesh.daemons[..] else {
        unreachable!()
    };

    let qualified = QualifiedOrigin::new(a_id, "producer").unwrap().to_string();
    assert_eq!(
        b.delivered,
        [Delivery {
            client: "jobs".into(),
            origin: qualified.clone(),
            channel: "jobs/new".into(),
            id: job,
        }],
        "across the link the origin is qualified by its daemon"
    );
    assert_eq!(c.deliveries_to("metrics").len(), 1);
    assert_eq!(c.deliveries_to("metrics")[0].id, cpu);
    assert_eq!(
        (b.received_from(a_id), c.received_from(a_id)),
        (1, 1),
        "each got its own send only"
    );
    assert_eq!(b.received_from(c_id), 0);
    // On its own daemon the producer keeps its local origin.
    assert_eq!(a.deliveries_to("audit")[0].origin, local_origin("producer"));
    assert_ne!(local_origin("producer"), qualified);
}

#[test]
fn a_destination_send_reaches_exactly_its_nodes_daemon() {
    let mut mesh = Mesh::full(3);
    mesh.daemons[0].attach("boss");
    mesh.daemons[1].attach("worker");
    mesh.daemons[2].attach("worker");
    mesh.settle();
    let worker_b = mesh.daemons[1].node("worker");
    let ghost_c = mesh.daemons[2].node("ghost");
    let boss = mesh.daemons[0].node("boss");

    let task = mesh.daemons[0]
        .send_to("boss", &worker_b, "tasks", b"t")
        .unwrap();
    let refusal = mesh.daemons[0]
        .send_to("boss", &ghost_c, "tasks", b"t")
        .unwrap_err();
    assert!(refusal.contains(&ghost_c.to_string()), "{refusal}");
    mesh.daemons[0]
        .send_to("boss", &boss, "self", b"s")
        .unwrap();
    mesh.settle();

    let [a, b, c] = &mesh.daemons[..] else {
        unreachable!()
    };
    assert_eq!(b.deliveries_to("worker").len(), 1);
    assert_eq!(b.deliveries_to("worker")[0].id, task);
    assert!(
        c.delivered.is_empty(),
        "the other host's worker is another node"
    );
    assert_eq!(c.received_from(a.id), 0);
    assert_eq!(
        a.deliveries_to("boss").len(),
        1,
        "a local destination is delivered here"
    );
}

#[test]
fn the_same_content_sent_twice_by_one_origin_is_delivered_twice() {
    let mut mesh = Mesh::full(2);
    let now = mesh.now;
    mesh.daemons[0].attach("producer");
    mesh.daemons[1].attach("jobs");
    mesh.daemons[1].subscribe("jobs", on("jobs/*"), now);
    mesh.settle();
    let first = mesh.daemons[0].send("producer", "jobs/tick", b"same");
    let second = mesh.daemons[0].send("producer", "jobs/tick", b"same");
    assert_eq!(first.envelope.id(), second.envelope.id(), "one content id");
    mesh.settle();
    let deliveries = mesh.daemons[1].deliveries_to("jobs");
    assert_eq!(deliveries.len(), 2, "two sends, two deliveries");
    assert!(deliveries.iter().all(|d| d.id == first.envelope.id()));
}

#[test]
fn one_envelope_arriving_by_two_links_is_delivered_once() {
    let mut mesh = Mesh::full(3);
    let now = mesh.now;
    mesh.daemons[0].attach("producer");
    mesh.daemons[1].attach("jobs");
    mesh.daemons[1].subscribe("jobs", on("jobs/*"), now);
    mesh.settle();
    let (a_id, b_id, c_id) = (mesh.daemons[0].id, mesh.daemons[1].id, mesh.daemons[2].id);
    // A forwards it to B directly; a copy reaches B by way of C as well.
    let sent = mesh.daemons[0].send("producer", "jobs/new", b"once");
    mesh.daemons[2]
        .links
        .get_mut(&b_id)
        .unwrap()
        .send_envelope(&sent)
        .unwrap();
    mesh.settle();
    let b = &mesh.daemons[1];
    assert_eq!((b.received_from(a_id), b.received_from(c_id)), (1, 1));
    assert_eq!(b.deliveries_to("jobs").len(), 1);
}

#[test]
fn a_reordered_older_announcement_is_ignored() {
    let mut mesh = Mesh::full(2);
    mesh.daemons[1].attach("x");
    mesh.daemons[1].attach("y");
    mesh.settle();
    let b_id = mesh.daemons[1].id;
    let a_id = mesh.daemons[0].id;
    let (x, y) = (mesh.daemons[1].node("x"), mesh.daemons[1].node("y"));
    // The first announcement, of x alone, arrives again late.
    let stale = Control::NodesAnnounced {
        generation: 1,
        part: 0,
        parts: 1,
        nodes: [x.clone()].into_iter().collect(),
        via: BTreeSet::new(),
    };
    mesh.daemons[1]
        .links
        .get_mut(&a_id)
        .unwrap()
        .send_control(&stale)
        .unwrap();
    mesh.settle();
    let a = &mesh.daemons[0];
    assert_eq!(a.router.route_to(&y), Destination::Peer(b_id));
    assert_eq!(a.router.nodes(b_id).unwrap().len(), 2);
    assert!(a.router.nodes(b_id).unwrap().contains(&x));
}

#[test]
fn an_envelope_arriving_twice_is_delivered_once() {
    let mut mesh = Mesh::full(2);
    let now = mesh.now;
    mesh.daemons[1].attach("jobs");
    mesh.daemons[1].subscribe("jobs", on("jobs/*"), now);
    mesh.settle();
    let a = &mut mesh.daemons[0];
    let envelope = PulseEnvelope::with_content(0, Some("jobs/new".into()), b"once".to_vec());
    let forwarded = Forwarded::new(a.node("producer"), "jobs/new", envelope);
    let b_id = *a.links.keys().next().unwrap();
    let link = a.links.get_mut(&b_id).unwrap();
    link.send_envelope(&forwarded).unwrap();
    link.send_envelope(&forwarded).unwrap();
    let a_id = a.id;
    mesh.settle();
    let b = &mesh.daemons[1];
    assert_eq!(b.received_from(a_id), 2);
    assert_eq!(b.deliveries_to("jobs").len(), 1);
}

#[test]
fn a_peer_whose_interest_changes_stops_or_starts_receiving() {
    let mut mesh = Mesh::full(2);
    mesh.daemons[0].attach("producer");
    mesh.daemons[1].attach("jobs");
    mesh.settle();
    let a_id = mesh.daemons[0].id;
    let b_id = mesh.daemons[1].id;

    mesh.daemons[0].send("producer", "jobs/1", b"1");
    mesh.settle();
    assert_eq!(
        mesh.daemons[1].received_from(a_id),
        0,
        "no summary, nothing forwarded"
    );

    let now = mesh.now;
    mesh.daemons[1].subscribe("jobs", on("jobs/*"), now);
    mesh.settle();
    assert!(mesh.daemons[0]
        .router
        .interest(b_id)
        .unwrap()
        .may_match("jobs/2", 0, None));
    mesh.daemons[0].send("producer", "jobs/2", b"2");
    mesh.settle();
    assert_eq!(
        mesh.daemons[1].deliveries_to("jobs").len(),
        1,
        "it starts receiving"
    );

    // The unsubscribe falls inside the pacer's interval: until its summary
    // goes out, A still forwards, and B matches exactly and delivers none.
    mesh.daemons[1].unsubscribe("jobs", now);
    mesh.settle();
    mesh.daemons[0].send("producer", "jobs/3", b"3");
    mesh.settle();
    assert_eq!(mesh.daemons[1].received_from(a_id), 2);
    assert_eq!(mesh.daemons[1].deliveries_to("jobs").len(), 1);

    mesh.advance(Duration::from_millis(250));
    mesh.daemons[0].send("producer", "jobs/4", b"4");
    mesh.settle();
    assert_eq!(mesh.daemons[1].received_from(a_id), 2, "it stops receiving");

    let now = mesh.now + Duration::from_millis(250);
    mesh.now = now;
    mesh.daemons[1].subscribe(
        "jobs",
        FilterSpec {
            channel: Some("jobs/*".into()),
            health: true,
            ..FilterSpec::default()
        },
        now,
    );
    mesh.settle();
    let held = mesh.daemons[0].router.interest(b_id).unwrap();
    assert!(held.wants_health());
    assert_eq!(held.generation(), 3);
    mesh.daemons[0].send("producer", "jobs/5", b"5");
    mesh.settle();
    assert_eq!(
        mesh.daemons[1].deliveries_to("jobs").len(),
        2,
        "and starts again"
    );
}

#[test]
fn what_a_peer_forwarded_is_not_forwarded_again() {
    let mut mesh = Mesh::full(3);
    let now = mesh.now;
    mesh.daemons[0].attach("producer");
    for daemon in &mut mesh.daemons[1..] {
        daemon.attach("jobs");
        daemon.subscribe("jobs", on("jobs/*"), now);
    }
    mesh.settle();
    mesh.daemons[0].send("producer", "jobs/new", b"x");
    mesh.settle();
    let [a, b, c] = &mesh.daemons[..] else {
        unreachable!()
    };
    assert_eq!(b.deliveries_to("jobs").len(), 1);
    assert_eq!(c.deliveries_to("jobs").len(), 1);
    assert_eq!((b.received_from(a.id), c.received_from(a.id)), (1, 1));
    assert_eq!((b.received_from(c.id), c.received_from(b.id)), (0, 0));
}

#[test]
fn a_link_that_goes_down_reports_its_peers_nodes_detached() {
    let mut mesh = Mesh::full(2);
    mesh.daemons[1].attach("x");
    mesh.daemons[1].attach("y");
    mesh.settle();
    let b_id = mesh.daemons[1].id;
    let nodes = [mesh.daemons[1].node("x"), mesh.daemons[1].node("y")];
    let a = &mut mesh.daemons[0];
    assert_eq!(a.router.route_to(&nodes[0]), Destination::Peer(b_id));
    assert_eq!(
        a.unlink(b_id),
        nodes.iter().cloned().collect::<BTreeSet<_>>()
    );
    assert_eq!(a.router.route_to(&nodes[0]), Destination::Unknown);
    assert!(a.send_to("anyone", &nodes[1], "c", b"p").is_err());
}
