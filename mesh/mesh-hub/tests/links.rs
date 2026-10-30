// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Daemons that link over sealed UDP on loopback (ADR-0021): a client's send
//! reaches the subscribers of the daemons whose interest matches it, with
//! its qualified origin, once, one hop, and nothing goes to a daemon that
//! wants none of it; a daemon whose key is not configured cannot link; a
//! peer that goes down and comes back resumes; a peer cannot speak for
//! another, by sending from its address or by claiming its id; and an
//! envelope of nearly 64 KiB crosses as a run of sealed fragments.
//!
//! Then the second part (items 6 and 7): each daemon announces its clients,
//! and a peer's view follows an attach and a detach within the pacer
//! interval and ignores an older announcement; a send with `to` reaches the
//! named node alone, on its daemon or another, and is refused for a node no
//! one announced; a peer's nodes' health reaches the watchers here, a new
//! watcher is told those not healthy at once, and a link that falls silent
//! reports its nodes `detached`; and a lower-keyed daemon leaves a peer
//! connecting from another port of its configured IP room to make its
//! session within about a second.
//!
//! Then LAN announcement (item 2's second half): daemons that name each
//! other by key alone find each other's link endpoints on a multicast group
//! on loopback, two and three of them, and link and forward as above, from
//! their flags too; an announcement from a key no one lists is ignored and
//! counted; a forged one, naming a listed key at a port where that key is
//! not, costs one handshake that fails, however often it repeats within
//! five seconds, and none while a session stands; and a peer named with its
//! address keeps it. A host that carries no multicast on loopback (some
//! sandboxes and containers) says so and checks nothing of these.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;

use common::{hub_name, reserved_udp_addr, small_store, socket_path, Node, Upp};
use mesh_capability::{CapabilityFlags, Hello};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::internals::{link_announce, link_wire};
use mesh_hub::link::{AnnounceConfig, DaemonId, LinkConfig, PublicKey, ANNOUNCE_INTERVAL};
use mesh_hub::protocol::base64;
use mesh_hub::{ConnectionPolicy, LinkStats};
use mesh_link::{Control, HealthState, QualifiedOrigin};
use pulse_canon::PulseEnvelope;
use pulse_wire_udp::{bind_sealed_pair, Allowlist, MulticastConfig, Receiver, Sender};
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// The longest any condition is waited for: generous, for a loaded machine;
/// each wait polls and ends as soon as its condition holds.
const PATIENCE: Duration = Duration::from_secs(15);

/// A reply's timeout.
const REPLY: Duration = Duration::from_secs(5);

/// The links' heartbeat and silence limit in these tests, short so that a
/// peer that goes away is noticed in well under a second.
const HEARTBEAT: Duration = Duration::from_millis(100);
const SILENCE: Duration = Duration::from_millis(600);

/// The pacer's shortest time between two summaries, by default.
const PACER_INTERVAL: Duration = Duration::from_millis(250);

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl Node {
    /// Its links, to no peer yet, with the tests' heartbeat and silence.
    fn links(&self) -> LinkConfig {
        LinkConfig::new(self.key.clone(), self.addr)
            .with_heartbeat(HEARTBEAT)
            .with_silence(SILENCE)
    }
}

/// A running daemon and the socket its clients attach on.
struct Daemon {
    mesh: EmbeddedMesh,
    socket: PathBuf,
}

impl Daemon {
    /// `node`, linked to `peers`.
    fn start(node: &Node, peers: &[&Node]) -> Self {
        Self::start_with(node, peers, ConnectionPolicy::default())
    }

    /// `node`, linked to `peers`, serving its clients under `policy`.
    fn start_with(node: &Node, peers: &[&Node], policy: ConnectionPolicy) -> Self {
        let links = peers
            .iter()
            .fold(node.links(), |links, peer| links.with_peer(peer.peer()));
        Self::launch(node, links, policy)
    }

    /// `node`, announcing itself on `group`, linked to `alone` by their keys
    /// alone and to `fixed` at their addresses.
    fn start_lan(node: &Node, alone: &[&Node], fixed: &[&Node], group: SocketAddrV4) -> Self {
        let links = node.links().with_announce(AnnounceConfig::new(group));
        let links = alone.iter().fold(links, |links, peer| {
            links.with_peer_key(peer.key.public_key())
        });
        let links = fixed
            .iter()
            .fold(links, |links, peer| links.with_peer(peer.peer()));
        Self::launch(node, links, ConnectionPolicy::default())
    }

    /// `node`, linked by `links`, serving its clients under `policy`.
    fn launch(node: &Node, links: LinkConfig, policy: ConnectionPolicy) -> Self {
        let socket = socket_path(&node.tag);
        let mesh = EmbeddedMesh::start_with_links(
            &hub_name(&node.tag),
            &[Bind::Uds(socket.clone())],
            policy,
            small_store(),
            links,
        )
        .expect("a linked daemon");
        assert_eq!(mesh.link_addr(), Some(node.addr));
        assert_eq!(mesh.daemon_id().map(|id| id.to_string()), Some(node.id()));
        Self { mesh, socket }
    }

    fn stats(&self) -> LinkStats {
        self.mesh.link_stats().expect("links")
    }

    /// A client attached here as `name`.
    fn client(&self, name: &str) -> Client {
        self.attached(name).0
    }

    /// A client attached here as `name`, and the node id its ack named.
    fn attached(&self, name: &str) -> (Client, String) {
        let mut client = Client::new(Upp::connect(&self.socket));
        client.upp.send(&format!(
            r#"{{"op":"attach","id":"attach","name":"{name}","protocol_version":"v0"}}"#
        ));
        let ack = client.reply("attach");
        assert_eq!(ack["op"], "ack", "attach as {name}: {ack}");
        let node_id = ack["node_id"].as_str().unwrap().to_string();
        (client, node_id)
    }

    /// Wait until `n` of its links are up.
    fn wait_up(&self, n: usize) {
        wait_until(&format!("{n} links up"), || self.stats().up == n);
    }
}

/// A client of a daemon.
struct Client {
    upp: Upp,
    n: u64,
    /// Frames read while waiting for a reply, in the order they came.
    stash: VecDeque<serde_json::Value>,
}

impl Client {
    fn new(upp: Upp) -> Self {
        Self {
            upp,
            n: 0,
            stash: VecDeque::new(),
        }
    }

    fn next_id(&mut self) -> String {
        self.n += 1;
        format!("r{}", self.n)
    }

    /// The reply to the request `id`, keeping the frames before it.
    fn reply(&mut self, id: &str) -> serde_json::Value {
        let deadline = Instant::now() + REPLY;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = self.upp.frame(left).expect("a reply");
            let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
            if frame["id"] == id {
                return frame;
            }
            self.stash.push_back(frame);
        }
    }

    /// The next frame within `timeout`, a kept one first, or `None`.
    fn next(&mut self, timeout: Duration) -> Option<serde_json::Value> {
        if let Some(frame) = self.stash.pop_front() {
            return Some(frame);
        }
        let frame = self.upp.frame(timeout)?;
        Some(serde_json::from_str(&frame).unwrap())
    }

    /// Subscribe to `channel`; the subscription id.
    fn subscribe(&mut self, channel: &str) -> String {
        self.subscribe_to(&format!(r#"{{"channel":"{channel}"}}"#))
    }

    /// Subscribe with the filter `filter`, as JSON; the subscription id.
    fn subscribe_to(&mut self, filter: &str) -> String {
        let id = self.next_id();
        self.upp.send(&format!(
            r#"{{"op":"subscribe","id":"{id}","filter":{filter}}}"#
        ));
        let ack = self.reply(&id);
        assert_eq!(ack["op"], "ack", "{ack}");
        ack["subscription_id"].as_str().unwrap().to_string()
    }

    fn unsubscribe(&mut self, subscription: &str) {
        let id = self.next_id();
        self.upp.send(&format!(
            r#"{{"op":"unsubscribe","id":"{id}","subscription_id":"{subscription}"}}"#
        ));
        let ack = self.reply(&id);
        assert_eq!(ack["op"], "ack", "{ack}");
    }

    /// Send `payload` on `channel`; the envelope id the ack names.
    fn send(&mut self, channel: &str, payload: &[u8]) -> String {
        let id = self.next_id();
        let payload = base64::encode(payload);
        self.upp.send(&format!(
            r#"{{"op":"send","id":"{id}","channel":"{channel}","payload":"{payload}"}}"#
        ));
        let ack = self.reply(&id);
        assert_eq!(ack["op"], "ack", "{ack}");
        ack["envelope_id"].as_str().unwrap().to_string()
    }

    /// Send `payload` on `channel` to the node `to`; the ack or the error.
    fn send_to(&mut self, to: &str, channel: &str, payload: &[u8]) -> serde_json::Value {
        let id = self.next_id();
        let payload = base64::encode(payload);
        self.upp.send(&format!(
            r#"{{"op":"send","id":"{id}","channel":"{channel}","payload":"{payload}","to":"{to}"}}"#
        ));
        self.reply(&id)
    }

    /// The next event within `timeout`, or `None`.
    fn event(&mut self, timeout: Duration) -> Option<serde_json::Value> {
        let event = self.next(timeout)?;
        assert_eq!(event["op"], "event", "{event}");
        Some(event)
    }

    /// The states the health notices about `node` that arrive within
    /// `quiet` of each other name, skipping every other frame.
    fn states_of(&mut self, node: &str, quiet: Duration) -> Vec<String> {
        std::iter::from_fn(|| self.next(quiet))
            .filter(|frame| frame["op"] == "health" && frame["node_id"] == node)
            .map(|frame| frame["state"].as_str().unwrap().to_string())
            .collect()
    }

    /// Wait until a health notice says `node` is `state`.
    fn wait_for_state(&mut self, node: &str, state: &str) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            assert!(
                Instant::now() < deadline,
                "no notice that {node} is {state}"
            );
            if let Some(frame) = self.next(Duration::from_millis(50)) {
                if frame["op"] == "health" && frame["node_id"] == node && frame["state"] == state {
                    return;
                }
            }
        }
    }

    /// Every event that arrives within `quiet` of the one before.
    fn drain(&mut self, quiet: Duration) -> Vec<serde_json::Value> {
        std::iter::from_fn(|| self.event(quiet)).collect()
    }
}

/// Send probes from `from` on `channel` until one reaches `to`, then drain
/// `to`; how long the first probe took to arrive after the call began.
fn wait_for_flow(from: &mut Client, to: &mut Client, channel: &str) -> Duration {
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < PATIENCE, "no probe on {channel} arrived");
        from.send(channel, b"probe");
        if to.event(Duration::from_millis(20)).is_some() {
            let took = start.elapsed();
            to.drain(Duration::from_millis(200));
            return took;
        }
    }
}

#[test]
fn a_send_reaches_a_subscriber_on_another_daemon_with_its_qualified_origin() {
    let (a, b) = (Node::new("lka"), Node::new("lkb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    db.wait_up(1);

    let mut sender = da.client("sender");
    let mut watcher = db.client("watcher");
    watcher.subscribe("jobs/new");
    wait_for_flow(&mut sender, &mut watcher, "jobs/new");

    let envelope_id = sender.send("jobs/new", b"job 1");
    let event = watcher.event(REPLY).expect("the event");
    assert_eq!(event["channel"], "jobs/new");
    assert_eq!(event["origin"], format!("sender@{}", a.id()));
    assert_eq!(event["envelope_id"], envelope_id.as_str());
    assert_eq!(event["type_id"], 0);
    assert!(
        event.get("type_name").is_none(),
        "the send named none: {event}"
    );
    assert_eq!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap(),
        b"job 1"
    );
    assert!(watcher.drain(Duration::from_millis(200)).is_empty());

    // The sender's own daemon has no subscriber, so B forwards nothing back.
    assert_eq!(db.stats().forwards_sent, 0);
    let stats = da.stats();
    assert_eq!((stats.configured, stats.up), (1, 1));
    assert!(stats.summaries_received >= 1, "{stats:?}");
    assert!(db.stats().summaries_sent >= 1);
    assert_eq!(db.stats().duplicates_dropped, 0);
}

#[test]
fn nothing_goes_to_a_daemon_whose_subscribers_want_none_of_it() {
    let (a, b) = (Node::new("lna"), Node::new("lnb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);

    let mut sender = da.client("sender");
    let mut watcher = db.client("watcher");
    watcher.subscribe("other/*");
    // Once a send on other/ arrives, A holds B's summary.
    wait_for_flow(&mut sender, &mut watcher, "other/x");
    let before = da.stats().forwards_sent;
    for i in 0..20u8 {
        sender.send("jobs/new", &[i]);
    }
    assert!(watcher.drain(Duration::from_millis(300)).is_empty());
    assert_eq!(
        da.stats().forwards_sent,
        before,
        "A forwarded none of the sends B's interest refuses"
    );
    assert_eq!(db.stats().forwards_received, before);

    // What B wants still goes, one forward each.
    sender.send("other/y", b"wanted");
    assert_eq!(watcher.event(REPLY).unwrap()["channel"], "other/y");
    wait_until("the forward to be counted", || {
        da.stats().forwards_sent == before + 1
    });
}

#[test]
fn a_subscription_starts_the_flow_within_the_pacer_interval_and_its_end_stops_it() {
    let (a, b) = (Node::new("lsa"), Node::new("lsb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    db.wait_up(1);
    let mut sender = da.client("sender");
    let mut watcher = db.client("watcher");
    // B's summary of no subscription has reached A: nothing is forwarded.
    wait_until("B's first summary", || da.stats().summaries_received >= 1);
    for _ in 0..5 {
        sender.send("flow/x", b"before");
    }
    assert_eq!(da.stats().forwards_sent, 0);

    // A pacer interval has passed since B's last summary, so the new one goes
    // at once; probes every 20 ms find the flow within the interval and the
    // round trips, with slack for a loaded machine.
    std::thread::sleep(PACER_INTERVAL);
    let subscribed = Instant::now();
    let sub = watcher.subscribe("flow/x");
    let took = wait_for_flow(&mut sender, &mut watcher, "flow/x");
    assert!(
        took < PACER_INTERVAL + Duration::from_millis(750),
        "the flow started {took:?} after the subscribe ({:?} in all)",
        subscribed.elapsed()
    );
    assert!(da.stats().forwards_sent >= 1);

    // Unsubscribed, the flow stops once the next summary arrives.
    watcher.unsubscribe(&sub);
    let unsubscribed = Instant::now();
    wait_until("the flow to stop", || {
        let before = da.stats().forwards_sent;
        sender.send("flow/x", b"after");
        std::thread::sleep(Duration::from_millis(100));
        da.stats().forwards_sent == before
    });
    assert!(
        unsubscribed.elapsed() < PACER_INTERVAL + Duration::from_secs(2),
        "{:?}",
        unsubscribed.elapsed()
    );
    let before = da.stats().forwards_sent;
    for _ in 0..10 {
        sender.send("flow/x", b"after");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(da.stats().forwards_sent, before);
    assert!(watcher.drain(Duration::from_millis(100)).is_empty());
}

#[test]
fn in_a_triangle_a_send_reaches_each_other_daemon_once_and_goes_no_further() {
    let nodes = [Node::new("lta"), Node::new("ltb"), Node::new("ltc")];
    let daemons: Vec<Daemon> = nodes
        .iter()
        .map(|node| {
            let peers: Vec<&Node> = nodes.iter().filter(|n| n.tag != node.tag).collect();
            Daemon::start(node, &peers)
        })
        .collect();
    for daemon in &daemons {
        daemon.wait_up(2);
    }
    let mut sender = daemons[0].client("sender");
    let mut on_b = daemons[1].client("on-b");
    let mut on_c = daemons[2].client("on-c");
    on_b.subscribe("tri/x");
    on_c.subscribe("tri/x");
    wait_for_flow(&mut sender, &mut on_b, "tri/x");
    wait_for_flow(&mut sender, &mut on_c, "tri/x");
    on_b.drain(Duration::from_millis(200));
    on_c.drain(Duration::from_millis(200));
    let before: Vec<LinkStats> = daemons.iter().map(Daemon::stats).collect();

    let id = sender.send("tri/x", b"once");
    for (client, daemon) in [(&mut on_b, &daemons[1]), (&mut on_c, &daemons[2])] {
        let event = client.event(REPLY).expect("the event");
        assert_eq!(event["envelope_id"], id.as_str());
        assert_eq!(event["origin"], format!("sender@{}", nodes[0].id()));
        let again = client.drain(Duration::from_millis(300));
        assert!(again.is_empty(), "a second copy: {again:?}");
        let stats = daemon.stats();
        assert_eq!(stats.forwards_sent, 0, "one hop: it forwards nothing on");
        assert_eq!(stats.duplicates_dropped, 0);
    }
    wait_until("A's two forwards to be counted", || {
        daemons[0].stats().forwards_sent == before[0].forwards_sent + 2
    });
    for i in [1, 2] {
        assert_eq!(
            daemons[i].stats().forwards_received,
            before[i].forwards_received + 1
        );
    }
}

#[test]
fn a_daemon_whose_key_is_not_configured_cannot_link() {
    let (a, b, stranger) = (Node::new("lra"), Node::new("lrb"), Node::new("lrs"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    // The stranger knows B's key and address; B does not list the stranger.
    let ds = Daemon::start(&stranger, &[&b]);
    da.wait_up(1);
    db.wait_up(1);
    wait_until("B to refuse the stranger's handshakes", || {
        db.stats().handshakes_refused >= 2
    });
    std::thread::sleep(SILENCE);
    assert_eq!(ds.stats().up, 0);
    assert_eq!(db.stats().up, 1, "B links to A alone");
    assert_eq!(ds.stats().summaries_received, 0);
    assert_eq!(ds.stats().forwards_received, 0);

    // And nothing the stranger's clients send reaches B's.
    let mut watcher = db.client("watcher");
    watcher.subscribe("open/x");
    let mut intruder = ds.client("intruder");
    for _ in 0..10 {
        intruder.send("open/x", b"let me in");
    }
    assert!(watcher.drain(Duration::from_millis(300)).is_empty());
    assert_eq!(ds.stats().forwards_sent, 0);
}

#[test]
fn a_peer_that_goes_down_and_comes_back_resumes() {
    let (a, b) = (Node::new("lda"), Node::new("ldb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    let mut sender = da.client("sender");
    {
        let mut watcher = db.client("watcher");
        watcher.subscribe("up/x");
        wait_for_flow(&mut sender, &mut watcher, "up/x");
    }

    // B stops: A notices its silence and takes the link down.
    db.mesh.shutdown();
    wait_until("A to take the link down", || da.stats().up == 0);
    for _ in 0..5 {
        sender.send("up/x", b"while down");
    }

    // B comes back with its key and its address, and the flow resumes.
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    db.wait_up(1);
    let mut watcher = db.client("watcher");
    watcher.subscribe("up/x");
    wait_for_flow(&mut sender, &mut watcher, "up/x");
    let id = sender.send("up/x", b"after");
    let event = watcher.event(REPLY).expect("the event");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap(),
        b"after"
    );
    assert!(
        watcher.drain(Duration::from_millis(200)).is_empty(),
        "nothing sent while B was down arrives late"
    );
}

/// A link datagram forwarding a send on `channel` by `name`, a client of
/// `origin`, from a daemon that claims to be `claimed`.
fn forged(claimed: DaemonId, origin: DaemonId, name: &str, channel: &str) -> link_wire::Datagram {
    let mut envelope = PulseEnvelope::with_content(0, Some(channel.into()), b"forged".to_vec());
    envelope.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
    let forward = link_wire::LinkForward {
        origin: QualifiedOrigin::new(origin, name).unwrap(),
        channel: channel.into(),
        named_type: false,
        envelope,
        dest: None,
    };
    link_wire::forward(&forward, claimed).unwrap()
}

/// B is a configured peer of C's, with a sealed session of its own, but it
/// sends from A's address: C takes what it sends as B's, by the key that
/// opened it, and refuses B's datagrams that claim A's id or forward A's
/// clients, while another peer's traffic goes on as before.
#[test]
fn a_peer_cannot_speak_for_another_by_its_address_or_its_claims() {
    let (a, b, c, d) = (
        Node::new("lia"),
        Node::new("lib"),
        Node::new("lic"),
        Node::new("lid"),
    );
    let dc = Daemon::start(&c, &[&a, &b, &d]);
    let dd = Daemon::start(&d, &[&c]);
    dd.wait_up(1);
    let mut watcher = dc.client("watcher");
    watcher.subscribe("who/*");
    let mut honest = dd.client("honest");
    wait_for_flow(&mut honest, &mut watcher, "who/d");

    // B's key, on A's address (A's daemon is not running).
    let mut allowlist = Allowlist::new();
    allowlist.allow_at(c.key.public_key(), c.addr);
    let (mut rogue, _rx) = bind_sealed_pair(a.addr, b.key.clone(), allowlist).unwrap();
    rogue
        .sealing()
        .unwrap()
        .connect(c.addr, &c.key.public_key(), PATIENCE)
        .unwrap();
    let id = |node: &Node| DaemonId::from_public_key(node.key.public_key().as_bytes());
    let refused = dc.stats().datagrams_refused;
    for datagram in [
        // Claiming to be A, from A's address, forwarding A's client.
        forged(id(&a), id(&a), "mallory", "who/a"),
        // As B, forwarding a client of A's: one hop, a peer's own clients only.
        forged(id(&b), id(&a), "mallory", "who/a"),
        // As B, its own client: taken as B's, whatever address it came from.
        forged(id(&b), id(&b), "mallory", "who/b"),
    ] {
        rogue
            .send_to(
                datagram.pulse.monotonic_nanos,
                &datagram.pulse,
                &datagram.bytes,
                c.addr,
            )
            .unwrap();
    }
    wait_until("C to refuse the two forgeries", || {
        dc.stats().datagrams_refused == refused + 2
    });
    let events = watcher.drain(Duration::from_millis(300));
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["channel"], "who/b");
    assert_eq!(events[0]["origin"], format!("mallory@{}", b.id()));

    // The other peer's traffic is as it was.
    let sent = honest.send("who/d", b"still here");
    let event = watcher.event(REPLY).expect("the honest event");
    assert_eq!(event["envelope_id"], sent.as_str());
    assert_eq!(event["origin"], format!("honest@{}", d.id()));
    assert_eq!(dc.stats().datagrams_refused, refused + 2);
}

/// The bytes a forward of a send on `channel` by the client `name` spends
/// around its payload: the link envelope, the forward's header with the two
/// texts, and the forwarded envelope's own framing, measured on the
/// datagram the link writes for an empty payload.
fn forward_framing(name: &str, channel: &str) -> usize {
    let daemon = DaemonId::from_bytes([0; 8]);
    let forward = link_wire::LinkForward {
        origin: QualifiedOrigin::new(daemon, name).unwrap(),
        channel: channel.into(),
        named_type: false,
        envelope: PulseEnvelope::with_content(0, Some(channel.into()), Vec::new()),
        dest: None,
    };
    link_wire::forward(&forward, daemon).unwrap().bytes.len()
}

/// The largest payload a send on `channel` by the client `name` can carry
/// across a link: the transport's message limit less the forward's framing.
fn largest_payload(name: &str, channel: &str) -> usize {
    pulse_wire_udp::MAX_MESSAGE - forward_framing(name, channel)
}

/// The payload of a send on `channel` whose envelope fills one entry of the
/// hub's store.
fn full_entry_payload(channel: &str) -> usize {
    core_store::MAX_ENTRY_SIZE
        - PulseEnvelope::with_content(0, Some(channel.into()), Vec::new()).canonical_size()
}

#[test]
fn an_envelope_of_nearly_64_kib_crosses_as_a_run_of_sealed_fragments() {
    let (a, b) = (Node::new("lfa"), Node::new("lfb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    let mut sender = da.client("sender");
    let mut watcher = db.client("watcher");
    watcher.subscribe("big");
    wait_for_flow(&mut sender, &mut watcher, "big");

    let len = largest_payload("sender", "big");
    assert!(len + 200 > pulse_wire_udp::MAX_MESSAGE, "{len}");
    let payload: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
    let id = sender.send("big", &payload);
    let event = watcher.event(REPLY).expect("the large event");
    assert_eq!(event["envelope_id"], id.as_str());
    assert!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap() == payload,
        "the payload arrived whole and unchanged"
    );

    // One byte more does not fit a run: it is delivered at home and not
    // forwarded, and the refusal is counted.
    let dropped = da.stats().forwards_dropped;
    sender.send("big", &vec![7; len + 1]);
    wait_until("the refused forward to be counted", || {
        da.stats().forwards_dropped == dropped + 1
    });
    assert!(watcher.drain(Duration::from_millis(300)).is_empty());
    assert_eq!(db.stats().datagrams_refused, 0);

    // Once the transport's limit leaves room for an envelope that fills a
    // store entry, such an envelope crosses too.
    let full = full_entry_payload("big");
    if len >= full {
        let payload: Vec<u8> = (0..full).map(|i| (i * 17 % 253) as u8).collect();
        let id = sender.send("big", &payload);
        let event = watcher.event(REPLY).expect("the full entry's event");
        assert_eq!(event["envelope_id"], id.as_str());
        assert!(
            base64::decode(event["payload"].as_str().unwrap()).unwrap() == payload,
            "a full store entry arrived whole"
        );
    }
}

/// A `mesh-hub` process with links and metrics, and its log.
struct Process {
    child: Child,
    log: PathBuf,
    socket: PathBuf,
}

impl Process {
    fn start(tag: &str, node: &Node, peer: &Node, key_file: &std::path::Path) -> Self {
        let links = ["--link-peer".to_string(), peer.peer().to_string()];
        Self::start_with(tag, node, key_file, &links)
    }

    /// `node`'s daemon, its node key in `key_file`, its peers and the rest
    /// of its link flags `links`.
    fn start_with(tag: &str, node: &Node, key_file: &std::path::Path, links: &[String]) -> Self {
        let socket = socket_path(tag);
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name(tag), "--uds-path"])
            .arg(&socket)
            .args([
                "--no-ws",
                "--store-slots",
                "4",
                "--metrics-bind",
                "127.0.0.1:0",
            ])
            .arg("--node-key")
            .arg(key_file)
            .args(["--link-bind", &node.addr.to_string()])
            .args(links)
            .env("MESH_HUB_LOG", "info")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("start mesh-hub");
        Self { child, log, socket }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The metrics address, once the daemon serves.
    fn metrics(&mut self) -> SocketAddr {
        let mut addr = None;
        wait_until("the daemon to serve", || {
            let text = self.log();
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("mesh-hub exited ({status}):\n{text}");
            }
            addr = text
                .lines()
                .find(|l| l.contains("metrics listening"))
                .and_then(|l| l.split("addr=").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|a| a.parse().ok());
            addr.is_some() && UnixStream::connect(&self.socket).is_ok()
        });
        addr.unwrap()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

/// The value of the sample `line` names, scraped from `metrics`.
fn sample(metrics: SocketAddr, line: &str) -> u64 {
    let mut stream = TcpStream::connect(metrics).unwrap();
    stream.set_read_timeout(Some(REPLY)).unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).unwrap();
    page.lines()
        .find_map(|l| l.strip_prefix(line).and_then(|v| v.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("no {line} in:\n{page}"))
        .parse()
        .unwrap()
}

#[test]
fn the_daemon_links_from_its_flags_logs_its_identity_and_exports_its_link_counts() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Node::new("lpa"), Node::new("lpb"));
    let (key_a, key_b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    a.key.save(&key_a).unwrap();
    b.key.save(&key_b).unwrap();
    let mut pa = Process::start("lpa", &a, &b, &key_a);
    let mut pb = Process::start("lpb", &b, &a, &key_b);
    let (ma, mb) = (pa.metrics(), pb.metrics());
    for (metrics, process, node) in [(ma, &pa, &a), (mb, &pb, &b)] {
        assert_eq!(sample(metrics, "pms_daemon_links_configured"), 1);
        wait_until("the link to come up", || {
            sample(metrics, "pms_daemon_links_up") == 1
        });
        let log = process.log();
        let line = log
            .lines()
            .find(|l| l.contains("links to other daemons configured"))
            .unwrap_or_else(|| panic!("no startup line:\n{log}"));
        assert!(line.contains(&node.id()), "{line}");
        assert!(line.contains(&node.key.public_key().to_hex()), "{line}");
        assert!(line.contains(&node.addr.to_string()), "{line}");
        assert!(log.contains("link up"), "{log}");
    }

    // A send on A reaches a subscriber on B, and the counters say so.
    let mut watcher = Client::new(Upp::connect(&pb.socket));
    watcher.upp.attach("watcher");
    watcher.subscribe("cli/x");
    let mut sender = Client::new(Upp::connect(&pa.socket));
    sender.upp.attach("sender");
    wait_for_flow(&mut sender, &mut watcher, "cli/x");
    assert!(sample(ma, "pms_daemon_link_forwards_sent_total") >= 1);
    assert!(sample(mb, "pms_daemon_link_forwards_received_total") >= 1);
    assert!(sample(mb, "pms_daemon_link_summaries_sent_total") >= 1);
    assert!(sample(ma, "pms_daemon_link_summaries_received_total") >= 1);
    assert_eq!(sample(mb, "pms_daemon_link_duplicates_dropped_total"), 0);
    assert_eq!(sample(mb, "pms_daemon_link_datagrams_refused_total"), 0);
    // Without --link-announce, nothing is announced.
    for name in [
        "pms_daemon_link_lan_announcements_sent_total",
        "pms_daemon_link_lan_announcements_received_total",
        "pms_daemon_link_lan_announcements_ignored_total",
        "pms_daemon_link_lan_connects_total",
    ] {
        assert_eq!(sample(ma, name), 0, "{name}");
    }
}

/// A daemon's peer played by the test: a node's key on its link address,
/// on a sealed socket of the test's own, speaking link messages by hand.
struct Rogue {
    id: DaemonId,
    tx: Sender,
    _rx: Receiver,
    to: SocketAddr,
}

impl Rogue {
    /// `node`, linked to the daemon of `peer`: a sealed session made and a
    /// Hello sent, so that the daemon takes its link to `node` up.
    fn link(node: &Node, peer: &Node) -> Self {
        let mut allowlist = Allowlist::new();
        allowlist.allow_at(peer.key.public_key(), peer.addr);
        let (tx, rx) = bind_sealed_pair(node.addr, node.key.clone(), allowlist).unwrap();
        tx.sealing()
            .unwrap()
            .connect(peer.addr, &peer.key.public_key(), PATIENCE)
            .unwrap();
        let mut rogue = Self {
            id: DaemonId::from_public_key(node.key.public_key().as_bytes()),
            tx,
            _rx: rx,
            to: peer.addr,
        };
        let hello = Hello {
            version: mesh_capability::MAX_VERSION,
            capabilities: CapabilityFlags::default(),
            registry_hash: [0; 32],
        };
        rogue.control(&Control::Hello(link_wire::hello(
            &hello,
            link_wire::HelloFlags::default(),
        )));
        rogue
    }

    fn control(&mut self, message: &Control) {
        let datagram = link_wire::control(message, self.id).unwrap();
        self.tx
            .send_to(
                datagram.pulse.monotonic_nanos,
                &datagram.pulse,
                &datagram.bytes,
                self.to,
            )
            .unwrap();
    }

    /// Its clients `names`, qualified by its id.
    fn nodes(&self, names: &[&str]) -> BTreeSet<QualifiedOrigin> {
        names
            .iter()
            .map(|name| QualifiedOrigin::new(self.id, *name).unwrap())
            .collect()
    }

    /// Announce `names` as announcement `generation`, whole.
    fn announce(&mut self, generation: u64, names: &[&str]) {
        let nodes = self.nodes(names);
        self.control(&Control::NodesAnnounced {
            generation,
            part: 0,
            parts: 1,
            nodes,
            via: BTreeSet::new(),
        });
    }
}

/// A send's ack field `delivered`, refusing an error.
fn delivered(reply: &serde_json::Value) -> bool {
    assert_eq!(reply["op"], "ack", "{reply}");
    assert!(
        reply.get("persisted").is_none(),
        "a send to a node is not stored: {reply}"
    );
    reply["delivered"].as_bool().unwrap()
}

#[test]
fn a_send_to_a_node_reaches_that_node_alone_on_its_daemon_or_another() {
    let nodes = [Node::new("lea"), Node::new("leb"), Node::new("lec")];
    let daemons: Vec<Daemon> = nodes
        .iter()
        .map(|node| {
            let peers: Vec<&Node> = nodes.iter().filter(|n| n.tag != node.tag).collect();
            Daemon::start(node, &peers)
        })
        .collect();
    for daemon in &daemons {
        daemon.wait_up(2);
    }
    let (a, c) = (&daemons[0], &daemons[2]);
    let (mut sender, sender_id) = a.attached("sender");
    let (mut near, near_id) = a.attached("near");
    near.subscribe("dm/*");
    let mut on_b = daemons[1].client("on-b");
    on_b.subscribe("dm/*");
    let (mut target, target_here) = c.attached("target");
    target.subscribe("dm/x");
    let mut beside = c.client("beside");
    beside.subscribe("dm/*");
    let target_id = format!("target@{}", nodes[2].id());
    wait_until("A to hold the nodes B and C announce", || {
        a.stats().peer_nodes == 3
    });
    let quiet = Duration::from_millis(300);

    // To a node of C's: forwarded to C alone, and delivered there to that
    // node's matching subscription alone, with the sender's qualified origin.
    let ack = sender.send_to(&target_id, "dm/x", b"for target");
    assert!(delivered(&ack), "forwarded: {ack}");
    let event = target.event(REPLY).expect("the event");
    assert_eq!(event["envelope_id"], ack["envelope_id"]);
    assert_eq!(event["channel"], "dm/x");
    assert_eq!(event["origin"], format!("sender@{}", nodes[0].id()));
    assert_eq!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap(),
        b"for target"
    );
    for other in [&mut target, &mut beside, &mut on_b, &mut near] {
        assert!(other.drain(quiet).is_empty(), "a copy elsewhere");
    }
    // Forwarded on a channel the node does not subscribe to, it is acked as
    // forwarded, since delivery is remote, and nothing arrives.
    assert!(delivered(&sender.send_to(
        &target_id,
        "dm/other",
        b"unwanted"
    )));
    assert!(target.drain(quiet).is_empty());
    let stats = c.stats();
    assert_eq!((stats.addressed_received, stats.addressed_missing), (2, 0));
    assert_eq!(stats.forwards_sent, 0, "one hop: C forwards nothing on");
    assert_eq!(daemons[1].stats().addressed_received, 0, "nothing to B");

    // To a node here, by its node id or its qualified id: that connection's
    // matching subscription alone.
    for to in [near_id.clone(), format!("near@{}", nodes[0].id())] {
        assert!(delivered(&sender.send_to(&to, "dm/y", b"near")), "{to}");
        let event = near.event(REPLY).expect("the local event");
        assert_eq!(event["origin"], sender_id.as_str());
        assert_eq!(event["channel"], "dm/y");
    }
    // A node that holds no subscription matching the send: acked, and not
    // delivered.
    assert!(!delivered(&sender.send_to(&near_id, "other/z", b"nobody")));
    for other in [&mut near, &mut on_b, &mut target, &mut beside] {
        assert!(other.drain(quiet).is_empty(), "a copy elsewhere");
    }

    // No such node: refused, naming it. C's own form of its client's id
    // means nothing here.
    for ghost in [
        format!("ghost@{}", nodes[2].id()),
        "ghost@0011223344556677".to_string(),
        "ghost".to_string(),
        target_here,
    ] {
        let error = sender.send_to(&ghost, "dm/x", b"lost");
        assert_eq!(error["op"], "error", "{error}");
        assert_eq!(error["code"], "unknown_destination");
        assert!(
            error["message"].as_str().unwrap().contains(&ghost),
            "{error}"
        );
    }
    assert!(target.drain(quiet).is_empty());
    let sends = a.mesh.destination_sends();
    assert_eq!(
        (sends.local, sends.forwarded, sends.unknown),
        (3, 2, 4),
        "{sends:?}"
    );
}

#[test]
fn a_peers_view_of_the_nodes_follows_an_attach_and_a_detach_within_the_pacer_interval() {
    let (a, b) = (Node::new("lva"), Node::new("lvb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    db.wait_up(1);
    let mut sender = da.client("sender");
    wait_until("B's first announcement", || {
        da.stats().announcements_received >= 1
    });
    let slack = Duration::from_millis(500);

    // A pacer interval after the last, B's next announcement goes at once.
    std::thread::sleep(PACER_INTERVAL);
    let attached = Instant::now();
    let (mut late, _) = db.attached("late");
    wait_until("A to hold late", || da.stats().peer_nodes == 1);
    let took = attached.elapsed();
    assert!(took < PACER_INTERVAL + slack, "{took:?}");
    late.subscribe("hi");
    let node = format!("late@{}", b.id());
    assert!(delivered(&sender.send_to(&node, "hi", b"you")));
    assert_eq!(late.event(REPLY).expect("the event")["channel"], "hi");

    std::thread::sleep(PACER_INTERVAL);
    let detached = Instant::now();
    drop(late);
    wait_until("A to forget late", || da.stats().peer_nodes == 0);
    let took = detached.elapsed();
    assert!(took < PACER_INTERVAL + slack, "{took:?}");
    assert_eq!(
        sender.send_to(&node, "hi", b"gone")["code"],
        "unknown_destination"
    );
    assert!(db.stats().announcements_sent >= 3);
}

/// B is played by the test: its announcements, and an older one that
/// arrives late, its health reports, about its own client and about
/// another daemon's, and then its silence.
#[test]
fn a_peers_older_announcement_is_ignored_and_its_silence_reports_its_nodes_detached() {
    let (c, b) = (Node::new("loc"), Node::new("lob"));
    let dc = Daemon::start(&c, &[&b]);
    let (mut watcher, _) = dc.attached("watcher");
    watcher.subscribe_to(r#"{"channel":"none","health":true}"#);
    // C's summary that watches health is the one it sends B at the link's
    // start.
    std::thread::sleep(PACER_INTERVAL + Duration::from_millis(100));
    let mut rogue = Rogue::link(&b, &c);
    wait_until("C's link to B", || dc.stats().up == 1);
    rogue.announce(5, &["x", "y"]);
    rogue.announce(3, &["z"]);
    wait_until("C to hold B's announcement", || dc.stats().peer_nodes == 2);
    let mut sender = dc.client("sender");
    let [x, y] = ["x", "y"].map(|name| format!("{name}@{}", b.id()));
    rogue.control(&Control::Heartbeat);
    assert!(delivered(&sender.send_to(&x, "c", b"to x")));
    assert_eq!(
        sender.send_to(&format!("z@{}", b.id()), "c", b"to z")["code"],
        "unknown_destination",
        "the older announcement, which named z, was ignored"
    );

    // A report about B's own client reaches the watcher; one about C's
    // client, from B, is refused.
    let refused = dc.stats().datagrams_refused;
    let c_id = DaemonId::from_public_key(c.key.public_key().as_bytes());
    rogue.control(&Control::Health {
        node: QualifiedOrigin::new(c_id, "watcher").unwrap(),
        state: HealthState::Isolated,
    });
    rogue.control(&Control::Health {
        node: QualifiedOrigin::new(rogue.id, "x").unwrap(),
        state: HealthState::Degraded,
    });
    watcher.wait_for_state(&x, "degraded");
    wait_until("the foreign report to be refused", || {
        dc.stats().datagrams_refused == refused + 1
    });

    // B falls silent: C takes the link down and tells the watcher both of
    // B's nodes are detached, once each.
    let silent = Instant::now();
    wait_until("the link to go down", || dc.stats().up == 0);
    let mut states: Vec<(String, String)> = Vec::new();
    while states.len() < 2 {
        assert!(silent.elapsed() < PATIENCE, "{states:?}");
        if let Some(frame) = watcher.next(Duration::from_millis(50)) {
            if frame["op"] == "health" {
                let field = |key: &str| frame[key].as_str().unwrap().to_string();
                states.push((field("node_id"), field("state")));
            }
        }
    }
    states.sort();
    assert_eq!(
        states,
        [(x.clone(), "detached".into()), (y, "detached".into())]
    );
    assert!(
        silent.elapsed() < SILENCE + Duration::from_secs(1),
        "{:?}",
        silent.elapsed()
    );
    assert!(watcher.drain(Duration::from_millis(200)).is_empty());
    assert_eq!(dc.stats().peer_nodes, 0);
    assert_eq!(
        sender.send_to(&x, "c", b"to x")["code"],
        "unknown_destination"
    );
    let stats = dc.stats();
    assert_eq!(stats.health_received, 1);
    assert!(stats.remote_health_notices >= 3, "{stats:?}");
}

#[test]
fn a_watcher_sees_a_silent_node_on_another_daemon_turn_warning_isolated_and_detached() {
    let (a, b) = (Node::new("lwa"), Node::new("lwb"));
    let da = Daemon::start(&a, &[&b]);
    // B's clients are closed after a second of silence: a tick every 100 ms,
    // warning after about half a second, isolated after about nine tenths.
    let quick = ConnectionPolicy::default().with_idle_timeout(Duration::from_secs(1));
    let db = Daemon::start_with(&b, &[&a], quick);
    da.wait_up(1);
    db.wait_up(1);
    let (mut watcher, _) = da.attached("watcher");
    let before = db.stats().summaries_received;
    watcher.subscribe_to(r#"{"channel":"none","health":true}"#);
    wait_until("B to take A's summary that watches health", || {
        db.stats().summaries_received > before
    });

    let (quiet, _) = db.attached("quiet");
    let node = format!("quiet@{}", b.id());
    let mut states = Vec::new();
    let deadline = Instant::now() + PATIENCE;
    while states.last().map(String::as_str) != Some("detached") {
        assert!(Instant::now() < deadline, "{states:?}");
        if let Some(frame) = watcher.next(Duration::from_millis(50)) {
            if frame["op"] == "health" && frame["node_id"] == node.as_str() {
                states.push(frame["state"].as_str().unwrap().to_string());
            }
        }
    }
    assert_eq!(states, ["warning", "isolated", "detached"]);
    drop(quiet);
    assert!(db.stats().health_sent >= 2);
    assert!(da.stats().health_received >= 2);
    assert_eq!(da.stats().peer_nodes, 0);
}

#[test]
fn a_new_watcher_is_told_at_once_of_a_degraded_node_on_another_daemon() {
    let (a, b) = (Node::new("lga"), Node::new("lgb"));
    let da = Daemon::start(&a, &[&b]);
    let db = Daemon::start(&b, &[&a]);
    da.wait_up(1);
    db.wait_up(1);
    let (mut busy, _) = db.attached("busy");
    busy.upp.send(r#"{"op":"health","state":"degraded"}"#);
    let node = format!("busy@{}", b.id());
    // No subscription of A's watched health, so A knows nothing of B's
    // nodes: its first watcher learns of busy once its summary reaches B,
    // which answers with its nodes that are not healthy.
    let (mut first, _) = da.attached("first");
    first.subscribe_to(r#"{"channel":"none","health":true}"#);
    first.wait_for_state(&node, "degraded");
    // A second watcher's first notices name it: A knows it now.
    let (mut second, _) = da.attached("second");
    let subscribed = Instant::now();
    second.subscribe_to(r#"{"channel":"none","health":true}"#);
    assert_eq!(
        second.states_of(&node, Duration::from_millis(100)),
        ["degraded"]
    );
    assert!(subscribed.elapsed() < Duration::from_millis(500));
    assert!(
        first
            .states_of(&node, Duration::from_millis(200))
            .is_empty(),
        "told once"
    );
    // Healthy again, both are told.
    busy.upp.send(r#"{"op":"health","state":"ok"}"#);
    first.wait_for_state(&node, "healthy");
    second.wait_for_state(&node, "healthy");
}

/// As in #114's report: the daemon C, the lower key, lists B at an address
/// where nothing answers, and B's key connects from another port of the
/// same IP, sending a fresh initiation each second. C's own unanswered
/// initiations to the listed address refuse B's while fresh; spaced two
/// seconds apart, they leave B the next second, and B's session is made
/// within about one, where back-to-back attempts kept it waiting for
/// several.
#[test]
fn a_peer_reaching_a_lower_keyed_daemon_from_another_port_makes_its_session_promptly() {
    for offset in [0, 400, 1_300] {
        let (mut c, mut b) = (Node::new("lmc"), Node::new("lmb"));
        if c.key.public_key() > b.key.public_key() {
            std::mem::swap(&mut c.key, &mut b.key);
        }
        let dc = Daemon::start(&c, &[&b]);
        std::thread::sleep(Duration::from_millis(offset));
        let mut allowlist = Allowlist::new();
        allowlist.allow_at(c.key.public_key(), c.addr);
        let (peer, _rx) = bind_sealed_pair("127.0.0.1:0", b.key.clone(), allowlist).unwrap();
        let started = Instant::now();
        peer.sealing()
            .unwrap()
            .connect(c.addr, &c.key.public_key(), PATIENCE)
            .unwrap();
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(1_500),
            "{offset} ms after C started: the session took {took:?} ({} refused)",
            dc.stats().handshakes_refused
        );
    }
}

/// The multicast settings of a daemon whose links are bound to 127.0.0.1:
/// TTL 1 and loopback on, sent from and joined on the loopback interface.
fn loopback_multicast() -> MulticastConfig {
    let mut cfg = MulticastConfig::default();
    cfg.interface_v4 = Some(Ipv4Addr::LOCALHOST);
    cfg
}

/// A multicast group and port of the calling test's own, on loopback, once
/// a frame sent there has been seen to arrive; or `None`, said why, on a
/// host that does not carry multicast on loopback, where the test checks
/// nothing.
fn lan_group() -> Option<SocketAddrV4> {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    let host = NEXT.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id().to_le_bytes();
    let group = SocketAddrV4::new(
        Ipv4Addr::new(239, 255, pid[0] % 200 + 1, host),
        reserved_udp_addr().port(),
    );
    let cfg = loopback_multicast();
    let skip = |what: String| {
        eprintln!("{what}; this LAN announcement test checks nothing on this host");
        None
    };
    let rx = match Receiver::bind_multicast(group.into(), &cfg) {
        Ok(rx) => rx,
        Err(e) => return skip(format!("cannot join {group} on loopback ({e})")),
    };
    rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut rx = rx;
    let mut tx = Sender::bind("127.0.0.1:0").unwrap();
    if let Err(e) = tx.set_multicast(&cfg) {
        return skip(format!("multicast options refused on loopback ({e})"));
    }
    let mut probe = pulse_canon::Pulse::zeroed();
    probe.instruction = pulse_canon::Instruction::Data as u16;
    if let Err(e) = tx.send_to(1, &probe, b"probe", group.into()) {
        return skip(format!("cannot send to {group} on loopback ({e})"));
    }
    match rx.recv() {
        Ok(_) => Some(group),
        Err(e) => skip(format!(
            "no multicast frame reached {group} on loopback ({e})"
        )),
    }
}

/// Announcements the test makes up and sends to a group from a socket of
/// its own on 127.0.0.1, as a daemon sends its own.
struct Forger {
    tx: Sender,
    group: SocketAddrV4,
}

impl Forger {
    fn new(group: SocketAddrV4) -> Self {
        let tx = Sender::bind("127.0.0.1:0").unwrap();
        tx.set_multicast(&loopback_multicast()).unwrap();
        Self { tx, group }
    }

    /// Announce `key` with its links at `port` of this forger's IP.
    fn announce(&mut self, key: PublicKey, port: u16) {
        let announcement = link_announce::LanAnnouncement { key, port };
        let pulse = link_announce::pulse(&announcement);
        self.tx
            .send_to(
                pulse.monotonic_nanos,
                &pulse,
                &link_announce::encode(&announcement),
                self.group.into(),
            )
            .unwrap();
    }

    /// Announce `key` at `port` every 50 ms for `how_long`.
    fn keep_announcing(&mut self, key: PublicKey, port: u16, how_long: Duration) {
        let start = Instant::now();
        while start.elapsed() < how_long {
            self.announce(key, port);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A UDP socket on loopback where no daemon is, which counts what reaches
/// it: the port a forged announcement names.
struct Trap {
    socket: UdpSocket,
}

impl Trap {
    fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        Self { socket }
    }

    fn port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }

    /// The handshake initiations that have arrived since the last look,
    /// refusing anything else.
    fn initiations(&self) -> usize {
        let mut buf = [0; 2048];
        let mut n = 0;
        while let Ok(len) = self.socket.recv(&mut buf) {
            assert_eq!(len, pulse_wire_udp::sealed::INITIATION_BYTES);
            assert_eq!(buf[5], pulse_wire_udp::sealed::KIND_INITIATION);
            n += 1;
        }
        n
    }
}

#[test]
fn two_daemons_named_by_key_alone_find_each_other_on_a_lan_and_link() {
    let Some(group) = lan_group() else {
        return;
    };
    let (a, b) = (Node::new("lla"), Node::new("llb"));
    let da = Daemon::start_lan(&a, &[&b], &[], group);
    let db = Daemon::start_lan(&b, &[&a], &[], group);
    da.wait_up(1);
    db.wait_up(1);

    let mut on_a = da.client("on-a");
    let mut on_b = db.client("on-b");
    on_b.subscribe("lan/x");
    on_a.subscribe("lan/y");
    wait_for_flow(&mut on_a, &mut on_b, "lan/x");
    let id = on_a.send("lan/x", b"found");
    let event = on_b.event(REPLY).expect("the event");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], format!("on-a@{}", a.id()));
    assert_eq!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap(),
        b"found"
    );
    assert!(on_b.drain(Duration::from_millis(200)).is_empty());
    wait_for_flow(&mut on_b, &mut on_a, "lan/y");

    let (sa, sb) = (da.stats(), db.stats());
    for stats in [&sa, &sb] {
        assert_eq!(stats.configured, 1);
        assert!(stats.lan_announcements_sent >= 1, "{stats:?}");
        assert_eq!(stats.lan_announcements_ignored, 0, "{stats:?}");
    }
    // B announced itself at its start, which A heard and answered with a
    // handshake.
    assert!(sa.lan_announcements_received >= 1, "{sa:?}");
    assert!(
        sa.lan_connects_triggered + sb.lan_connects_triggered >= 1,
        "{sa:?} {sb:?}"
    );
}

#[test]
fn three_daemons_named_by_key_alone_find_each_other_and_forward_one_hop() {
    let Some(group) = lan_group() else {
        return;
    };
    let nodes = [Node::new("l3a"), Node::new("l3b"), Node::new("l3c")];
    let daemons: Vec<Daemon> = nodes
        .iter()
        .map(|node| {
            let others: Vec<&Node> = nodes.iter().filter(|n| n.tag != node.tag).collect();
            Daemon::start_lan(node, &others, &[], group)
        })
        .collect();
    for daemon in &daemons {
        daemon.wait_up(2);
    }
    let mut sender = daemons[0].client("sender");
    let mut on_b = daemons[1].client("on-b");
    let mut on_c = daemons[2].client("on-c");
    on_b.subscribe("tri/lan");
    on_c.subscribe("tri/lan");
    wait_for_flow(&mut sender, &mut on_b, "tri/lan");
    wait_for_flow(&mut sender, &mut on_c, "tri/lan");
    on_b.drain(Duration::from_millis(200));
    on_c.drain(Duration::from_millis(200));

    let id = sender.send("tri/lan", b"once");
    for (client, daemon) in [(&mut on_b, &daemons[1]), (&mut on_c, &daemons[2])] {
        let event = client.event(REPLY).expect("the event");
        assert_eq!(event["envelope_id"], id.as_str());
        assert_eq!(event["origin"], format!("sender@{}", nodes[0].id()));
        assert!(client.drain(Duration::from_millis(300)).is_empty());
        assert_eq!(daemon.stats().forwards_sent, 0, "one hop");
    }
    // And back, from the last to start to the first.
    let mut on_a = daemons[0].client("on-a");
    on_a.subscribe("tri/back");
    let mut from_c = daemons[2].client("from-c");
    wait_for_flow(&mut from_c, &mut on_a, "tri/back");
    for daemon in &daemons {
        assert_eq!(daemon.stats().lan_announcements_ignored, 0);
    }
}

/// A key no one lists is ignored; B's key, which A lists by key alone,
/// announced at a port where B is not, costs one handshake there in five
/// seconds however often it repeats, and none while A's session to B
/// stands; and B, once it runs, links all the same.
#[test]
fn a_forged_announcement_costs_at_most_one_failed_handshake_every_five_seconds() {
    let Some(group) = lan_group() else {
        return;
    };
    let (a, b, stranger) = (Node::new("lxa"), Node::new("lxb"), Node::new("lxs"));
    let da = Daemon::start_lan(&a, &[&b], &[], group);
    let mut forger = Forger::new(group);

    forger.announce(stranger.key.public_key(), stranger.addr.port());
    wait_until("the stranger's announcement to be ignored", || {
        da.stats().lan_announcements_ignored == 1
    });
    assert_eq!(da.stats().lan_connects_triggered, 0);

    let trap = Trap::new();
    let received = da.stats().lan_announcements_received;
    let forged = Instant::now();
    forger.keep_announcing(
        b.key.public_key(),
        trap.port(),
        Duration::from_millis(2_500),
    );
    let stats = da.stats();
    assert!(
        stats.lan_announcements_received >= received + 20,
        "{stats:?}"
    );
    assert_eq!(stats.lan_connects_triggered, 1, "{stats:?}");
    assert_eq!(trap.initiations(), 1, "one handshake at the forged port");
    assert_eq!(stats.up, 0);
    assert_eq!(stats.lan_announcements_ignored, 1);

    // B starts, and hears A's next announcement, or A hears B's once the
    // forgery's five seconds are up: either makes the session, at B's own
    // address.
    let db = Daemon::start_lan(&b, &[&a], &[], group);
    da.wait_up(1);
    db.wait_up(1);
    let mut on_a = da.client("on-a");
    on_a.subscribe("real/x");
    let mut on_b = db.client("on-b");
    wait_for_flow(&mut on_b, &mut on_a, "real/x");

    // Five seconds after the forgery began, while the session stands, the
    // forgery asks for nothing.
    std::thread::sleep(
        (forged + ANNOUNCE_INTERVAL + Duration::from_millis(200))
            .saturating_duration_since(Instant::now()),
    );
    let before = da.stats();
    forger.keep_announcing(b.key.public_key(), trap.port(), Duration::from_secs(1));
    let after = da.stats();
    assert!(after.lan_announcements_received >= before.lan_announcements_received + 10);
    assert_eq!(after.lan_connects_triggered, before.lan_connects_triggered);
    assert_eq!(trap.initiations(), 0);
    assert_eq!(after.up, 1);
    let id = on_b.send("real/x", b"still linked");
    assert_eq!(
        on_a.event(REPLY).expect("the event")["envelope_id"],
        id.as_str()
    );
}

/// A peer named with its address keeps it: its key announced at another
/// port asks for a handshake at the configured address, never at the
/// announced one.
#[test]
fn an_announcement_does_not_move_a_peer_named_with_its_address() {
    let Some(group) = lan_group() else {
        return;
    };
    let (a, b) = (Node::new("lya"), Node::new("lyb"));
    let da = Daemon::start_lan(&a, &[], &[&b], group);
    let trap = Trap::new();
    let mut forger = Forger::new(group);
    forger.keep_announcing(b.key.public_key(), trap.port(), Duration::from_secs(1));
    assert_eq!(trap.initiations(), 0, "nothing went to the announced port");
    let stats = da.stats();
    assert_eq!(stats.lan_connects_triggered, 1, "{stats:?}");
    assert_eq!(stats.lan_announcements_ignored, 0);

    let db = Daemon::start_lan(&b, &[], &[&a], group);
    da.wait_up(1);
    db.wait_up(1);
    let mut on_b = db.client("on-b");
    on_b.subscribe("kept/x");
    let mut on_a = da.client("on-a");
    wait_for_flow(&mut on_a, &mut on_b, "kept/x");
    forger.keep_announcing(b.key.public_key(), trap.port(), Duration::from_secs(1));
    assert_eq!(trap.initiations(), 0);
    assert_eq!(da.stats().up, 1);
    let id = on_a.send("kept/x", b"at its address");
    assert_eq!(
        on_b.event(REPLY).expect("the event")["envelope_id"],
        id.as_str()
    );
}

#[test]
fn daemons_named_by_key_alone_link_by_announcement_from_their_flags() {
    let Some(group) = lan_group() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Node::new("lqa"), Node::new("lqb"));
    let (key_a, key_b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    a.key.save(&key_a).unwrap();
    b.key.save(&key_b).unwrap();
    let flags = |peer: &Node| {
        [
            "--link-peer-key".to_string(),
            peer.key.public_key().to_string(),
            "--link-announce".to_string(),
            group.to_string(),
        ]
    };
    let mut pa = Process::start_with("lqa", &a, &key_a, &flags(&b));
    let mut pb = Process::start_with("lqb", &b, &key_b, &flags(&a));
    let (ma, mb) = (pa.metrics(), pb.metrics());
    for (metrics, process, peer) in [(ma, &pa, &b), (mb, &pb, &a)] {
        wait_until("the link to come up", || {
            sample(metrics, "pms_daemon_links_up") == 1
        });
        let log = process.log();
        let line = log
            .lines()
            .find(|l| l.contains("links to other daemons configured"))
            .unwrap_or_else(|| panic!("no startup line:\n{log}"));
        assert!(
            line.contains(&format!("{} by its key", peer.id())),
            "{line}"
        );
        assert!(line.contains(&group.to_string()), "{line}");
        assert!(sample(metrics, "pms_daemon_link_lan_announcements_sent_total") >= 1);
        assert_eq!(
            sample(metrics, "pms_daemon_link_lan_announcements_ignored_total"),
            0
        );
    }
    let connects = sample(ma, "pms_daemon_link_lan_connects_total")
        + sample(mb, "pms_daemon_link_lan_connects_total");
    assert!(connects >= 1);
    // The two processes start together, so B's first announcement can go
    // out before A has joined the group, and the link come up on A's alone;
    // A then hears B's next one, an announcement interval later.
    wait_until("A to hear B's announcement", || {
        sample(ma, "pms_daemon_link_lan_announcements_received_total") >= 1
    });
}
