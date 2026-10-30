// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Daemons that link through a relay, over sealed UDP on loopback (ADR-0021,
//! item 9). On a line A–R–C, A and C not linked and R a relay both trust, a
//! send on A reaches a subscriber on C once, with A's qualified origin, and
//! back; nothing crosses while C wants nothing, and a subscription on C
//! starts and stops the flow through R within pacer intervals. In a triangle
//! with A–C linked too, each send reaches C once, its copy through R
//! dropped, and a send to a node of C's takes the direct link. Behind C, a
//! second relay does not carry what R relayed a third hop. A daemon that
//! does not trust R refuses what R relays, and counts it, and takes R's own
//! clients' sends. A send to a node behind R reaches it, and once C goes
//! down A's watchers are told it is detached and a send to it is refused.
//! A silent node of C's turns warning, isolated and detached for a watcher
//! on A, through R. And the daemon relays and trusts a relay from its flags,
//! and exports its relay counts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;

use common::{hub_name, small_store, socket_path, Node, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::link::LinkConfig;
use mesh_hub::protocol::base64;
use mesh_hub::{ConnectionPolicy, LinkStats};
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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

/// The pacer's shortest time between two summaries, by default. A change
/// on C reaches A through R in two of them: C's summary to R, then R's to A.
const PACER_INTERVAL: Duration = Duration::from_millis(250);

/// How long a quiet stretch must last for a client to be taken as having
/// received everything it will.
const QUIET: Duration = Duration::from_millis(300);

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl Node {
    /// `name`, a client of this daemon, as a qualified origin writes it.
    fn client(&self, name: &str) -> String {
        format!("{name}@{}", self.id())
    }

    /// Its links to `peers`, trusting `trusted` as relays, with the tests'
    /// heartbeat and silence.
    fn links(&self, peers: &[&Node], trusted: &[&Node]) -> LinkConfig {
        let links = LinkConfig::new(self.key.clone(), self.addr)
            .with_heartbeat(HEARTBEAT)
            .with_silence(SILENCE);
        let links = peers
            .iter()
            .fold(links, |links, peer| links.with_peer(peer.peer()));
        trusted.iter().fold(links, |links, relay| {
            links.with_trusted_relay(relay.key.public_key())
        })
    }
}

/// A running daemon and the socket its clients attach on.
struct Daemon {
    mesh: EmbeddedMesh,
    socket: PathBuf,
}

impl Daemon {
    /// `node`, linked by `links`.
    fn start(node: &Node, links: LinkConfig) -> Self {
        Self::start_with(node, links, ConnectionPolicy::default())
    }

    /// `node`, linked by `links`, serving its clients under `policy`.
    fn start_with(node: &Node, links: LinkConfig, policy: ConnectionPolicy) -> Self {
        let socket = socket_path(&node.tag);
        let mesh = EmbeddedMesh::start_with_links(
            &hub_name(&node.tag),
            &[Bind::Uds(socket.clone())],
            policy,
            small_store(),
            links,
        )
        .expect("a linked daemon");
        assert_eq!(mesh.daemon_id(), Some(node.daemon_id()));
        Self { mesh, socket }
    }

    fn stats(&self) -> LinkStats {
        self.mesh.link_stats().expect("links")
    }

    /// A client attached here as `name`.
    fn client(&self, name: &str) -> Client {
        let mut client = Client::new(Upp::connect(&self.socket));
        client.upp.send(&format!(
            r#"{{"op":"attach","id":"attach","name":"{name}","protocol_version":"v0"}}"#
        ));
        let ack = client.reply("attach");
        assert_eq!(ack["op"], "ack", "attach as {name}: {ack}");
        client
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

    /// The next event within `timeout`, or `None`, passing over other
    /// frames.
    fn event(&mut self, timeout: Duration) -> Option<serde_json::Value> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = self.next(left)?;
            if frame["op"] == "event" {
                return Some(frame);
            }
        }
    }

    /// Every event that arrives within `quiet` of the one before.
    fn drain(&mut self, quiet: Duration) -> Vec<serde_json::Value> {
        std::iter::from_fn(|| self.event(quiet)).collect()
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

/// A line A–R–C: R relays, and A and C trust it.
fn line(tags: [&str; 3]) -> ([Node; 3], [Daemon; 3]) {
    let nodes = tags.map(Node::new);
    let [a, r, c] = &nodes;
    let daemons = [
        Daemon::start(a, a.links(&[r], &[r])),
        Daemon::start(r, r.links(&[a, c], &[]).with_relay()),
        Daemon::start(c, c.links(&[r], &[r])),
    ];
    for (daemon, up) in daemons.iter().zip([1, 2, 1]) {
        daemon.wait_up(up);
    }
    (nodes, daemons)
}

#[test]
fn a_send_crosses_a_relay_once_with_its_origin_and_only_while_it_is_wanted() {
    let ([a, _, c], [da, dr, dc]) = line(["rla", "rlr", "rlc"]);
    let mut sender = da.client("sender");
    let mut on_c = dc.client("on-c");

    // C wants nothing: once its summary has reached R, and R's has reached
    // A, a send on A goes nowhere.
    wait_until("the summaries through R", || {
        dr.stats().summaries_received >= 2 && da.stats().summaries_received >= 1
    });
    std::thread::sleep(2 * PACER_INTERVAL);
    for i in 0..10u8 {
        sender.send("line/x", &[i]);
    }
    std::thread::sleep(QUIET);
    assert_eq!(da.stats().forwards_sent, 0, "A forwards nothing to R");
    let relay = dr.stats();
    assert_eq!(
        (relay.forwards_received, relay.relayed_sent),
        (0, 0),
        "{relay:?}"
    );
    assert_eq!(dc.stats().forwards_received, 0);
    assert!(on_c.drain(Duration::from_millis(50)).is_empty());

    // A subscription on C starts the flow through R within two pacer
    // intervals, with slack for the round trips on a loaded machine.
    let subscribed = Instant::now();
    let sub = on_c.subscribe("line/x");
    let took = wait_for_flow(&mut sender, &mut on_c, "line/x");
    assert!(
        took < 2 * PACER_INTERVAL + Duration::from_secs(1),
        "the flow started {took:?} after the subscribe ({:?} in all)",
        subscribed.elapsed()
    );
    let before = (dr.stats(), dc.stats());
    let id = sender.send("line/x", b"through R");
    let event = on_c.event(REPLY).expect("the event");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], a.client("sender"), "A's qualified origin");
    assert_eq!(event["channel"], "line/x");
    assert_eq!(
        base64::decode(event["payload"].as_str().unwrap()).unwrap(),
        b"through R"
    );
    assert!(on_c.drain(QUIET).is_empty(), "once");
    wait_until("R's relayed forward to be counted", || {
        dr.stats().relayed_sent == before.0.relayed_sent + 1
    });
    let (relay, far) = (dr.stats(), dc.stats());
    assert_eq!(far.relayed_received, before.1.relayed_received + 1);
    assert_eq!(far.duplicates_dropped, 0);
    assert_eq!(far.relayed_refused, 0);
    assert!(relay.relay_interest_bytes > 0, "{relay:?}");
    assert_eq!(da.stats().relay_interest_bytes, 0, "A does not relay");
    assert_eq!(far.forwards_sent, 0, "C passes nothing on");

    // And back, from C to A.
    let mut on_a = da.client("on-a");
    on_a.subscribe("back/y");
    let mut from_c = dc.client("from-c");
    wait_for_flow(&mut from_c, &mut on_a, "back/y");
    let id = from_c.send("back/y", b"from C");
    let event = on_a.event(REPLY).expect("the event back");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], c.client("from-c"));
    assert!(on_a.drain(QUIET).is_empty());

    // Unsubscribed, the flow through R stops once the summaries have
    // crossed again.
    on_c.unsubscribe(&sub);
    let unsubscribed = Instant::now();
    wait_until("the flow to stop", || {
        let before = da.stats().forwards_sent;
        sender.send("line/x", b"after");
        std::thread::sleep(Duration::from_millis(100));
        da.stats().forwards_sent == before
    });
    assert!(
        unsubscribed.elapsed() < 2 * PACER_INTERVAL + Duration::from_secs(2),
        "{:?}",
        unsubscribed.elapsed()
    );
    let before = (da.stats().forwards_sent, dr.stats().relayed_sent);
    for _ in 0..10 {
        sender.send("line/x", b"after");
    }
    std::thread::sleep(QUIET);
    assert_eq!((da.stats().forwards_sent, dr.stats().relayed_sent), before);
    assert!(on_c.drain(Duration::from_millis(100)).is_empty());
}

#[test]
fn in_a_triangle_with_a_relay_a_send_arrives_once_and_a_destination_goes_direct() {
    let nodes = ["rta", "rtr", "rtc"].map(Node::new);
    let [a, r, c] = &nodes;
    let da = Daemon::start(a, a.links(&[r, c], &[r]));
    let dr = Daemon::start(r, r.links(&[a, c], &[]).with_relay());
    let dc = Daemon::start(c, c.links(&[r, a], &[r]));
    for daemon in [&da, &dr, &dc] {
        daemon.wait_up(2);
    }
    let mut sender = da.client("sender");
    let mut on_c = dc.client("on-c");
    on_c.subscribe("tri/x");
    let mut target = dc.client("target");
    target.subscribe("dm/x");
    // Both paths carry the flow once R relays a probe too.
    wait_until("the flow on both paths", || {
        sender.send("tri/x", b"probe");
        std::thread::sleep(Duration::from_millis(20));
        dr.stats().relayed_sent >= 1 && on_c.event(Duration::from_millis(20)).is_some()
    });
    std::thread::sleep(QUIET);
    on_c.drain(QUIET);
    wait_until("C's copies to settle", || {
        let before = dc.stats().duplicates_dropped;
        std::thread::sleep(Duration::from_millis(100));
        dc.stats().duplicates_dropped == before
    });
    let before = (dc.stats(), dr.stats(), da.stats());

    let ids: BTreeSet<String> = (0..5u8).map(|i| sender.send("tri/x", &[i])).collect();
    let events = on_c.drain(QUIET);
    let got: BTreeSet<String> = events
        .iter()
        .map(|e| e["envelope_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(events.len(), 5, "each send once: {events:?}");
    assert_eq!(got, ids);
    for event in &events {
        assert_eq!(event["origin"], a.client("sender"));
    }
    // Each arrived twice, directly and through R, and its copy was dropped.
    wait_until("the copies through R to be dropped", || {
        dc.stats().duplicates_dropped == before.0.duplicates_dropped + 5
    });
    assert_eq!(dr.stats().relayed_sent, before.1.relayed_sent + 5);
    assert_eq!(
        da.stats().forwards_received,
        before.2.forwards_received,
        "nothing back to its origin"
    );

    // A send to a node of C's takes the direct link, though R reaches it
    // too: A holds C's two nodes directly and through R.
    wait_until("A to hold C's nodes both ways", || {
        da.stats().peer_nodes == 4
    });
    let before = (dr.stats(), dc.stats());
    let ack = sender.send_to(&c.client("target"), "dm/x", b"direct");
    assert_eq!(ack["op"], "ack", "{ack}");
    assert_eq!(ack["delivered"], true);
    let event = target.event(REPLY).expect("the addressed event");
    assert_eq!(event["origin"], a.client("sender"));
    assert!(target.drain(QUIET).is_empty());
    let (relay, far) = (dr.stats(), dc.stats());
    assert_eq!(far.addressed_received, before.1.addressed_received + 1);
    assert_eq!(far.relayed_received, before.1.relayed_received);
    assert_eq!(
        (relay.forwards_received, relay.relayed_sent),
        (before.0.forwards_received, before.0.relayed_sent),
        "R had no part in it"
    );
}

/// A–R–C–R2–D, and R–R2: R and R2 relay. What A sends reaches R's and C's
/// subscribers, and R relays it to R2 too, whose summary carries D's
/// interest; R2 takes it, but it has no hop left, so D, a third hop from A,
/// gets nothing. What C sends, R2 relays to D: one relay, as A's crossed R.
#[test]
fn a_second_relay_does_not_carry_a_relayed_send_a_third_hop() {
    let nodes = ["rha", "rhr", "rhc", "rhs", "rhd"].map(Node::new);
    let [a, r, c, r2, d] = &nodes;
    let da = Daemon::start(a, a.links(&[r], &[r]));
    let dr = Daemon::start(r, r.links(&[a, c, r2], &[]).with_relay());
    let dc = Daemon::start(c, c.links(&[r, r2], &[r, r2]));
    let dr2 = Daemon::start(r2, r2.links(&[c, d, r], &[r]).with_relay());
    let dd = Daemon::start(d, d.links(&[r2], &[r2]));
    for (daemon, up) in [(&da, 1), (&dr, 3), (&dc, 2), (&dr2, 3), (&dd, 1)] {
        daemon.wait_up(up);
    }
    let mut sender = da.client("sender");
    let mut on_r = dr.client("on-r");
    let mut on_c = dc.client("on-c");
    let mut on_d = dd.client("on-d");
    for client in [&mut on_r, &mut on_c, &mut on_d] {
        client.subscribe("hop/x");
    }
    // C's sends reach D through R2: the second relay carries one hop.
    let mut from_c = dc.client("from-c");
    wait_for_flow(&mut from_c, &mut on_d, "hop/x");
    let id = from_c.send("hop/x", b"from C");
    let event = on_d.event(REPLY).expect("C's send on D");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], c.client("from-c"));
    // A's reach R, C and R2.
    wait_until("A's sends to reach C, and R2 through R", || {
        sender.send("hop/x", b"probe");
        std::thread::sleep(Duration::from_millis(20));
        dr2.stats().relayed_received >= 1 && on_c.event(Duration::from_millis(20)).is_some()
    });
    std::thread::sleep(QUIET);
    for client in [&mut on_r, &mut on_c, &mut on_d] {
        client.drain(QUIET);
    }
    let before: Vec<LinkStats> = [&da, &dr, &dc, &dr2, &dd].map(Daemon::stats).into();

    let ids: BTreeSet<String> = (0..5u8).map(|i| sender.send("hop/x", &[i])).collect();
    for (client, name) in [(&mut on_r, "R"), (&mut on_c, "C")] {
        let events = client.drain(QUIET);
        let got: BTreeSet<String> = events
            .iter()
            .map(|e| e["envelope_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(events.len(), 5, "on {name}, each once: {events:?}");
        assert_eq!(got, ids, "on {name}");
        assert!(events.iter().all(|e| e["origin"] == a.client("sender")));
    }
    assert!(on_d.drain(QUIET).is_empty(), "no third hop to D");
    wait_until("R2 to take R's relayed forwards", || {
        dr2.stats().relayed_received == before[3].relayed_received + 5
    });
    let after: Vec<LinkStats> = [&da, &dr, &dc, &dr2, &dd].map(Daemon::stats).into();
    assert_eq!(
        after[1].relayed_sent,
        before[1].relayed_sent + 10,
        "R relays each once, to C and to R2"
    );
    assert_eq!(
        after[2].forwards_sent, before[2].forwards_sent,
        "C does not relay"
    );
    assert_eq!(
        after[3].relayed_sent, before[3].relayed_sent,
        "R2 passes nothing of A's on"
    );
    assert_eq!(after[4].forwards_received, before[4].forwards_received);
    assert_eq!(after[3].relayed_refused, 0);
}

#[test]
fn a_daemon_that_does_not_trust_a_relay_refuses_what_it_relays_and_takes_its_own_clients() {
    let nodes = ["rua", "rur", "ruc"].map(Node::new);
    let [a, r, c] = &nodes;
    let da = Daemon::start(a, a.links(&[r], &[r]));
    let dr = Daemon::start(r, r.links(&[a, c], &[]).with_relay());
    // C links to R without trusting it as a relay.
    let dc = Daemon::start(c, c.links(&[r], &[]));
    for (daemon, up) in [(&da, 1), (&dr, 2), (&dc, 1)] {
        daemon.wait_up(up);
    }
    let mut sender = da.client("sender");
    let mut on_c = dc.client("on-c");
    on_c.subscribe("trust/x");
    // R's summary carries C's interest to A, so A's sends reach R, which
    // relays them: C refuses each, and counts it.
    wait_until("C to refuse what R relays", || {
        sender.send("trust/x", b"relayed");
        std::thread::sleep(Duration::from_millis(20));
        dc.stats().relayed_refused >= 3
    });
    let stats = dc.stats();
    assert_eq!(stats.relayed_received, 0);
    assert!(
        stats.datagrams_refused >= stats.relayed_refused,
        "{stats:?}"
    );
    assert!(dr.stats().relayed_sent >= stats.relayed_refused);
    assert!(on_c.drain(QUIET).is_empty(), "nothing of A's reaches C");

    // R's own clients are R's to speak for: their sends are taken.
    let mut own = dr.client("own");
    wait_for_flow(&mut own, &mut on_c, "trust/x");
    let id = own.send("trust/x", b"R's own");
    let event = on_c.event(REPLY).expect("R's own client's send");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], r.client("own"));
    let refused = dc.stats().relayed_refused;
    own.send("trust/x", b"again");
    assert!(on_c.event(REPLY).is_some());
    assert_eq!(
        dc.stats().relayed_refused,
        refused,
        "R's own are no relayed traffic"
    );
}

#[test]
fn a_send_to_a_node_behind_a_relay_reaches_it_and_its_daemon_gone_detaches_it() {
    let ([a, _, c], [da, dr, dc]) = line(["rda", "rdr", "rdc"]);
    let mut watcher = da.client("watcher");
    watcher.subscribe_to(r#"{"channel":"none","health":true}"#);
    let mut sender = da.client("sender");
    let mut target = dc.client("target");
    target.subscribe("dm/x");
    let target_id = c.client("target");
    // A learns of the target through R's announcement, as reached through
    // R; R names no node of its own.
    wait_until("A to hold C's node through R", || {
        da.stats().peer_nodes == 1
    });

    let ack = sender.send_to(&target_id, "dm/x", b"for target");
    assert_eq!(ack["op"], "ack", "{ack}");
    assert_eq!(ack["delivered"], true, "forwarded: {ack}");
    let event = target.event(REPLY).expect("the addressed event");
    assert_eq!(event["envelope_id"], ack["envelope_id"]);
    assert_eq!(event["origin"], a.client("sender"));
    assert_eq!(event["channel"], "dm/x");
    assert!(target.drain(QUIET).is_empty());
    let (relay, far) = (dr.stats(), dc.stats());
    assert_eq!((relay.relayed_sent, relay.forwards_received), (1, 1));
    assert_eq!((far.addressed_received, far.relayed_received), (1, 1));
    assert_eq!(da.mesh.destination_sends().forwarded, 1);

    // C goes down, its node still attached: R takes the link down when C
    // falls silent and stops announcing the node, which A's watcher is told
    // is detached; a send to it is then refused.
    dc.mesh.shutdown();
    let gone = Instant::now();
    watcher.wait_for_state(&target_id, "detached");
    assert!(
        gone.elapsed() < SILENCE + 2 * PACER_INTERVAL + Duration::from_secs(2),
        "{:?}",
        gone.elapsed()
    );
    let error = sender.send_to(&target_id, "dm/x", b"lost");
    assert_eq!(error["op"], "error", "{error}");
    assert_eq!(error["code"], "unknown_destination");
    assert_eq!(da.stats().peer_nodes, 0);
    assert_eq!(dr.stats().up, 1);
    drop(target);
}

#[test]
fn a_silent_node_behind_a_relay_turns_warning_isolated_and_detached_for_a_watcher() {
    let nodes = ["rwa", "rwr", "rwc"].map(Node::new);
    let [a, r, c] = &nodes;
    let da = Daemon::start(a, a.links(&[r], &[r]));
    let dr = Daemon::start(r, r.links(&[a, c], &[]).with_relay());
    // C's clients are closed after two seconds of silence: warning after
    // about one, isolated after about 1.8.
    let quick = ConnectionPolicy::default().with_idle_timeout(Duration::from_secs(2));
    let dc = Daemon::start_with(c, c.links(&[r], &[r]), quick);
    for (daemon, up) in [(&da, 1), (&dr, 2), (&dc, 1)] {
        daemon.wait_up(up);
    }
    let mut watcher = da.client("watcher");
    watcher.subscribe_to(r#"{"channel":"none","health":true}"#);
    // Once a degraded node of C's reaches the watcher, the summaries that
    // watch health have crossed R both ways.
    let mut busy = dc.client("busy");
    busy.upp.send(r#"{"op":"health","state":"degraded"}"#);
    watcher.wait_for_state(&c.client("busy"), "degraded");

    let _quiet = dc.client("quiet");
    let node = c.client("quiet");
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
    assert!(dr.stats().health_received >= 2, "R took C's reports");
    assert!(dr.stats().health_sent >= 2, "and passed them on");
    assert!(da.stats().health_received >= 3, "{:?}", da.stats());
    assert_eq!(da.stats().relayed_refused, 0);
    drop(busy);
}

/// A `mesh-hub` process with links and metrics, and its log.
struct Process {
    child: Child,
    log: PathBuf,
    socket: PathBuf,
}

impl Process {
    /// `node`'s daemon, its node key in `key_file`, and its link flags
    /// `links`.
    fn start(node: &Node, key_file: &std::path::Path, links: &[String]) -> Self {
        let socket = socket_path(&node.tag);
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name(&node.tag), "--uds-path"])
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
fn the_daemon_relays_and_trusts_a_relay_from_its_flags_and_exports_its_relay_counts() {
    let dir = tempfile::tempdir().unwrap();
    let nodes = ["rpa", "rpr", "rpc"].map(Node::new);
    let [a, r, c] = &nodes;
    let keys = nodes.each_ref().map(|node| {
        let file = dir.path().join(format!("{}.key", node.tag));
        node.key.save(&file).unwrap();
        file
    });
    let peer = |node: &Node| ["--link-peer".to_string(), node.peer().to_string()];
    let trust = |node: &Node| {
        [
            "--link-trust-relay".to_string(),
            node.key.public_key().to_string(),
        ]
    };
    let mut pa = Process::start(a, &keys[0], &[peer(r), trust(r)].concat());
    let relay_flags = [&peer(a)[..], &peer(c)[..], &["--link-relay".to_string()]].concat();
    let mut pr = Process::start(r, &keys[1], &relay_flags);
    let mut pc = Process::start(c, &keys[2], &[peer(r), trust(r)].concat());
    let (ma, mr, mc) = (pa.metrics(), pr.metrics(), pc.metrics());
    for (metrics, up) in [(ma, 1), (mr, 2), (mc, 1)] {
        wait_until("the links to come up", || {
            sample(metrics, "pms_daemon_links_up") == up
        });
    }
    let line = |process: &Process| {
        let log = process.log();
        log.lines()
            .find(|l| l.contains("links to other daemons configured"))
            .unwrap_or_else(|| panic!("no startup line:\n{log}"))
            .to_string()
    };
    assert!(line(&pr).contains("relay=true"), "{}", line(&pr));
    assert!(line(&pa).contains(&r.id()), "{}", line(&pa));

    let mut watcher = Client::new(Upp::connect(&pc.socket));
    watcher.upp.attach("watcher");
    watcher.subscribe("cli/x");
    let mut sender = Client::new(Upp::connect(&pa.socket));
    sender.upp.attach("sender");
    wait_for_flow(&mut sender, &mut watcher, "cli/x");
    let id = sender.send("cli/x", b"through the relay");
    let event = watcher.event(REPLY).expect("the event");
    assert_eq!(event["envelope_id"], id.as_str());
    assert_eq!(event["origin"], a.client("sender"));
    assert!(sample(mr, "pms_daemon_link_relayed_sent_total") >= 1);
    assert!(sample(mc, "pms_daemon_link_relayed_received_total") >= 1);
    assert!(sample(mr, "pms_daemon_link_relay_interest_bytes") > 0);
    assert_eq!(sample(ma, "pms_daemon_link_relay_interest_bytes"), 0);
    assert_eq!(sample(mc, "pms_daemon_link_relayed_refused_total"), 0);
    assert_eq!(sample(ma, "pms_daemon_link_relayed_sent_total"), 0);
}
