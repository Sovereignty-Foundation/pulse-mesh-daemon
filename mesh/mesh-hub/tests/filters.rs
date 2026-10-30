// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An `origin` filter matches what the protocol says it matches: the
//! producer's node id in the canonical `name@suffix` form its attach ack
//! returned, which its events carry as `origin`. Since every event carries
//! the name, a name longer than the protocol allows is refused at attach,
//! and one at the cap still fits an `origin` filter.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, start_small, Upp};
use mesh_hub::embed::Bind;
use mesh_hub::protocol::{MAX_NAME_LEN, MAX_PATTERN_LEN};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Attach as `name` and return the node id the ack gives.
fn attach(client: &mut Upp, name: &str) -> String {
    client.send(&format!(
        r#"{{"op":"attach","id":"a","name":"{name}","protocol_version":"v0"}}"#
    ));
    let ack = client.recv_json(TIMEOUT);
    assert_eq!(ack["op"], "ack", "{ack}");
    ack["node_id"].as_str().unwrap().to_string()
}

/// Subscribe with `filter` (JSON) and return the subscription's id.
fn subscribe(client: &mut Upp, id: &str, filter: &str) -> String {
    client.send(&format!(
        r#"{{"op":"subscribe","id":"{id}","filter":{filter}}}"#
    ));
    let ack = client.recv_json(TIMEOUT);
    assert_eq!(ack["op"], "ack", "{ack}");
    ack["subscription_id"].as_str().unwrap().to_string()
}

/// Send a two-byte payload on `channel`.
fn send(client: &mut Upp, channel: &str) {
    client.send(&format!(
        r#"{{"op":"send","id":"s","channel":"{channel}","payload":"aGk="}}"#
    ));
    assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");
}

/// Every event `client` receives until it goes quiet, as (subscription,
/// origin).
fn events(client: &mut Upp) -> Vec<(String, String)> {
    let mut got = Vec::new();
    while let Some(frame) = client.frame(Duration::from_millis(500)) {
        let event: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(event["op"], "event", "{event}");
        got.push((
            event["subscription_id"].as_str().unwrap().to_string(),
            event["origin"].as_str().unwrap().to_string(),
        ));
    }
    got
}

#[test]
fn an_origin_filter_matches_the_node_id_the_producers_attach_ack_gave() {
    let path = socket_path("flt-origin");
    let mesh = start_small(&hub_name("flt-orig"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut alice = Upp::connect(&path);
    let alice_id = attach(&mut alice, "alice");
    let mut bob = Upp::connect(&path);
    let bob_id = attach(&mut bob, "bob");
    let suffix = alice_id.strip_prefix("alice@").expect("name@suffix");
    assert!(
        suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
        "{alice_id}"
    );

    let mut watcher = Upp::connect(&path);
    attach(&mut watcher, "watcher");
    let from_alice = subscribe(&mut watcher, "a", &format!(r#"{{"origin":"{alice_id}"}}"#));
    let from_bob = subscribe(&mut watcher, "b", &format!(r#"{{"origin":"{bob_id}"}}"#));
    // The suffix alone, which events carried before they named their
    // producer, is not the node id and matches nothing.
    subscribe(&mut watcher, "s", &format!(r#"{{"origin":"@{suffix}"}}"#));

    send(&mut alice, "c");
    send(&mut bob, "c");
    assert_eq!(
        events(&mut watcher),
        [(from_alice, alice_id), (from_bob, bob_id)],
        "each event on its producer's subscription, naming its producer as the ack did"
    );
    mesh.shutdown();
}

#[test]
fn a_name_longer_than_the_protocol_allows_is_refused_at_attach() {
    let path = socket_path("flt-name");
    let mesh = start_small(&hub_name("flt-name"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut client = Upp::connect(&path);
    let over = "n".repeat(MAX_NAME_LEN + 1);
    client.send(&format!(
        r#"{{"op":"attach","id":"long","name":"{over}","protocol_version":"v0"}}"#
    ));
    let reply = client.recv_json(TIMEOUT);
    assert_eq!(reply["op"], "error", "{reply}");
    assert_eq!(reply["code"], "bad_request", "{reply}");
    let message = reply["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("name of {} bytes", MAX_NAME_LEN + 1))
            && message.contains(&format!("{MAX_NAME_LEN} bytes allowed")),
        "{message}"
    );

    // The connection stays, a name at the cap attaches, and its node id
    // fits an `origin` filter.
    let at = "n".repeat(MAX_NAME_LEN);
    let node_id = attach(&mut client, &at);
    assert!(node_id.len() <= MAX_PATTERN_LEN, "{}", node_id.len());
    let own = subscribe(&mut client, "own", &format!(r#"{{"origin":"{node_id}"}}"#));
    send(&mut client, "c");
    assert_eq!(events(&mut client), [(own, node_id)]);
    mesh.shutdown();
}
