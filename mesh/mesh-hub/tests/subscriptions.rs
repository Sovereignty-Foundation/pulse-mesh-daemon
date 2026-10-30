// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A connection holds at most the policy's `max_subscriptions` (64 by
//! default): the subscribe past the limit is refused with `limit_exceeded`
//! and a message naming the limit, an unsubscribe frees a place, and every
//! connection has an allowance of its own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, small_store, socket_path, start_small, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::ConnectionPolicy;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

/// Subscribe to everything under request id `id` and return the reply.
fn subscribe(client: &mut Upp, id: &str) -> serde_json::Value {
    client.send(&format!(
        r#"{{"op":"subscribe","id":"{id}","filter":{{}}}}"#
    ));
    client.recv_json(TIMEOUT)
}

/// Open `n` subscriptions, each acknowledged, and return their ids.
fn fill(client: &mut Upp, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let ack = subscribe(client, &format!("s{i}"));
            assert_eq!(ack["op"], "ack", "subscribe {} of {n}: {ack}", i + 1);
            ack["subscription_id"].as_str().unwrap().to_string()
        })
        .collect()
}

/// The reply is a `limit_exceeded` error for request `id` that names `limit`.
fn assert_refused(reply: &serde_json::Value, id: &str, limit: usize) {
    assert_eq!(reply["op"], "error", "{reply}");
    assert_eq!(reply["id"], id, "{reply}");
    assert_eq!(reply["code"], "limit_exceeded", "{reply}");
    let message = reply["message"].as_str().unwrap();
    assert!(
        message.contains(&limit.to_string()),
        "the message names the limit: {message}"
    );
}

#[test]
fn the_subscribe_past_the_limit_is_refused_until_an_unsubscribe_frees_a_place() {
    let limit = ConnectionPolicy::default().max_subscriptions;
    assert_eq!(limit, 64, "the default limit");
    let path = socket_path("sub-limit");
    let mesh = start_small(&hub_name("sub-limit"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut client = Upp::connect(&path);
    client.attach("subscriber");

    let held = fill(&mut client, limit);
    assert_refused(&subscribe(&mut client, "over"), "over", limit);

    client.send(&format!(
        r#"{{"op":"unsubscribe","id":"free","subscription_id":"{}"}}"#,
        held[0]
    ));
    assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");
    let again = subscribe(&mut client, "again");
    assert_eq!(again["op"], "ack", "the freed place is taken: {again}");
    assert_refused(&subscribe(&mut client, "over-again"), "over-again", limit);
    mesh.shutdown();
}

#[test]
fn each_connection_has_its_own_allowance() {
    let limit = ConnectionPolicy::default().max_subscriptions;
    let path = socket_path("sub-each");
    let mesh = start_small(&hub_name("sub-each"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut first = Upp::connect(&path);
    first.attach("first");
    fill(&mut first, limit);
    assert_refused(&subscribe(&mut first, "over"), "over", limit);

    // A full connection leaves another's allowance whole.
    let mut second = Upp::connect(&path);
    second.attach("second");
    fill(&mut second, limit);
    assert_refused(&subscribe(&mut second, "over"), "over", limit);
    mesh.shutdown();
}

#[test]
fn a_limit_of_zero_refuses_every_subscribe() {
    let path = socket_path("sub-zero");
    let policy = ConnectionPolicy::default().with_max_subscriptions(0);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("sub-zero"),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");
    let mut client = Upp::connect(&path);
    client.attach("subscriber");
    assert_refused(&subscribe(&mut client, "none"), "none", 0);
    mesh.shutdown();
}
