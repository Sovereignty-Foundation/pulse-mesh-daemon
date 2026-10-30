// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Matching sends against the subscriptions' filters cannot stall the daemon. A
//! channel, type name or filter string longer than the protocol's caps is
//! refused with `bad_request` at once, a 160 KB pattern and a 320 KB channel
//! included, and publishes or subscribes nothing; strings at the caps are
//! accepted; and sends that meet hundreds of the longest legal patterns are
//! matched promptly while another client sends.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, start_small, Upp};
use mesh_hub::embed::Bind;
use mesh_hub::protocol::{MAX_CHANNEL_LEN, MAX_PATTERN_LEN};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

/// The most any one reply may take here: far above what the daemon needs,
/// far below the 12.7 s one send took before the caps.
const PROMPT: Duration = Duration::from_secs(2);

/// Subscribe with the filter `filter` (JSON) and return the reply.
fn subscribe(client: &mut Upp, id: &str, filter: &str) -> serde_json::Value {
    client.send(&format!(
        r#"{{"op":"subscribe","id":"{id}","filter":{filter}}}"#
    ));
    client.recv_json(TIMEOUT)
}

/// Send a two-byte payload on `channel` and return the reply.
fn send(client: &mut Upp, id: &str, channel: &str) -> serde_json::Value {
    client.send(&format!(
        r#"{{"op":"send","id":"{id}","channel":"{channel}","payload":"aGk="}}"#
    ));
    client.recv_json(TIMEOUT)
}

/// The reply is `bad_request` naming the string, its length and the cap.
fn assert_too_long(reply: &serde_json::Value, what: &str, len: usize, max: usize) {
    assert_eq!(reply["op"], "error", "{reply}");
    assert_eq!(reply["code"], "bad_request", "{reply}");
    let message = reply["message"].as_str().unwrap();
    assert!(
        message.starts_with(&format!("{what} of {len} bytes"))
            && message.contains(&format!("the {max} bytes allowed")),
        "{message}"
    );
}

#[test]
fn the_reviews_input_and_everything_over_the_caps_is_refused_at_once() {
    let path = socket_path("match-cap");
    let mesh = start_small(&hub_name("match-cap"), &[Bind::Uds(path.clone())]).expect("daemon");
    let mut watcher = Upp::connect(&path);
    watcher.attach("watcher");
    assert_eq!(subscribe(&mut watcher, "all", "{}")["op"], "ack");
    let mut client = Upp::connect(&path);
    client.attach("client");

    // A 160 KB pattern and a 320 KB channel, which a backtracking matcher takes
    // seconds over while it holds the subscriber lock.
    let started = Instant::now();
    let pattern = format!("*{}b", "a".repeat(160_000));
    let reply = subscribe(
        &mut client,
        "long",
        &format!(r#"{{"channel":"{pattern}"}}"#),
    );
    assert_too_long(&reply, "filter channel", pattern.len(), MAX_PATTERN_LEN);
    let channel = "a".repeat(320_000);
    let reply = send(&mut client, "long", &channel);
    assert_too_long(&reply, "channel", channel.len(), MAX_CHANNEL_LEN);
    assert!(started.elapsed() < PROMPT, "{:?}", started.elapsed());

    // One byte over a cap is refused, in any field; at the cap is accepted.
    let over = "*".repeat(MAX_PATTERN_LEN + 1);
    for field in ["channel", "type_name", "origin"] {
        let reply = subscribe(&mut client, field, &format!(r#"{{"{field}":"{over}"}}"#));
        assert_too_long(
            &reply,
            &format!("filter {field}"),
            MAX_PATTERN_LEN + 1,
            MAX_PATTERN_LEN,
        );
    }
    let at = "*".repeat(MAX_PATTERN_LEN);
    let reply = subscribe(
        &mut client,
        "at",
        &format!(r#"{{"channel":"{at}","type_name":"{at}"}}"#),
    );
    assert_eq!(reply["op"], "ack", "{reply}");
    let over = "c".repeat(MAX_CHANNEL_LEN + 1);
    let reply = send(&mut client, "over", &over);
    assert_too_long(&reply, "channel", MAX_CHANNEL_LEN + 1, MAX_CHANNEL_LEN);
    client.send(&format!(
        r#"{{"op":"send","id":"named","channel":"c","type_name":"{over}","payload":"aGk="}}"#
    ));
    let reply = client.recv_json(TIMEOUT);
    assert_too_long(&reply, "type_name", MAX_CHANNEL_LEN + 1, MAX_CHANNEL_LEN);
    let at = "c".repeat(MAX_CHANNEL_LEN);
    let reply = send(&mut client, "at", &at);
    assert_eq!(reply["op"], "ack", "{reply}");

    // Only the send at the cap was published.
    let event = watcher.recv_json(TIMEOUT);
    assert_eq!(event["op"], "event", "{event}");
    assert_eq!(event["channel"], at.as_str());
    assert!(
        watcher.frame(Duration::from_millis(200)).is_none(),
        "a refused send publishes nothing"
    );
    mesh.shutdown();
}

#[test]
fn sends_meeting_hundreds_of_the_longest_patterns_are_matched_while_another_client_sends() {
    let path = socket_path("match-load");
    let mesh = start_small(&hub_name("match-ld"), &[Bind::Uds(path.clone())]).expect("daemon");

    // Four connections hold 64 subscriptions each, every pattern at the cap:
    // one that keeps the match alive to its last byte, the worst case for a
    // backtracking matcher, and two that match.
    let patterns = [
        format!("*{}b", "a".repeat(MAX_PATTERN_LEN - 2)),
        "*a".repeat(MAX_PATTERN_LEN / 2),
        "a**".repeat(MAX_PATTERN_LEN / 3),
    ];
    let mut holders = Vec::new();
    for h in 0..4 {
        let mut holder = Upp::connect(&path);
        holder.attach(&format!("holder-{h}"));
        for i in 0..64 {
            let pattern = &patterns[(h + i) % patterns.len()];
            assert!(pattern.len() <= MAX_PATTERN_LEN);
            let reply = subscribe(
                &mut holder,
                &format!("s{i}"),
                &format!(r#"{{"channel":"{pattern}"}}"#),
            );
            assert_eq!(reply["op"], "ack", "{reply}");
        }
        holders.push(holder);
    }

    // A bystander sends on its own channel all the while.
    let bystander_path = path.clone();
    let bystander = std::thread::spawn(move || {
        let mut client = Upp::connect(&bystander_path);
        client.attach("bystander");
        let mut slowest = Duration::ZERO;
        for i in 0..50 {
            let started = Instant::now();
            let reply = send(&mut client, &format!("b{i}"), "unrelated");
            assert_eq!(reply["op"], "ack", "{reply}");
            slowest = slowest.max(started.elapsed());
        }
        slowest
    });

    // The publisher's channel is at the cap and meets all 256 patterns.
    let mut publisher = Upp::connect(&path);
    publisher.attach("publisher");
    let channel = "a".repeat(MAX_CHANNEL_LEN);
    let mut slowest = Duration::ZERO;
    for i in 0..50 {
        let started = Instant::now();
        let reply = send(&mut publisher, &format!("p{i}"), &channel);
        assert_eq!(reply["op"], "ack", "{reply}");
        slowest = slowest.max(started.elapsed());
    }
    let bystander_slowest = bystander.join().unwrap();
    assert!(
        slowest < PROMPT,
        "the publisher's slowest send: {slowest:?}"
    );
    assert!(
        bystander_slowest < PROMPT,
        "the bystander's slowest send: {bystander_slowest:?}"
    );

    // The patterns that match did: a holder receives the publisher's event.
    let event = holders[0].recv_json(TIMEOUT);
    assert_eq!(event["op"], "event", "{event}");
    assert_eq!(event["channel"], channel.as_str());
    mesh.shutdown();
}
