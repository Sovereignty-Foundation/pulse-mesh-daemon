// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `mesh_link::Control::decode`, a control message a peer
// daemon sends over a link: a Hello, an interest summary, the nodes it
// announces or a part of them (from a relay, version 2, with the nodes
// reached through it), a health notice or a heartbeat.
//
// Invariants:
// - decoding is total: any bytes give a message or an error, never a
//   panic or an allocation from a size the input declares (the harness's
//   malloc limit stands guard);
// - a decoded message re-encodes to exactly the bytes it was read from, and
//   `encoded_len` is their length;
// - an interest message's body is the summary's own encoding: the bytes
//   after the two-byte header decode, as a summary, to the same one;
// - every node a message names, announced, reached through its sender or
//   in a health notice, is written as `name@daemon` text that parses back
//   to it;
// - a message is version 2 exactly when it is an announcement naming nodes
//   through its sender, none of which it names as the sender's own;
// - an announcement's part is below its count of parts, which is 1 to
//   `MAX_ANNOUNCE_PARTS`, and a router takes it as a part of its sender's
//   announcement, or refuses it for naming another daemon's client as the
//   sender's or the sender's or the receiver's own as reached through it,
//   and never panics; a router that trusts the sender as a relay holds the
//   nodes through it once the announcement is whole, and one that does not
//   holds none.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_link::{
    Control, DaemonId, Interest, QualifiedOrigin, RouteError, Router, CONTROL_HEADER_BYTES,
    CONTROL_VERSION, MAX_ANNOUNCE_PARTS,
};

fuzz_target!(|data: &[u8]| {
    let Ok(message) = Control::decode(data) else {
        return;
    };
    assert_eq!(
        message.encode().as_deref(),
        Ok(data),
        "a decoded message does not re-encode to its bytes"
    );
    assert_eq!(message.encoded_len(), data.len());
    assert_eq!(data[0], message.version());
    let through = matches!(&message, Control::NodesAnnounced { via, .. } if !via.is_empty());
    assert_eq!(
        data[0] == CONTROL_VERSION,
        through,
        "version 2 is a relay's announcement, and only that"
    );
    match &message {
        Control::Interest(interest) => assert_eq!(
            Interest::decode(&data[CONTROL_HEADER_BYTES..]).as_ref(),
            Ok(interest),
            "an interest message's body is not the summary's encoding"
        ),
        Control::NodesAnnounced {
            generation,
            part,
            parts,
            nodes,
            via,
        } => {
            nodes.iter().chain(via).for_each(round_trips);
            assert!(
                via.iter().all(|n| !nodes.contains(n)),
                "a node in both lists"
            );
            assert!(*part < *parts && *parts <= MAX_ANNOUNCE_PARTS);
            // As from the daemon of its first node, or of none, to a router
            // that trusts it as a relay and to one that does not.
            let local = DaemonId::from_bytes([0; 8]);
            let peer = nodes
                .first()
                .map_or(DaemonId::from_bytes([1; 8]), QualifiedOrigin::daemon);
            for trusted in [false, true] {
                let mut router = Router::new(local);
                if trusted && router.trust_relay(peer).is_err() {
                    continue;
                }
                if router.add_peer(peer).is_err() {
                    continue;
                }
                let taken = router.announce_part(
                    peer,
                    *generation,
                    *part,
                    *parts,
                    nodes.clone(),
                    via.clone(),
                );
                match taken {
                    Ok(taken) => {
                        assert!(nodes.iter().all(|n| n.daemon() == peer));
                        assert!(via
                            .iter()
                            .all(|n| n.daemon() != peer && n.daemon() != local));
                        assert_eq!(taken, *parts == 1, "a lone part completes alone");
                        if taken {
                            assert_eq!(router.nodes(peer), Some(nodes));
                            let held = router.via(peer).cloned().unwrap_or_default();
                            assert_eq!(held.is_empty(), !trusted || via.is_empty());
                            assert!(!trusted || held == *via);
                        }
                    }
                    Err(RouteError::ForeignNode { .. } | RouteError::ViaNode { .. }) => {}
                    Err(e) => panic!("a decoded part was refused: {e}"),
                }
            }
        }
        Control::Health { node, .. } => round_trips(node),
        Control::Hello(_) | Control::Heartbeat => {}
    }
});

fn round_trips(node: &QualifiedOrigin) {
    assert_eq!(
        QualifiedOrigin::parse(&node.to_string()).as_ref(),
        Ok(node),
        "a node's text does not parse back to it"
    );
}
