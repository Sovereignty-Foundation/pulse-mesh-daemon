// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: a daemon's LAN announcement of its link endpoint
// (`mesh_hub::internals::link_announce`, the daemon's `link/announce.rs`),
// what anything on the multicast group can send it.
//
// The first byte picks what the rest is:
// - even: the bytes of a datagram's envelope, decoded as an announcement;
// - odd: a key (32 bytes) and a port (2 bytes, little-endian), encoded as
//   an announcement and decoded again.
//
// Invariants:
// - decoding is total: any bytes give an announcement or an error, never a
//   panic;
// - a decoded announcement re-encodes to exactly the bytes it was read
//   from: it is the 47 bytes of the layout, its port is not zero, and its
//   daemon id is its key's fingerprint, so every other byte string is
//   refused;
// - the link address it gives is the source's IP and the announced port;
// - an announcement made of any key and any port but 0 decodes to itself,
//   and one of port 0 is refused.

#![no_main]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use mesh_hub::internals::link_announce::{decode, encode, LanAnnouncement, ANNOUNCE_BYTES};
use mesh_link::DaemonId;
use pulse_wire_udp::PublicKey;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    if pick % 2 == 0 {
        check(rest);
    } else {
        made(rest);
    }
});

/// Decode `bytes`, and hold an announcement that decodes to the invariants.
fn check(bytes: &[u8]) {
    let Ok(announcement) = decode(bytes) else {
        return;
    };
    assert_eq!(bytes.len(), ANNOUNCE_BYTES);
    assert_eq!(
        &encode(&announcement)[..],
        bytes,
        "a decoded announcement does not re-encode to its bytes"
    );
    assert_ne!(announcement.port, 0);
    assert_eq!(
        announcement.daemon_id(),
        DaemonId::from_public_key(announcement.key.as_bytes())
    );
    let source = SocketAddr::from(([192, 0, 2, 9], 50_000));
    let at = announcement.link_addr(source);
    assert_eq!((at.ip(), at.port()), (source.ip(), announcement.port));
}

/// Encode an announcement of the key and the port `bytes` start with, and
/// decode it again.
fn made(bytes: &[u8]) {
    if bytes.len() < 34 {
        return;
    }
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[..32]);
    let port = u16::from_le_bytes([bytes[32], bytes[33]]);
    let announcement = LanAnnouncement {
        key: PublicKey::from_bytes(key),
        port,
    };
    let encoded = encode(&announcement);
    match decode(&encoded) {
        Ok(decoded) => {
            assert_ne!(port, 0, "an announcement of port 0 was taken");
            assert_eq!(
                decoded, announcement,
                "an announcement does not decode to itself"
            );
        }
        Err(e) => assert_eq!(port, 0, "an announcement was refused: {e}"),
    }
    check(&encoded);
}
