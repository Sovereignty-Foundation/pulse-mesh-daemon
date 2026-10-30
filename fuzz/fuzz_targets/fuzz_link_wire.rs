// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the datagrams daemons send one another over a link
// (`mesh_hub::internals::link_wire`, the daemon's `link/wire.rs`): the
// link envelope a peer's sealed session delivers, the control and forward
// payloads it carries (a relay's announcement among them, in control
// version 2), and the link Hello's layout with its flags.
//
// The first byte picks what the rest is:
// - 0: a frame's envelope bytes, under a Pulse that claims the sending
//   daemon and names the envelope the bytes state, if they state one;
// - 1: a control payload, which the harness wraps in a link control
//   envelope with its own id, so the decoder's payload paths are reached
//   past the id check;
// - 2: a forward payload, wrapped in a link forward envelope likewise;
// - 3: a link Hello.
//
// Invariants:
// - decoding is total: any bytes give a message or an error, never a panic
//   or an allocation from a size the input declares;
// - a decoded message re-encodes to exactly the bytes it was read from: the
//   link envelope's form is fixed, the control encoding and the forward's
//   layout are canonical, and so is the forwarded envelope;
// - a datagram that decodes as from one daemon is refused as from another;
// - the hop limit a forward carries in its Pulse's `chain_step` changes
//   nothing a datagram decodes to;
// - a forward's origin, and its destination when it is addressed, are
//   written as `name@daemon` text that parses back to them;
// - a Hello re-encodes to bytes that decode to the same Hello and the same
//   flags (that it answers one, that its sender relays), its flags byte to
//   itself, and to its own bytes when the capability Hello's reserved bytes
//   are zero (they are not checked, so a later version may use them).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_hub::internals::link_wire::{
    control, decode, forward, hello, read_hello, Message, CONTROL_TYPE, FORWARD_TYPE,
    LINK_HELLO_BYTES,
};
use mesh_link::{with_hop_limit, DaemonId, QualifiedOrigin, ORIGIN_HOP_LIMIT};
use pulse_canon::{Instruction, Pulse, PulseEnvelope};
use pulse_wire_udp::MAX_MESSAGE;

/// The daemon the datagrams come from, and one they do not.
const FROM: DaemonId = DaemonId::from_bytes([7; 8]);
const OTHER: DaemonId = DaemonId::from_bytes([8; 8]);

/// The capability Hello's six reserved bytes, before the link's flags byte.
const RESERVED: std::ops::Range<usize> = LINK_HELLO_BYTES - 7..LINK_HELLO_BYTES - 1;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    match pick % 4 {
        0 => {
            let named = PulseEnvelope::from_canonical_bytes(rest)
                .ok()
                .map(|e| e.id());
            check(&pulse_naming(named), rest);
        }
        1 => wrapped(CONTROL_TYPE, rest),
        2 => wrapped(FORWARD_TYPE, rest),
        _ => check_hello(rest),
    }
});

/// A Data pulse from [`FROM`] naming `envelope`, as a link writes one.
fn pulse_naming(envelope: Option<pulse_canon::PulseEnvelopeId>) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.origin_id[..DaemonId::LEN].copy_from_slice(FROM.as_bytes());
    if let Some(id) = envelope {
        pulse.set_envelope_id(&id);
    }
    pulse
}

/// `payload` in a link envelope of `kind` with its own id, then checked.
fn wrapped(kind: &str, payload: &[u8]) {
    let envelope = PulseEnvelope::typed(kind, payload.to_vec());
    check(
        &pulse_naming(Some(envelope.id())),
        &envelope.to_canonical_bytes(),
    );
}

/// Decode `bytes` under `pulse` as from [`FROM`], and hold a decoded
/// message to the invariants.
fn check(pulse: &Pulse, bytes: &[u8]) {
    let Ok(message) = decode(pulse, bytes, FROM) else {
        return;
    };
    assert!(
        decode(pulse, bytes, OTHER).is_err(),
        "a datagram claiming one daemon was taken as another's"
    );
    for hops in [1, ORIGIN_HOP_LIMIT, u64::MAX] {
        assert!(
            decode(&with_hop_limit(*pulse, hops), bytes, FROM).is_ok(),
            "a hop limit changed whether a datagram decodes"
        );
    }
    let again = match &message {
        Message::Control(message) => control(message, FROM),
        Message::Forward(forwarded) => {
            assert_eq!(
                QualifiedOrigin::parse(&forwarded.origin.to_string()).as_ref(),
                Ok(&forwarded.origin),
                "a forward's origin does not parse back to it"
            );
            if let Some(dest) = &forwarded.dest {
                assert_eq!(
                    QualifiedOrigin::parse(&dest.to_string()).as_ref(),
                    Ok(dest),
                    "a forward's destination does not parse back to it"
                );
            }
            forward(forwarded, FROM)
        }
    };
    match again {
        Ok(datagram) => assert!(
            datagram.bytes == bytes,
            "a decoded link message does not re-encode to its bytes"
        ),
        // Only a datagram longer than a run of fragments carries, which the
        // transport never delivers, can fail to re-encode.
        Err(_) => assert!(bytes.len() > MAX_MESSAGE),
    }
}

/// Read `bytes` as a link Hello, and hold one that decodes to the
/// invariants.
fn check_hello(bytes: &[u8]) {
    let Ok((decoded, flags)) = read_hello(bytes) else {
        return;
    };
    let again = hello(&decoded, flags);
    assert_eq!(again.len(), LINK_HELLO_BYTES);
    assert_eq!(
        read_hello(&again).ok(),
        Some((decoded, flags)),
        "a Hello does not decode to itself once re-encoded"
    );
    assert_eq!(
        again[LINK_HELLO_BYTES - 1],
        bytes[LINK_HELLO_BYTES - 1],
        "a Hello's flags do not re-encode to their byte"
    );
    if bytes[RESERVED].iter().all(|&b| b == 0) {
        assert_eq!(again, bytes, "a Hello does not re-encode to its bytes");
    }
}
