// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What a link's datagrams carry: the layouts `crate::link`'s docs give,
//! and their encoding and decoding. Public only for the fuzz harness and the
//! tests, through `crate::internals::link_wire`; not API, and not stable.

use mesh_capability::{decode_hello, encode_hello, Hello, HELLO_BYTES};
use mesh_link::{
    Control, DaemonId, QualifiedOrigin, CONTROL_HEADER_BYTES, MAX_CONTROL_BYTES, MAX_INTEREST_BYTES,
};
use mesh_port_protocol::{MAX_CHANNEL_LEN, MAX_NAME_LEN};
use pulse_canon::{Instruction, Pulse, PulseEnvelope};
use pulse_wire_udp::MAX_MESSAGE;

/// The type name of the envelope that carries a control message.
pub const CONTROL_TYPE: &str = "pms.link/v0/control";

/// The type name of the envelope that carries a forwarded envelope.
pub const FORWARD_TYPE: &str = "pms.link/v0/forward";

/// The version of the forward layout this build writes and reads.
pub const FORWARD_VERSION: u8 = 1;

/// Forward flag: the send named its type name, so the event carries it;
/// otherwise the envelope's type name is the channel, and the event names
/// none.
const NAMED_TYPE: u8 = 1 << 0;

/// Forward flag: the send is addressed to one node, which follows the
/// channel.
const ADDRESSED: u8 = 1 << 1;

/// The forward flags this build writes and reads.
const FORWARD_FLAGS: u8 = NAMED_TYPE | ADDRESSED;

/// Hello flag: this Hello answers one, and is not answered.
const ANSWER: u8 = 1 << 0;

/// Hello flag: the sender relays (`--link-relay`).
const RELAY: u8 = 1 << 1;

/// The Hello flags this build writes and reads.
const HELLO_FLAGS: u8 = ANSWER | RELAY;

/// A link Hello's length: the capability Hello, then the flags byte.
pub const LINK_HELLO_BYTES: usize = HELLO_BYTES + 1;

/// A forward's bytes before the origin's name: the version, the flags and
/// the origin's daemon id.
const FORWARD_FIXED: usize = 1 + 1 + DaemonId::LEN;

/// Why a datagram is not a link message, or a message cannot be sent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DatagramError {
    /// The frame's bytes are not a canonical envelope with its own id in the
    /// form a link writes: type 0, a zero origin and time, no flags and a
    /// raw payload.
    #[error("not a link envelope: canonical, with its own id, type 0, no origin, time or flags, and a raw payload")]
    Envelope,
    /// The frame's Pulse does not name the envelope it carries, or names
    /// another daemon than the peer it came from.
    #[error("the pulse does not name the envelope, or names another daemon")]
    Pulse,
    /// The envelope's type name is neither link type.
    #[error("an envelope of type {0:?}, which no link sends")]
    Kind(Option<String>),
    /// A control message that does not decode.
    #[error("a control message that does not decode: {0}")]
    Control(mesh_link::CodecError),
    /// A forward whose layout is not this build's.
    #[error("a forward that does not decode: {0}")]
    Forward(&'static str),
    /// A Hello that is not a link Hello.
    #[error("a Hello that does not decode: {0}")]
    Hello(&'static str),
    /// What would be sent is longer than a run of fragments carries.
    #[error("{len} bytes are more than the {max} a link datagram carries")]
    TooLarge {
        /// The frame envelope's length.
        len: usize,
        /// [`MAX_MESSAGE`].
        max: usize,
    },
}

/// A forwarded envelope as a link carries it.
#[derive(Debug, Clone)]
pub struct LinkForward {
    /// The client that sent it, qualified by its daemon.
    pub origin: QualifiedOrigin,
    /// The channel it was sent on, which the envelope does not carry.
    pub channel: String,
    /// Whether the send named its type name.
    pub named_type: bool,
    /// The envelope, stamped with its hub's `monotonic_nanos`.
    pub envelope: PulseEnvelope,
    /// The node it is addressed to, a client of the receiving daemon; `None`
    /// for a send to the subscribers of its channel.
    pub dest: Option<QualifiedOrigin>,
}

/// What a link datagram carries.
#[derive(Debug)]
pub enum Message {
    /// A control message.
    Control(Control),
    /// A forwarded envelope.
    Forward(LinkForward),
}

/// A datagram to send: the frame's Pulse and its envelope bytes.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// A Data pulse naming the envelope, the sender's daemon id in its
    /// `origin_id`.
    pub pulse: Pulse,
    /// The link envelope's canonical bytes.
    pub bytes: Vec<u8>,
}

/// The bytes the link envelope of `kind` spends around its payload.
fn overhead(kind: &str) -> usize {
    PulseEnvelope::typed(kind, Vec::new()).canonical_size()
}

/// The longest interest summary a link sends: a control message in one run
/// of fragments, less the envelope around it and the message's header, and
/// never more than `mesh_link::MAX_INTEREST_BYTES`, whatever
/// [`MAX_MESSAGE`] allows.
pub fn max_interest_bytes() -> usize {
    (max_control_bytes() - CONTROL_HEADER_BYTES).min(MAX_INTEREST_BYTES)
}

/// The longest control message a link sends: one run of fragments, less the
/// envelope around it, and never more than `mesh_link::MAX_CONTROL_BYTES`,
/// the most a control message encodes to, whatever [`MAX_MESSAGE`] allows.
pub fn max_control_bytes() -> usize {
    (MAX_MESSAGE - overhead(CONTROL_TYPE)).min(MAX_CONTROL_BYTES)
}

/// The datagram that carries `message` from the daemon `from`.
///
/// # Errors
///
/// [`DatagramError::Control`] for a message that does not encode, and
/// [`DatagramError::TooLarge`] for one longer than a run of fragments
/// carries.
pub fn control(message: &Control, from: DaemonId) -> Result<Datagram, DatagramError> {
    let bytes = message.encode().map_err(DatagramError::Control)?;
    frame(PulseEnvelope::typed(CONTROL_TYPE, bytes), from)
}

/// The datagram that carries `forward` from the daemon `from`.
///
/// # Errors
///
/// [`DatagramError::TooLarge`] for an envelope too long for a run of
/// fragments with the forward's header.
pub fn forward(forward: &LinkForward, from: DaemonId) -> Result<Datagram, DatagramError> {
    let name = forward.origin.name().as_bytes();
    let channel = forward.channel.as_bytes();
    let inner = forward.envelope.canonical_size();
    let dest = forward
        .dest
        .as_ref()
        .map_or(0, |d| DaemonId::LEN + 2 + d.name().len());
    let mut payload =
        Vec::with_capacity(FORWARD_FIXED + 4 + name.len() + channel.len() + dest + inner);
    payload.push(FORWARD_VERSION);
    let mut flags = 0;
    if forward.named_type {
        flags |= NAMED_TYPE;
    }
    if forward.dest.is_some() {
        flags |= ADDRESSED;
    }
    payload.push(flags);
    payload.extend_from_slice(forward.origin.daemon().as_bytes());
    put_text(&mut payload, name);
    put_text(&mut payload, channel);
    if let Some(dest) = &forward.dest {
        payload.extend_from_slice(dest.daemon().as_bytes());
        put_text(&mut payload, dest.name().as_bytes());
    }
    forward.envelope.write_canonical_into(&mut payload);
    frame(PulseEnvelope::typed(FORWARD_TYPE, payload), from)
}

/// A text's length as a `u16`, then its bytes. Every text written is a
/// name or a channel, held far below `u16::MAX` bytes when it is made.
fn put_text(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(&u16::try_from(text.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(text);
}

/// The frame for `envelope`: a Data pulse naming it, from `from`, and its
/// canonical bytes, refused when a run of fragments cannot carry them.
fn frame(envelope: PulseEnvelope, from: DaemonId) -> Result<Datagram, DatagramError> {
    let bytes = envelope.to_canonical_bytes();
    if bytes.len() > MAX_MESSAGE {
        return Err(DatagramError::TooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE,
        });
    }
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
    pulse.origin_id[..DaemonId::LEN].copy_from_slice(from.as_bytes());
    pulse.set_envelope_id(&envelope.id());
    Ok(Datagram { pulse, bytes })
}

/// Read the datagram `pulse` and `bytes` that the session of the daemon
/// `from` opened: refused unless the Pulse names the envelope and claims
/// `from`, and the envelope is a link envelope of the form [`control`] and
/// [`forward`] write, whose decoded message they write back byte for byte.
///
/// # Errors
///
/// The [`DatagramError`] naming the first thing that is not a link
/// datagram's: the envelope, the Pulse, the type name, or the control
/// message's or the forward's layout.
pub fn decode(pulse: &Pulse, bytes: &[u8], from: DaemonId) -> Result<Message, DatagramError> {
    let envelope =
        PulseEnvelope::from_canonical_bytes(bytes).map_err(|_| DatagramError::Envelope)?;
    // Only the form a link writes: nothing the id leaves out may vary, so
    // that a message has one datagram.
    if !envelope.verify()
        || envelope.envelope_type() != 0
        || envelope.origin != [0; 16]
        || envelope.monotonic_nanos != 0
        || !envelope.flags.is_empty()
    {
        return Err(DatagramError::Envelope);
    }
    if pulse.envelope_id() != Some(envelope.id())
        || pulse.origin_id[..DaemonId::LEN] != from.as_bytes()[..]
    {
        return Err(DatagramError::Pulse);
    }
    let payload = envelope.payload().as_raw().ok_or(DatagramError::Envelope)?;
    match envelope.type_name() {
        Some(CONTROL_TYPE) => Control::decode(payload)
            .map(Message::Control)
            .map_err(DatagramError::Control),
        Some(FORWARD_TYPE) => read_forward(payload).map(Message::Forward),
        other => Err(DatagramError::Kind(other.map(str::to_owned))),
    }
}

/// Reads fields from the front of a forward's payload.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DatagramError> {
        if self.bytes.len() < n {
            return Err(DatagramError::Forward(what));
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn text(&mut self, max: usize, what: &'static str) -> Result<&'a str, DatagramError> {
        let len = self.take(2, what)?;
        let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
        if len > max {
            return Err(DatagramError::Forward(what));
        }
        std::str::from_utf8(self.take(len, what)?).map_err(|_| DatagramError::Forward(what))
    }
}

fn read_forward(payload: &[u8]) -> Result<LinkForward, DatagramError> {
    let mut r = Reader { bytes: payload };
    let head = r.take(FORWARD_FIXED, "the bytes end in the header")?;
    if head[0] != FORWARD_VERSION {
        return Err(DatagramError::Forward("a version this build does not read"));
    }
    let flags = head[1];
    if flags & !FORWARD_FLAGS != 0 {
        return Err(DatagramError::Forward("flags this build does not know"));
    }
    let mut daemon = [0; DaemonId::LEN];
    daemon.copy_from_slice(&head[2..]);
    let name = r.text(
        MAX_NAME_LEN,
        "an origin's name that is too long or not UTF-8",
    )?;
    let origin = QualifiedOrigin::new(DaemonId::from_bytes(daemon), name)
        .map_err(|_| DatagramError::Forward("an origin's name that is too long"))?;
    let channel = r
        .text(MAX_CHANNEL_LEN, "a channel that is too long or not UTF-8")?
        .to_owned();
    let dest = if flags & ADDRESSED != 0 {
        let daemon = r.take(DaemonId::LEN, "the bytes end in the destination")?;
        let mut id = [0; DaemonId::LEN];
        id.copy_from_slice(daemon);
        let name = r.text(
            MAX_NAME_LEN,
            "a destination's name that is too long or not UTF-8",
        )?;
        Some(
            QualifiedOrigin::new(DaemonId::from_bytes(id), name)
                .map_err(|_| DatagramError::Forward("a destination's name that is too long"))?,
        )
    } else {
        None
    };
    let envelope = PulseEnvelope::from_canonical_bytes(r.bytes)
        .map_err(|_| DatagramError::Forward("an envelope that is not canonical"))?;
    if !envelope.verify() {
        return Err(DatagramError::Forward(
            "an envelope whose id is not its content's",
        ));
    }
    Ok(LinkForward {
        origin,
        channel,
        named_type: flags & NAMED_TYPE != 0,
        envelope,
        dest,
    })
}

/// What a link Hello's flags byte says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HelloFlags {
    /// The Hello answers one, and is not answered (bit 0).
    pub answer: bool,
    /// Its sender relays (bit 1): it forwards once more what one peer sent
    /// it, and its summaries and announcements cover its other peers. A
    /// relay does not sum a relay's summaries up. What a receiver accepts
    /// from it is the receiver's own configuration (`--link-trust-relay`),
    /// never this bit.
    pub relay: bool,
}

/// A link Hello: `local`'s 48 bytes, then the flags.
pub fn hello(local: &Hello, flags: HelloFlags) -> Vec<u8> {
    let mut out = Vec::with_capacity(LINK_HELLO_BYTES);
    encode_hello(local, &mut out);
    let mut byte = 0;
    if flags.answer {
        byte |= ANSWER;
    }
    if flags.relay {
        byte |= RELAY;
    }
    out.push(byte);
    out
}

/// Read a link Hello: the capability Hello, and its flags. The capability
/// Hello's reserved bytes are not checked (`mesh-capability`), so a later
/// version may carry data there.
///
/// # Errors
///
/// [`DatagramError::Hello`] for bytes that are not 49 long, carry no
/// capability Hello, or set flags this build does not know.
pub fn read_hello(bytes: &[u8]) -> Result<(Hello, HelloFlags), DatagramError> {
    if bytes.len() != LINK_HELLO_BYTES {
        return Err(DatagramError::Hello("not the 49 bytes of a link Hello"));
    }
    let hello = decode_hello(&bytes[..HELLO_BYTES])
        .map_err(|_| DatagramError::Hello("no capability Hello"))?;
    let byte = bytes[HELLO_BYTES];
    if byte & !HELLO_FLAGS != 0 {
        return Err(DatagramError::Hello("flags this build does not know"));
    }
    let flags = HelloFlags {
        answer: byte & ANSWER != 0,
        relay: byte & RELAY != 0,
    };
    Ok((hello, flags))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_capability::{CapabilityFlags, MAX_VERSION};
    use mesh_link::Interest;

    fn daemon(byte: u8) -> DaemonId {
        DaemonId::from_bytes([byte; 8])
    }

    fn forwarded(named_type: bool, payload: Vec<u8>) -> LinkForward {
        let mut envelope = PulseEnvelope::with_content(7, Some("jobs/new".into()), payload);
        envelope.monotonic_nanos = 123_456_789;
        LinkForward {
            origin: QualifiedOrigin::new(daemon(1), "worker@00ff").unwrap(),
            channel: "jobs/new".into(),
            named_type,
            envelope,
            dest: None,
        }
    }

    fn round_trip(datagram: &Datagram, from: DaemonId) -> Message {
        decode(&datagram.pulse, &datagram.bytes, from).unwrap()
    }

    #[test]
    fn a_forward_crosses_with_its_origin_channel_and_stamp() {
        for named_type in [false, true] {
            let sent = forwarded(named_type, b"payload".to_vec());
            let datagram = forward(&sent, daemon(1)).unwrap();
            let outer = PulseEnvelope::from_canonical_bytes(&datagram.bytes).unwrap();
            assert_eq!(outer.type_name(), Some(FORWARD_TYPE));
            assert_eq!(datagram.pulse.envelope_id(), Some(outer.id()));
            assert_eq!(datagram.pulse.instruction, Instruction::Data as u16);
            let Message::Forward(got) = round_trip(&datagram, daemon(1)) else {
                panic!("not a forward");
            };
            assert_eq!(got.origin, sent.origin);
            assert_eq!(got.channel, sent.channel);
            assert_eq!(got.named_type, named_type);
            assert_eq!(got.envelope, sent.envelope);
            assert_eq!(got.envelope.monotonic_nanos, 123_456_789, "the hub's stamp");
        }
    }

    #[test]
    fn the_forward_layout_is_the_documented_one() {
        let sent = forwarded(true, b"p".to_vec());
        let datagram = forward(&sent, daemon(1)).unwrap();
        let outer = PulseEnvelope::from_canonical_bytes(&datagram.bytes).unwrap();
        let payload = outer.payload().as_raw().unwrap();
        let mut want = vec![FORWARD_VERSION, NAMED_TYPE];
        want.extend_from_slice(&[1; 8]);
        want.extend_from_slice(&11u16.to_le_bytes());
        want.extend_from_slice(b"worker@00ff");
        want.extend_from_slice(&8u16.to_le_bytes());
        want.extend_from_slice(b"jobs/new");
        want.extend_from_slice(&sent.envelope.to_canonical_bytes());
        assert_eq!(payload, &want[..]);
    }

    #[test]
    fn an_addressed_forward_carries_its_destination_after_the_channel() {
        let mut sent = forwarded(false, b"p".to_vec());
        sent.dest = Some(QualifiedOrigin::new(daemon(2), "w").unwrap());
        let datagram = forward(&sent, daemon(1)).unwrap();
        let outer = PulseEnvelope::from_canonical_bytes(&datagram.bytes).unwrap();
        let payload = outer.payload().as_raw().unwrap();
        let mut want = vec![FORWARD_VERSION, ADDRESSED];
        want.extend_from_slice(&[1; 8]);
        want.extend_from_slice(&11u16.to_le_bytes());
        want.extend_from_slice(b"worker@00ff");
        want.extend_from_slice(&8u16.to_le_bytes());
        want.extend_from_slice(b"jobs/new");
        want.extend_from_slice(&[2; 8]);
        want.extend_from_slice(&1u16.to_le_bytes());
        want.push(b'w');
        want.extend_from_slice(&sent.envelope.to_canonical_bytes());
        assert_eq!(payload, &want[..]);
        let Message::Forward(got) = round_trip(&datagram, daemon(1)) else {
            panic!("not a forward");
        };
        assert_eq!(got.dest, sent.dest);
        assert_eq!(got.envelope, sent.envelope);
        // Cut inside the destination, it is refused.
        let cut = 2 + 8 + 2 + 11 + 2 + 8 + 5;
        assert!(read_forward(&payload[..cut]).is_err());
    }

    #[test]
    fn a_control_message_crosses_as_its_canonical_bytes() {
        let interest = Interest::everything().with_generation(4);
        for message in [Control::Heartbeat, Control::Interest(interest)] {
            let datagram = control(&message, daemon(2)).unwrap();
            let outer = PulseEnvelope::from_canonical_bytes(&datagram.bytes).unwrap();
            assert_eq!(outer.type_name(), Some(CONTROL_TYPE));
            assert_eq!(
                outer.payload().as_raw().unwrap(),
                &message.encode().unwrap()[..]
            );
            match round_trip(&datagram, daemon(2)) {
                Message::Control(got) => assert_eq!(got, message),
                Message::Forward(_) => panic!("not a control message"),
            }
        }
    }

    #[test]
    fn a_datagram_naming_another_daemon_or_envelope_is_refused() {
        let datagram = control(&Control::Heartbeat, daemon(2)).unwrap();
        assert!(matches!(
            decode(&datagram.pulse, &datagram.bytes, daemon(3)),
            Err(DatagramError::Pulse)
        ));
        let mut pulse = datagram.pulse;
        pulse.set_envelope_id(&PulseEnvelope::typed("x", vec![]).id());
        assert!(matches!(
            decode(&pulse, &datagram.bytes, daemon(2)),
            Err(DatagramError::Pulse)
        ));
        let other = PulseEnvelope::typed("app/x", vec![1]);
        let mut pulse = datagram.pulse;
        pulse.set_envelope_id(&other.id());
        assert!(matches!(
            decode(&pulse, &other.to_canonical_bytes(), daemon(2)),
            Err(DatagramError::Kind(Some(_)))
        ));
    }

    #[test]
    fn a_link_envelope_in_any_form_but_the_one_a_link_writes_is_refused() {
        let message = Control::Heartbeat.encode().unwrap();
        let variants: [fn(&mut PulseEnvelope); 3] = [
            |e| e.origin = [1; 16],
            |e| e.monotonic_nanos = 1,
            |e| e.flags = pulse_canon::PulseEnvelopeFlags::BROADCAST,
        ];
        for change in variants {
            let mut envelope = PulseEnvelope::typed(CONTROL_TYPE, message.clone());
            change(&mut envelope);
            let mut pulse = control(&Control::Heartbeat, daemon(2)).unwrap().pulse;
            pulse.set_envelope_id(&envelope.id());
            assert!(matches!(
                decode(&pulse, &envelope.to_canonical_bytes(), daemon(2)),
                Err(DatagramError::Envelope)
            ));
        }
        let typed = PulseEnvelope::with_content(5, Some(CONTROL_TYPE.into()), message);
        let mut pulse = control(&Control::Heartbeat, daemon(2)).unwrap().pulse;
        pulse.set_envelope_id(&typed.id());
        assert!(matches!(
            decode(&pulse, &typed.to_canonical_bytes(), daemon(2)),
            Err(DatagramError::Envelope)
        ));
    }

    #[test]
    fn a_forward_cut_short_or_with_unknown_flags_is_refused() {
        let datagram = forward(&forwarded(false, b"p".to_vec()), daemon(1)).unwrap();
        let outer = PulseEnvelope::from_canonical_bytes(&datagram.bytes).unwrap();
        let payload = outer.payload().as_raw().unwrap().to_vec();
        for cut in [0, 5, FORWARD_FIXED + 1, payload.len() - 1] {
            assert!(read_forward(&payload[..cut]).is_err(), "cut at {cut}");
        }
        let mut flagged = payload.clone();
        flagged[1] = 0x80;
        assert!(read_forward(&flagged).is_err());
        // The addressed flag, with no destination after the channel.
        let mut addressed = payload.clone();
        addressed[1] = ADDRESSED;
        assert!(read_forward(&addressed).is_err());
        let mut versioned = payload;
        versioned[0] = 2;
        assert!(read_forward(&versioned).is_err());
    }

    #[test]
    fn an_envelope_too_large_for_a_run_is_refused_before_it_is_sent() {
        let fits = MAX_MESSAGE - overhead(FORWARD_TYPE) - FORWARD_FIXED - 4 - 11 - 8;
        let base = forwarded(false, Vec::new()).envelope.canonical_size();
        assert!(forward(&forwarded(false, vec![0; fits - base]), daemon(1)).is_ok());
        assert!(matches!(
            forward(&forwarded(false, vec![0; fits - base + 1]), daemon(1)),
            Err(DatagramError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_hello_is_the_capability_hello_and_a_flag() {
        let local = Hello {
            version: MAX_VERSION,
            capabilities: CapabilityFlags::from_bits(0),
            registry_hash: [0; 32],
        };
        for answer in [false, true] {
            for relay in [false, true] {
                let flags = HelloFlags { answer, relay };
                let bytes = hello(&local, flags);
                assert_eq!(bytes.len(), LINK_HELLO_BYTES);
                assert_eq!(
                    bytes[HELLO_BYTES],
                    u8::from(answer) | u8::from(relay) << 1,
                    "bit 0 answers, bit 1 relays"
                );
                assert_eq!(read_hello(&bytes).unwrap(), (local, flags));
            }
        }
        let asking = HelloFlags::default();
        assert!(read_hello(&hello(&local, asking)[..HELLO_BYTES]).is_err());
        let mut flagged = hello(&local, asking);
        flagged[HELLO_BYTES] = 4;
        assert!(read_hello(&flagged).is_err());
        assert!(max_interest_bytes() <= MAX_INTEREST_BYTES);
        assert!(max_control_bytes() <= MAX_CONTROL_BYTES);
        assert_eq!(
            max_control_bytes(),
            (MAX_MESSAGE - overhead(CONTROL_TYPE)).min(MAX_CONTROL_BYTES)
        );
    }
}
