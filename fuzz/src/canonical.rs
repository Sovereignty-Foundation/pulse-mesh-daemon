// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The canonical envelope, read from the specification.
//!
//! [`parse`] reads the layout of section 3.1 of the specification and
//! [`Parsed::spec_id`] computes the content identifier of section 3.2. Both
//! are written from the text, not from `pulse-canon`: the identifier's
//! preimage is taken from the input's own bytes, the type-name section and
//! the payload bytes exactly as they appear on the wire, so no encoder is
//! involved. Two rules come from the reference decoder's documented
//! contract rather than the chapter as it stands: a reserved flag bit
//! (bits 4 to 15) is refused, since the decoder refuses what its encoder
//! would not write, and nesting is bounded at [`MAX_DEPTH`] as section 3.4
//! allows.

use std::ops::Range;

/// Bytes of the fixed header (section 3.1).
pub const FIXED_HEADER: usize = 44;
/// The smallest envelope: the header, an absent name, a variant tag and a
/// zero length.
pub const MIN_ENVELOPE: usize = FIXED_HEADER + 1 + 1 + 4;
/// The four defined flag bits; the other twelve are reserved.
pub const DEFINED_FLAGS: u16 = 0x000f;
/// Nested payloads accepted below the outermost envelope (section 3.4).
pub const MAX_DEPTH: usize = 32;
/// The identifier's domain tag (section 3.2).
pub const DOMAIN_TAG: &[u8] = b"pulse-envelope-id/v2";

/// A payload as the wire carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Variant 0: opaque bytes.
    Raw(Vec<u8>),
    /// Variant 1: envelopes, each in its canonical form.
    Nested(Vec<Parsed>),
}

/// One envelope read from a buffer, with where its parts lie in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Bytes 0..16: the identifier the envelope carries.
    pub id: [u8; 16],
    /// Bytes 16..32.
    pub origin: [u8; 16],
    /// Bytes 32..40.
    pub monotonic_nanos: u64,
    /// Bytes 40..42.
    pub envelope_type: u16,
    /// Bytes 42..44.
    pub flags: u16,
    /// The type name, when the presence tag is 1.
    pub type_name: Option<String>,
    /// The payload.
    pub payload: Payload,
    /// The type-name section as it appears on the wire.
    pub name_section: Vec<u8>,
    /// The payload variant tag.
    pub variant: u8,
    /// The payload bytes of section 3.2: a raw payload's bytes, or a nested
    /// payload's count and its children's canonical bytes.
    pub payload_bytes: Vec<u8>,
    /// Where the envelope lies in the buffer it was read from.
    pub span: Range<usize>,
}

/// Read one envelope from `buf` at `at`, nested `depth` levels below the
/// outermost, or `None` when the bytes there are not one.
#[must_use]
pub fn parse(buf: &[u8], at: usize, depth: usize) -> Option<Parsed> {
    let mut cur = Cursor { buf, pos: at };
    let id: [u8; 16] = cur.array()?;
    let origin: [u8; 16] = cur.array()?;
    let monotonic_nanos = u64::from_le_bytes(cur.array()?);
    let envelope_type = u16::from_le_bytes(cur.array()?);
    let flags = u16::from_le_bytes(cur.array()?);
    if flags & !DEFINED_FLAGS != 0 {
        return None;
    }
    let name_start = cur.pos;
    let type_name = match cur.byte()? {
        0 => None,
        1 => {
            let len = u32::from_le_bytes(cur.array()?) as usize;
            Some(std::str::from_utf8(cur.take(len)?).ok()?.to_owned())
        }
        _ => return None,
    };
    let name_section = buf[name_start..cur.pos].to_vec();
    let variant = cur.byte()?;
    let body_start = cur.pos + 4;
    let count_or_len = u32::from_le_bytes(cur.array()?) as usize;
    let payload = match variant {
        0 => Payload::Raw(cur.take(count_or_len)?.to_vec()),
        1 => {
            if depth >= MAX_DEPTH {
                return None;
            }
            let mut children = Vec::new();
            for _ in 0..count_or_len {
                let child = parse(buf, cur.pos, depth + 1)?;
                cur.pos = child.span.end;
                children.push(child);
            }
            Payload::Nested(children)
        }
        _ => return None,
    };
    let payload_bytes = match payload {
        Payload::Raw(ref bytes) => bytes.clone(),
        // The count and the children, exactly as the wire carries them.
        Payload::Nested(_) => buf[body_start - 4..cur.pos].to_vec(),
    };
    Some(Parsed {
        id,
        origin,
        monotonic_nanos,
        envelope_type,
        flags,
        type_name,
        payload,
        name_section,
        variant,
        payload_bytes,
        span: at..cur.pos,
    })
}

/// Read `buf` as exactly one envelope, or `None`.
#[must_use]
pub fn parse_exact(buf: &[u8]) -> Option<Parsed> {
    parse(buf, 0, 0).filter(|p| p.span.end == buf.len())
}

impl Parsed {
    /// The content identifier section 3.2 defines, computed from the
    /// envelope's own bytes.
    #[must_use]
    pub fn spec_id(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_TAG);
        hasher.update(&self.envelope_type.to_le_bytes());
        hasher.update(&self.name_section);
        hasher.update(&[self.variant]);
        hasher.update(&(self.payload_bytes.len() as u32).to_le_bytes());
        hasher.update(&self.payload_bytes);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    /// Whether the identifier the envelope carries is the one its content
    /// hashes to: section 3.5's self-verification.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.spec_id() == self.id
    }

    /// Whether `env`, as `pulse-canon` decoded it, holds exactly what this
    /// reading of the same bytes holds, field by field and child by child.
    #[must_use]
    pub fn matches(&self, env: &pulse_canon::PulseEnvelope) -> bool {
        use pulse_canon::PayloadData;
        let payload = match (&self.payload, env.payload()) {
            (Payload::Raw(a), PayloadData::Raw(b)) => a == b,
            (Payload::Nested(a), PayloadData::Nested(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(p, e)| p.matches(e))
            }
            _ => false,
        };
        payload
            && self.id == env.id().0
            && self.origin == env.origin
            && self.monotonic_nanos == env.monotonic_nanos
            && self.envelope_type == env.envelope_type()
            && self.flags == env.flags.bits()
            && self.type_name.as_deref() == env.type_name()
    }
}

/// The content identifier section 3.2 defines for an envelope of
/// `envelope_type`, an optional type name and a raw payload, computed from
/// those values without building the envelope.
#[must_use]
pub fn raw_id(envelope_type: u16, type_name: Option<&str>, payload: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(&envelope_type.to_le_bytes());
    match type_name {
        None => {
            hasher.update(&[0]);
        }
        Some(name) => {
            hasher.update(&[1]);
            hasher.update(&(name.len() as u32).to_le_bytes());
            hasher.update(name.as_bytes());
        }
    }
    hasher.update(&[0]);
    hasher.update(&(payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

/// A read position in a buffer; every read is bounds-checked.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
}
