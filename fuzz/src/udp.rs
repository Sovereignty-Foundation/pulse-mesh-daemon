// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The UDP transport's datagrams, read from the specification.
//!
//! [`parse_frame`] reads a data frame as section 6.1 of the specification
//! (`book/src/reference/spec/06-udp-transport.md`) lays it out, checked with
//! [`crc32c`], the Castagnoli CRC written from its definition; [`parse_parity`]
//! reads a parity datagram as section 6.3 lays it out; [`parse_fragment`]
//! reads a fragment as the transport's `fragment` module documents its
//! layout. None calls `pulse-wire-udp`, so a target can judge the
//! transport's decoding, and what its receiver makes of a datagram, without
//! asking the code under test.

use std::net::IpAddr;

/// A data frame's magic, `PMSW`, in the order the bytes travel.
pub const FRAME_MAGIC: [u8; 4] = *b"PMSW";
/// A parity datagram's magic, `PMSF`.
pub const PARITY_MAGIC: [u8; 4] = *b"PMSF";
/// A fragment's magic, `PMSG`.
pub const FRAGMENT_MAGIC: [u8; 4] = *b"PMSG";
/// A fragment's header: magic, version, sequence number, send time, the
/// run's first sequence number, index, count, total length and chunk
/// length.
pub const FRAGMENT_HEADER: usize = 4 + 1 + 8 + 8 + 8 + 2 + 2 + 4 + 2;
/// The longest envelope a run of fragments carries.
pub const MAX_MESSAGE: usize = 65_536 + 1_024;
/// The most fragments in one run.
pub const MAX_FRAGMENTS: u16 = 1024;
/// The version byte a data frame carries.
pub const VERSION: u8 = 1;
/// A data frame's header: magic, version, sequence number, send time, the
/// Pulse's 128 bytes and the envelope length.
pub const FRAME_HEADER: usize = 4 + 1 + 8 + 8 + 128 + 4;
/// A data frame's trailer, the CRC.
pub const FRAME_TRAILER: usize = 4;
/// The path allowance every datagram fits: 1,500 bytes less 20 of IPv4
/// and 8 of UDP.
pub const MTU: usize = 1_500 - 20 - 8;
/// The largest envelope a data frame carries.
pub const MAX_ENVELOPE: usize = MTU - FRAME_HEADER - FRAME_TRAILER;
/// A parity datagram's header: magic, window start, window size and parity
/// length.
pub const PARITY_HEADER: usize = 4 + 8 + 2 + 4;

/// A data frame, field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The sequence number.
    pub seq: u64,
    /// The sender's clock.
    pub send_ns: u64,
    /// The Pulse's bytes.
    pub pulse: [u8; 128],
    /// The envelope.
    pub envelope: Vec<u8>,
}

/// A fragment, field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentSpec {
    /// The fragment's sequence number.
    pub seq: u64,
    /// The sender's clock.
    pub send_ns: u64,
    /// The run's first sequence number.
    pub first_seq: u64,
    /// The fragment's place in the run.
    pub index: u16,
    /// Fragments in the run.
    pub count: u16,
    /// The whole envelope's length.
    pub total_len: u32,
    /// The Pulse, in the first fragment only.
    pub pulse: Option<[u8; 128]>,
    /// The fragment's part of the envelope.
    pub chunk: Vec<u8>,
}

/// The fragment at the start of `bytes`: the magic, version 1, a chunk
/// (after the Pulse, in the first fragment) of the declared length that the
/// bytes hold, a CRC over everything before it that matches, an index below
/// a count of at most [`MAX_FRAGMENTS`], a total length of at most
/// [`MAX_MESSAGE`], and a sequence number that is the run's first plus the
/// index. Bytes after the CRC are not the fragment's.
#[must_use]
pub fn parse_fragment(bytes: &[u8]) -> Option<FragmentSpec> {
    if bytes.get(..4)? != FRAGMENT_MAGIC || *bytes.get(4)? != VERSION {
        return None;
    }
    let u64_at = |at: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
    };
    let u16_at = |at: usize| -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
    };
    let (seq, send_ns, first_seq) = (u64_at(5)?, u64_at(13)?, u64_at(21)?);
    let (index, count) = (u16_at(29)?, u16_at(31)?);
    let total_len = u32::from_le_bytes(bytes.get(33..37)?.try_into().ok()?);
    let chunk_len = usize::from(u16_at(37)?);
    let pulse_len = if index == 0 { 128 } else { 0 };
    let body = bytes.get(..FRAGMENT_HEADER + pulse_len + chunk_len)?;
    let crc = u32::from_le_bytes(bytes.get(body.len()..body.len() + 4)?.try_into().ok()?);
    let pulse: Option<[u8; 128]> = match index {
        0 => Some(
            body.get(FRAGMENT_HEADER..FRAGMENT_HEADER + 128)?
                .try_into()
                .ok()?,
        ),
        _ => None,
    };
    let valid = crc32c(body) == crc
        && count >= 1
        && count <= MAX_FRAGMENTS
        && index < count
        && total_len as usize <= MAX_MESSAGE
        && seq == first_seq.wrapping_add(u64::from(index));
    valid.then(|| FragmentSpec {
        seq,
        send_ns,
        first_seq,
        index,
        count,
        total_len,
        pulse,
        chunk: body[FRAGMENT_HEADER + pulse_len..].to_vec(),
    })
}

/// A parity datagram, field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parity {
    /// The first sequence number of the window it covers.
    pub window_start: u64,
    /// The window's size, K.
    pub window_n: u16,
    /// The parity bytes.
    pub parity: Vec<u8>,
}

/// The data frame at the start of `bytes`: the magic, version 1, an envelope
/// length of at most [`MAX_ENVELOPE`] that the bytes hold, and a CRC over
/// everything before it that matches. Bytes after the CRC are not the
/// frame's, as the zero padding after a frame rebuilt from parity is not;
/// the receiver's decode path passes over them.
#[must_use]
pub fn parse_frame(bytes: &[u8]) -> Option<Frame> {
    if bytes.get(..4)? != FRAME_MAGIC || *bytes.get(4)? != VERSION {
        return None;
    }
    let seq = u64::from_le_bytes(bytes.get(5..13)?.try_into().ok()?);
    let send_ns = u64::from_le_bytes(bytes.get(13..21)?.try_into().ok()?);
    let pulse: [u8; 128] = bytes.get(21..149)?.try_into().ok()?;
    let n = u32::from_le_bytes(bytes.get(149..153)?.try_into().ok()?) as usize;
    if n > MAX_ENVELOPE {
        return None;
    }
    let body = bytes.get(..FRAME_HEADER + n)?;
    let crc = u32::from_le_bytes(
        bytes
            .get(FRAME_HEADER + n..FRAME_HEADER + n + FRAME_TRAILER)?
            .try_into()
            .ok()?,
    );
    (crc32c(body) == crc).then(|| Frame {
        seq,
        send_ns,
        pulse,
        envelope: body[FRAME_HEADER..].to_vec(),
    })
}

/// The parity datagram at the start of `bytes`: the magic, a window of at
/// least one frame, and as many parity bytes as the header declares. Bytes
/// after them are not the datagram's.
#[must_use]
pub fn parse_parity(bytes: &[u8]) -> Option<Parity> {
    if bytes.get(..4)? != PARITY_MAGIC {
        return None;
    }
    let window_start = u64::from_le_bytes(bytes.get(4..12)?.try_into().ok()?);
    let window_n = u16::from_le_bytes(bytes.get(12..14)?.try_into().ok()?);
    let len = u32::from_le_bytes(bytes.get(14..18)?.try_into().ok()?) as usize;
    if window_n == 0 {
        return None;
    }
    let parity = bytes.get(PARITY_HEADER..PARITY_HEADER.checked_add(len)?)?;
    Some(Parity {
        window_start,
        window_n,
        parity: parity.to_vec(),
    })
}

/// CRC-32C (Castagnoli): the reflected polynomial `0x82F63B78`, with the
/// initial value and the final exclusive or all ones.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &b| {
        (crc >> 8) ^ CRC_TABLE[usize::from((crc as u8) ^ b)]
    })
}

/// The CRC of every byte value, one byte at a time.
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// The address a source is compared by: an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`) is the IPv4 address it maps, as the transport's peer
/// filters take it; any other address is itself.
#[must_use]
pub fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => IpAddr::from([a, b, c, d]),
            _ => ip,
        },
        v4 => v4,
    }
}
