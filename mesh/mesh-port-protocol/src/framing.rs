// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The Unix socket's framing: a 4-byte big-endian payload length, then the
//! payload (the JSON).
//!
//! Sans-IO, so the daemon, the Rust client and the fuzz target
//! `fuzz_uds_framing` run the same code: [`FrameDecoder`] takes bytes in pieces
//! of any size and hands back whole payloads, and [`encode_frame`] prefixes
//! one. Neither looks inside a payload.
//!
//! ```
//! use mesh_port_protocol::framing::{encode_frame, FrameDecoder};
//!
//! let mut stream = encode_frame(br#"{"op":"health"}"#)?;
//! stream.extend(encode_frame(b"{}")?);
//! let mut frames = FrameDecoder::new(1024);
//! frames.push(&stream[..3]);
//! assert_eq!(frames.pop()?, None, "the prefix is not complete yet");
//! frames.push(&stream[3..]);
//! assert_eq!(frames.pop()?.as_deref(), Some(&br#"{"op":"health"}"#[..]));
//! assert_eq!(frames.pop()?.as_deref(), Some(&b"{}"[..]));
//! assert_eq!(frames.pop()?, None);
//! # Ok::<(), mesh_port_protocol::framing::FrameError>(())
//! ```

/// Bytes in the length prefix.
pub const PREFIX_LEN: usize = 4;

/// The longest frame a prefix can declare, and so the longest payload
/// [`encode_frame`] accepts: `u32::MAX` bytes.
pub const MAX_FRAME_LEN: usize = u32::MAX as usize;

/// Capacity an emptied decoder keeps; a larger buffer is released.
const RETAINED_CAPACITY: usize = 16 * 1024;

/// Why the framer refused a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// A frame longer than the decoder's maximum, or a payload longer than a
    /// prefix can declare.
    Oversized {
        /// The frame's length in bytes: what its prefix declared, or the
        /// payload's length.
        len: usize,
        /// The most allowed: the decoder's maximum, or [`MAX_FRAME_LEN`]
        /// for the encoder.
        max: usize,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Oversized { len, max } => {
                write!(f, "frame of {len} bytes exceeds the {max} byte limit")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Frame `payload`: its length as 4 big-endian bytes, then the payload.
///
/// # Errors
///
/// [`FrameError::Oversized`] when the payload is longer than
/// [`MAX_FRAME_LEN`], the most a prefix can declare.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let prefix = prefix(payload.len())?;
    let mut frame = Vec::with_capacity(PREFIX_LEN + payload.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// The prefix declaring a frame of `len` bytes.
fn prefix(len: usize) -> Result<[u8; PREFIX_LEN], FrameError> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| FrameError::Oversized {
            len,
            max: MAX_FRAME_LEN,
        })
}

/// Cuts a byte stream into frames: [`push`](Self::push) bytes as they
/// arrive, then [`pop`](Self::pop) until it returns `Ok(None)`.
pub struct FrameDecoder {
    /// Bytes received. Those before `start` have been returned as frames.
    buf: Vec<u8>,
    /// Where the bytes not yet returned begin.
    start: usize,
    /// The longest frame accepted.
    max_frame: usize,
}

impl FrameDecoder {
    /// A decoder that accepts frames of at most `max_frame` bytes.
    #[must_use]
    pub fn new(max_frame: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            max_frame,
        }
    }

    /// Append bytes received from the stream, in pieces of any size.
    pub fn push(&mut self, bytes: &[u8]) {
        // Reclaim the returned bytes once they outweigh the rest: amortised
        // constant work per byte.
        if self.start > 0 && self.start >= self.buf.len() - self.start {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame's payload, in push order, or `Ok(None)` until
    /// more bytes arrive.
    ///
    /// # Errors
    ///
    /// [`FrameError::Oversized`] as soon as the next prefix declares more than
    /// the maximum, before any of that frame is allocated; every later call
    /// returns it again, so the caller closes the connection.
    pub fn pop(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let pending = &self.buf[self.start..];
        let Some((prefix, rest)) = pending.split_first_chunk::<PREFIX_LEN>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*prefix) as usize;
        if len > self.max_frame {
            return Err(FrameError::Oversized {
                len,
                max: self.max_frame,
            });
        }
        let Some(payload) = rest.get(..len) else {
            return Ok(None);
        };
        let frame = payload.to_vec();
        self.start += PREFIX_LEN + len;
        if self.start == self.buf.len() {
            self.start = 0;
            if self.buf.capacity() > RETAINED_CAPACITY {
                self.buf = Vec::new();
            } else {
                self.buf.clear();
            }
        }
        Ok(Some(frame))
    }

    /// Bytes pushed and not yet returned in a frame: a partial frame, or
    /// complete ones waiting for [`pop`](Self::pop).
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

// The sizes, not the bytes, which may be a megabyte of someone's JSON.
impl std::fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("buffered", &self.buffered())
            .field("max_frame", &self.max_frame)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// Payloads of the shapes a stream carries: JSON, empty, one byte,
    /// every byte value, and bytes that look like prefixes.
    fn payloads() -> Vec<Vec<u8>> {
        vec![
            br#"{"op":"health"}"#.to_vec(),
            Vec::new(),
            b"x".to_vec(),
            (0..=255u8).cycle().take(700).collect(),
            Vec::new(),
            vec![0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            br#"{"op":"attach","name":"n","protocol_version":"v0"}"#.to_vec(),
        ]
    }

    /// The frames of `payloads`, back to back, and where each prefix and
    /// each payload begins.
    fn stream(payloads: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>) {
        let (mut bytes, mut boundaries) = (Vec::new(), Vec::new());
        for p in payloads {
            boundaries.push(bytes.len());
            boundaries.push(bytes.len() + PREFIX_LEN);
            bytes.extend(encode_frame(p).unwrap());
        }
        boundaries.push(bytes.len());
        (bytes, boundaries)
    }

    /// Push `pieces` in order, popping every complete frame after each.
    fn decode_pieces<'a>(pieces: impl IntoIterator<Item = &'a [u8]>) -> Vec<Vec<u8>> {
        let mut decoder = FrameDecoder::new(1 << 20);
        let mut frames = Vec::new();
        for piece in pieces {
            decoder.push(piece);
            while let Some(frame) = decoder.pop().unwrap() {
                frames.push(frame);
            }
        }
        assert_eq!(decoder.buffered(), 0, "nothing left over");
        frames
    }

    #[test]
    fn one_push_or_one_byte_at_a_time_yields_the_same_frames() {
        let payloads = payloads();
        let (bytes, _) = stream(&payloads);
        assert_eq!(decode_pieces([&bytes[..]]), payloads);
        assert_eq!(decode_pieces(bytes.chunks(1)), payloads);
    }

    #[test]
    fn a_split_at_any_byte_yields_the_same_frames() {
        let payloads = payloads();
        let (bytes, _) = stream(&payloads);
        for at in 0..=bytes.len() {
            let (head, tail) = bytes.split_at(at);
            assert_eq!(decode_pieces([head, tail]), payloads, "split at {at}");
        }
    }

    #[test]
    fn pieces_cut_at_every_prefix_and_payload_boundary_yield_the_same_frames() {
        let payloads = payloads();
        let (bytes, boundaries) = stream(&payloads);
        let pieces: Vec<&[u8]> = boundaries.windows(2).map(|w| &bytes[w[0]..w[1]]).collect();
        assert_eq!(decode_pieces(pieces), payloads);
        // And one byte either side of each boundary.
        for shift in [-1isize, 1] {
            let mut cuts: Vec<usize> = boundaries
                .iter()
                .map(|&b| b.saturating_add_signed(shift).min(bytes.len()))
                .collect();
            cuts.insert(0, 0);
            cuts.push(bytes.len());
            let pieces: Vec<&[u8]> = cuts.windows(2).map(|w| &bytes[w[0]..w[1]]).collect();
            assert_eq!(
                decode_pieces(pieces),
                payloads,
                "boundaries shifted {shift}"
            );
        }
    }

    #[test]
    fn several_frames_in_one_push_come_out_in_order() {
        let mut decoder = FrameDecoder::new(64);
        let mut bytes = Vec::new();
        for p in [&b"one"[..], b"two", b"three"] {
            bytes.extend(encode_frame(p).unwrap());
        }
        decoder.push(&bytes);
        assert_eq!(decoder.pop().unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(decoder.pop().unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(decoder.pop().unwrap().as_deref(), Some(&b"three"[..]));
        assert_eq!(decoder.pop().unwrap(), None);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn a_partial_frame_waits_for_the_rest() {
        let mut decoder = FrameDecoder::new(64);
        let bytes = encode_frame(b"hello").unwrap();
        decoder.push(&bytes[..6]);
        assert_eq!(decoder.pop().unwrap(), None);
        assert_eq!(decoder.buffered(), 6, "held, not dropped");
        decoder.push(&bytes[6..]);
        assert_eq!(decoder.pop().unwrap().as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn an_empty_frame_works() {
        assert_eq!(encode_frame(b"").unwrap(), [0, 0, 0, 0]);
        let mut decoder = FrameDecoder::new(0);
        decoder.push(&[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoder.pop().unwrap(), Some(Vec::new()));
        assert_eq!(decoder.pop().unwrap(), Some(Vec::new()));
        assert_eq!(decoder.pop().unwrap(), None);
    }

    #[test]
    fn an_oversized_declared_length_is_reported_without_allocating_it() {
        let mut decoder = FrameDecoder::new(1024);
        let declared = u32::MAX.to_be_bytes();
        decoder.push(&declared[..3]);
        assert_eq!(
            decoder.pop(),
            Ok(None),
            "not known until the prefix is whole"
        );
        decoder.push(&declared[3..]);
        let oversized = Err(FrameError::Oversized {
            len: MAX_FRAME_LEN,
            max: 1024,
        });
        assert_eq!(decoder.pop(), oversized, "refused at the prefix");
        assert!(
            decoder.buf.capacity() < 64,
            "nothing allocated for the declared length: capacity {}",
            decoder.buf.capacity()
        );
        decoder.push(b"more");
        assert_eq!(decoder.pop(), oversized, "no resynchronising past it");
    }

    #[test]
    fn a_declared_length_within_the_maximum_is_not_reserved_either() {
        let mut decoder = FrameDecoder::new(1 << 20);
        decoder.push(&(1u32 << 20).to_be_bytes());
        decoder.push(b"{");
        assert_eq!(decoder.pop(), Ok(None));
        assert!(
            decoder.buf.capacity() < 64,
            "only what arrived is held: capacity {}",
            decoder.buf.capacity()
        );
    }

    #[test]
    fn the_maximum_itself_is_accepted() {
        let mut decoder = FrameDecoder::new(8);
        decoder.push(&encode_frame(&[7; 8]).unwrap());
        assert_eq!(decoder.pop().unwrap(), Some(vec![7; 8]));
        decoder.push(&encode_frame(&[7; 9]).unwrap());
        assert_eq!(decoder.pop(), Err(FrameError::Oversized { len: 9, max: 8 }));
    }

    #[test]
    fn the_prefix_is_the_big_endian_length() {
        assert_eq!(encode_frame(b"hi").unwrap(), [0, 0, 0, 2, b'h', b'i']);
        assert_eq!(
            encode_frame(&[0; 300]).unwrap()[..PREFIX_LEN],
            [0, 0, 1, 44]
        );
        assert_eq!(prefix(MAX_FRAME_LEN), Ok([0xff; 4]));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_encoder_refuses_a_length_no_prefix_can_declare() {
        let err = prefix(MAX_FRAME_LEN + 1).unwrap_err();
        assert_eq!(
            err,
            FrameError::Oversized {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            }
        );
        assert_eq!(
            err.to_string(),
            "frame of 4294967296 bytes exceeds the 4294967295 byte limit"
        );
    }

    #[test]
    fn frames_left_waiting_across_pushes_come_out_in_order() {
        // One frame always waits while two go in and two come out, so each
        // push finds returned bytes to reclaim ahead of a waiting frame.
        let frame = |n: u32| encode_frame(&n.to_be_bytes()).unwrap();
        let mut decoder = FrameDecoder::new(64);
        decoder.push(&frame(0));
        let (mut sent, mut received) = (1u32, 0u32);
        for _ in 0..5_000 {
            decoder.push(&frame(sent));
            decoder.push(&frame(sent + 1));
            sent += 2;
            for _ in 0..2 {
                assert_eq!(
                    decoder.pop().unwrap(),
                    Some(received.to_be_bytes().to_vec())
                );
                received += 1;
            }
            assert!(
                decoder.buf.len() <= 4 * 8,
                "reclaimed as it goes: {} bytes held",
                decoder.buf.len()
            );
        }
        assert_eq!(
            decoder.pop().unwrap(),
            Some(received.to_be_bytes().to_vec())
        );
        assert_eq!(decoder.pop().unwrap(), None);
    }

    #[test]
    fn a_large_frame_does_not_leave_its_buffer_behind() {
        let mut decoder = FrameDecoder::new(1 << 20);
        decoder.push(&encode_frame(&vec![1; 200_000]).unwrap());
        assert_eq!(decoder.pop().unwrap().map(|f| f.len()), Some(200_000));
        assert!(
            decoder.buf.capacity() <= RETAINED_CAPACITY,
            "capacity {} kept after the frame",
            decoder.buf.capacity()
        );
    }
}
