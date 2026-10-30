// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What the link's encodings share: integers little-endian, a text as its
//! `u16` length and its UTF-8 bytes, a count of entries as a `u32`, and a
//! reader that refuses, rather than panics on, bytes that end early, run
//! on, or declare more than they hold.

/// Why bytes are not a control message or an interest summary. Decoding is
/// total: every input is either a value or one of these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// A message, or a field in one, is longer than its cap.
    #[error("{what} of {len} bytes is longer than the {max} bytes allowed")]
    TooLarge {
        /// What is too long.
        what: &'static str,
        /// Its length in bytes.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// The bytes end inside the field that starts at `at`, or before the
    /// entries a count there declares.
    #[error("the bytes end inside the field at byte {at}")]
    Truncated {
        /// Where the field starts.
        at: usize,
    },
    /// Bytes follow the end of the message.
    #[error("{extra} bytes follow the end of the message")]
    TrailingBytes {
        /// How many.
        extra: usize,
    },
    /// The encoding's version is not one this build reads.
    #[error("version {0} is not one this build reads")]
    UnknownVersion(u8),
    /// A control message's kind is not one this build knows.
    #[error("message kind {0} is not one this build knows")]
    UnknownKind(u8),
    /// An interest summary sets flag bits this build does not know.
    #[error("flags {0:#04x} set bits this build does not know")]
    UnknownFlags(u8),
    /// A health notice's state code is not one this build knows.
    #[error("health state {0} is not one this build knows")]
    UnknownState(u8),
    /// An announcement's part is not below its count of parts, or the count
    /// is 0 or above 64 (`MAX_ANNOUNCE_PARTS`).
    #[error("part {part} of {parts}: an announcement has 1 to 64 parts, numbered from 0")]
    BadPart {
        /// The part.
        part: u16,
        /// The count of parts.
        parts: u16,
    },
    /// A text field that starts at `at` is not UTF-8.
    #[error("the text at byte {at} is not UTF-8")]
    NotUtf8 {
        /// Where its bytes start.
        at: usize,
    },
    /// The bytes are well formed but not in the one form the encoding
    /// allows for their value, such as a set out of order; the reason says
    /// which rule they break.
    #[error("not canonical: {0}")]
    NotCanonical(&'static str),
}

/// Reads fields from the front of a byte slice.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let at = self.at;
        let slice = at
            .checked_add(n)
            .and_then(|end| self.bytes.get(at..end))
            .ok_or(CodecError::Truncated { at })?;
        self.at = at + n;
        Ok(slice)
    }

    /// The next `N` bytes, as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let at = self.at;
        self.take(N)?
            .try_into()
            .map_err(|_| CodecError::Truncated { at })
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
        self.array().map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        self.array().map(u64::from_le_bytes)
    }

    /// A count of entries each at least `min_entry` bytes long. A count the
    /// bytes left cannot hold is refused here, so nothing is allocated from
    /// a size the input declares.
    pub(crate) fn count(&mut self, min_entry: usize) -> Result<usize, CodecError> {
        let at = self.at;
        let count = usize::try_from(self.u32()?).map_err(|_| CodecError::Truncated { at })?;
        if count
            .checked_mul(min_entry)
            .is_none_or(|need| need > self.remaining())
        {
            return Err(CodecError::Truncated { at });
        }
        Ok(count)
    }

    /// A text of at most `max` bytes; `what` names it in a refusal.
    pub(crate) fn text(&mut self, what: &'static str, max: usize) -> Result<&'a str, CodecError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(CodecError::TooLarge { what, len, max });
        }
        let at = self.at;
        std::str::from_utf8(self.take(len)?).map_err(|_| CodecError::NotUtf8 { at })
    }

    /// The bytes not yet read.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    /// Refuse bytes after the end of the message.
    pub(crate) fn finish(&self) -> Result<(), CodecError> {
        match self.remaining() {
            0 => Ok(()),
            extra => Err(CodecError::TrailingBytes { extra }),
        }
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A count of entries. Every count written is held below `u32::MAX` by the
/// caps on what is encoded; were it not, the count would not match the
/// entries and the peer would refuse the message.
pub(crate) fn put_count(out: &mut Vec<u8>, count: usize) {
    put_u32(out, u32::try_from(count).unwrap_or(u32::MAX));
}

/// A text, its length first. Every text written is held far below
/// `u16::MAX` bytes when its value is made, so the length is exact.
pub(crate) fn put_text(out: &mut Vec<u8>, text: &str) {
    put_u16(out, u16::try_from(text.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn a_reader_refuses_what_runs_short_or_runs_on() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16(), Ok(0x0201));
        assert_eq!(r.u16(), Err(CodecError::Truncated { at: 2 }));
        assert_eq!(r.finish(), Err(CodecError::TrailingBytes { extra: 1 }));
        assert_eq!(r.u8(), Ok(3));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn a_count_the_bytes_cannot_hold_is_refused_before_anything_is_read() {
        let mut bytes = u32::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 6]);
        assert_eq!(
            Reader::new(&bytes).count(2),
            Err(CodecError::Truncated { at: 0 })
        );
        let mut bytes = 3u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 6]);
        assert_eq!(Reader::new(&bytes).count(2), Ok(3));
        assert_eq!(
            Reader::new(&bytes).count(3),
            Err(CodecError::Truncated { at: 0 })
        );
    }

    #[test]
    fn a_text_is_its_length_then_utf8() {
        let mut out = Vec::new();
        put_text(&mut out, "jobs/é");
        assert_eq!(out[..2], [7, 0]);
        assert_eq!(Reader::new(&out).text("a channel", 7), Ok("jobs/é"));
        assert_eq!(
            Reader::new(&out).text("a channel", 6),
            Err(CodecError::TooLarge {
                what: "a channel",
                len: 7,
                max: 6
            })
        );
        let bad = [1, 0, 0xff];
        assert_eq!(
            Reader::new(&bad).text("a channel", 7),
            Err(CodecError::NotUtf8 { at: 2 })
        );
    }
}
