// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Base64 as the port protocol carries it, in the `payload` of `send` and
//! `event`: RFC 4648 §4's standard alphabet, padded with `=` to a multiple of
//! four characters, and nothing else.
//!
//! [`decode`] refuses every other form, so each byte string has exactly one
//! text: `decode(&encode(b))` is `Ok(b)`, and when `decode(t)` is `Ok(b)`,
//! `encode(&b)` is `t` (checked by the tests below and `fuzz_base64`). Python's
//! `base64.b64encode`, Node's `Buffer.toString('base64')` and `btoa` all write
//! this form.
//!
//! ```
//! use mesh_port_protocol::base64;
//!
//! assert_eq!(base64::encode(b"hello"), "aGVsbG8=");
//! assert_eq!(base64::decode("aGVsbG8=")?, b"hello");
//! assert!(base64::decode("aGVsbG8").is_err(), "the padding is required");
//! # Ok::<(), base64::Base64Error>(())
//! ```

/// The standard alphabet, indexed by the value of a 6-bit group.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The padding character.
const PAD: u8 = b'=';

/// Why [`decode`] refused a text: its length first, then its first faulty byte,
/// at its offset in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base64Error {
    /// The length is not a multiple of four.
    Length {
        /// The text's length in bytes.
        len: usize,
    },
    /// A byte outside the standard alphabet, whitespace and the URL-safe `-`
    /// and `_` included.
    InvalidByte {
        /// Where the byte is.
        offset: usize,
        /// The byte.
        byte: u8,
    },
    /// A `=` other than the one or two that end the text.
    Padding {
        /// Where the misplaced `=` is.
        offset: usize,
    },
    /// The symbol before the padding sets bits that carry no data, which no
    /// encoder writes.
    TrailingBits {
        /// Where the symbol is.
        offset: usize,
    },
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Length { len } => write!(f, "length {len} is not a multiple of four"),
            Self::InvalidByte { offset, byte } if byte.is_ascii_whitespace() => {
                write!(f, "whitespace (0x{byte:02x}) at offset {offset}")
            }
            Self::InvalidByte { offset, byte } => write!(
                f,
                "byte 0x{byte:02x} at offset {offset} is not in the standard alphabet"
            ),
            Self::Padding { offset } => write!(
                f,
                "`=` at offset {offset}: padding is one or two `=` at the end"
            ),
            Self::TrailingBits { offset } => write!(
                f,
                "the symbol at offset {offset}, before the padding, sets unused bits"
            ),
        }
    }
}

impl std::error::Error for Base64Error {}

/// Encode `bytes` in the standard alphabet, padded to a multiple of four
/// characters.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut groups = bytes.chunks_exact(3);
    for group in &mut groups {
        let n = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        push_symbols(&mut out, n, 4);
    }
    match *groups.remainder() {
        [a] => {
            push_symbols(&mut out, u32::from(a) << 16, 2);
            out.push_str("==");
        }
        [a, b] => {
            push_symbols(&mut out, (u32::from(a) << 16) | (u32::from(b) << 8), 3);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Push the first `count` symbols of the 24-bit group `n`, most significant
/// first.
fn push_symbols(out: &mut String, n: u32, count: usize) {
    for shift in [18u32, 12, 6, 0].into_iter().take(count) {
        out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
    }
}

/// The value of one symbol of the standard alphabet.
const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode a text in the one form the [module](self) describes.
///
/// # Errors
///
/// A [`Base64Error`] for any other text.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Base64Error::Length { len: bytes.len() });
    }
    // Any other `=` is refused below as a misplaced symbol.
    let padding = bytes
        .iter()
        .rev()
        .take(2)
        .take_while(|&&b| b == PAD)
        .count();
    let symbols = &bytes[..bytes.len() - padding];
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3 + 2);
    // Bits read and not yet written out: `held` of them, at most 12, in
    // the low end of `bits`.
    let (mut bits, mut held) = (0u32, 0u32);
    for (offset, &byte) in symbols.iter().enumerate() {
        let Some(value) = sextet(byte) else {
            return Err(if byte == PAD {
                Base64Error::Padding { offset }
            } else {
                Base64Error::InvalidByte { offset, byte }
            });
        };
        bits = (bits << 6) | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    // What is left is the last symbol's unused bits.
    if bits != 0 {
        return Err(Base64Error::TrailingBits {
            offset: symbols.len().saturating_sub(1),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A deterministic byte stream (xorshift64), so a failure reproduces.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn matches_the_rfc_4648_vectors() {
        for (plain, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("hello", "aGVsbG8="),
        ] {
            assert_eq!(encode(plain.as_bytes()), text);
            assert_eq!(decode(text).unwrap(), plain.as_bytes(), "{text}");
        }
    }

    #[test]
    fn round_trips_every_length_from_0_to_64() {
        for len in 0..=64usize {
            for bytes in [vec![0x00; len], vec![0xff; len], noise(len as u64, len)] {
                let text = encode(&bytes);
                assert_eq!(text.len(), len.div_ceil(3) * 4, "length {len}");
                assert_eq!(
                    text.bytes().filter(|&b| b == PAD).count(),
                    (3 - len % 3) % 3,
                    "padding for length {len}"
                );
                assert_eq!(decode(&text).unwrap(), bytes, "length {len}");
            }
        }
    }

    #[test]
    fn round_trips_arbitrary_buffers() {
        let mut buffers: Vec<Vec<u8>> = [65, 100, 255, 256, 257, 1000, 4097, 65_521]
            .into_iter()
            .zip(100u64..)
            .map(|(len, seed)| noise(seed, len))
            .collect();
        buffers.push((0..=255).collect());
        buffers.push((0..=255).rev().collect());
        for bytes in buffers {
            let text = encode(&bytes);
            assert_eq!(decode(&text).unwrap(), bytes, "{} bytes", bytes.len());
            assert_eq!(encode(&decode(&text).unwrap()), text);
        }
    }

    #[test]
    fn a_padded_quantum_has_exactly_one_text_per_byte_string() {
        // Every text of two symbols and `==`, and of three symbols and `=`:
        // exactly one per byte string is accepted, and it is the encoder's.
        let mut text = [PAD; 4];
        let mut accepted = 0;
        for &a in ALPHABET {
            for &b in ALPHABET {
                text[0] = a;
                text[1] = b;
                let t = std::str::from_utf8(&text).unwrap();
                if let Ok(bytes) = decode(t) {
                    assert_eq!(encode(&bytes), t);
                    accepted += 1;
                }
            }
        }
        assert_eq!(accepted, 256, "one text per byte");
        let mut accepted = 0;
        for &a in ALPHABET {
            for &b in ALPHABET {
                for &c in ALPHABET {
                    text[..3].copy_from_slice(&[a, b, c]);
                    let t = std::str::from_utf8(&text).unwrap();
                    if let Ok(bytes) = decode(t) {
                        assert_eq!(encode(&bytes), t);
                        accepted += 1;
                    }
                }
            }
        }
        assert_eq!(accepted, 65_536, "one text per pair of bytes");
    }

    #[test]
    fn refuses_padding_in_mid_string() {
        for (text, offset) in [
            ("AA==AA==", 2),
            ("Zg==Zg==", 2),
            ("Zm8=Zm8=", 3),
            ("AA=A", 2),
            ("=AAA", 0),
            ("AAAA=AAA", 4),
        ] {
            assert_eq!(decode(text), Err(Base64Error::Padding { offset }), "{text}");
        }
    }

    #[test]
    fn refuses_a_length_that_is_not_a_multiple_of_four() {
        for text in [
            "A", "Zg", "Zg=", "Zm9", "Zm9vY", "Zm9vYg=", "Zg===", "aGVsbG8",
        ] {
            assert_eq!(
                decode(text),
                Err(Base64Error::Length { len: text.len() }),
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_more_padding_than_the_length_needs() {
        for (text, offset) in [("A===", 1), ("====", 0), ("AAAA====", 4), ("AAAAA===", 5)] {
            assert_eq!(decode(text), Err(Base64Error::Padding { offset }), "{text}");
        }
    }

    #[test]
    fn refuses_whitespace() {
        for (text, offset, byte) in [
            (" Zg=", 0, b' '),
            ("Zm\r\nYmFy", 2, b'\r'),
            ("Zm9v\tZg=", 4, b'\t'),
            ("Zm9vYmF\n", 7, b'\n'),
        ] {
            assert_eq!(
                decode(text),
                Err(Base64Error::InvalidByte { offset, byte }),
                "{text:?}"
            );
        }
        // What a MIME encoder writes (Python's `base64.encodebytes`): a
        // line break after the text, and after every 76 characters.
        assert!(decode("aGVsbG8=\n").is_err());
        let long = encode(&noise(7, 60));
        assert!(decode(&format!("{}\n{}\n", &long[..76], &long[76..])).is_err());
    }

    #[test]
    fn refuses_bytes_outside_the_standard_alphabet() {
        for (text, offset, byte) in [
            ("Zm-v", 2, b'-'),
            ("Zm_v", 2, b'_'),
            ("Zm9*", 3, b'*'),
            ("\0AAA", 0, 0),
            ("Zm\u{e9}", 2, 0xc3),
        ] {
            assert_eq!(
                decode(text),
                Err(Base64Error::InvalidByte { offset, byte }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn refuses_bits_set_after_the_last_byte() {
        // "f" is "Zg==" and "fo" is "Zm8="; with a low bit set, a lenient
        // decoder reads the same bytes from a second text.
        for (text, offset) in [
            ("Zh==", 1),
            ("Zm9=", 2),
            ("AB==", 1),
            ("AAB=", 2),
            ("Zm9vZh==", 5),
        ] {
            assert_eq!(
                decode(text),
                Err(Base64Error::TrailingBits { offset }),
                "{text}"
            );
        }
    }

    #[test]
    fn errors_say_what_and_where() {
        assert_eq!(
            decode("Zm-v").unwrap_err().to_string(),
            "byte 0x2d at offset 2 is not in the standard alphabet"
        );
        assert_eq!(
            decode("Zm\r\nYmFy").unwrap_err().to_string(),
            "whitespace (0x0d) at offset 2"
        );
        assert_eq!(
            decode("AA==AA==").unwrap_err().to_string(),
            "`=` at offset 2: padding is one or two `=` at the end"
        );
    }
}
