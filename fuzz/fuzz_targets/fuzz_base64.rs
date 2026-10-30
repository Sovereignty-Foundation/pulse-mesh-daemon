// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `mesh_port_protocol::base64`, the strict codec of the
// payload that `send` and `event` carry.
//
// The oracle is a second codec, written here from RFC 4648 rather than
// from the crate: section 4's alphabet, built from the RFC's table as
// ranges of values, and its encoding, which reads the input as a string of
// bits, six at a time, padding the last group with zero bits and the text
// with `=` to a whole number of four-character quanta. Decoding is the
// RFC's, made strict as the crate documents it (section 3.3 and 3.5 leave
// both to the application): the length must be a multiple of four, the
// padding is the one or two `=` that end the text, every other byte must be
// in the alphabet, and the bits the padding marks as unused must be zero.
// A text with several faults is refused for its length first and then for
// its first faulty byte, and the refusal names what the crate's error type
// says it names.
//
// Invariants:
// - `encode` of any bytes is exactly the RFC's text for them, and decodes
//   back to them;
// - `decode` of any text accepts exactly the texts the oracle accepts, with
//   the same bytes, and refuses every other one with the oracle's error:
//   the same variant, offset and byte.
//
// The text decoded is the input itself, or now and then an encoding of the
// input with a few bytes changed, dropped or added, which keeps the decoder
// among texts that are nearly valid.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_port_protocol::base64::{self, Base64Error};

fuzz_target!(|data: &[u8]| {
    let encoded = base64::encode(data);
    assert_eq!(encoded, rfc4648::encode(data), "encode is not RFC 4648");
    assert_eq!(
        base64::decode(&encoded).as_deref(),
        Ok(data),
        "an encoding does not decode back"
    );

    // The decoder takes text; bytes that are not UTF-8 still make text.
    let text = match data.split_first() {
        Some((&mode, rest)) if mode % 4 == 0 => near_valid(rest),
        _ => String::from_utf8_lossy(data).into_owned(),
    };
    assert_eq!(
        base64::decode(&text),
        rfc4648::decode(text.as_bytes()),
        "decode of {text:?} is not RFC 4648's strict decoding"
    );
});

/// The RFC's text for the first part of `rest`, with the edits the rest of
/// it asks for: each three bytes put a byte at, or insert one before, or
/// remove, the position they name.
fn near_valid(rest: &[u8]) -> String {
    let split = rest.len() / 2;
    let (bytes, edits) = rest.split_at(split);
    let mut text = rfc4648::encode(bytes).into_bytes();
    for edit in edits.chunks_exact(3) {
        let at = usize::from(edit[1]) % (text.len() + 1);
        match edit[0] % 3 {
            0 if at < text.len() => text[at] = edit[2],
            1 => text.insert(at, edit[2]),
            _ if at < text.len() => {
                text.remove(at);
            }
            _ => text.push(edit[2]),
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}

/// Base64 as RFC 4648 section 4 defines it, for the oracle.
mod rfc4648 {
    use super::Base64Error;

    /// The pad character, section 4.
    const PAD: u8 = b'=';

    /// Table 1 of section 4, value to symbol: 0 to 25 are `A` to `Z`, 26
    /// to 51 are `a` to `z`, 52 to 61 are `0` to `9`, 62 is `+` and 63 is
    /// `/`.
    fn symbol(value: u8) -> u8 {
        match value {
            0..=25 => b'A' + value,
            26..=51 => b'a' + (value - 26),
            52..=61 => b'0' + (value - 52),
            62 => b'+',
            63 => b'/',
            _ => unreachable!("a six-bit value"),
        }
    }

    /// Table 1 read the other way: the value whose symbol is `byte`, found
    /// by looking through the table.
    fn value(byte: u8) -> Option<u8> {
        (0..64u8).find(|&v| symbol(v) == byte)
    }

    /// The input as a string of bits, most significant first, six at a
    /// time; the last group filled out with zero bits; then `=` until the
    /// text is a whole number of four-character quanta.
    pub fn encode(bytes: &[u8]) -> String {
        let bits: Vec<bool> = bytes
            .iter()
            .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
            .collect();
        let mut text: Vec<u8> = bits
            .chunks(6)
            .map(|group| {
                let value =
                    (0..6).fold(0u8, |v, i| (v << 1) | u8::from(group.get(i) == Some(&true)));
                symbol(value)
            })
            .collect();
        while !text.len().is_multiple_of(4) {
            text.push(PAD);
        }
        String::from_utf8(text).expect("the alphabet is ASCII")
    }

    /// Strict decoding: the length first, then the first byte that is not
    /// a symbol of the alphabet outside the final padding, then the unused
    /// bits the padding marks.
    pub fn decode(text: &[u8]) -> Result<Vec<u8>, Base64Error> {
        if !text.len().is_multiple_of(4) {
            return Err(Base64Error::Length { len: text.len() });
        }
        // The final padding: the `=` that end the text, one or two of them;
        // an `=` before those is in the body, where it does not belong.
        let run = text.iter().rev().take_while(|&&b| b == PAD).count();
        let pad = run.min(2);
        let body = &text[..text.len() - pad];
        let mut values = Vec::with_capacity(body.len());
        for (offset, &byte) in body.iter().enumerate() {
            match value(byte) {
                Some(v) => values.push(v),
                None if byte == PAD => return Err(Base64Error::Padding { offset }),
                None => return Err(Base64Error::InvalidByte { offset, byte }),
            }
        }
        // Six bits a symbol, most significant first; eight bits a byte. The
        // bits after the last whole byte are the ones the padding marks
        // unused: four after two symbols, two after three, none after four.
        let bits: Vec<bool> = values
            .iter()
            .flat_map(|&v| (0..6).rev().map(move |i| (v >> i) & 1 == 1))
            .collect();
        let whole = bits.len() / 8 * 8;
        if bits[whole..].iter().any(|&bit| bit) {
            return Err(Base64Error::TrailingBits {
                offset: body.len() - 1,
            });
        }
        Ok(bits[..whole]
            .chunks(8)
            .map(|byte| byte.iter().fold(0u8, |b, &bit| (b << 1) | u8::from(bit)))
            .collect())
    }
}
