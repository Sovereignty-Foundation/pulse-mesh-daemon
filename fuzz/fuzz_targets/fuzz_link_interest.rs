// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `mesh_link::Interest::decode`, the interest summary a peer
// daemon sends over a link, and `Interest::from_filters`, which makes one
// from a daemon's subscriptions.
//
// The first byte of the input picks the mode. Even: the rest is bytes a
// peer sent, and they are decoded. Odd: the rest draws subscription
// filters, over a small alphabet with `*` and `/` or as any text, some
// longer than a summary's texts may be; their summary is made, encoded and
// decoded.
//
// Invariants:
// - decoding is total: any bytes give a summary or an error, never a panic
//   or an allocation from a size the input declares (the harness's malloc
//   limit stands guard);
// - a decoded summary re-encodes to exactly the bytes it was read from, and
//   `encoded_len` is their length;
// - a decoded summary admits the channels and type names it lists and the
//   type ids it holds, and coarsening it gives a summary that decodes to
//   itself and admits whatever the first admits;
// - a summary made from any filters encodes within MAX_INTEREST_BYTES and
//   decodes to itself;
// - it admits every send a filter of exact texts admits, whatever the
//   filter's texts' lengths: the filters' own channel, type id and type
//   name.

#![no_main]

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_link::{Interest, MAX_INTEREST_BYTES};
use mesh_port_protocol::FilterSpec;
use pulse_mesh_fuzz::take;

/// Most filters drawn from one input.
const MAX_FILTERS: usize = 64;
/// The alphabet of drawn patterns, so globs and prefixes meet.
const ALPHABET: [char; 6] = ['a', 'b', '/', '*', '.', 'é'];

fuzz_target!(|input: &[u8]| {
    let Some((&mode, rest)) = input.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        decoded(rest);
    } else {
        let _ = made(&mut Unstructured::new(rest));
    }
});

fn decoded(bytes: &[u8]) {
    let Ok(interest) = Interest::decode(bytes) else {
        return;
    };
    assert_eq!(
        interest.encode(),
        bytes,
        "a decoded summary does not re-encode to its bytes"
    );
    assert_eq!(interest.encoded_len(), bytes.len());
    for channel in interest.exact_channels().chain(interest.channel_prefixes()) {
        assert!(
            interest.may_match(channel, 0, None),
            "{channel:?} is listed and refused"
        );
    }
    for type_name in interest
        .exact_type_names()
        .chain(interest.type_name_prefixes())
    {
        assert!(
            interest.may_match("", 0, Some(type_name)),
            "{type_name:?} is listed and refused"
        );
    }
    for type_id in interest.type_ids() {
        assert!(
            interest.may_match("", type_id, None),
            "type id {type_id} is held and refused"
        );
    }
    let coarse = interest.coarsened(bytes.len() / 2);
    assert_eq!(Interest::decode(&coarse.encode()).as_ref(), Ok(&coarse));
    let texts: Vec<&str> = interest
        .exact_channels()
        .chain(interest.channel_prefixes())
        .chain(interest.exact_type_names())
        .chain(interest.type_name_prefixes())
        .chain(["", "a", "a/b"])
        .collect();
    for channel in &texts {
        for type_name in [None, Some("a"), Some(*channel)] {
            for type_id in [0, 1, u16::MAX] {
                if interest.may_match(channel, type_id, type_name) {
                    assert!(
                        coarse.may_match(channel, type_id, type_name),
                        "coarsening refused what the summary admits"
                    );
                }
            }
        }
    }
}

fn made(u: &mut Unstructured<'_>) -> Result<()> {
    let mut filters = Vec::new();
    while !u.is_empty() && filters.len() < MAX_FILTERS {
        filters.push(FilterSpec {
            channel: text(u)?,
            type_id: if u.arbitrary()? {
                Some(u.arbitrary()?)
            } else {
                None
            },
            type_name: text(u)?,
            origin: None,
            health: u.arbitrary()?,
            snapshot: false,
        });
    }
    let interest = Interest::from_filters(&filters);
    let bytes = interest.encode();
    assert!(
        bytes.len() <= MAX_INTEREST_BYTES,
        "a made summary is past the cap"
    );
    assert_eq!(Interest::decode(&bytes).as_ref(), Ok(&interest));
    for filter in &filters {
        let exact = |p: &Option<String>| p.as_deref().is_none_or(|p| !p.contains('*'));
        if !(exact(&filter.channel) && exact(&filter.type_name)) {
            continue;
        }
        // The send the filter admits: its channel (any, when it names
        // none), its type id and its type name.
        let channel = filter.channel.as_deref().unwrap_or("any");
        let type_name = filter.type_name.as_deref();
        assert!(
            interest.may_match(channel, filter.type_id.unwrap_or(0), type_name),
            "the summary refused a send {filter:?} admits"
        );
    }
    Ok(())
}

/// A pattern, or none: text over the small alphabet, or any text.
fn text(u: &mut Unstructured<'_>) -> Result<Option<String>> {
    if !u.arbitrary::<bool>()? {
        return Ok(None);
    }
    let small = u.arbitrary::<bool>()?;
    let bytes = take(u, 300)?;
    Ok(Some(if small {
        bytes
            .iter()
            .map(|&b| ALPHABET[usize::from(b) % ALPHABET.len()])
            .collect()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }))
}
