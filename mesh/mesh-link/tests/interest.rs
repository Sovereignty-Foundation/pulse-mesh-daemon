// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The summary's guarantee, against the reference matcher in `common`: a
//! send that some filter of a set admits is one the set's summary may
//! match, before encoding, after a round trip through its bytes, and
//! coarsened. The summary may admit more; the peer matches exactly.
//!
//! Sends are drawn at random and also made from the filters themselves,
//! each glob filled in, so that the filters admit many of them; and every
//! short pattern is tried against every short text, one filter at a time.

mod common;

use common::{admits, instance};
use mesh_link::Interest;
use mesh_port_protocol::FilterSpec;
use proptest::prelude::*;

/// Patterns over a small alphabet, so that matches are common.
fn pattern() -> impl Strategy<Value = String> {
    "[ab/.*]{0,6}"
}

fn text() -> impl Strategy<Value = String> {
    "[ab/.]{0,6}"
}

const ORIGINS: [&str; 3] = ["w@0a0b0c0d", "w@0123456789abcdef", "x@0123456789abcdef"];

fn origin() -> impl Strategy<Value = String> {
    proptest::sample::select(&ORIGINS[..]).prop_map(str::to_owned)
}

fn filter() -> impl Strategy<Value = FilterSpec> {
    (
        proptest::option::of(pattern()),
        proptest::option::of(0u16..3),
        proptest::option::of(pattern()),
        proptest::option::of(origin()),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(channel, type_id, type_name, origin, health, snapshot)| FilterSpec {
                channel,
                type_id,
                type_name,
                origin,
                health,
                snapshot,
            },
        )
}

/// A send: its channel, type id, type name (`None` for none) and origin.
type Send = (String, u16, Option<String>, String);

fn send() -> impl Strategy<Value = Send> {
    (text(), 0u16..3, proptest::option::of(text()), origin())
}

/// A send that `filter` admits, made by filling in its globs; the fields
/// it does not set come from `fill`.
fn admitted_by(filter: &FilterSpec, mut seed: u64, fill: &Send) -> Send {
    let channel = match &filter.channel {
        Some(p) => instance(p, &mut seed),
        None => fill.0.clone(),
    };
    let mut type_name = match &filter.type_name {
        Some(p) => Some(instance(p, &mut seed)),
        None => fill.2.clone(),
    };
    // A send that names no type name is matched on its channel, so when the
    // type-name pattern matches the channel too, now and then name none.
    if let Some(p) = &filter.type_name {
        if seed.is_multiple_of(3) && common::glob(p, &channel) {
            type_name = None;
        }
    }
    (
        channel,
        filter.type_id.unwrap_or(fill.1),
        type_name,
        filter.origin.clone().unwrap_or_else(|| fill.3.clone()),
    )
}

fn check(filters: &[FilterSpec], sends: &[Send]) -> Result<(), TestCaseError> {
    let interest = Interest::from_filters(filters);
    let bytes = interest.encode();
    let decoded = Interest::decode(&bytes).unwrap();
    prop_assert_eq!(&decoded, &interest);
    prop_assert_eq!(decoded.encode(), bytes);
    let coarse = interest.coarsened(40);
    for (channel, type_id, type_name, origin) in sends {
        let type_name = type_name.as_deref();
        let admitted = filters
            .iter()
            .any(|f| admits(f, channel, *type_id, type_name, origin));
        if admitted {
            for summary in [&interest, &decoded, &coarse] {
                prop_assert!(
                    summary.may_match(channel, *type_id, type_name),
                    "{:?} refused {:?} that {:?} admit",
                    summary,
                    (channel, type_id, type_name, origin),
                    filters
                );
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn a_summary_never_refuses_a_send_a_filter_admits(
        filters in proptest::collection::vec(filter(), 0..6),
        random in proptest::collection::vec(send(), 0..12),
        seeds in proptest::collection::vec(1u64.., 6),
    ) {
        let mut sends = random.clone();
        let fill = random.first().cloned().unwrap_or_default();
        for (f, &seed) in filters.iter().zip(&seeds) {
            let made = admitted_by(f, seed, &fill);
            prop_assert!(
                admits(f, &made.0, made.1, made.2.as_deref(), &made.3),
                "the generator made {:?}, which {:?} does not admit", made, f
            );
            sends.push(made);
        }
        check(&filters, &sends)?;
    }

    /// A relay's union of two summaries is the summary of their filters
    /// together, and so never refuses a send either set admits.
    #[test]
    fn a_union_of_summaries_is_the_summary_of_the_filters_together(
        left in proptest::collection::vec(filter(), 0..5),
        right in proptest::collection::vec(filter(), 0..5),
        sends in proptest::collection::vec(send(), 0..12),
    ) {
        let union = Interest::from_filters(&left).union(&Interest::from_filters(&right));
        let together: Vec<FilterSpec> = left.iter().chain(&right).cloned().collect();
        prop_assert_eq!(&union, &Interest::from_filters(&together));
        check(&together, &sends)?;
    }

    #[test]
    fn the_summary_is_the_same_whatever_the_filters_order(
        filters in proptest::collection::vec(filter(), 0..8),
    ) {
        let mut reversed = filters.clone();
        reversed.reverse();
        prop_assert_eq!(Interest::from_filters(&filters), Interest::from_filters(&reversed));
    }
}

/// Every string over `alphabet` of at most `max` bytes.
fn strings(alphabet: &str, max: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut layer = vec![String::new()];
    for _ in 0..max {
        layer = layer
            .iter()
            .flat_map(|s| alphabet.chars().map(move |c| format!("{s}{c}")))
            .collect();
        all.extend(layer.iter().cloned());
    }
    all
}

#[test]
fn every_short_pattern_and_text_one_filter_at_a_time() {
    let texts = strings("ab/", 4);
    for pattern in strings("a/*", 4) {
        let filters = [
            FilterSpec {
                channel: Some(pattern.clone()),
                ..FilterSpec::default()
            },
            FilterSpec {
                type_name: Some(pattern.clone()),
                ..FilterSpec::default()
            },
        ];
        for filter in &filters {
            let interest = Interest::from_filters(std::slice::from_ref(filter));
            for channel in &texts {
                for type_name in std::iter::once(None).chain(texts.iter().map(|t| Some(t.as_str())))
                {
                    if admits(filter, channel, 0, type_name, "o@0a0b0c0d") {
                        assert!(
                            interest.may_match(channel, 0, type_name),
                            "{filter:?} admits {channel:?} / {type_name:?}, its summary refuses it"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn a_summary_of_exact_filters_refuses_what_they_refuse() {
    let filters = [
        FilterSpec {
            channel: Some("jobs/new".into()),
            ..FilterSpec::default()
        },
        FilterSpec {
            channel: Some("metrics/*".into()),
            type_id: Some(3),
            ..FilterSpec::default()
        },
    ];
    let interest = Interest::from_filters(&filters);
    for (channel, admitted) in [
        ("jobs/new", true),
        ("jobs/old", false),
        ("metrics/cpu", true),
        ("metrics/cpu/0", true),
        ("metric", false),
        ("other", false),
    ] {
        assert_eq!(interest.may_match(channel, 0, None), admitted, "{channel}");
    }
}
