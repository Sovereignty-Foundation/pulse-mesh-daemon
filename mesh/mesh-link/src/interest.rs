// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Interest summaries (ADR-0021, item 4) and their encoding.

use std::collections::BTreeSet;
use std::ops::Bound;

use mesh_port_protocol::{FilterSpec, MAX_PATTERN_LEN};

use crate::codec::{self, Reader};
use crate::{CodecError, MAX_INTEREST_BYTES};

/// The version of [`Interest`]'s encoding this build writes and reads.
pub const INTEREST_VERSION: u8 = 1;

/// Flag bit: the summary admits every send.
const EVERYTHING: u8 = 1 << 0;
/// Flag bit: a subscriber watches health.
const HEALTH: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = EVERYTHING | HEALTH;
/// The version, the generation, the flags and the five counts.
const FIXED_BYTES: usize = 1 + 8 + 1 + 5 * 4;

/// What a daemon's subscribers ask for, as its peers forward by: a summary
/// of its subscriptions' filters that may admit a send no filter takes, and
/// never refuses one that a filter does take.
///
/// # What a filter adds
///
/// A filter ([`FilterSpec`]) admits a send when each field it sets matches
/// (`mesh-hub`'s `filter.rs`): the channel and the type name as exact text
/// or as a glob, in which `*` matches a run of bytes other than `/` and
/// `**` any run; the type id exactly; the origin exactly. A send that names
/// no type name is matched on its channel there, and here. Each filter adds
/// to the summary one condition that every send it admits meets, the first
/// of these that it sets:
///
/// 1. an exact channel: the channel is that text;
/// 2. an exact type name: the type name is that text;
/// 3. a channel glob that does not start with `*`: the channel starts with
///    the literal text before the glob's first `*`, since every byte of it
///    must match itself;
/// 4. a type-name glob that does not start with `*`, likewise;
/// 5. a type id: the type id is that one.
///
/// A filter that sets none of them, its channel and type name each absent
/// or a glob that starts with `*` and its type id absent, makes the summary
/// admit everything. So do a filter whose only field is its origin and one
/// that only asks for health: neither narrows the envelopes it takes (an
/// absent field admits everything), and a summary does not carry origins. A filter that asks
/// for health also sets [`Interest::wants_health`], so the peer sends the
/// states of its nodes. The `snapshot` flag is reserved and changes
/// nothing.
///
/// The order is a choice of which condition narrows most, and only decides
/// how many sends are admitted that no filter takes; any choice is sound,
/// since each condition is one the filter's own match requires. A text
/// longer than [`MAX_PATTERN_LEN`] bytes, which the daemon refuses at
/// subscribe, is cut to its first bytes and kept as a prefix, which admits
/// more and refuses nothing the whole text would admit.
///
/// [`Interest::may_match`] admits a send when it meets one condition the
/// summary holds. Each filter that admits the send added a condition that
/// the send meets, so a send that some filter admits is admitted. That is
/// the guarantee, and the property tests check it against an independent
/// glob matcher.
///
/// # Normal form
///
/// A summary is held, and encoded, in one form for its conditions: the
/// sets sorted, no prefix starting with another prefix of its set, no exact
/// text that a prefix of its set admits, no empty prefix, no `*` in any
/// text, and no set filled when the summary admits everything. A form that
/// breaks one of these is refused on decode, so decoding and encoding are
/// inverses. A summary whose encoding would pass [`MAX_INTEREST_BYTES`] is
/// replaced, when it is made, by one that admits everything.
///
/// # Encoding
///
/// Version 1, integers little-endian:
///
/// ```text
/// u8   version (1)
/// u64  generation
/// u8   flags: bit 0 admits everything, bit 1 wants health; others zero
/// u32  count, then each type id as a u16, ascending
/// then four sets, in this order: exact channels, channel prefixes,
/// exact type names, type-name prefixes; each one
///   u32  count, then each text as a u16 length and its UTF-8 bytes,
///        ascending by bytes, each at most MAX_PATTERN_LEN (256) bytes
/// ```
///
/// The generation is the sender's count of summaries ([`SummaryPacer`]
/// sets it), so a receiver keeps the newest of summaries that arrive out
/// of order ([`Router::update_interest`]).
///
/// [`SummaryPacer`]: crate::SummaryPacer
/// [`Router::update_interest`]: crate::Router::update_interest
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Interest {
    generation: u64,
    everything: bool,
    health: bool,
    type_ids: BTreeSet<u16>,
    channels: BTreeSet<String>,
    channel_prefixes: BTreeSet<String>,
    type_names: BTreeSet<String>,
    type_name_prefixes: BTreeSet<String>,
}

/// What one field of a filter requires of a send.
enum Condition<'a> {
    /// The text is this.
    Exact(&'a str),
    /// The text starts with this, which is not empty.
    Prefix(&'a str),
    /// Nothing: the field is absent, or a glob that starts with `*`.
    Any,
}

impl<'a> Condition<'a> {
    fn of(pattern: Option<&'a str>) -> Self {
        let Some(pattern) = pattern else {
            return Self::Any;
        };
        match pattern.find('*') {
            None => Self::Exact(pattern),
            Some(0) => Self::Any,
            Some(star) => Self::Prefix(&pattern[..star]),
        }
    }
}

impl Interest {
    /// The summary of no subscriptions: it admits no send. A peer is held
    /// at this until its first summary arrives.
    #[must_use]
    pub fn nothing() -> Self {
        Self::default()
    }

    /// A summary that admits every send.
    #[must_use]
    pub fn everything() -> Self {
        Self {
            everything: true,
            ..Self::default()
        }
    }

    /// The summary of `filters`, at generation 0.
    #[must_use]
    pub fn from_filters<'a, I>(filters: I) -> Self
    where
        I: IntoIterator<Item = &'a FilterSpec>,
    {
        let mut interest = Self::nothing();
        for filter in filters {
            interest.health |= filter.health;
            interest.add(filter);
        }
        interest.normalize();
        interest.coarsened(MAX_INTEREST_BYTES)
    }

    /// Add the condition `filter` requires (the type's docs give the
    /// order).
    fn add(&mut self, filter: &FilterSpec) {
        if self.everything {
            return;
        }
        let channel = Condition::of(filter.channel.as_deref());
        let type_name = Condition::of(filter.type_name.as_deref());
        match (channel, type_name, filter.type_id) {
            (Condition::Exact(text), _, _) => {
                insert_exact(&mut self.channels, &mut self.channel_prefixes, text);
            }
            (_, Condition::Exact(text), _) => {
                insert_exact(&mut self.type_names, &mut self.type_name_prefixes, text);
            }
            (Condition::Prefix(prefix), _, _) => {
                self.channel_prefixes.insert(clip(prefix).to_owned());
            }
            (_, Condition::Prefix(prefix), _) => {
                self.type_name_prefixes.insert(clip(prefix).to_owned());
            }
            (_, _, Some(type_id)) => {
                self.type_ids.insert(type_id);
            }
            _ => self.everything = true,
        }
    }

    /// Bring the conditions to normal form, which admits the same sends.
    fn normalize(&mut self) {
        if self.everything {
            *self = Self {
                generation: self.generation,
                health: self.health,
                ..Self::everything()
            };
            return;
        }
        prefix_free(&mut self.channel_prefixes);
        prefix_free(&mut self.type_name_prefixes);
        let channel_prefixes = &self.channel_prefixes;
        self.channels.retain(|c| !covered(channel_prefixes, c));
        let type_name_prefixes = &self.type_name_prefixes;
        self.type_names.retain(|t| !covered(type_name_prefixes, t));
    }

    /// The same summary at `generation`.
    #[must_use]
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// The summary itself when its encoding is at most `max_bytes` long,
    /// and otherwise one that admits everything, at the same generation and
    /// with the same health flag. That one encodes in 30 bytes, whatever
    /// `max_bytes` asks. A link sends a summary to fit its frame this way:
    /// admitting more is always sound.
    #[must_use]
    pub fn coarsened(&self, max_bytes: usize) -> Self {
        if self.encoded_len() <= max_bytes {
            return self.clone();
        }
        Self {
            generation: self.generation,
            health: self.health,
            ..Self::everything()
        }
    }

    /// The summary that admits every send that `self` or `other` admits,
    /// and watches health when either does: their conditions together, in
    /// normal form, at generation 0. Like a summary made from filters, one
    /// whose encoding would pass [`MAX_INTEREST_BYTES`] is replaced by one
    /// that admits everything. The union of two summaries of filters is the
    /// summary of the filters together, unless one of them was coarsened. A
    /// relay summarises its subscribers and its other peers' summaries this
    /// way ([`Router::summary_for`]).
    ///
    /// [`Router::summary_for`]: crate::Router::summary_for
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let both = |a: &BTreeSet<String>, b: &BTreeSet<String>| a.union(b).cloned().collect();
        let mut union = Self {
            generation: 0,
            everything: self.everything || other.everything,
            health: self.health || other.health,
            type_ids: self.type_ids.union(&other.type_ids).copied().collect(),
            channels: both(&self.channels, &other.channels),
            channel_prefixes: both(&self.channel_prefixes, &other.channel_prefixes),
            type_names: both(&self.type_names, &other.type_names),
            type_name_prefixes: both(&self.type_name_prefixes, &other.type_name_prefixes),
        };
        union.normalize();
        union.coarsened(MAX_INTEREST_BYTES)
    }

    /// Whether a send may match a subscription the summary was made from:
    /// false only when none matches. `type_name` is the send's type name,
    /// or `None` when it names none, and the channel stands for it then, as
    /// it does in the daemon's own matching.
    #[must_use]
    pub fn may_match(&self, channel: &str, type_id: u16, type_name: Option<&str>) -> bool {
        if self.everything {
            return true;
        }
        let type_name = type_name.unwrap_or(channel);
        self.channels.contains(channel)
            || covered(&self.channel_prefixes, channel)
            || self.type_names.contains(type_name)
            || covered(&self.type_name_prefixes, type_name)
            || self.type_ids.contains(&type_id)
    }

    /// The sender's count of summaries when it sent this one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the summary admits every send.
    #[must_use]
    pub fn matches_everything(&self) -> bool {
        self.everything
    }

    /// Whether a subscriber watches health, so the peer should send the
    /// states of its nodes.
    #[must_use]
    pub fn wants_health(&self) -> bool {
        self.health
    }

    /// The exact channels, ascending.
    pub fn exact_channels(&self) -> impl Iterator<Item = &str> + '_ {
        self.channels.iter().map(String::as_str)
    }

    /// The channel prefixes, ascending.
    pub fn channel_prefixes(&self) -> impl Iterator<Item = &str> + '_ {
        self.channel_prefixes.iter().map(String::as_str)
    }

    /// The exact type names, ascending.
    pub fn exact_type_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.type_names.iter().map(String::as_str)
    }

    /// The type-name prefixes, ascending.
    pub fn type_name_prefixes(&self) -> impl Iterator<Item = &str> + '_ {
        self.type_name_prefixes.iter().map(String::as_str)
    }

    /// The type ids, ascending.
    pub fn type_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.type_ids.iter().copied()
    }

    /// Whether `other` holds the same conditions and flags, whatever its
    /// generation.
    #[must_use]
    pub fn same_summary(&self, other: &Self) -> bool {
        self.clone().with_generation(other.generation) == *other
    }

    fn texts(&self) -> [&BTreeSet<String>; 4] {
        [
            &self.channels,
            &self.channel_prefixes,
            &self.type_names,
            &self.type_name_prefixes,
        ]
    }

    fn flags(&self) -> u8 {
        (if self.everything { EVERYTHING } else { 0 }) | (if self.health { HEALTH } else { 0 })
    }

    /// The length of [`Interest::encode`]'s bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let texts: usize = self
            .texts()
            .iter()
            .flat_map(|set| set.iter())
            .map(|text| 2 + text.len())
            .sum();
        FIXED_BYTES + 2 * self.type_ids.len() + texts
    }

    /// The summary's canonical bytes, at most [`MAX_INTEREST_BYTES`] long.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(INTEREST_VERSION);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.push(self.flags());
        codec::put_count(out, self.type_ids.len());
        for &type_id in &self.type_ids {
            codec::put_u16(out, type_id);
        }
        for set in self.texts() {
            codec::put_count(out, set.len());
            for text in set {
                codec::put_text(out, text);
            }
        }
    }

    /// Read a summary from exactly `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::TooLarge`] for more than [`MAX_INTEREST_BYTES`] bytes,
    /// and otherwise the error naming the first field that is not a
    /// summary's in normal form: a version other than
    /// [`INTEREST_VERSION`], unknown flags, bytes that end early or run on,
    /// a text that is not UTF-8 or is too long, or a form the type's docs
    /// rule out. Any bytes give a summary or an error; none panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_INTEREST_BYTES {
            return Err(CodecError::TooLarge {
                what: "an interest summary",
                len: bytes.len(),
                max: MAX_INTEREST_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let interest = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(interest)
    }

    pub(crate) fn decode_from(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let version = r.u8()?;
        if version != INTEREST_VERSION {
            return Err(CodecError::UnknownVersion(version));
        }
        let generation = r.u64()?;
        let flags = r.u8()?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(CodecError::UnknownFlags(flags));
        }
        let mut type_ids = BTreeSet::new();
        for _ in 0..r.count(2)? {
            let type_id = r.u16()?;
            if type_ids.last().is_some_and(|&last| type_id <= last) {
                return Err(CodecError::NotCanonical(
                    "type ids out of order or repeated",
                ));
            }
            type_ids.insert(type_id);
        }
        let interest = Self {
            generation,
            everything: flags & EVERYTHING != 0,
            health: flags & HEALTH != 0,
            type_ids,
            channels: read_texts(r, false)?,
            channel_prefixes: read_texts(r, true)?,
            type_names: read_texts(r, false)?,
            type_name_prefixes: read_texts(r, true)?,
        };
        if interest.everything
            && (!interest.type_ids.is_empty() || interest.texts().iter().any(|s| !s.is_empty()))
        {
            return Err(CodecError::NotCanonical(
                "a summary that admits everything lists conditions",
            ));
        }
        if interest
            .channels
            .iter()
            .any(|c| covered(&interest.channel_prefixes, c))
            || interest
                .type_names
                .iter()
                .any(|t| covered(&interest.type_name_prefixes, t))
        {
            return Err(CodecError::NotCanonical(
                "an exact text that a prefix of its set admits",
            ));
        }
        Ok(interest)
    }
}

/// Read one set of texts: ascending, without `*`, and, for prefixes, none
/// empty and none starting with the one before it. Since the set is sorted,
/// a prefix that starts with any earlier prefix starts with the one just
/// before it, so that one comparison makes the set prefix-free.
fn read_texts(r: &mut Reader<'_>, prefixes: bool) -> Result<BTreeSet<String>, CodecError> {
    let what = if prefixes {
        "a prefix in a summary"
    } else {
        "a text in a summary"
    };
    let mut set = BTreeSet::new();
    let mut last: Option<&str> = None;
    for _ in 0..r.count(2)? {
        let text = r.text(what, MAX_PATTERN_LEN)?;
        if text.contains('*') {
            return Err(CodecError::NotCanonical("a text in a summary holds a '*'"));
        }
        if prefixes && text.is_empty() {
            return Err(CodecError::NotCanonical(
                "an empty prefix, where the flags say a summary admits everything",
            ));
        }
        if let Some(last) = last {
            if text <= last {
                return Err(CodecError::NotCanonical("texts out of order or repeated"));
            }
            if prefixes && text.starts_with(last) {
                return Err(CodecError::NotCanonical(
                    "a prefix that starts with another prefix of its set",
                ));
            }
        }
        set.insert(text.to_owned());
        last = Some(text);
    }
    Ok(set)
}

/// Whether some prefix in `prefixes`, a prefix-free set, starts `text`.
///
/// A prefix of `text` sorts at or before it, and in a prefix-free set any
/// entry between that prefix and `text` would itself start with the
/// prefix. So the one candidate is the greatest entry not after `text`.
fn covered(prefixes: &BTreeSet<String>, text: &str) -> bool {
    prefixes
        .range::<str, _>((Bound::Unbounded, Bound::Included(text)))
        .next_back()
        .is_some_and(|prefix| text.starts_with(prefix.as_str()))
}

/// Keep, of each run of prefixes that start with one another, the
/// shortest: they admit the same texts.
fn prefix_free(set: &mut BTreeSet<String>) {
    for prefix in std::mem::take(set) {
        if set
            .last()
            .is_some_and(|kept| prefix.starts_with(kept.as_str()))
        {
            continue;
        }
        set.insert(prefix);
    }
}

/// An exact text, or its first bytes as a prefix when it is longer than a
/// summary's texts may be.
fn insert_exact(exact: &mut BTreeSet<String>, prefixes: &mut BTreeSet<String>, text: &str) {
    if text.len() <= MAX_PATTERN_LEN {
        exact.insert(text.to_owned());
    } else {
        prefixes.insert(clip(text).to_owned());
    }
}

/// The longest start of `text` of at most [`MAX_PATTERN_LEN`] bytes that
/// ends on a character boundary. It is empty only when `text` is.
fn clip(text: &str) -> &str {
    let mut end = text.len().min(MAX_PATTERN_LEN);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn filter(channel: Option<&str>, type_name: Option<&str>, type_id: Option<u16>) -> FilterSpec {
        FilterSpec {
            channel: channel.map(Into::into),
            type_name: type_name.map(Into::into),
            type_id,
            ..FilterSpec::default()
        }
    }

    fn of(filters: &[FilterSpec]) -> Interest {
        Interest::from_filters(filters)
    }

    #[test]
    fn each_filter_adds_the_first_condition_it_sets() {
        let i = of(&[filter(Some("jobs/new"), Some("job.*"), Some(7))]);
        assert_eq!(i.exact_channels().collect::<Vec<_>>(), ["jobs/new"]);
        assert_eq!(i.type_name_prefixes().count(), 0);
        assert_eq!(i.type_ids().count(), 0);

        let i = of(&[filter(Some("*/new"), Some("job.created"), Some(7))]);
        assert_eq!(i.exact_type_names().collect::<Vec<_>>(), ["job.created"]);

        let i = of(&[filter(Some("jobs/*"), Some("job.created"), None)]);
        assert_eq!(i.exact_type_names().collect::<Vec<_>>(), ["job.created"]);

        let i = of(&[filter(Some("jobs/**/x"), Some("job.*"), Some(7))]);
        assert_eq!(i.channel_prefixes().collect::<Vec<_>>(), ["jobs/"]);

        let i = of(&[filter(Some("**"), Some("job.*"), Some(7))]);
        assert_eq!(i.type_name_prefixes().collect::<Vec<_>>(), ["job."]);

        let i = of(&[filter(Some("*"), Some("*.created"), Some(7))]);
        assert_eq!(i.type_ids().collect::<Vec<_>>(), [7]);
        assert!(!i.matches_everything());
    }

    #[test]
    fn a_filter_that_narrows_nothing_admits_everything() {
        assert!(of(&[FilterSpec::default()]).matches_everything());
        assert!(of(&[filter(Some("*/x"), Some("**"), None)]).matches_everything());
        let origin_only = FilterSpec {
            origin: Some("worker@0a0b0c0d".into()),
            ..FilterSpec::default()
        };
        assert!(of(&[origin_only]).matches_everything());
        let health_only = FilterSpec {
            health: true,
            ..FilterSpec::default()
        };
        let i = of(&[health_only, filter(Some("a"), None, None)]);
        assert!(i.matches_everything() && i.wants_health());
        assert_eq!(
            i.exact_channels().count(),
            0,
            "everything holds no conditions"
        );
        assert!(!of(&[]).matches_everything());
        assert!(!of(&[]).may_match("any", 0, None));
    }

    #[test]
    fn may_match_reads_the_channel_as_the_type_name_when_a_send_names_none() {
        let i = of(&[filter(None, Some("metrics/cpu"), None)]);
        assert!(i.may_match("metrics/cpu", 0, None));
        assert!(!i.may_match("metrics/cpu", 0, Some("other")));
        assert!(i.may_match("x", 0, Some("metrics/cpu")));
        let i = of(&[filter(None, Some("metrics/*"), None)]);
        assert!(i.may_match("metrics/mem", 0, None));
        assert!(!i.may_match("jobs", 0, None));
    }

    #[test]
    fn normal_form_drops_what_a_shorter_prefix_already_admits() {
        let i = of(&[
            filter(Some("jobs/new"), None, None),
            filter(Some("jobs/*"), None, None),
            filter(Some("jobs/a/**"), None, None),
            filter(Some("job*"), None, None),
            filter(Some("other"), None, None),
            filter(Some("jo"), None, None),
        ]);
        assert_eq!(i.channel_prefixes().collect::<Vec<_>>(), ["job"]);
        assert_eq!(i.exact_channels().collect::<Vec<_>>(), ["jo", "other"]);
        assert!(i.may_match("jobs/new", 0, None));
        assert!(i.may_match("jo", 0, None));
        assert!(!i.may_match("j", 0, None));
    }

    #[test]
    fn a_text_too_long_for_a_summary_is_kept_as_its_first_bytes() {
        let long = format!("{}é{}", "a".repeat(MAX_PATTERN_LEN - 1), "b".repeat(9));
        let i = of(&[filter(Some(&long), None, None)]);
        assert_eq!(i.exact_channels().count(), 0);
        let prefix = i.channel_prefixes().next().unwrap().to_owned();
        assert_eq!(
            prefix,
            "a".repeat(MAX_PATTERN_LEN - 1),
            "cut on a character boundary"
        );
        assert!(i.may_match(&long, 0, None));
        assert_eq!(Interest::decode(&i.encode()), Ok(i));
    }

    #[test]
    fn a_summary_past_the_cap_admits_everything() {
        let filters: Vec<_> = (0..400)
            .map(|n| filter(Some(&format!("{n:0>250}")), None, None))
            .collect();
        let i = of(&filters);
        assert!(i.matches_everything());
        assert!(i.encoded_len() <= MAX_INTEREST_BYTES);
        let small = of(&filters[..3]);
        assert!(!small.matches_everything());
        let coarse = small.clone().with_generation(9).coarsened(100);
        assert!(coarse.matches_everything());
        assert_eq!(coarse.generation(), 9);
        assert_eq!(coarse.encoded_len(), 30);
        assert_eq!(small.coarsened(small.encoded_len()), small);
    }

    #[test]
    fn the_encoding_is_the_documented_layout() {
        let i = of(&[
            filter(Some("b"), None, None),
            filter(Some("a/*"), None, None),
            filter(None, Some("t"), None),
            filter(None, None, Some(0x0102)),
            FilterSpec {
                channel: Some("z".into()),
                health: true,
                ..FilterSpec::default()
            },
        ])
        .with_generation(0x0807_0605_0403_0201);
        let mut want = vec![1, 1, 2, 3, 4, 5, 6, 7, 8, HEALTH];
        want.extend_from_slice(&[1, 0, 0, 0, 0x02, 0x01]);
        want.extend_from_slice(&[2, 0, 0, 0, 1, 0, b'b', 1, 0, b'z']);
        want.extend_from_slice(&[1, 0, 0, 0, 2, 0, b'a', b'/']);
        want.extend_from_slice(&[1, 0, 0, 0, 1, 0, b't']);
        want.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(i.encode(), want);
        assert_eq!(i.encoded_len(), want.len());
        assert_eq!(Interest::decode(&want), Ok(i));
        let mut everything = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, EVERYTHING];
        everything.extend_from_slice(&[0; 20]);
        assert_eq!(Interest::everything().encode(), everything);
    }

    #[test]
    fn decoding_refuses_every_form_but_the_normal_one() {
        let base = |flags: u8| {
            let mut b = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, flags];
            b.extend_from_slice(&[0, 0, 0, 0]);
            b
        };
        let set = |b: &mut Vec<u8>, texts: &[&str]| {
            b.extend_from_slice(&u32::try_from(texts.len()).unwrap().to_le_bytes());
            for t in texts {
                b.extend_from_slice(&u16::try_from(t.len()).unwrap().to_le_bytes());
                b.extend_from_slice(t.as_bytes());
            }
        };
        let with = |flags: u8, sets: [&[&str]; 4]| {
            let mut b = base(flags);
            for s in sets {
                set(&mut b, s);
            }
            b
        };
        let not_canonical =
            |b: &[u8]| matches!(Interest::decode(b), Err(CodecError::NotCanonical(_)));
        assert!(Interest::decode(&with(0, [&["a", "b"], &["c"], &[], &[]])).is_ok());
        assert!(not_canonical(&with(0, [&["b", "a"], &[], &[], &[]])));
        assert!(not_canonical(&with(0, [&["a", "a"], &[], &[], &[]])));
        assert!(not_canonical(&with(0, [&[], &["a", "ab"], &[], &[]])));
        assert!(not_canonical(&with(0, [&[], &[""], &[], &[]])));
        assert!(not_canonical(&with(0, [&["ab"], &["a"], &[], &[]])));
        assert!(not_canonical(&with(0, [&[], &[], &["tx"], &["t"]])));
        assert!(not_canonical(&with(0, [&["a*"], &[], &[], &[]])));
        assert!(not_canonical(&with(EVERYTHING, [&["a"], &[], &[], &[]])));
        assert_eq!(
            Interest::decode(&with(4, [&[], &[], &[], &[]])),
            Err(CodecError::UnknownFlags(4))
        );
        let mut ids = base(0);
        ids.truncate(10);
        ids.extend_from_slice(&[2, 0, 0, 0, 5, 0, 5, 0]);
        for _ in 0..4 {
            ids.extend_from_slice(&[0, 0, 0, 0]);
        }
        assert!(not_canonical(&ids));
        let mut v2 = with(0, [&[], &[], &[], &[]]);
        v2[0] = 2;
        assert_eq!(Interest::decode(&v2), Err(CodecError::UnknownVersion(2)));
        let mut long = with(0, [&[], &[], &[], &[]]);
        long.push(0);
        assert_eq!(
            Interest::decode(&long),
            Err(CodecError::TrailingBytes { extra: 1 })
        );
        assert!(matches!(
            Interest::decode(&vec![0; MAX_INTEREST_BYTES + 1]),
            Err(CodecError::TooLarge { .. })
        ));
        assert!(matches!(
            Interest::decode(&[1, 0]),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn a_union_admits_what_either_admits_in_normal_form() {
        let a = of(&[
            filter(Some("jobs/new"), None, None),
            filter(None, Some("t"), None),
        ])
        .with_generation(4);
        let b = of(&[
            filter(Some("jobs/*"), None, None),
            FilterSpec {
                channel: Some("z".into()),
                health: true,
                ..FilterSpec::default()
            },
        ]);
        let union = a.union(&b);
        assert_eq!(union.generation(), 0);
        assert!(union.wants_health());
        assert_eq!(union.channel_prefixes().collect::<Vec<_>>(), ["jobs/"]);
        assert_eq!(
            union.exact_channels().collect::<Vec<_>>(),
            ["z"],
            "jobs/new is admitted by the prefix"
        );
        assert_eq!(union.exact_type_names().collect::<Vec<_>>(), ["t"]);
        assert_eq!(Interest::decode(&union.encode()), Ok(union.clone()));
        assert_eq!(union, b.union(&a), "either order");
        assert!(a.union(&Interest::everything()).matches_everything());
        assert_eq!(a.union(&Interest::nothing()), a.clone().with_generation(0));
        // Each small, together past the cap: everything.
        let half: Vec<_> = (0..200)
            .map(|n| filter(Some(&format!("a{n:0>250}")), None, None))
            .collect();
        let other: Vec<_> = (0..200)
            .map(|n| filter(Some(&format!("b{n:0>250}")), None, None))
            .collect();
        let (x, y) = (of(&half), of(&other));
        assert!(!x.matches_everything() && !y.matches_everything());
        let big = x.union(&y);
        assert!(big.matches_everything());
        assert!(big.encoded_len() <= MAX_INTEREST_BYTES);
    }

    #[test]
    fn covered_finds_the_one_prefix_that_can_start_a_text() {
        let set: BTreeSet<String> = ["a", "b/", "b0", "c/d"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        for (text, want) in [
            ("a", true),
            ("ab", true),
            ("b", false),
            ("b/", true),
            ("b/x", true),
            ("b0", true),
            ("b1", false),
            ("c", false),
            ("c/", false),
            ("c/d/e", true),
            ("", false),
        ] {
            assert_eq!(covered(&set, text), want, "{text:?}");
        }
    }
}
