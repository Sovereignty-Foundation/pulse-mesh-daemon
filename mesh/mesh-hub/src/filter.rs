// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Subscription filters, compiled once and matched in time the protocol's caps
//! bound.
//!
//! A glob has the meaning [`FilterSpec`] gives it (`***` is `**` then `*`) and
//! is matched in one pass over the pattern, each step a few operations on bit
//! sets over the text's positions: at most `MAX_PATTERN_LEN` steps on
//! `MAX_CHANNEL_LEN / 64 + 1` words. Not backtracking, whose cost is the
//! product of the two lengths, since every send meets up to `max_connections`
//! times `max_subscriptions` filters (`tests/matching.rs`).

use crate::protocol::FilterSpec;
use std::cell::OnceCell;

/// A subscription's filter, compiled when the subscription opens. Its
/// fields AND-combine, and one that is absent admits everything.
#[derive(Debug)]
pub(crate) struct Filter {
    channel: Option<Pattern>,
    type_id: Option<u16>,
    type_name: Option<Pattern>,
    origin: Option<Box<str>>,
}

impl Filter {
    /// Compile `spec`'s channel and type-name patterns; its type id and
    /// origin are compared as they are.
    pub(crate) fn compile(spec: &FilterSpec) -> Self {
        Self {
            channel: spec.channel.as_deref().map(Pattern::compile),
            type_id: spec.type_id,
            type_name: spec.type_name.as_deref().map(Pattern::compile),
            origin: spec.origin.as_deref().map(Box::from),
        }
    }

    /// Whether a send passes the filter. `scratch` is working space, kept
    /// by the caller across matches so a match allocates nothing.
    pub(crate) fn matches(&self, send: &Subject<'_>, scratch: &mut Vec<u64>) -> bool {
        self.type_id.is_none_or(|id| id == send.type_id)
            && self.origin.as_deref().is_none_or(|o| o == send.origin)
            && self
                .channel
                .as_ref()
                .is_none_or(|p| send.channel.matches(p, scratch))
            && self
                .type_name
                .as_ref()
                .is_none_or(|p| send.type_name.matches(p, scratch))
    }
}

/// What a send is matched on: its channel, type id, type name (the channel
/// when the send names none) and origin, prepared once for every filter.
pub(crate) struct Subject<'a> {
    channel: Text<'a>,
    type_id: u16,
    type_name: Text<'a>,
    origin: &'a str,
}

impl<'a> Subject<'a> {
    /// A send on `channel` with these attributes.
    pub(crate) fn new(channel: &'a str, type_id: u16, type_name: &'a str, origin: &'a str) -> Self {
        Self {
            channel: Text::new(channel),
            type_id,
            type_name: Text::new(type_name),
            origin,
        }
    }
}

/// A string patterns are matched against, with its positions worked out
/// the first time a glob needs them.
struct Text<'a> {
    text: &'a str,
    positions: OnceCell<Positions>,
}

impl<'a> Text<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            positions: OnceCell::new(),
        }
    }

    fn matches(&self, pattern: &Pattern, scratch: &mut Vec<u64>) -> bool {
        match pattern {
            Pattern::Exact(exact) => **exact == *self.text,
            Pattern::Glob(tokens) => {
                let positions = self
                    .positions
                    .get_or_init(|| Positions::new(self.text.as_bytes()));
                glob_matches(tokens, positions, scratch)
            }
        }
    }
}

/// A channel or type-name pattern.
#[derive(Debug)]
enum Pattern {
    /// No `*`: the text must be exactly this.
    Exact(Box<str>),
    /// A glob, as the steps [`glob_matches`] takes.
    Glob(Box<[Token]>),
}

impl Pattern {
    fn compile(pattern: &str) -> Self {
        if !pattern.contains('*') {
            return Self::Exact(pattern.into());
        }
        let bytes = pattern.as_bytes();
        let mut tokens = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&byte) = bytes.get(i) {
            let (token, width) = match (byte, bytes.get(i + 1)) {
                (b'*', Some(b'*')) => (Token::AnyRun, 2),
                (b'*', _) => (Token::Run, 1),
                _ => (Token::Byte(byte), 1),
            };
            tokens.push(token);
            i += width;
        }
        Self::Glob(tokens.into_boxed_slice())
    }
}

/// One step of a glob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    /// This byte.
    Byte(u8),
    /// `*`: any run of bytes other than `/`.
    Run,
    /// `**`: any run of bytes.
    AnyRun,
}

/// Where each byte value sits in a text, and where the bytes that are not
/// `/` sit, as bit sets over the positions `0..=len` of a text of `len`
/// bytes: bit `i % 64` of word `i / 64` stands for position `i`, the place
/// before byte `i`, and position `len` is the end.
struct Positions {
    /// The text's length in bytes.
    len: usize,
    /// Words per bit set: `len / 64 + 1`.
    words: usize,
    /// For each byte value `b`, `words` words from `b * words`: bit `i`
    /// set when byte `i` is `b`.
    of_byte: Box<[u64]>,
    /// Bit `i` set when byte `i` is not `/`.
    not_slash: Box<[u64]>,
}

impl Positions {
    fn new(text: &[u8]) -> Self {
        let words = text.len() / 64 + 1;
        let mut of_byte = vec![0u64; 256 * words].into_boxed_slice();
        let mut not_slash = vec![0u64; words].into_boxed_slice();
        for (i, &byte) in text.iter().enumerate() {
            let (word, bit) = (i / 64, 1u64 << (i % 64));
            of_byte[usize::from(byte) * words + word] |= bit;
            if byte != b'/' {
                not_slash[word] |= bit;
            }
        }
        Self {
            len: text.len(),
            words,
            of_byte,
            not_slash,
        }
    }

    /// The positions of the bytes equal to `byte`.
    fn of(&self, byte: u8) -> &[u64] {
        let start = usize::from(byte) * self.words;
        &self.of_byte[start..start + self.words]
    }
}

/// Whether the glob `tokens` matches the whole text `positions` describes.
///
/// `reach` holds the positions the tokens read so far can end at, all of
/// them at once. A byte moves each reached position that is followed by
/// that byte on by one; `*` extends each to every later position up to the
/// next `/`, which adding the reached positions to the runs of bytes that
/// are not `/` does in one carry; `**` extends the first to every later
/// position. The glob matches when the end of the text is reached.
fn glob_matches(tokens: &[Token], positions: &Positions, reach: &mut Vec<u64>) -> bool {
    let words = positions.words;
    let last = words - 1;
    // The bits of the last word that stand for positions up to the end.
    let within = u64::MAX >> (63 - positions.len % 64);
    reach.clear();
    reach.resize(words, 0);
    reach[0] = 1;
    for &token in tokens {
        match token {
            Token::Byte(byte) => {
                let mut carry = 0;
                for (r, &at) in reach.iter_mut().zip(positions.of(byte)) {
                    let hit = *r & at;
                    *r = (hit << 1) | carry;
                    carry = hit >> 63;
                }
            }
            Token::Run => {
                let mut carry = 0;
                for (r, &run) in reach.iter_mut().zip(positions.not_slash.iter()) {
                    let (sum, first) = run.overflowing_add(*r & run);
                    let (sum, second) = sum.overflowing_add(carry);
                    carry = u64::from(first | second);
                    *r |= sum ^ run;
                }
            }
            Token::AnyRun => {
                if let Some(first) = reach.iter().position(|&r| r != 0) {
                    let lowest = reach[first] & reach[first].wrapping_neg();
                    reach[first] = !(lowest - 1);
                    reach[first + 1..].fill(u64::MAX);
                    reach[last] &= within;
                }
            }
        }
        if reach.iter().all(|&r| r == 0) {
            return false;
        }
    }
    reach[last] & (1 << (positions.len % 64)) != 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn glob(pattern: &str, text: &str) -> bool {
        Text::new(text).matches(&Pattern::compile(pattern), &mut Vec::new())
    }

    /// The glob as the regular expression it stands for, `*` as `[^/]*`
    /// and `**` as `.*`, matched by memoised recursion: slow and plainly
    /// right.
    fn reference(pattern: &str, text: &str) -> bool {
        let tokens = match Pattern::compile(pattern) {
            Pattern::Exact(exact) => return *exact == *text,
            Pattern::Glob(tokens) => tokens,
        };
        let text = text.as_bytes();
        let mut memo = vec![None; (tokens.len() + 1) * (text.len() + 1)];
        fn go(t: &[Token], s: &[u8], i: usize, j: usize, memo: &mut [Option<bool>]) -> bool {
            let key = i * (s.len() + 1) + j;
            if let Some(known) = memo[key] {
                return known;
            }
            let found = match t.get(i) {
                None => j == s.len(),
                Some(Token::Byte(b)) => s.get(j) == Some(b) && go(t, s, i + 1, j + 1, memo),
                Some(Token::Run) => {
                    go(t, s, i + 1, j, memo)
                        || (s.get(j).is_some_and(|&c| c != b'/') && go(t, s, i, j + 1, memo))
                }
                Some(Token::AnyRun) => {
                    go(t, s, i + 1, j, memo) || (j < s.len() && go(t, s, i, j + 1, memo))
                }
            };
            memo[key] = Some(found);
            found
        }
        go(&tokens, text, 0, 0, &mut memo)
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
    fn a_star_stays_within_a_level_and_a_double_star_crosses_levels() {
        assert!(glob("db/*", "db/rows"));
        assert!(!glob("db/*", "db/rows/sub"));
        assert!(glob("db/**", "db/rows/sub"));
        assert!(glob("**", "anything/here"));
        assert!(glob("**", ""));
        assert!(!glob("db/*", "other"));
        assert!(glob("jobs/*", "jobs/"));
        assert!(glob("*/new", "jobs/new"));
        assert!(!glob("*/new", "a/jobs/new"));
        assert!(glob("**/new", "a/jobs/new"));
        assert!(!glob("**/new", "new"));
    }

    #[test]
    fn a_pattern_without_a_star_is_the_channel_itself() {
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(!glob("exactly", "exact"));
        assert!(glob("", ""));
        assert!(!glob("", "x"));
    }

    #[test]
    fn a_star_after_a_double_star_does_not_strand_the_match() {
        // `**` takes `a/x/b`, then `/x`, then `*` takes `c`.
        assert!(glob("**/x*", "a/x/b/xc"));
        assert!(glob("**/*.rs", "src/a/b/main.rs"));
        assert!(!glob("**/*.rs", "src/a/b/main.rs/x"));
        assert!(glob("a/**/z/*", "a/b/c/z/y"));
    }

    #[test]
    fn every_short_pattern_agrees_with_the_regular_expression_it_stands_for() {
        let patterns: Vec<(String, Pattern)> = strings("a*/", 5)
            .into_iter()
            .map(|p| {
                let compiled = Pattern::compile(&p);
                (p, compiled)
            })
            .collect();
        let scratch = &mut Vec::new();
        for text in strings("ab/", 5) {
            let prepared = Text::new(&text);
            for (pattern, compiled) in &patterns {
                assert_eq!(
                    prepared.matches(compiled, scratch),
                    reference(pattern, &text),
                    "{pattern:?} against {text:?}"
                );
            }
        }
    }

    #[test]
    fn long_texts_agree_with_the_reference_across_word_boundaries() {
        // A fixed xorshift, so a failure repeats.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..3_000 {
            let len = (next() % 300) as usize;
            let text: String = (0..len)
                .map(|_| ['a', 'b', '/'][(next() % 3) as usize])
                .collect();
            // A pattern cut from the text, so that matches are common.
            let mut pattern = String::new();
            let mut i = 0;
            while i < text.len() {
                match next() % 6 {
                    0 => {
                        pattern.push('*');
                        i += (next() % 5) as usize;
                    }
                    1 => {
                        pattern.push_str("**");
                        i += (next() % 40) as usize;
                    }
                    _ => {
                        pattern.push_str(&text[i..=i]);
                        i += 1;
                    }
                }
            }
            assert_eq!(
                glob(&pattern, &text),
                reference(&pattern, &text),
                "{pattern:?} against {text:?}"
            );
        }
    }

    #[test]
    fn the_filter_and_combines_its_fields() {
        let spec = FilterSpec {
            channel: Some("jobs/*".into()),
            type_id: Some(7),
            type_name: Some("job.*".into()),
            origin: Some("worker@0a0b0c0d".into()),
            ..FilterSpec::default()
        };
        let filter = Filter::compile(&spec);
        let scratch = &mut Vec::new();
        let send = |channel, type_id, type_name, origin| {
            filter.matches(
                &Subject::new(channel, type_id, type_name, origin),
                &mut Vec::new(),
            )
        };
        assert!(send("jobs/new", 7, "job.created", "worker@0a0b0c0d"));
        assert!(!send("jobs/new/x", 7, "job.created", "worker@0a0b0c0d"));
        assert!(!send("jobs/new", 8, "job.created", "worker@0a0b0c0d"));
        assert!(!send("jobs/new", 7, "task.created", "worker@0a0b0c0d"));
        assert!(!send("jobs/new", 7, "job.created", "other@0a0b0c0d"));
        let everything = Filter::compile(&FilterSpec::default());
        assert!(everything.matches(&Subject::new("any/thing", 1, "t", "o@1"), scratch));
    }
}
