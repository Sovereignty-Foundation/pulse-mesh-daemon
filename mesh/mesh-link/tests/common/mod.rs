// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A reading of the daemon's subscription filters written apart from both
//! the daemon and this crate, to judge the summary by: a glob as the
//! regular expression it stands for, `*` as a run of bytes other than `/`
//! and `**` as any run (`***` is `**` then `*`), matched by memoised
//! recursion, slow and plainly right; and a filter's fields AND-combined,
//! an absent one admitting everything, the channel standing for the type
//! name of a send that names none (`mesh-hub`'s `filter.rs`).

#![allow(dead_code)]

use mesh_port_protocol::FilterSpec;

#[derive(Debug, Clone, Copy)]
enum Token {
    Byte(u8),
    Run,
    AnyRun,
}

fn tokens(pattern: &str) -> Vec<Token> {
    let bytes = pattern.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            if bytes.get(i + 1) == Some(&b'*') {
                out.push(Token::AnyRun);
                i += 2;
            } else {
                out.push(Token::Run);
                i += 1;
            }
        } else {
            out.push(Token::Byte(bytes[i]));
            i += 1;
        }
    }
    out
}

/// Whether the channel or type-name pattern `pattern` matches `text`.
pub(crate) fn glob(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let t = tokens(pattern);
    let s = text.as_bytes();
    let mut memo = vec![None; (t.len() + 1) * (s.len() + 1)];
    go(&t, s, 0, 0, &mut memo)
}

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

/// Whether `filter` admits a send on `channel` with these attributes;
/// `type_name` is `None` for a send that names none.
pub(crate) fn admits(
    filter: &FilterSpec,
    channel: &str,
    type_id: u16,
    type_name: Option<&str>,
    origin: &str,
) -> bool {
    let type_name = type_name.unwrap_or(channel);
    filter.type_id.is_none_or(|id| id == type_id)
        && filter.origin.as_deref().is_none_or(|o| o == origin)
        && filter.channel.as_deref().is_none_or(|p| glob(p, channel))
        && filter
            .type_name
            .as_deref()
            .is_none_or(|p| glob(p, type_name))
}

/// A text `pattern` matches, its `*`s and `**`s filled from `seed`: each
/// `*` with up to three of `a` and `b`, each `**` with up to three of `a`,
/// `b` and `/`.
pub(crate) fn instance(pattern: &str, seed: &mut u64) -> String {
    let mut next = move || {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    };
    let mut out = String::new();
    for token in tokens(pattern) {
        match token {
            Token::Byte(b) => out.push(char::from(b)),
            Token::Run | Token::AnyRun => {
                let alphabet: &[char] = if matches!(token, Token::Run) {
                    &['a', 'b']
                } else {
                    &['a', 'b', '/']
                };
                for _ in 0..next() % 4 {
                    let pick = usize::try_from(next() % alphabet.len() as u64).unwrap_or(0);
                    out.push(alphabet[pick]);
                }
            }
        }
    }
    out
}

#[test]
fn the_reference_reads_globs_as_the_daemon_documents_them() {
    assert!(glob("db/*", "db/rows"));
    assert!(!glob("db/*", "db/rows/sub"));
    assert!(glob("db/**", "db/rows/sub"));
    assert!(glob("**", ""));
    assert!(glob("jobs/*", "jobs/"));
    assert!(!glob("**/new", "new"));
    assert!(glob("**/x*", "a/x/b/xc"));
    assert!(glob("exact", "exact") && !glob("exact", "exactly"));
}
