// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Every repository path `pms` names exists in the repository.
//!
//! The text searched is what a user can be shown: the help, as the built
//! binary prints it (`pms -h`, `pms --help`, and `pms docs cli-markdown`,
//! which renders every subcommand and argument from the definitions that
//! parse them), and every string literal in the CLI's source, which is where
//! each message it prints is written.
//!
//! A word of that text is taken for a repository path only when it is
//! relative (it starts with neither `/`, `~`, `./` nor `../`, and holds no
//! `:`, `*` or `@`), holds a `/`, and either begins with a top-level entry of
//! the repository (`peripheral/`, `scripts/`, `rings/`, ...) or ends in a
//! file name with an extension. That keeps out what only looks like a path:
//! absolute and home paths (`/tmp/pms.sock`, `~/.local/state/pms`), URLs and
//! addresses (`ws://127.0.0.1:9876`), channel names and globs (`db/rows`,
//! `jobs/*`), ratios and units (`5/5`, `pulses/sec`) and markup (`</p>`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root: the first directory above this crate whose
/// `Cargo.toml` is a workspace's (the integrated tree and the daemon's own
/// repository keep the crate at different depths).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .skip(1)
        .find(|dir| {
            std::fs::read_to_string(dir.join("Cargo.toml"))
                .is_ok_and(|manifest| manifest.contains("[workspace]"))
        })
        .unwrap()
        .to_path_buf()
}

/// The names at the top of the repository a repository path begins with;
/// `.git` and the build output are not part of it.
fn top_level(root: &Path) -> BTreeSet<String> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != ".git" && name != "target")
        .collect()
}

/// What `pms <args>` prints on stdout; it must succeed.
fn pms(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_pms"))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "pms {args:?} exited {:?}", out.status);
    String::from_utf8(out.stdout).unwrap()
}

/// The contents of the string literals in Rust source, with comments and
/// character literals skipped. Escaped line ends and the indentation after
/// them vanish, `\n`, `\r` and `\t` become spaces, and any other escaped
/// character stands for itself: enough to read the words of a message.
fn string_literals(src: &str) -> Vec<String> {
    let c: Vec<char> = src.chars().collect();
    let at = |i: usize| c.get(i).copied();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let prev_ident = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
        match c[i] {
            '/' if at(i + 1) == Some('/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if at(i + 1) == Some('*') => {
                i += 2;
                while i < c.len() && !(c[i] == '*' && at(i + 1) == Some('/')) {
                    i += 1;
                }
                i += 2;
            }
            // A character literal, or else a lifetime or a label.
            '\'' if at(i + 1) == Some('\\') => {
                // Past the quote, the backslash and the escaped character.
                i += 3;
                while i < c.len() && c[i] != '\'' {
                    i += 1;
                }
                i += 1;
            }
            '\'' if at(i + 2) == Some('\'') => i += 3,
            // A raw string `r"…"` or `r#"…"#`; `r#name` is a raw identifier.
            'r' if !prev_ident && matches!(at(i + 1), Some('"' | '#')) => {
                let hashes = c[i + 1..].iter().take_while(|&&h| h == '#').count();
                let open = i + 1 + hashes;
                if at(open) != Some('"') {
                    i = open;
                    continue;
                }
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let body: String = c[open + 1..].iter().collect();
                let end = body.find(&close).unwrap_or(body.len());
                out.push(body[..end].to_string());
                i = open + 1 + body[..end].chars().count() + close.chars().count();
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        match at(i + 1) {
                            Some('\n') => {
                                i += 2;
                                while i < c.len() && c[i].is_whitespace() {
                                    i += 1;
                                }
                                continue;
                            }
                            Some('n' | 'r' | 't') => s.push(' '),
                            Some(escaped) => s.push(escaped),
                            None => {}
                        }
                        i += 2;
                        continue;
                    }
                    s.push(c[i]);
                    i += 1;
                }
                i += 1;
                out.push(s);
            }
            _ => i += 1,
        }
    }
    out
}

/// The words of `text` that are repository paths, by the rule in the
/// module documentation.
fn repository_paths(text: &str, top: &BTreeSet<String>) -> BTreeSet<String> {
    let path_char = |ch: char| ch.is_alphanumeric() || "._-/~:*@+".contains(ch);
    text.split(|ch: char| !path_char(ch))
        .map(|word| word.trim_end_matches(['.', ',', ':']))
        .filter(|word| {
            let relative = !word.starts_with(['/', '~'])
                && !word.starts_with("./")
                && !word.starts_with("../")
                && !word.contains([':', '*', '@']);
            let first = word.split('/').next().unwrap_or_default();
            let last = word
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default();
            let has_extension = last.rsplit_once('.').is_some_and(|(stem, ext)| {
                !stem.is_empty()
                    && (1..=4).contains(&ext.len())
                    && ext.chars().all(|ch| ch.is_ascii_alphanumeric())
            });
            relative && word.contains('/') && (top.contains(first) || has_extension)
        })
        .map(str::to_string)
        .collect()
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}

#[test]
fn every_repository_path_the_cli_names_exists() {
    let root = repo_root();
    let top = top_level(&root);

    let help = ["-h", "--help", "docs cli-markdown"]
        .iter()
        .map(|args| pms(&args.split(' ').collect::<Vec<_>>()))
        .collect::<Vec<_>>()
        .join("\n");
    let help_paths = repository_paths(&help, &top);

    let mut message_paths = BTreeSet::new();
    for file in rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")) {
        let src = std::fs::read_to_string(&file).unwrap();
        for literal in string_literals(&src) {
            message_paths.extend(repository_paths(&literal, &top));
        }
    }

    // The extraction itself works: both sources name at least one path.
    assert!(
        !help_paths.is_empty(),
        "no repository path found in the help"
    );
    assert!(
        !message_paths.is_empty(),
        "no repository path found in the CLI's messages"
    );
    let missing: Vec<_> = help_paths
        .iter()
        .map(|p| ("help", p))
        .chain(message_paths.iter().map(|p| ("message", p)))
        .filter(|(_, p)| !root.join(p.trim_end_matches('/')).exists())
        .collect();
    assert!(
        missing.is_empty(),
        "pms names repository paths that do not exist: {missing:?}"
    );
}

#[test]
fn only_relative_repository_paths_are_taken_for_paths() {
    let top: BTreeSet<String> = ["peripheral", "rings", "scripts"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let text = "see scripts/docs/gen-all.sh. Tap db/rows or jobs/* at \
                ws://127.0.0.1:9876 or unix:///tmp/pms.sock; 5/5 at 1000 pulses/sec, \
                log in ~/.local/state/pms, probe /dev/shm, schema in \
                src/commands/encode_decode.rs, templates in rings/other_ring/templates/ \
                and ./build.sh, ../x/y.rs, </p>";
    let found: Vec<_> = repository_paths(text, &top).into_iter().collect();
    assert_eq!(
        found,
        [
            "rings/other_ring/templates/",
            "scripts/docs/gen-all.sh",
            "src/commands/encode_decode.rs",
        ]
    );

    let src = r##"
        // "commented/out.rs" is not a message
        let a = '"'; let q = '\''; let b = "peripheral/a\
                    /b"; let r#for = 1; let c = r#"scripts/"quoted".sh"#; // 'x
        eprintln!("x\n  rings/y/z/");
    "##;
    assert_eq!(
        string_literals(src),
        ["peripheral/a/b", r#"scripts/"quoted".sh"#, "x   rings/y/z/"]
    );
}
