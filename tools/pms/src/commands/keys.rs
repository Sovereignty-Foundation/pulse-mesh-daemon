// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms keys`: the Ed25519 keys a client proves at attach, and the lines a
//! daemon's `--attach-keys` list holds (ADR-0018 item 6).
//!
//! A key file is `mesh_client::identity`'s: made readable and writable by its
//! owner alone, refused when its group or others may read or write it. Each
//! command prints the key's public half as one `--attach-keys` line, its
//! standard base64 and nothing else, so its output can be appended to a list.

use std::path::Path;
use std::process::ExitCode;

use mesh_client::identity::{generate_key_file, public_key_text, read_key_file};

/// `pms keys generate <path>`: write a new key to a new file at `path` and
/// print its public key. An existing file is never replaced: exit 1.
pub(crate) fn run_generate(path: &Path) -> anyhow::Result<ExitCode> {
    match generate_key_file(path) {
        Ok(key) => {
            println!("{}", public_key_text(&key));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("pms: {e}");
            Ok(ExitCode::from(1))
        }
    }
}

/// `pms keys public <path>`: print the public key of the key file at
/// `path`. A file that is not a key file, or that its group or others may
/// read or write, exits 1.
pub(crate) fn run_public(path: &Path) -> anyhow::Result<ExitCode> {
    match read_key_file(path) {
        Ok(key) => {
            println!("{}", public_key_text(&key));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("pms: {e}");
            Ok(ExitCode::from(1))
        }
    }
}
