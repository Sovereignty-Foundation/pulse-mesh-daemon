// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms keys generate` writes a key file its owner alone may read and prints
//! the public key as an `--attach-keys` line; `pms keys public` prints the
//! same line from the file; a file that exists is never replaced, and one its
//! group or others may read is refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use std::os::unix::fs::PermissionsExt as _;

fn pms() -> Command {
    Command::cargo_bin("pms").unwrap()
}

#[test]
fn generate_and_public_round_trip_and_guard_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.key");

    let made = pms()
        .args(["keys", "generate"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let line = String::from_utf8(made.stdout).unwrap();
    let public = line.trim_end();
    assert_eq!(line, format!("{public}\n"), "one line, nothing else");
    assert_eq!(public.len(), 44);
    assert!(mesh_hub::AttachKeys::parse(&line).unwrap().len() == 1);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");

    let read = pms().args(["keys", "public"]).arg(&path).output().unwrap();
    assert!(read.status.success(), "{read:?}");
    assert_eq!(String::from_utf8(read.stdout).unwrap(), line);
    let key = mesh_client::identity::read_key_file(&path).unwrap();
    assert_eq!(mesh_client::identity::public_key_text(&key), public);

    // The existing file is kept.
    let before = std::fs::read(&path).unwrap();
    let again = pms()
        .args(["keys", "generate"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(1), "{again:?}");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // Readable by others: refused.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = pms().args(["keys", "public"]).arg(&path).output().unwrap();
    assert_eq!(open.status.code(), Some(1), "{open:?}");
    assert!(
        String::from_utf8_lossy(&open.stderr).contains("chmod 600"),
        "{open:?}"
    );
    assert!(open.stdout.is_empty());
}
