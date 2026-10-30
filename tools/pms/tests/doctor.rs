// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms doctor` where the install guide sends people: any directory outside
//! the workspace. Nothing pins a toolchain there and there is no target
//! directory, so the rows that need either only inform, the command exits
//! 0, and it writes nothing where it runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

#[test]
fn doctor_outside_a_workspace_exits_zero_and_leaves_the_directory_empty() {
    let dir = tempfile::tempdir().unwrap();
    // The premise: no directory above this one makes it part of a Cargo
    // workspace or pins a toolchain.
    for ancestor in dir.path().ancestors() {
        for marker in ["Cargo.toml", "rust-toolchain", "rust-toolchain.toml"] {
            assert!(
                !ancestor.join(marker).exists(),
                "{} holds {marker}; this test needs a temporary directory outside any workspace",
                ancestor.display()
            );
        }
    }

    let out = Command::new(env!("CARGO_BIN_EXE_pms"))
        .arg("doctor")
        .current_dir(dir.path())
        // Set for this test by rustup and cargo, not by the host: without
        // them `rustc` is the host's default and no target directory is named.
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "pms doctor exited {:?}:\n{stdout}{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    for row in ["rust-toolchain", "cargo-target"] {
        assert!(
            stdout
                .lines()
                .any(|l| l.starts_with("[INFO ]") && l.contains(row)),
            "the {row} row should inform, not judge:\n{stdout}"
        );
    }
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "pms doctor left {left:?} behind");
}
