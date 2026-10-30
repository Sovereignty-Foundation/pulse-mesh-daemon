// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A basket is its owner's alone, as the daemon's Unix socket is: the file
//! and the `-wal` and `-shm` files SQLite keeps beside it are mode `0600`
//! however permissive the process's umask, the directories `Basket::open`
//! creates are `0700`, a file an earlier version left readable by others is
//! narrowed to its owner without losing its rows, and a directory that
//! exists already keeps its mode.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_basket::{Basket, CaptureMeta};
use pulse_canon::PulseEnvelope;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn capture(basket: &Basket, payload: &[u8]) {
    basket
        .insert(
            &PulseEnvelope::typed("jobs/new", payload.to_vec()),
            CaptureMeta::new("jobs/new", "worker@00000000"),
        )
        .unwrap();
}

#[test]
fn a_new_basket_and_the_directories_made_for_it_are_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capture").join("daily").join("basket.db");
    let basket = Basket::open(&path).unwrap();
    // A write in WAL mode makes the `-wal` and `-shm` files, which SQLite
    // keeps while the connection is open.
    capture(&basket, b"payload another user must not read");

    assert_eq!(mode(&dir.path().join("capture")), 0o700);
    assert_eq!(mode(&dir.path().join("capture").join("daily")), 0o700);
    assert_eq!(mode(&path), 0o600);
    for suffix in ["-wal", "-shm"] {
        assert_eq!(mode(&sidecar(&path, suffix)), 0o600, "{suffix}");
    }
}

#[test]
fn an_earlier_baskets_files_are_narrowed_to_their_owner_and_keep_their_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("basket.db");
    capture(&Basket::open(&path).unwrap(), b"kept");
    // As an earlier version left them under a umask of 022, with the
    // sidecars of a daemon that stopped without closing its basket.
    let open_to_all = fs::Permissions::from_mode(0o644);
    fs::set_permissions(&path, open_to_all.clone()).unwrap();
    for suffix in ["-wal", "-shm"] {
        let file = sidecar(&path, suffix);
        if !file.exists() {
            fs::write(&file, b"").unwrap();
        }
        fs::set_permissions(&file, open_to_all.clone()).unwrap();
    }

    let basket = Basket::open(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    for suffix in ["-wal", "-shm"] {
        assert_eq!(mode(&sidecar(&path, suffix)), 0o600, "{suffix}");
    }
    assert_eq!(basket.row_count().unwrap(), 1);
}

#[test]
fn a_directory_that_exists_already_keeps_its_mode() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    let path = shared.join("basket.db");
    let basket = Basket::open(&path).unwrap();
    capture(&basket, b"payload");

    assert_eq!(mode(&shared), 0o755);
    assert_eq!(mode(&path), 0o600);
}
