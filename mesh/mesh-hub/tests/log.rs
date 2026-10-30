// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon colours its log only on a terminal. `pms start` sends the log
//! to a file, where colour codes are bytes every reader of it must strip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path};
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_log_written_to_a_file_carries_no_colour_codes() {
    let socket = socket_path("log-file");
    let log = socket.with_extension("log");
    let out = File::create(&log).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name("logf"), "--uds-path"])
        .arg(&socket)
        .args(["--no-ws", "--store-slots", "4"])
        .env("MESH_HUB_LOG", "info")
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("start mesh-hub");
    let read_log = || std::fs::read_to_string(&log).unwrap_or_default();

    // Serving, so it has logged its start, the socket's line included.
    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(&socket).is_err() {
        if let Some(status) = daemon.try_wait().unwrap() {
            panic!("mesh-hub exited ({status}):\n{}", read_log());
        }
        assert!(
            Instant::now() < deadline,
            "mesh-hub never answered:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // SIGTERM, which it answers by logging its shutdown and exiting.
    let sent = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    while daemon.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("mesh-hub did not exit on SIGTERM:\n{}", read_log());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let text = read_log();
    let _ = std::fs::remove_file(&log);
    assert!(text.contains("uds listening"), "the log:\n{text}");
    assert!(
        !text.contains('\u{1b}'),
        "the log carries escape codes:\n{}",
        text.escape_debug()
    );
}
