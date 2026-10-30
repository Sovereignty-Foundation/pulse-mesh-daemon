// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon keeps its WebSocket on loopback unless told otherwise: without
//! TLS and attach keys nothing encrypts it or authenticates its clients, so a
//! network address would serve the hub to whoever reaches it. The command line
//! refuses such an address without `--ws-allow-remote`, and with it the daemon
//! warns in its log (`tests/attach_keys.rs` has the address taken with TLS and
//! attach keys).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path};
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_websocket_off_loopback_is_refused_without_ws_allow_remote() {
    let socket = socket_path("ws-refused");
    let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name("wsref"), "--uds-path"])
        .arg(&socket)
        .args(["--ws-bind", "0.0.0.0:0", "--store-slots", "4"])
        .output()
        .expect("run mesh-hub");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("--ws-allow-remote"), "stderr:\n{stderr}");
    assert!(
        !socket.exists(),
        "a refused command line made the socket {}",
        socket.display()
    );
}

#[test]
fn a_websocket_off_loopback_with_ws_allow_remote_starts_and_warns() {
    let socket = socket_path("ws-remote");
    let log = socket.with_extension("log");
    let out = File::create(&log).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name("wsrem"), "--uds-path"])
        .arg(&socket)
        .args([
            "--ws-bind",
            "0.0.0.0:0",
            "--ws-allow-remote",
            "--store-slots",
            "4",
        ])
        .env("MESH_HUB_LOG", "info")
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("start mesh-hub");
    let read_log = || std::fs::read_to_string(&log).unwrap_or_default();

    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(&socket).is_err() || !read_log().contains("websocket listening") {
        if let Some(status) = daemon.try_wait().unwrap() {
            panic!("mesh-hub exited ({status}):\n{}", read_log());
        }
        assert!(
            Instant::now() < deadline,
            "mesh-hub never served:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // SIGTERM, so it removes its socket and shared memory as it exits.
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
    assert!(
        text.contains("WARN") && text.contains("no authentication and no encryption"),
        "no warning in the log:\n{text}"
    );
}
