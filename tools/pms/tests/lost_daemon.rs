// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms attach` and `pms tap` park on the daemon until Ctrl-C. When the daemon
//! goes away under them instead, they must say so and exit non-zero, not end
//! silently with status 0 as if the user had stopped them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;

/// A hub name unique to this process and test, at most 15 characters.
fn hub(tag: char) -> String {
    format!("pc{tag}{:x}", std::process::id() & 0xf_ffff)
}

/// A daemon for the hub `hub(tag)` answering at `sock`. Its envelope store
/// has sixteen slots (about 1 MiB of shared memory): these tests store
/// nothing that needs more, and a container's `/dev/shm` is small.
fn start_daemon(tag: char, sock: &std::path::Path) -> EmbeddedMesh {
    let config = HubConfig::default().with_store_slots(16);
    EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Uds(sock.to_path_buf())],
        ConnectionPolicy::default(),
        config,
    )
    .expect("daemon")
}

/// Start `pms <args>` against the daemon at `sock`, and return the child once
/// `ready` has appeared on the stream the command announces itself on.
fn start_parked(
    sock: &std::path::Path,
    args: &[&str],
    ready: &str,
    on_stderr: bool,
) -> (Child, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pms"))
        .args(args)
        .env("PMS_DAEMON", format!("unix://{}", sock.display()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pms");
    let (tx, rx) = mpsc::channel();
    let stream: Box<dyn Read + Send> = if on_stderr {
        Box::new(child.stderr.take().unwrap())
    } else {
        Box::new(child.stdout.take().unwrap())
    };
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) if line.contains(ready) => break,
            Ok(_) => {}
            Err(_) => {
                let _ = child.kill();
                panic!("pms {args:?} never printed {ready:?}");
            }
        }
    }
    (child, rx)
}

/// Wait for the child to exit within ten seconds and return its status code.
fn exit_code(child: &mut Child) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("pms did not exit after the daemon went away");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut s = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut s);
    }
    s
}

#[test]
fn attach_reports_a_lost_daemon_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pms.sock");
    let daemon = start_daemon('a', &sock);
    let (mut child, _stdout) = start_parked(
        &sock,
        &["attach", "lost-daemon-attach"],
        "attached as",
        false,
    );

    daemon.shutdown();

    assert_eq!(
        exit_code(&mut child),
        Some(2),
        "a lost daemon is an error, not a clean stop"
    );
    let err = stderr_of(&mut child);
    assert!(
        err.contains("the connection to mesh-hub ended"),
        "stderr: {err}"
    );
}

#[test]
fn tap_reports_a_lost_daemon_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pms.sock");
    let daemon = start_daemon('t', &sock);
    let (mut child, stderr) = start_parked(&sock, &["tap", "--channel", "jobs/*"], "tapped", true);

    daemon.shutdown();

    assert_eq!(
        exit_code(&mut child),
        Some(2),
        "a lost daemon is an error, not a clean stop"
    );
    // The reader thread ends when the child's stderr closes; collect until then.
    let mut rest = Vec::new();
    while let Ok(line) = stderr.recv_timeout(Duration::from_secs(5)) {
        rest.push(line);
    }
    assert!(
        rest.iter()
            .any(|l| l.contains("the connection to mesh-hub ended")),
        "stderr after the ready line: {rest:?}"
    );
}
