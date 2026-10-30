// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A second daemon can never harm the first.
//!
//! The `mesh-hub` binary, started as a process: a second daemon for a live
//! hub, or on a live daemon's socket, is refused before it touches the first
//! one's shared memory or socket, and the first keeps serving, even when the
//! first one's lock files were removed from under it, since a daemon claims
//! its socket before it creates its hub. Once the
//! first has gone, however it went (SIGTERM, or `kill -9`, which leaves its
//! socket, its lock files and its shared memory behind), the next one starts
//! and reclaims what it left, and a process attached to the first one's
//! ring is told it was superseded and follows the next one's. A daemon
//! whose hub name another owner takes all the same (displaced) exits with
//! a status of its own rather than serve into a ring no reader follows,
//! and one signalled the moment its socket answers still cleans up.
//! `tests/one_owner.rs` does the same for an embedded mesh.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, Recv, Upp};
use mesh_hub::embed::HubConfig;
use mesh_hub::DISPLACED_EXIT_STATUS;
use mesh_hub_runtime::owner::{hub_lock_path, recorded_pid, socket_lock_path};
use mesh_hub_runtime::PulseHub;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Send one envelope through the daemon at `socket` and return its ack.
fn send_one(socket: &Path, payload_b64: &str) -> serde_json::Value {
    let mut client = Upp::connect(socket);
    client.attach("writer");
    client.send(&format!(
        r#"{{"op":"send","id":"one","channel":"owner","payload":"{payload_b64}"}}"#
    ));
    let ack = client.recv_json(TIMEOUT);
    assert_eq!(ack["op"], "ack", "{ack}");
    ack
}

/// The inode of the file at `path`.
fn inode(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).unwrap().ino()
}

/// A `mesh-hub` daemon this test started, answering at a private socket
/// with the WebSocket off; its output goes to a log file beside the socket.
struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn start(hub: &str, socket: &Path) -> Self {
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", hub, "--uds-path"])
            .arg(socket)
            .args(["--no-ws", "--store-slots", "4"])
            .env("MESH_HUB_LOG", "info")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("start mesh-hub");
        Self { child, log }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait until the daemon answers at `socket`; panic if it exits first.
    fn wait_serving(&mut self, socket: &Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("mesh-hub exited ({status}):\n{}", self.output());
            }
            if UnixStream::connect(socket).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "mesh-hub never answered:\n{}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait up to 20 s for the daemon to exit.
    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "mesh-hub did not exit:\n{}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// Stop the daemon with SIGTERM, as a service manager would.
    fn terminate(&mut self) -> ExitStatus {
        let sent = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        self.wait_exit()
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

#[test]
fn a_second_daemon_is_refused_and_the_first_keeps_its_shared_memory_and_socket() {
    let hub = hub_name("own-dmn");
    let other_hub = hub_name("own-dmn2");
    let (socket, second_socket) = (socket_path("own-dmn-a"), socket_path("own-dmn-b"));
    let mut first = Daemon::start(&hub, &socket);
    first.wait_serving(&socket);
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("attach by name");
    assert_eq!(attached.store_slots(), Some(4), "the first daemon's store");
    let socket_inode = inode(&socket);

    // A second daemon for the same hub, on a socket of its own.
    let mut second = Daemon::start(&hub, &second_socket);
    let status = second.wait_exit();
    let said = second.output();
    assert!(!status.success(), "{said}");
    assert!(said.contains("already has an owner"), "{said}");
    assert!(said.contains(&format!("process {}", first.pid())), "{said}");
    assert!(!second_socket.exists(), "the refused daemon bound nothing");

    // A daemon for another hub, on the first one's socket.
    let mut third = Daemon::start(&other_hub, &socket);
    let status = third.wait_exit();
    let said = third.output();
    assert!(!status.success(), "{said}");
    assert!(
        said.contains(&format!("another daemon (process {}) is live", first.pid())),
        "{said}"
    );
    assert_eq!(
        inode(&socket),
        socket_inode,
        "the socket file was left alone"
    );

    // The first daemon still owns its hub and serves on its socket, and its
    // ring and store are the ones the hub attached before the refusals.
    assert!(first.running());
    assert_eq!(
        recorded_pid(&hub_lock_path(&hub).unwrap()),
        Some(first.pid())
    );
    assert_eq!(send_one(&socket, "dGhyZWU=")["persisted"], true);
    assert_eq!(attached.poll(), 1);
    assert_eq!(attached.unfetched_envelopes(), 0);
    assert_eq!(attached.ring().cursor_position(), 1);
    assert!(!attached.ring_superseded(), "nobody replaced its ring");

    assert!(first.terminate().success(), "{}", first.output());
    assert!(!socket.exists(), "a clean exit removes the socket");
    assert!(!socket_lock_path(&socket).exists(), "and its lock file");
    assert!(!hub_lock_path(&hub).unwrap().exists(), "and the hub's");
}

#[test]
fn a_second_daemon_on_a_live_socket_stops_before_its_hub_even_with_the_lock_files_gone() {
    let hub = hub_name("own-gone");
    let socket = socket_path("own-gone");
    let mut first = Daemon::start(&hub, &socket);
    first.wait_serving(&socket);
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("attach by name");
    // Something removes both lock files from under the live daemon, as
    // macOS's tmp_cleaner would have after three idle days: until the
    // daemon puts them back, neither turns a second daemon away.
    std::fs::remove_file(hub_lock_path(&hub).unwrap()).unwrap();
    std::fs::remove_file(socket_lock_path(&socket)).unwrap();

    let mut second = Daemon::start(&hub, &socket);
    let status = second.wait_exit();
    let said = second.output();
    assert!(!status.success(), "{said}");
    assert!(said.contains("another daemon is live at"), "{said}");
    // It stopped at the socket, before its hub could replace the first
    // one's ring and store.
    assert_eq!(attached.poll(), 0);
    assert!(
        !attached.ring_superseded(),
        "nobody replaced the first ring"
    );
    assert!(first.running());
    assert_eq!(send_one(&socket, "Z29uZQ==")["persisted"], true);
    assert_eq!(attached.poll(), 1);
    assert_eq!(attached.unfetched_envelopes(), 0);
    assert!(first.terminate().success(), "{}", first.output());
}

#[test]
fn a_daemon_killed_outright_is_replaced_by_the_next() {
    let hub = hub_name("own-kill");
    let socket = socket_path("own-kill");
    let mut first = Daemon::start(&hub, &socket);
    first.wait_serving(&socket);
    let first_pid = first.pid();
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("attach by name");

    // kill -9: no handler runs, so the socket, both lock files and the
    // shared memory stay behind, and only the locks go with the process.
    first.child.kill().unwrap();
    first.child.wait().unwrap();
    assert!(socket.exists(), "the socket file stays behind");
    assert_eq!(
        recorded_pid(&hub_lock_path(&hub).unwrap()),
        Some(first_pid),
        "the lock file stays behind with the dead daemon's id"
    );

    let mut next = Daemon::start(&hub, &socket);
    next.wait_serving(&socket);
    assert_eq!(
        recorded_pid(&hub_lock_path(&hub).unwrap()),
        Some(next.pid()),
        "the next daemon reclaimed the hub's lock"
    );
    assert_eq!(
        recorded_pid(&socket_lock_path(&socket)),
        Some(next.pid()),
        "and the socket's"
    );
    // The hub attached to the killed daemon's ring is told that the ring
    // was replaced, and follows the next daemon's.
    assert_eq!(attached.poll(), 0);
    assert!(attached.ring_superseded(), "told its writer was replaced");
    assert!(attached.reopen().expect("the next daemon's ring is named"));
    assert_eq!(send_one(&socket, "Zm91cg==")["persisted"], true);
    assert_eq!(attached.poll(), 1);
    assert_eq!(attached.unfetched_envelopes(), 0);
    let said = next.output();
    assert!(
        said.contains("replaced a shared-memory ring left by an earlier hub"),
        "{said}"
    );
    assert!(said.contains("removing stale uds"), "{said}");

    assert!(next.terminate().success(), "{}", next.output());
    assert_eq!(attached.poll(), 0);
    assert!(
        attached.ring_superseded(),
        "a clean exit marks the ring too"
    );
    assert!(!socket.exists());
    assert!(!hub_lock_path(&hub).unwrap().exists());
    assert!(
        PulseHub::open(&hub, HubConfig::default()).is_err(),
        "the shared memory went with the daemon"
    );
}

#[test]
fn a_daemon_that_exits_leaves_a_successors_socket_alone() {
    let (first_hub, next_hub) = (hub_name("own-succ"), hub_name("own-sucn"));
    let socket = socket_path("own-succ");
    let mut first = Daemon::start(&first_hub, &socket);
    first.wait_serving(&socket);
    // The first daemon's socket and its lock file are removed from under
    // it, and another daemon binds the path.
    std::fs::remove_file(&socket).unwrap();
    std::fs::remove_file(socket_lock_path(&socket)).unwrap();
    let mut next = Daemon::start(&next_hub, &socket);
    next.wait_serving(&socket);
    let successors = inode(&socket);

    // The first one's exit removed whatever was at its path.
    assert!(first.terminate().success(), "{}", first.output());
    assert!(
        socket.exists() && inode(&socket) == successors,
        "the successor's socket is left alone:\n{}",
        first.output()
    );
    assert_eq!(
        recorded_pid(&socket_lock_path(&socket)),
        Some(next.pid()),
        "and so is its lock"
    );
    assert_eq!(send_one(&socket, "bmV4dA==")["persisted"], true);
    assert!(next.terminate().success(), "{}", next.output());
    assert!(!socket.exists(), "the successor removes its own");
}

#[test]
fn a_daemon_whose_hub_is_displaced_exits_with_its_own_status() {
    let hub = hub_name("own-dspd");
    let socket = socket_path("own-dspd");
    let mut daemon = Daemon::start(&hub, &socket);
    daemon.wait_serving(&socket);
    let mut client = Upp::connect(&socket);
    client.attach("stays");

    // The displacement: the hub's lock file is removed from under the live
    // daemon, and another owner, this process, takes the name, marking the
    // daemon's ring as it replaces its shared memory.
    std::fs::remove_file(hub_lock_path(&hub).unwrap()).unwrap();
    let taken = Instant::now();
    let owner = PulseHub::create_fresh(&hub, HubConfig::default().with_store_slots(6))
        .expect("the lock file was gone");

    // The daemon exits, with a status of its own, rather than serve into the
    // marked ring.
    let status = daemon.wait_exit();
    let waited = taken.elapsed();
    let said = daemon.output();
    assert_eq!(
        status.code(),
        Some(i32::from(DISPLACED_EXIT_STATUS)),
        "{said}"
    );
    assert!(
        waited < Duration::from_secs(10),
        "exited {waited:?} after the displacement:\n{said}"
    );
    assert!(said.contains("this daemon's hub was displaced"), "{said}");
    assert!(
        said.contains(&format!("process {} holds its lock", std::process::id())),
        "the log names who holds the name now:\n{said}"
    );
    assert!(
        matches!(client.recv(TIMEOUT), Recv::Eof),
        "its connection was closed"
    );
    assert!(!socket.exists(), "its own socket was removed");
    assert!(!socket_lock_path(&socket).exists(), "and its lock file");

    // The owner that took the name keeps its lock file, its ring and its
    // store: the daemon's exit left the names to it.
    assert_eq!(
        recorded_pid(&hub_lock_path(&hub).unwrap()),
        Some(std::process::id())
    );
    let mut attached = PulseHub::open(&hub, HubConfig::default()).expect("the new owner's ring");
    assert_eq!(attached.store_slots(), Some(6), "and its store");
    assert_eq!(attached.poll(), 0);
    assert!(!attached.ring_superseded());
    drop(attached);
    drop(owner);
    assert!(!hub_lock_path(&hub).unwrap().exists());
}

/// A shell waiting to send SIGTERM to a process the moment it is told to:
/// `kill` is a builtin, so the signal follows the word by microseconds,
/// where starting a `kill` process would take milliseconds.
struct Trigger(Child);

impl Trigger {
    fn arm(pid: u32) -> Self {
        let child = Command::new("sh")
            .arg("-c")
            .arg(format!("read go && kill -TERM {pid}"))
            .stdin(Stdio::piped())
            .spawn()
            .expect("start sh");
        Self(child)
    }

    fn fire(mut self) {
        let mut stdin = self.0.stdin.take().unwrap();
        stdin.write_all(b"go\n").unwrap();
        drop(stdin);
        assert!(self.0.wait().unwrap().success(), "the signal was sent");
    }
}

#[test]
fn a_daemon_signalled_the_moment_its_socket_answers_still_cleans_up() {
    // The daemon installed its signal handlers after it served, so SIGTERM
    // in between took the default action and left the socket, both lock
    // files and the shared memory behind: 99 of 100 daemons signalled
    // this way died so. Every trial must now exit 0 and leave nothing.
    for trial in 0..25 {
        let tag = format!("own-tm{trial}");
        let (hub, socket) = (hub_name(&tag), socket_path(&tag));
        let mut daemon = Daemon::start(&hub, &socket);
        let trigger = Trigger::arm(daemon.pid());
        let deadline = Instant::now() + Duration::from_secs(20);
        while UnixStream::connect(&socket).is_err() {
            assert!(
                daemon.running() && Instant::now() < deadline,
                "trial {trial}: mesh-hub never answered:\n{}",
                daemon.output()
            );
        }
        trigger.fire();
        let status = daemon.wait_exit();
        assert_eq!(
            status.code(),
            Some(0),
            "trial {trial}: {status}\n{}",
            daemon.output()
        );
        assert!(!socket.exists(), "trial {trial}: the socket was removed");
        assert!(
            !socket_lock_path(&socket).exists(),
            "trial {trial}: and its lock"
        );
        assert!(
            !hub_lock_path(&hub).unwrap().exists(),
            "trial {trial}: and the hub's"
        );
        assert!(
            PulseHub::open(&hub, HubConfig::default()).is_err(),
            "trial {trial}: and the shared memory"
        );
    }
}
