// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What keeps a connection open, and what dropping the last handle does.
//! Dropping the last `Mesh` closes the connection on whatever thread it
//! happens, the runtime's own included, and never aborts the process; a
//! callback that holds a `WeakMesh` keeps nothing alive; one that holds a
//! `Mesh` keeps the connection open until the connection ends, and nothing
//! alive after that.
//!
//! Each test runs its body in a child process of its own: this binary, with
//! the variable `DEV_HUB_LIFETIME_CHILD` set and only that test selected.
//! There every panic aborts the process, as the release profile's
//! `panic = "abort"` makes it, a panic the runtime would catch on one of its
//! own threads included; and the process's thread count moves with the
//! client alone. A fake daemon stands in for the real one, whose own threads
//! would be counted too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Set in a child's environment; its presence makes a test run its body.
const CHILD: &str = "DEV_HUB_LIFETIME_CHILD";

/// In the child, make every panic abort and return `true`, so the test runs
/// its body. In the parent, run `test` alone in a child, require it to
/// succeed, and return `false`.
fn in_child(test: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        let report = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            report(info);
            std::process::abort();
        }));
        return true;
    }
    let child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .expect("run the child");
    assert!(
        child.status.success(),
        "the child running {test} failed ({}):\n{}\n{}",
        child.status,
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    false
}

/// The threads of this process.
#[cfg(target_os = "linux")]
fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

/// The threads of this process: one line each under `ps -M`'s header.
#[cfg(not(target_os = "linux"))]
fn threads() -> usize {
    let out = Command::new("ps")
        .args(["-M", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .count()
        .saturating_sub(1)
}

/// The thread count once it is back to `baseline`, or after five seconds:
/// a runtime shut down without waiting ends its threads on its own.
fn settled_threads(baseline: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = threads();
        if now <= baseline || Instant::now() > deadline {
            return now;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A socket path private to this process and test.
fn sock(tag: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("dev-hub-{tag}-{pid}-{unique}.sock"))
}

/// A fake daemon's listening socket, and options that attach to it with the
/// heartbeat off, so every frame it reads is one a call or a detach sent.
fn listen(tag: &str) -> (MeshOptions, UnixListener) {
    let path = sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_heartbeat_interval(Duration::ZERO);
    (options, listener)
}

/// Accept the one client and acknowledge its attach. Reads wait at most ten
/// seconds, so a connection nobody closes is reported, not waited on.
fn accept(listener: &UnixListener) -> UnixStream {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let Heard::Frame(attach) = read(&mut stream) else {
        panic!("no attach");
    };
    assert_eq!(attach["op"], "attach");
    write_frame(
        &mut stream,
        &format!(
            r#"{{"op":"ack","id":{},"node_id":"n@1","protocol_version":"v0"}}"#,
            attach["id"]
        ),
    );
    stream
}

/// What one read from the client found.
enum Heard {
    /// A frame, as JSON.
    Frame(serde_json::Value),
    /// The client closed the connection.
    Closed,
    /// Nothing for ten seconds.
    Silent,
}

/// Read one length-prefixed frame from the client.
fn read(stream: &mut UnixStream) -> Heard {
    let mut len = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len) {
        return match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Heard::Silent,
            _ => Heard::Closed,
        };
    }
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).expect("the frame's body");
    Heard::Frame(serde_json::from_slice(&body).expect("JSON"))
}

/// The next frame from the client, which must come.
fn frame(stream: &mut UnixStream) -> serde_json::Value {
    match read(stream) {
        Heard::Frame(frame) => frame,
        Heard::Closed => panic!("the client closed the connection"),
        Heard::Silent => panic!("the client sent nothing"),
    }
}

/// Write one length-prefixed frame to the client.
fn write_frame(stream: &mut UnixStream, body: &str) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

/// Answer a subscribe with the subscription `sub`.
fn ack_subscribe(stream: &mut UnixStream, sub: &str) {
    let subscribe = frame(stream);
    assert_eq!(subscribe["op"], "subscribe");
    write_frame(
        stream,
        &format!(
            r#"{{"op":"ack","id":{},"subscription_id":"{sub}"}}"#,
            subscribe["id"]
        ),
    );
}

/// The ops of the frames a daemon read, in order.
fn ops(frames: &[serde_json::Value]) -> Vec<&str> {
    frames.iter().filter_map(|f| f["op"].as_str()).collect()
}

/// A subscribe times out while its callback holds a `Mesh`, and the program
/// drops its own handle at once, as `?` would after the `Timeout`, so the
/// driver drops the last `Mesh` on the runtime's own thread. The connection
/// closes and the client's threads end, round after round, with no abort.
#[test]
fn dropping_the_last_handle_inside_the_driver_closes_the_connection() {
    if !in_child("dropping_the_last_handle_inside_the_driver_closes_the_connection") {
        return;
    }
    let baseline = threads();
    for round in 0..5 {
        let (options, listener) = listen(&format!("drop{round}"));
        let daemon = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            // The subscribe, which is never answered.
            assert_eq!(frame(&mut stream)["op"], "subscribe");
            read(&mut stream)
        });
        let mesh = Mesh::attach_with("drop", options.with_rpc_timeout(Duration::from_millis(300)))
            .expect("attach");
        let held = mesh.clone();
        match mesh.on("c", move |event| {
            let _ = held.send("reply", &event.payload);
        }) {
            Err(DevError::Timeout { op, .. }) => assert_eq!(op, "subscribe"),
            other => panic!("the subscribe is never answered, got {other:?}"),
        }
        drop(mesh);
        match daemon.join().unwrap() {
            Heard::Closed => {}
            Heard::Frame(frame) => panic!("round {round}: the client sent {frame} before closing"),
            Heard::Silent => panic!("round {round}: the connection was never closed"),
        }
    }
    assert_eq!(
        settled_threads(baseline),
        baseline,
        "the client's threads ended"
    );
}

/// A callback that holds a `WeakMesh` calls back into the mesh while the
/// program holds its `Mesh`, and keeps nothing alive once the program drops
/// it: the connection closes without a detach, and the client's threads
/// end. Upgrading the handle afterwards fails with `MeshDropped`.
#[test]
fn a_callback_holding_a_weak_handle_keeps_nothing_alive() {
    if !in_child("a_callback_holding_a_weak_handle_keeps_nothing_alive") {
        return;
    }
    let baseline = threads();
    let (options, listener) = listen("weak");
    let daemon = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        ack_subscribe(&mut stream, "s");
        write_frame(
            &mut stream,
            r#"{"op":"event","subscription_id":"s","envelope_id":"e","channel":"c","type_id":0,"origin":"o@1","captured_at_unix_nanos":0,"payload":"aGk="}"#,
        );
        let mut read_after = Vec::new();
        loop {
            match read(&mut stream) {
                Heard::Frame(msg) => {
                    if msg["op"] == "send" {
                        write_frame(
                            &mut stream,
                            &format!(r#"{{"op":"ack","id":{},"envelope_id":"r"}}"#, msg["id"]),
                        );
                    }
                    read_after.push(msg);
                }
                Heard::Closed => return read_after,
                Heard::Silent => panic!("the connection was never closed"),
            }
        }
    });

    let mesh = Mesh::attach_with("weak", options).expect("attach");
    let weak = mesh.downgrade();
    let in_callback = mesh.downgrade();
    let (sent_tx, sent_rx) = mpsc::channel();
    mesh.on("c", move |event| {
        let sent = in_callback
            .upgrade()
            .and_then(|mesh| mesh.send("reply", &event.payload));
        let _ = sent_tx.send(sent);
    })
    .expect("subscribe");
    let sent = sent_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the callback ran");
    assert_eq!(sent.expect("a send through the weak handle"), "r");

    drop(mesh);
    let read_after = daemon.join().unwrap();
    assert_eq!(
        ops(&read_after),
        ["send"],
        "the callback's send, then the close, without a detach"
    );
    assert!(
        matches!(weak.upgrade(), Err(DevError::MeshDropped)),
        "the mesh is gone"
    );
    assert_eq!(
        settled_threads(baseline),
        baseline,
        "the client's threads ended"
    );
}

/// A callback that holds a `Mesh` keeps the connection open after the
/// program has dropped its own handle, as documented: the daemon sees
/// nothing close, and the client's threads stay. Once the daemon closes the
/// connection, the callback is dropped, the `Mesh` with it, and every
/// thread ends.
#[test]
fn a_callback_holding_the_mesh_keeps_the_connection_until_the_daemon_closes_it() {
    if !in_child("a_callback_holding_the_mesh_keeps_the_connection_until_the_daemon_closes_it") {
        return;
    }
    let baseline = threads();
    let (options, listener) = listen("held");
    let (conn_tx, conn_rx) = mpsc::channel();
    let daemon = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        conn_tx.send(stream.try_clone().unwrap()).unwrap();
        ack_subscribe(&mut stream, "s");
        read(&mut stream)
    });
    let mesh = Mesh::attach_with("held", options).expect("attach");
    let held = mesh.clone();
    mesh.on("c", move |event| {
        let _ = held.send("reply", &event.payload);
    })
    .expect("subscribe");
    let conn = conn_rx.recv().unwrap();
    let attached = threads();

    drop(mesh);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !daemon.is_finished(),
        "the connection stays open while a callback holds a Mesh"
    );
    assert_eq!(threads(), attached, "and so do the client's threads");

    // The daemon closes it. The client's connection ends, its callbacks are
    // dropped, and with them the last Mesh.
    conn.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(matches!(daemon.join().unwrap(), Heard::Closed));
    assert_eq!(
        settled_threads(baseline),
        baseline,
        "the client's threads ended"
    );
}

/// The same after a detach: a detach ends the connection, so the callbacks
/// are dropped, and a callback's `Mesh` keeps none of the client's threads
/// alive once the program drops its own.
#[test]
fn a_detach_releases_a_callback_that_holds_the_mesh() {
    if !in_child("a_detach_releases_a_callback_that_holds_the_mesh") {
        return;
    }
    let baseline = threads();
    for round in 0..3 {
        let (options, listener) = listen(&format!("detach{round}"));
        let daemon = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            ack_subscribe(&mut stream, "s");
            let detach = frame(&mut stream);
            assert_eq!(detach["op"], "detach");
            write_frame(
                &mut stream,
                &format!(r#"{{"op":"ack","id":{},"__detach":true}}"#, detach["id"]),
            );
            // A daemon closes the connection once it has acknowledged a
            // detach.
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });
        let mesh = Mesh::attach_with("detach", options).expect("attach");
        let held = mesh.clone();
        mesh.on("c", move |event| {
            let _ = held.send("reply", &event.payload);
        })
        .expect("subscribe");
        mesh.detach().expect("detach");
        assert!(matches!(mesh.wait(), Ok(())));
        drop(mesh);
        daemon.join().unwrap();
    }
    assert_eq!(
        settled_threads(baseline),
        baseline,
        "the client's threads ended"
    );
}
