// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Calls against a daemon that has stopped reading do not grow the client's
//! memory. Each call times out and its request, which the transport had not
//! begun to write, is withdrawn, so the heap holds no more after a hundred
//! such calls than before them. The heap is measured by a counting global
//! allocator, which is why this test has a binary of its own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod heap;

use heap::{LIVE, PEAK};
use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A socket path private to this process and test.
fn sock(tag: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("dev-hub-{tag}-{pid}-{unique}.sock"))
}

/// Read one length-prefixed frame from the client as JSON.
fn read_json(stream: &mut UnixStream) -> serde_json::Value {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .expect("a frame from the client");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).expect("the frame's body");
    serde_json::from_slice(&body).expect("JSON")
}

/// Write one length-prefixed frame to the client.
fn write_frame(stream: &mut UnixStream, body: &str) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

/// Sends of 512 KiB each against a daemon that acked the attach and never
/// reads again, each timing out: the heap never holds more than a few
/// frames beyond what it held before, and holds nothing more once the calls
/// are done.
#[test]
fn calls_against_a_stalled_daemon_do_not_grow_the_clients_memory() {
    const CALLS: usize = 30;
    let payload = vec![7u8; 512 * 1024];
    // The base64 of the payload, which is most of a send's frame.
    let frame = payload.len().div_ceil(3) * 4;

    let path = sock("mem");
    let listener = UnixListener::bind(&path).unwrap();
    let (stalled_tx, stalled_rx) = mpsc::channel::<()>();
    let (finish_tx, finish_rx) = mpsc::channel::<()>();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let attach = read_json(&mut stream);
        write_frame(
            &mut stream,
            &format!(
                r#"{{"op":"ack","id":{},"node_id":"n@1","protocol_version":"v0"}}"#,
                attach["id"]
            ),
        );
        // The length prefix of the first frame the writer begins, and then
        // nothing more: the daemon is alive and never reads again.
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        stalled_tx.send(()).unwrap();
        let _ = finish_rx.recv();
    });
    // Long enough for a debug build to encode a send before its caller
    // gives up, so each request is queued before it is withdrawn.
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_rpc_timeout(Duration::from_millis(150))
        .with_heartbeat_interval(Duration::ZERO);
    let mesh = Mesh::attach_with("stalled-mem", options).expect("attach");

    // The writer takes the first request and begins it. The frame is larger
    // than the socket's buffer, so the writer stalls part-way through it and
    // keeps it: that frame is part of the baseline, not of what is measured.
    // (A request whose call timed out before the writer took it would be
    // withdrawn instead, so a machine too slow to encode one in time gets a
    // few more tries.)
    let mut tries = 0;
    loop {
        let sent = mesh.send("c", &payload);
        assert!(matches!(sent, Err(DevError::Timeout { .. })), "{sent:?}");
        if stalled_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            break;
        }
        tries += 1;
        assert!(tries < 5, "the writer never began a request");
    }
    std::thread::sleep(Duration::from_millis(100));
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);

    for call in 0..CALLS {
        match mesh.send("c", &payload) {
            Err(DevError::Timeout { op, .. }) => assert_eq!(op, "send"),
            other => panic!("call {call} against a stalled daemon: {other:?}"),
        }
    }
    // At any moment the client holds a call's copy of the payload, the
    // frame being encoded and one waiting to be withdrawn: a few frames, and
    // sixteen leave room for a connection task the scheduler held back. The
    // unbounded queues grew by more than a frame a call, without end.
    let grew = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    assert!(
        grew < 16 * frame,
        "{CALLS} timed-out calls grew the heap by {grew} bytes at most, \
         {} frames' worth",
        grew / frame
    );

    // Nothing is left behind: the last call's request is withdrawn as soon
    // as the connection's task hears of its timeout.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = LIVE.load(Ordering::Relaxed).saturating_sub(before);
        if left < frame / 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{left} bytes more than before the calls are still held"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    drop(mesh);
    finish_tx.send(()).unwrap();
    daemon.join().unwrap();
    let _ = std::fs::remove_file(&path);
}
