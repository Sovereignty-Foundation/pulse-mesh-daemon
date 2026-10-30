// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The events a stalled callback has not run hold at most the event queue's
//! byte budget, however large they are, and give it back once the callback
//! runs them. The heap is measured by a counting global allocator (`heap`),
//! which is why this test has a binary of its own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod heap;

use heap::LIVE;
use mesh_client::{Endpoint, Mesh, MeshOptions};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Mutex};
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
fn write_frame(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

const MIB: usize = 1024 * 1024;

/// A daemon delivers events of 760 KiB, about what a 1 MiB send frame
/// carries, while the only callback is stalled on the first. The events
/// waiting, and the one the callback holds, stay within the default budget
/// of 16 MiB, the rest are dropped and counted, and the heap gives the
/// bytes back once the callback has run what waited.
#[test]
fn events_a_stalled_callback_has_not_run_hold_at_most_the_byte_budget() {
    const EVENTS: usize = 64;
    const PAYLOAD: usize = 760 * 1024;
    // Beyond the budget: the event being decoded, the frame the reader
    // holds, and the buffers they came through.
    const SLACK: usize = 6 * MIB;
    let budget = MeshOptions::default().event_queue_bytes;
    assert_eq!(budget, 16 * MIB);

    let path = sock("evmem");
    let listener = UnixListener::bind(&path).unwrap();
    // The send's reply follows all 64 events, about 64 MiB of base64 the
    // client reads and decodes first; a debug build on a loaded machine can
    // take longer than the default five seconds over it, and the test is
    // about memory, not time.
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_heartbeat_interval(Duration::ZERO)
        .with_rpc_timeout(Duration::from_secs(60));
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let attach = read_json(&mut stream);
        write_frame(
            &mut stream,
            format!(
                r#"{{"op":"ack","id":{},"node_id":"n@1","protocol_version":"v0"}}"#,
                attach["id"]
            )
            .as_bytes(),
        );
        let subscribe = read_json(&mut stream);
        write_frame(
            &mut stream,
            format!(
                r#"{{"op":"ack","id":{},"subscription_id":"s"}}"#,
                subscribe["id"]
            )
            .as_bytes(),
        );
        go_rx.recv().unwrap();
        let payload = mesh_port_protocol::base64::encode(&vec![0x5a; PAYLOAD]);
        let event = format!(
            r#"{{"op":"event","subscription_id":"s","envelope_id":"e","channel":"c","type_id":0,"origin":"o@1","captured_at_unix_nanos":0,"payload":"{payload}"}}"#
        );
        drop(payload);
        for _ in 0..EVENTS {
            write_frame(&mut stream, event.as_bytes());
        }
        drop(event);
        // The send that follows the events is answered after all of them.
        let send = read_json(&mut stream);
        write_frame(
            &mut stream,
            format!(r#"{{"op":"ack","id":{},"envelope_id":"d"}}"#, send["id"]).as_bytes(),
        );
        let _ = stream.read(&mut [0u8; 1]);
        let _ = std::fs::remove_file(&path);
    });

    let mesh = Mesh::attach_with("evmem", options).expect("attach");
    // The callback reports each event, then stalls until the gate opens,
    // which dropping its sender does for good.
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate = Mutex::new(gate_rx);
    let (ran_tx, ran_rx) = mpsc::channel::<()>();
    mesh.on("c", move |_event| {
        let _ = entered_tx.send(());
        let _ = gate.lock().unwrap().recv();
        let _ = ran_tx.send(());
    })
    .expect("subscribe");

    let before = LIVE.load(Ordering::Relaxed);
    go_tx.send(()).unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the first event reaches the callback");
    // Its reply comes after every event, so by then each was queued or
    // dropped.
    assert_eq!(mesh.send("done", b"").expect("the send"), "d");
    let held = LIVE.load(Ordering::Relaxed).saturating_sub(before);
    let dropped = mesh.events_dropped() as usize;
    assert!(
        held <= budget + SLACK,
        "the stalled callback's events hold {} MiB, over the {} MiB budget",
        held / MIB,
        budget / MIB
    );
    assert!(
        dropped >= EVENTS - budget / PAYLOAD,
        "no more events than fit the budget wait: {dropped} of {EVENTS} dropped"
    );

    // The callback runs the rest, and the bytes come back.
    drop(gate_tx);
    for _ in 0..EVENTS - dropped {
        ran_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("every queued event runs");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = LIVE.load(Ordering::Relaxed).saturating_sub(before);
        if left < SLACK {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{} MiB still held once the callback has run the events",
            left / MIB
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(mesh);
    daemon.join().unwrap();
}
