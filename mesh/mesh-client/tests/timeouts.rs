// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A call that times out leaves nothing behind. A fake daemon that stalls
//! stands in for a slow or stuck one: a subscribe whose ack comes late never
//! runs its callback, and the subscription the daemon made is released; the
//! requests of calls that timed out before they were written never reach
//! the daemon, however the client's threads interleave; calls past the
//! queues' depth wait for room until their deadlines and then fail with
//! `QueueFull`, having sent nothing; and a daemon that keeps up sees no
//! change, however many threads call, a burst of them at once included.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::client::{COMMAND_QUEUE, OUTBOUND_QUEUE};
use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// A hub name unique to this process and short enough for every SHM name
/// derived from it.
fn hub(tag: &str) -> String {
    format!("dh-{tag}-{:04x}", std::process::id() & 0xffff)
}

/// A socket path private to this process and test: the clock alone can
/// repeat across processes started in the same microsecond.
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

/// An event for subscription `sub`, carrying "hi".
fn event(sub: &str, envelope: &str) -> String {
    format!(
        r#"{{"op":"event","subscription_id":"{sub}","envelope_id":"{envelope}","channel":"c","type_id":0,"origin":"o@1","captured_at_unix_nanos":0,"payload":"aGk="}}"#
    )
}

/// A fake daemon on a private socket: it accepts one client, acks its
/// attach, runs `script` on the connection, then holds it until the client
/// closes it. The options attach to it with the heartbeat off, so every
/// frame the script reads is one a call sent.
fn fake_daemon(
    tag: &str,
    script: impl FnOnce(&mut UnixStream) + Send + 'static,
) -> (MeshOptions, std::thread::JoinHandle<()>) {
    let path = sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_heartbeat_interval(Duration::ZERO);
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let attach = read_json(&mut stream);
        assert_eq!(attach["op"], "attach");
        write_frame(
            &mut stream,
            &format!(
                r#"{{"op":"ack","id":{},"node_id":"n@1","protocol_version":"v0"}}"#,
                attach["id"]
            ),
        );
        script(&mut stream);
        let _ = stream.read(&mut [0u8; 1]);
        let _ = std::fs::remove_file(&path);
    });
    (options, daemon)
}

/// The daemon acks a subscribe only after the caller has given up, then
/// sends three events for the subscription it made. The callback never
/// runs, the late ack is counted, and the client releases the
/// subscription. A second subscribe, answered in time, works, and its
/// event, sent after one more for the late subscription, is delivered;
/// events reach callbacks in arrival order, so by then every event for the
/// late subscription has been passed over.
#[test]
fn a_subscribe_that_times_out_never_runs_its_callback_and_is_released() {
    let (gave_up_tx, gave_up_rx) = mpsc::channel::<()>();
    let (released_tx, released_rx) = mpsc::channel::<serde_json::Value>();
    let (options, daemon) = fake_daemon("late-sub", move |stream| {
        let subscribe = read_json(stream);
        assert_eq!(subscribe["op"], "subscribe");
        gave_up_rx.recv().unwrap();
        write_frame(
            stream,
            &format!(
                r#"{{"op":"ack","id":{},"subscription_id":"late"}}"#,
                subscribe["id"]
            ),
        );
        for envelope in ["e0", "e1", "e2"] {
            write_frame(stream, &event("late", envelope));
        }
        let release = read_json(stream);
        write_frame(stream, &format!(r#"{{"op":"ack","id":{}}}"#, release["id"]));
        released_tx.send(release).unwrap();

        let subscribe = read_json(stream);
        assert_eq!(subscribe["op"], "subscribe");
        write_frame(
            stream,
            &format!(
                r#"{{"op":"ack","id":{},"subscription_id":"good"}}"#,
                subscribe["id"]
            ),
        );
        write_frame(stream, &event("late", "e3"));
        write_frame(stream, &event("good", "e4"));
    });
    let mesh = Mesh::attach_with(
        "late-sub",
        options.with_rpc_timeout(Duration::from_millis(200)),
    )
    .expect("attach");

    let ran = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&ran);
    match mesh.on("c", move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
    }) {
        Err(DevError::Timeout { op, .. }) => assert_eq!(op, "subscribe"),
        other => panic!("the subscribe was not answered in time, got {other:?}"),
    }
    gave_up_tx.send(()).unwrap();

    let release = released_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the client released the subscription it never wanted");
    assert_eq!(release["op"], "unsubscribe");
    assert_eq!(release["subscription_id"], "late");

    let (tx, rx) = mpsc::channel();
    let good = mesh
        .on("c", move |ev| {
            let _ = tx.send(ev.envelope_id);
        })
        .expect("a subscribe answered in time");
    assert_eq!(good.0, "good");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the good event"),
        "e4"
    );
    assert_eq!(
        ran.load(Ordering::SeqCst),
        0,
        "the timed-out subscribe's callback never ran"
    );
    assert_eq!(mesh.late_replies(), 1, "the late ack was counted");
    assert_eq!(mesh.events_dropped(), 0);
    drop(mesh);
    daemon.join().unwrap();
}

/// A daemon that stops reading while the client writes a frame larger than
/// the socket's buffer stalls the client's writer part-way through it. Ten
/// more calls time out with their requests still queued behind it, and are
/// withdrawn: when the daemon reads again it finds the first request, whose
/// late reply is counted, and then the next call's, never the ten. The
/// daemon reads again the moment the calls have returned: a call that
/// returns `Timeout` has withdrawn its request itself, and does not rely on
/// the connection's task to do it in time.
#[test]
fn the_requests_of_calls_that_timed_out_never_reach_a_stalled_daemon() {
    let (stalled_tx, stalled_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let (seen_tx, seen_rx) = mpsc::channel::<Vec<serde_json::Value>>();
    let (options, daemon) = fake_daemon("stall", move |stream| {
        // The large send's length prefix, then nothing until told.
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        stalled_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&body).unwrap();
        write_frame(
            stream,
            &format!(
                r#"{{"op":"ack","id":{},"envelope_id":"late"}}"#,
                first["id"]
            ),
        );
        let next = read_json(stream);
        write_frame(
            stream,
            &format!(r#"{{"op":"ack","id":{},"envelope_id":"next"}}"#, next["id"]),
        );
        seen_tx.send(vec![first, next]).unwrap();
    });
    // Long enough for a debug build to encode the large send before its
    // caller gives up, so the writer surely takes it.
    let mesh = Mesh::attach_with("stall", options.with_rpc_timeout(Duration::from_secs(1)))
        .expect("attach");

    let big = {
        let mesh = mesh.clone();
        std::thread::spawn(move || mesh.send("big", &vec![7u8; 1 << 20]))
    };
    stalled_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the writer began the large send");
    let small: Vec<_> = (0..10)
        .map(|call| {
            let mesh = mesh.clone();
            std::thread::spawn(move || mesh.send(&format!("withdrawn-{call}"), b"small"))
        })
        .collect();
    for call in small.into_iter().chain([big]) {
        match call.join().unwrap() {
            Err(DevError::Timeout { op, .. }) => assert_eq!(op, "send"),
            other => panic!("a stalled daemon cannot answer, got {other:?}"),
        }
    }
    resume_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while mesh.late_replies() < 1 {
        assert!(Instant::now() < deadline, "the late reply was not counted");
        std::thread::sleep(Duration::from_millis(10));
    }
    let receipt = mesh
        .send_with_receipt("after", None, b"answered")
        .expect("the connection works again");
    assert_eq!(receipt.envelope_id, "next");

    let seen = seen_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(seen[0]["channel"], "big");
    assert_eq!(
        seen[1]["channel"], "after",
        "no withdrawn request reached the daemon"
    );
    assert_eq!(mesh.late_replies(), 1);
    drop(mesh);
    daemon.join().unwrap();
}

/// With the writer stalled part-way through one frame, calls queue until
/// `OUTBOUND_QUEUE` requests wait for the writer and `COMMAND_QUEUE` calls
/// behind them; every call past that waits for room until its deadline and
/// then fails with `QueueFull`, not at once, having sent nothing.
///
/// The calls are unsubscribes, whose requests are sent even when they time
/// out, so the queues stay full to the end: a withdrawn request would make
/// room for a later caller. When the daemon reads again it finds the large
/// send, then every unsubscribe that was queued, and then the next call,
/// never one that was refused.
#[test]
fn calls_wait_for_room_until_their_deadline_then_fail_with_queue_full() {
    const EXTRA: usize = 16;
    const QUEUED: usize = OUTBOUND_QUEUE + COMMAND_QUEUE;
    const RPC_TIMEOUT: Duration = Duration::from_secs(2);
    let (stalled_tx, stalled_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let (seen_tx, seen_rx) = mpsc::channel::<Vec<serde_json::Value>>();
    let (options, daemon) = fake_daemon("full", move |stream| {
        // The length prefix of the large send: the writer is part-way
        // through it, and the daemon reads no more until told.
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        stalled_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut seen = vec![first];
        // Everything after it, each answered, up to the next send.
        loop {
            let last = seen.last().unwrap();
            write_frame(
                stream,
                &format!(r#"{{"op":"ack","id":{},"envelope_id":"e"}}"#, last["id"]),
            );
            if seen.len() > 1 && last["op"] == "send" {
                break;
            }
            seen.push(read_json(stream));
        }
        seen_tx.send(seen).unwrap();
    });
    let mesh = Mesh::attach_with("full", options.with_rpc_timeout(RPC_TIMEOUT)).expect("attach");

    let big = {
        let mesh = mesh.clone();
        std::thread::spawn(move || mesh.send("big", &vec![7u8; 2 << 20]))
    };
    stalled_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the writer began the large send");
    let (results_tx, results_rx) = mpsc::channel();
    let callers: Vec<_> = (0..QUEUED + EXTRA)
        .map(|call| {
            let mesh = mesh.clone();
            let results = results_tx.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                let sub = format!("sub-{call}");
                let result = mesh.unsubscribe(mesh_client::SubscriptionId(sub.clone()));
                results.send((sub, result, started.elapsed())).unwrap();
            })
        })
        .collect();

    let mut refused = Vec::new();
    let mut queued = 0;
    for _ in 0..QUEUED + EXTRA {
        let (sub, result, took) = results_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("every call returns by its deadline");
        match result {
            Err(DevError::QueueFull { op }) => {
                assert_eq!(op, "unsubscribe");
                assert!(
                    took >= RPC_TIMEOUT,
                    "a call waits for room until its deadline, and this one took {took:?}"
                );
                refused.push(sub);
            }
            Err(DevError::Timeout { op, .. }) => {
                assert_eq!(op, "unsubscribe");
                queued += 1;
            }
            other => panic!("a stalled daemon answers nothing: {other:?}"),
        }
    }
    assert_eq!(queued, QUEUED, "both queues were full");
    assert_eq!(refused.len(), EXTRA, "and every call past them was refused");
    for caller in callers {
        caller.join().unwrap();
    }
    assert!(matches!(
        big.join().unwrap(),
        Err(DevError::Timeout { op: "send", .. })
    ));

    resume_tx.send(()).unwrap();
    let receipt = mesh
        .send_with_receipt("after", None, b"answered")
        .expect("the connection works again");
    assert_eq!(receipt.envelope_id, "e");
    let seen = seen_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(
        seen.len(),
        1 + QUEUED + 1,
        "the large send, the queued calls, the next"
    );
    assert_eq!(seen[0]["channel"], "big");
    assert_eq!(seen[QUEUED + 1]["channel"], "after");
    for unsubscribe in &seen[1..=QUEUED] {
        assert_eq!(unsubscribe["op"], "unsubscribe");
        let sub = unsubscribe["subscription_id"].as_str().unwrap();
        assert!(
            !refused.iter().any(|refused| refused == sub),
            "the refused {sub} reached the daemon"
        );
    }
    drop(mesh);
    daemon.join().unwrap();
}

/// Two hundred threads each make one send at the same moment against a
/// daemon that answers every request as it reads it. Far more calls than
/// both queues hold arrive at once, and each waits its turn: none is
/// refused, none is late.
#[test]
fn a_burst_against_a_daemon_that_keeps_up_is_never_refused() {
    const THREADS: usize = 200;
    let (options, daemon) = fake_daemon("burst", |stream| {
        for _ in 0..THREADS {
            let send = read_json(stream);
            write_frame(
                stream,
                &format!(r#"{{"op":"ack","id":{},"envelope_id":"e"}}"#, send["id"]),
            );
        }
    });
    let mesh = Mesh::attach_with("burst", options).expect("attach");
    let start = Arc::new(std::sync::Barrier::new(THREADS));
    let senders: Vec<_> = (0..THREADS)
        .map(|_| {
            let mesh = mesh.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let payload = vec![1u8; 64 * 1024];
                start.wait();
                mesh.send("burst", &payload)
            })
        })
        .collect();
    for sender in senders {
        let sent = sender.join().unwrap();
        assert!(matches!(sent.as_deref(), Ok("e")), "{sent:?}");
    }
    assert_eq!(mesh.late_replies(), 0);
    drop(mesh);
    daemon.join().unwrap();
}

/// Against a daemon that keeps up, thirty-two threads sending at once on one
/// handle are never refused and never late: each has one call in flight, so
/// fewer calls wait than either queue holds.
#[test]
fn many_threads_calling_a_daemon_that_keeps_up_all_succeed() {
    const THREADS: usize = 32;
    const SENDS: usize = 50;
    let path = sock("busy");
    let daemon = EmbeddedMesh::start_with_config(
        &hub("busy"),
        &[Bind::Uds(path.clone())],
        ConnectionPolicy::default(),
        HubConfig::default().with_store_slots(16),
    )
    .expect("daemon");
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    let mesh = Mesh::attach_with("busy", options).expect("attach");

    let senders: Vec<_> = (0..THREADS)
        .map(|thread| {
            let mesh = mesh.clone();
            std::thread::spawn(move || {
                for i in 0..SENDS {
                    let payload = format!("{thread}/{i}");
                    mesh.send("busy", payload.as_bytes()).expect("send");
                }
            })
        })
        .collect();
    for sender in senders {
        sender.join().unwrap();
    }
    assert_eq!(mesh.late_replies(), 0);
    mesh.detach().expect("detach");
    drop(daemon);
}
