// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! How the client fails: an unreachable endpoint is a transport error, a
//! silent daemon is a timeout, a call from inside a runtime is refused,
//! and `wait` reports a daemon that went away. A daemon that refuses the
//! connection or a frame is reported with its own reason, by every call
//! still waiting however far it got, an unprompted
//! error the daemon carries on after fails no call, an event whose payload
//! is not valid base64 is counted and never delivered, and a WebSocket
//! message longer than the client takes on the Unix socket ends the
//! connection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::client::MAX_INBOUND_MESSAGE;
use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

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

/// The daemon's hub configuration: a store of sixteen slots (about 1 MiB of
/// shared memory) is all these tests need, and the default's 16 MiB for each
/// daemon the tests start in parallel does not fit the 64 MB `/dev/shm`
/// Docker gives a container.
fn small_store() -> HubConfig {
    HubConfig::default().with_store_slots(16)
}

fn uds_daemon(tag: &str) -> (EmbeddedMesh, MeshOptions) {
    let path = sock(tag);
    let daemon = EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Uds(path.clone())],
        ConnectionPolicy::default(),
        small_store(),
    )
    .expect("daemon");
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    (daemon, options)
}

/// A daemon on a private socket under `policy`.
fn uds_daemon_with(tag: &str, policy: ConnectionPolicy) -> (EmbeddedMesh, MeshOptions) {
    let path = sock(tag);
    let daemon = EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Uds(path.clone())],
        policy,
        small_store(),
    )
    .expect("daemon");
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    (daemon, options)
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

/// A fake daemon on a private socket, for what the real one never sends:
/// it accepts one client, acks its attach, runs `script` on the
/// connection, then holds it open until the client closes it.
fn fake_daemon(
    tag: &str,
    script: impl FnOnce(&mut UnixStream) + Send + 'static,
) -> (MeshOptions, std::thread::JoinHandle<()>) {
    let path = sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()));
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
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

#[test]
fn an_unreachable_endpoint_is_a_transport_error() {
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Uds("/nonexistent/dir/pms.sock".into()));
    match Mesh::attach_with("nobody", options) {
        Err(DevError::Transport(_)) => {}
        Err(other) => panic!("expected a transport error, got {other}"),
        Ok(_) => panic!("attach cannot succeed with no daemon"),
    }
}

#[test]
fn a_silent_server_times_out() {
    let path = sock("silent");
    let listener = UnixListener::bind(&path).unwrap();
    let holder = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(2));
        drop(stream);
    });
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_rpc_timeout(Duration::from_millis(300));
    let started = Instant::now();
    match Mesh::attach_with("patient", options) {
        Err(DevError::Timeout { op, .. }) => assert_eq!(op, "attach"),
        Err(other) => panic!("expected a timeout, got {other}"),
        Ok(_) => panic!("a silent server cannot complete an attach"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the timeout is bounded"
    );
    holder.join().unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn calls_from_inside_a_runtime_are_refused() {
    let (_daemon, options) = uds_daemon("reent");
    let mesh = Mesh::attach_with("reent", options).expect("attach");
    let inner = mesh.clone();
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move { inner.send("c", b"x") });
    assert!(
        matches!(result, Err(DevError::ReentrantCall)),
        "got {result:?}"
    );
    mesh.detach().expect("detach");
}

/// A call from `spawn_blocking` is refused too, and the error's message
/// names what works, a plain thread, whose call goes.
#[test]
fn calls_from_spawn_blocking_are_refused_and_the_error_says_where_to_call() {
    let (_daemon, options) = uds_daemon("reentsb");
    let mesh = Mesh::attach_with("reentsb", options).expect("attach");
    let inner = mesh.clone();
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move { tokio::task::spawn_blocking(move || inner.send("c", b"x")).await })
        .expect("the closure ran");
    let Err(error) = result else {
        panic!("a call from spawn_blocking was not refused");
    };
    assert!(matches!(error, DevError::ReentrantCall), "got {error:?}");
    let message = error.to_string();
    assert!(message.contains("use a std::thread"), "{message}");
    assert!(!message.contains("use spawn_blocking"), "{message}");
    let inner = mesh.clone();
    std::thread::spawn(move || inner.send("c", b"x"))
        .join()
        .unwrap()
        .expect("a plain thread's call goes");
    mesh.detach().expect("detach");
}

/// `Duration::MAX` for the reply timeout, the heartbeat or the silence
/// limit is a wait with no end, not an overflow that aborts a release build.
#[test]
fn timeouts_too_long_for_the_clock_wait_rather_than_overflow() {
    let (_daemon, options) = uds_daemon("durmax");
    let options = options
        .with_rpc_timeout(Duration::MAX)
        .with_heartbeat_interval(Duration::MAX)
        .with_silence_limit(Duration::MAX);
    let mesh = Mesh::attach_with("durmax", options).expect("attach");
    let (tx, rx) = mpsc::channel();
    let sub = mesh
        .on("c", move |event| {
            let _ = tx.send(event.payload);
        })
        .expect("subscribe");
    assert!(!mesh.send("c", b"x").expect("send").is_empty());
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), b"x");
    mesh.unsubscribe(sub).expect("unsubscribe");
    mesh.detach().expect("detach");
}

#[test]
fn wait_returns_disconnected_when_the_daemon_goes_away() {
    let (daemon, options) = uds_daemon("gone");
    let mesh = Mesh::attach_with("gone", options).expect("attach");
    let waiter = {
        let mesh = mesh.clone();
        std::thread::spawn(move || mesh.wait())
    };
    std::thread::sleep(Duration::from_millis(100));
    daemon.shutdown();
    let outcome = waiter.join().unwrap();
    assert!(
        matches!(outcome, Err(DevError::Disconnected)),
        "got {outcome:?}"
    );
    assert!(mesh.send("c", b"x").is_err(), "the connection is gone");
}

#[test]
fn wait_returns_ok_after_a_detach() {
    let (_daemon, options) = uds_daemon("bye");
    let mesh = Mesh::attach_with("bye", options).expect("attach");
    mesh.detach().expect("detach");
    assert!(matches!(mesh.wait(), Ok(())));
}

/// A daemon at its connection cap says so unprompted and closes; the
/// attach reports the daemon's code and message, not a bare disconnect.
#[test]
fn an_attach_refused_at_the_connection_cap_reports_the_daemons_reason() {
    let (_daemon, options) =
        uds_daemon_with("cap", ConnectionPolicy::default().with_max_connections(0));
    match Mesh::attach_with("turned-away", options) {
        Err(DevError::Daemon { code, message }) => {
            assert_eq!(code, "limit_exceeded");
            assert!(
                message.contains("at most 0 connections") && message.contains("--max-connections"),
                "the daemon's own message: {message}"
            );
        }
        Err(other) => panic!("expected the daemon's refusal, got {other}"),
        Ok(_) => panic!("a daemon at its cap cannot admit an attach"),
    }
}

/// A frame over the daemon's limit is refused with `payload_too_large`,
/// unprompted because the daemon never read the request's id, and the
/// daemon closes: the send waiting on it, and `wait`, report that reason.
#[test]
fn a_send_over_the_daemons_frame_limit_reports_its_reason() {
    let (_daemon, options) = uds_daemon_with(
        "big",
        ConnectionPolicy::default().with_max_message_bytes(1024),
    );
    let mesh = Mesh::attach_with("big", options).expect("attach");
    match mesh.send("c", &[0u8; 4096]) {
        Err(DevError::Daemon { code, message }) => {
            assert_eq!(code, "payload_too_large");
            assert!(message.contains("1024 byte limit"), "{message}");
        }
        other => panic!("expected the daemon's refusal, got {other:?}"),
    }
    assert!(
        matches!(mesh.wait(), Err(DevError::Daemon { ref code, .. }) if code == "payload_too_large"),
        "wait says why the connection ended"
    );
}

/// Every call the connection's end finds waiting reports the daemon's
/// parting reason, however far it got. A fake daemon acks the attach and
/// stops reading, so the client's writer stalls and its queues fill:
/// requests waiting for the writer, calls in the command queue behind them,
/// and the rest of the callers waiting for room there. Then it says
/// `payload_too_large`, unprompted, and closes.
#[test]
fn every_call_still_waiting_reports_the_daemons_parting_reason() {
    const THREADS: usize = 200;
    let (close_tx, close_rx) = mpsc::channel::<()>();
    let (options, daemon) = fake_daemon("parting", move |stream| {
        close_rx.recv().unwrap();
        write_frame(
            stream,
            r#"{"op":"error","code":"payload_too_large","message":"frame of 99 bytes exceeds the 1 byte limit"}"#,
        );
        stream.shutdown(std::net::Shutdown::Both).unwrap();
    });
    let options = options
        .with_rpc_timeout(Duration::from_secs(60))
        .with_heartbeat_interval(Duration::ZERO);
    let mesh = Mesh::attach_with("parting", options).expect("attach");
    let start = Arc::new(Barrier::new(THREADS + 1));
    let callers: Vec<_> = (0..THREADS)
        .map(|call| {
            let mesh = mesh.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                // Larger than the socket's buffer holds, a few of them.
                let payload = vec![b'x'; 16 * 1024];
                start.wait();
                mesh.send(&format!("t{call}"), &payload)
            })
        })
        .collect();
    start.wait();
    // Long enough for every caller to wait somewhere.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        callers.iter().all(|caller| !caller.is_finished()),
        "a daemon that stopped reading answers nothing"
    );
    close_tx.send(()).unwrap();
    for caller in callers {
        let sent = caller.join().unwrap();
        assert!(
            matches!(sent, Err(DevError::Daemon { ref code, .. }) if code == "payload_too_large"),
            "{sent:?}"
        );
    }
    let ended = mesh.wait();
    assert!(
        matches!(ended, Err(DevError::Daemon { ref code, .. }) if code == "payload_too_large"),
        "{ended:?}"
    );
    drop(mesh);
    daemon.join().unwrap();
}

/// An error that answers no request fails no call while the connection
/// lives: the daemon says something unprompted, then answers the send,
/// and the send gets its answer.
#[test]
fn an_unprompted_error_the_daemon_carries_on_after_fails_no_call() {
    let (options, daemon) = fake_daemon("carry", |stream| {
        let send = read_json(stream);
        assert_eq!(send["op"], "send");
        write_frame(
            stream,
            r#"{"op":"error","code":"bad_request","message":"malformed JSON: not this client's"}"#,
        );
        write_frame(
            stream,
            &format!(
                r#"{{"op":"ack","id":{},"envelope_id":"abc","persisted":true}}"#,
                send["id"]
            ),
        );
    });
    let mesh = Mesh::attach_with("carry", options).expect("attach");
    let receipt = mesh
        .send_with_receipt("c", None, b"x")
        .expect("the send's own answer");
    assert_eq!(receipt.envelope_id, "abc");
    assert_eq!(receipt.persisted, Some(true));
    drop(mesh);
    daemon.join().unwrap();
}

/// An event whose payload is not valid base64 never reaches a callback,
/// which would be handed bytes nobody published: it is dropped and
/// counted. A fake daemon sends two such events, then a good one.
#[test]
fn an_event_whose_payload_is_not_base64_is_counted_and_never_delivered() {
    let (options, daemon) = fake_daemon("b64", |stream| {
        let subscribe = read_json(stream);
        assert_eq!(subscribe["op"], "subscribe");
        write_frame(
            stream,
            &format!(
                r#"{{"op":"ack","id":{},"subscription_id":"s"}}"#,
                subscribe["id"]
            ),
        );
        // Padding in mid-string, then no padding, then "hi".
        for payload in ["aGk=aGk=", "aGk", "aGk="] {
            write_frame(
                stream,
                &format!(
                    r#"{{"op":"event","subscription_id":"s","envelope_id":"e","channel":"c","type_id":0,"origin":"o@1","captured_at_unix_nanos":0,"payload":"{payload}"}}"#
                ),
            );
        }
    });
    let mesh = Mesh::attach_with("b64", options).expect("attach");
    let (tx, rx) = mpsc::channel();
    mesh.on("c", move |ev| {
        let _ = tx.send(ev.payload);
    })
    .expect("subscribe");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the good event"),
        b"hi",
        "the malformed events, sent first, were not delivered"
    );
    assert_eq!(mesh.events_malformed(), 2);
    assert_eq!(mesh.events_dropped(), 0, "not a drop for want of room");
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "nothing else was delivered"
    );
    drop(mesh);
    daemon.join().unwrap();
}

/// The WebSocket takes messages as long as the Unix socket does, and no
/// longer: `MAX_INBOUND_MESSAGE` for both, where the WebSocket library's own
/// limit let a message of 64 MiB through in frames of 16 MiB. A fake daemon
/// answers the first send after a message of exactly that length, which the
/// client reads, and the second after one two bytes longer, in two frames
/// each shorter than the limit, which ends the connection.
#[test]
fn a_websocket_message_longer_than_the_limit_ends_the_connection() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    use tokio_tungstenite::tungstenite::Message;

    /// A `health` message, whose state pads it to `len` bytes.
    fn health(len: usize) -> String {
        let (head, tail) = (r#"{"op":"health","node_id":"n@1","state":""#, r#""}"#);
        format!("{head}{}{tail}", "x".repeat(len - head.len() - tail.len()))
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let daemon = runtime.spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // The handshake callback's signature, its large error included, is
        // tungstenite's.
        #[allow(clippy::result_large_err)]
        let subprotocol = |_: &Request, mut response: Response| {
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_static(mesh_port_protocol::WS_SUBPROTOCOL),
            );
            Ok(response)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, subprotocol)
            .await
            .unwrap();
        let mut ops = Vec::new();
        while let Some(Ok(message)) = ws.next().await {
            let Message::Text(text) = message else {
                continue;
            };
            let request: serde_json::Value = serde_json::from_str(&text).unwrap();
            let ack = match request["op"].as_str() {
                Some("attach") => format!(
                    r#"{{"op":"ack","id":{},"node_id":"n@1","protocol_version":"v0"}}"#,
                    request["id"]
                ),
                _ => format!(r#"{{"op":"ack","id":{},"envelope_id":"e"}}"#, request["id"]),
            };
            let op = request["op"].as_str().unwrap_or_default().to_owned();
            let sends = ops.iter().filter(|op| *op == "send").count();
            ops.push(op);
            if request["op"] == "send" {
                let sent = if sends == 0 {
                    // As long as the client takes, in one frame.
                    ws.send(Message::Text(health(MAX_INBOUND_MESSAGE))).await
                } else {
                    // Longer, in two frames that are not.
                    let text = health(MAX_INBOUND_MESSAGE + 2).into_bytes();
                    let (first, rest) = text.split_at(text.len() / 2);
                    let first = Frame::message(first.to_vec(), OpCode::Data(Data::Text), false);
                    let rest = Frame::message(rest.to_vec(), OpCode::Data(Data::Continue), true);
                    match ws.send(Message::Frame(first)).await {
                        Ok(()) => ws.send(Message::Frame(rest)).await,
                        Err(e) => Err(e),
                    }
                };
                if sent.is_err() {
                    break;
                }
            }
            if ws.send(Message::Text(ack)).await.is_err() {
                break;
            }
        }
        ops
    });

    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(format!("ws://{addr}")))
        .with_heartbeat_interval(Duration::ZERO);
    let mesh = Mesh::attach_with("ws-limit", options).expect("attach");
    assert_eq!(
        mesh.send("c", b"x")
            .expect("a message of exactly the limit is read"),
        "e"
    );
    let over = mesh.send("c", b"y");
    assert!(
        matches!(over, Err(DevError::Disconnected)),
        "a longer message ends the connection: {over:?}"
    );
    assert!(matches!(mesh.wait(), Err(DevError::Disconnected)));
    let ops = runtime.block_on(daemon).unwrap();
    assert_eq!(ops, ["attach", "send", "send"]);
}
