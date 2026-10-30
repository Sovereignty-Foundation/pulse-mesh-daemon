// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Liveness against a real daemon: silent clients are dropped after the
//! idle timeout, clients that speak (health frames, pong replies) stay,
//! a handshake that never completes is dropped, an oversized frame is
//! answered with `payload_too_large` before the connection closes, on
//! either transport, and a WebSocket client that closes is answered with
//! a close carrying its own code, as RFC 6455 asks. A client whose
//! subscription sets `health` is told when a peer turns `warning` and when
//! it goes, and of nothing for a peer that keeps speaking; one whose
//! subscriptions do not set it is told nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, small_store, socket_path, Recv, Upp};
use futures_util::{SinkExt, StreamExt};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::protocol::WS_SUBPROTOCOL;
use mesh_hub::ConnectionPolicy;
use std::io::Read;
use std::time::{Duration, Instant};

fn policy(idle_ms: u64, ping_ms: u64, handshake_ms: u64) -> ConnectionPolicy {
    ConnectionPolicy::default()
        .with_ping_interval(Duration::from_millis(ping_ms))
        .with_idle_timeout(Duration::from_millis(idle_ms))
        .with_write_timeout(Duration::from_secs(5))
        .with_handshake_timeout(Duration::from_millis(handshake_ms))
        .with_max_message_bytes(1024)
        .with_subscriber_queue(16)
}

const ATTACH: &str = r#"{"op":"attach","id":"1","name":"probe","protocol_version":"v0"}"#;

/// A frame that keeps a client attached and is not answered.
const HEALTH: &str = r#"{"op":"health","state":"ok"}"#;

/// Attach `client` under `name` and return its `name@suffix`.
fn attach_as(client: &mut Upp, name: &str) -> String {
    client.send(&format!(
        r#"{{"op":"attach","id":"a","name":"{name}","protocol_version":"v0"}}"#
    ));
    let ack = client.recv_json(Duration::from_secs(2));
    assert_eq!(ack["op"], "ack", "attach as {name}: {ack}");
    ack["node_id"].as_str().unwrap().to_string()
}

/// Subscribe `client` with `filter` and check the daemon acknowledged it.
fn subscribe(client: &mut Upp, filter: &str) {
    client.send(&format!(
        r#"{{"op":"subscribe","id":"s","filter":{filter}}}"#
    ));
    let ack = client.recv_json(Duration::from_secs(2));
    assert_eq!(ack["op"], "ack", "subscribe {filter}: {ack}");
}

/// For up to `limit`, keep `client` attached with a health frame every
/// 100 ms, and collect every frame it receives, with when it came, until one
/// that `last` picks out.
fn listen(
    client: &mut Upp,
    limit: Duration,
    last: impl Fn(&serde_json::Value) -> bool,
) -> Vec<(Instant, serde_json::Value)> {
    let deadline = Instant::now() + limit;
    let mut frames = Vec::new();
    while Instant::now() < deadline {
        client.send(HEALTH);
        match client.recv(Duration::from_millis(100)) {
            Recv::Frame(f) => {
                let frame: serde_json::Value = serde_json::from_str(&f).unwrap();
                let done = last(&frame);
                frames.push((Instant::now(), frame));
                if done {
                    break;
                }
            }
            Recv::Timeout => {}
            Recv::Eof => panic!("the daemon dropped a client that kept speaking"),
        }
    }
    frames
}

/// The states of the `health` notices about `node` among `frames`.
fn states(frames: &[(Instant, serde_json::Value)], node: &str) -> Vec<String> {
    frames
        .iter()
        .filter(|(_, f)| f["op"] == "health" && f["node_id"] == node)
        .map(|(_, f)| f["state"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn uds_client_that_stays_silent_is_dropped_after_idle() {
    let path = socket_path("live-idle");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-idle"),
        &[Bind::Uds(path.clone())],
        policy(300, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut client = Upp::connect(&path);
    client.send(ATTACH);
    assert!(
        matches!(client.recv(Duration::from_secs(2)), Recv::Frame(f) if f.contains(r#""op":"ack""#))
    );
    let started = Instant::now();
    assert!(
        matches!(client.recv(Duration::from_secs(3)), Recv::Eof),
        "the daemon dropped it"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "within the idle limit"
    );
    mesh.shutdown();
}

#[test]
fn uds_client_sending_health_stays_attached() {
    let path = socket_path("live-health");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-health"),
        &[Bind::Uds(path.clone())],
        policy(300, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut client = Upp::connect(&path);
    client.send(ATTACH);
    assert!(matches!(
        client.recv(Duration::from_secs(2)),
        Recv::Frame(_)
    ));
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(100));
        client.send(r#"{"op":"health","state":"ok"}"#);
    }
    client.send(r#"{"op":"detach","id":"2"}"#);
    assert!(
        matches!(client.recv(Duration::from_secs(2)), Recv::Frame(f) if f.contains(r#""op":"ack""#)),
        "still attached after a second of heartbeats"
    );
    mesh.shutdown();
}

#[test]
fn oversized_uds_frame_gets_payload_too_large() {
    let path = socket_path("live-big");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-big"),
        &[Bind::Uds(path.clone())],
        policy(0, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut client = Upp::connect(&path);
    client.write_raw(&2048u32.to_be_bytes());
    assert!(
        matches!(client.recv(Duration::from_secs(2)), Recv::Frame(f) if f.contains("payload_too_large")),
        "the refusal names the reason"
    );
    assert!(matches!(client.recv(Duration::from_secs(2)), Recv::Eof));
    mesh.shutdown();
}

/// Send `len` bytes of text to a WebSocket daemon whose frame cap is 1024
/// bytes (`policy`), then return the first text frame it answers with and
/// whether the stream then ended.
fn oversized_ws_message(tag: &str, len: usize) -> (String, bool) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::{self, Message};
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name(tag),
        &[Bind::Ws(any)],
        policy(0, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut request = format!("ws://{}", mesh.ws_addr().unwrap())
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    let (mut ws, _) = tungstenite::connect(request).expect("connect");
    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = ws.get_ref() {
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    }
    // Whether the daemon lets the whole message in before it answers is
    // its business: a write it cut short is not the test's failure.
    let _ = ws.send(Message::Text("x".repeat(len)));
    let mut reply = None;
    // The end of the stream, not a read that timed out.
    let ended = loop {
        match ws.read() {
            Ok(Message::Text(text)) if reply.is_none() => reply = Some(text),
            Ok(Message::Close(_)) => break true,
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break false
            }
            Err(_) => break true,
            Ok(_) => {}
        }
    };
    mesh.shutdown();
    (reply.expect("a reply before the end"), ended)
}

#[test]
fn oversized_ws_message_gets_payload_too_large() {
    for (tag, len) in [("lv-wsbig", 2048), ("lv-wshuge", 4 << 20)] {
        let (reply, ended) = oversized_ws_message(tag, len);
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["op"], "error", "{len}: {reply}");
        assert_eq!(reply["code"], "payload_too_large", "{len}: {reply}");
        let message = reply["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("frame of {len} bytes"))
                && message.contains("1024 byte limit"),
            "the refusal names the size and the limit: {message}"
        );
        assert!(ended, "then the daemon closes");
    }
}

#[test]
fn ws_handshake_that_never_completes_is_dropped() {
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hs"),
        &[Bind::Ws(any)],
        policy(0, 0, 300),
        small_store(),
    )
    .expect("daemon");
    let mut tcp = std::net::TcpStream::connect(mesh.ws_addr().unwrap()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 16];
    assert_eq!(
        tcp.read(&mut buf).ok(),
        Some(0),
        "the daemon closed the socket"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    mesh.shutdown();
}

#[test]
fn ws_client_answering_pings_stays_attached() {
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-ping"),
        &[Bind::Ws(any)],
        policy(300, 100, 5000),
        small_store(),
    )
    .expect("daemon");
    let url = format!("ws://{}", mesh.ws_addr().unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async move {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message;
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(WS_SUBPROTOCOL),
        );
        let (ws, _) = tokio_tungstenite::connect_async(request)
            .await
            .expect("connect");
        let (mut tx, mut rx) = ws.split();
        tx.send(Message::Text(ATTACH.into())).await.unwrap();
        // Polling the stream is what answers the daemon's pings.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut acked = false;
        loop {
            match tokio::time::timeout_at(deadline, rx.next()).await {
                Ok(Some(Ok(Message::Text(t)))) if t.contains(r#""op":"ack""#) => acked = true,
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => panic!("websocket error: {e}"),
                Ok(None) => panic!("the daemon closed a client that answered every ping"),
                Err(_) => break,
            }
        }
        assert!(acked, "the attach was acked");
        tx.send(Message::Text(r#"{"op":"detach","id":"2"}"#.into()))
            .await
            .unwrap();
        // Pings keep arriving on the stream; the ack is the next text frame.
        let ack = loop {
            match tokio::time::timeout(Duration::from_secs(2), rx.next())
                .await
                .expect("a reply in time")
            {
                Some(Ok(Message::Text(t))) => break t,
                Some(Ok(_)) => continue,
                other => panic!("the connection ended before the detach ack: {other:?}"),
            }
        };
        assert!(
            ack.contains(r#""op":"ack""#),
            "detach acked after a second of pings: {ack}"
        );
    });
    mesh.shutdown();
}

#[test]
fn ws_client_that_closes_is_answered_with_its_own_code() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::{self, Message};
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-close"),
        &[Bind::Ws(any)],
        policy(0, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    for code in [CloseCode::Normal, CloseCode::Away, CloseCode::Library(4000)] {
        let mut request = format!("ws://{}", mesh.ws_addr().unwrap())
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(WS_SUBPROTOCOL),
        );
        let (mut ws, _) = tungstenite::connect(request).expect("connect");
        if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = ws.get_ref() {
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        }
        ws.send(Message::Text(ATTACH.into())).unwrap();
        assert!(matches!(ws.read().unwrap(), Message::Text(t) if t.contains(r#""op":"ack""#)));
        ws.close(Some(CloseFrame {
            code,
            reason: "done".into(),
        }))
        .unwrap();
        // The daemon answers with a close of its own, where a stream ending
        // without one would be 1006, abnormal closure.
        let answer = loop {
            match ws.read() {
                Ok(Message::Close(frame)) => break frame,
                Ok(_) => continue,
                Err(e) => panic!("{code}: the stream ended without a close: {e}"),
            }
        };
        assert_eq!(answer.map(|frame| frame.code), Some(code));
        assert!(
            matches!(ws.read(), Err(tungstenite::Error::ConnectionClosed)),
            "then the daemon ends the connection"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while mesh.connections() > 0 {
        assert!(Instant::now() < deadline, "the connections were let go");
        std::thread::sleep(Duration::from_millis(10));
    }
    mesh.shutdown();
}

#[test]
fn a_health_watcher_is_told_a_silent_peer_turns_warning_then_goes() {
    let path = socket_path("live-hwarn");
    // A tick every 200 ms: Warning after a second of silence, give or take
    // a tick, Isolated after 1.6 to 1.8 s, and the connection closed at two.
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hwarn"),
        &[Bind::Uds(path.clone())],
        policy(2000, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut watcher = Upp::connect(&path);
    attach_as(&mut watcher, "watcher");
    subscribe(&mut watcher, r#"{"health":true}"#);
    let mut peer = Upp::connect(&path);
    let node = attach_as(&mut peer, "peer");
    let silent_since = Instant::now();
    let frames = listen(&mut watcher, Duration::from_secs(6), |f| {
        f["state"] == "detached"
    });
    let seen = states(&frames, &node);
    assert_eq!(seen, ["warning", "isolated", "detached"], "{seen:?}");
    assert_eq!(
        frames.len(),
        seen.len(),
        "nothing but notices about the peer: {frames:?}"
    );
    let warned = frames[0].0 - silent_since;
    let gone = frames[frames.len() - 1].0 - silent_since;
    assert!(
        warned >= Duration::from_millis(900) && warned < Duration::from_millis(2000),
        "warning after {warned:?}"
    );
    assert!(
        gone >= Duration::from_millis(1900),
        "detached after {gone:?}"
    );
    assert!(frames[0].1["since_unix_nanos"].as_u64().unwrap() > 0);
    assert!(
        matches!(peer.recv(Duration::from_secs(2)), Recv::Eof),
        "the peer was dropped"
    );
    assert_eq!(
        (
            mesh.nodes_healthy(),
            mesh.nodes_warning(),
            mesh.nodes_isolated()
        ),
        (1, 0, 0)
    );
    mesh.shutdown();
}

#[test]
fn a_peer_that_keeps_sending_health_produces_no_notice() {
    let path = socket_path("live-hquiet");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hquiet"),
        &[Bind::Uds(path.clone())],
        policy(2000, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut watcher = Upp::connect(&path);
    attach_as(&mut watcher, "watcher");
    subscribe(&mut watcher, r#"{"health":true}"#);
    let mut peer = Upp::connect(&path);
    attach_as(&mut peer, "peer");
    // Longer than the second or so of silence that would make it Warning,
    // the peer speaking every 200 ms.
    for _ in 0..12 {
        peer.send(HEALTH);
        let frames = listen(&mut watcher, Duration::from_millis(200), |_| false);
        assert!(frames.is_empty(), "{frames:?}");
    }
    assert_eq!((mesh.nodes_healthy(), mesh.nodes_warning()), (2, 0));
    mesh.shutdown();
}

#[test]
fn a_subscriber_whose_filter_does_not_set_health_is_told_nothing() {
    let path = socket_path("live-hnone");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hnone"),
        &[Bind::Uds(path.clone())],
        policy(1000, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut subscriber = Upp::connect(&path);
    attach_as(&mut subscriber, "subscriber");
    subscribe(&mut subscriber, "{}");
    subscribe(&mut subscriber, r#"{"channel":"jobs/*"}"#);
    let mut peer = Upp::connect(&path);
    attach_as(&mut peer, "peer");
    // The peer turns Warning, then is dropped at the idle timeout.
    let frames = listen(&mut subscriber, Duration::from_millis(1600), |_| false);
    assert!(frames.is_empty(), "{frames:?}");
    assert!(
        matches!(peer.recv(Duration::from_secs(2)), Recv::Eof),
        "the peer was dropped"
    );
    mesh.shutdown();
}

#[test]
fn a_peer_that_detaches_is_told_as_detached() {
    let path = socket_path("live-hdet");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hdet"),
        &[Bind::Uds(path.clone())],
        policy(60_000, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut watcher = Upp::connect(&path);
    attach_as(&mut watcher, "watcher");
    // Two subscriptions ask; the notice comes once.
    subscribe(&mut watcher, r#"{"health":true}"#);
    subscribe(&mut watcher, r#"{"channel":"x","health":true}"#);
    let mut peer = Upp::connect(&path);
    let node = attach_as(&mut peer, "peer");
    assert_eq!(mesh.nodes_healthy(), 2);
    peer.send(r#"{"op":"detach","id":"d"}"#);
    assert_eq!(peer.recv_json(Duration::from_secs(2))["op"], "ack");
    let notice = watcher.recv_json(Duration::from_secs(2));
    assert_eq!(notice["op"], "health", "{notice}");
    assert_eq!(notice["node_id"], node.as_str());
    assert_eq!(notice["state"], "detached");
    assert!(notice["since_unix_nanos"].as_u64().unwrap() > 0);
    assert!(
        matches!(watcher.recv(Duration::from_millis(300)), Recv::Timeout),
        "once"
    );
    assert_eq!(mesh.nodes_healthy(), 1);
    // The watcher's own detach is told to nobody, and leaves nothing tracked.
    watcher.send(r#"{"op":"detach","id":"d"}"#);
    assert_eq!(watcher.recv_json(Duration::from_secs(2))["op"], "ack");
    let deadline = Instant::now() + Duration::from_secs(2);
    while mesh.nodes_healthy() > 0 {
        assert!(Instant::now() < deadline, "the watcher was unregistered");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(mesh.health_notices_dropped(), 0);
    mesh.shutdown();
}

#[test]
fn with_no_idle_timeout_nothing_is_tracked_or_told() {
    let path = socket_path("live-hoff");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hoff"),
        &[Bind::Uds(path.clone())],
        policy(0, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut watcher = Upp::connect(&path);
    attach_as(&mut watcher, "watcher");
    subscribe(&mut watcher, r#"{"health":true}"#);
    let mut peer = Upp::connect(&path);
    attach_as(&mut peer, "peer");
    assert_eq!(mesh.nodes_healthy(), 0);
    peer.send(r#"{"op":"detach","id":"d"}"#);
    assert_eq!(peer.recv_json(Duration::from_secs(2))["op"], "ack");
    assert!(matches!(
        watcher.recv(Duration::from_millis(300)),
        Recv::Timeout
    ));
    mesh.shutdown();
}

#[test]
fn a_peer_that_reports_degraded_is_told_as_degraded_until_it_reports_ok() {
    let path = socket_path("live-hdeg");
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("lv-hdeg"),
        &[Bind::Uds(path.clone())],
        policy(5000, 0, 5000),
        small_store(),
    )
    .expect("daemon");
    let mut peer = Upp::connect(&path);
    let node = attach_as(&mut peer, "peer");
    peer.send(r#"{"op":"health","state":"degraded"}"#);
    // A watcher that subscribes afterwards is told at once.
    let mut watcher = Upp::connect(&path);
    attach_as(&mut watcher, "watcher");
    subscribe(&mut watcher, r#"{"health":true}"#);
    let frames = listen(&mut watcher, Duration::from_millis(500), |f| {
        f["state"] == "degraded"
    });
    assert_eq!(states(&frames, &node), ["degraded"], "{frames:?}");
    assert_eq!(mesh.nodes_degraded(), 1);
    // Other frames keep it degraded; a health frame saying ok ends it.
    peer.send(r#"{"op":"send","id":"x","channel":"c","payload":"aGk="}"#);
    peer.send(r#"{"op":"health","state":"ok"}"#);
    let frames = listen(&mut watcher, Duration::from_secs(2), |f| {
        f["state"] == "healthy"
    });
    assert_eq!(states(&frames, &node), ["healthy"], "{frames:?}");
    assert_eq!((mesh.nodes_degraded(), mesh.nodes_healthy()), (0, 2));
    mesh.shutdown();
}
