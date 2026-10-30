// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon holds at most its policy's `max_connections` at once, counted
//! across both transports: a connection past the cap is refused at once, on
//! the Unix socket with an unprompted `limit_exceeded` error frame naming
//! the flag and on the WebSocket with HTTP 503 before the upgrade is read,
//! the refusal is counted, a refused connection holds no descriptor once
//! its refusal is written, and a connection that closes frees its place.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, small_store, socket_path, Recv, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::protocol::WS_SUBPROTOCOL;
use mesh_hub::ConnectionPolicy;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::stream::MaybeTlsStream;
use tokio_tungstenite::tungstenite::{self, WebSocket};

const TIMEOUT: Duration = Duration::from_secs(2);

type WsClient = WebSocket<MaybeTlsStream<TcpStream>>;

/// Open a WebSocket to the daemon, announcing the protocol's subprotocol;
/// a refused upgrade yields its HTTP status.
fn ws_connect(addr: SocketAddr) -> Result<WsClient, u16> {
    let mut request = format!("ws://{addr}").into_client_request().unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    match tungstenite::connect(request) {
        Ok((ws, _)) => Ok(ws),
        Err(tungstenite::Error::Http(response)) => Err(response.status().as_u16()),
        Err(e) => panic!("websocket connect failed: {e}"),
    }
}

/// A Unix-socket connection to the daemon is turned away: one unprompted
/// `limit_exceeded` error naming the limit and the flag, then the end of
/// the stream.
fn assert_uds_refused(path: &Path, limit: usize) {
    let mut client = Upp::connect(path);
    let Recv::Frame(text) = client.recv(TIMEOUT) else {
        panic!("a refused connection is told why");
    };
    let reply: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(reply["op"], "error", "{reply}");
    assert_eq!(reply["code"], "limit_exceeded", "{reply}");
    assert!(reply.get("id").is_none(), "unprompted, so no id: {reply}");
    let message = reply["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("at most {limit} connections"))
            && message.contains("--max-connections"),
        "the message names the limit and the flag: {message}"
    );
    assert!(
        matches!(client.recv(TIMEOUT), Recv::Eof),
        "then the daemon closes"
    );
}

/// Wait for the daemon to see a close: a place is freed once the
/// connection's task has noticed the end of its stream.
fn wait_for_connections(mesh: &EmbeddedMesh, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while mesh.connections() != n {
        assert!(
            Instant::now() < deadline,
            "{} connections, waiting for {n}",
            mesh.connections()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_connection_past_the_cap_is_refused_on_either_transport_until_one_closes() {
    let path = socket_path("conn-cap");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let policy = ConnectionPolicy::default().with_max_connections(2);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("conn-cap"),
        &[Bind::Uds(path.clone()), Bind::Ws(any)],
        policy,
        small_store(),
    )
    .expect("daemon");
    let ws_addr = mesh.ws_addr().unwrap();

    // One connection on each transport fills a cap of two: the count spans
    // both.
    let mut uds = Upp::connect(&path);
    uds.attach("uds-one");
    let ws = ws_connect(ws_addr).expect("the second connection is admitted");
    assert_eq!(mesh.connections(), 2);

    // A third is refused on either transport, at once and with the reason.
    assert_uds_refused(&path, 2);
    assert_eq!(
        ws_connect(ws_addr).err(),
        Some(503),
        "the upgrade is refused"
    );
    assert_eq!(mesh.connections_refused(), 2, "each refusal is counted");
    assert_eq!(mesh.connections(), 2, "a refusal takes no place");

    // A connection that closes frees its place, whichever transport takes
    // it next.
    drop(uds);
    wait_for_connections(&mesh, 1);
    let ws_two = ws_connect(ws_addr).expect("the place the socket client freed");
    drop(ws);
    wait_for_connections(&mesh, 1);
    let mut uds_two = Upp::connect(&path);
    uds_two.attach("uds-two");
    assert_eq!(mesh.connections(), 2);
    assert_eq!(mesh.connections_refused(), 2);
    drop(ws_two);
    mesh.shutdown();
}

/// The descriptors this process has open: its clients' and, the mesh being
/// embedded, the daemon's.
fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

#[test]
fn a_websocket_past_the_cap_is_refused_and_closed_before_it_says_anything() {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let policy = ConnectionPolicy::default().with_max_connections(1);
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("conn-fds"),
        &[Bind::Ws(any)],
        policy,
        small_store(),
    )
    .expect("daemon");
    let addr = mesh.ws_addr().unwrap();
    let _held = ws_connect(addr).expect("the one place");

    // Connections that never send an upgrade: each was read for up to the
    // five-second handshake deadline before it was answered, holding a
    // descriptor in the daemon all the while.
    let before = open_fds();
    let silent: Vec<TcpStream> = (0..200)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();
    for mut client in &silent {
        client.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut reply = String::new();
        client
            .read_to_string(&mut reply)
            .expect("refused and closed within the timeout");
        assert!(
            reply.starts_with("HTTP/1.1 503 Service Unavailable\r\n")
                && reply.contains("--max-connections"),
            "{reply}"
        );
    }
    // Only this side's ends are open; the daemon's are closed.
    let deadline = Instant::now() + TIMEOUT;
    while open_fds() > before + silent.len() + 16 {
        assert!(
            Instant::now() < deadline,
            "{} descriptors open for {} refused connections",
            open_fds() - before,
            silent.len()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(mesh.connections(), 1);
    assert_eq!(mesh.connections_refused(), 200);
    drop(silent);
    mesh.shutdown();
}
