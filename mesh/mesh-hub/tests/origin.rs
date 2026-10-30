// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The WebSocket serves web pages from this machine and from the origins it
//! was given, and no others. An upgrade whose `Origin` names another site,
//! as a browser's does for a page on that site, is answered 403 before it
//! completes, counted, and reads nothing the Unix socket's clients publish;
//! an upgrade without an `Origin` (a client that is not a page), a page
//! served from localhost and a page from an allowed origin are admitted;
//! and the Unix socket carries on as before.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, small_store, socket_path, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::protocol::WS_SUBPROTOCOL;
use mesh_hub::AllowedOrigin;
use mesh_hub::ConnectionPolicy;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::stream::MaybeTlsStream;
use tokio_tungstenite::tungstenite::{self, Message, WebSocket};

const TIMEOUT: Duration = Duration::from_secs(5);

type WsClient = WebSocket<MaybeTlsStream<TcpStream>>;

/// A mesh answering on a private Unix socket and on a WebSocket at a free
/// loopback port, whose policy allows `allowed` besides the loopback
/// origins.
fn mesh(tag: &str, allowed: &[&str]) -> (EmbeddedMesh, PathBuf, SocketAddr) {
    let path = socket_path(tag);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let policy = ConnectionPolicy::default().with_allowed_origins(
        allowed
            .iter()
            .map(|origin| AllowedOrigin::parse(origin).unwrap())
            .collect(),
    );
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name(tag),
        &[Bind::Uds(path.clone()), Bind::Ws(any)],
        policy,
        small_store(),
    )
    .expect("daemon");
    let addr = mesh.ws_addr().unwrap();
    (mesh, path, addr)
}

/// Open a WebSocket announcing the protocol's subprotocol and, when given,
/// an `Origin`; a refused upgrade yields its HTTP status.
fn ws_connect(addr: SocketAddr, origin: Option<&str>) -> Result<WsClient, u16> {
    let mut request = format!("ws://{addr}").into_client_request().unwrap();
    let headers = request.headers_mut();
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    if let Some(origin) = origin {
        headers.insert("Origin", HeaderValue::from_str(origin).unwrap());
    }
    match tungstenite::connect(request) {
        Ok((ws, _)) => {
            if let MaybeTlsStream::Plain(tcp) = ws.get_ref() {
                tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
            }
            Ok(ws)
        }
        Err(tungstenite::Error::Http(response)) => Err(response.status().as_u16()),
        Err(e) => panic!("websocket connect failed: {e}"),
    }
}

/// The next text frame, parsed.
fn next_text(ws: &mut WsClient) -> serde_json::Value {
    loop {
        match ws.read().expect("a frame in time") {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Close(frame) => panic!("closed: {frame:?}"),
            _ => {}
        }
    }
}

/// Send one message and return the reply.
fn request(ws: &mut WsClient, json: &str) -> serde_json::Value {
    ws.send(Message::Text(json.to_string())).unwrap();
    next_text(ws)
}

/// A Unix-socket client attached as `name` publishes what a page must not
/// read unless the daemon admitted it: `secrets/db`, "hunter2".
fn publish_secret(path: &Path, name: &str) {
    let mut owner = Upp::connect(path);
    owner.attach(name);
    owner.send(r#"{"op":"send","id":"p","channel":"secrets/db","payload":"aHVudGVyMg=="}"#);
    assert_eq!(owner.recv_json(TIMEOUT)["op"], "ack");
}

/// The admitted page attaches as `name`, subscribes to everything, and
/// reads what a Unix-socket client publishes.
fn reads_what_the_socket_publishes(mut ws: WsClient, path: &Path, name: &str) {
    let attach = format!(r#"{{"op":"attach","id":"a","name":"{name}","protocol_version":"v0"}}"#);
    assert_eq!(request(&mut ws, &attach)["op"], "ack");
    let subscribed = request(&mut ws, r#"{"op":"subscribe","id":"s","filter":{}}"#);
    assert_eq!(subscribed["op"], "ack", "{subscribed}");
    publish_secret(path, &format!("{name}-owner"));
    let event = next_text(&mut ws);
    assert_eq!(event["op"], "event", "{event}");
    assert_eq!(event["channel"], "secrets/db");
    assert_eq!(event["payload"], "aHVudGVyMg==");
}

/// Wait until `n` connections hold a place: a refused upgrade's place is
/// freed when its task ends.
fn wait_for_connections(mesh: &EmbeddedMesh, n: usize) {
    let deadline = Instant::now() + TIMEOUT;
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
fn a_page_from_another_site_is_refused_before_the_upgrade_and_reads_nothing() {
    let (mesh, path, addr) = mesh("or-evil", &[]);

    // A Unix-socket client is subscribed to everything throughout.
    let mut reader = Upp::connect(&path);
    reader.attach("reader");
    reader.send(r#"{"op":"subscribe","id":"s","filter":{}}"#);
    assert_eq!(reader.recv_json(TIMEOUT)["op"], "ack");

    // The upgrade a browser sends for a script on https://evil.example.
    let mut page = TcpStream::connect(addr).unwrap();
    page.set_read_timeout(Some(TIMEOUT)).unwrap();
    write!(
        page,
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {WS_SUBPROTOCOL}\r\nOrigin: https://evil.example\r\n\r\n"
    )
    .unwrap();

    // While it waits, the owner publishes over the Unix socket.
    publish_secret(&path, "owner");

    // The page gets a 403 and then the end of the stream: no upgrade, so
    // it never attached or subscribed, and nothing it could read.
    let mut answer = Vec::new();
    page.read_to_end(&mut answer).unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    assert!(
        !answer.contains("Switching Protocols")
            && !answer.contains("secrets/db")
            && !answer.contains("aHVudGVy"),
        "{answer}"
    );
    assert!(
        !answer.contains("evil.example"),
        "the refusal does not echo the origin: {answer}"
    );
    assert_eq!(mesh.origins_refused(), 1, "the refusal is counted");

    // A client library sees the same refusal.
    assert_eq!(
        ws_connect(addr, Some("https://evil.example")).err(),
        Some(403)
    );
    assert_eq!(
        ws_connect(addr, Some("null")).err(),
        Some(403),
        "a sandboxed frame's opaque origin"
    );
    assert_eq!(mesh.origins_refused(), 3);
    assert_eq!(
        mesh.connections_refused(),
        0,
        "not a connection-cap refusal"
    );

    // The Unix socket carried on: its subscriber got the owner's envelope,
    // and the refused upgrades hold no place.
    let event = reader.recv_json(TIMEOUT);
    assert_eq!(event["op"], "event", "{event}");
    assert_eq!(event["channel"], "secrets/db");
    wait_for_connections(&mesh, 1);
    publish_secret(&path, "owner-again");
    assert_eq!(reader.recv_json(TIMEOUT)["channel"], "secrets/db");
    mesh.shutdown();
}

#[test]
fn a_client_that_sends_no_origin_is_admitted() {
    let (mesh, path, addr) = mesh("or-none", &[]);
    let ws = ws_connect(addr, None).expect("a client that is not a page is admitted");
    reads_what_the_socket_publishes(ws, &path, "no-origin");
    assert_eq!(mesh.origins_refused(), 0);
    mesh.shutdown();
}

#[test]
fn a_page_served_from_this_machine_is_admitted() {
    let (mesh, path, addr) = mesh("or-local", &[]);
    for (i, origin) in [
        "http://localhost:8000",
        "http://127.0.0.1:8090",
        "https://[::1]:8443",
    ]
    .into_iter()
    .enumerate()
    {
        let ws = ws_connect(addr, Some(origin))
            .unwrap_or_else(|status| panic!("{origin} was refused with {status}"));
        reads_what_the_socket_publishes(ws, &path, &format!("local-{i}"));
    }
    assert_eq!(mesh.origins_refused(), 0);
    mesh.shutdown();
}

#[test]
fn an_allowed_origin_is_admitted_and_no_other() {
    let (mesh, path, addr) = mesh("or-allow", &["https://app.example"]);
    let ws = ws_connect(addr, Some("https://app.example")).expect("the allowed origin");
    reads_what_the_socket_publishes(ws, &path, "allowed");
    for other in [
        "https://app.example:8443",
        "http://app.example",
        "https://evil.example",
    ] {
        assert_eq!(ws_connect(addr, Some(other)).err(), Some(403), "{other}");
    }
    assert_eq!(mesh.origins_refused(), 3);
    mesh.shutdown();
}
