// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What a connection holds besides its queued events is the message it is
//! reading, at most `max_message_bytes`, and nothing of a message once it has
//! been handled. A counting allocator measures the heap, so this file holds one
//! test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod heap;

use common::{hub_name, small_store, socket_path, Upp};
use mesh_hub::embed::{Bind, EmbeddedMesh};
use mesh_hub::internals::MAX_QUOTED;
use mesh_hub::protocol::WS_SUBPROTOCOL;
use mesh_hub::ConnectionPolicy;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// The cap on a message, `max_message_bytes`.
const MAX: usize = 256 * 1024;
/// Connections on each transport.
const N: usize = 16;
/// What a connection may hold between messages, besides the queued events:
/// its read buffer (8 KiB on either transport), its task and its queue.
const IDLE: usize = 24 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Heap bytes the process holds: the daemon's, and the test's own.
fn live() -> usize {
    heap::LIVE.load(Ordering::Relaxed)
}

/// The heap once the daemon has taken in what it was sent.
fn settled() -> usize {
    std::thread::sleep(Duration::from_millis(400));
    live()
}

/// A client's WebSocket frame: `first` holds the final bit and the opcode;
/// the payload is masked, as a client's must be.
fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    const MASK: [u8; 4] = [0x1f, 0x2e, 0x3d, 0x4c];
    let mut frame = vec![first];
    match payload.len() {
        len @ 0..=125 => frame.push(0x80 | len as u8),
        len @ 126..=0xffff => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&MASK);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
    frame
}

/// A Unix-socket frame.
fn uds_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

/// A WebSocket client over a plain socket, whose frames are bytes built
/// before the measurement, so that it allocates next to nothing while the
/// daemon is measured.
struct RawWs(TcpStream);

impl RawWs {
    fn connect(addr: SocketAddr) -> Self {
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        write!(
            tcp,
            "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: {WS_SUBPROTOCOL}\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 101"), "{response:?}");
        Self(tcp)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).unwrap();
    }

    /// The next text message the daemon sends, or `None` once it closes.
    fn text(&mut self) -> Option<String> {
        loop {
            let mut head = [0u8; 2];
            self.0.read_exact(&mut head).ok()?;
            let len = match head[1] & 0x7f {
                126 => {
                    let mut len = [0u8; 2];
                    self.0.read_exact(&mut len).unwrap();
                    usize::from(u16::from_be_bytes(len))
                }
                127 => {
                    let mut len = [0u8; 8];
                    self.0.read_exact(&mut len).unwrap();
                    u64::from_be_bytes(len) as usize
                }
                short => usize::from(short),
            };
            let mut payload = vec![0u8; len];
            self.0.read_exact(&mut payload).unwrap();
            match head[0] & 0x0f {
                0x1 => return Some(String::from_utf8(payload).unwrap()),
                0x8 => return None,
                _ => {}
            }
        }
    }
}

/// The requests each connection sends, built before anything is measured:
/// an attach, then three messages of nearly `MAX` bytes (a health frame the
/// daemon does not answer, an unsubscribe whose error quotes the id, and a
/// send), and a fourth of exactly `MAX` bytes, sent all but its last byte.
struct Requests {
    attach: Vec<String>,
    large: [String; 3],
    at_cap: String,
}

impl Requests {
    fn new() -> Self {
        // `template` with its `PAD` made `fill`, as many as leave the text
        // 16 bytes short of the cap, rounded down to a multiple of four.
        let near_cap = |template: &str, fill: &str| {
            let room = MAX - 16 - (template.len() - 3);
            template.replace("PAD", &fill.repeat(room - room % 4))
        };
        let health = r#"{"op":"health","state":"PAD"}"#;
        let at_cap = health.replace("PAD", &"q".repeat(MAX - (health.len() - 3)));
        assert_eq!(at_cap.len(), MAX);
        Self {
            attach: (0..2 * N)
                .map(|i| {
                    format!(r#"{{"op":"attach","id":"a","name":"mem{i}","protocol_version":"v0"}}"#)
                })
                .collect(),
            large: [
                near_cap(health, "h"),
                near_cap(
                    r#"{"op":"unsubscribe","id":"u","subscription_id":"PAD"}"#,
                    "z",
                ),
                near_cap(
                    r#"{"op":"send","id":"s","channel":"mem","payload":"PAD"}"#,
                    "A",
                ),
            ],
            at_cap,
        }
    }
}

/// Check that `reply` is the error an unsubscribe of an unknown, enormous
/// id gets, quoting a small part of it.
fn check_unknown_subscription(reply: &str) {
    let reply: serde_json::Value = serde_json::from_str(reply).unwrap();
    assert_eq!(reply["code"], "unknown_subscription", "{reply}");
    let message = reply["message"].as_str().unwrap();
    assert!(
        message.len() <= MAX_QUOTED + 64 && message.contains(" bytes)"),
        "the error quotes the id only in part: {message}"
    );
}

#[test]
fn a_connection_holds_the_message_it_reads_and_nothing_once_it_is_handled() {
    let path = socket_path("mem-conn");
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::ZERO)
        .with_idle_timeout(Duration::ZERO)
        .with_write_timeout(Duration::from_secs(5))
        .with_max_message_bytes(MAX);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mesh = EmbeddedMesh::start_with_config(
        &hub_name("mem-conn"),
        &[Bind::Uds(path.clone()), Bind::Ws(any)],
        policy,
        small_store(),
    )
    .expect("daemon");
    let addr = mesh.ws_addr().unwrap();
    let requests = Requests::new();
    let ws_large: Vec<Vec<u8>> = requests
        .large
        .iter()
        .map(|text| client_frame(0x81, text.as_bytes()))
        .collect();
    let uds_large: Vec<Vec<u8>> = requests
        .large
        .iter()
        .map(|text| uds_frame(text.as_bytes()))
        .collect();
    let ws_at_cap = client_frame(0x81, requests.at_cap.as_bytes());
    let uds_at_cap = uds_frame(requests.at_cap.as_bytes());
    // A fragmented message: a first fragment of all but 2,000 bytes of the
    // cap, then a continuation whose header takes it over.
    let first_fragment = client_frame(0x01, &vec![b'f'; MAX - 2000]);
    let over = client_frame(0x80, &vec![b'g'; 4000]);
    let baseline = settled();

    // Each connection carries three messages near the cap and keeps none of
    // them, nor the replies: the error quotes the enormous id in part.
    let mut ws: Vec<RawWs> = (0..N)
        .map(|i| {
            let mut client = RawWs::connect(addr);
            client.write(&client_frame(0x81, requests.attach[i].as_bytes()));
            assert!(client.text().unwrap().contains(r#""op":"ack""#));
            client.write(&ws_large[0]);
            client.write(&ws_large[1]);
            check_unknown_subscription(&client.text().unwrap());
            client.write(&ws_large[2]);
            assert!(client.text().unwrap().contains(r#""op":"ack""#));
            client
        })
        .collect();
    let mut uds: Vec<Upp> = (0..N)
        .map(|i| {
            let mut client = Upp::connect(&path);
            client.send(&requests.attach[N + i]);
            assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");
            client.write_raw(&uds_large[0]);
            client.write_raw(&uds_large[1]);
            check_unknown_subscription(&client.frame(TIMEOUT).unwrap());
            client.write_raw(&uds_large[2]);
            assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");
            client
        })
        .collect();
    let idle = settled();
    let per_connection = idle.saturating_sub(baseline) / (2 * N);
    assert!(
        per_connection <= IDLE,
        "{per_connection} bytes held per connection once its messages were handled"
    );

    // A message being read holds at most the cap on a WebSocket; the Unix
    // socket's decoder may reserve up to twice what has arrived.
    for client in &mut ws {
        client.write(&ws_at_cap[..ws_at_cap.len() - 1]);
    }
    let reading = settled().saturating_sub(idle) / N;
    assert!(
        reading <= MAX + IDLE,
        "{reading} bytes held per WebSocket for a message of {MAX} bytes being read"
    );
    let before_uds = live();
    for client in &mut uds {
        client.write_raw(&uds_at_cap[..uds_at_cap.len() - 1]);
    }
    let reading = settled().saturating_sub(before_uds) / N;
    assert!(
        reading <= 2 * (MAX + 8 * 1024) + IDLE,
        "{reading} bytes held per Unix socket for a message of {MAX} bytes being read"
    );
    // Once the last byte arrives and the message is handled, it is all let
    // go.
    for client in &mut ws {
        client.write(&ws_at_cap[ws_at_cap.len() - 1..]);
    }
    for client in &mut uds {
        client.write_raw(&uds_at_cap[uds_at_cap.len() - 1..]);
    }
    let after = settled();
    assert!(
        after <= idle + N * 1024,
        "{} bytes more held after the messages were handled",
        after.saturating_sub(idle)
    );

    // An unfinished fragmented message counts against the same cap as the
    // frame being read: the header that takes it over is refused, and the
    // connection closes.
    let mut fragmented: Vec<RawWs> = (0..N)
        .map(|_| {
            let mut client = RawWs::connect(addr);
            client.write(&first_fragment);
            client
        })
        .collect();
    let holding = settled().saturating_sub(after) / N;
    assert!(
        holding <= MAX + IDLE,
        "{holding} bytes held per WebSocket for a fragment of {} bytes",
        MAX - 2000
    );
    for client in &mut fragmented {
        client.write(&over[..over.len() / 2]);
        let reply: serde_json::Value = serde_json::from_str(&client.text().unwrap()).unwrap();
        assert_eq!(reply["code"], "payload_too_large", "{reply}");
        assert!(
            reply["message"]
                .as_str()
                .unwrap()
                .contains(&format!("frame of {} bytes", MAX - 2000 + 4000)),
            "{reply}"
        );
        assert!(client.text().is_none(), "then the daemon closes");
    }
    drop(fragmented);
    std::thread::sleep(Duration::from_millis(1200));
    let closed = settled();
    assert!(
        closed <= after + N * 1024,
        "{} bytes still held after the refused connections closed",
        closed.saturating_sub(after)
    );
    drop((ws, uds));
    mesh.shutdown();
}
