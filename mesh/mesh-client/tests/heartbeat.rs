// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An idle client keeps the connection alive with `health` frames.
//!
//! A fake daemon acks the attach and then counts the frames it receives
//! while the client does nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{Endpoint, Mesh, MeshOptions};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

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

/// Read one length-prefixed frame; `None` on timeout or EOF.
fn read_frame(stream: &mut UnixStream) -> Option<String> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).ok()?;
    String::from_utf8(body).ok()
}

fn write_frame(stream: &mut UnixStream, body: &str) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn an_idle_client_heartbeats() {
    let path = sock("hb");
    let listener = UnixListener::bind(&path).unwrap();
    let counter = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let attach = read_frame(&mut stream).expect("the attach frame");
        let attach: serde_json::Value = serde_json::from_str(&attach).unwrap();
        assert_eq!(attach["op"], "attach");
        let id = attach["id"].as_str().unwrap().to_string();
        write_frame(
            &mut stream,
            &format!(r#"{{"op":"ack","id":"{id}","node_id":"n@1","protocol_version":"v0"}}"#),
        );
        let deadline = Instant::now() + Duration::from_millis(700);
        let mut health = 0;
        while Instant::now() < deadline {
            if let Some(frame) = read_frame(&mut stream) {
                if frame.contains(r#""op":"health""#) {
                    health += 1;
                }
            }
        }
        health
    });
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Uds(path.to_string_lossy().into_owned()))
        .with_heartbeat_interval(Duration::from_millis(100))
        .with_rpc_timeout(Duration::from_secs(2));
    let mesh = Mesh::attach_with("idle", options).expect("attach");
    let health = counter.join().unwrap();
    assert!(
        health >= 3,
        "expected at least 3 health frames in 700 ms, got {health}"
    );
    drop(mesh);
    let _ = std::fs::remove_file(&path);
}
