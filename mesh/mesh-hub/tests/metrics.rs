// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon serves its counts at `GET /metrics` on `--metrics-bind`, in the
//! Prometheus text format, and only there: another path is 404, another method
//! 405, and an address other than loopback is refused without
//! `--metrics-allow-remote`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path, Upp};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A daemon serving the Unix socket and the metrics on a free loopback port,
/// with the address the metrics listener logged.
struct Daemon {
    child: Child,
    log: std::path::PathBuf,
    socket: std::path::PathBuf,
    metrics: SocketAddr,
}

impl Daemon {
    fn start(tag: &str) -> Self {
        let socket = socket_path(tag);
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name(tag), "--uds-path"])
            .arg(&socket)
            .args([
                "--no-ws",
                "--store-slots",
                "4",
                "--metrics-bind",
                "127.0.0.1:0",
            ])
            .env("MESH_HUB_LOG", "info")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("start mesh-hub");
        let deadline = Instant::now() + Duration::from_secs(20);
        let metrics = loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let addr = text
                .lines()
                .find(|l| l.contains("metrics listening"))
                .and_then(|l| l.split("addr=").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|a| a.parse().ok());
            if let (Some(addr), true) = (addr, UnixStream::connect(&socket).is_ok()) {
                break addr;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("mesh-hub exited ({status}):\n{text}");
            }
            assert!(Instant::now() < deadline, "mesh-hub never served:\n{text}");
            std::thread::sleep(Duration::from_millis(20));
        };
        Self {
            child,
            log,
            socket,
            metrics,
        }
    }

    /// One HTTP request to the metrics address, and the whole response.
    fn request(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(self.metrics).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    /// The value of the sample `line` names, from a scrape.
    fn sample(&self, line: &str) -> u64 {
        let page = self.request("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
        page.lines()
            .find_map(|l| l.strip_prefix(line).and_then(|v| v.strip_prefix(' ')))
            .unwrap_or_else(|| panic!("no {line} in:\n{page}"))
            .parse()
            .unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

#[test]
fn the_metrics_are_served_in_the_prometheus_format_and_follow_the_daemon() {
    let daemon = Daemon::start("metrics");
    let page = daemon.request("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let (head, body) = page.split_once("\r\n\r\n").expect("a head and a body");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(
        head.contains("Content-Type: text/plain; version=0.0.4"),
        "{head}"
    );
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "{head}"
    );
    for family in [
        "pms_daemon_connections",
        "pms_daemon_attached",
        "pms_daemon_nodes",
        "pms_daemon_sends_total",
        "pms_daemon_subscriptions",
        "pms_daemon_events_dropped_total",
    ] {
        assert!(
            body.contains(&format!("# TYPE {family} ")),
            "{family}:\n{body}"
        );
    }
    assert_eq!(daemon.sample("pms_daemon_sends_total"), 0);
    assert_eq!(daemon.sample("pms_daemon_attached"), 0);

    // One client attaches and sends; the counts follow.
    let mut client = Upp::connect(&daemon.socket);
    client.send(r#"{"op":"attach","id":"a","name":"scraped","protocol_version":"v0"}"#);
    assert_eq!(client.recv_json(Duration::from_secs(2))["op"], "ack");
    client.send(r#"{"op":"send","id":"s","channel":"m/one","payload":"aGk="}"#);
    assert_eq!(client.recv_json(Duration::from_secs(2))["op"], "ack");
    assert_eq!(daemon.sample("pms_daemon_sends_total"), 1);
    assert_eq!(daemon.sample("pms_daemon_attached"), 1);
    assert_eq!(daemon.sample(r#"pms_daemon_nodes{state="healthy"}"#), 1);
}

#[test]
fn only_get_metrics_is_answered() {
    let daemon = Daemon::start("metpath");
    let other = daemon.request("GET / HTTP/1.1\r\n\r\n");
    assert!(other.starts_with("HTTP/1.1 404 Not Found"), "{other}");
    let post = daemon.request("POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert!(
        post.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "{post}"
    );
    let query = daemon.request("GET /metrics?x=1 HTTP/1.1\r\n\r\n");
    assert!(query.starts_with("HTTP/1.1 200 OK"), "{query}");
}

#[test]
fn metrics_off_loopback_are_refused_without_metrics_allow_remote() {
    let socket = socket_path("metrics-remote");
    let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name("metrrem"), "--uds-path"])
        .arg(&socket)
        .args(["--no-ws", "--metrics-bind", "0.0.0.0:0"])
        .output()
        .expect("run mesh-hub");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(
        stderr.contains("--metrics-allow-remote"),
        "stderr:\n{stderr}"
    );
}
