// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's WebSocket over TLS: `--ws-tls-cert` and `--ws-tls-key` make it
//! `wss://`, which the Rust client attaches to when it trusts the CA, sending
//! and receiving an event; a plaintext `ws://` client's upgrade fails, and the
//! daemon serves on; one flag without the other is refused (exit status 2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path};
use mesh_client::{Endpoint, Mesh, MeshOptions};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite;

/// A CA's certificate, and a certificate it issued for `localhost` and
/// `127.0.0.1` with its key, each written as PEM into `dir`.
struct Pems {
    ca: String,
    cert: PathBuf,
    key: PathBuf,
}

fn pems(dir: &Path) -> Pems {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let pems = Pems {
        ca: ca.pem(),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    };
    std::fs::write(&pems.cert, cert.pem()).unwrap();
    std::fs::write(&pems.key, key.serialize_pem()).unwrap();
    pems
}

/// A daemon serving `wss://` on a loopback port of its own, its log, and the
/// port.
struct Daemon {
    child: Child,
    log: PathBuf,
    port: u16,
}

impl Daemon {
    fn start(tag: &str, pems: &Pems) -> Self {
        let socket = socket_path(tag);
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name(tag), "--uds-path"])
            .arg(&socket)
            .args(["--ws-bind", "127.0.0.1:0", "--store-slots", "4"])
            .arg("--ws-tls-cert")
            .arg(&pems.cert)
            .arg("--ws-tls-key")
            .arg(&pems.key)
            .env("MESH_HUB_LOG", "info")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("start mesh-hub");
        let deadline = Instant::now() + Duration::from_secs(20);
        let port = loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if let Some(port) = listening_port(&text) {
                break port;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("mesh-hub exited ({status}):\n{text}");
            }
            assert!(Instant::now() < deadline, "mesh-hub never served:\n{text}");
            std::thread::sleep(Duration::from_millis(20));
        };
        Self { child, log, port }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Whether it still runs.
    fn running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// Stop it with SIGTERM, and its exit status.
    fn stop(mut self) -> Option<i32> {
        let sent = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let _ = std::fs::remove_file(&self.log);
                return status.code();
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("mesh-hub did not exit on SIGTERM:\n{}", self.log());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The port of the `websocket listening` line, once it is logged with the
/// `wss` scheme.
fn listening_port(log: &str) -> Option<u16> {
    let line = log
        .lines()
        .find(|l| l.contains("websocket listening") && l.contains("scheme=\"wss\""))?;
    let addr = line.split("addr=").nth(1)?.split_whitespace().next()?;
    addr.parse::<std::net::SocketAddr>().ok().map(|a| a.port())
}

/// The Rust client, trusting the CA, attaches over `wss://` by name and by
/// address; an event one client sends reaches the other's subscription.
#[test]
fn a_wss_client_trusting_the_ca_attaches_sends_and_receives() {
    let dir = tempfile::tempdir().unwrap();
    let pems = pems(dir.path());
    let daemon = Daemon::start("wss-rt", &pems);
    assert!(
        daemon.log().contains("websocket listening, TLS 1.3"),
        "the log does not say the WebSocket is wss:\n{}",
        daemon.log()
    );
    for host in ["localhost", "127.0.0.1"] {
        let options = MeshOptions::default()
            .with_endpoint(Endpoint::Ws(format!("wss://{host}:{}", daemon.port)))
            .with_tls_root_pem(pems.ca.clone());
        let a = Mesh::attach_with("wss-a", options.clone()).expect("attach a over wss");
        let b = Mesh::attach_with("wss-b", options).expect("attach b over wss");
        let (tx, rx) = mpsc::channel();
        a.on("jobs", move |ev| {
            let _ = tx.send((ev.payload, ev.origin));
        })
        .expect("subscribe");
        b.send("jobs", b"sealed in transit").expect("send");
        let (payload, origin) = rx.recv_timeout(Duration::from_secs(5)).expect("event");
        assert_eq!(payload, b"sealed in transit");
        assert!(origin.starts_with("wss-b@"), "{origin}");
        a.detach().expect("detach a");
        b.detach().expect("detach b");
    }
    assert_eq!(daemon.stop(), Some(0));
}

/// A plaintext WebSocket client of the TLS listener fails its upgrade, and
/// the daemon logs the failed TLS handshake and serves the next client.
#[test]
fn a_plaintext_client_of_the_tls_listener_fails_and_the_daemon_serves_on() {
    let dir = tempfile::tempdir().unwrap();
    let pems = pems(dir.path());
    let mut daemon = Daemon::start("wss-pl", &pems);
    let url = format!("ws://127.0.0.1:{}", daemon.port);
    let mut request =
        tungstenite::client::IntoClientRequest::into_client_request(url.as_str()).unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        tungstenite::http::HeaderValue::from_static(mesh_hub::protocol::WS_SUBPROTOCOL),
    );
    let tcp = std::net::TcpStream::connect(("127.0.0.1", daemon.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(
        tungstenite::client::client(request, tcp).is_err(),
        "a plaintext upgrade succeeded against the TLS listener"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !daemon.log().contains("websocket TLS handshake failed") {
        assert!(
            Instant::now() < deadline,
            "no failed handshake in the log:\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(daemon.running(), "the daemon stopped:\n{}", daemon.log());

    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(format!("wss://localhost:{}", daemon.port)))
        .with_tls_root_pem(pems.ca.clone());
    Mesh::attach_with("wss-next", options)
        .expect("a wss client attaches after the plaintext one")
        .detach()
        .expect("detach");
    assert_eq!(daemon.stop(), Some(0));
}

/// One of `--ws-tls-cert` and `--ws-tls-key` without the other is refused as
/// the command line is parsed: exit status 2, naming the missing flag, and
/// no socket made.
#[test]
fn one_tls_flag_without_the_other_exits_2() {
    for (given, missing) in [
        ("--ws-tls-cert", "--ws-tls-key"),
        ("--ws-tls-key", "--ws-tls-cert"),
    ] {
        let socket = socket_path("wss-one");
        let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name("wssone"), "--uds-path"])
            .arg(&socket)
            .args([given, "/nonexistent/tls.pem", "--store-slots", "4"])
            .output()
            .expect("run mesh-hub");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{given}: stderr:\n{stderr}");
        assert!(stderr.contains(missing), "{given}: stderr:\n{stderr}");
        assert!(!socket.exists(), "a refused command line made the socket");
    }
}

/// A certificate file that cannot be read stops the start with status 1 and
/// a log line naming the file, before any socket is made.
#[test]
fn an_unreadable_certificate_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let pems = pems(dir.path());
    let socket = socket_path("wss-bad");
    let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub_name("wssbad"), "--uds-path"])
        .arg(&socket)
        .args(["--ws-bind", "127.0.0.1:0", "--store-slots", "4"])
        .args(["--ws-tls-cert", "/nonexistent/cert.pem", "--ws-tls-key"])
        .arg(&pems.key)
        .output()
        .expect("run mesh-hub");
    let log = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "log:\n{log}");
    assert!(log.contains("/nonexistent/cert.pem"), "log:\n{log}");
    assert!(!socket.exists(), "a refused start made the socket");
}
