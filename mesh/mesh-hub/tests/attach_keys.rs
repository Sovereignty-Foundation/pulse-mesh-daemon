// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon with `--attach-keys`: a client with a listed key attaches over
//! `ws://` and `wss://` and is named by the key; a keyless attach on the
//! WebSocket, a key not listed, a wrong signature, a proof replayed on a
//! second connection, a proof on `wss://` that ignores the TLS exporter and
//! a challenge left unanswered past `--handshake-timeout-secs` are each
//! refused with `auth_failed` and the connection closed; the Unix socket
//! admits its owner without a key unless `--attach-keys-uds`; a WebSocket
//! off loopback starts without `--ws-allow-remote` with TLS and attach keys
//! both, and is refused (exit status 2) with either alone; a malformed list
//! stops the start (exit status 1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hub_name, socket_path};
use mesh_client::identity::{generate_key_file, public_key_text};
use mesh_client::{DevError, Endpoint, Mesh, MeshOptions, SigningKey};
use mesh_hub::protocol::{attach, base64, WS_SUBPROTOCOL};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::{self, Message};

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

/// Two key files in `dir`, the first listed in `dir/attach.keys`, and the
/// list's path.
struct Keys {
    listed: PathBuf,
    unlisted: PathBuf,
    list: PathBuf,
}

fn keys(dir: &Path) -> Keys {
    let listed = dir.join("listed.key");
    let unlisted = dir.join("unlisted.key");
    let key = generate_key_file(&listed).unwrap();
    generate_key_file(&unlisted).unwrap();
    let list = dir.join("attach.keys");
    std::fs::write(
        &list,
        format!("# the one client\n{} # listed\n", public_key_text(&key)),
    )
    .unwrap();
    Keys {
        listed,
        unlisted,
        list,
    }
}

/// A daemon run for a test, its log, its socket and its WebSocket's port.
struct Daemon {
    child: Child,
    log: PathBuf,
    socket: PathBuf,
    port: u16,
}

impl Daemon {
    /// Start `mesh-hub` with `args` on a socket and a hub name of its own,
    /// and wait until it serves the WebSocket.
    fn start(tag: &str, args: &[&str]) -> Self {
        let socket = socket_path(tag);
        let log = socket.with_extension("log");
        let out = File::create(&log).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name(tag), "--uds-path"])
            .arg(&socket)
            .args(["--store-slots", "4"])
            .args(args)
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
        Self {
            child,
            log,
            socket,
            port,
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
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

/// The port of the `websocket listening` line, once it is logged.
fn listening_port(log: &str) -> Option<u16> {
    let line = log.lines().find(|l| l.contains("websocket listening"))?;
    let addr = line.split("addr=").nth(1)?.split_whitespace().next()?;
    addr.parse::<std::net::SocketAddr>().ok().map(|a| a.port())
}

/// A raw client's stream: TCP, or TLS over it.
trait Stream: Read + Write {}
impl<S: Read + Write> Stream for S {}

/// A raw WebSocket client of the port protocol, and the TLS exporter value
/// of its connection (zeros in plaintext).
struct Raw {
    ws: tungstenite::WebSocket<Box<dyn Stream>>,
    exporter: [u8; 32],
}

impl Raw {
    /// Connect to `port`, over TLS trusting `ca` when it is given.
    fn connect(port: u16, ca: Option<&str>) -> Self {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let (stream, exporter, scheme): (Box<dyn Stream>, [u8; 32], &str) = match ca {
            None => (Box::new(tcp), attach::NO_EXPORTER, "ws"),
            Some(ca) => {
                use rustls::pki_types::pem::PemObject;
                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(rustls::pki_types::CertificateDer::from_pem_slice(ca.as_bytes()).unwrap())
                    .unwrap();
                let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
                let mut tcp = tcp;
                while conn.is_handshaking() {
                    conn.complete_io(&mut tcp).unwrap();
                }
                let exporter = conn
                    .export_keying_material([0u8; 32], attach::TLS_EXPORTER_LABEL, None)
                    .unwrap();
                (
                    Box::new(rustls::StreamOwned::new(conn, tcp)),
                    exporter,
                    "wss",
                )
            }
        };
        let url = format!("{scheme}://localhost:{port}");
        let mut request =
            tungstenite::client::IntoClientRequest::into_client_request(url.as_str()).unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            tungstenite::http::HeaderValue::from_static(WS_SUBPROTOCOL),
        );
        let (ws, _) = tungstenite::client::client(request, stream).unwrap();
        Self { ws, exporter }
    }

    fn send(&mut self, frame: Value) {
        self.ws.send(Message::Text(frame.to_string())).unwrap();
    }

    /// The next message, or `None` once the daemon has closed.
    fn recv(&mut self) -> Option<Value> {
        loop {
            match self.ws.read() {
                Ok(Message::Text(text)) => return Some(serde_json::from_str(&text).unwrap()),
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }

    /// Attach as `name` with `key`'s public half, and the challenge's
    /// nonce.
    fn challenged(&mut self, name: &str, key: &SigningKey) -> [u8; 32] {
        self.send(json!({
            "op": "attach", "id": "1", "name": name, "protocol_version": "v0",
            "key": attach::encode_key(&key.verifying_key().to_bytes()),
        }));
        let challenge = self.recv().expect("a challenge");
        assert_eq!(
            (challenge["op"].as_str(), challenge["id"].as_str()),
            (Some("challenge"), Some("1")),
            "{challenge}"
        );
        attach::decode_nonce(challenge["nonce"].as_str().unwrap()).unwrap()
    }

    fn prove(&mut self, signature: &[u8; 64]) {
        self.send(json!({"op": "prove", "id": "1", "signature": base64::encode(signature)}));
    }

    /// The next message is `auth_failed`, and the daemon closes after it.
    fn refused(mut self) {
        let reply = self.recv().expect("a refusal");
        assert_eq!(reply["code"], "auth_failed", "{reply}");
        assert_eq!(self.recv(), None, "the connection closed after auth_failed");
    }
}

/// The origin of the client's own send, as its own subscription sees it.
fn own_origin(mesh: &Mesh) -> String {
    let (tx, rx) = mpsc::channel();
    mesh.on("me", move |event| {
        let _ = tx.send(event.origin);
    })
    .expect("subscribe");
    mesh.send("me", b"who").expect("send");
    rx.recv_timeout(Duration::from_secs(5)).expect("the event")
}

/// Over ws and over wss: a listed key attaches with the Rust client and is
/// named by it; every way of failing the proof is refused with
/// `auth_failed`, the connection closed; the socket admits its owner without
/// a key.
#[test]
fn the_daemon_admits_a_listed_key_and_refuses_every_failed_proof() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys(dir.path());
    let pems = pems(dir.path());
    let listed = mesh_client::identity::read_key_file(&keys.listed).unwrap();
    let unlisted = mesh_client::identity::read_key_file(&keys.unlisted).unwrap();
    let list = keys.list.to_str().unwrap();
    let (cert, key) = (pems.cert.to_str().unwrap(), pems.key.to_str().unwrap());
    for tls in [false, true] {
        let tag = if tls { "akwss" } else { "akws" };
        let mut args = vec!["--ws-bind", "127.0.0.1:0", "--attach-keys", list];
        if tls {
            args.extend(["--ws-tls-cert", cert, "--ws-tls-key", key]);
        }
        let daemon = Daemon::start(tag, &args);
        assert!(
            daemon
                .log()
                .contains("attach keys: every attach on the WebSocket"),
            "{}",
            daemon.log()
        );
        let ca = tls.then_some(pems.ca.as_str());
        let url = format!(
            "{}://localhost:{}",
            if tls { "wss" } else { "ws" },
            daemon.port
        );
        let options = MeshOptions::default()
            .with_endpoint(Endpoint::Ws(url.clone()))
            .with_tls_root_pem(pems.ca.clone());

        // The Rust client with the listed key's file.
        let mesh = Mesh::attach_with(
            "keyed",
            options.clone().with_identity_file(&keys.listed).unwrap(),
        )
        .unwrap_or_else(|e| panic!("{url}: {e}\n{}", daemon.log()));
        assert_eq!(
            own_origin(&mesh),
            attach::keyed_node_id("keyed", &listed.verifying_key().to_bytes())
        );
        mesh.detach().unwrap();
        // Without a key, and with one not listed.
        assert!(matches!(
            Mesh::attach_with("keyless", options.clone()),
            Err(DevError::AuthFailed { .. })
        ));
        assert!(matches!(
            Mesh::attach_with(
                "stranger",
                options.with_identity_file(&keys.unlisted).unwrap()
            ),
            Err(DevError::AuthFailed { .. })
        ));

        // A raw client: a good proof attaches.
        let mut raw = Raw::connect(daemon.port, ca);
        let nonce = raw.challenged("raw", &listed);
        raw.prove(&attach::sign(&listed, &nonce, "raw", &raw.exporter));
        let ack = raw.recv().unwrap();
        assert_eq!(
            ack["node_id"],
            attach::keyed_node_id("raw", &listed.verifying_key().to_bytes()),
            "{ack}"
        );
        drop(raw);

        // A signature by another key.
        let mut raw = Raw::connect(daemon.port, ca);
        let nonce = raw.challenged("forged", &listed);
        raw.prove(&attach::sign(&unlisted, &nonce, "forged", &raw.exporter));
        raw.refused();

        // A good proof of a key not listed.
        let mut raw = Raw::connect(daemon.port, ca);
        let nonce = raw.challenged("stranger2", &unlisted);
        raw.prove(&attach::sign(&unlisted, &nonce, "stranger2", &raw.exporter));
        raw.refused();

        // A good proof replayed on a second connection.
        let mut first = Raw::connect(daemon.port, ca);
        let nonce = first.challenged("replayed", &listed);
        let proof = attach::sign(&listed, &nonce, "replayed", &first.exporter);
        let mut second = Raw::connect(daemon.port, ca);
        second.challenged("replayed", &listed);
        second.prove(&proof);
        second.refused();
        drop(first);

        // A keyless attach.
        let mut raw = Raw::connect(daemon.port, ca);
        raw.send(json!({"op": "attach", "id": "1", "name": "plain", "protocol_version": "v0"}));
        raw.refused();

        if tls {
            // On wss, a proof that signs the plaintext exporter instead of
            // the connection's, as a proof relayed from elsewhere would.
            let mut raw = Raw::connect(daemon.port, ca);
            let nonce = raw.challenged("unbound", &listed);
            assert_ne!(raw.exporter, attach::NO_EXPORTER);
            raw.prove(&attach::sign(
                &listed,
                &nonce,
                "unbound",
                &attach::NO_EXPORTER,
            ));
            raw.refused();
        }

        // The owner's socket admits it without a key.
        let owner = Mesh::attach_with(
            "owner",
            MeshOptions::default()
                .with_endpoint(Endpoint::Uds(daemon.socket.display().to_string())),
        )
        .expect("the socket admits its owner without a key");
        owner.detach().unwrap();

        assert!(
            daemon.log().contains("attach refused (auth_failed)"),
            "{}",
            daemon.log()
        );
        assert_eq!(daemon.stop(), Some(0));
    }
}

/// A challenge left unanswered past `--handshake-timeout-secs` is refused
/// with `auth_failed` under the attach's id; with `--attach-keys-uds` the
/// socket requires a key too.
#[test]
fn an_unanswered_challenge_is_refused_and_attach_keys_uds_holds_the_socket_to_keys() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys(dir.path());
    let listed = mesh_client::identity::read_key_file(&keys.listed).unwrap();
    let daemon = Daemon::start(
        "aklate",
        &[
            "--ws-bind",
            "127.0.0.1:0",
            "--attach-keys",
            keys.list.to_str().unwrap(),
            "--attach-keys-uds",
            "--handshake-timeout-secs",
            "1",
        ],
    );
    let mut raw = Raw::connect(daemon.port, None);
    let started = Instant::now();
    raw.challenged("slow", &listed);
    let reply = raw.recv().expect("the refusal");
    assert_eq!(
        (reply["code"].as_str(), reply["id"].as_str()),
        (Some("auth_failed"), Some("1")),
        "{reply}"
    );
    assert!(
        reply["message"]
            .as_str()
            .unwrap()
            .contains("not answered within"),
        "{reply}"
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(raw.recv(), None);

    let socket =
        MeshOptions::default().with_endpoint(Endpoint::Uds(daemon.socket.display().to_string()));
    assert!(matches!(
        Mesh::attach_with("owner", socket.clone()),
        Err(DevError::AuthFailed { .. })
    ));
    Mesh::attach_with("owner-keyed", socket.with_identity(listed))
        .expect("a listed key attaches on the socket")
        .detach()
        .unwrap();
    assert_eq!(daemon.stop(), Some(0));
}

/// Off loopback, TLS and attach keys together need no `--ws-allow-remote`,
/// and the daemon says at info what protects the address; either alone is
/// refused, naming what is missing.
#[test]
fn off_loopback_tls_and_attach_keys_together_need_no_ws_allow_remote() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys(dir.path());
    let pems = pems(dir.path());
    let (list, cert, key) = (
        keys.list.to_str().unwrap(),
        pems.cert.to_str().unwrap(),
        pems.key.to_str().unwrap(),
    );
    let daemon = Daemon::start(
        "akoff",
        &[
            "--ws-bind",
            "0.0.0.0:0",
            "--attach-keys",
            list,
            "--ws-tls-cert",
            cert,
            "--ws-tls-key",
            key,
        ],
    );
    let log = daemon.log();
    assert!(
        log.contains("TLS 1.3 encrypts it, and every attach on it proves a key"),
        "{log}"
    );
    assert!(!log.contains("WARN"), "{log}");
    assert_eq!(daemon.stop(), Some(0));

    for (flags, missing) in [
        (
            vec!["--attach-keys", list],
            "--ws-tls-cert and --ws-tls-key",
        ),
        (
            vec!["--ws-tls-cert", cert, "--ws-tls-key", key],
            "--attach-keys",
        ),
        (vec![], "TLS (--ws-tls-cert, --ws-tls-key)"),
    ] {
        let socket = socket_path("akoff-no");
        let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name("akoffn"), "--uds-path"])
            .arg(&socket)
            .args(["--ws-bind", "0.0.0.0:0", "--store-slots", "4"])
            .args(&flags)
            .output()
            .expect("run mesh-hub");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flags:?}: {stderr}");
        assert!(
            stderr.contains(&format!("Missing: {missing}")) && stderr.contains("--ws-allow-remote"),
            "{flags:?}: {stderr}"
        );
        assert!(!socket.exists());
    }
}

/// An attach keys file that cannot be read, or holds a line that is not a
/// key, stops the start with status 1, naming the file, before any socket is
/// made; `--attach-keys-uds` without `--attach-keys` is refused (status 2).
#[test]
fn a_malformed_attach_keys_file_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.keys");
    std::fs::write(&bad, "# fine\nnot a key\n").unwrap();
    for (file, says) in [
        (bad.clone(), "line 2".to_string()),
        (
            dir.path().join("absent.keys"),
            "could not be read".to_string(),
        ),
    ] {
        let socket = socket_path("akbad");
        let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
            .args(["--hub-name", &hub_name("akbad"), "--uds-path"])
            .arg(&socket)
            .args([
                "--ws-bind",
                "127.0.0.1:0",
                "--store-slots",
                "4",
                "--attach-keys",
            ])
            .arg(&file)
            .output()
            .expect("run mesh-hub");
        let log = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "log:\n{log}");
        assert!(
            log.contains(&file.display().to_string()) && log.contains(&says),
            "log:\n{log}"
        );
        assert!(!socket.exists(), "a refused start made the socket");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--attach-keys-uds"])
        .output()
        .expect("run mesh-hub");
    assert_eq!(out.status.code(), Some(2));
}
