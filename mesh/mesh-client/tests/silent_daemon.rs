// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A daemon that stops answering is given up after
//! `MeshOptions::silence_limit`, and a healthy one never is, however long
//! it stays idle.
//!
//! The daemon is a real one, in a process of its own that the tests stop
//! with SIGSTOP: this test binary again, run with `DEV_HUB_DAEMON_CHILD` set
//! and the test selected, which hosts an `EmbeddedMesh`, the daemon's own
//! server, on a Unix socket and a WebSocket until its standard input
//! closes. On a WebSocket the client pings a quiet daemon, so a stopped one
//! is given up even while the connection is idle. The Unix socket has no
//! ping, and an idle daemon answers nothing there, so a stopped one is given
//! up once a call waits for it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::ConnectionPolicy;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Set in a daemon child's environment: the hub's name, the socket's path
/// and the daemon's ping interval in milliseconds, separated by tabs. Its
/// presence makes a test serve as the daemon.
const CHILD: &str = "DEV_HUB_DAEMON_CHILD";

/// Long enough that no call here times out before the silence limit.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// A daemon in a process of its own, which dropping continues if stopped
/// and ends.
struct Daemon {
    child: Child,
    socket: PathBuf,
    ws: String,
}

impl Daemon {
    /// Run `test` in a child that serves as a daemon under a hub named for
    /// `tag` and this process, pinging its WebSocket clients every `ping`,
    /// or never for zero.
    fn start(test: &str, tag: &str, ping: Duration) -> Self {
        let pid = std::process::id();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let hub = format!("sd{tag}{:05x}", pid & 0xf_ffff);
        let socket = std::env::temp_dir().join(format!("dev-hub-sd{tag}-{pid}-{unique}.sock"));
        let spec = format!("{hub}\t{}\t{}", socket.display(), ping.as_millis());
        let mut child = Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, spec)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the daemon");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                // After the harness's "test <name> ... ", on the same line.
                if let Some((_, ws)) = line.split_once("daemon answers on ") {
                    let _ = tx.send(ws.to_owned());
                }
            }
        });
        let ws = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the daemon's WebSocket address");
        Self { child, socket, ws }
    }

    /// Send the daemon `signal` (`STOP`, `CONT`).
    fn signal(&self, signal: &str) -> bool {
        Command::new("sh")
            .args(["-c", &format!("kill -{signal} {}", self.child.id())])
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Stop the daemon, as SIGSTOP does: it answers nothing more. `kill`
    /// returns before the stop takes effect, and until every thread of the
    /// daemon has stopped one of them can still answer a request sent in the
    /// meantime, so wait until the kernel reports the child stopped.
    fn stop(&self) {
        assert!(self.signal("STOP"), "the daemon was not stopped");
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid fits in pid_t");
        let mut status = 0;
        // SAFETY: `pid` is this process's own child and `status` is a valid
        // place for waitpid to write. WUNTRACED reports the stop without
        // reaping the child, which `Child` still owns.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        assert!(
            waited == pid && libc::WIFSTOPPED(status),
            "the daemon did not stop: waitpid gave {waited}, status {status:#x}"
        );
    }

    /// Options that attach to the daemon's Unix socket.
    fn uds(&self, limit: Duration) -> MeshOptions {
        MeshOptions::default()
            .with_endpoint(Endpoint::Uds(self.socket.to_string_lossy().into_owned()))
            .with_rpc_timeout(RPC_TIMEOUT)
            .with_silence_limit(limit)
    }

    /// Options that attach to the daemon's WebSocket.
    fn ws(&self, limit: Duration) -> MeshOptions {
        MeshOptions::default()
            .with_endpoint(Endpoint::Ws(self.ws.clone()))
            .with_rpc_timeout(RPC_TIMEOUT)
            .with_silence_limit(limit)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Continued if stopped, it ends once its input closes, and removes
        // what it made; one that does not is killed.
        let _ = self.signal("CONT");
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// In a daemon child: serve until the standard input closes.
fn serve(spec: &str) {
    let fields: Vec<&str> = spec.split('\t').collect();
    let [hub, socket, ping] = fields[..] else {
        panic!("a daemon child's spec: {spec:?}");
    };
    let policy = ConnectionPolicy::default()
        .with_ping_interval(Duration::from_millis(ping.parse().unwrap()));
    let mesh = EmbeddedMesh::start_with_config(
        hub,
        &[
            Bind::Uds(socket.into()),
            Bind::Ws("127.0.0.1:0".parse().unwrap()),
        ],
        policy,
        HubConfig::default().with_store_slots(4),
    )
    .expect("the daemon");
    let ws = mesh.ws_addr().expect("the daemon's WebSocket address");
    announce(&format!("daemon answers on ws://{ws}"));
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
    mesh.shutdown();
}

/// Tell the parent a line, on the standard output it reads.
#[allow(clippy::print_stdout)]
fn announce(line: &str) {
    println!("{line}");
}

/// `mesh.wait()` on a thread of its own, its outcome sent when it returns.
fn wait_on(mesh: &Mesh) -> mpsc::Receiver<Result<(), DevError>> {
    let (tx, rx) = mpsc::channel();
    let mesh = mesh.clone();
    std::thread::spawn(move || {
        let _ = tx.send(mesh.wait());
    });
    rx
}

/// The Unix socket has no ping, and an idle daemon owes nothing there: a
/// stopped one is not given up while the connection is idle, and is once a
/// call waits for it, the call and `wait` reporting `Silent`.
#[test]
fn a_stopped_daemon_is_given_up_on_the_unix_socket_once_a_call_waits() {
    if let Ok(spec) = std::env::var(CHILD) {
        return serve(&spec);
    }
    const LIMIT: Duration = Duration::from_secs(1);
    let daemon = Daemon::start(
        "a_stopped_daemon_is_given_up_on_the_unix_socket_once_a_call_waits",
        "u",
        Duration::from_secs(30),
    );
    let mesh = Mesh::attach_with("stopped-uds", daemon.uds(LIMIT)).expect("attach");
    mesh.send("c", b"x").expect("the daemon answers");
    let waiting = wait_on(&mesh);
    daemon.stop();
    std::thread::sleep(LIMIT * 3);
    assert!(
        waiting.try_recv().is_err(),
        "idle on the Unix socket, a stopped daemon owes nothing, and is not given up"
    );

    let started = Instant::now();
    let sent = mesh.send("c", b"y");
    let took = started.elapsed();
    assert!(
        matches!(sent, Err(DevError::Silent { after }) if after == LIMIT),
        "{sent:?}"
    );
    assert!(took >= LIMIT && took < RPC_TIMEOUT, "{took:?}");
    let ended = waiting.recv_timeout(Duration::from_secs(10));
    assert!(
        matches!(ended, Ok(Err(DevError::Silent { .. }))),
        "{ended:?}"
    );
}

/// The client pings a quiet daemon on a WebSocket: a stopped one is given
/// up at the limit though nothing else is sent, and a call waiting then
/// reports `Silent` too.
#[test]
fn a_stopped_daemon_is_given_up_on_a_websocket_while_idle() {
    if let Ok(spec) = std::env::var(CHILD) {
        return serve(&spec);
    }
    const LIMIT: Duration = Duration::from_millis(1500);
    let daemon = Daemon::start(
        "a_stopped_daemon_is_given_up_on_a_websocket_while_idle",
        "w",
        Duration::from_secs(30),
    );
    let mesh = Mesh::attach_with("stopped-ws", daemon.ws(LIMIT)).expect("attach");
    mesh.send("c", b"x").expect("the daemon answers");
    let waiting = wait_on(&mesh);
    daemon.stop();
    let stopped = Instant::now();
    let call = {
        let mesh = mesh.clone();
        std::thread::spawn(move || mesh.send("c", b"y"))
    };
    let ended = waiting.recv_timeout(Duration::from_secs(20));
    let took = stopped.elapsed();
    assert!(
        matches!(ended, Ok(Err(DevError::Silent { after })) if after == LIMIT),
        "{ended:?}"
    );
    assert!(took >= LIMIT / 2, "given up too soon: {took:?}");
    let sent = call.join().unwrap();
    assert!(matches!(sent, Err(DevError::Silent { .. })), "{sent:?}");
}

/// A healthy daemon is never given up, however long the connection stays
/// idle, on either transport. Its own pings are off here, so on the
/// WebSocket only the client's pings and the daemon's answers cross the
/// idle connection, and the heartbeat is off, so on the Unix socket
/// nothing does.
#[test]
fn a_healthy_daemon_is_never_given_up_however_long_it_is_idle() {
    if let Ok(spec) = std::env::var(CHILD) {
        return serve(&spec);
    }
    const LIMIT: Duration = Duration::from_secs(2);
    let daemon = Daemon::start(
        "a_healthy_daemon_is_never_given_up_however_long_it_is_idle",
        "h",
        Duration::ZERO,
    );
    let quiet = |options: MeshOptions| options.with_heartbeat_interval(Duration::ZERO);
    let uds = Mesh::attach_with("idle-uds", quiet(daemon.uds(LIMIT))).expect("attach");
    let ws = Mesh::attach_with("idle-ws", quiet(daemon.ws(LIMIT))).expect("attach");
    let waiting = [wait_on(&uds), wait_on(&ws)];
    std::thread::sleep(LIMIT * 3);
    for (transport, waiting) in ["unix socket", "websocket"].iter().zip(&waiting) {
        let ended = waiting.try_recv();
        assert!(ended.is_err(), "{transport}: {ended:?}");
    }
    uds.send("c", b"x")
        .expect("still attached on the Unix socket");
    ws.send("c", b"x").expect("still attached on the WebSocket");
    uds.detach().expect("detach");
    ws.detach().expect("detach");
    for waiting in waiting {
        let ended = waiting.recv_timeout(Duration::from_secs(10));
        assert!(matches!(ended, Ok(Ok(()))), "{ended:?}");
    }
}
