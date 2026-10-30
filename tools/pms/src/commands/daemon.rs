// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Daemon-driven `pms` subcommands.
//!
//! These talk to a running `mesh-hub` daemon over the v0 Universal Port
//! Protocol via the `dev-functions` ergonomic API. Run `pms start` first
//! (or supply `PMS_DAEMON=ws://host:port`).

use anyhow::{Context, Result};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use mesh_client::{Mesh, TapFilter};
use mesh_hub::protocol::{DEFAULT_UDS_PATH, DEFAULT_WS_BIND};
use mesh_hub_runtime::owner::{hub_lock_path, lock_holder, recorded_pid, socket_lock_path};

/// The hub name of the daemon `pms start` and `pms demo` run, passed to it
/// explicitly so that what `pms start` checks is what the daemon claims.
/// Its endpoints are the protocol's defaults, which the daemon also uses
/// unless told otherwise.
pub(crate) const DAEMON_HUB: &str = "default_hub";

/// How long `pms start` waits for the daemon it started to serve: the
/// first run inside the workspace builds the daemon first.
const START_WAIT: Duration = Duration::from_secs(60);

/// How long a daemon this command stops (one that did not start in time,
/// or the one `pms demo` started) is given to exit after SIGTERM before it
/// is killed.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(5);

/// `pms start [--foreground]` — bring up the `mesh-hub` daemon.
///
/// Refuses, saying which daemon it found, when one already runs: a live
/// hub owns [`DAEMON_HUB`], a live daemon holds the default socket, or
/// something answers at the default socket or WebSocket address. Otherwise
/// it runs the installed `mesh-hub` binary, or `cargo run -p mesh-hub
/// --release` inside the workspace. A daemon started in the background
/// that does not serve within [`START_WAIT`] is stopped, so that nothing
/// keeps running behind a report that it did not start: SIGTERM, which a
/// daemon answers by removing its socket and shared memory, then SIGKILL
/// after [`STOP_GRACE`].
pub(crate) fn run_start(foreground: bool, basket_path: Option<&str>) -> Result<ExitCode> {
    let ws_addr: SocketAddr = DEFAULT_WS_BIND.parse()?;
    if let Some(running) = running_daemon(DAEMON_HUB, Path::new(DEFAULT_UDS_PATH), ws_addr)? {
        eprintln!("pms start: {running}; not starting a second daemon");
        return Ok(ExitCode::from(1));
    }
    if foreground {
        let mut cmd = mesh_hub_command(basket_path);
        let status = cmd.status().context("spawn mesh-hub")?;
        return Ok(ExitCode::from(status.code().unwrap_or(1) as u8));
    }
    let (mut child, log_path) = spawn_daemon_background(basket_path)?;
    let pid = child.id();
    // Block until the daemon this call started serves: a script that runs
    // `pms start` and then calls `Mesh::attach` must not race its bind. The
    // first run can be slow (cargo's release build and the daemon's own
    // start), so the wait is generous; a daemon that exits instead, having
    // found the hub or the socket taken after all, ends it at once.
    match wait_until_serving(&mut child, ws_addr, START_WAIT) {
        Ok(()) => {
            println!("mesh-hub started (pid {pid}); log: {}", log_path.display());
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            let stopped = match e {
                NotServing::Exited(_) => String::new(),
                NotServing::Timeout(_) | NotServing::Io(_) => {
                    format!("; {}", stop_daemon(&mut child, STOP_GRACE))
                }
            };
            eprintln!(
                "mesh-hub (pid {pid}) did not start: {e}{stopped}\n  log: {}",
                log_path.display()
            );
            Ok(ExitCode::from(1))
        }
    }
}

/// What [`stop_daemon`] did to a daemon.
#[derive(Debug)]
pub(crate) enum Stopped {
    /// It exited after SIGTERM.
    Terminated,
    /// It was still running when the grace ran out, and was killed.
    Killed,
    /// It could not be signalled or waited for; it may still be running.
    Failed {
        /// The process id.
        pid: u32,
        /// Why.
        error: std::io::Error,
    },
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminated => f.write_str("stopped it"),
            Self::Killed => f.write_str("it did not stop on SIGTERM, so it was killed"),
            Self::Failed { pid, error } => write!(
                f,
                "it could not be stopped ({error}) and may still be running as pid {pid}"
            ),
        }
    }
}

/// Stop `child`: SIGTERM, which the daemon answers by exiting cleanly, then
/// SIGKILL if it has not exited within `grace`, and reap it either way.
pub(crate) fn stop_daemon(child: &mut Child, grace: Duration) -> Stopped {
    let pid = child.id();
    let failed = |error| Stopped::Failed { pid, error };
    let Ok(raw) = libc::pid_t::try_from(pid) else {
        return failed(std::io::Error::other("the process id does not fit a pid_t"));
    };
    // SAFETY: kill(2) takes two integers and touches no memory of this
    // process. `raw` is the id of a child this process has not reaped
    // (`try_wait` reaps it only once it has exited), so it names no other
    // process.
    if unsafe { libc::kill(raw, libc::SIGTERM) } != 0 {
        let error = std::io::Error::last_os_error();
        // Gone already: reap it.
        return match child.try_wait() {
            Ok(Some(_)) => Stopped::Terminated,
            _ => failed(error),
        };
    }
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Stopped::Terminated,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => break,
            Err(error) => return failed(error),
        }
    }
    match child.kill().and_then(|()| child.wait()) {
        Ok(_) => Stopped::Killed,
        Err(error) => failed(error),
    }
}

/// A daemon already holding what `pms start` would claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Running {
    /// A live hub owns the hub name: its owner lock is held.
    Hub {
        /// The hub name.
        hub: String,
        /// The owner's process id, as its lock file records it.
        pid: Option<u32>,
    },
    /// A live daemon holds the lock beside the socket.
    Socket {
        /// The socket path.
        path: PathBuf,
        /// The daemon's process id, as the lock file records it.
        pid: Option<u32>,
    },
    /// Something answers at the socket without holding its lock (a daemon
    /// from before the lock existed).
    Answering {
        /// The socket path.
        path: PathBuf,
    },
    /// Something accepts connections on the WebSocket address.
    Listening {
        /// The address.
        addr: SocketAddr,
    },
}

impl std::fmt::Display for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let by = |pid: &Option<u32>| pid.map_or_else(String::new, |p| format!(" by process {p}"));
        match self {
            Self::Hub { hub, pid } => write!(
                f,
                "mesh-hub is already running: hub {hub} is owned{}",
                by(pid)
            ),
            Self::Socket { path, pid } => write!(
                f,
                "mesh-hub is already running: {} is held{}",
                path.display(),
                by(pid)
            ),
            Self::Answering { path } => {
                write!(f, "a daemon already answers at {}", path.display())
            }
            Self::Listening { addr } => write!(f, "something already listens on {addr}"),
        }
    }
}

/// What already holds `hub`, the socket at `socket` or the address `ws`,
/// checked in that order, or `None` when a daemon started now would find
/// all three free. The locks are read with a probe, which a daemon starting
/// at the same instant tolerates.
///
/// # Errors
///
/// When the hub name is invalid, or a lock file exists but cannot be read.
pub(crate) fn running_daemon(hub: &str, socket: &Path, ws: SocketAddr) -> Result<Option<Running>> {
    let hub_lock = hub_lock_path(hub).context("hub name")?;
    if let Some(holder) = lock_holder(&hub_lock)? {
        return Ok(Some(Running::Hub {
            hub: hub.to_string(),
            pid: holder.pid,
        }));
    }
    if let Some(holder) = lock_holder(&socket_lock_path(socket))? {
        return Ok(Some(Running::Socket {
            path: socket.to_path_buf(),
            pid: holder.pid,
        }));
    }
    if UnixStream::connect(socket).is_ok() {
        return Ok(Some(Running::Answering {
            path: socket.to_path_buf(),
        }));
    }
    if TcpStream::connect_timeout(&ws, Duration::from_millis(150)).is_ok() {
        return Ok(Some(Running::Listening { addr: ws }));
    }
    Ok(None)
}

/// Why a daemon `pms start` started is not serving.
#[derive(Debug)]
enum NotServing {
    /// It exited, with this status.
    Exited(ExitStatus),
    /// It did not serve within the wait.
    Timeout(Duration),
    /// Its state could not be read.
    Io(std::io::Error),
}

impl std::fmt::Display for NotServing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited(status) => write!(f, "it exited ({status}); its log says why"),
            Self::Timeout(wait) => write!(f, "it was not serving within {wait:?}"),
            Self::Io(e) => write!(f, "its state could not be read: {e}"),
        }
    }
}

/// Wait until `child` serves: it owns [`DAEMON_HUB`] (its process id is
/// the one the hub's lock file records, which a daemon from before cannot
/// be) and its socket and WebSocket address answer. `cargo run` replaces
/// itself with the daemon, so the child's process id is the daemon's.
fn wait_until_serving(child: &mut Child, ws: SocketAddr, wait: Duration) -> Result<(), NotServing> {
    let hub_lock =
        hub_lock_path(DAEMON_HUB).map_err(|e| NotServing::Io(std::io::Error::other(e)))?;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(NotServing::Io)? {
            return Err(NotServing::Exited(status));
        }
        if recorded_pid(&hub_lock) == Some(child.id())
            && UnixStream::connect(DEFAULT_UDS_PATH).is_ok()
            && TcpStream::connect_timeout(&ws, Duration::from_millis(150)).is_ok()
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(NotServing::Timeout(wait))
}

/// Spawn `mesh-hub` as a detached background child. Stdout/stderr go to
/// `~/.local/state/pms/mesh-hub.log`. Returns the child handle (so callers
/// can wait/kill) and the log path (for messaging).
///
/// Shared by `pms start` and `pms demo`.
pub(crate) fn spawn_daemon_background(
    basket_path: Option<&str>,
) -> Result<(std::process::Child, std::path::PathBuf)> {
    let log_dir = dirs_log_dir()?;
    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join("mesh-hub.log");
    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    let log_err = log.try_clone()?;
    let mut cmd = mesh_hub_command(basket_path);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let child = cmd.spawn().context("spawn mesh-hub")?;
    Ok((child, log_path))
}

/// The command that runs the daemon for [`DAEMON_HUB`]: an installed
/// `mesh-hub` binary when one sits beside this executable or on `PATH` (the
/// `just install` layout), otherwise `cargo run` inside the workspace.
fn mesh_hub_command(basket_path: Option<&str>) -> Command {
    let mut cmd = match installed_mesh_hub() {
        Some(bin) => Command::new(bin),
        None => {
            let mut c = Command::new("cargo");
            c.args(["run", "-q", "-p", "mesh-hub", "--release", "--"]);
            c
        }
    };
    cmd.args(["--hub-name", DAEMON_HUB]);
    if let Some(p) = basket_path {
        cmd.args(["--basket-path", p]);
    }
    cmd
}

/// A `mesh-hub` binary next to `pms`, or the first one on `PATH`.
fn installed_mesh_hub() -> Option<std::path::PathBuf> {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        let beside = dir.join("mesh-hub");
        if beside.is_file() {
            return Some(beside);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("mesh-hub"))
        .find(|candidate| candidate.is_file())
}

/// `pms attach <name>` — attach + park.
///
/// Useful as a smoke test or to claim a name in the registry while another
/// program writes to it from elsewhere. Holds the connection until ^C.
pub(crate) fn run_attach(name: &str) -> Result<ExitCode> {
    let mesh = Mesh::attach(name).context("attach to mesh-hub")?;
    println!("attached as '{}' — Ctrl-C to detach", name);
    // Ctrl-C ends the process here; anything that returns is the connection
    // ending under us, which the user must see rather than a silent success.
    mesh.run().context("the connection to mesh-hub ended")?;
    Ok(ExitCode::SUCCESS)
}

/// `pms send <channel> <payload>` — one-shot publish.
pub(crate) fn run_send(channel: &str, payload: &[u8], type_name: Option<&str>) -> Result<ExitCode> {
    let mesh = Mesh::attach("pms-cli-send")?;
    let env_id = mesh
        .send_typed(channel, type_name, payload)
        .context("send")?;
    println!("envelope_id={}", env_id);
    Ok(ExitCode::SUCCESS)
}

/// `pms tap [filter]` — live stream printer.
///
/// Subscribes with the given filter and prints each event one per line
/// (channel | bytes | hex-id-prefix). For agent-friendly structured
/// telemetry use `pms-query` instead.
pub(crate) fn run_tap(
    channel: Option<&str>,
    type_name: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let mesh = Mesh::attach("pms-cli-tap")?;
    let filter = TapFilter {
        channel: channel.map(String::from),
        type_name: type_name.map(String::from),
        ..Default::default()
    };

    let _sub = mesh
        .tap(filter, move |ev| {
            if json {
                let obj = serde_json::json!({
                    "subscription_id": ev.subscription_id.0,
                    "envelope_id": ev.envelope_id,
                    "channel": ev.channel,
                    "type_id": ev.type_id,
                    "type_name": ev.type_name,
                    "origin": ev.origin,
                    "captured_at_unix_nanos": ev.captured_at_unix_nanos.to_string(),
                    "payload_bytes": ev.payload.len(),
                });
                let s = serde_json::to_string(&obj).unwrap_or_default();
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{}", s);
            } else {
                let mut out = std::io::stdout().lock();
                let _ = writeln!(
                    out,
                    "{:>20} | {:>8}B | {} | {}",
                    ev.channel,
                    ev.payload.len(),
                    &ev.envelope_id[..ev.envelope_id.len().min(8)],
                    ev.origin
                );
            }
        })
        .context("tap")?;

    eprintln!("tapped; Ctrl-C to stop");
    // As in `run_attach`: returning means the daemon went away or refused us.
    mesh.run().context("the connection to mesh-hub ended")?;
    Ok(ExitCode::SUCCESS)
}

/// `pms hello` — 2-thread demo (sender + receiver) in one process.
///
/// A receiver thread attaches as `hello-recv`, subscribes to `hello` and
/// tells the main thread once the daemon has acknowledged the
/// subscription, so the envelope sent next is delivered to it; the main
/// thread then attaches as `hello-send` and sends one envelope to `hello`.
/// The receiver waits up to 2 s for it. Exits 0 when it arrives and 1
/// when it does not.
pub(crate) fn run_hello() -> Result<ExitCode> {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel::<String>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    // Receiver in a thread (no separate process; v0 simplicity).
    let receiver = thread::spawn(move || -> Result<bool> {
        let mesh = Mesh::attach("hello-recv")?;
        let txx = tx.clone();
        let _sub = mesh.on("hello", move |ev| {
            let s = String::from_utf8(ev.payload.clone())
                .unwrap_or_else(|_| format!("<{} bytes>", ev.payload.len()));
            let _ = txx.send(s);
        })?;
        // `on` returns once the daemon has acknowledged the subscription.
        let _ = ready_tx.send(());
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(s) => {
                println!("[recv] got: {}", s);
                Ok(true)
            }
            Err(_) => {
                println!("[recv] timeout");
                Ok(false)
            }
        }
    });

    // Send once the receiver is subscribed. A receiver that failed to
    // attach or subscribe drops its end without a word, and its error comes
    // out of the join below.
    if ready_rx.recv().is_ok() {
        let sender = Mesh::attach("hello-send")?;
        let payload = b"hello from pms";
        sender.send("hello", payload)?;
        println!("[send] sent 'hello from pms' to channel 'hello'");
    }

    let arrived = receiver
        .join()
        .map_err(|_| anyhow::anyhow!("receiver thread panicked"))??;
    if arrived {
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("✗ the envelope did not arrive within 2 s");
        Ok(ExitCode::from(1))
    }
}

// --- helpers --------------------------------------------------------------

fn dirs_log_dir() -> Result<std::path::PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        Ok(std::path::PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("pms"))
    } else {
        Ok(std::path::PathBuf::from("/tmp/pms"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
    use mesh_hub::ConnectionPolicy;

    /// A hub name private to this process, at most fifteen characters.
    fn hub(tag: &str) -> String {
        format!("{tag}{:x}", std::process::id())
    }

    /// A socket path private to this process and test.
    fn socket(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pms-start-{tag}-{}.sock", std::process::id()))
    }

    /// An address nothing can listen on. Port 0 names no port, so a
    /// connection to it fails at once on every platform: Linux refuses it
    /// and macOS cannot assign it. A port the system handed out and took
    /// back is free only until another process on the machine binds it,
    /// which under load it does, and the probe then finds it listening.
    fn nothing_listens() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    #[test]
    fn start_refuses_a_running_daemon_and_names_it() {
        let (hub_a, sock_a) = (hub("ps-a"), socket("a"));
        let ws = nothing_listens();
        assert_eq!(running_daemon(&hub_a, &sock_a, ws).unwrap(), None);

        let config = HubConfig::default().with_store_slots(4);
        let mesh = EmbeddedMesh::start_with_config(
            &hub_a,
            &[Bind::Uds(sock_a.clone())],
            ConnectionPolicy::default(),
            config,
        )
        .unwrap();
        let pid = Some(std::process::id());

        // The hub name is owned, whatever socket a new daemon would use.
        let found = running_daemon(&hub_a, &socket("unused"), ws).unwrap();
        assert_eq!(
            found,
            Some(Running::Hub {
                hub: hub_a.clone(),
                pid
            })
        );
        let said = found.unwrap().to_string();
        assert!(
            said.contains(&hub_a) && said.contains(&format!("process {}", std::process::id())),
            "{said}"
        );
        // The socket is held, whatever hub a new daemon would own.
        assert_eq!(
            running_daemon(&hub("ps-b"), &sock_a, ws).unwrap(),
            Some(Running::Socket {
                path: sock_a.clone(),
                pid
            })
        );
        // Something listens on the WebSocket address.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap();
        assert_eq!(
            running_daemon(&hub("ps-b"), &socket("unused"), busy).unwrap(),
            Some(Running::Listening { addr: busy })
        );

        mesh.shutdown();
        assert_eq!(running_daemon(&hub_a, &sock_a, ws).unwrap(), None);
    }

    #[test]
    fn a_daemon_that_does_not_serve_in_time_is_stopped() {
        // A child that never serves, as a daemon still building or wedged
        // would not: the wait runs out, and the child is stopped.
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let waited = wait_until_serving(&mut child, nothing_listens(), Duration::from_millis(50));
        assert!(matches!(waited, Err(NotServing::Timeout(_))), "{waited:?}");
        let stopped = stop_daemon(&mut child, STOP_GRACE);
        assert!(matches!(stopped, Stopped::Terminated), "{stopped:?}");
        assert!(child.try_wait().unwrap().is_some(), "and reaped");
        assert_eq!(stopped.to_string(), "stopped it");

        // One that ignores SIGTERM is killed once the grace runs out.
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; echo ready; sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut ready,
        )
        .unwrap();
        let stopped = stop_daemon(&mut child, Duration::from_millis(200));
        assert!(matches!(stopped, Stopped::Killed), "{stopped:?}");
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn start_refuses_a_socket_that_answers_without_its_lock() {
        // A daemon from before the lock: it answers, and holds nothing.
        let path = socket("old");
        let _ = std::fs::remove_file(&path);
        let old = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(
            running_daemon(&hub("ps-c"), &path, nothing_listens()).unwrap(),
            Some(Running::Answering { path: path.clone() })
        );
        drop(old);
        std::fs::remove_file(&path).unwrap();
    }
}
