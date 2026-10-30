// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms demo` — single-command end-to-end smoke loop.
//!
//! The goal of this subcommand is "zero-setup proof the mesh works":
//! one command, one terminal, output you can read.
//!
//! Flow:
//! 1. Probe for a running `mesh-hub` daemon (UDS socket / WS port). With
//!    `PMS_DAEMON` set there is nothing to probe: the clients attach to the
//!    daemon it names, so the demo uses that one and starts none.
//! 2. If absent, spawn one as a background child via the same path
//!    `pms start` uses; remember to clean it up on the way out.
//! 3. Attach a consumer (`frontend`) and producer (`db-worker`) to the
//!    same channel (`db/rows`), send 5 envelopes, print each one as it
//!    arrives, and exit 1, saying how many arrived, if fewer than all 5
//!    arrive within 5 s: a smoke test that cannot fail proves nothing.
//! 4. Tear down: if we spawned the daemon, stop it as `pms start` stops
//!    one: SIGTERM, which the daemon answers by removing its socket and
//!    its shared memory, then SIGKILL only if it has not exited five
//!    seconds later, so we leave the user in a clean state. SIGKILL alone
//!    left the socket file, the lock files and the shared memory behind.
//!
//! The output format intentionally mirrors what the multi-terminal flow
//! prints (`got: row N from <producer>`) so the demo feels familiar to
//! anyone who's used the protocol the long way.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mesh_client::Mesh;

use super::daemon::{stop_daemon, Stopped, STOP_GRACE};

/// The rows the producer sends, each of which must reach the consumer.
const ROWS: usize = 5;

/// How long the consumer waits for the rows once they are sent.
const COLLECT_WAIT: Duration = Duration::from_secs(5);

/// The thin Python client's directory, relative to the root of a checkout
/// of the repository.
const PY_THIN: &str = "clients/pms-py-thin";
/// Where a checkout keeps the thin Python client: [`PY_THIN`] in the
/// integrated tree, `clients/` in the daemon's own repository.
const PY_THIN_DIRS: [&str; 2] = [PY_THIN, "clients/pms-py-thin"];

/// Drop-guard so any return path stops the daemon the demo started and
/// leaves what it made cleaned up: SIGTERM, then SIGKILL after
/// [`STOP_GRACE`], as `pms start` stops a daemon.
struct DaemonGuard(Option<std::process::Child>);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = child.id();
            match stop_daemon(&mut child, STOP_GRACE) {
                Stopped::Terminated => {}
                stopped => eprintln!("⚠ the demo's mesh-hub (pid {pid}): {stopped}"),
            }
        }
    }
}

/// `pms demo` entry point.
pub(crate) fn run() -> Result<ExitCode> {
    eprintln!("pms demo — local mesh smoke loop\n");

    // ---- Step 1: daemon presence ----------------------------------------
    // The clients below attach to the daemon `PMS_DAEMON` names when it is
    // set; a daemon started on the default endpoints would serve nobody.
    let (guard, log_path) = if let Some(named) = std::env::var_os("PMS_DAEMON") {
        eprintln!(
            "· using the daemon PMS_DAEMON names ({}); starting none",
            named.to_string_lossy()
        );
        (DaemonGuard(None), None)
    } else if daemon_reachable() {
        eprintln!("✓ daemon already running");
        (DaemonGuard(None), None)
    } else {
        // A socket file left by a daemon that was killed is the daemon's to
        // reclaim: it removes one only once it holds the lock beside it, so
        // a live daemon's socket is never taken for a stale one.
        eprintln!("· starting mesh-hub daemon…");
        let (child, log_path) =
            super::daemon::spawn_daemon_background(None).context("spawn daemon")?;
        let pid = child.id();
        let guard = DaemonGuard(Some(child));
        if let Err(e) = wait_for_daemon_ready(Duration::from_secs(60)) {
            eprintln!(
                "✗ daemon did not become ready: {e}\n  see logs at {}",
                log_path.display()
            );
            return Ok(ExitCode::from(1));
        }
        eprintln!("✓ daemon ready (pid {pid})");
        (guard, Some(log_path))
    };

    // ---- Step 2: consumer ----------------------------------------------
    let (tx, rx) = mpsc::channel::<(String, String)>();
    let consumer = Mesh::attach("frontend").context("consumer attach (frontend)")?;
    let _sub = consumer
        .on("db/rows", move |ev| {
            let payload = String::from_utf8(ev.payload.clone())
                .unwrap_or_else(|_| format!("<{}B>", ev.payload.len()));
            let _ = tx.send((ev.origin, payload));
        })
        .context("subscribe db/rows")?;
    eprintln!("✓ consumer 'frontend' subscribed to db/rows");

    // Give the subscription a beat to register on the daemon side. The
    // protocol is ack'd, but events arriving while we're still wiring up
    // can race — empirically 200ms is comfortable.
    thread::sleep(Duration::from_millis(200));

    // ---- Step 3: producer ----------------------------------------------
    let producer = Mesh::attach("db-worker").context("producer attach (db-worker)")?;
    eprintln!("✓ producer 'db-worker' attached; sending {ROWS} rows…\n");
    for i in 0..ROWS {
        let payload = format!("row {i}");
        producer
            .send("db/rows", payload.as_bytes())
            .with_context(|| format!("send row {i}"))?;
    }

    // ---- Step 4: collect ------------------------------------------------
    let deadline = Instant::now() + COLLECT_WAIT;
    let mut received = 0usize;
    while received < ROWS {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if timeout.is_zero() {
            break;
        }
        match rx.recv_timeout(timeout) {
            Ok((origin, payload)) => {
                // An event's origin is its producer's `name@suffix`.
                let producer = origin
                    .rsplit_once('@')
                    .map_or(origin.as_str(), |(name, _)| name);
                println!("got: {payload} from {producer}");
                received += 1;
            }
            Err(_) => break,
        }
    }
    println!();
    if received < ROWS {
        eprintln!(
            "✗ only {received} of {ROWS} rows arrived within {} s",
            COLLECT_WAIT.as_secs()
        );
        if let Some(log) = &log_path {
            eprintln!("  the demo's daemon logged to {}", log.display());
        }
        // The guard stops the daemon the demo started, as below.
        drop(guard);
        return Ok(ExitCode::from(1));
    }
    eprintln!("✓ demo complete — {ROWS}/{ROWS} received");
    let checkout = std::env::current_dir()
        .ok()
        .and_then(|cwd| py_thin_in_checkout(&cwd));
    eprintln!("{}", next_steps(checkout.as_deref()));

    // guard drops here → daemon (if spawned) gets SIGTERM, then SIGKILL
    // if it has not exited within the grace
    drop(guard);
    Ok(ExitCode::SUCCESS)
}

/// The thin Python client in the checkout of the repository that `dir` is
/// inside, found in `dir` or the nearest ancestor that holds it. `None`
/// outside a checkout, which is where an installed `pms` usually runs.
fn py_thin_in_checkout(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .flat_map(|d| PY_THIN_DIRS.iter().map(move |rel| d.join(rel)))
        .find(|client| client.join("pyproject.toml").is_file())
}

/// What the demo suggests next. The pip line names the thin Python client
/// by a path that resolves: `py_thin`, the client in the checkout the
/// command runs in, or else the path relative to a checkout's root, said
/// to be one.
fn next_steps(py_thin: Option<&Path>) -> String {
    let pip = match py_thin {
        Some(client) => format!("pip install -e {}", shell_word(&client.to_string_lossy())),
        None => {
            format!("pip install -e {PY_THIN}   # from the root of a checkout of the repository")
        }
    };
    format!(
        "\nNext steps:\n  \
         · Python:  {pip}\n             \
         python3 -c 'import pms; m=pms.attach(\"me\"); m.send(\"db/rows\", b\"hi from py\")'\n  \
         · Tap:     pms tap --channel db/rows           # watch every envelope live\n  \
         · Keep daemon running for your own scripts:  pms start"
    )
}

/// `word` as one word of a POSIX shell command line: as it is when it holds
/// only characters a shell leaves alone, and single-quoted otherwise.
fn shell_word(word: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+,:=@%".contains(c);
    if !word.is_empty() && word.chars().all(plain) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

// =============================================================================
// helpers
// =============================================================================

/// True if a daemon is reachable on either of the v0 endpoints.
///
/// The UDS check actually attempts a `connect()`, not just `stat`,
/// because mesh-hub leaves `/tmp/pms.sock` on disk if the process is
/// killed without graceful shutdown — and a stale socket file would
/// otherwise fool the probe into thinking a daemon is up.
fn daemon_reachable() -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::os::unix::net::UnixStream;

    let uds = Path::new("/tmp/pms.sock");
    if uds.exists() && UnixStream::connect(uds).is_ok() {
        return true;
    }
    // Infallible compile-time construction — avoids a parse + expect
    // for what is, by definition, a fixed loopback address.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9876);
    TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
}

/// Poll until the daemon answers or `timeout` expires.
///
/// The first `cargo run -p mesh-hub --release` after a clean checkout has to
/// compile the daemon — that can take 30–60s on a cold cache, so we keep
/// the timeout generous.
fn wait_for_daemon_ready(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if daemon_reachable() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    anyhow::bail!("daemon did not become reachable within {:?}", timeout)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    #[test]
    fn the_demos_daemon_is_stopped_with_sigterm_so_its_shutdown_runs() {
        // A stand-in for the daemon that records the shutdown it runs on
        // SIGTERM, as mesh-hub removes its socket and shared memory then:
        // SIGKILL runs none.
        let marker = std::env::temp_dir().join(format!("pms-demo-stopped-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut child = Command::new("sh")
            .args([
                "-c",
                "trap 'echo shut down > \"$MARKER\"; exit 0' TERM; echo ready; \
                 while :; do sleep 0.05; done",
            ])
            .env("MARKER", &marker)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        drop(DaemonGuard(Some(child)));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap_or_default(),
            "shut down\n",
            "the daemon ran its shutdown"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn the_thin_python_client_is_found_in_the_checkout_a_directory_is_in() {
        // This crate's directory is in a checkout, which holds the client.
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let client = py_thin_in_checkout(here).expect("the thin client in this checkout");
        assert!(client.is_absolute(), "{}", client.display());
        assert!(client.ends_with(PY_THIN), "{}", client.display());

        // From deeper in a checkout too, and in no directory outside one.
        let tmp = tempfile::tempdir().unwrap();
        let checkout = tmp.path().join("checkout");
        std::fs::create_dir_all(checkout.join(PY_THIN)).unwrap();
        std::fs::write(checkout.join(PY_THIN).join("pyproject.toml"), "").unwrap();
        let deeper = checkout.join("a").join("b");
        std::fs::create_dir_all(&deeper).unwrap();
        assert_eq!(py_thin_in_checkout(&deeper), Some(checkout.join(PY_THIN)));
        assert_eq!(py_thin_in_checkout(Path::new("/")), None);
    }

    #[test]
    fn the_pip_hint_names_a_path_that_resolves_where_it_is_shown() {
        let inside = next_steps(Some(&Path::new("/home/me/my checkout").join(PY_THIN)));
        assert!(
            inside.contains(&format!(
                "pip install -e '/home/me/my checkout/{PY_THIN}'\n"
            )),
            "{inside}"
        );
        let outside = next_steps(None);
        assert!(
            outside.contains(&format!(
                "pip install -e {PY_THIN}   # from the root of a checkout of the repository\n"
            )),
            "{outside}"
        );
    }

    #[test]
    fn a_shell_word_is_quoted_only_when_a_shell_would_split_or_expand_it() {
        assert_eq!(shell_word("/a/b-c_d.e"), "/a/b-c_d.e");
        assert_eq!(shell_word("/a b/c"), "'/a b/c'");
        assert_eq!(shell_word("/a/$HOME"), "'/a/$HOME'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word(""), "''");
    }
}
