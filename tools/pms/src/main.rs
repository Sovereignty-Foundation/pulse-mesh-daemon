// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms`: the Pulse Mesh™ command line.
//!
//! One binary for the developer's loop: `demo` runs a producer and a
//! consumer through the daemon in one terminal; `doctor` checks the
//! toolchain and the runtime; `start`, `attach`, `push` and `tap` drive a
//! running daemon; `encode` and `decode` round-trip an envelope through the
//! canonical codec; `send` and `recv` move Pulses over UDP; `ring inspect`
//! reads a shared-memory ring; `modules ls` lists the optimization modules;
//! `bench smoke` times pulses over UDP loopback on this host; `keys` makes
//! the keys clients prove at attach and prints the lines a daemon's
//! `--attach-keys` list holds; and `docs` prints this command line as the
//! reference page the book carries.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/reference/cli-reference.html>.

#![allow(clippy::print_stdout, clippy::print_stderr)]
#![warn(missing_docs)]

mod commands;

use std::process::ExitCode;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "pms",
    about = "Unified developer CLI for the Pulse Mesh Standard.",
    version,
    long_about = "Sends, receives, encodes, and inspects pulses across the local mesh. \
Run `pms demo` first to see a producer + consumer talk through the mesh in one terminal."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify the local toolchain and mesh runtime preconditions.
    Doctor {
        /// Filter checks by developer profile (e.g. hft, ai, robotics).
        #[arg(long)]
        r#for: Option<String>,
    },
    /// Send pulses to a UDP destination.
    Send {
        /// Destination address (e.g. 127.0.0.1:9000).
        dest: String,
        /// Number of pulses to send.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Envelope payload size in bytes.
        #[arg(long, default_value_t = 16)]
        payload: usize,
    },
    /// Bind a UDP address and print received pulses.
    Recv {
        /// Local bind address (e.g. 127.0.0.1:9000).
        bind: String,
        /// Maximum pulses to receive before exiting.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Per-recv timeout in milliseconds.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Print workspace + codec version stamp.
    Version {
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Encode a JSON envelope spec and report the canonical wire bytes.
    Encode {
        /// Path to a JSON spec file (schema: `EnvelopeSpec` in
        /// `pulse_cli::commands::encode_decode`).
        #[arg(long = "json", value_name = "FILE")]
        json_path: PathBuf,
        /// Emit JSON instead of human-readable output.
        #[arg(long = "json-out")]
        json_out: bool,
    },
    /// Decode canonical wire hex back into an envelope summary.
    ///
    /// Exits with status 1 when the envelope does not verify: its content
    /// does not produce the identifier it carries.
    Decode {
        /// Hex string (whitespace trimmed).
        hex: String,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Snapshot a SHM-backed PulseRing (read-only secondary reader).
    Ring {
        #[command(subcommand)]
        action: RingAction,
    },
    /// List the M01..M12 optimization modules, optionally by profile.
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },
    /// Throughput and latency of pulses over UDP loopback on this host.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },

    /// Start the local `mesh-hub` daemon (UDS + WebSocket).
    ///
    /// In the background (the default) it waits up to 60 s for the daemon
    /// to serve, and stops one that does not (SIGTERM, then SIGKILL 5 s
    /// later) before it reports the failure and exits 1.
    Start {
        /// Run in the foreground (block until ^C).
        #[arg(long, default_value_t = false)]
        foreground: bool,
        /// Optional basket path for envelope capture.
        #[arg(long)]
        basket_path: Option<String>,
    },

    /// Attach to a running mesh-hub daemon under the given name and park.
    Attach {
        /// Process-visible name to register under.
        name: String,
    },

    /// Publish a one-shot envelope to a channel.
    Push {
        /// Routing key.
        channel: String,
        /// Payload as a UTF-8 string. Use `--hex` for raw bytes via hex.
        payload: String,
        /// Interpret `payload` as hex-encoded bytes.
        #[arg(long)]
        hex: bool,
        /// Optional type name.
        #[arg(long)]
        type_name: Option<String>,
    },

    /// Subscribe to a channel and print events live.
    Tap {
        /// Channel filter (exact or glob). Default: all.
        #[arg(long)]
        channel: Option<String>,
        /// Type-name filter.
        #[arg(long)]
        type_name: Option<String>,
        /// One JSON object per event instead of the table format.
        #[arg(long)]
        json: bool,
    },

    /// Spin up a 2-thread demo (send + recv on channel `hello`).
    Hello,

    /// One-command end-to-end smoke loop: auto-starts the daemon if
    /// needed, runs a 5-message producer/consumer demo, cleans up.
    ///
    /// It exits 1, saying how many arrived, when fewer than all five
    /// messages reach the consumer within 5 s. With `PMS_DAEMON` set it uses
    /// the daemon that names and starts none.
    Demo,

    /// Make and read the Ed25519 keys a client proves at attach.
    ///
    /// A key file is its owner's alone (mode 0600), and a client refuses one
    /// its group or others may read or write. Each subcommand prints the
    /// key's public half as a line of a daemon's `--attach-keys` list: its
    /// standard base64, 44 characters.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Print the generated reference pages the book carries.
    Docs {
        #[command(subcommand)]
        action: DocsAction,
    },
}

#[derive(Subcommand, Debug)]
enum KeysAction {
    /// Write a new key to a new file, readable and writable by its owner
    /// alone, and print its public key.
    ///
    /// Exits 1, replacing nothing, when the file exists or cannot be
    /// written.
    Generate {
        /// The key file to create.
        path: PathBuf,
    },
    /// Print the public key of a key file.
    ///
    /// Exits 1 when the file cannot be read, holds no key, or its group or
    /// others may read or write it.
    Public {
        /// The key file to read.
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum RingAction {
    /// Snapshot ring header + the N most-recent slot summaries.
    Inspect {
        /// Hub name (e.g. `default_hub`) or a raw POSIX SHM name
        /// starting with `/`; the ring's header gives its capacity.
        name: String,
        /// Number of most-recent slots to summarize.
        #[arg(long, default_value_t = 8)]
        count: usize,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ModulesAction {
    /// List modules, optionally filtered by developer profile.
    Ls {
        /// Filter by profile (hft, ai, robotics, telemetry, dev).
        #[arg(long = "for", value_name = "PROFILE")]
        r#for: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum BenchAction {
    /// Throughput and latency of pulses over UDP loopback on this host: the same run as `pulse bench`.
    Smoke {
        /// Number of pulses to send through the loopback.
        #[arg(long, default_value_t = pulse_cli::ops::bench::DEFAULT_PULSE_COUNT)]
        count: usize,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DocsAction {
    /// The `pms` command tree as Markdown, from the definitions that parse the real arguments.
    CliMarkdown,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Doctor { r#for } => commands::doctor::run(r#for.as_deref()),
        Command::Send {
            dest,
            count,
            payload,
        } => pulse_cli::commands::send_recv::run_send(&dest, count, payload),
        Command::Recv {
            bind,
            count,
            timeout_ms,
            json,
        } => pulse_cli::commands::send_recv::run_recv(&bind, count, timeout_ms, json),
        Command::Version { json } => pulse_cli::commands::version::run("pms (pms-cli)", json),
        Command::Encode {
            json_path,
            json_out,
        } => pulse_cli::commands::encode_decode::run_encode(&json_path, json_out),
        Command::Decode { hex, json } => pulse_cli::commands::encode_decode::run_decode(&hex, json),
        Command::Ring {
            action: RingAction::Inspect { name, count, json },
        } => commands::ring::run_inspect(&name, count, json),
        Command::Modules {
            action: ModulesAction::Ls { r#for, json },
        } => commands::modules::run_ls(r#for.as_deref(), json),
        Command::Bench {
            action: BenchAction::Smoke { count, json },
        } => pulse_cli::commands::bench::run(count, json),
        Command::Start {
            foreground,
            basket_path,
        } => commands::daemon::run_start(foreground, basket_path.as_deref()),
        Command::Attach { name } => commands::daemon::run_attach(&name),
        Command::Push {
            channel,
            payload,
            hex: hex_mode,
            type_name,
        } => {
            let bytes = if hex_mode {
                match hex::decode(payload.trim_start_matches("0x")) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("pms: hex decode failed: {}", e);
                        return ExitCode::from(2);
                    }
                }
            } else {
                payload.into_bytes()
            };
            commands::daemon::run_send(&channel, &bytes, type_name.as_deref())
        }
        Command::Tap {
            channel,
            type_name,
            json,
        } => commands::daemon::run_tap(channel.as_deref(), type_name.as_deref(), json),
        Command::Hello => commands::daemon::run_hello(),
        Command::Demo => commands::demo::run(),
        Command::Keys {
            action: KeysAction::Generate { path },
        } => commands::keys::run_generate(&path),
        Command::Keys {
            action: KeysAction::Public { path },
        } => commands::keys::run_public(&path),
        Command::Docs {
            action: DocsAction::CliMarkdown,
        } => commands::docs::run_cli_markdown(Cli::command()),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("pms: {err:#}");
            ExitCode::from(2)
        }
    }
}
