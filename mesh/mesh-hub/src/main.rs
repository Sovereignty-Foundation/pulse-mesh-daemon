// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh-hub`: the daemon's command line.
//!
//! Parses the flags into a [`DaemonConfig`] and runs [`mesh_hub::run`], the
//! same surface a host embeds; `--help` lists the flags and the exit statuses.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/reference/spec/07-port-protocol.html> (section 7.5).
#![forbid(unsafe_code)]

use clap::{CommandFactory, Parser};
use mesh_hub::link::{NodeKey, PublicKey};
use mesh_hub::protocol::framing::MAX_FRAME_LEN;
use mesh_hub::protocol::{DEFAULT_UDS_PATH, DEFAULT_WS_BIND};
#[cfg(feature = "basket")]
use mesh_hub::BasketConfig;
use mesh_hub::{
    AllowedOrigin, AnnounceConfig, AttachKeys, AttachKeysError, ConnectionPolicy, DaemonConfig,
    HubConfig, LinkConfig, LinkPeer, WsTls, WsTlsError, DEFAULT_STORE_SLOTS,
    DEFAULT_TOTAL_QUEUE_BYTES, DISPLACED_EXIT_STATUS, DISPLACEMENT_CHECK, MAX_QUEUE_EVENTS,
};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info};

/// The longest any timer flag takes, in seconds: a year, since a far longer
/// deadline could overflow the monotonic clock.
const MAX_TIMER_SECS: u64 = 365 * 24 * 60 * 60;

/// The smallest `--max-message-bytes`: below a kilobyte, an attach or a
/// subscribe with long names would not fit.
const MIN_MESSAGE_BYTES: u64 = 1024;

/// The flag range of a count or a size held in a `usize`.
fn usize_range(range: std::ops::RangeInclusive<u64>) -> clap::builder::RangedU64ValueParser<usize> {
    clap::builder::RangedU64ValueParser::<usize>::new().range(range)
}

/// A timer flag's value: 0 up to [`MAX_TIMER_SECS`].
fn timer_secs() -> clap::builder::RangedU64ValueParser<u64> {
    clap::value_parser!(u64).range(0..=MAX_TIMER_SECS)
}

/// A `--hub-name` the hub runtime can make shared-memory names of.
fn hub_name(value: &str) -> Result<String, String> {
    mesh_hub_runtime::hub_shm_names(value)
        .map(|_| value.to_string())
        .map_err(|_| {
            "a hub name is 1 to 15 characters from letters, digits, `_`, `.` and `-`".to_string()
        })
}

/// The daemon's exit statuses, which `--help` and the reference page list
/// after the flags.
fn exit_statuses() -> String {
    format!(
        "Exit status:\n\n\
         - 0: stopped by SIGINT or SIGTERM.\n\
         - 1: could not start, or could not install its signal handlers; the log says why (another daemon holds the socket, the port or the hub name, a store or a basket could not be made or opened, the WebSocket's TLS certificate or key could not be read or was refused, the --attach-keys file could not be read or holds a line that is not a key, the --node-key file could not be read or made, the --link-bind address could not be bound, or the --link-announce group could not be joined).\n\
         - 2: the command line was refused.\n\
         - {DISPLACED_EXIT_STATUS}: displaced. The hub name's lock file was removed while the daemon ran and another owner took the name, so the processes attached to the hub by name follow that owner and nothing sent to this daemon reaches them. The daemon notices within {DISPLACEMENT_CHECK:?}, logs at error level what happened and who holds the name now, closes its connections, removes its socket if the path still names it, and exits. A restart under the same `--hub-name` is refused while that owner lives, so a supervisor should not restart the daemon on this status (systemd: `RestartPreventExitStatus={DISPLACED_EXIT_STATUS}`).\n"
    )
}

/// A `--uds-path` a Unix socket address can hold.
fn uds_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err("the socket path is empty".to_string());
    }
    std::os::unix::net::SocketAddr::from_pathname(value)
        .map(|_| PathBuf::from(value))
        .map_err(|_| {
            format!(
                "{} bytes is longer than a Unix socket address holds on this system \
                 (sun_path: 103 bytes on macOS, 107 on Linux)",
                value.len()
            )
        })
}

#[derive(Debug, Parser)]
#[command(
    name = "mesh-hub",
    version,
    about = "Pulse Mesh local daemon — Universal Port Protocol terminator over UDS + WebSocket",
    after_help = exit_statuses()
)]
struct Args {
    /// Print this command line as the Markdown reference page the book carries, then exit.
    #[arg(long, hide = true)]
    dump_cli_markdown: bool,

    /// The hub name, which names its shared memory (`/pms-<name>` and
    /// `/pms-<name>-envelopes`): 1 to 15 characters from letters, digits, `_`,
    /// `.` and `-`.
    #[arg(long, default_value = "default_hub", value_parser = hub_name)]
    hub_name: String,

    /// Slots in the envelope store that keeps each envelope for the processes
    /// attached to the hub by name, 65,600 bytes of shared memory each: 0 (no
    /// store) to 4,294,967,295.
    #[arg(long, default_value_t = DEFAULT_STORE_SLOTS, value_parser = usize_range(0..=u64::from(u32::MAX)))]
    store_slots: usize,

    /// Unix-domain socket path, at most as long as a socket address holds
    /// (103 bytes on macOS, 107 on Linux).
    #[arg(long, default_value = DEFAULT_UDS_PATH, value_parser = uds_path)]
    uds_path: PathBuf,

    /// WebSocket bind address (`host:port`): a loopback address, unless
    /// `--ws-tls-cert` and `--attach-keys` are both given, so that the
    /// WebSocket is encrypted and its clients prove their keys, or
    /// `--ws-allow-remote` is.
    #[arg(long, default_value = DEFAULT_WS_BIND)]
    ws_bind: std::net::SocketAddr,

    /// Let `--ws-bind` take an address other than loopback without TLS and
    /// attach keys both. Without `--attach-keys` the WebSocket authenticates
    /// no client, so anything that can reach the address can attach, send and
    /// subscribe; without `--ws-tls-cert` nothing encrypts it, and a proof made
    /// at attach can be relayed as it is made. The daemon logs a warning when
    /// it binds such an address, naming what is missing.
    #[arg(long)]
    ws_allow_remote: bool,

    /// A PEM file of the certificate chain the WebSocket presents, its own
    /// certificate first. With `--ws-tls-key` (both or neither), the WebSocket
    /// is `wss://`: each connection completes a TLS 1.3 handshake before its
    /// upgrade, the two within `--handshake-timeout-secs`. TLS encrypts the
    /// WebSocket and authenticates the daemon to clients that trust the
    /// certificate; `--attach-keys` authenticates the clients, each proof
    /// bound to its TLS connection.
    #[arg(long, value_name = "PEM", requires = "ws_tls_key")]
    ws_tls_cert: Option<PathBuf>,

    /// A PEM file of the private key of `--ws-tls-cert`'s certificate (PKCS #8,
    /// PKCS #1 or SEC1); both or neither.
    #[arg(long, value_name = "PEM", requires = "ws_tls_cert")]
    ws_tls_key: Option<PathBuf>,

    /// A file of the Ed25519 public keys a client may prove at attach: one
    /// key's standard base64 per line, as `pms keys public` prints it, with
    /// `#` comments and blank lines. With it, an attach on the WebSocket must
    /// carry a listed key and answer the daemon's challenge with a proof of
    /// it within `--handshake-timeout-secs`, and is named by the key; one
    /// without a key, a proof that fails, or a key not listed is refused with
    /// `auth_failed`, and the connection closed. The Unix socket, which only
    /// the daemon's user can open, still admits an attach without a key unless
    /// `--attach-keys-uds` is given. A file that cannot be read, or holds a
    /// line that is not a key, stops the start (exit status 1).
    #[arg(long, value_name = "FILE")]
    attach_keys: Option<PathBuf>,

    /// Require a listed key, proved at attach, on the Unix socket too; needs
    /// `--attach-keys`.
    #[arg(long, requires = "attach_keys")]
    attach_keys_uds: bool,

    /// Serve the daemon's counts at `GET /metrics` on this address
    /// (`host:port`), in the Prometheus text format; off unless given. A
    /// loopback address unless `--metrics-allow-remote` is given.
    #[arg(long, value_name = "ADDR")]
    metrics_bind: Option<std::net::SocketAddr>,

    /// Let `--metrics-bind` take an address other than loopback. The endpoint
    /// has no authentication, so anything that can reach the address can read
    /// the daemon's counts; the daemon logs a warning when it binds one.
    #[arg(long)]
    metrics_allow_remote: bool,

    /// A web origin, `scheme://host[:port]`, whose pages may open the WebSocket
    /// besides pages served from `localhost`, `127.0.0.1` or `[::1]`
    /// (repeatable); other pages' upgrades get HTTP 403, and clients that send
    /// no `Origin` are admitted.
    #[arg(long = "allow-origin", value_name = "ORIGIN")]
    allow_origin: Vec<AllowedOrigin>,

    /// The file of this daemon's node key, the X25519 key its links to other
    /// daemons authenticate with: loaded, or, when there is no file, generated
    /// and saved with mode 0600. A file its group or others can read or write
    /// is refused. Links need it, `--link-bind` and at least one peer
    /// (`--link-peer` or `--link-peer-key`), all three or none. The daemon logs at startup its daemon
    /// id (the fingerprint of the key's public half, which names it across
    /// links), the public half, which its peers configure, its link address
    /// and its peers.
    #[arg(long, value_name = "FILE")]
    node_key: Option<PathBuf>,

    /// The UDP address (an IP address and port) every link to another daemon is sent
    /// from and received on: one sealed endpoint (Noise IK sessions,
    /// ChaCha20-Poly1305), whatever the number of peers. Links are off unless
    /// it is given, with `--node-key` and a peer.
    #[arg(long, value_name = "ADDR")]
    link_bind: Option<std::net::SocketAddr>,

    /// A daemon to link to, as `ADDR=PUBKEY`: the IP address and port of its
    /// `--link-bind`, and the public half of its node key as 64 hex digits
    /// (repeatable). Only the peers' keys are admitted, each of these from its
    /// address's IP. A client's send is forwarded, once, to each linked peer
    /// whose subscribers may want it, and what a peer forwards reaches the
    /// subscribers here, its origin `name@` and the sending daemon's id.
    #[arg(long = "link-peer", value_name = "ADDR=PUBKEY")]
    link_peer: Vec<LinkPeer>,

    /// A daemon to link to named by the public half of its node key alone, as
    /// 64 hex digits (repeatable). Its address is learned from its
    /// announcements on the `--link-announce` group, which this needs. Such a
    /// peer is admitted from any address its handshake comes from, its key
    /// authenticated as any peer's is, where a `--link-peer` is admitted only
    /// from its address's IP.
    #[arg(long = "link-peer-key", value_name = "PUBKEY")]
    link_peer_key: Vec<PublicKey>,

    /// An IPv4 multicast group and port, `GROUP:PORT` (the group's first
    /// byte 224 to 239, and 239 the range a site uses for its own), on which
    /// the daemon announces its link endpoint
    /// (its node key's public half and its link port) at startup and every 5
    /// seconds, and hears the other daemons' announcements; off unless given.
    /// An announcement is a plaintext hint, not signed. One from a key that is
    /// not a configured peer's is ignored; one from a configured peer's key,
    /// while no sealed session to it exists, asks for a handshake, which then
    /// authenticates the key: at the announced address for a
    /// `--link-peer-key`, and at its own address for a `--link-peer`, which no
    /// announcement changes; at most one such handshake per peer every 5
    /// seconds. Needs `--link-bind` to be an IPv4 address; the announcements
    /// leave by its interface when it is not 0.0.0.0.
    #[arg(long, value_name = "GROUP:PORT", value_parser = announce_group)]
    link_announce: Option<std::net::SocketAddrV4>,

    /// How many hops the `--link-announce` announcements may cross, their
    /// IPv4 TTL, 1 to 255. The default, 1, keeps them on the local network.
    #[arg(
        long,
        value_name = "TTL",
        requires = "link_announce",
        default_value_t = mesh_hub::link::DEFAULT_ANNOUNCE_TTL,
        value_parser = clap::value_parser!(u32).range(1..=255)
    )]
    link_announce_ttl: u32,

    /// Relay for the linked daemons (ADR-0021, item 9): forward once more
    /// what one peer sent, to the other peers whose subscribers may want it
    /// (never back to the peer it came from, nor to its origin's daemon),
    /// and tell each peer what the other peers that are not relays want and
    /// which clients they have, so that sends and `to` sends reach them
    /// through this daemon. A send crosses one relay at most: it leaves its
    /// origin with a hop limit of two, and a relay spends one. The peers
    /// see in its Hello that it relays; whether they accept what it relays
    /// is their own `--link-trust-relay`. Needs links.
    #[arg(long)]
    link_relay: bool,

    /// A configured peer, named by the public half of its node key as 64
    /// hex digits, whose relayed traffic this daemon accepts (repeatable):
    /// sends of other daemons' clients that it forwards, the clients it
    /// announces as reached through it, and their health. From any other
    /// peer such traffic is refused and counted. The peer's link
    /// authenticates the peer itself, but the origins it reports for what
    /// it relays are only as trustworthy as it is: nothing signs an
    /// envelope end to end. The key must be a `--link-peer`'s or a
    /// `--link-peer-key`. Needs links.
    #[arg(long = "link-trust-relay", value_name = "PUBKEY")]
    link_trust_relay: Vec<PublicKey>,

    /// Disable the UDS transport.
    #[arg(long)]
    no_uds: bool,

    /// Disable the WebSocket transport.
    #[arg(long)]
    no_ws: bool,

    /// Run in the foreground, the only mode; use a supervisor (launchd,
    /// systemd, `nohup`) to run it in the background.
    #[arg(long, default_value_t = true)]
    foreground: bool,

    /// Seconds between WebSocket pings, at most 31,536,000 (a year); 0
    /// disables them.
    #[arg(long, default_value_t = 30, value_parser = timer_secs())]
    ping_interval_secs: u64,

    /// Seconds of silence (no frame, no pong) before a connection is closed, at
    /// most 31,536,000 (a year); 0 disables the check.
    #[arg(long, default_value_t = 90, value_parser = timer_secs())]
    idle_timeout_secs: u64,

    /// Seconds one outbound write may take before the connection is
    /// closed as unreadable, at most 31,536,000 (a year); 0 waits forever.
    #[arg(long, default_value_t = 10, value_parser = timer_secs())]
    write_timeout_secs: u64,

    /// Seconds a WebSocket upgrade may take before the connection is
    /// dropped, the TLS handshake before it included on `wss://`, 1 to
    /// 31,536,000 (a year).
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=MAX_TIMER_SECS))]
    handshake_timeout_secs: u64,

    /// Largest message accepted on either transport, a WebSocket message
    /// counting whole however many frames it comes in: 1,024 to 4,294,967,295
    /// bytes.
    #[arg(long, default_value_t = 1_048_576, value_parser = usize_range(MIN_MESSAGE_BYTES..=MAX_FRAME_LEN as u64))]
    max_message_bytes: usize,

    /// Events queued per connection before newer ones are dropped and counted
    /// in the unsubscribe ack, 1 to 1,048,576.
    #[arg(long, default_value_t = 1024, value_parser = usize_range(1..=MAX_QUEUE_EVENTS as u64))]
    subscriber_queue: usize,

    /// Bytes of event JSON queued per connection, the event being written
    /// included, before newer events are dropped and counted; 0 drops every
    /// event.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    subscriber_queue_bytes: usize,

    /// Bytes of event JSON queued across all connections, shared so that one
    /// within its equal share takes room from the one holding the most. A
    /// subscriber that keeps up holds at most two events, so it loses no event
    /// to this budget while fewer connections hold events than this over twice
    /// `--max-message-bytes` (about 128 at the defaults); past that it can lose
    /// events too. 0 drops every event.
    #[arg(long, default_value_t = DEFAULT_TOTAL_QUEUE_BYTES)]
    total_queue_bytes: usize,

    /// Subscriptions one connection may hold at once, a subscribe beyond it
    /// refused with `limit_exceeded`; 0 refuses every subscribe.
    #[arg(long, default_value_t = 64)]
    max_subscriptions: usize,

    /// Connections the daemon holds at once across both transports, one beyond
    /// it refused (a `limit_exceeded` frame on the Unix socket, HTTP 503 on the
    /// WebSocket); 0 refuses every connection.
    #[arg(long, default_value_t = 256)]
    max_connections: usize,

    /// A basket SQLite file to capture every published envelope into, for
    /// `pms-query` and the `mesh_query` MCP tool. Each row keeps the
    /// envelope's payload until the retention sweep drops it, so the basket is
    /// the daemon's user's alone: the file and SQLite's files beside it are
    /// mode 0600, and a directory made for it 0700.
    #[cfg(feature = "basket")]
    #[arg(long)]
    basket_path: Option<String>,

    /// Seconds between the basket's retention sweeps, 1 to 31,536,000 (a year);
    /// no effect without `--basket-path`.
    #[cfg(feature = "basket")]
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=MAX_TIMER_SECS))]
    basket_retention_secs: u64,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let traces = init_tracing(&args);
    if args.dump_cli_markdown {
        use std::io::Write as _;
        let page = format!(
            "<!-- Generated by `mesh-hub --dump-cli-markdown` (scripts/docs/gen-all.sh); do not edit by hand. -->\n\
             # The mesh-hub daemon\n\n\
             <p class=\"pm-kind\"><b>Reference · generated</b> · every flag of the daemon with its default, printed by the binary itself</p>\n\n{}",
            mesh_hub::cli_docs::markdown(&Args::command())
        );
        let mut out = std::io::stdout().lock();
        return match out.write_all(page.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                error!("writing the reference page: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if let Err(refusal) = check_ws_bind(&args)
        .and_then(|()| check_metrics_bind(&args))
        .and_then(|()| check_links(&args))
    {
        traces.shutdown();
        Args::command()
            .error(clap::error::ErrorKind::ArgumentConflict, refusal)
            .exit();
    }
    info!(?args, "starting mesh-hub");
    let ws_tls = match ws_tls(&args) {
        Ok(tls) => tls,
        Err(e) => {
            error!("{e}");
            traces.shutdown();
            return std::process::ExitCode::from(1);
        }
    };
    let attach_keys = match attach_keys(&args) {
        Ok(keys) => keys,
        Err(e) => {
            error!("{e}");
            traces.shutdown();
            return std::process::ExitCode::from(1);
        }
    };

    let links = match link_config(&args) {
        Ok(links) => links,
        Err(e) => {
            error!("{e}");
            traces.shutdown();
            return std::process::ExitCode::from(1);
        }
    };

    let config = daemon_config(&args).with_ws_tls(ws_tls).with_links(links);
    let policy = config.policy.clone().with_attach_keys(attach_keys);
    let status = match mesh_hub::run(config.with_policy(policy)).await {
        Ok(exit) => std::process::ExitCode::from(exit.status()),
        Err(e) => {
            error!("{e}");
            std::process::ExitCode::from(1)
        }
    };
    traces.shutdown();
    status
}

/// Refuse a WebSocket bound to an address other than loopback unless TLS
/// encrypts it and attach keys authenticate its clients, or
/// `--ws-allow-remote` says that is meant: otherwise a network address serves
/// the hub to whoever reaches it, or in plaintext. The refusal names what is
/// missing.
fn check_ws_bind(args: &Args) -> Result<(), String> {
    if args.no_ws || args.ws_allow_remote || args.ws_bind.ip().is_loopback() {
        return Ok(());
    }
    let exposure = match (args.ws_tls_cert.is_some(), args.attach_keys.is_some()) {
        (true, true) => return Ok(()),
        (true, false) => {
            "TLS (--ws-tls-cert) encrypts the WebSocket but authenticates no client, \
             so anything that can reach that address could still attach, send and \
             subscribe. Missing: --attach-keys, so that clients prove a listed key \
             at attach."
        }
        (false, true) => {
            "--attach-keys makes clients prove a listed key at attach, but without \
             TLS the WebSocket is plaintext: anything on the path could read and \
             change what follows an attach, and relay a proof as it is made. \
             Missing: --ws-tls-cert and --ws-tls-key."
        }
        (false, false) => {
            "The WebSocket has no authentication and no encryption, so anything \
             that can reach that address could attach, send and subscribe. \
             Missing: TLS (--ws-tls-cert, --ws-tls-key), which encrypts it, and \
             --attach-keys, so that clients prove a listed key at attach."
        }
    };
    Err(format!(
        "--ws-bind {} is not a loopback address. {exposure} Bind it to 127.0.0.1 \
         or [::1], add what is missing, or add --ws-allow-remote to bind it \
         anyway.",
        args.ws_bind
    ))
}

/// Refuse links half configured: `--node-key`, `--link-bind` and a peer
/// (`--link-peer` or `--link-peer-key`) come together or not at all, a
/// `--link-peer-key` needs `--link-announce`, `--link-announce`,
/// `--link-announce-ttl`, `--link-relay` and `--link-trust-relay` need
/// links, and a `--link-trust-relay` names a configured peer's key.
fn check_links(args: &Args) -> Result<(), String> {
    let given = [
        ("--node-key", args.node_key.is_some()),
        ("--link-bind", args.link_bind.is_some()),
        (
            "--link-peer or --link-peer-key",
            !args.link_peer.is_empty() || !args.link_peer_key.is_empty(),
        ),
    ];
    let announcing = args.link_announce.is_some();
    let relaying = args.link_relay || !args.link_trust_relay.is_empty();
    let none = given.iter().all(|(_, on)| !*on);
    if none && !announcing && !relaying {
        return Ok(());
    }
    if !given.iter().all(|(_, on)| *on) {
        let missing: Vec<&str> = given
            .iter()
            .filter(|(_, on)| !*on)
            .map(|(flag, _)| *flag)
            .collect();
        return Err(format!(
            "links to other daemons need --node-key, --link-bind and at least one --link-peer \
             or --link-peer-key; missing: {}",
            missing.join(", ")
        ));
    }
    if !args.link_peer_key.is_empty() && !announcing {
        return Err(
            "a --link-peer-key names a peer whose address its announcements give, \
             so it needs --link-announce"
                .to_string(),
        );
    }
    let peer_keys: Vec<PublicKey> = args
        .link_peer
        .iter()
        .map(|peer| peer.key)
        .chain(args.link_peer_key.iter().copied())
        .collect();
    if let Some(key) = args
        .link_trust_relay
        .iter()
        .find(|key| !peer_keys.contains(key))
    {
        return Err(format!(
            "--link-trust-relay {key} is not a configured peer's key: a relay is trusted \
             only as a peer, so it needs a --link-peer or --link-peer-key with that key"
        ));
    }
    Ok(())
}

/// A `--link-announce` group: an IPv4 multicast address and a port.
fn announce_group(value: &str) -> Result<std::net::SocketAddrV4, String> {
    let group: std::net::SocketAddrV4 = value
        .parse()
        .map_err(|_| format!("{value:?} is not an IPv4 address and port"))?;
    if !group.ip().is_multicast() || group.port() == 0 {
        return Err(format!(
            "{group} is not an IPv4 multicast group (its first byte 224 to 239) and a port \
             other than 0"
        ));
    }
    Ok(group)
}

/// The links from `--node-key`, `--link-bind`, the peers and
/// `--link-announce`, the key loaded or generated; none without them.
fn link_config(args: &Args) -> Result<Option<LinkConfig>, String> {
    let (Some(path), Some(bind)) = (&args.node_key, args.link_bind) else {
        return Ok(None);
    };
    let key = NodeKey::load_or_generate(path)
        .map_err(|e| format!("the node key could not be loaded or made: {e}"))?;
    let config = args
        .link_peer
        .iter()
        .fold(LinkConfig::new(key, bind), |config, peer| {
            config.with_peer(*peer)
        });
    let config = args
        .link_peer_key
        .iter()
        .fold(config, |config, key| config.with_peer_key(*key));
    let config = match args.link_announce {
        Some(group) => {
            config.with_announce(AnnounceConfig::new(group).with_ttl(args.link_announce_ttl))
        }
        None => config,
    };
    let config = if args.link_relay {
        config.with_relay()
    } else {
        config
    };
    let config = args
        .link_trust_relay
        .iter()
        .fold(config, |config, key| config.with_trusted_relay(*key));
    Ok(Some(config))
}

/// The keys `--attach-keys` lists, read and checked; none without it.
fn attach_keys(args: &Args) -> Result<Option<AttachKeys>, AttachKeysError> {
    args.attach_keys
        .as_deref()
        .map(AttachKeys::from_file)
        .transpose()
}

/// The WebSocket's TLS from `--ws-tls-cert` and `--ws-tls-key`, read and
/// checked; none without them, or with `--no-ws`.
fn ws_tls(args: &Args) -> Result<Option<WsTls>, WsTlsError> {
    match (&args.ws_tls_cert, &args.ws_tls_key) {
        (Some(cert), Some(key)) if !args.no_ws => WsTls::from_pem_files(cert, key).map(Some),
        _ => Ok(None),
    }
}

/// Refuse a metrics endpoint on an address other than loopback unless
/// `--metrics-allow-remote` says that is meant: nothing authenticates it.
fn check_metrics_bind(args: &Args) -> Result<(), String> {
    match args.metrics_bind {
        Some(addr) if !args.metrics_allow_remote && !addr.ip().is_loopback() => Err(format!(
            "--metrics-bind {addr} is not a loopback address. The metrics endpoint has no \
             authentication, so anything that can reach that address could read the \
             daemon's counts. Bind it to 127.0.0.1 or [::1], or add --metrics-allow-remote \
             to bind it anyway."
        )),
        _ => Ok(()),
    }
}

/// The daemon's configuration from the command line.
fn daemon_config(args: &Args) -> DaemonConfig {
    let config = DaemonConfig::new(args.hub_name.clone())
        .with_hub(hub_config(args))
        .with_uds_path((!args.no_uds).then(|| args.uds_path.clone()))
        .with_ws_bind((!args.no_ws).then_some(args.ws_bind))
        .with_metrics_bind(args.metrics_bind)
        .with_policy(policy(args));
    #[cfg(feature = "basket")]
    let config = config.with_basket(args.basket_path.as_ref().map(|path| {
        BasketConfig::new(
            PathBuf::from(path),
            Duration::from_secs(args.basket_retention_secs),
        )
    }));
    config
}

/// The hub's configuration: `--store-slots`, and the ring and the validation
/// mode at their defaults.
fn hub_config(args: &Args) -> HubConfig {
    HubConfig::default().with_store_slots(args.store_slots)
}

/// The connection policy from the command line.
fn policy(args: &Args) -> ConnectionPolicy {
    ConnectionPolicy::default()
        .with_ping_interval(Duration::from_secs(args.ping_interval_secs))
        .with_idle_timeout(Duration::from_secs(args.idle_timeout_secs))
        .with_write_timeout(Duration::from_secs(args.write_timeout_secs))
        .with_handshake_timeout(Duration::from_secs(args.handshake_timeout_secs))
        .with_max_message_bytes(args.max_message_bytes)
        .with_subscriber_queue(args.subscriber_queue)
        .with_subscriber_queue_bytes(args.subscriber_queue_bytes)
        .with_total_queue_bytes(args.total_queue_bytes)
        .with_max_subscriptions(args.max_subscriptions)
        .with_max_connections(args.max_connections)
        .with_allowed_origins(args.allow_origin.clone())
        .with_attach_keys_uds(args.attach_keys_uds)
}

/// The span export [`init_tracing`] started: with the `otel` feature, the OTLP
/// exporter when the environment names a collector (`mesh_hub::otel`), and
/// otherwise none.
struct TraceExport {
    #[cfg(feature = "otel")]
    exporter: Option<mesh_hub::otel::Traces>,
}

impl TraceExport {
    /// Export the spans still batched, as the daemon exits.
    fn shutdown(self) {
        #[cfg(feature = "otel")]
        if let Some(exporter) = self.exporter {
            if let Err(e) = exporter.shutdown() {
                error!("the last traces could not be exported: {e}");
            }
        }
    }
}

/// Install the log, on standard output at `MESH_HUB_LOG`'s levels, and with the
/// `otel` feature, when the environment names a collector, the layer that
/// exports the daemon's spans to it; `--dump-cli-markdown` exports nothing, as
/// its output is the page.
///
/// The daemon's spans stay out of the log, which is the same with the feature
/// or without it, and with a collector or without one, but for the line that
/// says where the traces go.
fn init_tracing(args: &Args) -> TraceExport {
    use std::io::IsTerminal;
    use tracing_subscriber::filter::{filter_fn, FilterExt as _, LevelFilter};
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{EnvFilter, Layer as _};
    let filter = EnvFilter::try_from_env("MESH_HUB_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,mesh_hub=info"));
    let mut log = tracing_subscriber::fmt::layer().with_target(false);
    // Colour only on a terminal (`pms start` logs to a file; `tests/log.rs`),
    // where the layer's default also honours NO_COLOR.
    if !std::io::stdout().is_terminal() {
        log = log.with_ansi(false);
    }
    // The hint keeps the filter's level, so a span or an event below it
    // costs a level check.
    let not_a_daemon_span =
        filter_fn(|meta| !(meta.is_span() && meta.target().starts_with("mesh_hub")))
            .with_max_level_hint(LevelFilter::TRACE);
    let log = log.with_filter(filter.and(not_a_daemon_span));
    let subscriber = tracing_subscriber::registry().with(log);

    #[cfg(feature = "otel")]
    {
        let exporter = if args.dump_cli_markdown {
            Ok(None)
        } else {
            mesh_hub::otel::Traces::from_env(&args.hub_name)
        };
        let (exporter, refused) = match exporter {
            Ok(exporter) => (exporter, None),
            Err(e) => (None, Some(e)),
        };
        let subscriber = subscriber.with(exporter.as_ref().map(mesh_hub::otel::Traces::layer));
        let _ = tracing::subscriber::set_global_default(subscriber);
        if let Some(exporter) = &exporter {
            info!(
                endpoint = exporter.endpoint(),
                "exporting traces over OTLP/HTTP"
            );
        }
        if let Some(e) = refused {
            error!("traces are not exported: {e}");
        }
        TraceExport { exporter }
    }
    #[cfg(not(feature = "otel"))]
    {
        let _ = args;
        let _ = tracing::subscriber::set_global_default(subscriber);
        TraceExport {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn parse(flags: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("mesh-hub").chain(flags.iter().copied()))
    }

    /// `--store-slots` reaches the hub's configuration, and nothing else in
    /// the configuration moves with it.
    #[test]
    fn store_slots_reach_the_hub_config() {
        assert_eq!(
            hub_config(&parse(&[]).unwrap()).store_slots,
            DEFAULT_STORE_SLOTS
        );
        let small = hub_config(&parse(&["--store-slots", "16"]).unwrap());
        assert_eq!(small.store_slots, 16);
        assert_eq!(small.ring_size, HubConfig::default().ring_size);
        assert_eq!(small.validation, HubConfig::default().validation);
        assert_eq!(
            hub_config(&parse(&["--store-slots", "0"]).unwrap()).store_slots,
            0
        );
        assert!(parse(&["--store-slots", "-1"]).is_err());
    }

    /// The flags reach the daemon's configuration: each transport is
    /// served unless its flag disables it, and the policy carries every
    /// limit.
    #[test]
    fn the_flags_reach_the_daemon_config() {
        let config = daemon_config(&parse(&[]).unwrap());
        assert_eq!(config.hub_name, "default_hub");
        assert_eq!(config.uds_path, Some(PathBuf::from(DEFAULT_UDS_PATH)));
        assert_eq!(config.ws_bind, Some(DEFAULT_WS_BIND.parse().unwrap()));
        assert_eq!(
            config.policy.max_connections,
            ConnectionPolicy::default().max_connections
        );
        let none =
            daemon_config(&parse(&["--no-uds", "--no-ws", "--max-connections", "7"]).unwrap());
        assert_eq!(none.uds_path, None);
        assert_eq!(none.ws_bind, None);
        assert_eq!(none.policy.max_connections, 7);
    }

    /// A WebSocket on loopback, or none at all, passes; one on any other
    /// address is refused, naming `--ws-allow-remote`, unless that flag is
    /// given.
    #[test]
    fn a_websocket_off_loopback_needs_ws_allow_remote() {
        for flags in [
            &[][..],
            &["--ws-bind", "127.0.0.1:0"][..],
            &["--ws-bind", "[::1]:9876"][..],
            &["--ws-bind", "0.0.0.0:9876", "--no-ws"][..],
            &["--ws-bind", "0.0.0.0:9876", "--ws-allow-remote"][..],
            &["--ws-bind", "[::]:9876", "--ws-allow-remote"][..],
        ] {
            assert_eq!(check_ws_bind(&parse(flags).unwrap()), Ok(()), "{flags:?}");
        }
        for addr in ["0.0.0.0:9876", "[::]:9876", "192.168.1.20:9876"] {
            let refusal = check_ws_bind(&parse(&["--ws-bind", addr]).unwrap()).unwrap_err();
            assert!(refusal.contains("--ws-allow-remote"), "{refusal}");
            assert!(refusal.contains("no authentication"), "{refusal}");
            assert!(
                refusal.contains("Missing: TLS (--ws-tls-cert, --ws-tls-key)")
                    && refusal.contains("--attach-keys"),
                "{refusal}"
            );
        }
        // TLS alone does not lift the refusal, and the refusal says why.
        let off = ["--ws-bind", "0.0.0.0:9876"];
        let tls = ["--ws-tls-cert", "cert.pem", "--ws-tls-key", "key.pem"];
        let keys = ["--attach-keys", "attach.keys"];
        let flags = [&off[..], &tls[..]].concat();
        let refusal = check_ws_bind(&parse(&flags).unwrap()).unwrap_err();
        assert!(refusal.contains("--ws-allow-remote"), "{refusal}");
        assert!(refusal.contains("authenticates no client"), "{refusal}");
        assert!(refusal.contains("could still attach"), "{refusal}");
        assert!(refusal.contains("Missing: --attach-keys"), "{refusal}");
        let allowed = [&flags[..], &["--ws-allow-remote"][..]].concat();
        assert_eq!(check_ws_bind(&parse(&allowed).unwrap()), Ok(()));
        // Nor do attach keys alone.
        let flags = [&off[..], &keys[..]].concat();
        let refusal = check_ws_bind(&parse(&flags).unwrap()).unwrap_err();
        assert!(refusal.contains("--ws-allow-remote"), "{refusal}");
        assert!(
            refusal.contains("Missing: --ws-tls-cert and --ws-tls-key"),
            "{refusal}"
        );
        // TLS and attach keys together do: the clients are authenticated and
        // the channel encrypted.
        let flags = [&off[..], &tls[..], &keys[..]].concat();
        assert_eq!(check_ws_bind(&parse(&flags).unwrap()), Ok(()));
    }

    /// `--attach-keys` is read into the policy's keys, a file that is not a
    /// list refused before anything starts; `--attach-keys-uds` needs it.
    #[test]
    fn the_attach_keys_flags_reach_the_policy() {
        assert_eq!(attach_keys(&parse(&[]).unwrap()).unwrap(), None);
        assert!(!policy(&parse(&[]).unwrap()).attach_keys_uds);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attach.keys");
        let key = mesh_hub::protocol::attach::encode_key(&[0x11; 32]);
        std::fs::write(&path, format!("# one\n{key}\n")).unwrap();
        let file = path.to_str().unwrap();
        let args = parse(&["--attach-keys", file, "--attach-keys-uds"]).unwrap();
        let keys = attach_keys(&args).unwrap().expect("the keys");
        assert!(keys.contains(&[0x11; 32]) && keys.len() == 1);
        assert!(policy(&args).attach_keys_uds);
        std::fs::write(&path, "not a key\n").unwrap();
        let err = attach_keys(&args).unwrap_err().to_string();
        assert!(err.contains("line 1") && err.contains(file), "{err}");
        let err = parse(&["--attach-keys-uds"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--attach-keys"), "{err}");
    }

    /// `--ws-tls-cert` and `--ws-tls-key` come together or not at all, one
    /// alone refused as the command line is parsed (exit status 2); together
    /// they are read and checked into the WebSocket's TLS, unless `--no-ws`.
    #[test]
    fn the_tls_flags_come_together() {
        for (given, missing) in [
            (["--ws-tls-cert", "cert.pem"], "--ws-tls-key"),
            (["--ws-tls-key", "key.pem"], "--ws-tls-cert"),
        ] {
            let err = parse(&given).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{err}"
            );
            assert_eq!(err.exit_code(), 2);
            assert!(err.to_string().contains(missing), "{err}");
        }
        assert_eq!(ws_tls(&parse(&[]).unwrap()).unwrap(), None);

        let dir = tempfile::tempdir().unwrap();
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        std::fs::write(&cert, made.cert.pem()).unwrap();
        std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();
        let (cert, key) = (cert.to_str().unwrap(), key.to_str().unwrap());
        let tls = ws_tls(&parse(&["--ws-tls-cert", cert, "--ws-tls-key", key]).unwrap())
            .unwrap()
            .expect("the flags make the WebSocket wss://");
        assert_eq!(tls.chain_len(), 1);
        let off = parse(&["--no-ws", "--ws-tls-cert", cert, "--ws-tls-key", key]).unwrap();
        assert_eq!(ws_tls(&off).unwrap(), None);
        let swapped = parse(&["--ws-tls-cert", key, "--ws-tls-key", cert]).unwrap();
        assert!(matches!(ws_tls(&swapped), Err(WsTlsError::Certificates(_))));
    }

    /// Metrics are off unless asked for; on loopback they pass, and off it they
    /// are refused, naming `--metrics-allow-remote`, unless that flag is given.
    #[test]
    fn metrics_off_loopback_need_metrics_allow_remote() {
        assert_eq!(daemon_config(&parse(&[]).unwrap()).metrics_bind, None);
        let on = parse(&["--metrics-bind", "127.0.0.1:9877"]).unwrap();
        assert_eq!(check_metrics_bind(&on), Ok(()));
        assert_eq!(
            daemon_config(&on).metrics_bind,
            Some("127.0.0.1:9877".parse().unwrap())
        );
        let allowed = parse(&["--metrics-bind", "0.0.0.0:9877", "--metrics-allow-remote"]).unwrap();
        assert_eq!(check_metrics_bind(&allowed), Ok(()));
        let refusal =
            check_metrics_bind(&parse(&["--metrics-bind", "0.0.0.0:9877"]).unwrap()).unwrap_err();
        assert!(refusal.contains("--metrics-allow-remote"), "{refusal}");
    }

    /// Every flag's range is checked as the flags are parsed, with the range in
    /// the message.
    #[test]
    fn every_flag_out_of_its_range_is_refused_with_the_range() {
        let refused = [
            (
                "--ping-interval-secs",
                "18446744073709551615",
                "0..=31536000",
            ),
            (
                "--idle-timeout-secs",
                "18446744073709551615",
                "0..=31536000",
            ),
            ("--write-timeout-secs", "31536001", "0..=31536000"),
            ("--handshake-timeout-secs", "0", "1..=31536000"),
            ("--subscriber-queue", "2305843009213693952", "1..=1048576"),
            ("--subscriber-queue", "0", "1..=1048576"),
            ("--max-message-bytes", "1023", "1024..=4294967295"),
            ("--max-message-bytes", "4294967296", "1024..=4294967295"),
            ("--store-slots", "4294967296", "0..=4294967295"),
            ("--hub-name", "sixteen-chars-xx", "1 to 15 characters"),
            ("--hub-name", "a/b", "1 to 15 characters"),
            ("--ws-bind", "localhost", "socket address"),
            ("--uds-path", "", "empty"),
        ];
        for (flag, value, says) in refused {
            let err = parse(&[flag, value]).unwrap_err().to_string();
            assert!(
                err.contains(flag) && err.contains(says),
                "{flag} {value}: {err}"
            );
        }
        let long = format!("/tmp/{}", "x".repeat(120));
        let err = parse(&["--uds-path", &long]).unwrap_err().to_string();
        assert!(
            err.contains("longer than a Unix socket address holds"),
            "{err}"
        );

        // The ends of each range are taken.
        let args = parse(&[
            "--ping-interval-secs",
            "31536000",
            "--idle-timeout-secs",
            "0",
            "--handshake-timeout-secs",
            "1",
            "--subscriber-queue",
            "1048576",
            "--max-message-bytes",
            "1024",
            "--store-slots",
            "4294967295",
            "--total-queue-bytes",
            "0",
        ])
        .unwrap();
        assert_eq!(args.ping_interval_secs, MAX_TIMER_SECS);
        assert_eq!(args.subscriber_queue, MAX_QUEUE_EVENTS);
        assert_eq!(args.max_message_bytes, 1024);
        assert_eq!(args.store_slots, u32::MAX as usize);
        assert_eq!(args.total_queue_bytes, 0);
    }

    /// The defaults parse, and give the connection policy's defaults.
    #[test]
    fn the_defaults_are_the_policys() {
        let args = parse(&[]).unwrap();
        let policy = ConnectionPolicy::default();
        assert_eq!(args.hub_name, "default_hub");
        assert_eq!(args.uds_path, PathBuf::from(DEFAULT_UDS_PATH));
        assert_eq!(args.ws_bind, DEFAULT_WS_BIND.parse().unwrap());
        assert_eq!(args.subscriber_queue, policy.subscriber_queue);
        assert_eq!(args.subscriber_queue_bytes, policy.subscriber_queue_bytes);
        assert_eq!(args.total_queue_bytes, policy.total_queue_bytes);
        assert_eq!(args.max_message_bytes, policy.max_message_bytes);
        assert_eq!(args.max_subscriptions, policy.max_subscriptions);
        assert_eq!(args.max_connections, policy.max_connections);
        assert_eq!(
            Duration::from_secs(args.idle_timeout_secs),
            policy.idle_timeout
        );
        assert_eq!(
            Duration::from_secs(args.ping_interval_secs),
            policy.ping_interval
        );
    }

    /// `--help` and the reference page list every exit status, and the
    /// displaced daemon's is none of the others.
    #[test]
    fn the_help_and_the_reference_page_list_the_exit_statuses() {
        assert!(!matches!(DISPLACED_EXIT_STATUS, 0..=2));
        let displaced = format!("- {DISPLACED_EXIT_STATUS}: displaced.");
        let help = Args::command().render_long_help().to_string();
        let page = mesh_hub::cli_docs::markdown(&Args::command());
        for text in [&help, &page] {
            for status in [
                "- 0: stopped by SIGINT or SIGTERM",
                "- 1: ",
                "- 2: ",
                &displaced,
            ] {
                assert!(text.contains(status), "{status}:\n{text}");
            }
            assert!(
                text.contains(&format!("RestartPreventExitStatus={DISPLACED_EXIT_STATUS}")),
                "{text}"
            );
        }
    }

    /// `--total-queue-bytes`'s help, in `--help` and on the reference
    /// page, says what a subscriber that keeps up is promised and when the
    /// promise ends, with the number of connections the defaults give.
    #[test]
    fn the_queue_budget_help_says_when_a_reader_that_keeps_up_can_lose_events() {
        let policy = ConnectionPolicy::default();
        let connections = policy.total_queue_bytes / (2 * policy.max_message_bytes);
        let help = Args::command().render_long_help().to_string();
        let page = mesh_hub::cli_docs::markdown(&Args::command());
        for text in [&help, &page] {
            let flag = text
                .split("--total-queue-bytes")
                .nth(1)
                .expect("the flag is listed");
            for says in [
                "keeps up holds at most two events".to_string(),
                "loses no event to this budget".to_string(),
                format!("(about {connections} at the defaults)"),
                "can lose events too".to_string(),
            ] {
                assert!(flag.contains(&says), "{says}:\n{flag}");
            }
        }
    }

    /// An administratively scoped multicast group and port, as a flag's
    /// text.
    fn group(port: u16) -> String {
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(239, 255, 80, 1), port).to_string()
    }

    /// `--node-key`, `--link-bind` and `--link-peer` come together or not
    /// at all; together they make the links, the key generated into a file
    /// of mode 0600 on the first start and loaded on the next.
    #[test]
    fn the_link_flags_come_together() {
        assert_eq!(check_links(&parse(&[]).unwrap()), Ok(()));
        assert_eq!(link_config(&parse(&[]).unwrap()).unwrap().map(|_| ()), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let file = path.to_str().unwrap();
        let peer_key = NodeKey::generate().unwrap().public_key();
        let peer = format!("127.0.0.1:7401={peer_key}");
        let peers = "--link-peer or --link-peer-key";
        let group = group(7401);
        for (flags, missing) in [
            (&["--node-key", file][..], format!("--link-bind, {peers}")),
            (
                &["--link-bind", "127.0.0.1:7400"][..],
                format!("--node-key, {peers}"),
            ),
            (
                &["--link-peer", peer.as_str()][..],
                "--node-key, --link-bind".to_string(),
            ),
            (
                &["--node-key", file, "--link-bind", "127.0.0.1:7400"][..],
                peers.to_string(),
            ),
            (
                &["--link-announce", group.as_str()][..],
                format!("--node-key, --link-bind, {peers}"),
            ),
        ] {
            let refusal = check_links(&parse(flags).unwrap()).unwrap_err();
            assert!(
                refusal.ends_with(&format!("missing: {missing}")),
                "{refusal}"
            );
        }
        let args = parse(&[
            "--node-key",
            file,
            "--link-bind",
            "127.0.0.1:7400",
            "--link-peer",
            &peer,
        ])
        .unwrap();
        assert_eq!(check_links(&args), Ok(()));
        let made = link_config(&args).unwrap().expect("links");
        assert_eq!(made.bind, "127.0.0.1:7400".parse().unwrap());
        assert_eq!(made.peers.len(), 1);
        assert_eq!(made.peers[0].key, peer_key);
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let again = link_config(&args).unwrap().expect("links");
        assert_eq!(
            again.public_key(),
            made.public_key(),
            "the saved key is loaded"
        );
        let err = parse(&["--link-peer", "127.0.0.1:7401"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("ADDR=PUBKEY"), "{err}");
    }

    /// A `--link-peer-key` needs `--link-announce`, whose group is an IPv4
    /// multicast address, and `--link-announce-ttl` needs it too; together
    /// they make links that announce, with key-only peers beside fixed ones.
    #[test]
    fn a_peer_named_by_its_key_is_found_by_announcement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let file = path.to_str().unwrap();
        let fixed_key = NodeKey::generate().unwrap().public_key();
        let fixed = format!("127.0.0.1:7401={fixed_key}");
        let alone = NodeKey::generate().unwrap().public_key().to_string();
        let base = ["--node-key", file, "--link-bind", "127.0.0.1:7400"];
        let (group, no_port) = (group(7401), group(0));
        let args = parse(&[&base[..], &["--link-peer-key", &alone]].concat()).unwrap();
        let refusal = check_links(&args).unwrap_err();
        assert!(refusal.contains("needs --link-announce"), "{refusal}");
        let announced = [
            "--link-peer-key",
            &alone,
            "--link-peer",
            &fixed,
            "--link-announce",
            &group,
        ];
        let args = parse(&[&base[..], &announced[..]].concat()).unwrap();
        assert_eq!(check_links(&args), Ok(()));
        let made = link_config(&args).unwrap().expect("links");
        assert_eq!(made.peer_keys, [alone.parse().unwrap()]);
        assert_eq!(made.peers.len(), 1);
        let announce = made.announce.expect("announcing");
        assert_eq!(announce.group.to_string(), group);
        assert_eq!(announce.ttl, 1);
        let ttl =
            parse(&[&base[..], &announced[..], &["--link-announce-ttl", "4"]].concat()).unwrap();
        assert_eq!(link_config(&ttl).unwrap().unwrap().announce.unwrap().ttl, 4);
        for bad in [
            &["--link-announce", "192.0.2.1:7401"][..],
            &["--link-announce", &no_port][..],
            &["--link-announce", "[ff02::1]:7401"][..],
            &["--link-announce-ttl", "2"][..],
            &["--link-announce", &group, "--link-announce-ttl", "0"][..],
            &["--link-peer-key", "abcd"][..],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// `--link-relay` and `--link-trust-relay` need links, and a trusted
    /// relay is a configured peer; together they make links that relay and
    /// trust the peers named.
    #[test]
    fn a_trusted_relay_is_a_configured_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let file = path.to_str().unwrap();
        let fixed_key = NodeKey::generate().unwrap().public_key();
        let fixed = format!("127.0.0.1:7401={fixed_key}");
        let alone = NodeKey::generate().unwrap().public_key().to_string();
        let stranger = NodeKey::generate().unwrap().public_key().to_string();
        let group = group(7401);
        let base = [
            "--node-key",
            file,
            "--link-bind",
            "127.0.0.1:7400",
            "--link-peer",
            &fixed,
            "--link-peer-key",
            &alone,
            "--link-announce",
            &group,
        ];
        let fixed_text = fixed_key.to_string();
        let trusting = [
            "--link-relay",
            "--link-trust-relay",
            &fixed_text,
            "--link-trust-relay",
            &alone,
        ];
        let args = parse(&[&base[..], &trusting[..]].concat()).unwrap();
        assert_eq!(check_links(&args), Ok(()));
        let made = link_config(&args).unwrap().expect("links");
        assert!(made.relay);
        assert_eq!(made.trusted_relays, [fixed_key, alone.parse().unwrap()]);
        let plain = link_config(&parse(&base).unwrap()).unwrap().expect("links");
        assert!(
            !plain.relay && plain.trusted_relays.is_empty(),
            "off by default"
        );
        let refusal =
            check_links(&parse(&[&base[..], &["--link-trust-relay", &stranger]].concat()).unwrap())
                .unwrap_err();
        assert!(refusal.contains("not a configured peer's key"), "{refusal}");
        assert!(refusal.contains(&stranger), "{refusal}");
        for alone_flag in [&["--link-relay"][..], &["--link-trust-relay", &alone][..]] {
            let refusal = check_links(&parse(alone_flag).unwrap()).unwrap_err();
            assert!(refusal.contains("missing: --node-key"), "{refusal}");
        }
        assert!(parse(&["--link-trust-relay", "abcd"]).is_err());
    }

    /// `--allow-origin` repeats, keeps each origin in the form a browser
    /// sends, and refuses what is not an origin.
    #[test]
    fn allow_origin_repeats_and_refuses_what_is_not_an_origin() {
        assert!(parse(&[]).unwrap().allow_origin.is_empty());
        let args = parse(&[
            "--allow-origin",
            "https://App.example:443",
            "--allow-origin",
            "http://intranet.lan:8080",
        ])
        .unwrap();
        let origins: Vec<&str> = args
            .allow_origin
            .iter()
            .map(AllowedOrigin::as_str)
            .collect();
        assert_eq!(origins, ["https://app.example", "http://intranet.lan:8080"]);
        for bad in ["https://example.com/", "null", "example.com"] {
            let err = parse(&["--allow-origin", bad]).unwrap_err();
            assert!(err.to_string().contains("is not an origin"), "{bad}: {err}");
        }
    }
}
