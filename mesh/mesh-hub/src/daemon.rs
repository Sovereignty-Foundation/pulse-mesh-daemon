// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon as a library: [`run`] and its [`DaemonConfig`].

use crate::connection::ConnectionPolicy;
use crate::health;
use crate::hub_bridge::{name_holder, HubBridge};
use crate::link::{LinkConfig, LinkSetupError};
use crate::metrics::{bind_metrics, serve_metrics};
use crate::registry::Registry;
use crate::server::{bind_ws, claim_uds, serve_ws};
use crate::tls::WsTls;
use crate::DISPLACED_EXIT_STATUS;
use mesh_hub_runtime::HubConfig;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "basket")]
use std::time::Duration;
use tracing::{error, info};

/// What the daemon serves and how, built with [`DaemonConfig::new`] and the
/// `with_*` methods.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DaemonConfig {
    /// The hub name, as `mesh_hub_runtime::hub_shm_names` accepts it.
    pub hub_name: String,
    /// The hub's configuration.
    pub hub: HubConfig,
    /// The Unix socket to serve, if any.
    pub uds_path: Option<PathBuf>,
    /// The WebSocket address to serve, if any.
    pub ws_bind: Option<SocketAddr>,
    /// The certificate chain and key the WebSocket presents, which make it
    /// `wss://` (TLS 1.3); `None` serves `ws://`, in plaintext.
    pub ws_tls: Option<WsTls>,
    /// The address to serve the metrics on (`GET /metrics`), if any.
    pub metrics_bind: Option<SocketAddr>,
    /// The policy every connection is served under.
    pub policy: ConnectionPolicy,
    /// A basket to capture every published envelope into, or `None`.
    #[cfg(feature = "basket")]
    pub basket: Option<BasketConfig>,
    /// Links to other daemons over sealed UDP, or `None`, the default
    /// ([`crate::link`]).
    pub links: Option<LinkConfig>,
}

impl DaemonConfig {
    /// A daemon for `hub_name` with the default hub configuration and policy,
    /// serving nothing until the `with_*` methods say where.
    #[must_use]
    pub fn new(hub_name: impl Into<String>) -> Self {
        Self {
            hub_name: hub_name.into(),
            hub: HubConfig::default(),
            uds_path: None,
            ws_bind: None,
            ws_tls: None,
            metrics_bind: None,
            policy: ConnectionPolicy::default(),
            #[cfg(feature = "basket")]
            basket: None,
            links: None,
        }
    }

    /// This configuration linking to other daemons by `links`, or to none.
    #[must_use]
    pub fn with_links(mut self, links: Option<LinkConfig>) -> Self {
        self.links = links;
        self
    }

    /// This configuration with the given hub configuration.
    #[must_use]
    pub fn with_hub(mut self, hub: HubConfig) -> Self {
        self.hub = hub;
        self
    }

    /// This configuration serving the Unix socket at `path`, or none.
    #[must_use]
    pub fn with_uds_path(mut self, path: Option<PathBuf>) -> Self {
        self.uds_path = path;
        self
    }

    /// This configuration serving the WebSocket at `bind`, or none.
    #[must_use]
    pub fn with_ws_bind(mut self, bind: Option<SocketAddr>) -> Self {
        self.ws_bind = bind;
        self
    }

    /// This configuration serving the WebSocket over TLS with `tls`
    /// (`wss://`), or in plaintext (`ws://`) with `None`.
    #[must_use]
    pub fn with_ws_tls(mut self, tls: Option<WsTls>) -> Self {
        self.ws_tls = tls;
        self
    }

    /// This configuration serving the metrics, in the Prometheus text format,
    /// at `bind`, or not at all.
    #[must_use]
    pub fn with_metrics_bind(mut self, bind: Option<SocketAddr>) -> Self {
        self.metrics_bind = bind;
        self
    }

    /// This configuration with the given connection policy.
    #[must_use]
    pub fn with_policy(mut self, policy: ConnectionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// This configuration capturing into `basket`, or into none.
    #[cfg(feature = "basket")]
    #[must_use]
    pub fn with_basket(mut self, basket: Option<BasketConfig>) -> Self {
        self.basket = basket;
        self
    }
}

/// A basket the daemon captures every published envelope into, for
/// structured queries through `pms-query` and the `mesh_query` MCP tool.
#[cfg(feature = "basket")]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BasketConfig {
    /// The SQLite file, created if it does not exist.
    pub path: PathBuf,
    /// How often the retention sweep runs.
    pub retention_interval: Duration,
}

#[cfg(feature = "basket")]
impl BasketConfig {
    /// A basket at `path` whose retention sweep runs every
    /// `retention_interval`.
    #[must_use]
    pub fn new(path: PathBuf, retention_interval: Duration) -> Self {
        Self {
            path,
            retention_interval,
        }
    }
}

/// How a run of the daemon ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonExit {
    /// SIGINT or SIGTERM arrived and the daemon stopped in order.
    Signalled,
    /// Another owner took the hub name while the daemon ran (its lock file was
    /// removed), so the daemon closed its connections and stopped.
    Displaced,
}

impl DaemonExit {
    /// The process status this end is reported with: 0 when signalled,
    /// [`DISPLACED_EXIT_STATUS`] when displaced.
    #[must_use]
    pub fn status(self) -> u8 {
        match self {
            Self::Signalled => 0,
            Self::Displaced => DISPLACED_EXIT_STATUS,
        }
    }
}

/// Why the daemon could not start; nothing is left running behind any of these.
#[derive(Debug)]
#[non_exhaustive]
pub enum DaemonError {
    /// A signal handler could not be installed; `signal` names it.
    Signals {
        /// `SIGINT` or `SIGTERM`.
        signal: &'static str,
        /// The error installing it.
        source: std::io::Error,
    },
    /// The Unix socket could not be claimed or served: another daemon holds
    /// the path, or the socket could not be bound.
    Uds(std::io::Error),
    /// The WebSocket address could not be bound or served.
    Ws(std::io::Error),
    /// The metrics address could not be bound or served.
    Metrics(std::io::Error),
    /// The hub could not be created; the string is the bridge's reason.
    Hub(String),
    /// The basket file could not be opened.
    #[cfg(feature = "basket")]
    Basket {
        /// The file that was asked for.
        path: PathBuf,
        /// The basket's reason.
        reason: String,
    },
    /// The envelope store asked for could not be made (the runtime logged why),
    /// and the daemon will not run without it: attached processes would receive
    /// nothing.
    StoreRefused {
        /// The slots asked for.
        asked: usize,
    },
    /// The links to other daemons could not be started: their configuration
    /// was refused, their address could not be bound, or a thread could not
    /// start.
    Links(LinkSetupError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signals { signal, source } => {
                write!(f, "failed to install {signal} handler: {source}")
            }
            Self::Uds(e) => write!(f, "UDS bind failed: {e}"),
            Self::Ws(e) => write!(f, "WS bind failed: {e}"),
            Self::Metrics(e) => write!(f, "metrics bind failed: {e}"),
            Self::Hub(e) => write!(f, "failed to initialize PulseHub: {e}"),
            #[cfg(feature = "basket")]
            Self::Basket { path, reason } => {
                write!(f, "basket open at '{}' failed: {reason}", path.display())
            }
            Self::StoreRefused { asked } => write!(
                f,
                "refusing to start: --store-slots {asked} asks for an envelope store the hub \
                 could not make (the warning above says why); give fewer slots, or 0 to run \
                 without a store"
            ),
            Self::Links(e) => write!(f, "links to other daemons failed to start: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signals { source, .. } => Some(source),
            Self::Uds(e) | Self::Ws(e) | Self::Metrics(e) => Some(e),
            Self::Links(e) => Some(e),
            _ => None,
        }
    }
}

/// The refusal when `asked` slots were asked for and none were made.
fn store_refusal(asked: usize, made: Option<usize>) -> Option<DaemonError> {
    (asked > 0 && made.is_none()).then_some(DaemonError::StoreRefused { asked })
}

/// Open the basket and attach it to the bridge, whose basket thread writes
/// the captures and runs the retention sweep, off the runtime's workers.
#[cfg(feature = "basket")]
fn attach_basket(bridge: HubBridge, config: &BasketConfig) -> Result<HubBridge, DaemonError> {
    let refused = |reason: String| DaemonError::Basket {
        path: config.path.clone(),
        reason,
    };
    let basket = mesh_basket::Basket::open(&config.path).map_err(|e| refused(e.to_string()))?;
    let bridge = bridge
        .with_basket(basket, config.retention_interval)
        .map_err(|e| refused(format!("the basket thread did not start: {e}")))?;
    info!(path = %config.path.display(), "basket attached");
    Ok(bridge)
}

/// Serve the daemon on the current tokio runtime until SIGINT, SIGTERM or a
/// displacement, and say which ended it.
///
/// The start runs in an order a second daemon cannot hurt: the signal handlers
/// first, so a signal during the start still shuts down in order; then the Unix
/// socket is claimed and the WebSocket bound, so a daemon already there stops
/// this one before its hub replaces the hub name's shared memory, and the link
/// address bound, when links are configured; then the hub, and the links' threads.
/// Checked by `tests/one_daemon.rs`.
///
/// # Errors
///
/// A [`DaemonError`] naming the step that failed, with nothing left running.
pub async fn run(config: DaemonConfig) -> Result<DaemonExit, DaemonError> {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|source| DaemonError::Signals {
            signal: "SIGINT",
            source,
        })?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|source| DaemonError::Signals {
            signal: "SIGTERM",
            source,
        })?;

    // R-LEX.8: log the conformance anchor at startup.
    let lex_root = mesh_lex::lex_root_hex(&mesh_lex::LexRegistry::new());
    info!(lex_root = %lex_root, "mesh-lex public conformance anchor");

    // Claimed before the hub is created (see above); a claim dropped on a later
    // error releases its lock.
    let uds = match &config.uds_path {
        Some(path) => Some(claim_uds(path.clone()).await.map_err(DaemonError::Uds)?),
        None => None,
    };
    let ws = match config.ws_bind {
        Some(addr) => Some(
            bind_ws(
                addr,
                config.ws_tls.is_some(),
                config.policy.attach_keys.is_some(),
            )
            .await
            .map_err(DaemonError::Ws)?,
        ),
        None => None,
    };
    let metrics = match config.metrics_bind {
        Some(addr) => Some(bind_metrics(addr).await.map_err(DaemonError::Metrics)?),
        None => None,
    };
    let links = match config.links.clone() {
        Some(links) => Some(crate::link::bind(links).map_err(DaemonError::Links)?),
        None => None,
    };

    let asked = config.hub.store_slots;
    let bridge = HubBridge::with_config(&config.hub_name, config.hub)
        .map_err(|e| DaemonError::Hub(e.to_string()))?;
    #[cfg(feature = "basket")]
    let bridge = match &config.basket {
        Some(basket) => attach_basket(bridge, basket)?,
        None => bridge,
    };
    if let Some(refused) = store_refusal(asked, bridge.store_slots()) {
        return Err(refused);
    }
    // The registry before the links, which announce its nodes; the links
    // last, so that a refused start links to nobody.
    let registry = Registry::for_policy(&config.policy);
    let bridge = match links {
        Some(bound) => bridge
            .with_links(bound, &registry)
            .map_err(DaemonError::Links)?,
        None => bridge,
    };
    let bridge = Arc::new(bridge);
    if let Some(keys) = &config.policy.attach_keys {
        info!(
            keys = keys.len(),
            uds = config.policy.attach_keys_uds,
            "attach keys: every attach on the WebSocket proves a listed key{}",
            if config.policy.attach_keys_uds {
                ", and on the Unix socket too"
            } else {
                "; the Unix socket admits its owner without one"
            }
        );
    }

    if let Some(claim) = uds {
        claim
            .serve(bridge.clone(), registry.clone(), config.policy.clone())
            .await
            .map_err(DaemonError::Uds)?;
    }
    if let Some(listener) = ws {
        let scheme = if config.ws_tls.is_some() { "wss" } else { "ws" };
        let bound = serve_ws(
            listener,
            bridge.clone(),
            registry.clone(),
            config.policy.clone(),
            config.ws_tls.clone(),
        )
        .map_err(DaemonError::Ws)?;
        info!(%bound, scheme, "websocket bound");
    }
    if let Some(listener) = metrics {
        serve_metrics(listener, registry.clone(), bridge.clone()).map_err(DaemonError::Metrics)?;
    }
    // The attached connections' liveness, unless the idle timeout is zero.
    let ticking = health::ticks(&registry).map(tokio::spawn);

    // Beside the signals, a displacement: the clients would otherwise send into
    // a ring no reader follows.
    let displaced = tokio::select! {
        _ = sigint.recv() => {
            info!("SIGINT received; shutting down");
            false
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received; shutting down");
            false
        }
        () = bridge.displaced() => true,
    };
    if displaced {
        error!(
            hub = %config.hub_name,
            connections = registry.connections(),
            status = DISPLACED_EXIT_STATUS,
            "this daemon's hub was displaced: its lock file was removed while the daemon ran, \
             and another owner took the hub name, marking the daemon's ring and replacing its \
             shared memory ({}). Processes attached to the hub by name follow that owner and \
             receive nothing this daemon's clients send, so the daemon closes its connections \
             and exits with status {DISPLACED_EXIT_STATUS}. To serve the name from here again, \
             stop that owner if it still runs and restart this daemon, or restart it under \
             another --hub-name; and find what removed the lock file, which the daemon keeps \
             fresh against cleaners that go by age",
            name_holder(&config.hub_name)
        );
    }

    if let Some(ticking) = ticking {
        ticking.abort();
    }
    // The socket goes with the listener's claim as the runtime stops, and the
    // connections with their tasks.
    info!(
        attached = registry.len(),
        subscribers = bridge.subscriber_count(),
        store_failures = bridge.store_failures(),
        connections_refused = registry.connections_refused(),
        origins_refused = registry.origins_refused(),
        events_dropped_at_total_queue_bytes = registry.queue_total().events_dropped(),
        health_notices_dropped = registry.health_notices_dropped(),
        "exit"
    );
    if let Some(links) = bridge.links() {
        let stats = links.stats();
        info!(
            links_up = stats.up,
            forwards_sent = stats.forwards_sent,
            forwards_received = stats.forwards_received,
            duplicates_dropped = stats.duplicates_dropped,
            forwards_dropped = stats.forwards_dropped,
            "links at exit"
        );
    }
    Ok(if displaced {
        DaemonExit::Displaced
    } else {
        DaemonExit::Signalled
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A store asked for and not made is refused, with the flag and the
    /// way out in the message; one not asked for, or made, is not.
    #[test]
    fn a_store_asked_for_and_not_made_is_refused() {
        assert!(store_refusal(16, Some(16)).is_none());
        assert!(store_refusal(0, None).is_none());
        let refusal = store_refusal(5_000_000_000, None).unwrap().to_string();
        assert!(
            refusal.contains("--store-slots 5000000000") && refusal.contains("0 to run without"),
            "{refusal}"
        );
    }

    /// Each exit reports the status the daemon documents.
    #[test]
    fn each_exit_has_its_status() {
        assert_eq!(DaemonExit::Signalled.status(), 0);
        assert_eq!(DaemonExit::Displaced.status(), DISPLACED_EXIT_STATUS);
    }

    /// Every start failure displays as the line the daemon logs.
    #[test]
    fn start_failures_display_as_the_daemons_lines() {
        let io = || std::io::Error::other("held");
        assert_eq!(
            DaemonError::Signals {
                signal: "SIGINT",
                source: io()
            }
            .to_string(),
            "failed to install SIGINT handler: held"
        );
        assert_eq!(DaemonError::Uds(io()).to_string(), "UDS bind failed: held");
        assert_eq!(DaemonError::Ws(io()).to_string(), "WS bind failed: held");
        assert_eq!(
            DaemonError::Hub("no room".into()).to_string(),
            "failed to initialize PulseHub: no room"
        );
    }
}
