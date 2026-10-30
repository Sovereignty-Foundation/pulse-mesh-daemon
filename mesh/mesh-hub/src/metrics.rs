// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's metrics, served on an opt-in TCP address as the Prometheus
//! text exposition format (version 0.0.4) to `GET /metrics`.
//!
//! The counts are the ones the daemon already keeps for its own log and for a
//! host embedding it ([`crate::embed::EmbeddedMesh`]): connections, the event
//! queues and their budget, the bridge's subscriptions, sends and store
//! failures, the sends with a destination by where they went, the attached
//! nodes by health state, and the links to other daemons (all zero without
//! links). Nothing here keeps a count of its own but the scrapes refused at
//! [`MAX_SCRAPES`].
//!
//! The format is written by hand: a dozen lines need no dependency, and the
//! tier rules keep the peripheral exporter (`pms-telemetry-export`) out of the
//! daemon. The listener answers one request per connection and closes it; a
//! request must arrive within [`REQUEST_TIMEOUT`] and fit in
//! [`MAX_REQUEST_BYTES`], and at most [`MAX_SCRAPES`] are answered at once, so
//! a slow or hostile scraper cannot hold the daemon's resources. Like the
//! WebSocket, the endpoint has no authentication: the command line refuses an
//! address other than loopback unless `--metrics-allow-remote` is given, and
//! [`bind_metrics`] logs a warning when it binds one.

use crate::hub_bridge::HubBridge;
use crate::registry::Registry;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// The longest a scraper may take to send its request.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes of request read before it is answered 431.
pub(crate) const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Scrapes answered at once; one past it is answered 503 and counted.
pub(crate) const MAX_SCRAPES: usize = 8;

/// The exposition format's content type.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// One metric: its name, its type, its help line and its samples, each a
/// label set (empty or `{key="value"}`) and a value.
struct Family<'a> {
    name: &'a str,
    kind: &'a str,
    help: &'a str,
    samples: Vec<(&'a str, u64)>,
}

/// Write `families` in the exposition format.
fn write_families(out: &mut String, families: &[Family<'_>]) {
    for family in families {
        let _ = writeln!(out, "# HELP {} {}", family.name, family.help);
        let _ = writeln!(out, "# TYPE {} {}", family.name, family.kind);
        for (labels, value) in &family.samples {
            let _ = writeln!(out, "{}{labels} {value}", family.name);
        }
    }
}

/// A count as the exposition format's integer.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The daemon's metrics now, in the exposition format; `scrapes_refused` is
/// the endpoint's own count.
pub(crate) fn render(registry: &Registry, bridge: &HubBridge, scrapes_refused: u64) -> String {
    let queued = registry.queue_total();
    let links = bridge
        .links()
        .map(crate::link::Links::stats)
        .unwrap_or_default();
    let destinations = bridge.destination_sends();
    let families = [
        Family {
            name: "pms_daemon_connections",
            kind: "gauge",
            help: "Connections holding a place now, on either transport.",
            samples: vec![("", count(registry.connections()))],
        },
        Family {
            name: "pms_daemon_connections_refused_total",
            kind: "counter",
            help: "Connections refused at --max-connections.",
            samples: vec![("", registry.connections_refused())],
        },
        Family {
            name: "pms_daemon_origins_refused_total",
            kind: "counter",
            help: "WebSocket upgrades refused for their Origin.",
            samples: vec![("", registry.origins_refused())],
        },
        Family {
            name: "pms_daemon_attaches_refused_total",
            kind: "counter",
            help: "Attaches refused with auth_failed (bad or unlisted key, unanswered challenge).",
            samples: vec![("", registry.attaches_refused())],
        },
        Family {
            name: "pms_daemon_attached",
            kind: "gauge",
            help: "Connections attached under a name now.",
            samples: vec![("", count(registry.len()))],
        },
        Family {
            name: "pms_daemon_nodes",
            kind: "gauge",
            help: "Attached nodes by health state (none while --idle-timeout-secs is 0).",
            samples: vec![
                (r#"{state="healthy"}"#, count(registry.nodes_healthy())),
                (r#"{state="warning"}"#, count(registry.nodes_warning())),
                (r#"{state="isolated"}"#, count(registry.nodes_isolated())),
                (r#"{state="degraded"}"#, count(registry.nodes_degraded())),
            ],
        },
        Family {
            name: "pms_daemon_health_notices_dropped_total",
            kind: "counter",
            help: "Health notices dropped at a watcher's queue or the daemon's budget.",
            samples: vec![("", registry.health_notices_dropped())],
        },
        Family {
            name: "pms_daemon_subscriptions",
            kind: "gauge",
            help: "Subscriptions the daemon routes now.",
            samples: vec![("", count(bridge.subscriber_count()))],
        },
        Family {
            name: "pms_daemon_sends_total",
            kind: "counter",
            help: "Envelopes sent through the daemon and published to the hub.",
            samples: vec![("", bridge.sends())],
        },
        Family {
            name: "pms_daemon_destination_sends_total",
            kind: "counter",
            help: "Sends with a destination (to): to a node attached here, forwarded to the peer daemon that announced it, or refused as unknown_destination.",
            samples: vec![
                (r#"{outcome="local"}"#, destinations.local),
                (r#"{outcome="forwarded"}"#, destinations.forwarded),
                (r#"{outcome="unknown"}"#, destinations.unknown),
            ],
        },
        Family {
            name: "pms_daemon_store_failures_total",
            kind: "counter",
            help: "Envelopes the hub's store refused; each was still delivered.",
            samples: vec![("", bridge.store_failures())],
        },
        Family {
            name: "pms_daemon_event_queues",
            kind: "gauge",
            help: "Connections' event queues now.",
            samples: vec![("", count(queued.queues()))],
        },
        Family {
            name: "pms_daemon_event_queue_bytes",
            kind: "gauge",
            help: "Bytes of event JSON queued across every connection now.",
            samples: vec![("", count(queued.held_bytes()))],
        },
        Family {
            name: "pms_daemon_events_dropped_total",
            kind: "counter",
            help: "Events dropped at the daemon-wide queue budget.",
            samples: vec![("", queued.events_dropped())],
        },
        Family {
            name: "pms_daemon_links_configured",
            kind: "gauge",
            help: "Peer daemons configured to link to (--link-peer).",
            samples: vec![("", count(links.configured))],
        },
        Family {
            name: "pms_daemon_links_up",
            kind: "gauge",
            help: "Links to peer daemons up now: a Hello heard, and the peer not silent since.",
            samples: vec![("", count(links.up))],
        },
        Family {
            name: "pms_daemon_link_forwards_sent_total",
            kind: "counter",
            help: "Envelopes forwarded to peer daemons, one for each peer a send went to, relayed ones included.",
            samples: vec![("", links.forwards_sent)],
        },
        Family {
            name: "pms_daemon_link_forwards_received_total",
            kind: "counter",
            help: "Envelopes peer daemons forwarded here, duplicates and relayed ones included.",
            samples: vec![("", links.forwards_received)],
        },
        Family {
            name: "pms_daemon_link_relayed_sent_total",
            kind: "counter",
            help: "Forwards this daemon passed on as a relay (--link-relay), sends of other daemons' clients, one for each peer they went to.",
            samples: vec![("", links.relayed_sent)],
        },
        Family {
            name: "pms_daemon_link_relayed_received_total",
            kind: "counter",
            help: "Forwards of other daemons' clients than the sending peer's, taken from a peer trusted as a relay (--link-trust-relay), duplicates included.",
            samples: vec![("", links.relayed_received)],
        },
        Family {
            name: "pms_daemon_link_relayed_refused_total",
            kind: "counter",
            help: "Relayed forwards and health reports refused because their peer is not trusted as a relay (--link-trust-relay).",
            samples: vec![("", links.relayed_refused)],
        },
        Family {
            name: "pms_daemon_link_relay_interest_bytes",
            kind: "gauge",
            help: "For a relay, the bytes of the largest interest summary it gives a peer now, its other peers' summed up in it; 0 for a daemon that does not relay.",
            samples: vec![("", count(links.relay_interest_bytes))],
        },
        Family {
            name: "pms_daemon_link_duplicates_dropped_total",
            kind: "counter",
            help: "Forwarded envelopes dropped as duplicates by the forward cache.",
            samples: vec![("", links.duplicates_dropped)],
        },
        Family {
            name: "pms_daemon_link_forwards_dropped_total",
            kind: "counter",
            help: "Forwards not made: too long for a link datagram, the send queue full, or refused by the socket.",
            samples: vec![("", links.forwards_dropped)],
        },
        Family {
            name: "pms_daemon_link_summaries_sent_total",
            kind: "counter",
            help: "Interest summaries sent to peer daemons, one for each peer.",
            samples: vec![("", links.summaries_sent)],
        },
        Family {
            name: "pms_daemon_link_summaries_received_total",
            kind: "counter",
            help: "Interest summaries received from peer daemons.",
            samples: vec![("", links.summaries_received)],
        },
        Family {
            name: "pms_daemon_link_handshakes_refused_total",
            kind: "counter",
            help: "Link handshakes refused: from a key not configured, or from the wrong address.",
            samples: vec![("", links.handshakes_refused)],
        },
        Family {
            name: "pms_daemon_link_datagrams_refused_total",
            kind: "counter",
            help: "Link datagrams refused once opened: sealed by no peer, claiming another daemon, relayed by a peer not trusted as a relay, or not a link message.",
            samples: vec![("", links.datagrams_refused)],
        },
        Family {
            name: "pms_daemon_link_peer_nodes",
            kind: "gauge",
            help: "Nodes the peer daemons' announcements name now, every peer's together, those trusted relays reach included.",
            samples: vec![("", count(links.peer_nodes))],
        },
        Family {
            name: "pms_daemon_link_announcements_sent_total",
            kind: "counter",
            help: "Announcements of the nodes attached here sent to peer daemons, each part counted, one for each peer.",
            samples: vec![("", links.announcements_sent)],
        },
        Family {
            name: "pms_daemon_link_announcements_received_total",
            kind: "counter",
            help: "Announcements of their nodes received from peer daemons, each part counted.",
            samples: vec![("", links.announcements_received)],
        },
        Family {
            name: "pms_daemon_link_health_sent_total",
            kind: "counter",
            help: "Health reports about the nodes here sent to the peer daemons that watch health, one for each peer.",
            samples: vec![("", links.health_sent)],
        },
        Family {
            name: "pms_daemon_link_health_received_total",
            kind: "counter",
            help: "Health reports about their nodes taken from peer daemons.",
            samples: vec![("", links.health_received)],
        },
        Family {
            name: "pms_daemon_remote_health_notices_total",
            kind: "counter",
            help: "Health notices about peer daemons' nodes queued for the watchers here, one for each watcher.",
            samples: vec![("", links.remote_health_notices)],
        },
        Family {
            name: "pms_daemon_link_addressed_missing_total",
            kind: "counter",
            help: "Forwards addressed to a node here dropped because the node was no longer attached.",
            samples: vec![("", links.addressed_missing)],
        },
        Family {
            name: "pms_daemon_link_lan_announcements_sent_total",
            kind: "counter",
            help: "Announcements of this daemon's link endpoint sent to its --link-announce group.",
            samples: vec![("", links.lan_announcements_sent)],
        },
        Family {
            name: "pms_daemon_link_lan_announcements_received_total",
            kind: "counter",
            help: "Announcements heard on the --link-announce group from other daemons, repeats included.",
            samples: vec![("", links.lan_announcements_received)],
        },
        Family {
            name: "pms_daemon_link_lan_announcements_ignored_total",
            kind: "counter",
            help: "Announcements heard on the --link-announce group from a key that is not a configured peer's.",
            samples: vec![("", links.lan_announcements_ignored)],
        },
        Family {
            name: "pms_daemon_link_lan_connects_total",
            kind: "counter",
            help: "Handshakes with configured peers that announcements asked for: at most one per peer every 5 s.",
            samples: vec![("", links.lan_connects_triggered)],
        },
        Family {
            name: "pms_daemon_metrics_scrapes_refused_total",
            kind: "counter",
            help: "Scrapes of this endpoint refused while others were answered.",
            samples: vec![("", scrapes_refused)],
        },
    ];
    let mut out = String::with_capacity(2048);
    write_families(&mut out, &families);
    out
}

/// Bind the metrics listener without answering yet. An address other than
/// loopback is logged as a warning, since nothing authenticates the endpoint.
///
/// # Errors
///
/// The error of [`TcpListener::bind`].
pub(crate) async fn bind_metrics(bind: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    if !bind.ip().is_loopback() {
        warn!(
            addr = %bind,
            "metrics bound to an address other than loopback: the endpoint has no \
             authentication, so anything that can reach it can read the daemon's counts"
        );
    }
    TcpListener::bind(bind).await
}

/// Answer scrapes on `listener` from a detached task, and return the address
/// it is bound to (the port a bind to port 0 got).
///
/// # Errors
///
/// The error of reading the listener's address.
pub(crate) fn serve_metrics(
    listener: TcpListener,
    registry: Arc<Registry>,
    bridge: Arc<HubBridge>,
) -> std::io::Result<std::net::SocketAddr> {
    let bound = listener.local_addr()?;
    info!(addr = %bound, "metrics listening");
    let slots = Arc::new(Semaphore::new(MAX_SCRAPES));
    let refused = Arc::new(AtomicU64::new(0));
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    debug!(error = %e, "metrics accept failed");
                    continue;
                }
            };
            let registry = Arc::clone(&registry);
            let bridge = Arc::clone(&bridge);
            let refused = Arc::clone(&refused);
            match Arc::clone(&slots).try_acquire_owned() {
                Ok(slot) => {
                    tokio::spawn(async move {
                        answer(stream, &registry, &bridge, &refused).await;
                        drop(slot);
                    });
                }
                Err(_) => {
                    refused.fetch_add(1, Ordering::Relaxed);
                    debug!(%peer, "metrics scrape refused: too many at once");
                    tokio::spawn(async move {
                        let _ = respond(stream, "503 Service Unavailable", "busy\n").await;
                    });
                }
            }
        }
    });
    Ok(bound)
}

/// Read one request and answer it: the metrics for `GET /metrics`, 404 for
/// another path, 405 for another method, 431 for a request too long, and
/// nothing for one that does not arrive in time.
async fn answer(
    mut stream: TcpStream,
    registry: &Registry,
    bridge: &HubBridge,
    refused: &AtomicU64,
) {
    let mut request = Vec::with_capacity(512);
    let read = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut buf = [0u8; 1024];
        loop {
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok::<bool, std::io::Error>(true);
            }
            if request.len() >= MAX_REQUEST_BYTES {
                return Ok(false);
            }
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            request.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    let complete = match read {
        Ok(Ok(complete)) => complete,
        Ok(Err(_)) | Err(_) => return,
    };
    if !complete {
        let _ = respond(
            stream,
            "431 Request Header Fields Too Large",
            "request too long\n",
        )
        .await;
        return;
    }
    let line = request
        .split(|&b| b == b'\r')
        .next()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    let outcome = match (method, path) {
        ("GET", "/metrics") => {
            let body = render(registry, bridge, refused.load(Ordering::Relaxed));
            respond_with(stream, "200 OK", CONTENT_TYPE, &body).await
        }
        ("GET", _) => {
            respond(
                stream,
                "404 Not Found",
                "not found; the metrics are at /metrics\n",
            )
            .await
        }
        _ => respond(stream, "405 Method Not Allowed", "only GET\n").await,
    };
    if let Err(e) = outcome {
        debug!(error = %e, "metrics response not written");
    }
}

/// Write a plain-text response and close the connection.
async fn respond(stream: TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    respond_with(stream, status, "text/plain; charset=utf-8", body).await
}

/// Write a response with `content_type` and close the connection.
async fn respond_with(
    mut stream: TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let write = async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.shutdown().await
    };
    tokio::time::timeout(REQUEST_TIMEOUT, write)
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every family has its HELP and TYPE lines and integer samples, so a
    /// Prometheus scraper reads the page.
    #[test]
    fn the_page_is_the_exposition_format() {
        let mut out = String::new();
        write_families(
            &mut out,
            &[
                Family {
                    name: "pms_a",
                    kind: "gauge",
                    help: "A gauge.",
                    samples: vec![("", 3)],
                },
                Family {
                    name: "pms_b_total",
                    kind: "counter",
                    help: "A counter.",
                    samples: vec![(r#"{state="x"}"#, 1), (r#"{state="y"}"#, 2)],
                },
            ],
        );
        assert_eq!(
            out,
            "# HELP pms_a A gauge.\n# TYPE pms_a gauge\npms_a 3\n\
             # HELP pms_b_total A counter.\n# TYPE pms_b_total counter\n\
             pms_b_total{state=\"x\"} 1\npms_b_total{state=\"y\"} 2\n"
        );
    }
}
