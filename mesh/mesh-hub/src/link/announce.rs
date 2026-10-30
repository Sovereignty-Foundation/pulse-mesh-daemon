// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A daemon's announcement of its link endpoint on a LAN multicast group
//! (`crate::link`'s docs, "Finding peers on a LAN"): the layout and its
//! encoding and decoding, public only for the fuzz harness and the tests,
//! through `crate::internals::link_announce`; not API, and not stable. And
//! the thread that sends this daemon's announcement and hears the others'.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use mesh_link::DaemonId;
use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{MulticastConfig, PublicKey, Receiver, Sender};
use tracing::{debug, warn};

use super::{bump, AnnounceConfig, LinkSetupError, Shared, ANNOUNCE_INTERVAL};

/// The first four bytes of an announcement: `PMLA`.
pub const ANNOUNCE_MAGIC: [u8; 4] = *b"PMLA";

/// The version of the announcement layout this build writes and reads.
pub const ANNOUNCE_VERSION: u8 = 1;

/// An announcement's length: the magic, the version, the public key, the
/// port and the daemon id.
pub const ANNOUNCE_BYTES: usize = 4 + 1 + 32 + 2 + DaemonId::LEN;

/// How long the announcement thread waits for a datagram before it looks
/// at its timer and at the stop flag again.
const RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// What a daemon announces: the public half of its node key, which its
/// sealed sessions authenticate, and the UDP port its links use. The
/// address is the datagram's source; the daemon id is the key's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanAnnouncement {
    /// The public half of the announcing daemon's node key.
    pub key: PublicKey,
    /// The port of its link address (`--link-bind`); never zero.
    pub port: u16,
}

impl LanAnnouncement {
    /// The id the announcing daemon is named by across links: its key's
    /// fingerprint.
    #[must_use]
    pub fn daemon_id(&self) -> DaemonId {
        DaemonId::from_public_key(self.key.as_bytes())
    }

    /// Where the announcing daemon's links are, when the announcement came
    /// from `source`: the source's IP and the announced port.
    #[must_use]
    pub fn link_addr(&self, source: SocketAddr) -> SocketAddr {
        SocketAddr::new(source.ip(), self.port)
    }
}

/// Why bytes are not an announcement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnnounceError {
    /// The bytes are not the 47 of an announcement.
    #[error("{0} bytes, where an announcement is {ANNOUNCE_BYTES}")]
    Length(usize),
    /// The bytes do not start with [`ANNOUNCE_MAGIC`].
    #[error("not an announcement: the magic is not PMLA")]
    Magic,
    /// A version this build does not read.
    #[error("an announcement of version {0}, which this build does not read")]
    Version(u8),
    /// The announced port is zero.
    #[error("an announcement of port 0")]
    Port,
    /// The daemon id is not the fingerprint of the announced key.
    #[error("an announcement whose daemon id is not its key's")]
    DaemonId,
}

/// The bytes of `announcement`, integers little-endian: the magic, the
/// version, the key's 32 bytes, the port and the daemon id.
#[must_use]
pub fn encode(announcement: &LanAnnouncement) -> [u8; ANNOUNCE_BYTES] {
    let mut out = [0; ANNOUNCE_BYTES];
    out[..4].copy_from_slice(&ANNOUNCE_MAGIC);
    out[4] = ANNOUNCE_VERSION;
    out[5..37].copy_from_slice(announcement.key.as_bytes());
    out[37..39].copy_from_slice(&announcement.port.to_le_bytes());
    out[39..].copy_from_slice(announcement.daemon_id().as_bytes());
    out
}

/// Read an announcement: exactly [`ANNOUNCE_BYTES`] in the layout
/// [`encode`] writes, a nonzero port, and the key's own daemon id, so that
/// a decoded announcement re-encodes to its bytes.
///
/// # Errors
///
/// The [`AnnounceError`] naming the first thing that is not an
/// announcement's.
pub fn decode(bytes: &[u8]) -> Result<LanAnnouncement, AnnounceError> {
    if bytes.len() != ANNOUNCE_BYTES {
        return Err(AnnounceError::Length(bytes.len()));
    }
    if bytes[..4] != ANNOUNCE_MAGIC {
        return Err(AnnounceError::Magic);
    }
    if bytes[4] != ANNOUNCE_VERSION {
        return Err(AnnounceError::Version(bytes[4]));
    }
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[5..37]);
    let port = u16::from_le_bytes([bytes[37], bytes[38]]);
    if port == 0 {
        return Err(AnnounceError::Port);
    }
    let announcement = LanAnnouncement {
        key: PublicKey::from_bytes(key),
        port,
    };
    if bytes[39..] != announcement.daemon_id().as_bytes()[..] {
        return Err(AnnounceError::DaemonId);
    }
    Ok(announcement)
}

/// The Pulse of the frame that carries `announcement`: a Data pulse whose
/// `origin_id` starts with the announcing daemon's id, as a link
/// datagram's does. The receiver reads the announcement alone.
#[must_use]
pub fn pulse(announcement: &LanAnnouncement) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
    pulse.origin_id[..DaemonId::LEN].copy_from_slice(announcement.daemon_id().as_bytes());
    pulse
}

/// The sockets of a daemon's LAN announcement: a sender to the group and a
/// receiver joined to it.
pub(super) struct AnnounceSockets {
    pub(super) group: SocketAddrV4,
    tx: Sender,
    rx: Receiver,
}

/// The multicast settings for a daemon whose links are bound to `bind`:
/// `config`'s TTL, loopback on (so that daemons on one host hear each
/// other), and, when `bind` names an IPv4 address, that address's interface
/// to send from and join on, so that an announcement's source is the
/// address its links are reached at.
fn multicast(config: &AnnounceConfig, bind: SocketAddr) -> MulticastConfig {
    let mut cfg = MulticastConfig::default();
    cfg.ttl = config.ttl;
    cfg.loopback = true;
    cfg.interface_v4 = match bind.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    };
    cfg
}

/// Join `config`'s group and set up a sender to it, for links bound to
/// `bind`: the sender on `bind`'s IP and a port of its own.
///
/// # Errors
///
/// [`LinkSetupError::Announce`] when the group cannot be joined or the
/// sender's socket set up.
pub(super) fn bind(
    config: &AnnounceConfig,
    bind: SocketAddr,
) -> Result<AnnounceSockets, LinkSetupError> {
    let group = config.group;
    let failed = |source: std::io::Error| LinkSetupError::Announce { group, source };
    let cfg = multicast(config, bind);
    let rx = Receiver::bind_multicast(group.into(), &cfg).map_err(failed)?;
    rx.set_read_timeout(Some(RECV_TIMEOUT)).map_err(failed)?;
    let ip = match bind.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let tx = Sender::bind(SocketAddrV4::new(ip, 0)).map_err(|e| failed(sender_io(e)))?;
    tx.set_multicast(&cfg).map_err(|e| failed(sender_io(e)))?;
    Ok(AnnounceSockets { group, tx, rx })
}

/// A sender's error as the I/O error it is at setup.
fn sender_io(e: pulse_wire_udp::SenderError) -> std::io::Error {
    match e {
        pulse_wire_udp::SenderError::Io(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

/// The announcement thread: announce this daemon at once and every
/// [`ANNOUNCE_INTERVAL`], and act on the announcements heard, until the
/// links stop.
pub(super) fn run(shared: &Shared, sockets: AnnounceSockets) {
    let AnnounceSockets {
        group,
        mut tx,
        mut rx,
    } = sockets;
    let own = LanAnnouncement {
        key: shared.public_key,
        port: shared.addr.port(),
    };
    let bytes = encode(&own);
    let mut due = Instant::now();
    while !shared.stop.load(Ordering::Acquire) {
        if Instant::now() >= due {
            let pulse = pulse(&own);
            match tx.send_to(pulse.monotonic_nanos, &pulse, &bytes, group.into()) {
                Ok(_) => {
                    shared
                        .counts
                        .lan_announcements_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    if let Some(total) = bump(&shared.counts.lan_send_errors, 1) {
                        warn!(%group, errors = total, error = %e, "the LAN announcement was not sent");
                    }
                }
            }
            due = Instant::now() + ANNOUNCE_INTERVAL;
        }
        match rx.recv() {
            Ok((_, bytes, meta)) => heard(shared, &bytes, meta.peer),
            Err(e) if e.is_timeout() => {}
            Err(e) => malformed(shared, &e),
        }
    }
}

/// Count a datagram on the group that is not an announcement, logging at
/// the first and each doubling.
fn malformed(shared: &Shared, why: &dyn std::fmt::Display) {
    if let Some(total) = bump(&shared.counts.lan_malformed, 1) {
        debug!(
            malformed = total,
            "a datagram on the LAN announcement group was not an announcement: {why}"
        );
    }
}

/// Act on the datagram `bytes` heard on the group from `source`. This
/// daemon's own announcement, looped back, is passed over; another
/// daemon's is counted, and one whose key is not a configured peer's is
/// ignored and counted besides. A configured peer with no sealed session
/// is then tried, at most once every [`ANNOUNCE_INTERVAL`]: at the address the
/// announcement gives, for a peer named by its key alone, or at its fixed
/// address, which no announcement changes. The connect thread makes the
/// attempt.
fn heard(shared: &Shared, bytes: &[u8], source: SocketAddr) {
    let announcement = match decode(bytes) {
        Ok(announcement) => announcement,
        Err(e) => {
            malformed(shared, &e);
            return;
        }
    };
    if announcement.key == shared.public_key {
        return;
    }
    let counts = &shared.counts;
    counts
        .lan_announcements_received
        .fetch_add(1, Ordering::Relaxed);
    let daemon = announcement.daemon_id();
    let Some(peer) = shared
        .peers
        .get(&daemon)
        .filter(|peer| peer.key == announcement.key)
    else {
        if let Some(total) = bump(&counts.lan_announcements_ignored, 1) {
            debug!(%daemon, %source, ignored = total, "a LAN announcement from a key not configured was ignored");
        }
        return;
    };
    if shared.sealing.has_session(&peer.key) {
        return;
    }
    let target = peer.fixed.unwrap_or_else(|| announcement.link_addr(source));
    let now = Instant::now();
    {
        let mut found = peer.found.lock();
        if found
            .triggered
            .is_some_and(|at| now.saturating_duration_since(at) < ANNOUNCE_INTERVAL)
        {
            return;
        }
        found.triggered = Some(now);
        found.candidate = Some(target);
    }
    counts.lan_connects.fetch_add(1, Ordering::Relaxed);
    debug!(peer = %daemon, addr = %target, "a LAN announcement asks for a handshake with the peer daemon");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use pulse_wire_udp::NodeKey;

    fn announcement() -> LanAnnouncement {
        LanAnnouncement {
            key: NodeKey::generate().unwrap().public_key(),
            port: 7401,
        }
    }

    #[test]
    fn an_announcement_is_its_documented_47_bytes_and_decodes_to_itself() {
        let sent = announcement();
        let bytes = encode(&sent);
        assert_eq!(bytes.len(), 47);
        let mut want = b"PMLA".to_vec();
        want.push(1);
        want.extend_from_slice(sent.key.as_bytes());
        want.extend_from_slice(&7401u16.to_le_bytes());
        want.extend_from_slice(sent.daemon_id().as_bytes());
        assert_eq!(&bytes[..], &want[..]);
        assert_eq!(decode(&bytes), Ok(sent));
        let from: SocketAddr = "192.0.2.9:50123".parse().unwrap();
        assert_eq!(
            sent.link_addr(from),
            "192.0.2.9:7401".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn bytes_that_are_not_an_announcement_are_refused_saying_why() {
        let bytes = encode(&announcement());
        assert_eq!(decode(&bytes[..46]), Err(AnnounceError::Length(46)));
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode(&longer), Err(AnnounceError::Length(48)));
        let mut magic = bytes;
        magic[0] = b'X';
        assert_eq!(decode(&magic), Err(AnnounceError::Magic));
        let mut version = bytes;
        version[4] = 2;
        assert_eq!(decode(&version), Err(AnnounceError::Version(2)));
        let mut port = bytes;
        port[37..39].copy_from_slice(&[0, 0]);
        assert_eq!(decode(&port), Err(AnnounceError::Port));
        let mut id = bytes;
        id[46] ^= 1;
        assert_eq!(decode(&id), Err(AnnounceError::DaemonId));
        // Another key under the first key's id.
        let mut key = bytes;
        key[5] ^= 1;
        assert_eq!(decode(&key), Err(AnnounceError::DaemonId));
    }

    #[test]
    fn the_pulse_names_the_announcing_daemon() {
        let sent = announcement();
        let pulse = pulse(&sent);
        assert_eq!(pulse.instruction, Instruction::Data as u16);
        assert_eq!(
            &pulse.origin_id[..DaemonId::LEN],
            &sent.daemon_id().as_bytes()[..]
        );
    }

    #[test]
    fn the_sender_takes_the_link_address_interface_and_the_ttl() {
        let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 0, 1), 7402);
        let config = AnnounceConfig::new(group).with_ttl(3);
        let cfg = multicast(&config, "10.0.0.5:7400".parse().unwrap());
        assert_eq!(cfg.ttl, 3);
        assert!(cfg.loopback);
        assert_eq!(cfg.interface_v4, Some(Ipv4Addr::new(10, 0, 0, 5)));
        let any = multicast(&config, "0.0.0.0:7400".parse().unwrap());
        assert_eq!(any.interface_v4, None);
    }
}
