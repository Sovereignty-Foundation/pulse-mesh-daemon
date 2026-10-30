// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! What the daemon's integration tests share: names and link addresses that
//! no other test and no other process can take, a linked daemon's identity,
//! a mesh whose envelope store is small, and a raw Unix-socket client that
//! speaks the length-prefixed framing byte for byte.
//!
//! Each test file compiles its own copy of this module and uses part of it,
//! hence the `dead_code` allowance.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_hub::embed::{Bind, EmbedError, EmbeddedMesh, HubConfig};
use mesh_hub::link::{DaemonId, LinkPeer, NodeKey};
use mesh_hub::ConnectionPolicy;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Range;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Slots in the envelope store of a mesh a test starts: about 1 MiB of
/// shared memory, which is all these tests need. The default store takes
/// 16 MiB, and a few meshes started in parallel with it would not fit the
/// 64 MB `/dev/shm` Docker gives a container.
pub(crate) const TEST_STORE_SLOTS: usize = 16;

/// The default hub configuration with a store of [`TEST_STORE_SLOTS`] slots.
pub(crate) fn small_store() -> HubConfig {
    HubConfig::default().with_store_slots(TEST_STORE_SLOTS)
}

/// A mesh answering at `binds` under the default connection policy, with a
/// [`small_store`].
pub(crate) fn start_small(hub: &str, binds: &[Bind]) -> Result<EmbeddedMesh, EmbedError> {
    EmbeddedMesh::start_with_config(hub, binds, ConnectionPolicy::default(), small_store())
}

/// A socket path private to this process and this test. Runs of the same
/// test in other worktrees share the temporary directory, and the clock
/// alone can repeat across processes started in the same microsecond, so
/// the name carries the process id as well; `tag` tells the tests of one
/// process apart.
pub(crate) fn socket_path(tag: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("mesh-{tag}-{pid}-{unique}.sock"))
}

/// A hub name private to this process and this test: `tag`, distinct per
/// test and at most nine characters, then the process id in hex, which
/// keeps the name within the fifteen characters a hub name allows.
pub(crate) fn hub_name(tag: &str) -> String {
    format!("{tag}{:x}", std::process::id())
}

/// The ports [`reserved_udp_addr`] hands out. They lie below the range a
/// system picks from for a socket bound to port 0 (49152 to 65535 on macOS,
/// 32768 to 60999 by default on Linux), so no socket on the host is given
/// one of them unless it names it.
pub(crate) const RESERVED_PORTS: Range<u16> = 20_000..32_000;

/// A loopback UDP address that nothing holds now, for a daemon to bind
/// later, which no other socket on the host is given meanwhile.
///
/// Binding `127.0.0.1:0` and releasing the socket would race. That port
/// comes from the system's ephemeral range, which it hands out again to the
/// next socket anywhere on the host bound to port 0, and macOS gives a
/// socket bound to the wildcard address with `SO_REUSEADDR` a port another
/// socket still holds on 127.0.0.1: the daemon's bind then fails with
/// `AddrInUse`. A port of [`RESERVED_PORTS`] is taken only by a socket that
/// names it. Each process walks the range from a starting point of its own,
/// so that runs of these tests in other worktrees take other ports, and
/// binds each port once to see that nothing holds it before handing it out.
pub(crate) fn reserved_udp_addr() -> SocketAddr {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let span = u32::from(RESERVED_PORTS.end - RESERVED_PORTS.start);
    // Spread neighbouring process ids across the range (Knuth's
    // multiplicative hash), since a gate starts its test binaries in a row.
    let start = std::process::id().wrapping_mul(2_654_435_761) % span;
    for _ in 0..span {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        let offset = u16::try_from(start.wrapping_add(step) % span).unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, RESERVED_PORTS.start + offset));
        if UdpSocket::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("every UDP port in {RESERVED_PORTS:?} on 127.0.0.1 is held");
}

/// A linked daemon's identity: its node key, its link address
/// ([`reserved_udp_addr`]) and the tag its hub name and socket are made
/// from.
pub(crate) struct Node {
    pub(crate) key: NodeKey,
    pub(crate) addr: SocketAddr,
    pub(crate) tag: String,
}

impl Node {
    pub(crate) fn new(tag: &str) -> Self {
        Self {
            key: NodeKey::generate().unwrap(),
            addr: reserved_udp_addr(),
            tag: tag.to_string(),
        }
    }

    /// It as a peer at its address.
    pub(crate) fn peer(&self) -> LinkPeer {
        LinkPeer::new(self.addr, self.key.public_key())
    }

    pub(crate) fn daemon_id(&self) -> DaemonId {
        DaemonId::from_public_key(self.key.public_key().as_bytes())
    }

    /// Its daemon id as a qualified origin writes it.
    pub(crate) fn id(&self) -> String {
        self.daemon_id().to_string()
    }
}

/// What one receive yielded.
pub(crate) enum Recv {
    /// A whole frame.
    Frame(String),
    /// The daemon closed the connection.
    Eof,
    /// Nothing arrived in time.
    Timeout,
}

/// A raw Unix-socket client speaking the length-prefixed framing.
pub(crate) struct Upp(UnixStream);

impl Upp {
    /// Connect to the daemon at `path`.
    pub(crate) fn connect(path: &Path) -> Self {
        Self(UnixStream::connect(path).expect("connect"))
    }

    /// Write one frame: the 4-byte big-endian length, then the JSON.
    pub(crate) fn send(&mut self, json: &str) {
        self.write_raw(&(json.len() as u32).to_be_bytes());
        self.write_raw(json.as_bytes());
    }

    /// Write bytes as they are, framing or not.
    pub(crate) fn write_raw(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).unwrap();
        self.0.flush().unwrap();
    }

    /// Wait up to `timeout` for one frame, telling a closed connection
    /// from a quiet one.
    pub(crate) fn recv(&mut self, timeout: Duration) -> Recv {
        // A peer that already closed makes macOS refuse the option; the
        // buffered frame is still readable, so the failure is ignored.
        let _ = self.0.set_read_timeout(Some(timeout));
        let mut len = [0u8; 4];
        match self.0.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Recv::Timeout,
            Err(_) => return Recv::Eof,
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        match self.0.read_exact(&mut body) {
            Ok(()) => Recv::Frame(String::from_utf8(body).unwrap()),
            Err(_) => Recv::Eof,
        }
    }

    /// One frame, or `None` on timeout or end of stream.
    pub(crate) fn frame(&mut self, timeout: Duration) -> Option<String> {
        match self.recv(timeout) {
            Recv::Frame(text) => Some(text),
            Recv::Eof | Recv::Timeout => None,
        }
    }

    /// One frame parsed as JSON; panics if none arrives in time.
    pub(crate) fn recv_json(&mut self, timeout: Duration) -> serde_json::Value {
        serde_json::from_str(&self.frame(timeout).expect("a frame")).unwrap()
    }

    /// Attach under `name` and check the daemon acknowledged it.
    pub(crate) fn attach(&mut self, name: &str) {
        self.send(&format!(
            r#"{{"op":"attach","id":"attach","name":"{name}","protocol_version":"v0"}}"#
        ));
        let ack = self.recv_json(Duration::from_secs(2));
        assert_eq!(ack["op"], "ack", "attach as {name}: {ack}");
    }
}
