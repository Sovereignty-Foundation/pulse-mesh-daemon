// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Daemon ids and qualified origins (ADR-0021, item 3).

use std::fmt;
use std::str::FromStr;

use mesh_port_protocol::MAX_NAME_LEN;

/// A daemon as its peers name it: the first eight bytes of the BLAKE3 hash
/// of its 32-byte public key, ADR-0018's node key, written as 16 lowercase
/// hex digits.
///
/// It is a name, not a credential. A link authenticates the whole key
/// (ADR-0018), and the id only says which daemon an origin or a node
/// belongs to. Ids order and compare by their bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DaemonId([u8; 8]);

impl DaemonId {
    /// Bytes in a daemon id.
    pub const LEN: usize = 8;

    /// The id of the daemon whose public key is `key`.
    #[must_use]
    pub fn from_public_key(key: &[u8; 32]) -> Self {
        let hash = blake3::hash(key);
        let mut id = [0; Self::LEN];
        id.copy_from_slice(&hash.as_bytes()[..Self::LEN]);
        Self(id)
    }

    /// The id whose bytes are `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for DaemonId {
    /// The 16 lowercase hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DaemonId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DaemonId({self})")
    }
}

impl FromStr for DaemonId {
    type Err = OriginError;

    /// Exactly 16 lowercase hex digits: the one way an id is written, so
    /// that parsing and writing are inverses.
    fn from_str(text: &str) -> Result<Self, OriginError> {
        let digits = text.as_bytes();
        if digits.len() != 2 * Self::LEN {
            return Err(OriginError::BadDaemon);
        }
        let mut id = [0; Self::LEN];
        for (byte, pair) in id.iter_mut().zip(digits.chunks_exact(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(id))
    }
}

fn nibble(digit: u8) -> Result<u8, OriginError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(OriginError::BadDaemon),
    }
}

/// A client across links: the daemon it is attached to and the name it
/// attached with, written `name@` and the daemon's 16 hex digits.
///
/// On its own daemon a client is `name@` and 8 hex digits, the first four
/// bytes of the node id its name hashes to (`mesh-hub`'s `Origin`), or, when
/// it proved a key at attach, `name@` and the 32 hex digits of the node id
/// the key derives (`mesh_port_protocol::attach::keyed_node_id`), and those
/// forms do not change. None of them meets this one: an origin text whose
/// last `@` is followed by 8 or 32 digits is no qualified origin, and two
/// hosts' clients of one name are two qualified origins. The name may hold
/// `@` itself; the last one in the text separates it from the daemon.
///
/// Qualified origins order by their daemon, then by their name's bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedOrigin {
    pub(crate) daemon: DaemonId,
    pub(crate) name: String,
}

impl QualifiedOrigin {
    /// The client attached to `daemon` as `name`.
    ///
    /// # Errors
    ///
    /// [`OriginError::NameTooLong`] for a name longer than a daemon admits
    /// at attach, [`MAX_NAME_LEN`] bytes.
    pub fn new(daemon: DaemonId, name: impl Into<String>) -> Result<Self, OriginError> {
        let name = name.into();
        if name.len() > MAX_NAME_LEN {
            return Err(OriginError::NameTooLong { len: name.len() });
        }
        Ok(Self { daemon, name })
    }

    /// Read the text form, `name@` and 16 lowercase hex digits.
    ///
    /// # Errors
    ///
    /// [`OriginError::NoDaemon`] for a text without `@`,
    /// [`OriginError::BadDaemon`] when what follows the last `@` is not 16
    /// lowercase hex digits (a local origin's 8 or 32 among them), and
    /// [`OriginError::NameTooLong`] for a name longer than [`MAX_NAME_LEN`]
    /// bytes.
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let (name, daemon) = text.rsplit_once('@').ok_or(OriginError::NoDaemon)?;
        Self::new(daemon.parse()?, name)
    }

    /// The daemon the client is attached to.
    #[must_use]
    pub fn daemon(&self) -> DaemonId {
        self.daemon
    }

    /// The name the client attached with.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for QualifiedOrigin {
    /// `name@` and the daemon's 16 hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.daemon)
    }
}

impl FromStr for QualifiedOrigin {
    type Err = OriginError;

    fn from_str(text: &str) -> Result<Self, OriginError> {
        Self::parse(text)
    }
}

/// Why a name or a text is not a qualified origin.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OriginError {
    /// The name is longer than a daemon admits at attach.
    #[error("a name of {len} bytes is longer than the {max} bytes a client may attach with", max = MAX_NAME_LEN)]
    NameTooLong {
        /// The name's length in bytes.
        len: usize,
    },
    /// The text has no `@` between a name and a daemon.
    #[error("a qualified origin is name@daemon, and this text has no '@'")]
    NoDaemon,
    /// The daemon is not 16 lowercase hex digits.
    #[error("a daemon id is 16 lowercase hex digits")]
    BadDaemon,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;
    use pulse_canon::NodeId;
    use std::collections::HashSet;

    /// A local origin as the daemon writes it (`mesh-hub`'s `Origin::named`).
    fn local(name: &str) -> String {
        let suffix: String = NodeId::from_name(name).as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{name}@{suffix}")
    }

    #[test]
    fn a_daemon_id_is_the_head_of_the_keys_blake3_hash() {
        let key = [7u8; 32];
        let id = DaemonId::from_public_key(&key);
        assert_eq!(id.as_bytes()[..], blake3::hash(&key).as_bytes()[..8]);
        let text = id.to_string();
        assert_eq!(text.len(), 16);
        assert_eq!(text.parse::<DaemonId>(), Ok(id));
        assert_eq!(format!("{id:?}"), format!("DaemonId({text})"));
    }

    #[test]
    fn a_daemon_id_is_read_only_as_it_is_written() {
        for bad in [
            "",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "+123456789abcdef",
        ] {
            assert_eq!(
                bad.parse::<DaemonId>(),
                Err(OriginError::BadDaemon),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_last_at_sign_separates_the_name() {
        let daemon = DaemonId::from_bytes([0, 1, 2, 3, 4, 5, 6, 0xff]);
        let origin = QualifiedOrigin::new(daemon, "a@b").unwrap();
        assert_eq!(origin.to_string(), "a@b@00010203040506ff");
        assert_eq!(QualifiedOrigin::parse("a@b@00010203040506ff"), Ok(origin));
        assert_eq!(
            QualifiedOrigin::parse("@00010203040506ff").unwrap().name(),
            ""
        );
        assert_eq!(QualifiedOrigin::parse("worker"), Err(OriginError::NoDaemon));
        assert_eq!(
            QualifiedOrigin::parse("worker@00010203"),
            Err(OriginError::BadDaemon)
        );
    }

    #[test]
    fn a_name_longer_than_attach_admits_is_refused() {
        let daemon = DaemonId::from_bytes([0; 8]);
        assert!(QualifiedOrigin::new(daemon, "n".repeat(MAX_NAME_LEN)).is_ok());
        assert_eq!(
            QualifiedOrigin::new(daemon, "n".repeat(MAX_NAME_LEN + 1)),
            Err(OriginError::NameTooLong {
                len: MAX_NAME_LEN + 1
            })
        );
    }

    #[test]
    fn two_hosts_clients_of_one_name_are_two_origins() {
        let a = QualifiedOrigin::new(DaemonId::from_public_key(&[1; 32]), "worker").unwrap();
        let b = QualifiedOrigin::new(DaemonId::from_public_key(&[2; 32]), "worker").unwrap();
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
        let set: HashSet<_> = [a.clone(), b.clone(), a.clone()].into_iter().collect();
        assert_eq!(set.len(), 2);
        // Ordered by daemon first.
        assert_eq!(a < b, a.daemon() < b.daemon());
    }

    proptest! {
        #[test]
        fn text_round_trips(name in "\\PC{0,30}", bytes in any::<[u8; 8]>()) {
            let origin = QualifiedOrigin::new(DaemonId::from_bytes(bytes), name.clone()).unwrap();
            let text = origin.to_string();
            prop_assert_eq!(QualifiedOrigin::parse(&text), Ok(origin.clone()));
            prop_assert_eq!(origin.name(), name.as_str());
        }

        #[test]
        fn a_local_origin_is_never_a_qualified_one(name in "\\PC{0,30}", key in any::<[u8; 32]>()) {
            prop_assert!(QualifiedOrigin::parse(&local(&name)).is_err());
            let keyed = mesh_port_protocol::attach::keyed_node_id(&name, &key);
            prop_assert!(QualifiedOrigin::parse(&keyed).is_err());
        }

        #[test]
        fn order_is_by_daemon_then_name(
            a in any::<[u8; 8]>(), b in any::<[u8; 8]>(), m in "[a-c@]{0,4}", n in "[a-c@]{0,4}",
        ) {
            let x = QualifiedOrigin::new(DaemonId::from_bytes(a), m.clone()).unwrap();
            let y = QualifiedOrigin::new(DaemonId::from_bytes(b), n.clone()).unwrap();
            prop_assert_eq!(x.cmp(&y), (a, m).cmp(&(b, n)));
        }
    }
}
