// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`AttachKeys`], the Ed25519 public keys a client may prove at attach
//! (ADR-0018 item 6), as `--attach-keys` reads them from a file.
//!
//! The file holds one key per line, the 44 characters of its standard base64
//! (`pms keys public` prints them). A `#` begins a comment, on a line of its
//! own or after a key; blank lines and spaces around a key are ignored.
//! Anything else is refused, naming the line, so a daemon never starts with
//! a list other than the one its operator wrote.

use mesh_port_protocol::attach::{self, PUBLIC_KEY_LEN};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The public keys a client may prove at attach: with them in the
/// connection policy (`ConnectionPolicy::attach_keys`), every attach on the
/// WebSocket proves one of them, and every keyed attach on either transport
/// proves a listed key. Cheap to clone.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachKeys {
    keys: Arc<BTreeSet<[u8; PUBLIC_KEY_LEN]>>,
}

impl AttachKeys {
    /// The list of `keys`, each a 32-byte Ed25519 public key.
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = [u8; PUBLIC_KEY_LEN]>) -> Self {
        Self {
            keys: Arc::new(keys.into_iter().collect()),
        }
    }

    /// The keys an allowlist file's text lists (see the module
    /// documentation).
    ///
    /// # Errors
    ///
    /// [`AttachKeysError::Line`] for the first line that is neither blank, a
    /// comment, nor a key with an optional comment after it.
    pub fn parse(text: &str) -> Result<Self, AttachKeysError> {
        let mut keys = BTreeSet::new();
        for (index, line) in text.lines().enumerate() {
            let content = line.split_once('#').map_or(line, |(before, _)| before);
            let content = content.trim();
            if content.is_empty() {
                continue;
            }
            let key = attach::decode_key(content).map_err(|e| AttachKeysError::Line {
                path: None,
                line: index + 1,
                reason: e.to_string(),
            })?;
            keys.insert(key);
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    /// The keys the allowlist file at `path` lists, as `--attach-keys` reads
    /// it.
    ///
    /// # Errors
    ///
    /// [`AttachKeysError::Read`] when the file cannot be read or is not
    /// UTF-8, and [`AttachKeysError::Line`], naming the file, as
    /// [`AttachKeys::parse`] refuses.
    pub fn from_file(path: &Path) -> Result<Self, AttachKeysError> {
        let read = |source| AttachKeysError::Read {
            path: path.to_path_buf(),
            source,
        };
        let text = std::fs::read_to_string(path).map_err(read)?;
        Self::parse(&text).map_err(|e| match e {
            AttachKeysError::Line { line, reason, .. } => AttachKeysError::Line {
                path: Some(path.to_path_buf()),
                line,
                reason,
            },
            other => other,
        })
    }

    /// Whether `key` is listed.
    #[must_use]
    pub fn contains(&self, key: &[u8; PUBLIC_KEY_LEN]) -> bool {
        self.keys.contains(key)
    }

    /// How many keys are listed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is listed, which refuses every keyed attach.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys, in byte order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; PUBLIC_KEY_LEN]> {
        self.keys.iter()
    }
}

impl fmt::Debug for AttachKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(attach::encode_key))
            .finish()
    }
}

/// Why an allowlist of attach keys could not be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum AttachKeysError {
    /// The file could not be read, or is not UTF-8.
    Read {
        /// The file.
        path: PathBuf,
        /// The error reading it.
        source: std::io::Error,
    },
    /// A line is neither blank, a comment, nor a key.
    Line {
        /// The file, when the list was read from one.
        path: Option<PathBuf>,
        /// The line's number, from 1.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
}

impl fmt::Display for AttachKeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(
                f,
                "the attach keys file {} could not be read: {source}",
                path.display()
            ),
            Self::Line {
                path: Some(path),
                line,
                reason,
            } => write!(
                f,
                "the attach keys file {}, line {line}: {reason}; each line is a key's \
                 standard base64, a `#` comment, or blank",
                path.display()
            ),
            Self::Line {
                path: None,
                line,
                reason,
            } => write!(
                f,
                "attach keys, line {line}: {reason}; each line is a key's standard \
                 base64, a `#` comment, or blank"
            ),
        }
    }
}

impl std::error::Error for AttachKeysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Line { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mesh_port_protocol::attach::SigningKey;

    fn public(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn keys_comments_and_blank_lines_are_read_and_nothing_else() {
        let (a, b) = (public(1), public(2));
        let text = format!(
            "# the workers\n\n  {}  \n{} # the collector\n{}\n",
            attach::encode_key(&a),
            attach::encode_key(&b),
            attach::encode_key(&a),
        );
        let keys = AttachKeys::parse(&text).unwrap();
        assert_eq!(keys.len(), 2, "a key listed twice is one key");
        assert!(keys.contains(&a) && keys.contains(&b));
        assert!(!keys.contains(&public(3)));
        assert_eq!(keys, AttachKeys::new([b, a]));
        assert!(format!("{keys:?}").contains(&attach::encode_key(&a)));
        assert!(AttachKeys::parse("# nothing\n").unwrap().is_empty());

        for (bad, line) in [
            ("not a key\n", 1),
            (&format!("# ok\n{}=\n", attach::encode_key(&a)) as &str, 2),
            (&format!("{}\nAAAA\n", attach::encode_key(&a)), 2),
            (
                &format!("{} {}\n", attach::encode_key(&a), attach::encode_key(&b)),
                1,
            ),
        ] {
            match AttachKeys::parse(bad) {
                Err(AttachKeysError::Line { line: got, .. }) => assert_eq!(got, line, "{bad:?}"),
                other => panic!("{bad:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_file_is_read_and_its_errors_name_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attach.keys");
        std::fs::write(&path, format!("{}\n", attach::encode_key(&public(4)))).unwrap();
        assert!(AttachKeys::from_file(&path).unwrap().contains(&public(4)));
        std::fs::write(&path, "# one\nnope\n").unwrap();
        let err = AttachKeys::from_file(&path).unwrap_err().to_string();
        assert!(
            err.contains(&path.display().to_string()) && err.contains("line 2"),
            "{err}"
        );
        let missing = dir.path().join("missing.keys");
        let err = AttachKeys::from_file(&missing).unwrap_err();
        assert!(matches!(err, AttachKeysError::Read { .. }), "{err:?}");
        assert!(err.to_string().contains("missing.keys"), "{err}");
    }
}
