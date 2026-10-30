// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! TLS for the WebSocket, `wss://` (ADR-0018 item 6): [`WsTls`], the
//! certificate chain and key the daemon presents, checked when it is made.
//!
//! The daemon offers TLS 1.3 alone, on rustls with its `ring` provider, and
//! asks for no client certificate: TLS encrypts the WebSocket and proves the
//! daemon's identity to a client that trusts its certificate, and it
//! authenticates no client. Clients prove Ed25519 keys at attach instead
//! (`crate::AttachKeys`, `mesh_port_protocol::attach`), each proof bound to
//! its connection by the TLS exporter value the accept loop reads from the
//! session once the handshake is done.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// The certificate chain and private key the WebSocket presents, which make it
/// serve `wss://`: a TLS 1.3 handshake on each connection before the upgrade,
/// within the policy's handshake timeout. Made from PEM, and checked as it is
/// made, so a daemon given one starts with a key that works.
///
/// Two are equal when they present the same certificate chain. `Debug` names
/// the chain's length and never the key.
#[derive(Clone)]
pub struct WsTls {
    chain: Vec<CertificateDer<'static>>,
    acceptor: TlsAcceptor,
}

impl WsTls {
    /// The chain in `cert_chain`, its own certificate first, and the key in
    /// `private_key` (PKCS #8, PKCS #1 or SEC1), both PEM.
    ///
    /// # Errors
    ///
    /// [`WsTlsError::Certificates`] when `cert_chain` holds no certificate or
    /// is not PEM, [`WsTlsError::Key`] when `private_key` holds no key or is
    /// not PEM, [`WsTlsError::Refused`] when rustls refuses the pair (a key
    /// it cannot sign with, or not the certificate's).
    pub fn from_pem(cert_chain: &[u8], private_key: &[u8]) -> Result<Self, WsTlsError> {
        let chain = CertificateDer::pem_slice_iter(cert_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| WsTlsError::Certificates(e.to_string()))?;
        if chain.is_empty() {
            return Err(WsTlsError::Certificates(
                "no CERTIFICATE section in it".into(),
            ));
        }
        let key = PrivateKeyDer::from_pem_slice(private_key).map_err(|e| {
            WsTlsError::Key(match e {
                rustls::pki_types::pem::Error::NoItemsFound => {
                    "no PRIVATE KEY section in it".into()
                }
                e => e.to_string(),
            })
        })?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| WsTlsError::Refused(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key)
        .map_err(|e| WsTlsError::Refused(e.to_string()))?;
        Ok(Self {
            chain,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    /// [`WsTls::from_pem`] with the PEM read from the files at `cert_chain`
    /// and `private_key`, as `--ws-tls-cert` and `--ws-tls-key` give them.
    ///
    /// # Errors
    ///
    /// [`WsTlsError::Read`] when a file cannot be read, and otherwise as
    /// [`WsTls::from_pem`].
    pub fn from_pem_files(cert_chain: &Path, private_key: &Path) -> Result<Self, WsTlsError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|source| WsTlsError::Read {
                path: path.to_path_buf(),
                source,
            })
        };
        Self::from_pem(&read(cert_chain)?, &read(private_key)?)
    }

    /// How many certificates the chain holds, its own first.
    #[must_use]
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// The acceptor that runs the handshake.
    pub(crate) fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }
}

impl PartialEq for WsTls {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain
    }
}

impl Eq for WsTls {}

impl fmt::Debug for WsTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsTls")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// Why a [`WsTls`] could not be made.
#[derive(Debug)]
#[non_exhaustive]
pub enum WsTlsError {
    /// A PEM file could not be read.
    Read {
        /// The file.
        path: PathBuf,
        /// The error reading it.
        source: std::io::Error,
    },
    /// The certificate chain holds no certificate, or is not PEM.
    Certificates(String),
    /// The private key's PEM holds no key, or is not PEM.
    Key(String),
    /// rustls refused the certificate and key: the key is not one it can sign
    /// with, or not the certificate's.
    Refused(String),
}

impl fmt::Display for WsTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(
                f,
                "the WebSocket's TLS file {} could not be read: {source}",
                path.display()
            ),
            Self::Certificates(why) => write!(f, "the WebSocket's certificate chain: {why}"),
            Self::Key(why) => write!(f, "the WebSocket's private key: {why}"),
            Self::Refused(why) => {
                write!(f, "the WebSocket's certificate and key were refused: {why}")
            }
        }
    }
}

impl std::error::Error for WsTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn identity() -> (String, String) {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (made.cert.pem(), made.signing_key.serialize_pem())
    }

    /// A certificate and its key make one; equality goes by the chain, and
    /// `Debug` shows no key.
    #[test]
    fn a_certificate_and_its_key_make_one() {
        let (cert, key) = identity();
        let tls = WsTls::from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(tls.chain_len(), 1);
        assert_eq!(
            tls,
            WsTls::from_pem(cert.as_bytes(), key.as_bytes()).unwrap()
        );
        let (other, other_key) = identity();
        assert_ne!(
            tls,
            WsTls::from_pem(other.as_bytes(), other_key.as_bytes()).unwrap()
        );
        assert_eq!(
            format!("{tls:?}"),
            "WsTls { certificates: 1, .. }",
            "Debug shows the chain's length alone"
        );
    }

    /// Each way the PEM can be wrong is named.
    #[test]
    fn what_is_wrong_is_named() {
        let (cert, key) = identity();
        let (_, other_key) = identity();
        assert!(matches!(
            WsTls::from_pem(b"", key.as_bytes()),
            Err(WsTlsError::Certificates(_))
        ));
        assert!(matches!(
            WsTls::from_pem(key.as_bytes(), key.as_bytes()),
            Err(WsTlsError::Certificates(_))
        ));
        assert!(matches!(
            WsTls::from_pem(cert.as_bytes(), cert.as_bytes()),
            Err(WsTlsError::Key(_))
        ));
        assert!(matches!(
            WsTls::from_pem(cert.as_bytes(), other_key.as_bytes()),
            Err(WsTlsError::Refused(_))
        ));
        let missing = Path::new("/nonexistent/pms-ws.pem");
        let err = WsTls::from_pem_files(missing, missing).unwrap_err();
        assert!(matches!(err, WsTlsError::Read { .. }), "{err:?}");
        assert!(err.to_string().contains("/nonexistent/pms-ws.pem"), "{err}");
    }
}
