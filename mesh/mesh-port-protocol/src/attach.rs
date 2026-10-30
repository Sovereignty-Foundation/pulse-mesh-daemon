// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Key-proof attach (ADR-0018 item 6): a client that holds an Ed25519 key
//! proves it at attach, and the daemon names the connection by the key rather
//! than by the name it claims.
//!
//! The exchange, in protocol version `v0`:
//!
//! 1. The client attaches with `key`, the standard base64 ([`crate::base64`])
//!    of its 32-byte Ed25519 public key:
//!    `{"op":"attach","id":"1","name":"worker","protocol_version":"v0","key":"<44 characters>"}`.
//! 2. The daemon answers with a challenge instead of the ack, echoing the
//!    attach's id: `{"op":"challenge","id":"1","nonce":"<base64 of 32 random bytes>"}`.
//! 3. The client answers with a proof under the same id:
//!    `{"op":"prove","id":"1","signature":"<base64 of 64 bytes>"}`, the
//!    Ed25519 signature ([`sign`]) of the bytes [`signed_bytes`] lays out.
//! 4. The daemon verifies the signature ([`verify`], RFC 8032 with the strict
//!    checks: no small-order key, no non-canonical signature) and, when it
//!    keeps an allowlist, that the key is on it (after the signature, so only
//!    the key's holder learns whether it is listed), then acks the attach as
//!    it acks any other, with the node id [`keyed_node_id`] gives. A proof that
//!    fails, a key not allowed, a `prove` with no challenge pending, any other
//!    request while one is pending, and a challenge unanswered within the
//!    daemon's handshake timeout are each answered with an `error` whose code
//!    is `auth_failed`, and the daemon closes the connection. A key that is
//!    not the padded base64 of 32 bytes is a `bad_request`, and the
//!    connection stays open. A proven key whose name another attached
//!    connection holds, or that another connection has proved under another
//!    name (a key is one attached connection at a time), is answered
//!    `name_in_use`, and the connection stays open too.
//!
//! An attach without `key` is the attach the protocol always had; a daemon
//! that requires a key refuses it with `auth_failed`. A daemon from before
//! this exchange ignores `key` and acks at once, and a client takes that ack
//! as the attach's answer.
//!
//! # The signed bytes
//!
//! In order: [`DOMAIN`] (`pulse-mesh/attach/v0` and a zero byte, 21 bytes);
//! the challenge's 32-byte nonce; the attach name's length in bytes as an
//! 8-byte big-endian integer, then the name's UTF-8; and 32 bytes binding the
//! proof to its connection. On a TLS connection (`wss://`) those are the
//! connection's TLS exporter value (RFC 8446 §7.5) for the label
//! [`TLS_EXPORTER_LABEL`] with no context, which both ends compute from the
//! session, so a proof made on one connection is refused on any other, even
//! by a party that relays the daemon's challenge to the key's holder. On a
//! plaintext connection, a `ws://` WebSocket or the Unix socket, they are 32
//! zero bytes ([`NO_EXPORTER`]), and only the nonce ties a proof to its
//! connection: a party on the path of a plaintext connection can relay a
//! challenge and its proof as they happen, which is why a daemon off loopback
//! takes keys with TLS. Ed25519 hashes the public key into every signature,
//! so the key is bound without being repeated here.
//!
//! # Node ids
//!
//! A connection attached by name is `name@` and 8 hex digits, the first four
//! bytes of `BLAKE3(name)`; across links (ADR-0021) a client is `name@` and its
//! daemon's 16. A connection that proved a key is `name@` and 32 hex digits:
//! [`key_node_id`], the 16-byte node id derived from the key alone, which is
//! also the id the hub's schema lists name (`mesh-schema`). The three forms
//! differ in the digits after the last `@`, so no text of one is a text of
//! another, and the key's id is derived in BLAKE3's key-derivation mode, which
//! no hash of a name can give.

pub use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::base64::{self, Base64Error};
use ed25519_dalek::Signature;
use std::fmt;

/// Bytes in an Ed25519 public key, the `key` an attach carries.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Bytes in an Ed25519 secret key: the seed a key file holds.
pub const SECRET_KEY_LEN: usize = 32;

/// Bytes in an Ed25519 signature, the `signature` a `prove` carries.
pub const SIGNATURE_LEN: usize = 64;

/// Bytes in a challenge's `nonce`.
pub const NONCE_LEN: usize = 32;

/// Bytes of the TLS exporter value a proof is bound to.
pub const EXPORTER_LEN: usize = 32;

/// The first bytes of every signed attach proof: the protocol and its
/// version, then a zero byte, so no other message this crate or another
/// signs can be read as one.
pub const DOMAIN: &[u8] = b"pulse-mesh/attach/v0\0";

/// The TLS exporter label (RFC 8446 §7.5, RFC 5705 §4) both ends of a
/// `wss://` connection export [`EXPORTER_LEN`] bytes under, with no context,
/// to bind a proof to the connection. `EXPERIMENTAL` is RFC 5705's prefix for
/// a label used without registration.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL pulse-mesh attach v0";

/// What stands in for the TLS exporter value on a plaintext connection.
pub const NO_EXPORTER: [u8; EXPORTER_LEN] = [0; EXPORTER_LEN];

/// The BLAKE3 key-derivation context of a key's node id ([`key_node_id`]).
const NODE_ID_CONTEXT: &str = "pulse-mesh 2026-10-17 attach key node id v0";

/// The bytes a client signs to prove its key: see the module documentation.
#[must_use]
pub fn signed_bytes(nonce: &[u8; NONCE_LEN], name: &str, exporter: &[u8; EXPORTER_LEN]) -> Vec<u8> {
    let name_len = u64::try_from(name.len()).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(DOMAIN.len() + NONCE_LEN + 8 + name.len() + EXPORTER_LEN);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&name_len.to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(exporter);
    bytes
}

/// The proof of `key` for the challenge `nonce` to an attach under `name`
/// on the connection `exporter` names ([`NO_EXPORTER`] on a plaintext one):
/// the Ed25519 signature of [`signed_bytes`].
#[must_use]
pub fn sign(
    key: &SigningKey,
    nonce: &[u8; NONCE_LEN],
    name: &str,
    exporter: &[u8; EXPORTER_LEN],
) -> [u8; SIGNATURE_LEN] {
    use ed25519_dalek::Signer as _;
    key.sign(&signed_bytes(nonce, name, exporter)).to_bytes()
}

/// Check that `signature` proves `public_key` for the challenge `nonce` to
/// an attach under `name` on the connection `exporter` names.
///
/// # Errors
///
/// [`ProofError::Key`] when `public_key` is no Ed25519 point, or one of small
/// order, which proves nothing; [`ProofError::Signature`] when the signature
/// is not the key's over these bytes, or is not in its canonical form.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    name: &str,
    exporter: &[u8; EXPORTER_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ProofError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ProofError::Key)?;
    if key.is_weak() {
        return Err(ProofError::Key);
    }
    key.verify_strict(
        &signed_bytes(nonce, name, exporter),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ProofError::Signature)
}

/// A public key as an attach and an allowlist write it: standard base64 of
/// its 32 bytes, 44 characters.
#[must_use]
pub fn encode_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    base64::encode(public_key)
}

/// The 32 bytes of a public key written as [`encode_key`] writes it.
///
/// # Errors
///
/// [`ProofError::Text`] when `text` is not padded standard base64 of exactly
/// 32 bytes.
pub fn decode_key(text: &str) -> Result<[u8; PUBLIC_KEY_LEN], ProofError> {
    decode_fixed("key", text)
}

/// The 32 bytes of a challenge's `nonce`.
///
/// # Errors
///
/// [`ProofError::Text`] when `text` is not padded standard base64 of exactly
/// 32 bytes.
pub fn decode_nonce(text: &str) -> Result<[u8; NONCE_LEN], ProofError> {
    decode_fixed("nonce", text)
}

/// The 64 bytes of a `prove`'s `signature`.
///
/// # Errors
///
/// [`ProofError::Text`] when `text` is not padded standard base64 of exactly
/// 64 bytes.
pub fn decode_signature(text: &str) -> Result<[u8; SIGNATURE_LEN], ProofError> {
    decode_fixed("signature", text)
}

/// `N` bytes from the padded standard base64 `text` of the field `field`.
fn decode_fixed<const N: usize>(field: &'static str, text: &str) -> Result<[u8; N], ProofError> {
    let bytes = base64::decode(text).map_err(|e| ProofError::Text {
        field,
        reason: TextError::Base64(e),
    })?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| ProofError::Text {
        field,
        reason: TextError::Length {
            expected: N,
            got: bytes.len(),
        },
    })
}

/// The 16-byte node id of a connection that proved `public_key`: the first
/// 16 bytes BLAKE3 derives from the key in its key-derivation mode, under a
/// context of this protocol's own. It depends on the key alone, so a
/// schema's producer and consumer lists name a key by it
/// (`pulse_canon::NodeId::from_bytes(key_node_id(&key))`).
#[must_use]
pub fn key_node_id(public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; 16] {
    let derived = blake3::derive_key(NODE_ID_CONTEXT, public_key);
    let mut id = [0; 16];
    id.copy_from_slice(&derived[..16]);
    id
}

/// The node id an attach under `name` that proved `public_key` is acked
/// with, and its events carry as `origin`: `name@` and the 32 lowercase hex
/// digits of [`key_node_id`].
#[must_use]
pub fn keyed_node_id(name: &str, public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    use fmt::Write as _;
    let mut text = String::with_capacity(name.len() + 33);
    text.push_str(name);
    text.push('@');
    for byte in key_node_id(public_key) {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Why a key, a nonce, a signature or a proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofError {
    /// The field's text is not the padded standard base64 of as many bytes as
    /// the field holds.
    Text {
        /// `key`, `nonce` or `signature`.
        field: &'static str,
        /// What is wrong with it.
        reason: TextError,
    },
    /// The public key is not an Ed25519 point, or is one of small order.
    Key,
    /// The signature is not the key's over the challenge, the name and the
    /// connection, or is not in its canonical form.
    Signature,
}

/// What is wrong with a fixed-length base64 field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TextError {
    /// Not padded standard base64.
    Base64(Base64Error),
    /// Base64 of the wrong number of bytes.
    Length {
        /// The bytes the field holds.
        expected: usize,
        /// The bytes the text decodes to.
        got: usize,
    },
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text {
                field,
                reason: TextError::Base64(e),
            } => write!(f, "`{field}` is not padded standard base64: {e}"),
            Self::Text {
                field,
                reason: TextError::Length { expected, got },
            } => write!(f, "`{field}` holds {got} bytes, not {expected}"),
            Self::Key => {
                f.write_str("the key is not an Ed25519 public key that can prove anything")
            }
            Self::Signature => f.write_str(
                "the signature does not prove the key for this challenge, name and connection",
            ),
        }
    }
}

impl std::error::Error for ProofError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; SECRET_KEY_LEN])
    }

    #[test]
    fn the_signed_bytes_are_the_domain_the_nonce_the_name_and_the_exporter() {
        let nonce = [1; NONCE_LEN];
        let exporter = [2; EXPORTER_LEN];
        let bytes = signed_bytes(&nonce, "worker", &exporter);
        let mut want = b"pulse-mesh/attach/v0\0".to_vec();
        want.extend_from_slice(&[1; 32]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 6]);
        want.extend_from_slice(b"worker");
        want.extend_from_slice(&[2; 32]);
        assert_eq!(bytes, want);
        assert_eq!(DOMAIN.len(), 21);
    }

    #[test]
    fn a_proof_verifies_for_its_challenge_name_and_connection_alone() {
        let k = key(7);
        let public = k.verifying_key().to_bytes();
        let nonce = [9; NONCE_LEN];
        let exporter = [3; EXPORTER_LEN];
        let proof = sign(&k, &nonce, "worker", &exporter);
        assert_eq!(verify(&public, &nonce, "worker", &exporter, &proof), Ok(()));
        let refused = Err(ProofError::Signature);
        assert_eq!(
            verify(&public, &[8; NONCE_LEN], "worker", &exporter, &proof),
            refused
        );
        assert_eq!(
            verify(&public, &nonce, "worker2", &exporter, &proof),
            refused
        );
        assert_eq!(
            verify(&public, &nonce, "worker", &NO_EXPORTER, &proof),
            refused,
            "a proof for one connection is refused on another"
        );
        let other = key(8).verifying_key().to_bytes();
        assert_eq!(verify(&other, &nonce, "worker", &exporter, &proof), refused);
        let mut flipped = proof;
        flipped[10] ^= 1;
        assert_eq!(
            verify(&public, &nonce, "worker", &exporter, &flipped),
            refused
        );
    }

    #[test]
    fn a_small_order_or_invalid_key_proves_nothing() {
        // The identity point, of order one: any "signature" with R = identity
        // and s = 0 would verify under the lax rules.
        let mut identity = [0u8; PUBLIC_KEY_LEN];
        identity[0] = 1;
        let mut forged = [0u8; SIGNATURE_LEN];
        forged[0] = 1;
        assert_eq!(
            verify(&identity, &[0; 32], "x", &NO_EXPORTER, &forged),
            Err(ProofError::Key)
        );
        // Not a point at all (y = 2 has no x on the curve).
        let mut off_curve = [0u8; PUBLIC_KEY_LEN];
        off_curve[0] = 2;
        assert!(matches!(
            verify(&off_curve, &[0; 32], "x", &NO_EXPORTER, &forged),
            Err(ProofError::Key | ProofError::Signature)
        ));
    }

    #[test]
    fn keys_nonces_and_signatures_are_strict_base64_of_their_length() {
        let public = key(1).verifying_key().to_bytes();
        let text = encode_key(&public);
        assert_eq!(text.len(), 44);
        assert_eq!(decode_key(&text), Ok(public));
        assert!(matches!(
            decode_key(&text[..43]),
            Err(ProofError::Text {
                field: "key",
                reason: TextError::Base64(_)
            })
        ));
        assert_eq!(
            decode_key(&base64::encode(&[0; 31])),
            Err(ProofError::Text {
                field: "key",
                reason: TextError::Length {
                    expected: 32,
                    got: 31
                }
            })
        );
        assert_eq!(decode_nonce(&base64::encode(&[5; 32])), Ok([5; 32]));
        assert!(decode_signature(&base64::encode(&[5; 32])).is_err());
        assert_eq!(decode_signature(&base64::encode(&[5; 64])), Ok([5; 64]));
        let shown = decode_signature("!").unwrap_err().to_string();
        assert!(shown.contains("`signature`"), "{shown}");
    }

    #[test]
    fn a_keys_node_id_is_its_own_and_unlike_any_names() {
        let public = key(2).verifying_key().to_bytes();
        let id = key_node_id(&public);
        assert_eq!(id, key_node_id(&public));
        assert_ne!(id, key_node_id(&key(3).verifying_key().to_bytes()));
        // The plain hash of the key's bytes, which a name of those bytes
        // would give, is another id.
        assert_ne!(id[..], blake3::hash(&public).as_bytes()[..16]);
        let text = keyed_node_id("worker", &public);
        let (name, digits) = text.rsplit_once('@').unwrap();
        assert_eq!(name, "worker");
        assert_eq!(digits.len(), 32);
        assert!(digits
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digits, hex);
    }
}
