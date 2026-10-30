// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Key files: the Ed25519 secret key a client proves at attach
//! (`MeshOptions::with_identity_file`), which `pms keys generate` makes.
//!
//! A key file is text: `#` comment lines, which [`generate_key_file`] uses to
//! name what the file is and its public key, and one line holding the
//! standard base64 of the 32-byte secret key (the Ed25519 seed). It is created
//! readable and writable by its owner alone (`0o600`), and [`read_key_file`]
//! refuses one that its group or anyone else may read or write, as SSH
//! refuses a private key with open permissions: the key is the client's
//! identity, and whoever reads the file can attach as it. The public key,
//! which goes in a daemon's `--attach-keys` list, is [`public_key_text`].
//!
//! The file's text and the decoded key are held in buffers cleared as they
//! drop, and `SigningKey` clears itself.

use crate::error::DevError;
use mesh_port_protocol::attach::{self, SigningKey, SECRET_KEY_LEN};
use mesh_port_protocol::base64;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use zeroize::Zeroizing;

/// The permission bits a key file may not carry: any for its group or for
/// others.
const OPEN_BITS: u32 = 0o077;

/// The error naming the key file at `path`.
fn key_file(path: &Path, reason: impl Into<String>) -> DevError {
    DevError::KeyFile {
        path: path.display().to_string(),
        reason: reason.into(),
    }
}

/// A new key, from the operating system's random source.
///
/// # Errors
///
/// [`DevError::KeyFile`], naming no file, when the operating system gives no
/// random bytes.
pub fn generate_key() -> Result<SigningKey, DevError> {
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_LEN]);
    getrandom::getrandom(&mut seed[..]).map_err(|e| DevError::KeyFile {
        path: String::new(),
        reason: format!("no random bytes for a new key: {e}"),
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The public key of `key` as a daemon's `--attach-keys` list and an attach's
/// `key` write it: standard base64, 44 characters.
#[must_use]
pub fn public_key_text(key: &SigningKey) -> String {
    attach::encode_key(&key.verifying_key().to_bytes())
}

/// Make a new key and write it to a new file at `path`, readable and writable
/// by its owner alone, and return it. An existing file is never replaced.
///
/// # Errors
///
/// [`DevError::KeyFile`] when the file exists already, cannot be created or
/// written, or no random bytes can be had.
pub fn generate_key_file(path: &Path) -> Result<SigningKey, DevError> {
    let key = generate_key()?;
    let secret = Zeroizing::new(base64::encode(&key.to_bytes()));
    let text = Zeroizing::new(format!(
        "# Pulse Mesh attach key (Ed25519). Keep this file to yourself: whoever reads it can attach as this key.\n\
         # public key: {}\n\
         {}\n",
        public_key_text(&key),
        secret.as_str()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| key_file(path, format!("cannot create it: {e}")))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| key_file(path, format!("cannot write it: {e}")))?;
    Ok(key)
}

/// The key in the key file at `path`.
///
/// # Errors
///
/// [`DevError::KeyFile`] when the file cannot be opened or read, when its
/// group or others may read or write it (`chmod 600` mends that), or when it
/// holds anything but comments, blank lines and one line of the standard
/// base64 of 32 bytes.
pub fn read_key_file(path: &Path) -> Result<SigningKey, DevError> {
    let mut file =
        std::fs::File::open(path).map_err(|e| key_file(path, format!("cannot open it: {e}")))?;
    // The permissions of the file opened, not of whatever the path names
    // after.
    let mode = file
        .metadata()
        .map_err(|e| key_file(path, format!("cannot read its permissions: {e}")))?
        .permissions()
        .mode();
    if mode & OPEN_BITS != 0 {
        return Err(key_file(
            path,
            format!(
                "its permissions are {:04o}: a key file is its owner's alone \
                 (chmod 600 {})",
                mode & 0o7777,
                path.display()
            ),
        ));
    }
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)
        .map_err(|e| key_file(path, format!("cannot read it: {e}")))?;
    parse_key(&text).map_err(|reason| key_file(path, reason))
}

/// The key a key file's text holds, or what is wrong with it.
fn parse_key(text: &str) -> Result<SigningKey, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let Some(line) = lines.next() else {
        return Err("it holds no key".into());
    };
    if lines.next().is_some() {
        return Err("it holds more than one line that is not a comment".into());
    }
    let bytes = Zeroizing::new(
        base64::decode(line).map_err(|e| format!("its key is not padded standard base64: {e}"))?,
    );
    let seed: Zeroizing<[u8; SECRET_KEY_LEN]> = Zeroizing::new(
        <[u8; SECRET_KEY_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| format!("its key holds {} bytes, not 32", bytes.len()))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    #[test]
    fn a_generated_key_file_is_its_owners_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("pms-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("worker.key");
        let _ = std::fs::remove_file(&path);
        let made = generate_key_file(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let read = read_key_file(&path).unwrap();
        assert_eq!(read.to_bytes(), made.to_bytes());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&public_key_text(&made)), "{text}");
        assert!(
            matches!(generate_key_file(&path), Err(DevError::KeyFile { .. })),
            "an existing file is never replaced"
        );
        assert_eq!(read_key_file(&path).unwrap().to_bytes(), made.to_bytes());

        for open in [0o640, 0o604, 0o620, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(open)).unwrap();
            let err = read_key_file(&path).unwrap_err().to_string();
            assert!(err.contains("chmod 600"), "{open:o}: {err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            read_key_file(&path).is_ok(),
            "read-only for its owner is fine"
        );
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn a_key_files_text_is_comments_and_one_key() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let line = base64::encode(&key.to_bytes());
        assert_eq!(
            parse_key(&format!("# a\n\n  {line}  \n# b\n"))
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
        assert!(parse_key("# nothing\n").unwrap_err().contains("no key"));
        assert!(parse_key(&format!("{line}\n{line}\n"))
            .unwrap_err()
            .contains("more than one"));
        assert!(parse_key("AAAA\n").unwrap_err().contains("3 bytes"));
        assert!(parse_key("not base64\n")
            .unwrap_err()
            .contains("not padded standard base64"));
    }
}
