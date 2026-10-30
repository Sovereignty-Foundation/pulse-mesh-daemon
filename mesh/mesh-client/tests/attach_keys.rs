// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Key-proof attach against an in-process daemon whose policy lists the
//! keys it allows: a client with a listed key attaches over `ws://` and over
//! `wss://`, its proof bound there to the TLS connection, and is named by
//! the key; a client without a key, or with a key not listed, is refused
//! with `DevError::AuthFailed`; a daemon with no list names any proven key;
//! the Unix socket admits its owner without a key unless the policy says
//! otherwise; and a key file is refused when its group or others may read
//! it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::identity::{generate_key_file, public_key_text, read_key_file};
use mesh_client::{DevError, Endpoint, Mesh, MeshOptions, SigningKey};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::protocol::attach;
use mesh_hub::{AttachKeys, ConnectionPolicy, WsTls};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::mpsc;
use std::time::Duration;

/// A hub name unique to this process and short enough for every SHM name
/// derived from it.
fn hub(tag: &str) -> String {
    format!("ak-{tag}-{:04x}", std::process::id() & 0xffff)
}

/// A CA, as PEM, and a daemon certificate it issued for `localhost`.
fn issued() -> (String, WsTls) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let tls = WsTls::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    (ca.pem(), tls)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn start(tag: &str, binds: &[Bind], policy: ConnectionPolicy) -> EmbeddedMesh {
    EmbeddedMesh::start_with_config(
        &hub(tag),
        binds,
        policy,
        HubConfig::default().with_store_slots(16),
    )
    .expect("the mesh starts")
}

/// The origin of the client's own send, as its own subscription sees it.
fn own_origin(mesh: &Mesh) -> String {
    let (tx, rx) = mpsc::channel();
    let sub = mesh
        .on("me", move |event| {
            let _ = tx.send(event.origin);
        })
        .expect("subscribe");
    mesh.send("me", b"who").expect("send");
    let origin = rx.recv_timeout(Duration::from_secs(5)).expect("the event");
    mesh.unsubscribe(sub).expect("unsubscribe");
    origin
}

/// A listed key attaches over ws and over wss and is named by the key; a
/// client without a key and one with a key not listed are refused.
#[test]
fn a_listed_key_attaches_over_ws_and_wss_and_others_are_refused() {
    let listed = key(1);
    let policy =
        ConnectionPolicy::default().with_attach_keys(Some(AttachKeys::new([public(&listed)])));
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (ca, tls) = issued();
    let ws = start("ws", &[Bind::Ws(any)], policy.clone());
    let wss = start("wss", &[Bind::Wss(any, tls)], policy);
    let endpoints = [
        (
            format!("ws://127.0.0.1:{}", ws.ws_addr().unwrap().port()),
            "k-ws",
        ),
        (
            format!("wss://localhost:{}", wss.ws_addr().unwrap().port()),
            "k-wss",
        ),
    ];
    for (url, name) in &endpoints {
        let options = MeshOptions::default()
            .with_endpoint(Endpoint::Ws(url.clone()))
            .with_tls_root_pem(ca.clone());
        let mesh = Mesh::attach_with(name, options.clone().with_identity(listed.clone()))
            .unwrap_or_else(|e| panic!("{url}: a listed key attaches: {e}"));
        assert_eq!(
            own_origin(&mesh),
            attach::keyed_node_id(name, &public(&listed)),
            "{url}"
        );
        mesh.detach().expect("detach");

        match Mesh::attach_with("keyless", options.clone()) {
            Err(DevError::AuthFailed { message }) => {
                assert!(message.contains("--attach-keys"), "{url}: {message}")
            }
            other => panic!("{url}: a keyless attach: {:?}", other.err()),
        }
        match Mesh::attach_with("stranger", options.with_identity(key(2))) {
            Err(DevError::AuthFailed { message }) => {
                assert!(
                    message.contains("not one this daemon allows"),
                    "{url}: {message}"
                )
            }
            other => panic!("{url}: an unlisted key: {:?}", other.err()),
        }
    }
}

/// Without a list, any key proven at attach names its connection, and an
/// attach without a key is named by its name as before; on the Unix socket
/// under a list, the owner attaches without a key unless the policy asks for
/// one there too.
#[test]
fn without_a_list_any_proven_key_names_the_connection_and_the_socket_admits_its_owner() {
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let open = start("open", &[Bind::Ws(any)], ConnectionPolicy::default());
    let url = format!("ws://127.0.0.1:{}", open.ws_addr().unwrap().port());
    let options = MeshOptions::default().with_endpoint(Endpoint::Ws(url));
    let keyed = Mesh::attach_with("any-key", options.clone().with_identity(key(3))).unwrap();
    assert_eq!(
        own_origin(&keyed),
        attach::keyed_node_id("any-key", &public(&key(3)))
    );
    let named = Mesh::attach_with("by-name", options).unwrap();
    let origin = own_origin(&named);
    let (name, digits) = origin.rsplit_once('@').unwrap();
    assert_eq!((name, digits.len()), ("by-name", 8), "{origin}");
    keyed.detach().unwrap();
    named.detach().unwrap();

    let listed = key(4);
    let keys = Some(AttachKeys::new([public(&listed)]));
    for strict in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "ak-uds-{}-{strict}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let policy = ConnectionPolicy::default()
            .with_attach_keys(keys.clone())
            .with_attach_keys_uds(strict);
        let tag = if strict { "uds-s" } else { "uds" };
        let _mesh = start(tag, &[Bind::Uds(path.clone())], policy);
        let options =
            MeshOptions::default().with_endpoint(Endpoint::Uds(path.display().to_string()));
        let keyless = Mesh::attach_with("owner", options.clone());
        if strict {
            assert!(
                matches!(keyless, Err(DevError::AuthFailed { .. })),
                "{:?}",
                keyless.err()
            );
        } else {
            keyless
                .expect("the owner attaches without a key")
                .detach()
                .unwrap();
        }
        let mesh = Mesh::attach_with("owner-key", options.clone().with_identity(listed.clone()))
            .expect("a listed key attaches on the socket");
        assert_eq!(
            own_origin(&mesh),
            attach::keyed_node_id("owner-key", &public(&listed))
        );
        mesh.detach().unwrap();
        assert!(matches!(
            Mesh::attach_with("owner-other", options.with_identity(key(5))),
            Err(DevError::AuthFailed { .. })
        ));
    }
}

/// A key file the client makes reads back and attaches; one its group or
/// others may read is refused before anything connects.
#[test]
fn key_files_are_their_owners_alone() {
    let dir = std::env::temp_dir().join(format!("ak-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("client.key");
    let _ = std::fs::remove_file(&path);
    let made = generate_key_file(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");

    let policy = ConnectionPolicy::default().with_attach_keys(Some(
        AttachKeys::parse(&format!("{}\n", public_key_text(&made))).unwrap(),
    ));
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let daemon = start("file", &[Bind::Ws(any)], policy);
    let url = format!("ws://127.0.0.1:{}", daemon.ws_addr().unwrap().port());
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(url))
        .with_identity_file(&path)
        .expect("the key file reads");
    let mesh = Mesh::attach_with("from-file", options).expect("the file's key is listed");
    assert_eq!(
        own_origin(&mesh),
        attach::keyed_node_id("from-file", &public(&made))
    );
    mesh.detach().unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    match MeshOptions::default().with_identity_file(&path) {
        Err(DevError::KeyFile { reason, .. }) => assert!(reason.contains("chmod 600"), "{reason}"),
        other => panic!("{:?}", other.err()),
    }
    assert!(read_key_file(&dir.join("absent.key")).is_err());
    std::fs::remove_file(&path).unwrap();
    let _ = std::fs::remove_dir(&dir);
}
