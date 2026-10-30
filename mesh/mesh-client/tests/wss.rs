// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The client over `wss://` against an in-process daemon serving TLS 1.3
//! (`Bind::Wss`): it attaches and round-trips an event when it trusts the
//! daemon's CA, refuses a daemon it does not trust or that names another
//! host, finds the daemon through `PMS_DAEMON`, and a `ws://` client of the
//! TLS listener fails without hurting it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mesh_client::{DevError, Endpoint, Mesh, MeshOptions};
use mesh_hub::embed::{Bind, EmbeddedMesh, HubConfig};
use mesh_hub::{ConnectionPolicy, WsTls};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use std::sync::mpsc;
use std::time::Duration;

/// A hub name unique to this process and short enough for every SHM name
/// derived from it.
fn hub(tag: &str) -> String {
    format!("ws-{tag}-{:04x}", std::process::id() & 0xffff)
}

/// A CA, as PEM, and the daemon's TLS: a certificate it issued for `names`.
fn issued_for(names: &[&str]) -> (String, WsTls) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let cert = CertificateParams::new(names)
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let tls = WsTls::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    (ca.pem(), tls)
}

/// [`issued_for`] `localhost` and `127.0.0.1`.
fn issued() -> (String, WsTls) {
    issued_for(&["localhost", "127.0.0.1"])
}

/// A daemon serving `wss://` on a loopback port of its own with a
/// certificate for `names`, and its CA.
fn wss_daemon_for(tag: &str, names: &[&str]) -> (EmbeddedMesh, String) {
    let (ca, tls) = issued_for(names);
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let daemon = EmbeddedMesh::start_with_config(
        &hub(tag),
        &[Bind::Wss(any, tls)],
        ConnectionPolicy::default(),
        HubConfig::default().with_store_slots(16),
    )
    .expect("daemon");
    (daemon, ca)
}

/// [`wss_daemon_for`] `localhost` and `127.0.0.1`.
fn wss_daemon(tag: &str) -> (EmbeddedMesh, String) {
    wss_daemon_for(tag, &["localhost", "127.0.0.1"])
}

fn wss_url(daemon: &EmbeddedMesh, host: &str) -> String {
    let port = daemon.ws_addr().expect("a websocket address").port();
    format!("wss://{host}:{port}")
}

/// Two clients that trust the daemon's CA attach over TLS, and an event one
/// sends reaches the other's subscription.
#[test]
fn a_client_trusting_the_ca_attaches_and_round_trips_an_event() {
    let (daemon, ca) = wss_daemon("rt");
    assert!(matches!(daemon.binds(), [Bind::Wss(..)]));
    assert!(daemon.binds()[0]
        .to_string()
        .starts_with("wss://127.0.0.1:"));
    for host in ["localhost", "127.0.0.1"] {
        let options = MeshOptions::default()
            .with_endpoint(Endpoint::Ws(wss_url(&daemon, host)))
            .with_tls_root_pem(ca.clone());
        let a = Mesh::attach_with("wss-a", options.clone()).expect("attach a over wss");
        let b = Mesh::attach_with("wss-b", options).expect("attach b over wss");
        let (tx, rx) = mpsc::channel();
        a.on("jobs", move |ev| {
            let _ = tx.send(ev.payload);
        })
        .expect("subscribe");
        b.send("jobs", b"over tls").expect("send");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).expect("event"),
            b"over tls"
        );
        a.detach().expect("detach a");
        b.detach().expect("detach b");
    }
}

/// Without the CA, the daemon's certificate chains to nothing the client
/// trusts, and the attach fails with `DevError::Tls`; a CA of another
/// daemon's does not help, nor does a host the certificate does not name.
#[test]
fn a_daemon_the_client_does_not_trust_is_refused() {
    let (daemon, ca) = wss_daemon("trust");
    let (other_ca, _) = issued();
    for options in [
        MeshOptions::default(),
        MeshOptions::default().with_tls_root_pem(other_ca),
    ] {
        let options = options.with_endpoint(Endpoint::Ws(wss_url(&daemon, "localhost")));
        match Mesh::attach_with("wss-no", options) {
            Err(DevError::Tls(why)) => assert!(why.contains("certificate"), "{why}"),
            Err(e) => panic!("refused, but not for TLS: {e:?}"),
            Ok(_) => panic!("attached to a daemon it does not trust"),
        }
    }
    // A certificate for `localhost` alone does not name 127.0.0.1.
    let (named, named_ca) = wss_daemon_for("named", &["localhost"]);
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(wss_url(&named, "127.0.0.1")))
        .with_tls_root_pem(named_ca);
    match Mesh::attach_with("wss-name", options) {
        Err(DevError::Tls(why)) => assert!(why.contains("not valid for name"), "{why}"),
        other => panic!("a certificate for another name: {:?}", other.err()),
    }
    // A root that is not a certificate fails the attach as TLS's.
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(wss_url(&daemon, "localhost")))
        .with_tls_root_pem("not a certificate");
    assert!(matches!(
        Mesh::attach_with("wss-pem", options),
        Err(DevError::Tls(_))
    ));
    // The daemon still serves a client that trusts it.
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(wss_url(&daemon, "localhost")))
        .with_tls_root_pem(ca);
    Mesh::attach_with("wss-yes", options)
        .expect("attach after the refusals")
        .detach()
        .expect("detach");
}

/// A `ws://` client of the TLS listener fails its handshake, and so does a
/// `wss://` client of a plaintext one; neither daemon is hurt.
#[test]
fn plaintext_and_tls_do_not_meet() {
    let (daemon, ca) = wss_daemon("plain");
    let port = daemon.ws_addr().unwrap().port();
    let plain = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(format!("ws://127.0.0.1:{port}")))
        .with_rpc_timeout(Duration::from_secs(5));
    assert!(Mesh::attach_with("ws-at-wss", plain).is_err());
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(wss_url(&daemon, "localhost")))
        .with_tls_root_pem(ca.clone());
    Mesh::attach_with("wss-after", options)
        .expect("the TLS listener still serves")
        .detach()
        .expect("detach");

    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let plaintext = EmbeddedMesh::start_with_config(
        &hub("ws"),
        &[Bind::Ws(any)],
        ConnectionPolicy::default(),
        HubConfig::default().with_store_slots(16),
    )
    .expect("daemon");
    let port = plaintext.ws_addr().unwrap().port();
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(format!("wss://localhost:{port}")))
        .with_tls_root_pem(ca);
    let refused = Mesh::attach_with("wss-at-ws", options);
    assert!(
        matches!(refused, Err(DevError::Tls(_))),
        "{:?}",
        refused.err()
    );
    let options =
        MeshOptions::default().with_endpoint(Endpoint::Ws(format!("ws://127.0.0.1:{port}")));
    Mesh::attach_with("ws-after", options)
        .expect("the plaintext listener still serves")
        .detach()
        .expect("detach");
}

/// `PMS_DAEMON=wss://...` is found by discovery, and the options' roots
/// apply to it. The only test here that reads the variable.
#[test]
fn pms_daemon_names_a_wss_endpoint() {
    let (daemon, ca) = wss_daemon("env");
    std::env::set_var("PMS_DAEMON", wss_url(&daemon, "localhost"));
    let attached = Mesh::attach_with("wss-env", MeshOptions::default().with_tls_root_pem(ca));
    let untrusted = Mesh::attach_with("wss-env-no", MeshOptions::default());
    std::env::remove_var("PMS_DAEMON");
    attached
        .expect("attach through PMS_DAEMON")
        .detach()
        .expect("detach");
    assert!(matches!(untrusted, Err(DevError::Tls(_))));
}

/// At its connection cap the TLS listener still answers 503, inside TLS, so
/// the client is told why rather than seeing a broken handshake.
#[test]
fn the_tls_listener_refuses_past_its_cap_with_a_503() {
    let (ca, tls) = issued();
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let daemon = EmbeddedMesh::start_with_config(
        &hub("cap"),
        &[Bind::Wss(any, tls)],
        ConnectionPolicy::default().with_max_connections(1),
        HubConfig::default().with_store_slots(16),
    )
    .expect("daemon");
    let options = MeshOptions::default()
        .with_endpoint(Endpoint::Ws(wss_url(&daemon, "localhost")))
        .with_tls_root_pem(ca);
    let first = Mesh::attach_with("cap-a", options.clone()).expect("the first attaches");
    match Mesh::attach_with("cap-b", options) {
        Err(DevError::Transport(why)) => assert!(why.contains("503"), "{why}"),
        other => panic!("past the cap: {:?}", other.err()),
    }
    assert_eq!(daemon.connections_refused(), 1);
    first.detach().expect("detach");
}
