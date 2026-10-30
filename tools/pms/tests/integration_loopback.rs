// SPDX-License-Identifier: LicenseRef-Proprietary
//! Integration tests for the `pms` binary.
//!
//! Exercises the binary end-to-end via `assert_cmd`. The headline
//! test is a UDP send→recv loopback against the locally-built `pms`
//! binary: the receiver is spawned in a background process, given a
//! brief moment to bind, then the sender pushes one pulse. The
//! receiver is invoked with `--json` so the output can be parsed and
//! asserted.
//!
//! Complementary tests cover deterministic, non-networked
//! subcommands (`version --json`, `modules ls --json`) to give the
//! CI a fast-failing surface that doesn't depend on a free UDP port.
//!
//! These tests are intentionally minimal — they prove the binary
//! launches, the commands wire to real behavior, and the loopback
//! path round-trips. They are not a substitute for the unit tests of
//! `dev_functions::core_ops`, which exercise the underlying logic directly.

// Integration tests assert on infallible setup steps (binary
// discovery, JSON parsing of known-shape output) where `.expect()`
// is the idiomatic failure mode. Per the workspace test convention,
// these lints are relaxed at the test-file level.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::UdpSocket;
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use assert_cmd::Command;

/// Reserve a free UDP port on loopback by binding `:0`, reading the
/// assigned port, and then closing the socket. There is a small race
/// window between drop and the next bind by the spawned `pms recv`,
/// but on loopback this is negligible in practice.
fn pick_free_udp_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe socket on loopback");
    let port = probe.local_addr().expect("read probe local_addr").port();
    drop(probe);
    port
}

#[test]
fn version_subcommand_emits_valid_json() {
    let assertion = Command::cargo_bin("pms")
        .expect("locate pms binary")
        .args(["version", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).expect("utf-8 stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("version --json emits valid JSON");
    assert!(parsed.is_object(), "version --json should emit an object");
}

#[test]
fn version_names_the_binary_and_the_package_it_is_built_from() {
    let assertion = Command::cargo_bin("pms")
        .expect("locate pms binary")
        .arg("version")
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).expect("utf-8 stdout");
    assert_eq!(
        stdout.lines().next(),
        Some(format!("pms (pms-cli)     {}", env!("CARGO_PKG_VERSION")).as_str()),
        "{stdout}"
    );
}

#[test]
fn modules_ls_emits_valid_json() {
    let assertion = Command::cargo_bin("pms")
        .expect("locate pms binary")
        .args(["modules", "ls", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).expect("utf-8 stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("modules ls --json emits valid JSON");
    let arr = parsed
        .as_array()
        .expect("modules ls --json should emit an array");
    assert!(!arr.is_empty(), "modules registry should be non-empty");
}

#[test]
fn send_recv_udp_loopback_round_trips_one_pulse() {
    let port = pick_free_udp_port();
    let addr = format!("127.0.0.1:{port}");

    // Spawn `pms recv` in the background. It is invoked with
    // `--json` so its stdout is a deterministic array of pulse
    // summaries, and `--count 1` so it exits cleanly after the
    // first delivery.
    let pms_bin = cargo_bin("pms");
    let recv_child = StdCommand::new(&pms_bin)
        .args([
            "recv",
            &addr,
            "--count",
            "1",
            "--timeout-ms",
            "5000",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pms recv");

    // Give the receiver a brief moment to bind before sending.
    thread::sleep(Duration::from_millis(250));

    // Send one pulse with a 16-byte payload.
    Command::new(&pms_bin)
        .args(["send", &addr, "--count", "1", "--payload", "16"])
        .assert()
        .success();

    // Wait for the receiver to exit and inspect its stdout.
    let output = recv_child
        .wait_with_output()
        .expect("wait for pms recv to exit");
    assert!(
        output.status.success(),
        "pms recv exited with non-zero status: {:?}",
        output.status
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 recv stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("recv --json emits valid JSON");
    let arr = parsed
        .as_array()
        .expect("recv --json should emit an array of pulse summaries");
    assert_eq!(
        arr.len(),
        1,
        "expected exactly one pulse summary, got {}",
        arr.len()
    );
    let summary = &arr[0];
    assert!(
        summary.is_object(),
        "pulse summary should be an object: {summary}"
    );
    assert!(
        summary
            .get("envelope_len")
            .and_then(|v| v.as_u64())
            .is_some(),
        "summary should report envelope_len: {summary}"
    );
}
