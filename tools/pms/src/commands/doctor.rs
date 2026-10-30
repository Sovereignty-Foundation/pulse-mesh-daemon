// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms doctor` — toolchain + runtime preconditions check.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Severity {
    fn tag(self) -> &'static str {
        match self {
            Self::Ok => "OK   ",
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
            Self::Fail => "FAIL ",
        }
    }
}

struct CheckResult {
    name: &'static str,
    severity: Severity,
    detail: String,
}

/// Run the doctor checks. Returns exit code = number of FAILs.
///
/// # Errors
/// Currently infallible — all checks degrade to a FAIL row rather than
/// propagating. The `anyhow::Result` shape is reserved for future checks
/// that may need to surface I/O failures distinctly.
pub(crate) fn run(profile_filter: Option<&str>) -> anyhow::Result<ExitCode> {
    let mut results = vec![
        check_rust_toolchain(),
        check_cargo_target_writable(),
        check_codec_parity(),
        check_python_version(),
        check_node_version(),
        check_shm_writable(),
    ];

    if let Some(profile) = profile_filter {
        results.push(check_profile_requirements(profile));
    }

    println!("pms doctor — Pulse Mesh Standard toolchain check");
    println!("-----------------------------------------------");
    let mut fails = 0u8;
    for r in &results {
        if r.severity == Severity::Fail {
            fails = fails.saturating_add(1);
        }
        println!("[{}] {:<20}  {}", r.severity.tag(), r.name, r.detail);
    }
    println!("-----------------------------------------------");
    if fails == 0 {
        println!("ready. try: pms send 127.0.0.1:9000 --count 5");
    } else {
        println!("{fails} blocker(s) need fixing before pms can run.");
    }
    Ok(ExitCode::from(fails))
}

/// A toolchain pin: the file that names it and the channel it names.
struct Pin {
    file: PathBuf,
    channel: String,
}

/// The toolchain pin that applies in the current directory, found as rustup
/// finds it: the nearest `rust-toolchain` or `rust-toolchain.toml` in the
/// directory or an ancestor. Inside the workspace that is its
/// `rust-toolchain.toml`; outside a workspace there is normally none.
fn toolchain_pin() -> Option<Pin> {
    let cwd = std::env::current_dir().ok()?;
    cwd.ancestors().find_map(|dir| {
        ["rust-toolchain", "rust-toolchain.toml"]
            .iter()
            .map(|name| dir.join(name))
            .find_map(|file| {
                let text = std::fs::read_to_string(&file).ok()?;
                let channel = pinned_channel(&text)?;
                Some(Pin { file, channel })
            })
    })
}

/// The channel a toolchain file names: the `channel` key of its TOML form,
/// or the whole of the legacy one-line form.
fn pinned_channel(text: &str) -> Option<String> {
    let keyed = text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|quoted| quoted.split('"').next())
            .unwrap_or(value);
        (key.trim() == "channel").then(|| value.to_string())
    });
    let legacy = || {
        let line = text.trim();
        (!line.is_empty() && !line.contains(['=', '[', '\n'])).then(|| line.to_string())
    };
    keyed.or_else(legacy).filter(|c| !c.is_empty())
}

/// Whether `rustc -V` output is the pinned `channel`, or `None` when the
/// channel is a name (`stable`, `nightly-…`) rather than a version, which
/// only rustup can resolve.
fn matches_pin(rustc_version: &str, channel: &str) -> Option<bool> {
    if !channel.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let found = rustc_version.split_whitespace().nth(1).unwrap_or_default();
    Some(found == channel || found.starts_with(&format!("{channel}.")))
}

/// The toolchain row. Only a toolchain file pins a version, so only where
/// one applies (the workspace) is a different `rustc` a failure; elsewhere
/// the row reports the `rustc` on `PATH` and fails nothing.
fn check_rust_toolchain() -> CheckResult {
    let rustc = Command::new("rustc")
        .arg("-V")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());
    let (severity, detail) = match (toolchain_pin(), rustc) {
        (None, Some(found)) => (
            Severity::Info,
            format!("{found} (no rust-toolchain file pins a version here)"),
        ),
        (None, None) => (
            Severity::Info,
            "rustc not on PATH (needed only to build from source)".to_string(),
        ),
        (Some(_), None) => (Severity::Fail, "rustc not found on PATH".to_string()),
        (Some(pin), Some(found)) => match matches_pin(&found, &pin.channel) {
            Some(true) => (Severity::Ok, found),
            Some(false) => (
                Severity::Fail,
                format!(
                    "{} pins {}, found: {found}",
                    pin.file.display(),
                    pin.channel
                ),
            ),
            None => (
                Severity::Info,
                format!(
                    "{found} ({} selects the {} channel)",
                    pin.file.display(),
                    pin.channel
                ),
            ),
        },
    };
    CheckResult {
        name: "rust-toolchain",
        severity,
        detail,
    }
}

/// The root of the Cargo workspace the current directory is inside, if any:
/// the nearest ancestor whose `Cargo.toml` has a `[workspace]` table.
fn workspace_root() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(dir);
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn check_cargo_target_writable() -> CheckResult {
    // Outside a workspace there is no target directory to probe, and probing
    // one would create a stray `target/` wherever `pms` happens to run.
    let target_dir = match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) => dir,
        Err(_) => match workspace_root() {
            Some(root) => root.join("target").to_string_lossy().into_owned(),
            None => {
                return CheckResult {
                    name: "cargo-target",
                    severity: Severity::Info,
                    detail: "not inside a Cargo workspace; nothing to probe".to_string(),
                }
            }
        },
    };
    let probe = std::path::Path::new(&target_dir).join(".pms-doctor-probe");
    if let Some(parent) = probe.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            CheckResult {
                name: "cargo-target",
                severity: Severity::Ok,
                detail: format!("{target_dir} is writable"),
            }
        }
        Err(e) => CheckResult {
            name: "cargo-target",
            severity: Severity::Fail,
            detail: format!("{target_dir}: {e}"),
        },
    }
}

fn check_codec_parity() -> CheckResult {
    let env = pulse_cli::ops::version::test_vector();
    match pulse_cli::ops::codec::roundtrip(&env) {
        Ok(r) if r.decoded_equal => {
            let stamp = pulse_cli::ops::version::info();
            CheckResult {
                name: "codec-parity",
                severity: Severity::Ok,
                detail: format!(
                    "canonical test vector {} B, BLAKE3-16 {}",
                    r.size, stamp.codec_test_vector_hash
                ),
            }
        }
        Ok(_) => CheckResult {
            name: "codec-parity",
            severity: Severity::Fail,
            detail: "canonical decode produced a different envelope (codec drift)".into(),
        },
        Err(e) => CheckResult {
            name: "codec-parity",
            severity: Severity::Fail,
            detail: format!("codec roundtrip errored: {e}"),
        },
    }
}

fn check_python_version() -> CheckResult {
    match Command::new("python3").arg("-V").output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            CheckResult {
                name: "python-version",
                severity: Severity::Info,
                detail: format!("{stdout} (only needed for pulse-wire-py)"),
            }
        }
        _ => CheckResult {
            name: "python-version",
            severity: Severity::Warn,
            detail: "python3 not on PATH — pulse-wire-py binding will not build".into(),
        },
    }
}

fn check_node_version() -> CheckResult {
    match Command::new("node").arg("-v").output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            CheckResult {
                name: "node-version",
                severity: Severity::Info,
                detail: format!("{stdout} (only needed for pulse-wire-node)"),
            }
        }
        _ => CheckResult {
            name: "node-version",
            severity: Severity::Warn,
            detail: "node not on PATH — pulse-wire-node binding will not build".into(),
        },
    }
}

fn check_shm_writable() -> CheckResult {
    let candidate = if std::path::Path::new("/dev/shm").exists() {
        "/dev/shm"
    } else {
        "/tmp"
    };
    let probe = std::path::Path::new(candidate).join(".pms-doctor-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            CheckResult {
                name: "shm-tmpfs",
                severity: Severity::Ok,
                detail: format!("{candidate} writable"),
            }
        }
        Err(e) => CheckResult {
            name: "shm-tmpfs",
            severity: Severity::Warn,
            detail: format!("{candidate}: {e}"),
        },
    }
}

fn check_profile_requirements(profile: &str) -> CheckResult {
    use dev_hub::functions::core_ops::modules::{list, Profile};
    let parsed = Profile::parse(profile);
    match parsed {
        Some(p) => {
            let mods = list(Some(p));
            let names: Vec<&str> = mods.iter().map(|m| m.id).collect();
            CheckResult {
                name: "profile",
                severity: Severity::Info,
                detail: format!("profile {profile}: enable modules {}", names.join(", ")),
            }
        }
        None => CheckResult {
            name: "profile",
            severity: Severity::Warn,
            detail: format!("unknown profile {profile} (try: hft, ai, robotics, telemetry, dev)"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_toolchain_file_names_its_channel_in_either_form() {
        let toml = "[toolchain]\nchannel = \"1.95.0\" # the pin\nprofile = \"minimal\"\n";
        assert_eq!(pinned_channel(toml).as_deref(), Some("1.95.0"));
        assert_eq!(pinned_channel("1.95.0\n").as_deref(), Some("1.95.0"));
        assert_eq!(pinned_channel("[toolchain]\nprofile = \"minimal\"\n"), None);
        assert_eq!(pinned_channel(""), None);
    }

    #[test]
    fn rustc_matches_a_version_pin_and_leaves_a_named_channel_to_rustup() {
        let rustc = "rustc 1.95.0 (59807616e 2026-04-14)";
        assert_eq!(matches_pin(rustc, "1.95.0"), Some(true));
        assert_eq!(matches_pin(rustc, "1.95"), Some(true));
        assert_eq!(matches_pin(rustc, "1.9"), Some(false));
        assert_eq!(
            matches_pin("rustc 1.98.0 (88d9e12ae 2026-08-18)", "1.95.0"),
            Some(false)
        );
        assert_eq!(matches_pin(rustc, "stable"), None);
    }
}
