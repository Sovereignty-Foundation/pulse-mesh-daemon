// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The table of the twelve optimization modules, M01 to M12, behind
//! `pms modules ls` and the MCP `modules_list` tool.
//!
//! It is static because the profile tags live in no manifest. A test below
//! checks every entry against the workspace, and `scripts/arch-check.py`
//! checks the table against the hubs' manifests.

use serde::Serialize;

/// Descriptive metadata for one workspace module.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    /// M-prefixed identifier (e.g. "M01"). Stable; do not renumber.
    pub id: &'static str,
    /// A workspace crate, or `crate::module` for a module inside a ring layer.
    pub crate_name: &'static str,
    /// Short, public-safe one-liner.
    pub summary: &'static str,
    /// Profile tags this module is "always enable" for.
    pub profiles: &'static [Profile],
}

/// Developer-intent profile used to filter modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Profile {
    /// High-frequency trading: lowest latency on a single host, conflated quotes.
    Hft,
    /// AI inference orchestration: many readers, large envelopes.
    Ai,
    /// Robotics: deterministic, telemetry-aware.
    Robotics,
    /// Telemetry-heavy workloads.
    Telemetry,
    /// Single-host development and experimentation.
    Dev,
}

impl Profile {
    /// Parse a profile from CLI input.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hft" => Some(Self::Hft),
            "ai" | "inference" => Some(Self::Ai),
            "robotics" => Some(Self::Robotics),
            "telemetry" => Some(Self::Telemetry),
            "dev" => Some(Self::Dev),
            _ => None,
        }
    }
}

/// The twelve modules, in id order.
pub const MODULES: &[ModuleInfo] = &[
    ModuleInfo {
        id: "M01",
        crate_name: "hft_stages::numa",
        summary: "Hugepages + NUMA-aware ring placement",
        profiles: &[Profile::Hft, Profile::Ai],
    },
    ModuleInfo {
        id: "M02",
        crate_name: "dev_stages::conflation",
        summary: "Symbol-keyed last-write-wins router for quote-style traffic",
        profiles: &[Profile::Hft],
    },
    ModuleInfo {
        id: "M03",
        crate_name: "hft_functions::wait",
        summary: "UMWAIT / Park / BusySpin + smart poll_hint",
        profiles: &[Profile::Hft, Profile::Robotics],
    },
    ModuleInfo {
        id: "M04",
        crate_name: "hft_stages::spmc",
        summary: "Lock-free SPMC ring (1 publisher, N readers)",
        profiles: &[Profile::Hft, Profile::Ai, Profile::Robotics, Profile::Dev],
    },
    ModuleInfo {
        id: "M05",
        crate_name: "robotics_stages::net_uring",
        summary: "io_uring batched send/recv for cross-host fan-out",
        profiles: &[Profile::Ai, Profile::Telemetry],
    },
    ModuleInfo {
        id: "M06",
        crate_name: "robotics_stages::large_payload",
        summary: "Tier-2 envelope LRU + NACK backfill",
        profiles: &[Profile::Ai],
    },
    ModuleInfo {
        id: "M07",
        crate_name: "robotics_stages::autoscale",
        summary: "LagObserver + swap-ring protocol",
        profiles: &[Profile::Telemetry, Profile::Ai],
    },
    ModuleInfo {
        id: "M08",
        crate_name: "pms-telemetry-export",
        summary: "Prometheus exporter",
        profiles: &[Profile::Telemetry, Profile::Robotics],
    },
    ModuleInfo {
        id: "M09",
        crate_name: "hft_core::prefetch",
        summary: "Adaptive cache-line prefetch",
        profiles: &[Profile::Hft],
    },
    ModuleInfo {
        id: "M10",
        crate_name: "pms-crc32c",
        summary: "CRC32C trailer integrity",
        profiles: &[Profile::Robotics, Profile::Telemetry],
    },
    ModuleInfo {
        id: "M11",
        crate_name: "hft_core::wire_v2",
        summary: "Wire format v2 (separate data-ready line)",
        profiles: &[Profile::Hft],
    },
    ModuleInfo {
        id: "M12",
        crate_name: "mesh-broadcast",
        summary: "In-process listener fan-out",
        profiles: &[Profile::Ai, Profile::Robotics],
    },
];

/// Return all modules, optionally filtered by profile.
pub fn list(filter: Option<Profile>) -> Vec<&'static ModuleInfo> {
    match filter {
        None => MODULES.iter().collect(),
        Some(p) => MODULES.iter().filter(|m| m.profiles.contains(&p)).collect(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// Every package cargo knows from this crate's workspace, by name, with
    /// its directory: the members, and the crates they depend on by path
    /// (the standard's, when the ring is built in the daemon's own
    /// repository), so the table resolves wherever the ring is built.
    fn workspace_packages() -> HashMap<String, PathBuf> {
        let out = std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let packages: HashMap<String, PathBuf> = meta["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let dir = Path::new(p["manifest_path"].as_str().unwrap())
                    .parent()
                    .unwrap()
                    .to_path_buf();
                (p["name"].as_str().unwrap().to_string(), dir)
            })
            .collect();
        assert!(
            packages.len() > 20,
            "cargo metadata listed {} packages",
            packages.len()
        );
        packages
    }

    #[test]
    fn every_module_points_at_a_workspace_crate_or_module() {
        let packages = workspace_packages();
        let ids: Vec<&str> = MODULES.iter().map(|m| m.id).collect();
        for m in MODULES {
            // A crate cargo metadata does not know from here is another
            // repository's to hold (the profiles' rings, when this ring is
            // built in the daemon's own repository); its module is checked
            // where it is.
            if let Some((krate, module)) = m.crate_name.split_once("::") {
                let Some(dir) = packages.get(&krate.replace('_', "-")) else {
                    continue;
                };
                let src = dir.join("src");
                assert!(
                    src.join(format!("{module}.rs")).exists()
                        || src.join(module).join("mod.rs").exists(),
                    "{}: module {module} not found under {}",
                    m.id,
                    src.display()
                );
            }
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "ids must be unique and ordered");
        assert_eq!(ids.first(), Some(&"M01"));
        assert_eq!(ids.last(), Some(&"M12"));
    }
}
