// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms modules ls` — module inventory.

use std::process::ExitCode;

use dev_hub::functions::core_ops::modules::{list, Profile};

/// Implementation of `pms modules ls`.
///
/// # Errors
/// Currently infallible. Returns `anyhow::Result` for forward compatibility.
pub(crate) fn run_ls(profile: Option<&str>, json: bool) -> anyhow::Result<ExitCode> {
    let filter = profile.and_then(Profile::parse);
    if let Some(p) = profile {
        if filter.is_none() {
            eprintln!("pms: unknown profile {p:?}. Try: hft, ai, robotics, telemetry, dev.");
            return Ok(ExitCode::from(1));
        }
    }
    let modules = list(filter);
    if json {
        println!("{}", serde_json::to_string_pretty(&modules)?);
    } else {
        let header = match filter {
            None => "All twelve modules:".to_string(),
            Some(p) => format!("Modules to enable for profile {p:?}:"),
        };
        println!("{header}");
        for m in &modules {
            println!("  {}  {:<22}  {}", m.id, m.crate_name, m.summary);
        }
    }
    Ok(ExitCode::SUCCESS)
}
