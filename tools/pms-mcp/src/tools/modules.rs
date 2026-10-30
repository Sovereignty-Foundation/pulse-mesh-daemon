// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Module-inventory tools: `modules_list`, `modules_describe`.

use serde::Deserialize;
use serde_json::{json, Value};

use super::ToolSpec;
use dev_hub::functions::core_ops::modules::{list, Profile, MODULES};

#[derive(Debug, Deserialize)]
struct ListArgs {
    #[serde(default)]
    profile: Option<String>,
}

pub(crate) fn spec_modules_list() -> ToolSpec {
    ToolSpec {
        name: "modules_list",
        description: "List the M01..M12 optimization modules, optionally filtered to one developer profile (hft / ai / robotics / telemetry / dev). Each entry includes its M-id, crate name, one-line summary, and the profiles it is recommended for.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "enum": ["hft", "ai", "robotics", "telemetry", "dev"],
                    "description": "Optional profile filter."
                }
            }
        }),
    }
}

pub(crate) fn call_modules_list(args: &Value) -> anyhow::Result<Value> {
    let parsed: ListArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let filter = match parsed.profile.as_deref() {
        None => None,
        Some(s) => match Profile::parse(s) {
            Some(p) => Some(p),
            None => {
                anyhow::bail!("unknown profile {s:?} — try hft, ai, robotics, telemetry, or dev")
            }
        },
    };
    let modules = list(filter);
    Ok(json!({
        "profile": parsed.profile,
        "modules": modules,
    }))
}

#[derive(Debug, Deserialize)]
struct DescribeArgs {
    /// M-id, e.g. `"M04"`.
    id: String,
}

pub(crate) fn spec_modules_describe() -> ToolSpec {
    ToolSpec {
        name: "modules_describe",
        description: "Describe one M01..M12 optimization module by its M-id: the crate or module that implements it, its one-line summary, and the developer profiles it is recommended for. The implementing crate's rustdoc carries the full documentation.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "pattern": "^M[0-9]{2}$", "description": "Module id like 'M04'." }
            },
            "required": ["id"]
        }),
    }
}

pub(crate) fn call_modules_describe(args: &Value) -> anyhow::Result<Value> {
    let parsed: DescribeArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let info = MODULES
        .iter()
        .find(|m| m.id == parsed.id)
        .ok_or_else(|| anyhow::anyhow!("unknown module id {:?}", parsed.id))?;
    Ok(serde_json::to_value(info)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn describe_answers_from_the_module_table() {
        let first = &MODULES[0];
        let v = call_modules_describe(&json!({ "id": first.id })).unwrap();
        assert_eq!(v["id"], first.id);
        assert_eq!(v["crate_name"], first.crate_name);
        assert_eq!(v["summary"], first.summary);
        assert!(v["profiles"].is_array());
    }

    #[test]
    fn describe_refuses_an_unknown_id() {
        assert!(call_modules_describe(&json!({ "id": "M99" })).is_err());
    }
}
