// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Ring-introspection tools: `mesh_list_rings`, `mesh_ring_peek`.

use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};

use super::ToolSpec;

pub(crate) fn spec_list_rings() -> ToolSpec {
    ToolSpec {
        name: "mesh_list_rings",
        description: "Enumerate POSIX SHM regions that look like Pulse Mesh rings. On Linux this scans /dev/shm/pms-*; on macOS POSIX shared-memory names are not enumerable via the filesystem, so this returns an empty list with a `note` field rather than failing.",
        input_schema: json!({
            "type": "object",
            "properties": {}
        }),
    }
}

pub(crate) fn call_list_rings(_args: &Value) -> anyhow::Result<Value> {
    let dev_shm = Path::new("/dev/shm");
    if !dev_shm.exists() {
        return Ok(json!({
            "rings": [],
            "note": "/dev/shm not present (likely macOS) — POSIX SHM names are not enumerable via the filesystem on this platform. Pass an explicit ring name to mesh_ring_peek.",
        }));
    }
    let mut rings = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(dev_shm) {
        for entry in read_dir.flatten() {
            let fname = entry.file_name();
            let s = fname.to_string_lossy();
            if s.starts_with("pms-") {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                rings.push(json!({
                    "name": format!("/{}", s),
                    "size_bytes": size,
                }));
            }
        }
    }
    Ok(json!({ "rings": rings }))
}

#[derive(Debug, Deserialize)]
struct PeekArgs {
    ring_name: String,
    #[serde(default = "default_count")]
    count: usize,
}

fn default_count() -> usize {
    8
}

pub(crate) fn spec_ring_peek() -> ToolSpec {
    ToolSpec {
        name: "mesh_ring_peek",
        description: "Read-only snapshot of an existing SHM-backed PulseRing. Returns capacity, write_count, cursor, and the most-recent N slot summaries. Give a hub name (e.g. default_hub) for the daemon's ring or a raw POSIX SHM name starting with /; the ring's header records its capacity and slot size, so none is passed. The reader attaches as a secondary reader — it does not advance the primary cursor.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "ring_name": { "type": "string", "description": "Hub name (e.g. default_hub) or a raw POSIX SHM name starting with /." },
                "count": { "type": "integer", "description": "Max number of recent slots to summarize.", "default": 8 }
            },
            "required": ["ring_name"]
        }),
    }
}

pub(crate) fn call_ring_peek(args: &Value) -> anyhow::Result<Value> {
    let parsed: PeekArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let shm_name = dev_hub::functions::core_ops::ring::resolve_ring_name(&parsed.ring_name)?;
    let peek = dev_hub::functions::core_ops::ring::ring_peek(&shm_name, parsed.count)?;
    Ok(serde_json::to_value(peek)?)
}
