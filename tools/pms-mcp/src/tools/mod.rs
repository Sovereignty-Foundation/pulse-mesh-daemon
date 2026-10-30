// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! MCP tool registration + dispatch.

use serde::Serialize;
use serde_json::Value;

pub(crate) mod codec;
pub(crate) mod daemon;
pub(crate) mod modules;
pub(crate) mod probe;
pub(crate) mod ring;

/// Tool descriptor as returned by `tools/list`.
#[derive(Debug, Serialize, Clone)]
pub(crate) struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Typed tool handler.
type Handler = fn(&Value) -> anyhow::Result<Value>;

// ── Shared arg-parsing helpers ───────────────────────────────────────
//
// Tool handlers all parse `args: &Value` the same way: pull a key,
// ensure it's of the right type, error out with a uniform
// "{ctx}: missing '{key}'" message when absent. The helpers below
// concentrate the pattern so each call site stays one-liner-shaped.

/// Pull a required string from `args[key]`. Returns a borrowed `&str`
/// tied to `args`'s lifetime. The `ctx` prefix appears in the error
/// message; conventionally it's the tool name (`"mesh_send"`) but for
/// nested contexts (e.g. `aggregate=time_bucket`) any descriptive
/// label works.
pub(crate) fn required_str<'a>(args: &'a Value, key: &str, ctx: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("{ctx}: missing '{key}'"))
}

/// Pull a required `u64` from `args[key]`. Same conventions as
/// [`required_str`].
pub(crate) fn required_u64(args: &Value, key: &str, ctx: &str) -> anyhow::Result<u64> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("{ctx}: missing '{key}'"))
}

/// Registry pairing tool descriptors with their handlers.
pub(crate) struct ToolRegistry {
    entries: Vec<(ToolSpec, Handler)>,
}

impl ToolRegistry {
    pub(crate) fn list(&self) -> Vec<ToolSpec> {
        self.entries.iter().map(|(s, _)| s.clone()).collect()
    }

    pub(crate) fn call(&self, params: &Value) -> anyhow::Result<Value> {
        let name = required_str(params, "name", "tools/call")?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        for (spec, handler) in &self.entries {
            if spec.name == name {
                return handler(&arguments);
            }
        }
        Err(anyhow::anyhow!("tools/call: unknown tool {name}"))
    }
}

/// Build the registered tool set. Probe tools are only registered when
/// `allow_probe` is true (gated on `PMS_MCP_ALLOW_PROBE=1`).
pub(crate) fn build_registry(allow_probe: bool) -> ToolRegistry {
    let mut entries: Vec<(ToolSpec, Handler)> = vec![
        (ring::spec_list_rings(), ring::call_list_rings),
        (ring::spec_ring_peek(), ring::call_ring_peek),
        (codec::spec_codec_roundtrip(), codec::call_codec_roundtrip),
        (
            codec::spec_envelope_describe(),
            codec::call_envelope_describe,
        ),
        (modules::spec_modules_list(), modules::call_modules_list),
        (
            modules::spec_modules_describe(),
            modules::call_modules_describe,
        ),
        // Daemon-driven tools
        (daemon::spec_mesh_attach(), daemon::call_mesh_attach),
        (daemon::spec_mesh_send(), daemon::call_mesh_send),
        (daemon::spec_mesh_query(), daemon::call_mesh_query),
        (daemon::spec_mesh_health(), daemon::call_mesh_health),
        (daemon::spec_mesh_replay(), daemon::call_mesh_replay),
    ];
    if allow_probe {
        entries.push((probe::spec_probe_pulse(), probe::call_probe_pulse));
        entries.push((probe::spec_reachability(), probe::call_reachability));
    }
    ToolRegistry { entries }
}
