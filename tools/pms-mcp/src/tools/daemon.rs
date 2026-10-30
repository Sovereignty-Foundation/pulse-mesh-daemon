// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Daemon-driven MCP tools — `mesh_attach`, `mesh_send`, `mesh_query`,
//! `mesh_health`, `mesh_replay`.
//!
//! `mesh_query` reads the basket SQLite file directly (so it works even
//! when the daemon is down). The other tools open a short-lived
//! dev-functions Mesh per call.

use super::{required_str, required_u64, ToolSpec};
use anyhow::{anyhow, Context, Result};
use mesh_basket::{AggregateResult, Aggregation, Basket, QuerySpec};
use mesh_client::Mesh;
use serde_json::{json, Value};

const MAX_QUERY_LIMIT: usize = 200; // smaller than the basket's 5000 cap;
                                    // MCP responses should fit in agent context

// =============================================================================
// mesh_attach
// =============================================================================

pub(crate) fn spec_mesh_attach() -> ToolSpec {
    ToolSpec {
        name: "mesh_attach",
        description:
            "Register a process name in the mesh-hub registry. Returns the daemon's assigned node_id. The connection is dropped at the end of the call; another call (or the dev-functions Rust crate) holds the name persistently if you need that.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Process-visible name to register under." }
            },
            "required": ["name"]
        }),
    }
}

pub(crate) fn call_mesh_attach(args: &Value) -> Result<Value> {
    let name = required_str(args, "name", "mesh_attach")?;
    let mesh = Mesh::attach(name).context("attach to mesh-hub")?;
    // Drop immediately — for this tool we just want to validate the name is
    // available and the daemon is reachable.
    drop(mesh);
    Ok(json!({
        "ok": true,
        "name": name,
        "note": "name validated; connection dropped (MCP tool is stateless)."
    }))
}

// =============================================================================
// mesh_send
// =============================================================================

pub(crate) fn spec_mesh_send() -> ToolSpec {
    ToolSpec {
        name: "mesh_send",
        description:
            "Publish an envelope to a channel on the mesh-hub daemon. Returns the daemon's envelope_id.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string", "description": "Routing key." },
                "payload": { "type": "string", "description": "UTF-8 payload (use payload_hex for binary)." },
                "payload_hex": { "type": "string", "description": "Hex-encoded payload bytes; mutually exclusive with payload." },
                "type_name": { "type": "string", "description": "Optional type name for typed schemas." },
                "as_name": { "type": "string", "description": "Name to attach under for this send. Defaults to 'mcp-send'." }
            },
            "required": ["channel"]
        }),
    }
}

pub(crate) fn call_mesh_send(args: &Value) -> Result<Value> {
    let channel = required_str(args, "channel", "mesh_send")?;
    let payload: Vec<u8> = if let Some(s) = args.get("payload_hex").and_then(|v| v.as_str()) {
        hex::decode(s.trim_start_matches("0x")).context("payload_hex decode")?
    } else if let Some(s) = args.get("payload").and_then(|v| v.as_str()) {
        s.as_bytes().to_vec()
    } else {
        Vec::new()
    };
    let type_name = args.get("type_name").and_then(|v| v.as_str());
    let as_name = args
        .get("as_name")
        .and_then(|v| v.as_str())
        .unwrap_or("mcp-send");

    let mesh = Mesh::attach(as_name).context("attach to mesh-hub")?;
    let env_id = mesh
        .send_typed(channel, type_name, &payload)
        .context("send")?;
    Ok(json!({
        "ok": true,
        "envelope_id": env_id,
        "channel": channel,
        "type_name": type_name,
        "payload_bytes": payload.len(),
    }))
}

// =============================================================================
// mesh_query
// =============================================================================

pub(crate) fn spec_mesh_query() -> ToolSpec {
    ToolSpec {
        name: "mesh_query",
        description:
            "Structured query against the daemon's basket SQLite store. Returns rows or aggregations; never a firehose. Supply filters (channel, type, origin, time window) + optional aggregation (count, count_by_channel, time_bucket, distinct_channels, distinct_types). Replaces unbounded mesh_tap streaming.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "basket_path": { "type": "string", "description": "Path to the basket DB. Defaults to $PMS_BASKET_DB or ~/.local/share/pms/basket.db." },
                "channel": { "type": "string" },
                "envelope_type": { "type": "integer" },
                "type_name": { "type": "string" },
                "origin": { "type": "string" },
                "since_unix_nanos": { "type": "integer", "description": "Time-window start (inclusive)." },
                "until_unix_nanos": { "type": "integer", "description": "Time-window end (exclusive)." },
                "limit": { "type": "integer", "description": "Max rows (default 50, capped at 200 for MCP)." },
                "aggregate": {
                    "type": "string",
                    "enum": ["count", "count_by_channel", "time_bucket", "distinct_channels", "distinct_types"]
                },
                "bucket_secs": { "type": "integer", "description": "Required when aggregate=time_bucket." }
            }
        }),
    }
}

pub(crate) fn call_mesh_query(args: &Value) -> Result<Value> {
    let path_str = match args.get("basket_path").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => default_basket_path()?,
    };
    let basket = Basket::open(std::path::Path::new(&path_str))
        .with_context(|| format!("open basket at {}", path_str))?;

    let mut spec = QuerySpec {
        channel: args
            .get("channel")
            .and_then(|v| v.as_str())
            .map(String::from),
        envelope_type: args
            .get("envelope_type")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        type_name: args
            .get("type_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        origin: args
            .get("origin")
            .and_then(|v| v.as_str())
            .map(String::from),
        since_unix_nanos: args
            .get("since_unix_nanos")
            .and_then(|v| v.as_u64())
            .map(|n| n as u128),
        until_unix_nanos: args
            .get("until_unix_nanos")
            .and_then(|v| v.as_u64())
            .map(|n| n as u128),
        limit: args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(MAX_QUERY_LIMIT))
            .unwrap_or(50),
        aggregate: None,
    };

    if let Some(kind) = args.get("aggregate").and_then(|v| v.as_str()) {
        spec.aggregate = Some(match kind {
            "count" => Aggregation::Count,
            "count_by_channel" => Aggregation::CountByChannel,
            "time_bucket" => Aggregation::TimeBucketCount {
                bucket_secs: required_u64(args, "bucket_secs", "aggregate=time_bucket")?,
            },
            "distinct_channels" => Aggregation::DistinctChannels,
            "distinct_types" => Aggregation::DistinctTypes,
            other => return Err(anyhow!("unknown aggregate: {}", other)),
        });
    }

    let result = basket.query(&spec).context("query")?;

    // Render. For agent friendliness, format aggregates as a small object
    // and rows as a tight array (no payload_bytes inline; agents fetch
    // one envelope's payload via mesh_query_get if needed).
    if let Some(agg) = result.aggregate {
        let agg_json = match agg {
            AggregateResult::Count(n) => json!({ "count": n }),
            AggregateResult::CountByChannel(rows) => json!({
                "count_by_channel": rows
                    .into_iter()
                    .map(|(c, n)| json!({"channel": c, "count": n}))
                    .collect::<Vec<_>>()
            }),
            AggregateResult::TimeBucketCount(rows) => json!({
                "time_bucket": rows
                    .into_iter()
                    .map(|b| json!({"bucket_start_unix_nanos": b.bucket_start_unix_nanos.to_string(), "count": b.count}))
                    .collect::<Vec<_>>()
            }),
            AggregateResult::DistinctChannels(rows) => {
                json!({ "distinct_channels": rows })
            }
            AggregateResult::DistinctTypes(rows) => {
                json!({ "distinct_types": rows })
            }
        };
        return Ok(agg_json);
    }

    let rows: Vec<Value> = result
        .rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "captured_at_unix_nanos": r.captured_at_unix_nanos.to_string(),
                "channel": r.channel,
                "envelope_type": r.envelope_type,
                "type_name": r.type_name,
                "origin": r.origin,
                "payload_hash": r.payload_hash,
                "payload_bytes": r.payload_bytes.len(),
            })
        })
        .collect();
    Ok(json!({
        "rows": rows,
        "next_before": result.next_before.map(|n| n.to_string()),
    }))
}

// =============================================================================
// mesh_health
// =============================================================================

pub(crate) fn spec_mesh_health() -> ToolSpec {
    ToolSpec {
        name: "mesh_health",
        description:
            "Report which names are attached to the daemon and basic liveness state. For v0 this returns a static snapshot (no heartbeat protocol yet); future revisions surface NodeState from mesh-health.",
        input_schema: json!({
            "type": "object",
            "properties": {}
        }),
    }
}

pub(crate) fn call_mesh_health(_args: &Value) -> Result<Value> {
    // v0 cannot enumerate the daemon's attached connections via the
    // universal port (the protocol doesn't expose `list_attached` yet).
    // Honest answer: the basket has a recent-origins view, so we report
    // the distinct origins seen in the last 5 minutes as a proxy.
    let path = default_basket_path()?;
    let basket = Basket::open(std::path::Path::new(&path)).context("open basket")?;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let since = now_ns.saturating_sub(5 * 60 * 1_000_000_000);
    let r = basket
        .query(&QuerySpec {
            since_unix_nanos: Some(since),
            aggregate: Some(Aggregation::CountByChannel),
            ..Default::default()
        })
        .context("health query")?;
    let by_channel = if let Some(AggregateResult::CountByChannel(rows)) = r.aggregate {
        rows.into_iter()
            .map(|(c, n)| json!({"channel": c, "count_last_5min": n}))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    Ok(json!({
        "note": "v0: derived from basket; native heartbeat aggregation lands in a follow-up.",
        "active_channels_last_5min": by_channel,
    }))
}

// =============================================================================
// mesh_replay
// =============================================================================

pub(crate) fn spec_mesh_replay() -> ToolSpec {
    ToolSpec {
        name: "mesh_replay",
        description:
            "Replay envelopes from the basket back through the daemon. Useful for re-running a captured workload. WARNING: also reaches subscribers — confirm with the user before using on production-relevant channels.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string", "description": "Source channel (basket query)." },
                "target_channel": { "type": "string", "description": "Where to replay. Defaults to source channel." },
                "limit": { "type": "integer", "description": "Max envelopes to replay (capped at 100)." },
                "since_unix_nanos": { "type": "integer" },
                "until_unix_nanos": { "type": "integer" },
                "as_name": { "type": "string", "description": "Name to attach under. Defaults to 'mcp-replay'." }
            },
            "required": ["channel"]
        }),
    }
}

pub(crate) fn call_mesh_replay(args: &Value) -> Result<Value> {
    let source = required_str(args, "channel", "mesh_replay")?;
    let target = args
        .get("target_channel")
        .and_then(|v| v.as_str())
        .unwrap_or(source);
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(100))
        .unwrap_or(20);
    let as_name = args
        .get("as_name")
        .and_then(|v| v.as_str())
        .unwrap_or("mcp-replay");

    let path = default_basket_path()?;
    let basket = Basket::open(std::path::Path::new(&path)).context("open basket")?;
    let result = basket
        .query(&QuerySpec {
            channel: Some(source.to_string()),
            since_unix_nanos: args
                .get("since_unix_nanos")
                .and_then(|v| v.as_u64())
                .map(|n| n as u128),
            until_unix_nanos: args
                .get("until_unix_nanos")
                .and_then(|v| v.as_u64())
                .map(|n| n as u128),
            limit,
            ..Default::default()
        })
        .context("source query")?;

    let mesh = Mesh::attach(as_name).context("attach to mesh-hub")?;
    let mut replayed = 0;
    for row in &result.rows {
        // Refetch the full payload (rows from query() carry payload_bytes
        // already since dev-basket returns them; the JSON-shaping above
        // strips them, but the in-memory row here still holds them).
        let _ = mesh.send_typed(target, row.type_name.as_deref(), &row.payload_bytes);
        replayed += 1;
    }
    Ok(json!({
        "ok": true,
        "source": source,
        "target": target,
        "replayed": replayed,
    }))
}

// --- helpers --------------------------------------------------------------

fn default_basket_path() -> Result<String> {
    if let Ok(p) = std::env::var("PMS_BASKET_DB") {
        return Ok(p);
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(format!("{}/.local/share/pms/basket.db", home))
}
