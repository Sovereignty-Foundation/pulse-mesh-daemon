// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Probe tools: `mesh_probe_pulse`, `mesh_reachability`. Env-var gated.
//!
//! These tools mutate external state (they send packets). They are only
//! registered when `PMS_MCP_ALLOW_PROBE=1`. Single-shot, bounded send —
//! no echo / RTT measurement in Phase 5 (would require a peer-side echo
//! service that doesn't exist by default).

use std::net::SocketAddr;
use std::time::Instant;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::Sender;
use serde::Deserialize;
use serde_json::{json, Value};

use super::ToolSpec;

#[derive(Debug, Deserialize)]
struct ProbeArgs {
    target: String,
    #[serde(default = "default_instruction")]
    instruction: u16,
    #[serde(default)]
    payload_hex: Option<String>,
}

fn default_instruction() -> u16 {
    Instruction::Heartbeat as u16
}

pub(crate) fn spec_probe_pulse() -> ToolSpec {
    ToolSpec {
        name: "mesh_probe_pulse",
        description: "Send a single pulse to a UDP target and return send-side duration. Bounded: exactly one frame per call. Does not echo / measure RTT — that requires a peer-side echo service not shipped by default. Use this for liveness checks and to surface kernel errors (destination unreachable, etc.). Gated on PMS_MCP_ALLOW_PROBE=1 at server launch.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": { "type": "string", "description": "UDP destination, e.g. 127.0.0.1:9000." },
                "instruction": {
                    "type": "integer",
                    "description": "Pulse instruction opcode (default: Heartbeat = 1).",
                    "default": 1
                },
                "payload_hex": {
                    "type": "string",
                    "description": "Optional hex-encoded envelope payload. Empty if omitted."
                }
            },
            "required": ["target"]
        }),
    }
}

pub(crate) fn call_probe_pulse(args: &Value) -> anyhow::Result<Value> {
    let parsed: ProbeArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let dest: SocketAddr = parsed
        .target
        .parse()
        .map_err(|e| anyhow::anyhow!("target is not a socket address: {e}"))?;
    let payload = match parsed.payload_hex {
        Some(h) => hex::decode(h.trim())
            .map_err(|e| anyhow::anyhow!("payload_hex is not valid hex: {e}"))?,
        None => Vec::new(),
    };

    let mut sender =
        Sender::bind("0.0.0.0:0").map_err(|e| anyhow::anyhow!("local bind failed: {e}"))?;
    sender.connect(dest)?;

    let mut pulse = Pulse::zeroed();
    pulse.instruction = parsed.instruction;
    pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();

    let start = Instant::now();
    let seq = sender.send(pulse.monotonic_nanos, &pulse, &payload)?;
    let send_ns = start.elapsed().as_nanos();

    Ok(json!({
        "target": parsed.target,
        "instruction": parsed.instruction,
        "envelope_bytes": payload.len(),
        "seq": seq,
        "send_ns": send_ns,
        "delivered_to_kernel": true,
    }))
}

#[derive(Debug, Deserialize)]
struct ReachabilityArgs {
    targets: Vec<String>,
}

pub(crate) fn spec_reachability() -> ToolSpec {
    ToolSpec {
        name: "mesh_reachability",
        description: "Send a one-pulse Heartbeat probe to each target in turn and report whether the kernel accepted the send. UDP is connectionless so this is a send-success check, not an RTT measurement. Gated on PMS_MCP_ALLOW_PROBE=1.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of UDP destinations, e.g. [\"127.0.0.1:9000\", \"10.0.0.5:9001\"]."
                }
            },
            "required": ["targets"]
        }),
    }
}

pub(crate) fn call_reachability(args: &Value) -> anyhow::Result<Value> {
    let parsed: ReachabilityArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let mut rows = Vec::new();
    for target in &parsed.targets {
        let row = match target.parse::<SocketAddr>() {
            Err(e) => json!({ "target": target, "ok": false, "error": format!("parse: {e}") }),
            Ok(dest) => match probe_one(dest) {
                Ok(ns) => json!({ "target": target, "ok": true, "send_ns": ns }),
                Err(e) => json!({ "target": target, "ok": false, "error": e.to_string() }),
            },
        };
        rows.push(row);
    }
    Ok(json!({ "results": rows }))
}

fn probe_one(dest: SocketAddr) -> anyhow::Result<u128> {
    let mut sender =
        Sender::bind("0.0.0.0:0").map_err(|e| anyhow::anyhow!("local bind failed: {e}"))?;
    sender.connect(dest)?;
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Heartbeat as u16;
    pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
    let start = Instant::now();
    sender.send(pulse.monotonic_nanos, &pulse, &[])?;
    Ok(start.elapsed().as_nanos())
}
