// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Codec-introspection tools: `codec_roundtrip`, `mesh_envelope_describe`.

use pulse_canon::{PayloadData, PulseEnvelope};
use serde::Deserialize;
use serde_json::{json, Value};

use super::ToolSpec;

#[derive(Debug, Deserialize)]
struct RoundtripArgs {
    envelope_type: u16,
    #[serde(default)]
    type_name: Option<String>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_utf8: Option<String>,
}

pub(crate) fn spec_codec_roundtrip() -> ToolSpec {
    ToolSpec {
        name: "codec_roundtrip",
        description: "Canonically encode a PulseEnvelope spec, round-trip decode it, and return the canonical hex + BLAKE3 content hash + size. Proves the canonical codec works for the supplied input. The same canonical_hex output is byte-identical across Rust, Python, and Node implementations of the codec, which is the byte equality the standard is built on.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "envelope_type": { "type": "integer", "minimum": 0, "maximum": 65535 },
                "type_name": { "type": "string" },
                "payload_hex": { "type": "string", "description": "Hex-encoded raw payload bytes (mutually exclusive with payload_utf8)." },
                "payload_utf8": { "type": "string", "description": "UTF-8 payload bytes (mutually exclusive with payload_hex)." }
            },
            "required": ["envelope_type"]
        }),
    }
}

pub(crate) fn call_codec_roundtrip(args: &Value) -> anyhow::Result<Value> {
    let parsed: RoundtripArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let payload_bytes = match (&parsed.payload_hex, &parsed.payload_utf8) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide payload_hex OR payload_utf8, not both")
        }
        (Some(h), None) => hex::decode(h.trim())
            .map_err(|e| anyhow::anyhow!("payload_hex is not valid hex: {e}"))?,
        (None, Some(s)) => s.as_bytes().to_vec(),
        (None, None) => Vec::new(),
    };
    // The arguments' whole content: a type name does not replace the type.
    let env = PulseEnvelope::with_content(
        parsed.envelope_type,
        parsed.type_name,
        PayloadData::Raw(payload_bytes),
    );
    let result = pulse_cli::ops::codec::roundtrip(&env)?;
    Ok(serde_json::to_value(result)?)
}

#[derive(Debug, Deserialize)]
struct DescribeArgs {
    /// Canonical wire bytes, hex-encoded.
    canonical_hex: String,
}

pub(crate) fn spec_envelope_describe() -> ToolSpec {
    ToolSpec {
        name: "mesh_envelope_describe",
        description: "Decode a canonical PulseEnvelope hex string and return a structural summary: envelope_type, content_hash, monotonic_nanos, flags, payload variant + size. Pure function — does not touch live mesh state.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "canonical_hex": { "type": "string", "description": "Canonical wire bytes, lowercase hex." }
            },
            "required": ["canonical_hex"]
        }),
    }
}

pub(crate) fn call_envelope_describe(args: &Value) -> anyhow::Result<Value> {
    let parsed: DescribeArgs = serde_json::from_value(args.clone())
        .map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))?;
    let env = pulse_cli::ops::codec::decode_hex(&parsed.canonical_hex)?;
    let payload_summary = match env.payload() {
        PayloadData::Raw(bytes) => json!({
            "variant": "Raw",
            "size": bytes.len(),
            "hex": hex::encode(bytes),
        }),
        PayloadData::Nested(children) => json!({
            "variant": "Nested",
            "child_count": children.len(),
        }),
    };
    Ok(json!({
        "envelope_type": env.envelope_type(),
        "type_name": env.type_name(),
        "content_hash": env.id().to_hex(),
        "monotonic_nanos": env.monotonic_nanos,
        "flags": env.flags.bits(),
        "payload": payload_summary,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// A type name does not replace the numeric type: the hash covers both.
    #[test]
    fn roundtrip_keeps_the_type_beside_a_type_name() {
        let out = call_codec_roundtrip(&json!({
            "envelope_type": 7,
            "type_name": "app/event",
            "payload_utf8": "x",
        }))
        .unwrap();
        let expected = PulseEnvelope::with_content(7, Some("app/event".into()), b"x".to_vec());
        assert_eq!(out["content_hash"], json!(expected.id().to_hex()));
    }
}
