// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Minimal JSON-RPC 2.0 wire types for the MCP server.
//!
//! No external JSON-RPC crate — the surface we need is a few hundred bytes
//! of struct definitions plus three error constructors.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Inbound JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcRequest {
    /// Always `"2.0"` per spec — accepted but not validated for forward compat.
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    /// Method name (e.g. `"tools/list"`).
    pub method: String,
    /// Optional method parameters.
    pub params: Option<Value>,
    /// Request id: a string, a number or null. A message without one is a
    /// notification, which JSON-RPC 2.0 forbids answering.
    #[serde(default, deserialize_with = "present")]
    pub id: Option<Value>,
}

/// `Some` for a member that is present, `null` included, so an absent id (a
/// notification) and a null one (a request) stay apart.
fn present<'de, D: serde::Deserializer<'de>>(member: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(member).map(Some)
}

/// Outbound JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcResponse {
    /// Always `"2.0"` per spec.
    pub jsonrpc: &'static str,
    /// Echo of the request id.
    pub id: Option<Value>,
    /// Result payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

impl JsonRpcResponse {
    /// Construct a success response.
    pub(crate) fn result(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    pub(crate) fn error(id: Option<Value>, err: ErrorObject) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(err),
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub(crate) struct ErrorObject {
    /// Numeric error code (per JSON-RPC 2.0 spec ranges).
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorObject {
    /// `-32700` Parse error: the input was not valid JSON.
    pub(crate) fn parse_error(detail: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: detail.into(),
            data: None,
        }
    }

    /// `-32601` Method not found.
    pub(crate) fn method_not_found(detail: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: detail.into(),
            data: None,
        }
    }

    /// `-32602` Invalid params.
    pub(crate) fn invalid_params(detail: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: detail.into(),
            data: None,
        }
    }

    /// `-32000` Application-level error.
    pub(crate) fn application_error(detail: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: detail.into(),
            data: None,
        }
    }
}
