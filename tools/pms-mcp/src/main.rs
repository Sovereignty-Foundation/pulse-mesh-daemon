// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms-mcp`: the Model Context Protocol server for Pulse Mesh™.
//!
//! JSON-RPC 2.0 over stdio, one request per line in and one response per
//! line out; no streaming and no long-lived subscriptions in this version.
//! The tools introspect a running mesh (attach, send, query the basket,
//! health, replay), prove the canonical codec on supplied input, and list
//! the optimization modules. The server is read-leaning by design: the
//! probe tools are registered only when `PMS_MCP_ALLOW_PROBE=1` is set at
//! launch.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/peripheral.html>.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![warn(missing_docs)]

mod protocol;
mod tools;

use std::io::{BufRead, Write};
use std::process::ExitCode;

use clap::Parser;

use protocol::{ErrorObject, JsonRpcRequest, JsonRpcResponse};

#[derive(Parser, Debug)]
#[command(
    name = "pms-mcp",
    about = "MCP server for the Pulse Mesh Standard (stdio JSON-RPC 2.0).",
    version
)]
struct Args {
    /// Use stdio transport (the only transport in v1). Present for forward compat.
    #[arg(long, default_value_t = true)]
    stdio: bool,
    /// Print the tool list as the Markdown reference page the book carries, then exit.
    #[arg(long, hide = true)]
    dump_tools_markdown: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let allow_probe = std::env::var("PMS_MCP_ALLOW_PROBE")
        .map(|v| v == "1")
        .unwrap_or(false);

    let registry = tools::build_registry(allow_probe);
    if args.dump_tools_markdown {
        print!("{}", tools_markdown(&tools::build_registry(true)));
        return ExitCode::SUCCESS;
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("pms-mcp: read error: {e}");
                return ExitCode::from(1);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let Some(response) = handle_line(&line, &registry) else {
            continue;
        };
        let serialized = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pms-mcp: failed to serialize response: {e}");
                continue;
            }
        };
        if let Err(e) = writeln!(stdout_lock, "{serialized}") {
            eprintln!("pms-mcp: write error: {e}");
            return ExitCode::from(1);
        }
        if let Err(e) = stdout_lock.flush() {
            eprintln!("pms-mcp: flush error: {e}");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

/// The response to one line, `None` for a notification: JSON-RPC 2.0 answers
/// a request, and a notification, a message without an id, gets nothing, not
/// even an error. A line that does not parse is answered with a null id.
fn handle_line(line: &str, registry: &tools::ToolRegistry) -> Option<JsonRpcResponse> {
    let req: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                None,
                ErrorObject::parse_error(format!("invalid JSON: {e}")),
            ))
        }
    };
    // The server acts on no notification (`notifications/initialized` and
    // `notifications/cancelled` need nothing from it), and answers none.
    let id = Some(req.id.clone()?);
    Some(respond(req, id, registry))
}

/// The response to request `req`, whose id is `id`.
fn respond(
    req: JsonRpcRequest,
    id: Option<serde_json::Value>,
    registry: &tools::ToolRegistry,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => JsonRpcResponse::result(
            id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "pms-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": {}
                }
            }),
        ),
        "tools/list" => {
            let tools = registry.list();
            JsonRpcResponse::result(id, serde_json::json!({ "tools": tools }))
        }
        "tools/call" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        ErrorObject::invalid_params("tools/call requires params"),
                    )
                }
            };
            match registry.call(&params) {
                Ok(content) => JsonRpcResponse::result(
                    id,
                    serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&content).unwrap_or_default(),
                        }],
                        "isError": false,
                    }),
                ),
                Err(e) => JsonRpcResponse::error(id, ErrorObject::application_error(e.to_string())),
            }
        }
        other => JsonRpcResponse::error(
            id,
            ErrorObject::method_not_found(format!("method not supported: {other}")),
        ),
    }
}

/// The tool list as Markdown, one section per tool with its input schema.
fn tools_markdown(registry: &tools::ToolRegistry) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "<!-- Generated by `pms-mcp --dump-tools-markdown` (scripts/docs/gen-all.sh); do not edit by hand. -->");
    let _ = writeln!(out, "# The MCP tools\n");
    let _ = writeln!(out, "<p class=\"pm-kind\"><b>Reference · generated</b> · every tool `pms-mcp` registers, with its input schema, printed by the server itself</p>\n");
    let _ = writeln!(out, "The server speaks JSON-RPC 2.0 over stdio. `mesh_probe_pulse` and `mesh_reachability` are registered only when `PMS_MCP_ALLOW_PROBE=1` is set at launch.\n");
    for spec in registry.list() {
        let _ = writeln!(out, "## `{}`\n\n{}\n", spec.name, spec.description);
        let props = spec
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object());
        let required: Vec<&str> = spec
            .input_schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if let Some(props) = props {
            let _ = writeln!(
                out,
                "| Input | Type | Required | Notes |\n|---|---|---|---|"
            );
            for (name, schema) in props {
                let ty = schema.get("type").and_then(|t| t.as_str()).unwrap_or("any");
                let desc = schema
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                let en = schema
                    .get("enum")
                    .map(|e| format!(" one of {e}"))
                    .unwrap_or_default();
                let req = if required.contains(&name.as_str()) {
                    "yes"
                } else {
                    ""
                };
                let _ = writeln!(out, "| `{name}` | {ty} | {req} | {desc}{en} |");
            }
            let _ = writeln!(out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn reply(line: &str) -> Option<serde_json::Value> {
        handle_line(line, &tools::build_registry(false)).map(|r| serde_json::to_value(r).unwrap())
    }

    #[test]
    fn a_notification_gets_no_response() {
        assert!(reply(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert!(reply(r#"{"jsonrpc":"2.0","method":"no/such/method"}"#).is_none());
    }

    #[test]
    fn a_request_with_a_null_id_is_answered_with_it() {
        let r = reply(r#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#).expect("a response");
        assert!(r["id"].is_null());
        assert!(r["result"]["tools"].is_array());
    }

    #[test]
    fn a_request_is_answered_with_its_id() {
        let r = reply(r#"{"jsonrpc":"2.0","id":7,"method":"no/such/method"}"#).expect("a response");
        assert_eq!(r["id"], 7);
        assert!(r["error"].is_object());
    }

    #[test]
    fn a_line_that_does_not_parse_is_answered_with_a_null_id() {
        let r = reply("{not json").expect("a response");
        assert!(r["id"].is_null());
        assert!(r["error"].is_object());
    }
}
