# Peripheral surface

<p class="pm-kind"><b>Reference</b> · everything beside the tier and the ring, directory by directory</p>

Everything that falls outside the fabric and the dev ring (per the four-question test in [Workspace Layout](overview.md)) sits beside them at the top of the repository. The thin clients and the fuzz harness opt out of the root Cargo workspace: the clients have no Rust to build, and the harness builds on nightly with `cargo-fuzz`.

| Directory | Contents |
|---|---|
| `tools/` | Developer-facing binaries: `pms` (the daemon's command line, see [The pms command line](../reference/cli-reference.md); its codec, UDP, version and bench commands are the standard's `pulse-cli`, which it depends on), `pms-mcp` (the MCP server, see [The MCP tools](../reference/mcp-tools.md)), `pms-telemetry-export` (the telemetry exporter), and `pms-query`, a Python query tool over the basket the daemon can capture, with its own tests under `tools/pms-query/tests`. |
| `clients/` | The pure-language thin clients with no compilation step, `pms-py-thin` and `pms-node-thin`, which talk to a running `mesh-hub` daemon over a WebSocket speaking the port protocol directly. Each holds its own tests, held to the golden frames under `mesh/mesh-port-protocol/fixtures`; `scripts/thin-e2e.py` runs both against a live daemon. [Two programs talk through the daemon](../examples/two-programs.md) uses them. |
| `examples/` | Runnable demos: `multi-process` (two processes talking through a `mesh-hub` daemon, the program [Two programs talk through the daemon](../examples/two-programs.md) includes) and `multi-lang` (a Python publisher and a Node subscriber talking through the same daemon, over the thin clients). |
| `fuzz/` | A `cargo-fuzz` harness over the daemon's parsers of untrusted bytes: the port protocol's base64 payloads, its Unix-socket framing and its JSON messages, an envelope's origin, and the client's routing of what a daemon sends. Not a workspace member: from the repository root, `cargo +nightly fuzz run <target> --fuzz-dir fuzz` runs one, and `just check-fuzz` builds them all. |

The standard's leaves, the `pulse` command line, the codec bindings, its examples and its fuzz harness over the wire and the codec, are [in its book](/docs/architecture/overview.html); the profiles' plugin and telemetry tool are [in theirs](/docs/profiles/architecture/overview.html).
