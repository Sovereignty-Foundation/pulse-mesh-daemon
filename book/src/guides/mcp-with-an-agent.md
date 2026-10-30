# Use the MCP server from an agent

<p class="pm-kind"><b>How-to guide</b> · for anyone giving an agent a running mesh to inspect, publish to, or prove the codec against</p>

`pms-mcp` is a Model Context Protocol server over stdio: one JSON-RPC request per line in, one response per line out. Any MCP client that can launch a command can use it.

## 1. Install and check

```bash
just install                # installs pms, mesh-hub and pms-mcp; or: cargo install --path tools/pms-mcp --locked
pms-mcp --help
```

The tools introspect a running daemon (`mesh_attach`, `mesh_send`, `mesh_health`, `mesh_query`, `mesh_replay`), prove the codec on supplied input (`codec_roundtrip`, `mesh_envelope_describe`), read shared memory (`mesh_list_rings`, `mesh_ring_peek`) and list the optimization modules (`modules_list`, `modules_describe`). The [generated tool reference](../reference/mcp-tools.md) has each tool's input schema. The two probe tools are registered only when `PMS_MCP_ALLOW_PROBE=1` is set.

## 2. Register it with the client

With Claude Code:

```bash
claude mcp add pms-mcp -- pms-mcp
```

With any client that reads a JSON configuration, the shape is the same everywhere: a command and, when the basket is somewhere other than the default, its path in the environment.

```json
{ "mcpServers": { "pms-mcp": { "command": "pms-mcp", "env": { "PMS_BASKET_DB": "/path/to/basket.db" } } } }
```

## 3. Try it without a client

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | pms-mcp | head -c 400
```

A daemon must be running for the `mesh_*` tools; the codec and module tools work without one.

## What the server will not do

It has no write path into the ring other than `mesh_send`, which is the same publish any client can make; it does not start or stop the daemon; and it redacts nothing it did not read from the mesh, so what an agent can see through it is what any attached client can see.
