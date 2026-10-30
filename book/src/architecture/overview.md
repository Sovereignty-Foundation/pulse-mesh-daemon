# Workspace Layout

<p class="pm-kind"><b>Reference</b> · the fabric, the dev ring and the leaves beside them, for anyone finding their way around the tree</p>

This repository holds tier 2 of the Pulse Mesh stack and one tier-3 ring. A tier depends only on the tiers below it: everything here depends on [the standard](/docs/architecture/overview.html), tiers 0 and 1, which is a sibling checkout (`../pulse-mesh`) while developing and a pinned tag at a release. Nothing in the standard depends on anything here.

| Tier | Path | What lives here |
|---|---|---|
| 2 — fabric | `mesh/` | `mesh-hub` (the daemon) and `mesh-port-protocol` (the JSON wire types it speaks, with their golden fixtures), `mesh-hub-runtime` (the embedded hub the daemon wraps), `mesh-client` (the Rust client), `mesh-basket` (the SQLite capture store), `mesh-broadcast` and `mesh-health` (the registries), and `mesh-module-hub` (pre-integration, see the [crate index](../reference/crates.md)) |
| 3 — the dev ring | `dev_ring/` | the general-purpose ring, four crates: `dev-core` (an empty placeholder that keeps the shape), `dev-functions` (the ring inspector and the module table), `dev-stages` (the conflation router) and `dev-hub` (the composition surface, which re-exports the Rust client and declares the ring through `register_stages!`) |

Beside the tiers sit the leaves: they consume the tiers and are consumed by nothing.

| Path | What lives here |
|---|---|
| `tools/` | `pms` (the daemon's command line: start, attach, push, tap, demo, doctor, and the codec, UDP, version and bench commands it takes from the standard's `pulse-cli`), `pms-mcp` (the MCP server), `pms-telemetry-export` (the telemetry exporter), and `pms-query`, a Python tool over the basket |
| `clients/` | the Python and Node thin clients, which speak the port protocol over a WebSocket without the codec ([Two programs talk through the daemon](../examples/two-programs.md) runs them) |
| `examples/` | the two-process example and the multi-language one, both run by [Two programs talk through the daemon](../examples/two-programs.md) |
| `fuzz/` | the `cargo-fuzz` harness over the daemon's parsers of untrusted bytes; not a workspace member: `cargo +nightly fuzz run <target> --fuzz-dir fuzz` runs one, and `just check-fuzz` builds them all |

## The other rings

The enterprise, HFT and robotics rings are [the profiles](/docs/profiles/architecture/overview.html), a repository built on the standard beside this one. Every ring has the same four crates, and the dev ring here is one of them; [Rings: domain surfaces](/docs/profiles/architecture/rings/overview.html) describes the shape.

## Deciding where new code goes

`CONTRIBUTING.md` frames this as a four-question test: does the code touch the canonical Pulse atom, touch the canonical envelope, cross a ring boundary, or sit on the hot path? Code that touches the atom or the envelope belongs in the standard, and is made there first. Code that is part of the daemon's contract (the port protocol, routing, the client) belongs in `mesh/`. A stage that crosses a ring boundary belongs in a ring: the dev ring here, or a profile. Anything that only uses the tiers (a tool, a client, an example) is a leaf here. Record any non-obvious classification call as a new ADR under `decisions/` rather than only justifying it in the PR.
