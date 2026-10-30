# ADR-0012 — The Rust client is a tier-2 crate

**Status:** Accepted
**Date:** 2026-09-25

## Context

`dev-hub` was two things: the dev ring's hub, which re-exports the ring's `core`, `functions` and `stages` layers and registers them with `register_stages!`, and the Rust client for the daemon, `Mesh`. A program that only talks to a daemon therefore compiled the whole ring and everything the ring's layers pull in (the basket's SQLite, the conflation stage), about 150 crates for a client whose own code needs a dozen: the port protocol's wire types with their base64 and framing, an async runtime, a WebSocket library and a few utilities. The client is the daemon's peer, not a ring surface: it speaks the wire types the daemon terminates, and nothing in it belongs to the dev ring.

## Decision

The client moves to `mesh/mesh-client`, a tier-2 crate beside `mesh-port-protocol` and `mesh-hub`, with its tests. It depends on `mesh-port-protocol` and the async stack only. `dev-hub` keeps the ring's re-exports and its manifest, uniform with the other three hubs, and re-exports the client (`pub use mesh_client::{client, error, Mesh, …}`), so every existing `dev_hub::Mesh` path compiles. The tools (`pms-cli`, `pms-mcp`), the multi-process example and the fuzz target that drive the client depend on `mesh-client`. The four-crate ring pattern is untouched: no ring crate, member or intra-ring edge is removed.

## Consequences

A client program's dependency closure is the client's own. The dev ring's hub is a hub like the others. `dev_hub::Mesh` remains as a re-export, so nothing downstream breaks, and new code names `mesh_client`. The documentation that placed the client in the dev ring (the Rust reference page, the third tutorial, the dev ring page and the crate index) is corrected by the documentation lane.
