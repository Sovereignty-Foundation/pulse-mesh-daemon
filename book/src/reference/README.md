<div class="pm-part">
  <img class="pm-logo pm-logo-light" src="../images/sov-mark-black.svg" alt="Sovereignty Foundation Inc.">
  <img class="pm-logo pm-logo-dark" src="../images/sov-mark-white.svg" alt="">
  <span class="pm-eyebrow">Part 03 · Reference</span>
  <h1>What is <span class="pm-accent">exactly</span> true</h1>
  <p class="pm-sub">The port protocol, the workspace crate by crate, and the tables generated from the code.</p>
</div>

<p class="pm-kind"><b>Part opener</b> · for implementers and integrators looking something up</p>

Reference pages state what is true and nothing else. They do not teach and they do not persuade. Where a table can be produced from the code, it is, and a check in continuous integration fails when the page and the code disagree.

The part has four layers. The specification is [the standard's](/docs/reference/spec/README.html); its chapter 7, [the port protocol](spec/07-port-protocol.md), is here because the daemon is what speaks it, and the golden fixtures under `mesh/mesh-port-protocol/fixtures` are its executable form. The workspace pages describe the tier and the ring, following the tree's own structure. The API page describes the Rust client. The generated pages are produced from the code by the gate.

- [The specification](spec/README.md): the chapters, and [chapter 7, the port protocol](spec/07-port-protocol.md).
- Workspace: [Layout](../architecture/overview.md), [Fabric: mesh/](../architecture/mesh.md), [the dev ring](../architecture/rings/dev_ring.md), [the leaves beside them](../architecture/peripheral.md). The standard's tiers and the other rings have their pages in [the standard's book](/docs/architecture/overview.html) and [the profiles' book](/docs/profiles/architecture/rings/overview.html).
- Generated from the code: [the pms command line](cli-reference.md), [the mesh-hub daemon](daemon-reference.md), [the MCP tools](mcp-tools.md), the [modules and developer profiles](modules.md), the [crate index](crates.md) and the [error catalogue](errors.md); the gate regenerates them and fails on any difference.
- API: [Overview](overview.md) and [Rust](rust.md); the codec bindings for Python, Node and C are [in the standard's book](/docs/reference/bindings.html).
- [Glossary](../glossary.md).
