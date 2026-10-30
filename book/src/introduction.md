<div class="pm-hero">
  <img class="pm-logo pm-logo-light" src="images/sov-mark-black.svg" alt="Sovereignty Foundation Inc.">
  <img class="pm-logo pm-logo-dark" src="images/sov-mark-white.svg" alt="">
  <span class="pm-eyebrow">Sovereignty Foundation Inc. · The Pulse Mesh™ Daemon Book</span>
  <h1>Pulse <span class="pm-accent">Mesh</span><sup class="pm-tm">™</sup> Daemon</h1>
  <p class="pm-sub">A runner on the standard: the daemon that routes envelopes between processes through a local port, its Rust client, the dev ring, and the pms tools.</p>
  <p class="pm-ident">Pulse Mesh Daemon · working draft · reference implementation</p>
  <div class="pm-status">Nothing in this book is a release announcement. Licensing questions go to <a href="mailto:legal@sovfound.org">legal@sovfound.org</a>.</div>
  <div class="pm-cta-row">
    <a class="pm-cta pm-cta-primary" href="start/onboard-your-agent.html">Onboard your agent</a>
    <a class="pm-cta pm-cta-secondary" href="examples/two-programs.html">Two programs through the daemon</a>
    <a class="pm-cta pm-cta-secondary" href="reference/README.html">Read the reference</a>
  </div>
</div>

Pulse Mesh™ is a transport substrate built on two byte layouts. The **Pulse** is a 128-byte control signal that occupies two cache lines and moves through a shared-memory ring without a lock. The **PulseEnvelope** carries anything larger, at any size, and is addressed by the 16-byte BLAKE3 hash of its canonical bytes, so the same content produces the same identifier in every language that implements the codec. The two layouts, their codec, the ring, the store and the wire are [the standard](/docs/introduction.html), a repository of its own; this one builds on it.

This repository is the daemon: `mesh-hub`, which attaches processes over a Unix socket or a WebSocket, routes envelopes between them by channel, and keeps nothing for a subscriber that is not there; the port protocol those processes speak, in JSON, with its golden fixtures; the embedded hub runtime the daemon wraps; the Rust client (`Mesh`: attach, send, on, tap, run); the dev ring, the general-purpose ring composed on the standard; the `pms` command line, the `pms-mcp` server for agents, the telemetry exporter and the basket query tool; the Python and Node thin clients; and the two-process and multi-language examples. It depends on the standard as a sibling checkout (`../pulse-mesh`) while developing and as a pinned tag at a release.

This book documents the daemon in this repository. It is organised in four parts, each answering one kind of question, and every page states at its top which kind it is and whom it is for.

## The four parts

| Part | The question it answers | How to read it |
|---|---|---|
| [Examples](examples/README.md) | How do I see it working? | Hand the prompt to your agent, or follow the steps; each ends with something running and checks you can run. |
| [Workflows](workflows/README.md) | How do I do my domain's job with it? | An example's shape for one domain, saying what is implemented and what is deferred. |
| [How-to guides](guides/README.md) | How do I do this particular task? | Find the task, follow the steps. |
| [Reference](reference/README.md) | What exactly is true? | Look things up. The port protocol, the daemon's flags and the generated tables live here. |
| [Concepts](explanation/README.md) | Why is it built this way? | Read for understanding. One invariant and one figure per page. |

A last part, [Contributing](contributing/README.md), is for people changing the tree: the workspace, the gates, the decision record, and the documentation's own rules.

## Where to start

- **Seeing the daemon work:** [Two programs talk through the daemon](examples/two-programs.md), then [An agent swarm](examples/agent-swarm.md). Encoding and verifying one envelope first, and sending Pulses over UDP, is [Across a network, in the standard's book](/docs/examples/across-a-network.html).
- **Talking to the mesh from another language:** the Python and Node steps of [Two programs talk through the daemon](examples/two-programs.md) with the thin clients, and the [Rust client](reference/rust.md); the codec bindings are [in the standard's book](/docs/reference/bindings.html).
- **Understanding how the pieces fit:** [Fabric: mesh/](architecture/mesh.md) and [the dev ring](architecture/rings/dev_ring.md) in the [Reference](reference/README.md) part, then [Daemon design](explanation/daemon-design.md) and [Substrate versus contract](explanation/substrate-versus-contract.md).
- **Contributing:** [Developer Onboarding](contributing/onboarding.md), then the [documentation style](contributing/style.md) if you are writing.

## How this book relates to the rest of the repository

Two records are authoritative, and this book defers to both. The rustdoc (`cargo doc --workspace --no-deps --open`) is the API contract: every crate opens with an overview, every public item is documented, and a workspace lint keeps it that way. The decision log under `decisions/` records why the non-obvious calls were made, in order and without rewriting. The book is the guided path through that material. Where the book and the code disagree, one of them is wrong, and either way it is a defect to report.

The specification is the standard's, and this book cites it by chapter; only chapter 7, the port protocol, is here, because the daemon is what speaks it.

## What this book claims and what it does not

The book describes the tree at the version shown in the sidebar. It records no measured figures. Where it describes a measurement it gives the command that produces one. Where a behaviour is specified but not yet implemented, the page says so and names the test that will prove it. Refutations are welcome: the fastest way to improve a page is to show where it is wrong.
