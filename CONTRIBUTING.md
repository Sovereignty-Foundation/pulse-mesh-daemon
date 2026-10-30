# Contributing

This document says how the Pulse Mesh daemon, a repository built on the standard (`pulse-mesh`, a sibling checkout at `../pulse-mesh`), is organised, how to build and check it, and what a contribution means while Pulse Mesh is in beta.

## Contributions during the beta

Code contributions are closed until the Proving Grounds' full launch, expected in the fourth quarter of 2026. From then on every contribution is routed through the Proving Grounds: a contributor first completes quests on [theproving.net](https://theproving.net), and that record of work is what opens the door. What helps now is use: run it, build on it, and report what does not hold. A page that does not match the code, a command that does not do what it says, a measurement you cannot reproduce: each is a defect. Report it on this repository's issue tracker on GitHub, naming the version, the command and what you saw; that is the most useful thing you can send. Security vulnerabilities are the exception: report them privately to org@sovfound.org as [SECURITY.md](SECURITY.md) describes, never on the issue tracker. Benchmarks are posted and refuted on [theproving.net](https://theproving.net), and [pulse-mesh.net](https://pulse-mesh.net) says how else to reach the project.

When contributions open, material is accepted only from contributors who have signed the Sovereignty Foundation Contributor Grant, through the channel the Foundation designates, as Section 6.3 of the Sovereignty Foundation Research License, Version 1.3, describes. Using the software, reporting defects and publishing findings need no Grant.

The rest of this document is for anyone building on the repository or preparing a change for when contributions open: how to check a change, where code lives, and how the documentation is kept.

## Test gates

`just check` is the gate a change passes, and `scripts/gate.sh` runs the same checks without `just`. This table is the one place the list is stated; the read-mes, the book and the CI workflow point here rather than restating it.

| Recipe | What it runs |
|---|---|
| `lint` | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | `cargo test --workspace --release` |
| `build` | `cargo build --workspace --release` |
| `doc` | `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links -D rustdoc::private-intra-doc-links"` |
| `check-features` | `cargo check --workspace --all-features`, clippy with every feature on, and `cargo check -p mesh-hub --no-default-features` |
| `deny` | `cargo deny --all-features check advisories bans sources` |
| `check-fuzz` | `cargo +nightly fuzz build --fuzz-dir fuzz` |
| `docs` | `scripts/docs/check.sh`: the book's version, summary, link, term and generated-page checks, `mdbook build`, and the tutorials' smoke run |
| `thin-clients` | the Python and Node thin clients' tests (`python3 -m unittest`, `node --test`), which hold both to the port protocol's fixtures under `mesh/mesh-port-protocol/fixtures` |
| `arch-check` | `scripts/arch-check.py`: the tiers depend downward, a ring is imported through its hub, every crate has a consumer or a status, the module table and the four manifests agree, the growing surfaces are `non_exhaustive`, and the workspace table pins the shared dependencies; then its self-test, a planted violation per rule |
| `license-gate` | `scripts/license-gate.sh`: the proprietary placeholder notice in `LICENSE` and `STATUS.md`, and `LicenseRef-Proprietary` on every source file, until the release license is placed |

Lints are enforced workspace-wide through the `[workspace.lints]` block in the root `Cargo.toml`; every crate inherits them. Every commit passes the gate on its own.

## Where code lives

New code belongs in one of three places: the fabric (`mesh/`), the dev ring (`dev_ring/`, routed to `core`, `functions`, `stages` or `hub` by role), or a leaf beside them (`tools/`, `clients/`, `examples/`, `fuzz/`). The two layouts, their codec, the ring, the store and the wire are the standard's, and a change to them is made there first. Use the four-question test to decide:

1. Does it touch the canonical Pulse atom?
2. Does it touch the canonical envelope?
3. Does it cross a ring boundary?
4. Is it on the hot path?

Yes to the first or the second puts it in the standard: it names the specification chapter it touches, and the change here follows. Yes to the third puts it in a ring: the dev ring here for general-purpose stages, a profile for a domain's. Yes to the fourth alone, for something every consumer may need, puts it in the standard's `core/`; for something the daemon alone needs, in `mesh/`. Code that is part of the daemon's contract (the port protocol, routing, the client) is `mesh/`. No to all four makes it a leaf here: a tool, a client, an example. Record any non-obvious classification or architectural decision as a new ADR under `decisions/`.

A crate whose code has no `unsafe` forbids it at its root with `#![forbid(unsafe_code)]`, so a later change that needs `unsafe` has to say so there; every `unsafe` block elsewhere carries a `// SAFETY:` comment, which the workspace's `undocumented_unsafe_blocks` lint enforces.

## Documentation

Documentation is code: a new crate opens with a module-level `//!` overview covering its scope, invariants and public API, and every public item carries a `///` doc comment; the workspace `missing_docs` lint enforces this. The API contract is the rustdoc, decisions are the append-only records under `decisions/`, and narrative documentation is the book under `book/src`, written to `book/src/contributing/style.md` and checked by `just docs`.
