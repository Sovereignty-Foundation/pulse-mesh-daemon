# Working in this repository

This file is for a coding agent opening the Pulse Mesh daemon for the first time, and for the person working with it. Read it whole before changing anything; it is short so that you can.

## What this repository is

`mesh-hub`, the daemon that attaches processes over a Unix socket or a WebSocket and routes envelopes between them, with its port protocol, the hub runtime it wraps, the Rust client, the dev ring, the `pms` tools and the Python and Node thin clients. It is built on the Pulse Mesh standard, the repository `pulse-mesh`, which holds the Pulse, the envelope, their codec, the ring, the store and the UDP transport. Nothing in the standard depends on this repository.

## Set up

- Check out the standard beside this repository, so that `../pulse-mesh` exists: every manifest here points at it. Without it nothing builds.
- Rust: `rust-toolchain.toml` pins the version, and `rustup` installs it on the first `cargo` command.
- The gate also uses `cargo-deny`, `mdbook` and `python3`, and `--full` adds `node` for the thin clients. A check whose tool is missing fails and prints the command that installs it, so install what it names and run it again.
- `just` is optional: every recipe in `justfile` is a thin wrapper, and `scripts/gate.sh` runs the gate without it.

## Prove the tree works, in this order

1. `cargo run --release -p pms-cli -- doctor` checks the toolchain and the environment.
2. `cargo run --release -p pms-cli -- demo` starts a daemon, passes five messages through it and stops it.
3. `scripts/gate.sh --quick` runs the per-commit checks.
4. `scripts/gate.sh` runs the gate a change passes before it merges. `--full` adds the fuzz build, the thin clients' tests, both clients end to end against a live daemon, and the Linux and x86 legs.

The gate prints one line per check and a summary, and writes each check's output to `target/gate/<check>.log`. A change is done when the gate passes, not when the tests you chose pass.

## Map

| Path | What it holds |
|---|---|
| `mesh/mesh-hub` | The daemon |
| `mesh/mesh-port-protocol` | The port protocol's message types, and the fixtures in `fixtures/` the thin clients are tested against |
| `mesh/mesh-hub-runtime` | `PulseHub`, the embedded event bus the daemon wraps |
| `mesh/mesh-client` | The Rust client |
| `mesh/mesh-link` | Daemons that link across hosts (ADR-0021) |
| `mesh/mesh-basket`, `mesh-broadcast`, `mesh-health`, `mesh-module-hub`, `mesh-schema` | The fabric's registries and the envelope basket |
| `dev_ring/` | The general-purpose ring, in the four-crate shape every ring has |
| `tools/pms` | The `pms` command line, the quickest tour of what the daemon does |
| `tools/pms-mcp`, `pms-query`, `pms-telemetry-export` | The MCP server, the basket query tool and the telemetry exporter |
| `clients/` | The Python and Node thin clients; not workspace members |
| `examples/`, `fuzz/` | The examples the tutorials use, and the harness over the daemon's parsers |
| `book/` | Tutorials, guides, the port protocol, reference and explanation; rendered at <https://pulse-mesh.net/docs/daemon/>, every page listed in <https://pulse-mesh.net/llms.txt> |
| `decisions/` | The architectural decision records |

## What is true, in order of authority

1. The specification. The port protocol is chapter 7, in `book/src/reference/spec/`; the chapters on the Pulse, the envelope, the ring and the store are in the standard's book. A MUST is normative.
2. The port protocol's fixtures, in `mesh/mesh-port-protocol/fixtures`, and the standard's test vectors.
3. The rustdoc, the API contract: `cargo doc --workspace --no-deps --open`.
4. The decision records in `decisions/`, for why a call was made. ADR-0018 is the security model.
5. The rest of the book, which explains and guides.

When two of them disagree, one is wrong. Report it; do not pick the one that suits the change.

## Rules that hold for every change

- Never edit a fixture, or a message's fields, to make a test pass. A change to the port protocol is a change to the specification: update chapter 7, the fixtures and both thin clients together, and add a decision record if the change is not obvious.
- The daemon's security is opt-in (ADR-0018): TLS 1.3 on the WebSocket (`--ws-tls-cert`, `--ws-tls-key`), Ed25519 key-proof attach (`--attach-keys`, and `--attach-keys-uds` for the Unix socket), and sealed UDP on the links between daemons, whose cryptographic review is still pending. On its defaults the Unix socket is owner-only, while the loopback WebSocket is plaintext and open to every local user, and no layer authorises per channel. Keep examples, tests and docs on loopback; off loopback the daemon wants TLS and attach keys together, and `--ws-allow-remote` exists for a deployment that wraps it, not for convenience. Only the Rust client proves a key; `pms`, the MCP server and the Python and Node thin clients attach by name.
- A change to the standard belongs in the standard's repository. Do not patch `../pulse-mesh` from here.
- `unsafe` is allowed only with a `// SAFETY:` comment on the block. A crate with no `unsafe` forbids it at its root, and keeps doing so.
- Every public item carries a doc comment, and the gate treats warnings as errors.
- A crate marked `status = "partial"` returns deferred errors on purpose (ADR-0017). Leave the label until the feature works; never make a deferred path look implemented.
- Decision records are append-only: add a record, never rewrite an accepted one.
- No measured figures in docs, comments or read-mes. A guide gives the command; the reader measures on their own machine.
- No links to a source-code host or server. Book pages link to each other relatively; links that leave the repository go to `https://pulse-mesh.net/docs/`. `scripts/docs/check-hosts.py` enforces this in the gate.
- Leave `LICENSE`, `STATUS.md`, the notices and the file headers exactly as they are.

## Making a change

Follow `CONTRIBUTING.md`: its gate table is the list of checks, and its four-question test says where new code goes. Code contributions are closed until the Proving Grounds' full launch, expected in the fourth quarter of 2026, and are then routed through it, so for now a change you make is for the person you work with, and for a report of what did not hold. Put tests beside the code they cover. If the change is visible to someone running the daemon, update the book page that describes it in the same change; the pages under `book/src/reference/` marked as generated are rebuilt by `scripts/docs/gen-all.sh`, never edited by hand. If you made a call a later contributor would have to reverse-engineer, add a decision record. Then run the gate.

## Where to look

| Question | Read |
|---|---|
| What does a client send, and what does the daemon answer? | Spec chapter 7, then `mesh/mesh-port-protocol` |
| How does an envelope get from one process to another? | `book/src/explanation/daemon-design.md`, then `mesh/mesh-hub-runtime` |
| What does the daemon protect, and what not? | `book/src/explanation/trust-boundaries.md` and ADR-0018 |
| What does a flag do? | `book/src/reference/daemon-reference.md` and `cli-reference.md` |
| How do I add a stage to a ring? | The guide *Add a stage to a ring* |
| What does an error mean? | `book/src/guides/troubleshoot.md` and `book/src/reference/errors.md` |

## Reporting back

When you hand work back, say what changed and why, paste the gate's summary line, and name anything you skipped or could not run.
