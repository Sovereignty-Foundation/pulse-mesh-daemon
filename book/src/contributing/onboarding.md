# Developer Onboarding

<p class="pm-kind"><b>Start here</b> · five minutes from a fresh checkout to a daemon you have watched work, by hand</p>

Working with a coding agent? Start with [Onboard your agent](../start/onboard-your-agent.md): one prompt sets up all three repositories. This page is the same setup by hand.

## By hand

1. **Set up.** Check out the standard at `../pulse-mesh`; every manifest here reaches it there. `rust-toolchain.toml` pins the Rust version, and `rustup` installs it on the first `cargo` command.
2. **See it work.**
   ```bash
   cargo install --path tools/pms --locked
   cargo install --path mesh/mesh-hub --locked
   pms doctor
   pms demo
   ```
   `pms doctor` checks the toolchain and the environment. `pms demo` starts a daemon, passes five messages from a producer to a consumer through it, prints each one, and stops the daemon.
3. **Run a mesh yourself.** [Two programs talk through the daemon](../examples/two-programs.md) starts a daemon and moves envelopes between terminals, programs and languages.
4. **Prove the tree.** `scripts/gate.sh --quick` runs the per-commit checks; `scripts/gate.sh` runs the gate a change passes before it merges. A check whose tool is missing fails and prints the command that installs it.

From there, [An agent swarm](../examples/agent-swarm.md) puts a planner and two workers on the mesh.

## Before your first change

- `CONTRIBUTING.md` says what a contribution means during the beta, holds the table of every check the gate runs, and gives the four-question test for where new code goes, which [Workspace Layout](../architecture/overview.md) explains.
- `AGENTS.md` lists the rules every change keeps, for a person as much as for an agent: a port-protocol change moves the specification, the fixtures and both thin clients together; the daemon stays on loopback; `unsafe` only with a `// SAFETY:` comment; decision records added and never rewritten.
- The specification is normative, the rustdoc is the API contract, and the [Decision log](../explanation/decision-log.md) records why the non-obvious calls were made. This book explains and guides; where it and the code disagree, one of them is wrong.

## Where to read first

- `mesh/mesh-hub-runtime/src/lib.rs`: the in-process event bus (`PulseHub`) the `mesh-hub` daemon wraps.
- `mesh/mesh-hub/src/`: the daemon, its transports, its per-connection loop, and the bridge to the hub.
- `mesh/mesh-port-protocol/src/lib.rs` and `fixtures/`: the messages every client speaks, and the frames the thin clients are held to.
- `mesh/mesh-client/src/client.rs`: the Rust client (`Mesh`), which `dev-hub` re-exports.
- `tools/pms/src/main.rs` and `src/commands/`: the `pms` command line, the most concrete tour of what the daemon does.
