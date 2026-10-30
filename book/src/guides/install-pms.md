# Install pms outside the workspace

<p class="pm-kind"><b>How-to guide</b> · for anyone who wants `pms` and the daemon on their path rather than behind `cargo run`</p>

You need the Rust toolchain pinned in `rust-toolchain.toml` (rustup picks it up) and a clone of the repository. Linux or macOS; the rings use POSIX shared memory.

## 1. Install the three binaries

```bash
just install
```

Without `just`, the recipe is three commands:

```bash
cargo install --path tools/pms --locked
cargo install --path mesh/mesh-hub --locked
cargo install --path tools/pms-mcp --locked
```

`pms`, `mesh-hub` and `pms-mcp` land in `~/.cargo/bin`, which rustup puts on your path. `pms start` looks for `mesh-hub` beside its own executable first and on your path second, and falls back to `cargo run` only inside the workspace, so the installed pair works from any directory.

## 2. Check

```bash
pms version
pms doctor
```

`version` prints the workspace and codec versions the binary was built from; `doctor` checks the toolchain and the runtime preconditions and names anything missing.

## 3. Run

```bash
pms demo
```

The demo starts a daemon if none is running, exchanges five envelopes between a producer and a consumer, and stops the daemon it started. From here the [examples](../examples/README.md) take over.

## Upgrading

Repeat step 1 after pulling a new release; `cargo install` replaces the binaries. The book's version in the sidebar is the version the pages describe; `pms version` is the version you have.
