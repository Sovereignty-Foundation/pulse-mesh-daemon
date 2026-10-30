# Add a stage to a ring

<p class="pm-kind"><b>How-to guide</b> · for a contributor adding stateful processing to a ring</p>

Every ring has the same four crates, and a new stage goes into the ring's `stages` crate, is declared in the ring's hub, and shows up in the hub's manifest. This guide adds a stage called `dedupe` to the dev ring; the enterprise, HFT and robotics rings, in the profiles repository, work the same way.

## 1. Decide it is a stage

A stage carries state or sits on the hot path: a router, a pool, a lane, an observer. A stateless transformation with no I/O is a function and belongs in `<ring>-functions`; a type several layers share and nothing else belongs in `<ring>-core`. `CONTRIBUTING.md` states the rule; when in doubt, ask whether the module owns anything between calls.

## 2. Add the module to the stages crate

```bash
mkdir dev_ring/dev-stages/src/dedupe
```

Create `dev_ring/dev-stages/src/dedupe/mod.rs` with the file header every source file carries, a crate-style overview (`//!`) that says what the stage is and what it owns, and the code. Declare it in `dev_ring/dev-stages/src/lib.rs`:

```rust
pub mod conflation;
pub mod dedupe;
```

Add the stage to the crate overview's list in the same file, one line, in the same shape as the existing entries.

## 3. Declare it in the hub

The hub is the ring's only import point. In `dev_ring/dev-hub/src/lib.rs`, add the stage to the `register_stages!` invocation:

```rust
mesh_stage_registry::register_stages! {
    functions: [
        dev_functions::basket,
        dev_functions::core_ops,
    ],
    stages: [
        dev_stages::conflation,
        dev_stages::dedupe,
    ],
}
```

The macro emits `RING_MANIFEST` and imports each listed path, so a path that names no module fails the hub's build here rather than becoming a string in the manifest. The hub's manifest test asserts the manifest: update `dev_ring/dev-hub/tests/manifest.rs` so it lists the new stage; the test is what keeps the manifest and the declaration together.

## 4. Check the gates

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dev-stages -p dev-hub
scripts/docs/check.sh
```

The first two are the code gates. The third fails if the crate overview names something that does not exist or if the ring's page in the book no longer matches the crate table; regenerate the crate index with `scripts/docs/gen-all.sh` if the description in `Cargo.toml` changed.

## 5. Document it

Add one row to the ring's table in `book/src/architecture/rings/dev_ring.md` and to `dev_ring/README.md`, in the same sentence shape as the existing rows: what the stage is and what it owns. If the stage introduces a term, the [glossary](../glossary.md) gets an entry.
