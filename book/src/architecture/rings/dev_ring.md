# `dev_ring`

<p class="pm-kind"><b>Reference</b> · the dev ring, crate by crate</p>

General-purpose developer ergonomics ring. Downstream code should depend on `dev-hub`, not the inner three crates directly.

| Crate | Layer | Contents |
|---|---|---|
| `dev-core` | core | **Empty by design.** Everything in the dev ring is a function, a stage, the hub or peripheral tooling; the crate keeps the four-crate shape uniform and is where shared core types land. |
| `dev-functions` | functions | `basket` — re-export of the tier-2 `mesh-basket` crate (SQLite-backed envelope capture), kept at its historical path. `core_ops` — the ring inspector and the module table; the codec, UDP, version and bench operations are the standard's `pulse-cli` since the split, which `pms` reaches through it. |
| `dev-stages` | stages | `conflation` — a symbol-keyed last-write-wins conflation router wrapping a `PulseRing` for O(1)-per-symbol latency. |
| `dev-hub` | hub | The ring's import point: re-exports `core`, `functions` and `stages`, emits the ring manifest via `register_stages!`, and re-exports the Rust client `Mesh` from `mesh-client`, its home since ADR-0012, so `dev_hub::Mesh` keeps working. |

If you're writing an example or a peripheral tool that just needs to talk to a running `mesh-hub` daemon, `mesh-client`'s `Mesh` API (reachable as `dev_hub::Mesh` too) is almost certainly the right entry point — [Two programs talk through the daemon](../../examples/two-programs.md) is built on exactly this.
