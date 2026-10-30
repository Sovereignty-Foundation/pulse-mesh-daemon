# Rust

<p class="pm-kind"><b>Reference</b> · the `Mesh` client's surface, and where the rest of the Rust API lives</p>

## The `Mesh` client

`Mesh`, in the `mesh-client` crate (and re-exported by `dev-hub`, its home before ADR-0012, so `dev_hub::Mesh` keeps working), is the Rust client for the daemon: a synchronous handle over the Universal Port Protocol. Every method blocks the calling thread and returns a `Result` whose error is `DevError`. None may be called from inside an async runtime, where it would deadlock; such a call returns `DevError::ReentrantCall` instead.

| Call | What it does |
|---|---|
| `Mesh::attach(name)` | Connects and registers the process under `name`. Tries the endpoint in `PMS_DAEMON`, which must name a `unix://` path or a `ws://` URL (anything else is `NoDaemon`), then `/tmp/pms.sock`, then `ws://127.0.0.1:9876`. A socket at `/tmp/pms.sock` that another user serves is refused with `ForeignDaemon`, since anyone may create that path first; a socket named in `PMS_DAEMON` is not checked. A daemon that refuses the attach answers with its code and message, `name_in_use` or, at its connection cap, `limit_exceeded`, which it says unprompted before it closes. |
| `Mesh::attach_with(name, options)` | The same with a `MeshOptions`: `with_endpoint(Endpoint::Uds(path))` or `with_endpoint(Endpoint::Ws(url))`, `with_rpc_timeout(duration)` (five seconds by default), `with_heartbeat_interval(duration)` (thirty seconds; zero switches the idle heartbeat off), `with_event_queue(depth)` (how many events may wait for the callbacks, 1,024 by default; a full queue drops the newest event and counts it). |
| `send(channel, payload) -> String` | Publishes the bytes on the channel and returns the envelope identifier the daemon computed, as 32 hexadecimal digits. |
| `send_typed(channel, Some(type_name), payload) -> String` | The same with a type name, which is part of the content and so of the identifier. |
| `send_with_receipt(channel, type_name, payload) -> SendReceipt` | Publishes, with or without a type name, and returns the daemon's receipt: `envelope_id`, and `persisted`, which is `Some(true)` when the daemon's envelope store kept the envelope for readers of the hub's shared memory, `Some(false)` when the store refused it (larger than a store entry, or no slot free) and `None` when the daemon runs without a store. A refused store does not fail the send, and the subscribers still receive the envelope. `send` and `send_typed` delegate to it and return only the identifier. |
| `on(channel, callback) -> SubscriptionId` | Subscribes to one channel. The callback receives a `MeshEvent` per envelope, on a dispatch thread of the client's own, so it may call back into `Mesh`. |
| `tap(filter, callback) -> SubscriptionId` | Subscribes with a `TapFilter`: any of `channel` (exact or glob), `type_id`, `type_name` and `origin`; an empty filter matches everything. |
| `unsubscribe(id) -> u64` | Ends a subscription and returns how many of its events the daemon dropped because this connection's queue was full (the daemon's `--subscriber-queue`). |
| `events_dropped() -> u64` | How many events this client dropped because its own event queue was full, across every subscription since attach: events the daemon delivered and no callback ran. Replies are never dropped. |
| `events_malformed() -> u64` | How many events this client dropped because their payload was not valid base64, across every subscription since attach. A conforming daemon sends none; such an event never reaches a callback, so no callback receives bytes nobody published, and it is logged at the first and at each doubling. Not counted in `events_dropped`. |
| `run() -> Result<(), DevError>` | Blocks until the connection ends and returns what `wait` reports, so a lost daemon cannot pass for a clean stop; `pms attach` and `pms tap` print that result and exit with status 2. |
| `wait() -> Result<(), DevError>` | The same, returning `Ok` only after a detach the daemon acknowledged. Any other end is an error: the daemon's parting error as `DevError::Daemon` when it gave one (`limit_exceeded` at its connection cap, `payload_too_large` after a frame over its limit; an error that answers no request is kept while it is the daemon's last word), otherwise `DevError::Disconnected`, whether the daemon closed the connection or a write to it failed. Every call still waiting gets the same error, and a call made after the end gets `DisconnectedDuringRpc`. |
| `detach()` | Leaves the mesh and releases the name. Returns `Disconnected`, or the daemon's error, when the connection ends before the daemon acknowledges, which is then not a clean end. |

A `MeshEvent` carries `subscription_id`, `envelope_id`, `channel`, `type_id`, `type_name`, `origin` (the publisher's node, as `short@hex`), `captured_at_unix_nanos` and `payload`.

`DevError` has one variant per failure: `NoDaemon`, `VersionMismatch`, `Transport`, `Protocol`, `Daemon { code, message }` (the daemon refused a request, or said why it was closing, and `code` is one of the protocol's error codes as text; `mesh_port_protocol::ErrorCode::parse` gives the typed code, or `None` for one this build does not know), `NotAttached`, `DisconnectedDuringRpc` (the call got no answer because the connection had already ended when it was made, or its task stopped without answering), `Timeout { op, after }`, `ReentrantCall` and `Disconnected` (the connection ended other than by an acknowledged detach and without a reason from the daemon). The enum is `non_exhaustive`, as every error enum and configuration struct of the mesh tier is: a `match` on it carries a wildcard arm, since a later release can add a variant, and a configuration is built from its `Default` with `with_*` methods rather than a struct literal. The [error catalogue](errors.md) lists them with their messages.

## The rest of the API

Generate the reference for every workspace crate — `pulse-canon`, `core-ring`, `mesh-hub-runtime`, each ring's `*-hub` crate, and so on — straight from source:

```
cargo doc --workspace --no-deps --open
```

This includes the module-level `//!` overview and every public item's `///` doc comment that `CONTRIBUTING.md`'s `missing_docs` lint enforces workspace-wide (see [Developer Onboarding](../contributing/onboarding.md)).

The three native language bindings ([Python](/docs/reference/python.html), [Node](/docs/reference/node.html), [C](/docs/reference/c.html)) are Rust crates too, but sit outside the root workspace, in the standard's repository (see [Language bindings](/docs/reference/bindings.html)), so document them from their own directories:

```
cargo doc -p pulse-wire-udp --no-deps   # the transport the bindings wrap
```
