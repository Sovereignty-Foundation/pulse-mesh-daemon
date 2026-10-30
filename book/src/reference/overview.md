# API Reference

<p class="pm-kind"><b>Reference</b> · where each API surface is documented and how to generate it</p>

This book is a guided path; the crate-level API reference is generated straight from source, not duplicated into book chapters where it would drift. The one hand-kept exception is the daemon client's surface on the Rust page, small enough to keep true by reading.

- [Rust](rust.md): the workspace's own crates via rustdoc, and the client's surface (`Mesh`: attach, send, on, tap, run) by hand.
- The codec bindings for [Python](/docs/reference/python.html), [Node](/docs/reference/node.html) and [C](/docs/reference/c.html), and the WebAssembly codec, are the standard's and are documented in its book; the thin clients that speak to this daemon from Python and Node are run in [Two programs talk through the daemon](../examples/two-programs.md).

Every page below generates its reference locally from the code actually in this repository.

## Why generate instead of write

Rustdoc already carries the authoritative signatures, types, and per-item documentation the workspace's `missing_docs` lint enforces (see [Developer Onboarding](../contributing/onboarding.md)). A hand-written API reference in this book would either duplicate that content and drift out of sync, or omit detail the generated reference already has for free. Generating it is also how the gate keeps the pages honest: a generated page that differs from its generator fails the docs check.
