# Pulse Mesh — task runner.
#
# Why `just` and not Make: parameterised recipes, no implicit dependency
# magic, no tab/space minefield, runs the same on macOS and Linux. Install
# with `brew install just` or `cargo install just`.
#
# Conventions:
#   - Every recipe runs from the workspace root regardless of where you
#     invoke it from.
#   - The publish gate is scripts/gate.sh, which needs no just; `just check`
#     runs it. The other recipes each run one step, most of them a check
#     the gate also runs.
#   - CI (.gitea/workflows) runs scripts/gate.sh too, so `just check`
#     reproduces it locally: `just check --full --skip
#     linux-test-1g,linux-test-64m,linux-net,linux-clippy` is the push
#     job's run.
#   - Recipes never assume a particular forge or remote name.

set shell := ["bash", "-cu"]

# Where the tree keeps the surfaces that are not workspace members: under
# peripheral/ in the integrated tree, at the top level in a repository cut
# from it (the standard's bindings and fuzz harness, the daemon's clients).
bindings := if path_exists(justfile_directory() / "peripheral/bindings") == "true" { "peripheral/bindings" } else { "bindings" }
fuzz := if path_exists(justfile_directory() / "fuzz") == "true" { "fuzz" } else { "fuzz" }
thin := if path_exists(justfile_directory() / "peripheral/bindings/dev-thin") == "true" { "peripheral/bindings/dev-thin" } else { "clients" }

# Default: list everything available.
default:
    @just --list --unsorted

# ─────────────────────────── core dev loop ───────────────────────────

# Workspace tests in release mode; the gate's test check runs them in the
# debug profile.
test:
    cargo test --workspace --release

# Format check and clippy -D warnings on the workspace: the gate's clippy
# check, and its fmt check less the fuzz harness.
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Reformat in place (only run locally, never in CI).
fmt:
    cargo fmt --all

# Release build of the whole workspace.
build:
    cargo build --workspace --release

# Rustdoc with the warnings the gate's rustdoc check denies.
doc:
    RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links -D rustdoc::private-intra-doc-links" \
        cargo doc --workspace --no-deps

# Feature matrix: every feature on, and the daemon without its defaults
# (the gate's check-all-features, clippy-all-features and hub-no-default
# checks). On arm64 this compiles the wfe backend; umwait/mwaitx need an
# x86_64 host or `--target x86_64-unknown-linux-gnu` (`just cross-check`).
check-features:
    cargo check --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo check -p mesh-hub --no-default-features

# Supply chain: advisories, bans and sources, with every feature on (the
# gate's deny check).
deny:
    cargo deny --all-features check advisories bans sources

# The fuzz harness builds on nightly with cargo-fuzz. A target runs as
# `cargo +nightly fuzz run <target> --fuzz-dir <the harness>`, which is
# what `just fuzz` does.
check-fuzz:
    cargo +nightly fuzz build --fuzz-dir {{fuzz}}

# Fuzz with scripts/fuzz.sh: `just fuzz` runs every target for 60 seconds,
# `just fuzz <target> [seconds]` one; the first crash stops the run and
# names the input that caused it.
fuzz *ARGS:
    scripts/fuzz.sh {{ARGS}}

# The book: version, SUMMARY, link, term and generated-page checks, `mdbook build`,
# then the tutorials' smoke run (the gate's docs check).
docs:
    scripts/docs/check.sh

# The thin clients' tests: the port protocol's golden frames under
# mesh/mesh-port-protocol/fixtures, held against the Python and Node
# clients, and the clients' own behaviour. Python needs websocket-client;
# Node needs nothing installed (mirrors CI).
thin-clients:
    cd {{thin}}/pms-py-thin && python3 -m unittest
    cd {{thin}}/pms-node-thin && node --test

# The architecture, executable: tiers, ring import points, consumers, the
# module table against the four manifests, non_exhaustive growth points and
# the workspace's dependency pins, checked from cargo metadata; the check
# then checks itself with a planted violation per rule (mirrors CI).
arch-check:
    python3 scripts/arch-check.py
    python3 scripts/arch-check.py --self-test

# License gate: the proprietary placeholder notice in LICENSE and STATUS.md,
# and LicenseRef-Proprietary on every source file, until the release license
# is placed. The same script runs as the pre-push hook (see `install-hooks`).
license-gate:
    scripts/license-gate.sh

# Enable the repository's git hooks for this clone (once per clone).
install-hooks:
    git config core.hooksPath .githooks
    @echo "pre-push hook enabled: scripts/license-gate.sh runs before every push"

# A cargo command on Linux, in a Docker container, against this worktree
# (default `test --workspace`; SHM_SIZE sets /dev/shm, 1g by default).
linux-verify *ARGS:
    scripts/linux-verify.sh {{ARGS}}

# Clippy for x86_64 Linux from any host, on every crate that links no
# native C library.
cross-check:
    scripts/cross-check.sh

# The publish gate, scripts/gate.sh: `just check` is the gate a change passes
# before it merges, `just check --quick` the per-commit subset, and
# `just check --full` adds the bindings, the fuzz build, the thin clients and
# the Linux and x86 legs; `--skip <check>,...` leaves checks out. The
# script's header lists every check.
check *ARGS:
    scripts/gate.sh {{ARGS}}

# Install `pms`, `mesh-hub` and `pms-mcp` into ~/.cargo/bin so they run outside the workspace.
install:
    cargo install --path tools/pms --locked
    cargo install --path mesh/mesh-hub --locked
    cargo install --path tools/pms-mcp --locked

# ─────────────────────────── daemon ───────────────────────────

# Run the mesh-hub daemon on default sockets. Ctrl-C to stop.
hub:
    cargo run --release -p mesh-hub

# Quick toolchain + environment doctor (the pms CLI's own check).
doctor:
    cargo run --release --quiet -p pms-cli -- doctor

# ─────────────────────────── housekeeping ───────────────────────────

# Wipe `target/` and any local SHM region this workspace created.
clean:
    cargo clean
    -find /dev/shm -maxdepth 1 -name 'pms-*' -user $(whoami) -delete 2>/dev/null || true

# Update every dependency in the workspace's Cargo.lock to the newest
# version its semver requirement allows. The bindings and the fuzz harness
# keep lockfiles of their own, updated from their directories.
update:
    cargo update
