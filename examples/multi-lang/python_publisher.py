# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""
Multi-language template — Python publisher.

Pairs with `node_subscriber.js`. Both processes attach to the same
local mesh-hub daemon and exchange envelopes through the v0 Universal
Port Protocol. Same surface across languages — no per-language schema
glue needed.

Run order:

    # Terminal 1
    cargo run -p mesh-hub --release

    # Terminal 2
    cd clients/pms-node-thin && npm install
    node examples/multi-lang/node_subscriber.js

    # Terminal 3
    cd clients/pms-py-thin && pip install -e .
    python examples/multi-lang/python_publisher.py
"""

import sys
import time

# Add the thin-client repo so we can import without installing globally.
sys.path.insert(0, "../../clients/pms-py-thin")
import pms


def main() -> None:
    mesh = pms.attach("py-publisher")
    print("py: attached")
    for i in range(10):
        payload = f"hello-from-python-{i}".encode("utf-8")
        env_id = mesh.send("multi-lang/demo", payload)
        print(f"py: sent {payload!r} as {env_id[:8]}")
        time.sleep(1.0)
    mesh.detach()
    print("py: done")


if __name__ == "__main__":
    main()
