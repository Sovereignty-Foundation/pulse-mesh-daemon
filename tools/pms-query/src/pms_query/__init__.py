# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""
Pulse Mesh basket query — structured queries over the basket SQLite store.

The dev-basket Rust crate writes envelopes into a SQLite file. This package
gives Python tools (and MCP agents) a typed API to run structured queries
against that file without exposing raw SQL.

Stdlib-only (sqlite3 + argparse + json). No third-party deps.
"""

from .query import (
    Aggregation,
    EnvelopeRow,
    QueryResult,
    QuerySpec,
    TimeBucket,
    query,
)

__all__ = [
    "Aggregation",
    "EnvelopeRow",
    "QueryResult",
    "QuerySpec",
    "TimeBucket",
    "query",
]
