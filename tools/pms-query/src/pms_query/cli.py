# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""`pms-query` CLI — argparse façade over `pms_query.query`."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from typing import Optional

from . import Aggregation, QuerySpec, query
from .query import get_envelope


def _default_db() -> str:
    env = os.environ.get("PMS_BASKET_DB")
    if env:
        return env
    home = os.path.expanduser("~/.local/share/pms")
    return os.path.join(home, "basket.db")


def _parse_duration_ns(s: str) -> int:
    """Parse `30s`, `5min`, `1h`, `1d` into nanoseconds."""
    units = {
        "ns": 1,
        "us": 1_000,
        "ms": 1_000_000,
        "s": 1_000_000_000,
        "sec": 1_000_000_000,
        "min": 60 * 1_000_000_000,
        "m": 60 * 1_000_000_000,
        "h": 3600 * 1_000_000_000,
        "hr": 3600 * 1_000_000_000,
        "d": 86400 * 1_000_000_000,
    }
    digits = ""
    while s and (s[0].isdigit() or s[0] == "."):
        digits += s[0]
        s = s[1:]
    if not digits:
        raise ValueError(f"invalid duration: missing number")
    if s not in units:
        raise ValueError(f"invalid duration unit: {s!r}")
    return int(float(digits) * units[s])


def _build_spec(args: argparse.Namespace) -> QuerySpec:
    now_ns = int(time.time() * 1_000_000_000)
    spec = QuerySpec(
        channel=args.channel,
        envelope_type=args.type_id,
        type_name=args.type_name,
        origin=args.origin,
        limit=args.limit,
    )
    if args.since:
        spec.since_unix_nanos = now_ns - _parse_duration_ns(args.since)
    if args.until:
        spec.until_unix_nanos = now_ns - _parse_duration_ns(args.until)

    if args.aggregate:
        kind = args.aggregate
        if kind == "time-bucket":
            if not args.bucket_secs:
                raise SystemExit("--aggregate time-bucket requires --bucket-secs")
            spec.aggregate = Aggregation.time_bucket(args.bucket_secs)
        else:
            mapping = {
                "count": Aggregation.count,
                "count-by-channel": Aggregation.count_by_channel,
                "distinct-channels": Aggregation.distinct_channels,
                "distinct-types": Aggregation.distinct_types,
            }
            spec.aggregate = mapping[kind]()
    return spec


def _result_to_json(result) -> dict:
    if result.aggregate is not None:
        agg = result.aggregate
        # Custom dict-conversion for TimeBucket list
        if isinstance(agg, list) and agg and hasattr(agg[0], "bucket_start_unix_nanos"):
            return {
                "aggregate": [
                    {"bucket_start_unix_nanos": b.bucket_start_unix_nanos, "count": b.count}
                    for b in agg
                ]
            }
        return {"aggregate": agg}
    return {
        "rows": [
            {
                "id": r.id,
                "captured_at_unix_nanos": r.captured_at_unix_nanos,
                "channel": r.channel,
                "envelope_type": r.envelope_type,
                "type_name": r.type_name,
                "origin": r.origin,
                "payload_hash": r.payload_hash,
            }
            for r in result.rows
        ],
        "next_before": result.next_before,
    }


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        prog="pms-query",
        description="Structured queries over the Pulse Mesh basket SQLite store.",
    )
    p.add_argument(
        "--db",
        default=None,
        help=(
            "Path to the basket SQLite file. Defaults to $PMS_BASKET_DB or "
            "~/.local/share/pms/basket.db"
        ),
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    # `pms-query rows ...` and `pms-query agg ...` both end up in the same
    # parser; for ergonomics we expose a single command that accepts both
    # row filters and the optional --aggregate flag.
    q = sub.add_parser("rows", help="Return row results (default).")
    q.add_argument("--channel")
    q.add_argument("--type-id", type=int)
    q.add_argument("--type-name")
    q.add_argument("--origin")
    q.add_argument("--since", help="Time-window start as duration ago (`5min`, `1h`, `1d`)")
    q.add_argument("--until", help="Time-window end as duration ago")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument(
        "--aggregate",
        choices=[
            "count",
            "count-by-channel",
            "time-bucket",
            "distinct-channels",
            "distinct-types",
        ],
        default=None,
    )
    q.add_argument("--bucket-secs", type=int, default=None)

    g = sub.add_parser("get", help="Fetch a single envelope's payload by hex id.")
    g.add_argument("id_hex")

    args = p.parse_args(argv)
    db = args.db or _default_db()

    if args.cmd == "rows":
        spec = _build_spec(args)
        try:
            result = query(db, spec)
        except FileNotFoundError:
            print(f"error: no basket at {db}", file=sys.stderr)
            return 1
        print(json.dumps(_result_to_json(result), indent=2, default=str))
        return 0

    if args.cmd == "get":
        try:
            row = get_envelope(db, args.id_hex)
        except FileNotFoundError:
            print(f"error: no basket at {db}", file=sys.stderr)
            return 1
        if row is None:
            print(json.dumps({"error": "not found", "id": args.id_hex}, indent=2))
            return 1
        # base64-encode the payload for JSON-safe output
        row["payload_b64"] = base64.b64encode(row.pop("payload_bytes")).decode("ascii")
        print(json.dumps(row, indent=2, default=str))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
