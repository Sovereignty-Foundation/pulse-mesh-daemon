# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Structured query DSL over the basket SQLite store."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

# =============================================================================
# Aggregation modes
# =============================================================================


@dataclass
class Aggregation:
    """Aggregation kind. Mirrors the Rust crate's `dev_basket::Aggregation`."""

    kind: str  # one of: count, count_by_channel, time_bucket, distinct_channels, distinct_types
    bucket_secs: Optional[int] = None  # only used for time_bucket

    @classmethod
    def count(cls) -> "Aggregation":
        return cls(kind="count")

    @classmethod
    def count_by_channel(cls) -> "Aggregation":
        return cls(kind="count_by_channel")

    @classmethod
    def time_bucket(cls, secs: int) -> "Aggregation":
        return cls(kind="time_bucket", bucket_secs=secs)

    @classmethod
    def distinct_channels(cls) -> "Aggregation":
        return cls(kind="distinct_channels")

    @classmethod
    def distinct_types(cls) -> "Aggregation":
        return cls(kind="distinct_types")


# =============================================================================
# Spec / Result types
# =============================================================================


@dataclass
class QuerySpec:
    channel: Optional[str] = None
    envelope_type: Optional[int] = None
    type_name: Optional[str] = None
    origin: Optional[str] = None
    since_unix_nanos: Optional[int] = None
    until_unix_nanos: Optional[int] = None
    limit: int = 50
    aggregate: Optional[Aggregation] = None


@dataclass
class EnvelopeRow:
    id: str
    captured_at_unix_nanos: int
    channel: str
    envelope_type: int
    type_name: Optional[str]
    origin: str
    payload_hash: str
    # Note: we DO NOT include payload_bytes in the default row shape —
    # large blobs would defeat the basket's purpose (small, structured
    # results). Use `pms-query get <id>` to fetch a single envelope's
    # payload explicitly.


@dataclass
class TimeBucket:
    bucket_start_unix_nanos: int
    count: int


@dataclass
class QueryResult:
    rows: List[EnvelopeRow] = field(default_factory=list)
    aggregate: Optional[
        Union[int, List[Tuple[str, int]], List[TimeBucket], List[str]]
    ] = None
    next_before: Optional[int] = None


# =============================================================================
# query()
# =============================================================================


def _open(db_path: str) -> sqlite3.Connection:
    # sqlite3 makes the file when it is missing; a query must find a basket,
    # not leave an empty file where the daemon's would be.
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"no basket at {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def query(db_path: str, spec: QuerySpec) -> QueryResult:
    """Execute a structured query against the basket SQLite file.

    Raises FileNotFoundError when there is no file at `db_path`."""
    conn = _open(db_path)
    try:
        if spec.aggregate is not None:
            return _run_aggregate(conn, spec, spec.aggregate)
        return _run_rows(conn, spec)
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# WHERE-clause builder (shared between rows + aggregate paths)
# -----------------------------------------------------------------------------


def _build_where(spec: QuerySpec) -> Tuple[str, List[object]]:
    clauses: List[str] = []
    params: List[object] = []
    if spec.channel is not None:
        clauses.append("channel = ?")
        params.append(spec.channel)
    if spec.envelope_type is not None:
        clauses.append("envelope_type = ?")
        params.append(spec.envelope_type)
    if spec.type_name is not None:
        clauses.append("type_name = ?")
        params.append(spec.type_name)
    if spec.origin is not None:
        clauses.append("origin = ?")
        params.append(spec.origin)
    if spec.since_unix_nanos is not None:
        clauses.append("captured_at_unix_nanos >= ?")
        params.append(spec.since_unix_nanos)
    if spec.until_unix_nanos is not None:
        clauses.append("captured_at_unix_nanos < ?")
        params.append(spec.until_unix_nanos)
    if not clauses:
        return "", params
    return "WHERE " + " AND ".join(clauses), params


def _clamp_limit(n: int) -> int:
    if n <= 0:
        return 50
    if n > 5000:
        return 5000
    return n


# -----------------------------------------------------------------------------
# Row mode
# -----------------------------------------------------------------------------


def _run_rows(conn: sqlite3.Connection, spec: QuerySpec) -> QueryResult:
    where_sql, params = _build_where(spec)
    sql = f"""
        SELECT id, captured_at_unix_nanos, channel, envelope_type,
               type_name, origin, payload_hash
        FROM envelopes
        {where_sql}
        ORDER BY captured_at_unix_nanos DESC
        LIMIT {_clamp_limit(spec.limit)}
    """
    cur = conn.execute(sql, params)
    rows = [
        EnvelopeRow(
            id=row["id"],
            captured_at_unix_nanos=row["captured_at_unix_nanos"],
            channel=row["channel"],
            envelope_type=row["envelope_type"],
            type_name=row["type_name"],
            origin=row["origin"],
            payload_hash=row["payload_hash"],
        )
        for row in cur.fetchall()
    ]
    next_before = rows[-1].captured_at_unix_nanos if rows else None
    return QueryResult(rows=rows, aggregate=None, next_before=next_before)


# -----------------------------------------------------------------------------
# Aggregate mode
# -----------------------------------------------------------------------------


def _run_aggregate(
    conn: sqlite3.Connection, spec: QuerySpec, agg: Aggregation
) -> QueryResult:
    where_sql, params = _build_where(spec)
    if agg.kind == "count":
        sql = f"SELECT COUNT(*) AS n FROM envelopes {where_sql}"
        n = conn.execute(sql, params).fetchone()["n"]
        return QueryResult(rows=[], aggregate=int(n))
    if agg.kind == "count_by_channel":
        sql = f"""
            SELECT channel, COUNT(*) AS n FROM envelopes {where_sql}
            GROUP BY channel ORDER BY n DESC
        """
        rows = [(r["channel"], int(r["n"])) for r in conn.execute(sql, params)]
        return QueryResult(rows=[], aggregate=rows)
    if agg.kind == "time_bucket":
        if not agg.bucket_secs or agg.bucket_secs <= 0:
            raise ValueError("time_bucket requires positive bucket_secs")
        bucket_ns = agg.bucket_secs * 1_000_000_000
        sql = f"""
            SELECT (captured_at_unix_nanos / ?) * ? AS bucket, COUNT(*) AS n
            FROM envelopes {where_sql}
            GROUP BY bucket ORDER BY bucket ASC
        """
        rows = [
            TimeBucket(bucket_start_unix_nanos=int(r["bucket"]), count=int(r["n"]))
            for r in conn.execute(sql, [bucket_ns, bucket_ns] + params)
        ]
        return QueryResult(rows=[], aggregate=rows)
    if agg.kind == "distinct_channels":
        sql = f"SELECT DISTINCT channel FROM envelopes {where_sql} ORDER BY channel"
        rows = [r["channel"] for r in conn.execute(sql, params)]
        return QueryResult(rows=[], aggregate=rows)
    if agg.kind == "distinct_types":
        if where_sql:
            sql = f"SELECT DISTINCT type_name FROM envelopes {where_sql} AND type_name IS NOT NULL ORDER BY type_name"
        else:
            sql = "SELECT DISTINCT type_name FROM envelopes WHERE type_name IS NOT NULL ORDER BY type_name"
        rows = [r["type_name"] for r in conn.execute(sql, params)]
        return QueryResult(rows=[], aggregate=rows)
    raise ValueError(f"unknown aggregation kind: {agg.kind}")


# -----------------------------------------------------------------------------
# Convenience: fetch one envelope's full payload by id
# -----------------------------------------------------------------------------


def get_envelope(db_path: str, id_hex: str) -> Optional[dict]:
    """Fetch a single envelope row (including payload_bytes) by hex id.

    Raises FileNotFoundError when there is no file at `db_path`."""
    conn = _open(db_path)
    try:
        cur = conn.execute(
            "SELECT id, captured_at_unix_nanos, channel, envelope_type, "
            "type_name, origin, payload_hash, payload_bytes "
            "FROM envelopes WHERE id = ?",
            (id_hex,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "captured_at_unix_nanos": row["captured_at_unix_nanos"],
            "channel": row["channel"],
            "envelope_type": row["envelope_type"],
            "type_name": row["type_name"],
            "origin": row["origin"],
            "payload_hash": row["payload_hash"],
            "payload_bytes": bytes(row["payload_bytes"]),
        }
    finally:
        conn.close()
