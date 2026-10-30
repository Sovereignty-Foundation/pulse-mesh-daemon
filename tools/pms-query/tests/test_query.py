# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
#
# Tests for pms-query: its queries, its aggregations and its command line,
# against basket files made here the way the daemon makes its own. The
# daemon's basket is mesh-basket's SQLite file, and its schema is the SQL
# the crate's `Basket::open` runs, the `SCHEMA_V1` constant: the tests read
# that constant from mesh/mesh-basket/src/lib.rs rather than restate it, so
# the file here is the daemon's whatever the crate changes, and a change
# that drops or renames a column pms-query reads fails here. Rows go in with
# the statement `Basket::insert` runs.
#
# Matching is exact, as in mesh-basket's own queries: a channel, a type
# name or an origin matches only itself, never as a glob, a LIKE pattern,
# a prefix or in another case.
#
# Run from tools/pms-query:
#
#     python3 -m unittest discover -s tests
#
# Standard library only; nothing needs installing and no daemon needs
# running.

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TOOL = Path(__file__).resolve().parents[1]
REPO = TOOL.parents[1]
sys.path.insert(0, str(TOOL / "src"))

from pms_query import Aggregation, QuerySpec, TimeBucket, query  # noqa: E402
from pms_query.cli import _default_db, _parse_duration_ns, main  # noqa: E402
from pms_query.query import get_envelope  # noqa: E402

BASKET_RS = REPO / "mesh" / "mesh-basket" / "src" / "lib.rs"
# The statement Basket::insert runs.
INSERT = """INSERT OR REPLACE INTO envelopes
    (id, captured_at_unix_nanos, channel, envelope_type, type_name, origin, payload_hash, payload_bytes)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"""
SECOND = 1_000_000_000
# A capture time on a minute boundary, so that the 60-second buckets are
# known: 1,700,000,040 seconds is 28,333,334 minutes.
BASE = 1_700_000_040 * SECOND


def basket_schema():
    """The SQL mesh-basket's Basket::open runs on the daemon's file."""
    source = BASKET_RS.read_text(encoding="utf-8")
    m = re.search(r'const SCHEMA_V1: &str = r#"(.*?)"#;', source, re.S)
    if m is None:
        raise AssertionError(
            f"no SCHEMA_V1 in {BASKET_RS.relative_to(REPO)}: read the schema from "
            "where mesh-basket keeps it now"
        )
    return m.group(1)


def row(captured, channel, envelope_type, type_name, origin, payload):
    """A row as Basket::insert writes it. The id is the envelope's content
    address and the hash BLAKE3's first 16 bytes; pms-query reads both
    back without computing either, so hex strings of the same length stand
    in for them."""
    key = f"{captured}|{channel}|{envelope_type}|{type_name}|{origin}".encode() + payload
    return (
        hashlib.sha256(key).hexdigest()[:32],
        captured,
        channel,
        envelope_type,
        type_name,
        origin,
        hashlib.sha256(payload).hexdigest()[:32],
        payload,
    )


def make_basket(path, rows):
    """A basket file at `path` holding `rows`, made as the daemon makes its
    own: Basket::open's journal mode and schema, then Basket::insert's
    statement."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(basket_schema())
        conn.executemany(INSERT, rows)
        conn.commit()
    finally:
        conn.close()
    return str(path)


# Newest last. Two channels differ from jobs/a only in a character a glob or
# a LIKE pattern would match.
ROWS = [
    row(BASE, "jobs/a", 1, None, "worker@1", b"a1"),
    row(BASE + 10 * SECOND, "jobs/a", 1, "job.created", "worker@1", b"a2"),
    row(BASE + 20 * SECOND, "jobs/b", 2, "job.done", "worker@2", b"b1"),
    row(BASE + 65 * SECOND, "jobs/a", 2, "job.done", "worker@2", b"a3"),
    row(BASE + 130 * SECOND, "metrics", 3, None, "probe@9", b"\x00\xff"),
    row(BASE + 131 * SECOND, "jobs_a", 1, None, "worker@1", b"underscore"),
]


def ids(result):
    return [r.id for r in result.rows]


def ids_of(*indexes):
    return [ROWS[i][0] for i in indexes]


def run_cli(*argv):
    """main(argv): its status, and what it printed to stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(list(argv))
    return status, out.getvalue(), err.getvalue()


class BasketTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = make_basket(Path(self.dir.name) / "basket.db", ROWS)

    def rows(self, **spec):
        return query(self.db, QuerySpec(**spec))

    def aggregate(self, agg, **spec):
        return query(self.db, QuerySpec(aggregate=agg, **spec)).aggregate


class SchemaTest(BasketTest):
    def test_the_basket_has_the_columns_pms_query_reads(self):
        conn = sqlite3.connect(self.db)
        try:
            columns = [c[1] for c in conn.execute("PRAGMA table_info(envelopes)")]
        finally:
            conn.close()
        self.assertEqual(
            columns,
            [
                "id",
                "captured_at_unix_nanos",
                "channel",
                "envelope_type",
                "type_name",
                "origin",
                "payload_hash",
                "payload_bytes",
            ],
        )


class RowsTest(BasketTest):
    def test_rows_come_newest_first_with_the_page_mark(self):
        result = self.rows()
        self.assertEqual(ids(result), ids_of(5, 4, 3, 2, 1, 0))
        self.assertIsNone(result.aggregate)
        self.assertEqual(result.next_before, BASE)
        first = result.rows[-1]
        self.assertEqual(
            (first.captured_at_unix_nanos, first.channel, first.envelope_type, first.type_name, first.origin),
            (BASE, "jobs/a", 1, None, "worker@1"),
        )
        self.assertEqual(first.payload_hash, ROWS[0][6])

    def test_a_channel_matches_only_itself(self):
        self.assertEqual(ids(self.rows(channel="jobs/a")), ids_of(3, 1, 0))
        self.assertEqual(ids(self.rows(channel="jobs_a")), ids_of(5))

    def test_a_channel_is_not_a_pattern(self):
        for pattern in ["jobs/*", "jobs/?", "jobs/%", "jobs/_", "jobs", "jobs/", "JOBS/A", "jobs/a "]:
            with self.subTest(channel=pattern):
                self.assertEqual(self.rows(channel=pattern).rows, [])
                self.assertEqual(self.aggregate(Aggregation.count(), channel=pattern), 0)

    def test_type_name_and_origin_match_only_themselves(self):
        self.assertEqual(ids(self.rows(type_name="job.done")), ids_of(3, 2))
        self.assertEqual(ids(self.rows(origin="worker@1")), ids_of(5, 1, 0))
        for spec in [{"type_name": "job"}, {"type_name": "job.*"}, {"origin": "worker@"}, {"origin": "worker@%"}]:
            with self.subTest(**spec):
                self.assertEqual(self.rows(**spec).rows, [])

    def test_envelope_type(self):
        self.assertEqual(ids(self.rows(envelope_type=2)), ids_of(3, 2))
        self.assertEqual(self.rows(envelope_type=9).rows, [])

    def test_filters_combine_with_and(self):
        self.assertEqual(ids(self.rows(channel="jobs/a", envelope_type=2)), ids_of(3))
        self.assertEqual(ids(self.rows(origin="worker@1", type_name="job.created")), ids_of(1))
        self.assertEqual(self.rows(channel="jobs/b", origin="worker@1").rows, [])

    def test_the_window_holds_its_start_and_not_its_end(self):
        result = self.rows(since_unix_nanos=BASE + 10 * SECOND, until_unix_nanos=BASE + 65 * SECOND)
        self.assertEqual(ids(result), ids_of(2, 1))

    def test_pages_follow_next_before(self):
        pages, until = [], None
        while True:
            result = self.rows(limit=2, until_unix_nanos=until)
            if not result.rows:
                break
            pages.append(ids(result))
            until = result.next_before
        self.assertEqual(pages, [ids_of(5, 4), ids_of(3, 2), ids_of(1, 0)])
        self.assertIsNone(self.rows(until_unix_nanos=BASE).next_before)

    def test_get_returns_one_envelope_with_its_payload(self):
        envelope = get_envelope(self.db, ROWS[4][0])
        self.assertEqual(
            envelope,
            {
                "id": ROWS[4][0],
                "captured_at_unix_nanos": BASE + 130 * SECOND,
                "channel": "metrics",
                "envelope_type": 3,
                "type_name": None,
                "origin": "probe@9",
                "payload_hash": ROWS[4][6],
                "payload_bytes": b"\x00\xff",
            },
        )
        self.assertIsNone(get_envelope(self.db, "0" * 32))
        self.assertIsNone(get_envelope(self.db, ROWS[4][0][:8]))


class AggregateTest(BasketTest):
    def test_count(self):
        self.assertEqual(self.aggregate(Aggregation.count()), 6)
        self.assertEqual(self.aggregate(Aggregation.count(), channel="jobs/a"), 3)

    def test_count_by_channel_puts_the_largest_first(self):
        counts = self.aggregate(Aggregation.count_by_channel())
        self.assertEqual(counts[0], ("jobs/a", 3))
        self.assertEqual(sorted(counts[1:]), [("jobs/b", 1), ("jobs_a", 1), ("metrics", 1)])
        by_origin = self.aggregate(Aggregation.count_by_channel(), origin="worker@2")
        self.assertEqual(sorted(by_origin), [("jobs/a", 1), ("jobs/b", 1)])

    def test_time_buckets(self):
        self.assertEqual(
            self.aggregate(Aggregation.time_bucket(60)),
            [
                TimeBucket(bucket_start_unix_nanos=BASE, count=3),
                TimeBucket(bucket_start_unix_nanos=BASE + 60 * SECOND, count=1),
                TimeBucket(bucket_start_unix_nanos=BASE + 120 * SECOND, count=2),
            ],
        )
        self.assertEqual(
            self.aggregate(Aggregation.time_bucket(60), channel="jobs/a"),
            [
                TimeBucket(bucket_start_unix_nanos=BASE, count=2),
                TimeBucket(bucket_start_unix_nanos=BASE + 60 * SECOND, count=1),
            ],
        )

    def test_a_time_bucket_needs_a_positive_size(self):
        for secs in [0, -60, None]:
            with self.subTest(bucket_secs=secs):
                with self.assertRaisesRegex(ValueError, "positive bucket_secs"):
                    self.aggregate(Aggregation(kind="time_bucket", bucket_secs=secs))

    def test_distinct_channels_are_sorted(self):
        self.assertEqual(self.aggregate(Aggregation.distinct_channels()), ["jobs/a", "jobs/b", "jobs_a", "metrics"])
        self.assertEqual(self.aggregate(Aggregation.distinct_channels(), envelope_type=1), ["jobs/a", "jobs_a"])

    def test_distinct_types_leave_out_untyped_envelopes(self):
        self.assertEqual(self.aggregate(Aggregation.distinct_types()), ["job.created", "job.done"])
        self.assertEqual(self.aggregate(Aggregation.distinct_types(), origin="worker@2"), ["job.done"])
        self.assertEqual(self.aggregate(Aggregation.distinct_types(), channel="metrics"), [])

    def test_an_unknown_aggregation_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown aggregation kind: median"):
            self.aggregate(Aggregation(kind="median"))


class LimitTest(unittest.TestCase):
    def test_the_limit_is_50_by_default_and_at_most_5000(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [row(BASE + i, "load", 1, None, "n@1", i.to_bytes(4, "little")) for i in range(5001)]
            db = make_basket(Path(d) / "basket.db", rows)
            for limit, returned in [(None, 50), (0, 50), (-1, 50), (7, 7), (5000, 5000), (5001, 5000)]:
                with self.subTest(limit=limit):
                    spec = QuerySpec() if limit is None else QuerySpec(limit=limit)
                    result = query(db, spec)
                    self.assertEqual(len(result.rows), returned)
                    self.assertEqual(result.rows[0].captured_at_unix_nanos, BASE + 5000)


class MissingBasketTest(unittest.TestCase):
    def test_a_missing_basket_is_an_error_and_is_not_made(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "basket.db")
            with self.assertRaisesRegex(FileNotFoundError, "no basket at"):
                query(db, QuerySpec())
            with self.assertRaisesRegex(FileNotFoundError, "no basket at"):
                get_envelope(db, "0" * 32)
            for argv in [("rows",), ("get", "0" * 32)]:
                with self.subTest(argv=argv):
                    self.assertEqual(run_cli("--db", db, *argv), (1, "", f"error: no basket at {db}\n"))
            self.assertEqual(os.listdir(d), [])


class CliTest(BasketTest):
    def test_rows_print_json(self):
        status, out, _ = run_cli("--db", self.db, "rows", "--channel", "jobs/a", "--limit", "2")
        self.assertEqual(status, 0)
        printed = json.loads(out)
        self.assertEqual([r["id"] for r in printed["rows"]], ids_of(3, 1))
        self.assertEqual(printed["next_before"], BASE + 10 * SECOND)
        self.assertEqual(
            printed["rows"][0],
            {
                "id": ROWS[3][0],
                "captured_at_unix_nanos": BASE + 65 * SECOND,
                "channel": "jobs/a",
                "envelope_type": 2,
                "type_name": "job.done",
                "origin": "worker@2",
                "payload_hash": ROWS[3][6],
            },
        )

    def test_the_glob_of_pms_tap_matches_nothing_here(self):
        status, out, _ = run_cli("--db", self.db, "rows", "--channel", "jobs/*")
        self.assertEqual((status, json.loads(out)), (0, {"rows": [], "next_before": None}))

    def test_filters_and_aggregates(self):
        cases = [
            (["--type-id", "2", "--aggregate", "count"], 2),
            (["--type-name", "job.done", "--origin", "worker@2", "--aggregate", "count"], 2),
            (["--aggregate", "count-by-channel", "--channel", "metrics"], [["metrics", 1]]),
            (["--aggregate", "distinct-channels", "--origin", "worker@2"], ["jobs/a", "jobs/b"]),
            (["--aggregate", "distinct-types"], ["job.created", "job.done"]),
            # 90 does not divide BASE: the first bucket starts 30 s before it.
            (
                ["--aggregate", "time-bucket", "--bucket-secs", "90"],
                [
                    {"bucket_start_unix_nanos": BASE - 30 * SECOND, "count": 3},
                    {"bucket_start_unix_nanos": BASE + 60 * SECOND, "count": 3},
                ],
            ),
        ]
        for args, aggregate in cases:
            with self.subTest(args=args):
                status, out, _ = run_cli("--db", self.db, "rows", *args)
                self.assertEqual((status, json.loads(out)), (0, {"aggregate": aggregate}))

    def test_a_time_bucket_needs_its_size(self):
        with self.assertRaisesRegex(SystemExit, "requires --bucket-secs"):
            run_cli("--db", self.db, "rows", "--aggregate", "time-bucket")

    def test_get_prints_the_payload_in_base64(self):
        status, out, _ = run_cli("--db", self.db, "get", ROWS[4][0])
        self.assertEqual(status, 0)
        printed = json.loads(out)
        self.assertEqual(printed["payload_b64"], base64.b64encode(b"\x00\xff").decode())
        self.assertEqual((printed["id"], printed["channel"]), (ROWS[4][0], "metrics"))
        self.assertNotIn("payload_bytes", printed)

    def test_get_of_an_unknown_id_fails(self):
        status, out, _ = run_cli("--db", self.db, "get", "f" * 32)
        self.assertEqual((status, json.loads(out)), (1, {"error": "not found", "id": "f" * 32}))

    def test_the_basket_comes_from_pms_basket_db_without_db(self):
        with mock.patch.dict(os.environ, {"PMS_BASKET_DB": self.db}):
            self.assertEqual(_default_db(), self.db)
            status, out, _ = run_cli("rows", "--aggregate", "count")
        self.assertEqual((status, json.loads(out)), (0, {"aggregate": 6}))
        with mock.patch.dict(os.environ, {"PMS_BASKET_DB": ""}):
            self.assertEqual(_default_db(), os.path.expanduser("~/.local/share/pms/basket.db"))


class WindowFromNowTest(unittest.TestCase):
    def test_since_and_until_are_durations_before_now(self):
        now = time.time_ns()
        with tempfile.TemporaryDirectory() as d:
            db = make_basket(
                Path(d) / "basket.db",
                [
                    row(now - 10 * SECOND, "w", 1, None, "n@1", b"10 s ago"),
                    row(now - 120 * SECOND, "w", 1, None, "n@1", b"2 min ago"),
                    row(now - 7200 * SECOND, "w", 1, None, "n@1", b"2 h ago"),
                ],
            )
            for args, count in [
                (["--since", "5min"], 2),
                (["--since", "3h"], 3),
                (["--since", "1h", "--until", "1min"], 1),
                (["--until", "1h"], 1),
            ]:
                with self.subTest(args=args):
                    status, out, _ = run_cli("--db", db, "rows", "--aggregate", "count", *args)
                    self.assertEqual((status, json.loads(out)), (0, {"aggregate": count}))


class DurationTest(unittest.TestCase):
    def test_durations(self):
        for text, nanos in [
            ("9ns", 9),
            ("7us", 7_000),
            ("250ms", 250_000_000),
            ("30s", 30 * SECOND),
            ("30sec", 30 * SECOND),
            ("5m", 300 * SECOND),
            ("5min", 300 * SECOND),
            ("1.5h", 5400 * SECOND),
            ("2hr", 7200 * SECOND),
            ("1d", 86400 * SECOND),
        ]:
            with self.subTest(text=text):
                self.assertEqual(_parse_duration_ns(text), nanos)

    def test_a_duration_needs_a_number_and_a_unit(self):
        for text, reason in [("", "missing number"), ("min", "missing number"), ("5", "unit"), ("5x", "unit"), ("5 min", "unit")]:
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, reason):
                    _parse_duration_ns(text)


if __name__ == "__main__":
    unittest.main()
