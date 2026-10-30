# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
#
# Tests for the thin Python client: its payload codec, which accepts only
# the padded standard base64 the daemon and the Rust client accept; what
# the client does with an event whose payload is in any other form, or a
# frame with a field of the wrong type; how it survives a callback that
# raises, replies nobody waits for, a subscribe that times out, and the end
# of its reader; how it joins a message's fragments, however they split it;
# and the bounds it keeps: on the events waiting for the callbacks, on the
# messages it reads, their bytes, frames and time, on the time an attach
# takes, and on the silence it takes from the daemon.
#
# Run from clients/pms-py-thin:
#
#     python3 -m unittest -v
#
# Nothing needs installing and no daemon needs running: a fake stands in
# for websocket-client's WebSocket, which the client opens the connection
# and writes with, and writes the daemon's frames into a socket pair,
# which the client reads itself.

import base64
import contextlib
import json
import os
import queue
import random
import socket
import threading
import time
import tracemalloc
import types
import unittest
from unittest import mock

import pms

# RFC 4648 §10, and one more.
VECTORS = [
    (b"", ""),
    (b"f", "Zg=="),
    (b"fo", "Zm8="),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy"),
    (b"hello", "aGVsbG8="),
]

# Every form the daemon and the Rust client refuse, by the fault.
REFUSED = {
    "padding missing": ["aGk", "Zg", "Zg=", "aGVsbG8", "Zm9vY"],
    "padding in mid-string": ["AA==AA==", "Zm8=Zm8=", "AA=A", "=AAA", "AAAA=AAA"],
    "more padding than the length needs": ["A===", "====", "AAAA====", "Zg==="],
    "whitespace": [" Zg==", "Zm\r\nYmFy", "Zm9v\tZg==", "aGVsbG8=\n"],
    "the URL-safe alphabet": ["Zm-v", "Zm_v"],
    "bytes outside the alphabet": ["Zm9*", "\0AAA", "Zmé="],
    "bits set after the last byte": ["Zh==", "Zm9=", "AB==", "AAB=", "Zm9vZh=="],
}


def noise(seed, length):
    """Reproducible bytes."""
    return random.Random(seed).randbytes(length)


class DecodePayloadTest(unittest.TestCase):
    def test_accepts_padded_standard_base64(self):
        for data, text in VECTORS:
            self.assertEqual(pms.decode_payload(text), data, text)

    def test_round_trips_every_length_from_0_to_64(self):
        for length in range(65):
            for data in (bytes(length), b"\xff" * length, noise(length, length)):
                self.assertEqual(pms.decode_payload(pms.encode_payload(data)), data)

    def test_refuses_every_other_form(self):
        for fault, texts in REFUSED.items():
            for text in texts:
                with self.subTest(fault=fault, text=text):
                    with self.assertRaises(ValueError):
                        pms.decode_payload(text)

    def test_refuses_what_a_mime_encoder_writes(self):
        # base64.encodebytes breaks lines every 76 characters and ends with
        # a line break.
        self.assertRaises(ValueError, pms.decode_payload, "aGVsbG8=\n")
        wrapped = base64.encodebytes(noise(7, 60)).decode("ascii")
        self.assertIn("\n", wrapped.rstrip("\n"))
        self.assertRaises(ValueError, pms.decode_payload, wrapped)

    def test_refuses_what_is_not_a_string(self):
        for value in (None, 5, b"Zg==", ["Zg=="], {"payload": "Zg=="}):
            with self.subTest(value=value):
                self.assertRaises(ValueError, pms.decode_payload, value)


class EncodePayloadTest(unittest.TestCase):
    def test_writes_padded_standard_base64(self):
        for data, text in VECTORS:
            self.assertEqual(pms.encode_payload(data), text)

    def test_writes_only_the_one_accepted_form(self):
        for length in range(65):
            data = noise(100 + length, length)
            text = pms.encode_payload(data)
            self.assertEqual(len(text), (length + 2) // 3 * 4)
            self.assertEqual(text.count("="), (3 - length % 3) % 3)
            self.assertEqual(pms.decode_payload(text), data)

    def test_takes_any_bytes_like_value(self):
        for data in (b"hi", bytearray(b"hi"), memoryview(b"hi")):
            self.assertEqual(pms.encode_payload(data), "aGk=")


def frame(payload=b"", opcode=0x1, fin=True, rsv=0, mask=None, length=None):
    """One frame as a daemon writes it (RFC 6455 §5.2). `length` announces
    another length than the payload's, and `mask` masks it, which no
    server may."""
    n = len(payload) if length is None else length
    head = bytes([(0x80 if fin else 0) | rsv << 4 | opcode])
    masked = 0x80 if mask else 0
    if n < 126:
        head += bytes([masked | n])
    elif n < 1 << 16:
        head += bytes([masked | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([masked | 127]) + n.to_bytes(8, "big")
    if mask:
        head += mask
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return head + payload


def split(rng, message, opcode=0x1, pieces=None):
    """`message` as frames a daemon, or anything between, may split it
    into: `pieces` of them (a random number if None), cut at random, empty
    ones among them, and a ping or a pong now and then between two, which
    RFC 6455 allows. Returns the frames' bytes, and what the reader hands
    on for them in turn: each control frame, and then the message."""
    if pieces is None:
        pieces = rng.choice((1, 1, 2, 3, rng.randint(4, 12), rng.randint(13, 300)))
    cuts = sorted(rng.randint(0, len(message)) for _ in range(pieces - 1))
    bounds = [0, *cuts, len(message)]
    data, handed = bytearray(), []
    for i, (a, b) in enumerate(zip(bounds, bounds[1:])):
        data += frame(message[a:b], opcode=opcode if i == 0 else 0x0, fin=i == pieces - 1)
        if i < pieces - 1 and rng.random() < 0.1:
            control = (rng.choice((0x9, 0xA)), rng.randbytes(rng.randint(0, 125)))
            data += frame(control[1], opcode=control[0])
            handed.append(control)
    handed.append((opcode, message))
    return bytes(data), handed


class ClientEnd:
    """The client's end of the connection: a socket it reads, and whose
    shutdown, which is how the client cuts the connection, the daemon sees."""

    def __init__(self, daemon, sock):
        self._daemon = daemon
        self._sock = sock

    def fileno(self):
        return self._sock.fileno()

    def recv(self, size):
        return self._sock.recv(size)

    def shutdown(self, how):
        self._daemon.cut()
        self._sock.shutdown(how)

    def close(self):
        self._sock.close()


class FakeDaemon:
    """What websocket.WebSocket makes in these tests: the far end of one
    connection. It answers every request as a daemon would, naming
    subscriptions sub-1, sub-2 and on, and answers the client's pings and
    its closing frame. A test pushes frames to the client through it, has
    it keep replies back, refuse an op, follow a reply with frames of its
    own, stop reading, leave pings unanswered, or take its time over the
    opening; or it hangs up."""

    def __init__(self, **_options):
        self.url = None
        self.subprotocols = None
        self.requests = []
        # The ops whose replies are kept back, and the replies kept back.
        self.hold = set()
        self.held = []
        # The ops refused, with the error code of the refusal.
        self.refuse = {}
        # The frames pushed right after the reply to an op.
        self.follow = {}
        # Whether the client sent its closing frame, cut the connection,
        # and closed the socket.
        self.closed = False
        self.aborted = False
        self.shut = False
        # The frames the client is stuck writing while the daemon does not
        # read.
        self.stuck = []
        # The client's pings, whether they are answered, and its pongs.
        self.pings = 0
        self.answer_pings = True
        self.pongs = []
        # How long the opening takes; whether it then waits, until the
        # client cuts the connection, for `opening` to be set; and whether
        # the socket comes into being only once the delay is over, as a TCP
        # connection does only once it is made.
        self.open_delay = 0.0
        self.opening = threading.Event()
        self.opening.set()
        self.late_socket = False
        self._reading = threading.Event()
        self._reading.set()
        self._subscriptions = 0
        client, self._far = socket.socketpair()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self._far.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        self._client = ClientEnd(self, client)
        self.sock = self._client
        self._writing = threading.Lock()
        self._gone = False

    # websocket-client's side, as the client uses it.

    def connect(self, url, subprotocols=None, **_options):
        self.url = url
        self.subprotocols = subprotocols
        if self.late_socket:
            self.sock = None
        time.sleep(self.open_delay)
        self.sock = self._client
        self.opening.wait()
        if self.aborted:
            raise ConnectionError("cut during the opening")

    def settimeout(self, _timeout):
        pass

    def send(self, text):
        # A daemon that has stopped reading leaves the client's send stuck,
        # as a full socket buffer does, until it reads again or the client
        # cuts the connection.
        if not self._reading.is_set():
            self.stuck.append(text)
            self._reading.wait()
            if self.aborted:
                raise ConnectionError("aborted")
        request = json.loads(text)
        self.requests.append(request)
        op = request["op"]
        if op in self.refuse:
            reply = {
                "op": "error",
                "id": request["id"],
                "code": self.refuse[op],
                "message": f"{op} refused",
            }
        else:
            reply = {"op": "ack", "id": request["id"]}
            if op == "subscribe":
                self._subscriptions += 1
                reply["subscription_id"] = f"sub-{self._subscriptions}"
            elif op == "send":
                reply["envelope_id"] = "e" * 32
        if op in self.hold:
            self.held.append(reply)
            return
        self.push(reply)
        for pushed in self.follow.get(op, ()):
            self.push(pushed)

    def ping(self, payload=b""):
        self.pings += 1
        if self.answer_pings:
            self.push_raw(frame(payload, 0xA))

    def pong(self, payload=b""):
        self.pongs.append(payload)

    def send_close(self, status=1000, reason=b""):
        # A daemon answers with its own closing frame and hangs up.
        self.closed = True
        self.push_raw(frame(status.to_bytes(2, "big") + reason, 0x8))
        self.hang_up()

    def shutdown(self):
        self.shut = True
        self._client.close()

    def abort(self):
        self.cut()

    # The test's side.

    def cut(self):
        """The client cut the connection: a stuck send, or an opening that
        waits, ends."""
        self.aborted = True
        self._reading.set()
        self.opening.set()

    def stop_reading(self):
        self._reading.clear()

    def read_again(self):
        self._reading.set()

    def push(self, message):
        """Push one message, a JSON object or a text as it is."""
        text = message if isinstance(message, str) else json.dumps(message)
        self.push_raw(frame(text.encode()))

    def push_raw(self, data):
        """Push bytes as they are. Once the client has gone they go
        nowhere."""
        with self._writing:
            if self._gone:
                return
            try:
                self._far.sendall(data)
            except OSError:
                pass

    def push_held(self):
        """Push the replies kept back, in the order of their requests."""
        while self.held:
            self.push(self.held.pop(0))

    def hang_up(self):
        """End the connection from the daemon's side."""
        with self._writing:
            if not self._gone:
                self._gone = True
                self._far.close()

    def dispose(self):
        """Close both ends, once the test is done."""
        self.hang_up()
        self._client.close()


def event(envelope_id, payload="aGk=", subscription_id="sub-1"):
    """An event frame; `payload=None` leaves the payload out."""
    frame = {
        "op": "event",
        "subscription_id": subscription_id,
        "envelope_id": envelope_id,
        "channel": "c",
        "type_id": 0,
        "origin": "o@1",
        "captured_at_unix_nanos": 0,
    }
    if payload is not None:
        frame["payload"] = payload
    return frame


def in_thread(fn, *args):
    """Call `fn(*args)` on a thread of its own. Returns a function that
    waits for the call, at most `timeout` seconds, and returns what it
    returned or the exception it raised."""
    outcome = queue.Queue()

    def call():
        try:
            outcome.put(fn(*args))
        except BaseException as e:
            outcome.put(e)

    threading.Thread(target=call, daemon=True).start()
    return lambda timeout=5: outcome.get(timeout=timeout)


def wait_for(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the condition did not hold in time")
        time.sleep(0.01)


def held(mesh):
    """What the client holds for its requests: the entries of its tables,
    its callbacks aside. A reply nobody waits for adds nothing to it."""
    return sum(
        len(table)
        for name, table in vars(mesh).items()
        if isinstance(table, dict) and name != "_callbacks"
    )


class Attached(unittest.TestCase):
    """The client connects to a fake daemon it makes with `configure`."""

    def connect(self, configure=lambda daemon: None):
        self.daemons = []

        def websocket(**options):
            daemon = FakeDaemon(**options)
            configure(daemon)
            self.daemons.append(daemon)
            self.addCleanup(daemon.dispose)
            return daemon

        transport = types.SimpleNamespace(WebSocket=websocket)
        for patch in (
            mock.patch.object(pms, "websocket", transport),
            mock.patch.dict(os.environ, {"PMS_DAEMON": "ws://127.0.0.1:9"}),
        ):
            patch.start()
            self.addCleanup(patch.stop)


class AttachTest(Attached):
    def test_a_client_the_daemon_does_not_attach_is_closed(self):
        self.connect(lambda daemon: daemon.refuse.update(attach="limit_exceeded"))
        with self.assertRaisesRegex(RuntimeError, r"\[limit_exceeded\]"):
            pms.attach("refused")
        (daemon,) = self.daemons
        self.assertTrue(daemon.closed, "the connection, and so the reader, ends")

    def test_the_opening_and_the_reply_share_one_deadline(self):
        def slow(daemon):
            daemon.open_delay = 1.0
            daemon.hold.add("attach")

        self.connect(slow)
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, r"op='attach'"):
            pms.attach("slow", rpc_timeout=1.5)
        # The reply had what the opening left of the deadline, not a
        # deadline of its own, which would have ended it after 2.5 s.
        self.assertLess(time.monotonic() - started, 2.2)
        (daemon,) = self.daemons
        self.assertEqual([r["op"] for r in daemon.requests], ["attach"])

    def test_an_opening_that_outlasts_the_deadline_is_cut(self):
        # A daemon that answers the upgrade a byte at a time kept each read
        # within the deadline and the whole attach past it.
        self.connect(lambda daemon: daemon.opening.clear())
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, r"no connection to the daemon"):
            pms.attach("trickled", rpc_timeout=0.3)
        self.assertLess(time.monotonic() - started, 1)
        (daemon,) = self.daemons
        self.assertTrue(daemon.aborted, "the socket is shut down under the opening")
        self.assertEqual(daemon.requests, [], "no attach was sent")

    def test_a_connection_made_after_the_deadline_is_closed(self):
        # Past the deadline before the TCP connection exists, there is no
        # socket to shut down: the thread that makes it closes it.
        def late(daemon):
            daemon.open_delay = 0.5
            daemon.late_socket = True

        self.connect(late)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            pms.attach("late", rpc_timeout=0.2)
        self.assertLess(time.monotonic() - started, 0.45)
        (daemon,) = self.daemons
        wait_for(lambda: daemon.shut)
        self.assertEqual(daemon.requests, [], "no attach was sent")


class ClientTest(Attached):
    """The client attached to a fake daemon, and subscribed to `c`."""

    def setUp(self):
        self.connect()
        self.mesh = pms.attach("thin-test")
        self.addCleanup(self.mesh.detach)
        (self.daemon,) = self.daemons
        self.delivered = queue.Queue()
        self.assertEqual(self.mesh.on("c", self.delivered.put), "sub-1")

    def next_event(self):
        return self.delivered.get(timeout=5)

    def assert_fails_at_once(self, call, *args):
        started = time.monotonic()
        with self.assertRaises(ConnectionError):
            call(*args)
        self.assertLess(time.monotonic() - started, 1)

    def test_an_event_in_the_accepted_form_is_delivered(self):
        self.daemon.push(event("e1", "aGk="))
        self.daemon.push(event("e2", ""))
        first, second = self.next_event(), self.next_event()
        self.assertEqual((first.envelope_id, first.payload), ("e1", b"hi"))
        self.assertEqual((second.envelope_id, second.payload), ("e2", b""))
        self.assertEqual(self.mesh.events_malformed, 0)

    def test_an_event_in_any_other_form_is_reported_and_never_delivered(self):
        bad = ["aGk", "AA==AA==", "Zh==", "aGk=\n", "aGk_", None, 5]
        with self.assertLogs("pms", level="ERROR") as logs:
            for i, payload in enumerate(bad):
                self.daemon.push(event(f"bad-{i}", payload))
            self.daemon.push(event("good", "aGk="))
            # The reader handles frames in order, so every bad one has been
            # handled once the good one arrives.
            delivered = self.next_event()
        self.assertEqual((delivered.envelope_id, delivered.payload), ("good", b"hi"))
        self.assertTrue(self.delivered.empty(), "no wrong payload was delivered")
        self.assertEqual(self.mesh.events_malformed, len(bad))
        # Reported at the first, second and fourth, as the Rust client
        # reports its count.
        self.assertEqual(len(logs.records), 3, logs.output)
        self.assertIn("not valid base64", logs.output[0])
        self.assertIn("bad-0", logs.output[0])

    def test_a_frame_that_is_not_a_json_object_is_reported_and_skipped(self):
        with self.assertLogs("pms", level="ERROR") as logs:
            self.daemon.push("not json")
            self.daemon.push("[1, 2]")
            self.daemon.push(event("after", "aGk="))
            delivered = self.next_event()
        self.assertEqual(delivered.envelope_id, "after")
        self.assertEqual(len(logs.records), 2, logs.output)
        self.assertEqual(self.mesh.events_malformed, 0)

    def test_send_writes_the_one_accepted_form(self):
        payload = bytes(range(256))
        self.assertEqual(self.mesh.send("c", payload), "e" * 32)
        sent = self.daemon.requests[-1]
        self.assertEqual(sent["op"], "send")
        self.assertEqual(sent["payload"], base64.b64encode(payload).decode("ascii"))
        self.assertEqual(pms.decode_payload(sent["payload"]), payload)

    def test_an_event_may_leave_out_what_the_protocol_makes_optional(self):
        no_type_id = event("no-type-id")
        del no_type_id["type_id"]
        self.daemon.push(no_type_id)
        self.daemon.push(dict(event("null-type-name"), type_name=None))
        self.daemon.push(
            dict(
                event("widest"),
                type_id=65535,
                type_name="t",
                captured_at_unix_nanos=(1 << 64) - 1,
            )
        )
        events = [self.next_event() for _ in range(3)]
        self.assertEqual(
            [(e.envelope_id, e.type_id, e.type_name) for e in events],
            [("no-type-id", 0, None), ("null-type-name", 0, None), ("widest", 65535, "t")],
        )
        self.assertEqual(events[2].captured_at_unix_nanos, (1 << 64) - 1)
        self.assertEqual(self.mesh.events_malformed, 0)

    def test_an_event_with_a_field_of_the_wrong_type_is_reported_and_never_delivered(self):
        wrong = [
            ("type_id", None),  # the review's case, which ended the reader
            ("type_id", "5"),
            ("type_id", 1.5),
            ("type_id", True),
            ("type_id", -1),
            ("type_id", 65536),
            ("captured_at_unix_nanos", None),
            ("captured_at_unix_nanos", -1),
            ("captured_at_unix_nanos", 1 << 64),
            ("captured_at_unix_nanos", "0"),
            ("subscription_id", ["sub-1"]),
            ("subscription_id", {"id": "sub-1"}),
            ("subscription_id", None),
            ("envelope_id", 7),
            ("channel", None),
            ("origin", False),
            ("type_name", 5),
        ]
        required = ["subscription_id", "envelope_id", "channel", "origin", "captured_at_unix_nanos"]
        with self.assertLogs("pms", level="ERROR") as logs:
            for i, (key, value) in enumerate(wrong):
                self.daemon.push(dict(event(f"bad-{i}"), **{key: value}))
            for key in required:
                frame = event(f"without-{key}")
                del frame[key]
                self.daemon.push(frame)
            self.daemon.push(event("good"))
            delivered = self.next_event()
        self.assertEqual(delivered.envelope_id, "good")
        self.assertTrue(self.delivered.empty(), "no malformed event was delivered")
        dropped = len(wrong) + len(required)
        self.assertEqual(self.mesh.events_malformed, dropped)
        # Reported at the first and at each doubling.
        self.assertEqual(len(logs.records), dropped.bit_length(), logs.output)
        self.assertIn("event is malformed", logs.output[0])
        self.assertIn("type_id is None", logs.output[0])
        # The reader carries on.
        self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)

    def test_a_reply_with_a_field_of_the_wrong_type_is_reported_and_ignored(self):
        with self.assertLogs("pms", level="ERROR") as logs:
            # Ids a dict cannot hold, which ended the reader.
            self.daemon.push({"op": "ack", "id": ["x"]})
            self.daemon.push({"op": "ack", "id": {"x": 1}})
            self.daemon.push({"op": "error", "id": 5, "code": "c", "message": "m"})
            self.daemon.push({"op": "error", "code": {"toString": 1}, "message": "m"})
            self.daemon.push({"op": "ack", "id": "nobody", "subscription_id": 5})
            self.daemon.push(event("after"))
            delivered = self.next_event()
        self.assertEqual(delivered.envelope_id, "after")
        self.assertEqual(len(logs.records), 5, logs.output)
        for line in logs.output:
            self.assertIn("a frame from the daemon is malformed; ignored", line)
        self.assertEqual(self.mesh.events_malformed, 0, "only events are counted")
        self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)

    def test_a_callback_that_raises_is_logged_and_dispatch_goes_on(self):
        def broken(_event):
            raise RuntimeError("a bug in the callback")

        self.assertEqual(self.mesh.on("broken", broken), "sub-2")
        with self.assertLogs("pms", level="ERROR") as logs:
            self.daemon.push(event("e1", subscription_id="sub-2"))
            self.daemon.push(event("e2"))
            delivered = self.next_event()
        self.assertEqual(delivered.envelope_id, "e2")
        self.assertEqual(len(logs.records), 1, logs.output)
        self.assertIn("subscription sub-2 raised on envelope e1", logs.output[0])
        # With the traceback.
        self.assertIs(logs.records[0].exc_info[0], RuntimeError)
        self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)
        self.assertEqual(self.mesh.events_malformed, 0)

    def test_replies_nobody_waits_for_are_not_kept(self):
        with self.assertLogs("pms", level="WARNING") as logs:
            for i in range(1000):
                self.daemon.push({"op": "ack", "id": f"nobody-{i}", "envelope_id": "e" * 32})
                self.daemon.push({"op": "error", "id": f"no-one-{i}", "code": "c", "message": "m"})
            # The reader takes frames in order, so it has read all of those
            # once this call has its reply.
            self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)
        # Each error is reported, as the daemon's reason should the
        # connection end next; nothing is kept for any of them.
        self.assertEqual(len(logs.records), 1000)
        self.assertIn("an error from the daemon answers no request: daemon error [c]: m", logs.output[0])
        self.assertEqual(held(self.mesh), 0)
        # A reply that comes after its call timed out is one of them, and
        # is counted.
        self.daemon.hold.add("send")
        with mock.patch.object(self.mesh, "_rpc_timeout", 0.5):
            with self.assertRaises(TimeoutError):
                self.mesh.send("c", b"late")
        self.daemon.hold.clear()
        with self.assertLogs("pms", level="WARNING") as logs:
            self.daemon.push_held()
            # The reader takes frames in order, so it has read all of those
            # once this call has its reply.
            self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)
        self.assertEqual(self.mesh.late_replies, 1)
        self.assertIn("a reply to send arrived after its call had timed out", logs.output[0])
        self.assertEqual(held(self.mesh), 0)

    def test_a_subscribe_that_timed_out_is_released_when_its_ack_comes(self):
        ran = []
        self.daemon.hold.add("subscribe")
        with mock.patch.object(self.mesh, "_rpc_timeout", 0.5):
            with self.assertRaises(TimeoutError):
                self.mesh.on("late", ran.append)
        self.daemon.hold.clear()
        with self.assertLogs("pms", level="WARNING") as logs:
            self.daemon.push_held()  # the ack, naming sub-2
            self.daemon.push(event("e1", subscription_id="sub-2"))
            self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)
        self.assertIn("a reply to subscribe arrived after its call had timed out", logs.output[0])
        wait_for(lambda: any(r["op"] == "unsubscribe" for r in self.daemon.requests))
        released = [r["subscription_id"] for r in self.daemon.requests if r["op"] == "unsubscribe"]
        self.assertEqual(released, ["sub-2"])
        self.assertEqual(self.mesh.late_replies, 1)
        self.assertEqual(ran, [], "its callback never runs")
        # The release is kept until its reply comes.
        wait_for(lambda: held(self.mesh) == 0)

    def test_an_error_that_answers_no_request_is_the_reason_the_connection_ended(self):
        # The daemon refuses a frame over its size limit so, unable to read
        # its id, and closes: the call waiting failed with nothing but "the
        # client closed", and nothing was reported.
        self.daemon.hold.add("send")
        waiting = in_thread(self.mesh.send, "c", b"x")
        wait_for(lambda: any(r["op"] == "send" for r in self.daemon.requests))
        refusal = "frame of 1228891 bytes exceeds the 1048576 byte limit"
        with self.assertLogs("pms", level="WARNING") as logs:
            self.daemon.push({"op": "error", "code": "payload_too_large", "message": refusal})
            self.daemon.hang_up()
            error = waiting()
        reason = f"the daemon's last word was daemon error [payload_too_large]: {refusal}"
        self.assertIsInstance(error, ConnectionError)
        self.assertEqual(str(error), f"the client closed before the reply to op='send' id='{self.daemon.requests[-1]['id']}'; {reason}")
        self.assertEqual(
            logs.output,
            [f"WARNING:pms:an error from the daemon answers no request: daemon error [payload_too_large]: {refusal}"],
        )
        # And every call after gives it.
        with self.assertRaises(ConnectionError) as after:
            self.mesh.send("c", b"y")
        self.assertEqual(str(after.exception), f"the client is closed; op='send' not sent; {reason}")

    def test_an_error_that_answers_no_request_is_no_reason_once_the_daemon_says_more(self):
        # An id no call waits for answers no request either.
        with self.assertLogs("pms", level="WARNING"):
            self.daemon.push({"op": "error", "id": "nobody", "code": "bad_request", "message": "malformed JSON"})
            self.daemon.push(event("after"))
            self.assertEqual(self.next_event().envelope_id, "after")
        self.daemon.hold.add("send")
        waiting = in_thread(self.mesh.send, "c", b"x")
        wait_for(lambda: any(r["op"] == "send" for r in self.daemon.requests))
        self.daemon.hang_up()
        error = waiting()
        self.assertIsInstance(error, ConnectionError)
        self.assertNotIn("last word", str(error))

    def test_an_error_that_answers_a_release_answers_a_request(self):
        # The client's own unsubscribe, releasing a subscription whose
        # subscribe timed out, is a request: an error in reply to it is
        # not the daemon's last word.
        self.daemon.hold.add("subscribe")
        self.daemon.refuse["unsubscribe"] = "unknown_subscription"
        with mock.patch.object(self.mesh, "_rpc_timeout", 0.5):
            with self.assertRaises(TimeoutError):
                self.mesh.on("late", print)
        with self.assertLogs("pms", level="WARNING") as logs:
            self.daemon.push_held()  # the ack, naming sub-2, and so the release
            wait_for(lambda: any(r["op"] == "unsubscribe" for r in self.daemon.requests))
            wait_for(lambda: held(self.mesh) == 0)
        self.assertEqual(len(logs.records), 1, logs.output)
        self.assertIn("a reply to subscribe arrived after its call had timed out", logs.output[0])
        self.daemon.hold.add("send")
        waiting = in_thread(self.mesh.send, "c", b"x")
        wait_for(lambda: any(r["op"] == "send" for r in self.daemon.requests))
        self.daemon.hang_up()
        self.assertNotIn("last word", str(waiting()))

    def test_an_event_right_behind_the_subscribe_ack_reaches_the_callback(self):
        self.daemon.follow["subscribe"] = [event("first", subscription_id="sub-2")]
        got = queue.Queue()
        self.assertEqual(self.mesh.on("d", got.put), "sub-2")
        self.assertEqual(got.get(timeout=5).envelope_id, "first")

    def test_when_the_daemon_hangs_up_the_client_closes(self):
        self.daemon.hold.add("send")
        waiting = in_thread(self.mesh.send, "c", b"x")
        wait_for(lambda: any(r["op"] == "send" for r in self.daemon.requests))
        started = time.monotonic()
        self.daemon.hang_up()
        # The call waiting fails at once, run() returns, and a new call
        # fails without waiting.
        self.assertIsInstance(waiting(), ConnectionError)
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNone(in_thread(self.mesh.run)())
        self.assert_fails_at_once(self.mesh.send, "c", b"y")
        self.assert_fails_at_once(self.mesh.on, "d", print)

    def test_when_a_callback_ends_its_thread_the_client_closes(self):
        # SystemExit is no Exception: the guard lets it end the dispatcher,
        # and the dispatcher's end closes the client and its connection.
        def leave(_event):
            raise SystemExit

        self.assertEqual(self.mesh.on("leave", leave), "sub-2")
        self.daemon.push(event("e1", subscription_id="sub-2"))
        self.assertIsNone(in_thread(self.mesh.run)())
        self.assertTrue(self.daemon.closed)
        self.assert_fails_at_once(self.mesh.send, "c", b"x")

    def test_a_callback_may_call_back_into_the_mesh(self):
        # It ran on the reader, which alone could read the reply it waited
        # for: the call waited out its deadline.
        replies = queue.Queue()

        def echo(ev):
            replies.put(self.mesh.send("echo", ev.payload))

        self.assertEqual(self.mesh.on("ping", echo), "sub-2")
        started = time.monotonic()
        self.daemon.push(event("e1", subscription_id="sub-2"))
        self.assertEqual(replies.get(timeout=5), "e" * 32)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.daemon.requests[-1]["op"], "send")

    def test_callbacks_run_in_order_on_a_thread_of_their_own(self):
        threads, order = set(), []

        def record(ev):
            threads.add(threading.current_thread())
            order.append(ev.envelope_id)

        self.assertEqual(self.mesh.on("order", record), "sub-2")
        for i in range(200):
            self.daemon.push(event(f"e{i}", subscription_id="sub-2"))
        wait_for(lambda: len(order) == 200)
        self.assertEqual(order, [f"e{i}" for i in range(200)])
        self.assertEqual(len(threads), 1)
        self.assertNotIn(threading.current_thread(), threads)

    def test_events_in_any_fragments_arrive_intact(self):
        # However a message is split, text or binary, into empty pieces or
        # with control frames between them, the event it carries arrives.
        rng = random.Random(2026)
        sent = []
        for i in range(200):
            payload = rng.randbytes(rng.choice((0, rng.randint(1, 200), rng.randint(200, 50_000))))
            text = json.dumps(event(f"e{i}", pms.encode_payload(payload))).encode()
            data, _ = split(rng, text, opcode=rng.choice((0x1, 0x2)))
            self.daemon.push_raw(data)
            sent.append((f"e{i}", payload))
        got = [self.next_event() for _ in sent]
        self.assertEqual([(ev.envelope_id, ev.payload) for ev in got], sent)
        self.assertEqual(self.mesh.events_malformed, 0)
        self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)

    def test_a_callback_that_falls_behind_loses_the_newest_events(self):
        mesh = pms.attach("slow", event_queue=4)
        self.addCleanup(mesh.detach)
        daemon = self.daemons[-1]
        started, release, got = threading.Event(), threading.Event(), []

        def slow(ev):
            started.set()
            release.wait(5)
            got.append(ev.envelope_id)

        self.assertEqual(mesh.on("c", slow), "sub-1")
        daemon.push(event("e0"))
        self.assertTrue(started.wait(5))
        with self.assertLogs("pms", level="WARNING") as logs:
            for i in range(1, 8):
                daemon.push(event(f"e{i}"))
            # Replies never wait behind events: this one comes while the
            # callback is stuck, after the reader has read every event.
            self.assertEqual(mesh.send("c", b"x"), "e" * 32)
        release.set()
        # One with the callback, four waiting, and the newest three dropped.
        wait_for(lambda: len(got) == 5)
        self.assertEqual(got, ["e0", "e1", "e2", "e3", "e4"])
        self.assertEqual(mesh.events_dropped, 3)
        # Reported at the first and second.
        self.assertEqual(len(logs.records), 2, logs.output)
        self.assertIn("event queue full; event dropped", logs.output[0])

    def test_a_callback_that_falls_behind_holds_at_most_its_bytes(self):
        # An event counts its payload and its text fields: 1,000 bytes and
        # sub-1, eN, c and o@1, 1,011 bytes. Four fit 4,100 bytes, the one
        # with the callback among them.
        mesh = pms.attach("heavy", event_queue_bytes=4100)
        self.addCleanup(mesh.detach)
        daemon = self.daemons[-1]
        started, release, got = threading.Event(), threading.Event(), []

        def slow(ev):
            started.set()
            release.wait(5)
            got.append(ev.envelope_id)

        self.assertEqual(mesh.on("c", slow), "sub-1")
        payload = pms.encode_payload(noise(1, 1000))
        daemon.push(event("e0", payload))
        self.assertTrue(started.wait(5))
        with self.assertLogs("pms", level="WARNING") as logs:
            for i in range(1, 8):
                daemon.push(event(f"e{i}", payload))
            self.assertEqual(mesh.send("c", b"x"), "e" * 32)
        self.assertEqual(mesh.events_dropped, 4)
        self.assertIn("event queue full; event dropped", logs.output[0])
        release.set()
        wait_for(lambda: len(got) == 4)
        self.assertEqual(got, ["e0", "e1", "e2", "e3"])
        # Their bytes are given back as their callbacks run.
        daemon.push(event("e8", payload))
        wait_for(lambda: len(got) == 5)
        self.assertEqual(got[-1], "e8")
        self.assertEqual(mesh.events_dropped, 4)

    def test_an_event_larger_than_the_byte_budget_is_always_dropped(self):
        for budget, payload_bytes, delivered in ((1000, 1000, False), (1000, 900, True), (0, 0, False)):
            with self.subTest(budget=budget, payload_bytes=payload_bytes):
                mesh = pms.attach("budget", event_queue_bytes=budget)
                self.addCleanup(mesh.detach)
                daemon = self.daemons[-1]
                got = queue.Queue()
                self.assertEqual(mesh.on("c", got.put), "sub-1")
                with self.assertLogs("pms", level="WARNING") if not delivered else contextlib.nullcontext():
                    daemon.push(event("e0", pms.encode_payload(bytes(payload_bytes))))
                    self.assertEqual(mesh.send("c", b"x"), "e" * 32)
                if delivered:
                    self.assertEqual(got.get(timeout=5).envelope_id, "e0")
                else:
                    self.assertTrue(got.empty())
                self.assertEqual(mesh.events_dropped, 0 if delivered else 1)

    def test_by_default_the_waiting_events_hold_at_most_16_mib(self):
        # The review's case, scaled: a callback that stopped held 1,024
        # events of 760 KiB each. Seven events of 2 MiB fit 16 MiB.
        mesh = pms.attach("default-budget")
        self.addCleanup(mesh.detach)
        daemon = self.daemons[-1]
        started, release, got = threading.Event(), threading.Event(), []

        def slow(ev):
            started.set()
            release.wait(10)
            got.append(ev.envelope_id)

        self.assertEqual(mesh.on("c", slow), "sub-1")
        payload = pms.encode_payload(bytes(2 << 20))
        daemon.push(event("e0", payload))
        self.assertTrue(started.wait(5))
        with self.assertLogs("pms", level="WARNING"):
            for i in range(1, 12):
                daemon.push(event(f"e{i}", payload))
            self.assertEqual(mesh.send("c", b"x"), "e" * 32)
        release.set()
        wait_for(lambda: len(got) == 7)
        self.assertEqual(mesh.events_dropped, 5)
        self.assertEqual(got, [f"e{i}" for i in range(7)])

    def test_a_call_the_daemon_does_not_read_fails_at_its_deadline(self):
        mesh = pms.attach("stalled", rpc_timeout=0.5)
        self.addCleanup(mesh.detach)
        daemon = self.daemons[-1]
        daemon.stop_reading()
        started = time.monotonic()
        first = in_thread(mesh.send, "c", b"first")
        wait_for(lambda: daemon.stuck)
        second = in_thread(mesh.send, "c", b"second")
        self.assertIsInstance(first(), TimeoutError)
        self.assertIsInstance(second(), TimeoutError)
        self.assertLess(time.monotonic() - started, 2)
        # The request being written goes when the daemon reads again, and
        # its reply is late; the one queued behind it was withdrawn at its
        # deadline, and never goes.
        with self.assertLogs("pms", level="WARNING"):
            daemon.read_again()
            wait_for(lambda: mesh.late_replies == 1)
        self.assertEqual(mesh.send("c", b"third"), "e" * 32)
        sent = [r["payload"] for r in daemon.requests if r["op"] == "send"]
        self.assertEqual(sent, [pms.encode_payload(b"first"), pms.encode_payload(b"third")])

    def test_closing_cuts_loose_a_send_the_daemon_never_takes(self):
        mesh = pms.attach("stuck", rpc_timeout=0.5)
        daemon = self.daemons[-1]
        daemon.stop_reading()
        stuck = in_thread(mesh.send, "c", b"x")
        wait_for(lambda: daemon.stuck)
        self.assertIsInstance(stuck(), TimeoutError)
        # The detach waits behind the send the writer is stuck in, and
        # times out too; closing then cuts the writer loose.
        started = time.monotonic()
        mesh.detach()
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(daemon.aborted, "the connection is cut under the writer")
        self.assertIsNone(in_thread(mesh.run)())

    def test_an_unsubscribe_that_times_out_still_goes_and_its_callback_goes_at_once(self):
        with mock.patch.object(self.mesh, "_rpc_timeout", 0.5):
            self.daemon.stop_reading()
            ahead = in_thread(self.mesh.send, "c", b"ahead")
            wait_for(lambda: self.daemon.stuck)
            # Queued behind a send the daemon does not take, where any
            # other call is withdrawn at its deadline.
            with self.assertRaises(TimeoutError):
                self.mesh.unsubscribe("sub-1")
            self.assertIsInstance(ahead(), TimeoutError)
        self.daemon.push(event("after"))
        # It goes, and its reply comes late, as the send's does.
        with self.assertLogs("pms", level="WARNING") as logs:
            self.daemon.read_again()
            wait_for(lambda: self.mesh.late_replies == 2)
        self.assertIn("a reply to unsubscribe arrived", logs.output[-1])
        self.assertEqual([r["op"] for r in self.daemon.requests][-2:], ["send", "unsubscribe"])
        # The reader took `after` before these replies, and its callback
        # was gone.
        self.assertEqual(self.mesh.send("c", b"x"), "e" * 32)
        self.assertTrue(self.delivered.empty(), "the callback ran for no event after")


class ConnectionTest(Attached):
    """What the client takes from the connection: messages up to 16 MiB,
    the frames RFC 6455 allows, and silence up to a limit."""

    def attach(self, configure=lambda daemon: None, **options):
        """A client attached to a fake daemon, and a call of it that waits:
        the daemon keeps the send's reply back."""
        self.connect(configure)
        mesh = pms.attach("frames", **options)
        self.addCleanup(mesh.detach)
        daemon = self.daemons[-1]
        daemon.hold.add("send")
        waiting = in_thread(mesh.send, "c", b"x")
        wait_for(lambda: any(r["op"] == "send" for r in daemon.requests))
        return mesh, daemon, waiting

    def assert_closed(self, mesh, waiting, within=1):
        """The client closed: the call waiting failed with ConnectionError,
        not at its deadline, and run returns."""
        started = time.monotonic()
        self.assertIsInstance(waiting(), ConnectionError)
        self.assertLess(time.monotonic() - started, within)
        self.assertIsNone(in_thread(mesh.run)())

    def test_a_message_over_16_mib_closes_the_connection_at_its_header(self):
        # The review's case announced 2^40 bytes and streamed 256 MiB, which
        # the client read into memory and kept reading.
        for length in ((16 << 20) + 1, 1 << 40, (1 << 63) + 5):
            with self.subTest(length=length):
                mesh, daemon, waiting = self.attach()
                with self.assertLogs("pms", level="ERROR") as logs:
                    daemon.push_raw(frame(length=length))
                    self.assert_closed(mesh, waiting)
                self.assertIn(f"of at least {length} bytes is over the 16777216 byte limit", logs.output[0])
                self.assertIn("closing the connection", logs.output[0])

    def test_a_message_of_16_mib_is_taken(self):
        mesh, daemon, waiting = self.attach()
        (send,) = [r for r in daemon.requests if r["op"] == "send"]
        reply = {"op": "ack", "id": send["id"], "envelope_id": "f" * 32, "pad": ""}
        reply["pad"] = "x" * ((16 << 20) - len(json.dumps(reply)))
        text = json.dumps(reply)
        self.assertEqual(len(text), 16 << 20)
        daemon.push(text)
        self.assertEqual(waiting(), "f" * 32)
        self.assertFalse(mesh._closed)

    def test_the_limit_holds_for_a_message_in_fragments(self):
        with mock.patch.object(pms, "_MAX_INBOUND_MESSAGE", 1000):
            mesh, daemon, waiting = self.attach()
            # 1,000 bytes in two fragments are taken.
            (send,) = [r for r in daemon.requests if r["op"] == "send"]
            reply = {"op": "ack", "id": send["id"], "envelope_id": "f" * 32, "pad": ""}
            reply["pad"] = "x" * (1000 - len(json.dumps(reply)))
            text = json.dumps(reply).encode()
            daemon.push_raw(frame(text[:500], fin=False) + frame(text[500:], opcode=0x0))
            self.assertEqual(waiting(), "f" * 32)
            # 1,200 in two fragments of 600 are not: the second fragment's
            # header takes the message past the limit.
            daemon.hold.add("send")
            waiting = in_thread(mesh.send, "c", b"y")
            wait_for(lambda: len([r for r in daemon.requests if r["op"] == "send"]) == 2)
            with self.assertLogs("pms", level="ERROR") as logs:
                daemon.push_raw(frame(b"[" * 600, fin=False) + frame(length=600, opcode=0x0))
                self.assert_closed(mesh, waiting)
        self.assertIn("of at least 1200 bytes is over the 1000 byte limit", logs.output[0])

    def test_a_flood_of_fragments_closes_the_connection_at_the_cap(self):
        # The review's flood: a message begun and never ended, then frames
        # of one byte, or of none, continuing it. Each was kept as an
        # object of its own: 4M of one byte grew the client by 218 MiB,
        # and empty ones counted against no limit at all.
        for unit in (frame(b"x", opcode=0x0, fin=False), frame(opcode=0x0, fin=False)):
            with self.subTest(unit=unit):
                mesh, daemon, waiting = self.attach()
                with self.assertLogs("pms", level="ERROR") as logs:
                    in_thread(daemon.push_raw, frame(b"{", fin=False) + unit * 1_000_000)
                    self.assert_closed(mesh, waiting)
                self.assertIn("a message from the daemon comes in more than 4096 frames", logs.output[0])
                self.assertIn("closing the connection", logs.output[0])

    def test_a_message_may_come_in_4096_frames_and_no_more(self):
        mesh, daemon, waiting = self.attach()
        (send,) = [r for r in daemon.requests if r["op"] == "send"]
        text = json.dumps({"op": "ack", "id": send["id"], "envelope_id": "f" * 32}).encode()
        # The reply in 4,096 frames, all but two of them empty, is taken.
        middle = frame(opcode=0x0, fin=False) * 4094
        daemon.push_raw(frame(text[:1], fin=False) + middle + frame(text[1:], opcode=0x0))
        self.assertEqual(waiting(), "f" * 32)
        # The frame after 4,096 is refused at its header, before its
        # payload: this one announces 2^40 bytes.
        waiting = in_thread(mesh.send, "c", b"y")
        wait_for(lambda: len([r for r in daemon.requests if r["op"] == "send"]) == 2)
        with self.assertLogs("pms", level="ERROR") as logs:
            middle = frame(opcode=0x0, fin=False) * 4095
            daemon.push_raw(frame(b"[", fin=False) + middle + frame(opcode=0x0, length=1 << 40))
            self.assert_closed(mesh, waiting)
        self.assertIn("comes in more than 4096 frames", logs.output[0])

    def test_a_message_in_fragments_costs_its_bytes_and_no_object_each(self):
        # With the cap lifted, 200,000 fragments of one byte, which the
        # review's reader kept as 200,000 objects (56 bytes each, 11 MB),
        # cost what their bytes do.
        with mock.patch.object(pms, "_MAX_FRAGMENTS", 1 << 40):
            mesh, daemon, waiting = self.attach()
            (send,) = [r for r in daemon.requests if r["op"] == "send"]
            reply = {"op": "ack", "id": send["id"], "envelope_id": "f" * 32, "pad": ""}
            reply["pad"] = "x" * (200_000 - len(json.dumps(reply)))
            text = json.dumps(reply).encode()
            # A frame for each byte: FIN=0 and a length of one, the first a
            # text frame and the rest continuations; the last one FIN=1.
            frames = bytearray(3 * len(text))
            frames[0::3] = b"\x00" * len(text)
            frames[1::3] = b"\x01" * len(text)
            frames[2::3] = text
            frames[0], frames[-3] = 0x01, 0x80
            data = bytes(frames)
            tracemalloc.start()
            try:
                in_thread(daemon.push_raw, data)
                self.assertEqual(waiting(timeout=30), "f" * 32)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertLess(peak, 3 << 20, f"the reader held {peak} bytes at its peak")

    def test_a_message_not_ended_in_time_closes_the_connection(self):
        # Every whole frame counts as hearing from the daemon, a pong too:
        # a daemon that trickled a message's frames, or began one and then
        # only answered pings, held the connection open without end.
        limits = {"_PING_AFTER": 0.2, "_SILENCE_LIMIT": 0.6, "_MESSAGE_TIME_LIMIT": 1.0}
        with contextlib.ExitStack() as stack:
            for name, value in limits.items():
                stack.enter_context(mock.patch.object(pms, name, value))
            # A message whose frames come within the limit is taken.
            mesh, daemon, waiting = self.attach()
            (send,) = [r for r in daemon.requests if r["op"] == "send"]
            text = json.dumps({"op": "ack", "id": send["id"], "envelope_id": "f" * 32}).encode()
            for i in range(5):
                daemon.push_raw(frame(text[i : i + 1], opcode=0x0 if i else 0x1, fin=False))
                time.sleep(0.1)
            daemon.push_raw(frame(text[5:], opcode=0x0))
            self.assertEqual(waiting(), "f" * 32)
            for trickled in (True, False):
                with self.subTest(trickled=trickled):
                    mesh, daemon, waiting = self.attach()
                    started = time.monotonic()
                    with self.assertLogs("pms", level="ERROR") as logs:
                        daemon.push_raw(frame(b"[", fin=False))
                        while not mesh._closed and time.monotonic() - started < 5:
                            if trickled:
                                daemon.push_raw(frame(b" ", opcode=0x0, fin=False))
                            time.sleep(0.1)
                        self.assert_closed(mesh, waiting)
                    self.assertGreaterEqual(time.monotonic() - started, 1.0)
                    self.assertIn(
                        "a message from the daemon has not ended 1.0 s after its first frame",
                        logs.output[0],
                    )
                    if not trickled:
                        self.assertGreaterEqual(daemon.pings, 2, "the pings were answered")

    def test_a_frame_the_protocol_does_not_allow_closes_the_connection(self):
        cases = {
            "masked, which RFC 6455 forbids a server": frame(b"{}", mask=b"abcd"),
            "sets a reserved bit": frame(b"{}", rsv=4),
            "reserved opcode 0x3": frame(b"{}", opcode=0x3),
            "reserved opcode 0xb": frame(opcode=0xB),
            "fragmented or longer than 125 bytes": frame(opcode=0x9, fin=False),
            "longer than 125 bytes": frame(b"p" * 126, opcode=0x9),
            "continues no message": frame(b"{}", opcode=0x0),
            "begins inside another": frame(b'{"op"', fin=False) + frame(b"{}"),
            "is not UTF-8": frame(b'{"op": "\xff"}'),
        }
        for fault, data in cases.items():
            with self.subTest(fault=fault):
                mesh, daemon, waiting = self.attach()
                with self.assertLogs("pms", level="ERROR") as logs:
                    daemon.push_raw(data)
                    self.assert_closed(mesh, waiting)
                self.assertIn(fault, logs.output[0])

    def test_a_ping_is_answered_with_its_payload_even_inside_a_message(self):
        mesh, daemon, waiting = self.attach()
        daemon.push_raw(frame(b"hello", opcode=0x9))
        wait_for(lambda: daemon.pongs == [b"hello"])
        # A control frame may come between a message's fragments.
        (send,) = [r for r in daemon.requests if r["op"] == "send"]
        text = json.dumps({"op": "ack", "id": send["id"], "envelope_id": "f" * 32}).encode()
        daemon.push_raw(frame(text[:10], fin=False) + frame(b"again", opcode=0x9) + frame(text[10:], opcode=0x0))
        self.assertEqual(waiting(), "f" * 32)
        wait_for(lambda: daemon.pongs == [b"hello", b"again"])

    def test_a_flood_of_pings_waits_as_one_pong(self):
        mesh, daemon, waiting = self.attach()
        # The writer is stuck in a send the daemon does not take, and the
        # daemon pings on.
        daemon.hold.clear()
        daemon.stop_reading()
        stuck = in_thread(mesh.send, "c", b"stuck")
        wait_for(lambda: daemon.stuck)

        def pongs():
            return [item.payload for item in list(mesh._outbox._items) if isinstance(item, pms._Control)]

        for i in range(1000):
            daemon.push_raw(frame(str(i).encode(), opcode=0x9))
        # The reader takes the pings in order.
        wait_for(lambda: pongs() == [b"999"])
        self.assertEqual(pongs(), [b"999"], "only the latest ping is answered")
        daemon.read_again()
        self.assertEqual(stuck(), "e" * 32)
        wait_for(lambda: daemon.pongs == [b"999"])

    def test_a_closing_frame_from_the_daemon_closes_the_client(self):
        # The client read on, and took more calls.
        mesh, daemon, waiting = self.attach()
        daemon.push_raw(frame((1000).to_bytes(2, "big"), opcode=0x8))
        self.assert_closed(mesh, waiting)
        # The client answers with its own closing frame as its writer leaves.
        wait_for(lambda: daemon.closed)

    def test_a_silent_daemon_is_pinged_and_then_given_up(self):
        with mock.patch.object(pms, "_PING_AFTER", 0.2), mock.patch.object(pms, "_SILENCE_LIMIT", 0.6):
            mesh, daemon, waiting = self.attach(lambda daemon: setattr(daemon, "answer_pings", False))
            with self.assertLogs("pms", level="WARNING") as logs:
                self.assert_closed(mesh, waiting, within=2)
        self.assertEqual(daemon.pings, 1)
        self.assertIn("the daemon has sent nothing for 0.6 s, not even an answer to a ping", logs.output[0])

    def test_a_daemon_that_answers_the_ping_is_kept(self):
        with mock.patch.object(pms, "_PING_AFTER", 0.2), mock.patch.object(pms, "_SILENCE_LIMIT", 0.6):
            mesh, daemon, waiting = self.attach()
            time.sleep(1.5)
            self.assertFalse(mesh._closed)
            self.assertGreaterEqual(daemon.pings, 3)
            daemon.push_held()
            self.assertEqual(waiting(), "e" * 32)

    def test_what_the_daemon_sends_keeps_the_client_from_pinging(self):
        with mock.patch.object(pms, "_PING_AFTER", 0.5), mock.patch.object(pms, "_SILENCE_LIMIT", 1.5):
            mesh, daemon, waiting = self.attach(lambda daemon: setattr(daemon, "answer_pings", False))
            # The daemon's own pings, as it sends them every 30 seconds.
            for _ in range(12):
                daemon.push_raw(frame(opcode=0x9))
                time.sleep(0.05)
            # Answered: a pong still waiting is replaced by the next, so
            # there may be fewer than twelve.
            wait_for(lambda: daemon.pongs)
            self.assertFalse(mesh._closed)
            self.assertEqual(daemon.pings, 0)
            daemon.push_held()
            self.assertEqual(waiting(), "e" * 32)

    def test_a_daemon_that_stops_inside_a_frame_is_given_up(self):
        # Its pongs, arriving inside the frame, are the frame's bytes, and
        # no whole frame comes.
        with mock.patch.object(pms, "_PING_AFTER", 0.2), mock.patch.object(pms, "_SILENCE_LIMIT", 0.6):
            mesh, daemon, waiting = self.attach()
            with self.assertLogs("pms", level="WARNING"):
                daemon.push_raw(frame(b"x" * 10, length=100))
                self.assert_closed(mesh, waiting, within=2)
        self.assertEqual(daemon.pings, 1)


class SilenceTest(unittest.TestCase):
    """The reader's clock for a daemon's silence, on its own."""

    def test_a_late_ping_still_has_the_rest_of_the_limit_for_its_answer(self):
        # A client held up itself, a machine asleep say, finds the daemon
        # silent past the limit: it pings, and waits for the answer.
        client, far = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(far.close)
        pings = []
        with mock.patch.object(pms, "_PING_AFTER", 0.2), mock.patch.object(pms, "_SILENCE_LIMIT", 1.2):
            frames = pms._Frames(client, 1000, lambda: pings.append(time.monotonic()))
            self.addCleanup(frames.close)
            frames._heard -= 10
            got = in_thread(frames.next)
            wait_for(lambda: pings)
            time.sleep(0.2)
            far.sendall(frame(opcode=0xA))
            self.assertEqual(got(), (0xA, b""))
        self.assertEqual(len(pings), 1)


class PieceSocket:
    """A socket whose reads return pieces of random sizes, down to a byte,
    so that frames, and their headers, come split across reads."""

    def __init__(self, sock, rng):
        self._sock = sock
        self._rng = rng

    def fileno(self):
        return self._sock.fileno()

    def recv(self, size):
        return self._sock.recv(min(size, self._rng.choice((1, 2, 3, 5, 14, 200, 4096, size))))


class FragmentsTest(unittest.TestCase):
    """The reader's joining of a message's fragments, on its own."""

    def test_valid_messages_in_any_fragments_arrive_intact(self):
        for seed in range(6):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                data, handed = bytearray(), []
                for _ in range(80):
                    size = rng.choice(
                        (0, rng.randint(1, 125), rng.randint(126, 1 << 16), rng.randint(1 << 16, 200_000))
                    )
                    more, out = split(rng, rng.randbytes(size), opcode=rng.choice((0x1, 0x2)))
                    data += more
                    handed += out
                # And one in as many frames as a message may come in.
                more, out = split(rng, rng.randbytes(1000), pieces=pms._MAX_FRAGMENTS)
                data += more
                handed += out
                client, far = socket.socketpair()
                self.addCleanup(client.close)
                self.addCleanup(far.close)
                frames = pms._Frames(PieceSocket(client, rng), 16 << 20, lambda: None)
                self.addCleanup(frames.close)
                sent = in_thread(far.sendall, bytes(data))
                for i, want in enumerate(handed):
                    self.assertEqual(frames.next(), want, f"seed {seed}, item {i}")
                self.assertIsNone(sent())


if __name__ == "__main__":
    unittest.main()
