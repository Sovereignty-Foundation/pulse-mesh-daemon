# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""
Pulse Mesh thin Python client — Universal Port Protocol v0 over WebSocket.

Minimal surface: attach / send / on / tap / run / detach.

Discovery follows §2.3 of the spec:
1. PMS_DAEMON env var (`ws://host:port` — UDS is not supported in this
   thin client; use the Rust dev-functions for UDS)
2. ws://127.0.0.1:9876 fallback

A `wss://host:port` URL reaches a daemon started with --ws-tls-cert:
websocket-client verifies its certificate against the system's roots, or
against the CA file WEBSOCKET_CLIENT_CA_BUNDLE names instead.

Key-proof attach is not supported here yet: this client attaches by name
alone, never with a `key`, and does not answer a `challenge`. A daemon
started with --attach-keys therefore refuses its attach on the WebSocket
with `auth_failed`; the Rust client (`MeshOptions::with_identity`) proves
a key.

Each `Mesh` runs three threads. The reader hands each reply to the call
waiting for it and each event to the callbacks' queue. The dispatcher runs
the callbacks, one event at a time and in the order the events came, so a
callback may call back into the mesh. The writer sends the requests, one
at a time, so that no call waits on the connection past its deadline.
Nothing a frame holds and nothing a callback raises stops them:

- Payloads travel as padded standard base64 (RFC 4648 §4), the one form
  the daemon and the Rust client accept: `encode_payload` writes it and
  `decode_payload` accepts nothing else. An event whose payload is in any
  other form, or that lacks a field the protocol requires or carries one of
  the wrong type, is never delivered; `Mesh.events_malformed` counts such
  events. Like a frame that is not a JSON object, or a reply with a field
  of the wrong type, it is reported through the `pms` logger at ERROR, and
  the connection carries on.
- An exception a callback raises is logged at ERROR with its traceback,
  and the next event is dispatched. When `event_queue` events (1,024 by
  default) wait for the callbacks, or a newer one would take the events
  waiting and the one a callback is running past `event_queue_bytes` (16
  MiB by default), the newer one is dropped and counted by
  `Mesh.events_dropped`; replies never wait behind events.
- A call waits at most `rpc_timeout` seconds (10 by default) for its
  reply, and then raises `TimeoutError`. A request not yet written by then
  is withdrawn, and the daemon never sees it. A reply that comes after the
  deadline is dropped and counted by `Mesh.late_replies`, and a
  subscription whose subscribe timed out is released at the daemon; its
  callback never runs. An unsubscribe removes its callback at once and
  reaches the daemon even if it times out.
- Attaching takes at most `rpc_timeout` in all: the TCP connection, TLS
  for wss://, the WebSocket upgrade and the attach's reply share the one
  deadline, and `attach` raises `TimeoutError` past it.
- The reader reads the daemon's frames itself (RFC 6455 §5). A message
  longer than 16 MiB, the Rust client's limit, or a frame of one, closes
  the connection at its header, before its payload is read, as does the
  frame that takes a message past 4,096 frames, empty ones counted, or a
  frame the protocol does not allow; so does a message not ended 90
  seconds after its first frame. Each is reported at ERROR. A daemon that
  has sent nothing for 30 seconds is pinged, and one that has sent nothing
  for 90, the ping's answer included, is given up: the connection closes,
  reported at WARNING.
- Whatever stops the reader, the dispatcher or the writer (the
  connection's end, `detach`, or an exception that is not an `Exception`)
  closes the client: every call, waiting or new, fails at once with
  `ConnectionError`, and `run` returns once the callbacks have run for the
  events already received.
- An error from the daemon that answers no request, having no id or one
  the client does not know, is reported at WARNING. The daemon says why it
  ends a connection this way (a frame over its size limit gets
  `payload_too_large`, and then the connection closes), so while such an
  error is the last thing the daemon said it is the reason the connection
  ended, as the Rust client has it: the `ConnectionError` of every call
  waiting then, and of every call after, gives it.
"""

from __future__ import annotations

import base64
import binascii
import collections
import json
import logging
import os
import selectors
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

try:
    import websocket  # websocket-client
except ImportError:
    # Needed only to connect: the payload codec works without it, and
    # `Mesh` says what to install.
    websocket = None

__all__ = [
    "Mesh",
    "MeshEvent",
    "TapFilter",
    "attach",
    "decode_payload",
    "encode_payload",
]

PROTOCOL_VERSION = "v0"
WS_SUBPROTOCOL = "pms-universal-port-v0"

# How long a call waits for the daemon's reply by default, in seconds.
_RPC_TIMEOUT = 10.0

# How many events may wait for the callbacks by default: the daemon's own
# per-connection default, as in the Rust client.
_EVENT_QUEUE = 1024

# How many bytes the events waiting for the callbacks, and the one a
# callback is running, may hold by default: the daemon's own per-connection
# default, as in the Rust client. An event counts its payload and its text
# fields. The count alone let a callback that stopped hold 1,024 events of
# most of a megabyte each.
_EVENT_QUEUE_BYTES = 16 * 1024 * 1024

# The longest message the client takes from the daemon, and so the longest
# frame of one: the Rust client's limit. A longer one closes the connection
# at its header, before its payload is read. An event is about as long as
# the send that brought its payload in, which the daemon caps at 1 MiB
# unless its --max-message-bytes says otherwise, so this leaves room for a
# daemon configured sixteen times higher.
_MAX_INBOUND_MESSAGE = 16 * 1024 * 1024

# The most frames a message from the daemon may come in, empty ones
# counted: the frame past it closes the connection at its header. The
# daemon writes each message in one frame; this leaves room for anything
# between that splits them, down to pieces of 4 KiB for a message of 16
# MiB, while a message split into empty or one-byte frames costs no more
# than this many frames' reading.
_MAX_FRAGMENTS = 4096

# How long a message from the daemon may take from its first frame to its
# last, in seconds, as long as the daemon may be silent (_SILENCE_LIMIT):
# one not ended by then closes the connection. Every whole frame, a pong
# included, counts as hearing from the daemon, so a daemon that trickled a
# message's frames, or began one and then only answered pings, would
# otherwise hold the connection open without ever ending it.
_MESSAGE_TIME_LIMIT = 90.0

# After _PING_AFTER seconds without a frame from the daemon the client
# pings it, and after _SILENCE_LIMIT seconds without one, the ping's answer
# included, it gives the daemon up and closes. These are the daemon's own
# defaults for its clients (--ping-interval-secs, --idle-timeout-secs), and
# a healthy daemon always meets them: it pings every 30 seconds unless told
# otherwise, and however it is configured it answers a ping as soon as it
# reads one, a frame it writes taking at most its write deadline (10
# seconds by default) before it closes the connection itself.
_PING_AFTER = 30.0
_SILENCE_LIMIT = 90.0

# Requests no call waits for the replies to: timed-out calls whose
# requests went to the daemon, and the client's own releases. They are
# remembered so that their replies are known: a late one is counted, the
# subscription a late subscribe's ack names is released, and none is taken
# for an error that answers no request. A conforming daemon answers every
# request, which forgets it; one that stops answering costs at most this
# many, the oldest forgotten first.
_MAX_ABANDONED = 4096

# How long closing waits for the writer to leave, in seconds, before it
# cuts the connection under a send the daemon does not take; and how long
# the writer, having sent its closing frame, waits for the reader to see
# the daemon's.
_CLOSE_GRACE = 1.0

# How many bytes the reader asks the socket for at a time.
_RECV_CHUNK = 64 * 1024

# Frame opcodes (RFC 6455 §5.2).
_CONTINUATION, _TEXT, _BINARY = 0x0, 0x1, 0x2
_CLOSE, _PING, _PONG = 0x8, 0x9, 0xA

# Where this client reports what the daemon sent that the protocol does not
# allow, and what a callback raised. The connection carries on.
_log = logging.getLogger(__name__)


def encode_payload(data: bytes) -> str:
    """Encode payload bytes as the port protocol carries them: standard
    base64 (RFC 4648 §4), padded with `=`, and nothing else in the text."""
    return base64.b64encode(data).decode("ascii")


def decode_payload(text: str) -> bytes:
    """Decode a payload as strictly as the daemon and the Rust client do.

    Only padded standard base64 is accepted: no whitespace or line breaks,
    no URL-safe alphabet, no missing padding, no `=` but the one or two that
    end the text, and no bits set after the last byte. Each byte string has
    exactly one such text, the one `encode_payload` writes.

    Raises `ValueError` for anything else, a value that is not a string
    included.
    """
    if not isinstance(text, str):
        raise ValueError(f"payload is {type(text).__name__}, not a string")
    try:
        raw = text.encode("ascii")
        data = base64.b64decode(raw, validate=True)
    except (UnicodeEncodeError, binascii.Error) as e:
        raise ValueError(f"payload is not padded standard base64: {e}") from None
    # b64decode takes a last symbol that sets bits the padding marks unused,
    # which no encoder writes: only the encoder's own text for these bytes
    # is accepted.
    if base64.b64encode(data) != raw:
        raise ValueError(
            "payload is not padded standard base64: "
            "not the text an encoder writes for its bytes"
        )
    return data


class _Malformed(ValueError):
    """A field of a frame from the daemon is not what the protocol says."""


class _Violation(Exception):
    """The daemon sent what RFC 6455, or the client's limits on a message,
    do not allow: the connection ends."""


class _Silent(Exception):
    """The daemon has sent nothing for _SILENCE_LIMIT seconds, not even an
    answer to a ping: the connection ends."""


def _preview(value) -> str:
    """A field's value as a report shows it, cut short."""
    if isinstance(value, (list, dict)):
        return "an array" if isinstance(value, list) else "an object"
    text = repr(value)
    return text if len(text) <= 64 else text[:61] + "..."


def _label(value) -> str:
    """An id as a report names it: a string as it is, anything else
    previewed."""
    return value if isinstance(value, str) else _preview(value)


def _string(msg: dict, key: str, optional: bool = False) -> Optional[str]:
    """`msg[key]`, which must be a string. An optional field may be
    missing or null, and is then None."""
    if key not in msg:
        if optional:
            return None
        raise _Malformed(f"{key} is missing")
    value = msg[key]
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise _Malformed(f"{key} is {_preview(value)}, not a string")
    return value


def _unsigned(msg: dict, key: str, bits: int, default: Optional[int] = None) -> int:
    """`msg[key]`, which must be an integer that fits in `bits` unsigned
    bits. A field with a default may be missing, but not null."""
    if key not in msg:
        if default is not None:
            return default
        raise _Malformed(f"{key} is missing")
    value = msg[key]
    # A bool is an int to Python, and not a number to JSON.
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise _Malformed(
            f"{key} is {_preview(value)}, not an unsigned {bits}-bit integer"
        )
    return value


class _Call:
    """A request on its way to the daemon, and then waiting for its reply."""

    __slots__ = ("op", "text", "done", "reply", "callback")

    def __init__(
        self,
        op: str,
        text: str,
        callback: Optional[Callable[["MeshEvent"], None]] = None,
    ):
        self.op = op
        # The frame the writer sends.
        self.text = text
        self.done = threading.Event()
        # The daemon's ack or error. Set before `done`, and still None once
        # `done` is set if the client closed first.
        self.reply: Optional[dict] = None
        # A subscribe's callback, registered as the ack is read.
        self.callback = callback


class _Control:
    """A control frame on its way to the daemon: the client's ping, or its
    pong to one of the daemon's. Never withdrawn."""

    __slots__ = ("opcode", "payload")

    def __init__(self, opcode: int, payload: bytes = b""):
        self.opcode = opcode
        self.payload = payload


class _Queue:
    """A first-in, first-out queue from any thread to the one thread that
    takes from it, bounded when given a depth, and a budget of bytes that an
    item holds from when it is put until it is released. Closing it wakes
    the taker for good."""

    def __init__(self, depth: Optional[int] = None, budget: Optional[int] = None):
        self._items: collections.deque = collections.deque()
        self._depth = depth
        self._budget = budget
        self._held = 0
        self._ready = threading.Condition()
        self.closed = False

    def put(self, item, size: int = 0) -> bool:
        """Queue `item`, holding `size` bytes of the budget, unless the
        queue is closed or full, or the bytes would take it past its
        budget."""
        with self._ready:
            if (
                self.closed
                or (self._depth is not None and len(self._items) >= self._depth)
                or (self._budget is not None and self._held + size > self._budget)
            ):
                return False
            self._items.append(item)
            self._held += size
            self._ready.notify()
            return True

    def put_control(self, control: _Control) -> bool:
        """Queue a control frame ahead of the requests, in place of one of
        its kind still waiting (RFC 6455 lets a pong answer only the latest
        ping), so a daemon that floods pings costs one pong here. False once
        the queue is closed."""
        with self._ready:
            if self.closed:
                return False
            for i, item in enumerate(self._items):
                if not isinstance(item, _Control):
                    break
                if item.opcode == control.opcode:
                    self._items[i] = control
                    return True
            self._items.appendleft(control)
            self._ready.notify()
            return True

    def release(self, size: int) -> None:
        """Give back the bytes an item taken held."""
        with self._ready:
            self._held -= size

    def take(self):
        """The oldest item, once there is one; None once the queue is
        closed and nothing is left in it."""
        with self._ready:
            while not self._items and not self.closed:
                self._ready.wait()
            return self._items.popleft() if self._items else None

    def withdraw(self, item) -> bool:
        """Take `item` back, if the taker has not taken it."""
        with self._ready:
            try:
                self._items.remove(item)
            except ValueError:
                return False
            return True

    def close(self, drain: bool) -> None:
        """Queue nothing more. The taker takes what is left when `drain`,
        and nothing otherwise."""
        with self._ready:
            self.closed = True
            if not drain:
                self._items.clear()
            self._ready.notify_all()


class _Frames:
    """The daemon's side of the connection, read off its socket frame by
    frame (RFC 6455 §5.2). The client reads it itself rather than through
    websocket-client, which read a frame of any announced length into
    memory, and waited for bytes without end or under a socket timeout that
    would also cut the writer off in the middle of a frame. Here a frame or
    a message longer than the limit is refused at its header, before its
    payload is read, and the wait for bytes has a deadline of its own.

    A frame the daemon has begun but not finished, and a message whose last
    fragment has not come, wait here, at most one message long; the limit
    bounds them. A message's fragments are gathered into one buffer as
    they come, so that each costs its bytes and no object of its own; and
    a message may come in at most _MAX_FRAGMENTS frames, and take at most
    _MESSAGE_TIME_LIMIT seconds from its first to its last."""

    def __init__(self, sock, limit: int, ping: Callable[[], None]):
        self._sock = sock
        self._limit = limit
        self._ping = ping
        self._buf = bytearray()
        self._selector = selectors.DefaultSelector()
        self._selector.register(sock, selectors.EVENT_READ)
        # The message whose fragments are arriving: its opcode (None
        # between messages), its bytes so far, how many frames have
        # brought them, and when the first came.
        self._opcode: Optional[int] = None
        self._message = bytearray()
        self._fragments = 0
        self._began = 0.0
        # When the last whole frame came; the `_heard` the client pinged the
        # daemon at, so that it pings once per silence; and when it gives
        # the daemon up if nothing comes.
        self._heard = time.monotonic()
        self._pinged: Optional[float] = None
        self._give_up = 0.0

    def close(self) -> None:
        self._selector.close()

    def next(self) -> Tuple[int, bytes]:
        """The next control frame, or message with its fragments joined,
        as its opcode and payload. Raises `ConnectionError` when the
        connection ends, `_Violation` for what the protocol or the limits
        do not allow, and `_Silent` when the daemon has gone quiet."""
        while True:
            frame = self._frame()
            if frame is None:
                self._fill()
                continue
            fin, opcode, payload = frame
            if opcode >= _CLOSE:
                return opcode, payload
            if opcode != _CONTINUATION:
                if fin:
                    return opcode, payload  # a whole message, as the daemon sends them
                self._opcode, self._began = opcode, time.monotonic()
            self._message += payload
            self._fragments += 1
            if fin:
                message = (self._opcode, bytes(self._message))
                self._opcode, self._message, self._fragments = None, bytearray(), 0
                return message

    def _frame(self) -> Optional[Tuple[bool, int, bytes]]:
        """The frame at the head of the buffer, as (fin, opcode, payload),
        once all of it has come, and None until then. Its header is judged
        as soon as it is in."""
        buf = self._buf
        if len(buf) < 2:
            return None
        first, second = buf[0], buf[1]
        fin, opcode, length = bool(first & 0x80), first & 0x0F, second & 0x7F
        if first & 0x70:
            raise _Violation(
                "a frame from the daemon sets a reserved bit, and no extension was agreed"
            )
        if second & 0x80:
            raise _Violation(
                "a frame from the daemon is masked, which RFC 6455 forbids a server"
            )
        if opcode >= _CLOSE:
            if opcode > _PONG:
                raise _Violation(f"a frame from the daemon has the reserved opcode {opcode:#x}")
            # A control frame's length fits the first byte of it, 125 at most.
            if not fin or length > 125:
                raise _Violation(
                    "a control frame from the daemon is fragmented or longer than 125 bytes"
                )
        elif opcode > _BINARY:
            raise _Violation(f"a frame from the daemon has the reserved opcode {opcode:#x}")
        elif opcode == _CONTINUATION and self._opcode is None:
            raise _Violation("a frame from the daemon continues no message")
        elif opcode != _CONTINUATION and self._opcode is not None:
            raise _Violation("a message from the daemon begins inside another")
        elif opcode == _CONTINUATION and self._fragments >= _MAX_FRAGMENTS:
            raise _Violation(
                f"a message from the daemon comes in more than {_MAX_FRAGMENTS} frames"
            )
        start = 2 + {126: 2, 127: 8}.get(length, 0)
        if len(buf) < start:
            return None
        if length >= 126:
            length = int.from_bytes(buf[2:start], "big")
        if opcode < _CLOSE and len(self._message) + length > self._limit:
            raise _Violation(
                f"a message from the daemon of at least {len(self._message) + length} bytes "
                f"is over the {self._limit} byte limit"
            )
        end = start + length
        if len(buf) < end:
            return None
        with memoryview(buf) as view:
            payload = view[start:end].tobytes()
        del buf[:end]
        self._heard = time.monotonic()
        return fin, opcode, payload

    def _fill(self) -> None:
        """Wait for more of the daemon's bytes and take what has come.
        Pings the daemon once it has been silent _PING_AFTER seconds, and
        raises `_Silent` once it has been silent _SILENCE_LIMIT seconds,
        and `_Violation` once a message has taken _MESSAGE_TIME_LIMIT
        seconds without ending."""
        # A TLS socket may hold bytes it has decrypted, which the selector
        # cannot see.
        pending = getattr(self._sock, "pending", None)
        while not (pending is not None and pending()):
            now = time.monotonic()
            # Whatever else the daemon sends meanwhile, pongs and fragments
            # alike, a message it has begun ends by then.
            ends = None if self._opcode is None else self._began + _MESSAGE_TIME_LIMIT
            if ends is not None and now >= ends:
                raise _Violation(
                    f"a message from the daemon has not ended {_MESSAGE_TIME_LIMIT} s "
                    "after its first frame"
                )
            if self._pinged != self._heard:
                wake = self._heard + _PING_AFTER
                if now >= wake:
                    self._pinged = self._heard
                    # The answer has the rest of the limit from the ping,
                    # however late the ping: a client held up itself (a
                    # machine asleep) does not give the daemon up unasked.
                    self._give_up = max(
                        self._heard + _SILENCE_LIMIT, now + _SILENCE_LIMIT - _PING_AFTER
                    )
                    self._ping()
                    continue
            else:
                wake = self._give_up
                if now >= wake:
                    raise _Silent()
            if ends is not None:
                wake = min(wake, ends)
            if self._selector.select(wake - now):
                break
        chunk = self._sock.recv(_RECV_CHUNK)
        if not chunk:
            raise ConnectionError("the daemon closed the connection")
        self._buf += chunk


def _open(url: str, timeout: float):
    """A WebSocket to the daemon at `url`, opened within `timeout` seconds
    in all: the TCP connection, TLS for wss://, and the upgrade.

    websocket-client bounds each read of the opening by its timeout, not
    the whole, so a daemon that answered a byte at a time held an attach for
    as long as it liked. The connection is therefore opened on a thread of
    its own, which at the deadline is left to end, the socket shut down
    under it, and closes what it opened if it opens it later.

    Raises `TimeoutError` at the deadline, and whatever the opening raises
    before it."""
    ws = websocket.WebSocket()
    lock = threading.Lock()
    opened = threading.Event()
    state: dict = {"error": None, "abandoned": False}

    def connect() -> None:
        try:
            # No Origin header: the daemon refuses an upgrade whose Origin
            # names a web page it does not trust, and this client is not a
            # page. websocket-client would otherwise send one naming the
            # daemon's own address, which a daemon on another host refuses.
            ws.connect(
                url,
                subprotocols=[WS_SUBPROTOCOL],
                suppress_origin=True,
                timeout=timeout,
            )
        except BaseException as e:  # handed to the caller, if it still waits
            state["error"] = e
        with lock:
            opened.set()
            abandoned = state["abandoned"]
        if abandoned and state["error"] is None:
            try:
                ws.shutdown()
            except Exception:
                pass

    threading.Thread(target=connect, name="pms-connect", daemon=True).start()
    try:
        opened.wait(timeout)
    finally:
        with lock:
            abandoned = state["abandoned"] = not opened.is_set()
        if abandoned:
            sock = ws.sock
            try:
                if sock is not None:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    if abandoned:
        raise TimeoutError(f"no connection to the daemon at {url} within {timeout} s")
    error = state["error"]
    if error is not None:
        # One read of the opening took the whole deadline.
        timed_out = (
            TimeoutError,
            socket.timeout,
            getattr(websocket, "WebSocketTimeoutException", ()),
        )
        if isinstance(error, timed_out):
            raise TimeoutError(
                f"no connection to the daemon at {url} within {timeout} s"
            ) from error
        raise error
    # The writer's sends block; the reader waits for bytes with deadlines of
    # its own.
    ws.settimeout(None)
    return ws


@dataclass
class MeshEvent:
    subscription_id: str
    envelope_id: str
    channel: str
    type_id: int
    type_name: Optional[str]
    origin: str
    captured_at_unix_nanos: int
    payload: bytes


def _event_bytes(event: MeshEvent) -> int:
    """What an event holds of the event queue's budget: its payload and its
    text fields, as the Rust client counts it."""
    return (
        len(event.payload)
        + len(event.subscription_id)
        + len(event.envelope_id)
        + len(event.channel)
        + len(event.type_name or "")
        + len(event.origin)
    )


@dataclass
class TapFilter:
    channel: Optional[str] = None
    type_id: Optional[int] = None
    type_name: Optional[str] = None
    origin: Optional[str] = None
    health: bool = False
    snapshot: bool = False

    def to_json(self) -> dict:
        out: dict = {}
        if self.channel is not None:
            out["channel"] = self.channel
        if self.type_id is not None:
            out["type_id"] = self.type_id
        if self.type_name is not None:
            out["type_name"] = self.type_name
        if self.origin is not None:
            out["origin"] = self.origin
        if self.health:
            out["health"] = True
        if self.snapshot:
            out["snapshot"] = True
        return out


def _discover_url() -> str:
    d = os.environ.get("PMS_DAEMON")
    if d:
        if d.startswith("ws://") or d.startswith("wss://"):
            return d
        raise RuntimeError(
            f"PMS_DAEMON='{d}' — pms-py-thin only supports ws:// URLs"
        )
    return "ws://127.0.0.1:9876"


class Mesh:
    """A blocking-API mesh client. Thread-safe; one connection per Mesh.

    `rpc_timeout` is how many seconds a call waits for the daemon's reply
    (10 by default), and the attach, the connection's opening included,
    too. `event_queue` is how many events may wait for the callbacks before
    a newer one is dropped (1,024 by default; zero is taken as one), and
    `event_queue_bytes` how many bytes they and the event a callback is
    running may hold (16 MiB by default): an event that would take them
    past it is dropped too, and one larger than it always is."""

    def __init__(
        self,
        name: str,
        *,
        rpc_timeout: float = _RPC_TIMEOUT,
        event_queue: int = _EVENT_QUEUE,
        event_queue_bytes: int = _EVENT_QUEUE_BYTES,
    ):
        if websocket is None:
            raise ImportError(
                "pms-py-thin connects with websocket-client: "
                "pip install websocket-client"
            )
        started = time.monotonic()
        self._name = name
        self._url = _discover_url()
        self._rpc_timeout = rpc_timeout
        self._ws = _open(self._url, rpc_timeout)
        self._lock = threading.Lock()
        # The calls waiting for replies, by request id. A reply is kept only
        # in the call it answers.
        self._pending: Dict[str, _Call] = {}
        # Requests no call waits for the replies to, by request id, with
        # their ops, "release" for a release (see _MAX_ABANDONED), oldest
        # first.
        self._abandoned: Dict[str, str] = {}
        self._callbacks: Dict[str, Callable[[MeshEvent], None]] = {}
        self._malformed = 0
        self._dropped = 0
        self._late = 0
        self._closed = False
        # The daemon's last word while it is an error that answered no
        # request, and, from when the client closes, why the connection
        # ended if the daemon said.
        self._parting: Optional[str] = None
        self._reason: Optional[str] = None
        # The requests on their way to the daemon, which the writer sends,
        # and the control frames ahead of them.
        self._outbox = _Queue()
        # The events on their way to the callbacks, which the dispatcher
        # runs, each holding its bytes until its callback has run.
        self._events = _Queue(max(1, event_queue), max(0, event_queue_bytes))
        # Set as the reader leaves: the daemon's end, or the client's, has
        # been read.
        self._reader_done = threading.Event()
        self._reader = threading.Thread(
            target=self._read_loop, name="pms-reader", daemon=True
        )
        self._writer = threading.Thread(
            target=self._write_loop, name="pms-writer", daemon=True
        )
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop, name="pms-dispatch", daemon=True
        )
        for thread in (self._reader, self._writer, self._dispatcher):
            thread.start()
        # Attach, within what the opening left of the deadline. A client the
        # daemon does not attach is closed, so that its reader and its
        # connection end with it.
        left = None if rpc_timeout is None else rpc_timeout - (time.monotonic() - started)
        try:
            self._roundtrip(
                {"op": "attach", "name": name, "protocol_version": PROTOCOL_VERSION},
                timeout=left,
            )
        except BaseException:
            self._close()
            raise

    # -- public API --------------------------------------------------------

    @property
    def events_malformed(self) -> int:
        """Events dropped as malformed: a payload that is not padded
        standard base64, or a field the protocol requires that is missing
        or of the wrong type. A conforming daemon sends none; each one is
        dropped rather than handed to a callback, which never receives
        bytes that nobody published, and reported through the `pms` logger
        at the first and at each doubling."""
        return self._malformed

    @property
    def events_dropped(self) -> int:
        """Events dropped because the callbacks fell behind: with
        `event_queue` events waiting for them, or with no room for a newer
        one in `event_queue_bytes`, the newer one is dropped, as the daemon
        drops for a slow connection, rather than held without limit.
        Reported through the `pms` logger at the first and at each
        doubling. Replies never wait behind events and are never dropped."""
        return self._dropped

    @property
    def late_replies(self) -> int:
        """Replies that came after their call had timed out. Such a reply
        is dropped, not acted on; for a subscribe, the subscription it
        made is released at once. A call that times out before its request
        is written withdraws it, and no reply comes. Reported through the
        `pms` logger at the first and at each doubling."""
        return self._late

    def send(self, channel: str, payload: bytes, type_name: Optional[str] = None) -> str:
        """Publish `payload` to `channel`. Returns the daemon's envelope_id."""
        msg = {
            "op": "send",
            "channel": channel,
            "payload": encode_payload(payload),
        }
        if type_name is not None:
            msg["type_name"] = type_name
        reply = self._roundtrip(msg)
        return reply.get("envelope_id") or ""

    def on(self, channel: str, callback: Callable[[MeshEvent], None]) -> str:
        """Subscribe to `channel`; `callback` fires per matching envelope."""
        return self.tap(TapFilter(channel=channel), callback)

    def tap(self, filter: TapFilter, callback: Callable[[MeshEvent], None]) -> str:
        """Subscribe with a full filter spec.

        `callback` runs on the client's dispatch thread, and may call back
        into the mesh. It is registered as the daemon's ack is read, so it
        sees every event of the subscription. If the ack does not come in
        time this raises `TimeoutError`, and a subscription the daemon
        makes after all is released as its ack arrives; `callback` never
        runs."""
        reply = self._roundtrip(
            {"op": "subscribe", "filter": filter.to_json()}, callback
        )
        return reply.get("subscription_id") or ""

    def unsubscribe(self, subscription_id: str) -> None:
        """Drop a subscription. Its callback is removed at once, whatever
        the daemon answers, and runs for no event after that. The request
        reaches the daemon even if the call times out, and a reply after
        the deadline is counted by `late_replies`."""
        with self._lock:
            self._callbacks.pop(subscription_id, None)
        self._roundtrip({"op": "unsubscribe", "subscription_id": subscription_id})

    def detach(self) -> None:
        """Clean detach."""
        try:
            self._roundtrip({"op": "detach"})
        except Exception:
            pass
        self._close()

    def run(self) -> None:
        """Block until the client closes (the connection ends, `detach`
        ends it, or one of its threads stops for any other reason), and
        the callbacks have run for every event it received."""
        while not self._closed:
            time.sleep(0.25)
        if threading.current_thread() is not self._dispatcher:
            self._dispatcher.join()

    def __enter__(self) -> "Mesh":
        return self

    def __exit__(self, *_exc) -> None:
        self.detach()

    # -- private -----------------------------------------------------------

    def _roundtrip(
        self,
        msg: dict,
        callback: Optional[Callable[[MeshEvent], None]] = None,
        timeout: Optional[float] = None,
    ) -> dict:
        rid = msg.setdefault("id", str(uuid.uuid4()))
        op = msg["op"]
        call = _Call(op, json.dumps(msg), callback)
        with self._lock:
            if self._closed:
                raise ConnectionError(f"the client is closed; op='{op}' not sent{self._because()}")
            self._pending[rid] = call
        # Refused only once the client has closed, which fails the call too.
        self._outbox.put(call)
        wait = self._rpc_timeout if timeout is None else max(0.0, timeout)
        if not call.done.wait(timeout=wait):
            # A request the writer has not taken is withdrawn, and the
            # daemon never sees it; an unsubscribe goes regardless.
            withdrawn = op != "unsubscribe" and self._outbox.withdraw(call)
            with self._lock:
                # Whoever takes the call from the table decides its fate: a
                # reply read just now is still taken.
                gave_up = self._pending.pop(rid, None) is call
                if gave_up and not withdrawn:
                    self._abandon(rid, op)
            if gave_up:
                raise TimeoutError(
                    f"no reply for op='{op}' id='{rid}' within {self._rpc_timeout} s"
                )
        reply = call.reply
        if reply is None:
            raise ConnectionError(
                f"the client closed before the reply to op='{op}' id='{rid}'{self._because()}"
            )
        if reply.get("op") == "error":
            raise RuntimeError(
                f"daemon error [{reply.get('code')}]: {reply.get('message')}"
            )
        return reply

    def _close(self) -> None:
        """Close the client: every call waiting fails at once, as does every
        call made from now on, the callbacks run for the events already
        queued, and the writer closes the connection as it leaves. Safe to
        call more than once and from any thread."""
        with self._lock:
            first = not self._closed
            self._closed = True
            if first:
                self._reason = self._parting
            waiting = list(self._pending.values())
            self._pending.clear()
            self._abandoned.clear()
        for call in waiting:
            call.done.set()
        self._events.close(drain=True)
        self._outbox.close(drain=False)
        if first and threading.current_thread() is not self._writer:
            self._writer.join(_CLOSE_GRACE)
            if self._writer.is_alive():
                self._cut()

    def _because(self) -> str:
        """Why the client closed, as the error of a call it fails gives it:
        the daemon's error that answered no request, when that was the last
        thing the daemon said."""
        reason = self._reason
        return "" if reason is None else f"; the daemon's last word was {reason}"

    def _cut(self) -> None:
        """Shut the connection down: under a writer stuck in a send the
        daemon does not take, and under a reader waiting for bytes, which
        both return at once. websocket-client's `abort` does this only
        while it counts the connection open, which its `close` stops doing
        before it writes the closing frame; so the socket is shut down
        directly where there is one."""
        sock = getattr(self._ws, "sock", None)
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
            else:
                self._ws.abort()
        except Exception:
            pass

    def _hang_up(self) -> None:
        """End the connection as the writer leaves: a closing frame, a
        moment for the reader to read the daemon's end, so that no bytes are
        left unread to answer with a reset, and the socket shut down. The
        reader closes it."""
        try:
            self._ws.send_close()
        except Exception:
            pass
        self._reader_done.wait(_CLOSE_GRACE)
        self._cut()

    def _ping_daemon(self) -> None:
        """Ask the daemon whether it is there: the writer sends a ping,
        ahead of the requests waiting."""
        self._outbox.put_control(_Control(_PING))

    def _abandon(self, rid: str, op: str) -> None:
        """Remember a request whose reply no call waits for (see
        _MAX_ABANDONED). Called with the lock held."""
        self._abandoned[rid] = op
        if len(self._abandoned) > _MAX_ABANDONED:
            del self._abandoned[next(iter(self._abandoned))]

    def _release(self, subscription_id: str) -> None:
        """Release a subscription whose subscribe timed out: the daemon
        made it, and nobody will run its events. The unsubscribe is the
        client's own, and its reply goes nowhere."""
        rid = str(uuid.uuid4())
        msg = {"op": "unsubscribe", "id": rid, "subscription_id": subscription_id}
        with self._lock:
            self._abandon(rid, "release")
        self._outbox.put(_Call("unsubscribe", json.dumps(msg)))

    def _count_late(self, op: str) -> None:
        """Count a reply that came after its call had timed out, and report
        it at the first and at each doubling, as the Rust client does."""
        with self._lock:
            self._late += 1
            n = self._late
        if n & (n - 1) == 0:
            _log.warning(
                "a reply to %s arrived after its call had timed out; "
                "dropped (%d so far)",
                op,
                n,
            )

    def _reject_malformed(self, msg: dict, what: str, error: ValueError) -> None:
        """Count an event dropped as malformed, and report it at the first
        and at each doubling, as the Rust client does."""
        with self._lock:
            self._malformed += 1
            n = self._malformed
        if n & (n - 1) == 0:
            _log.error(
                "%s; event dropped (subscription %s, envelope %s, %d so far): %s",
                what,
                _label(msg.get("subscription_id")),
                _label(msg.get("envelope_id")),
                n,
                error,
            )

    def _read_loop(self) -> None:
        # However the loop ends, the client closes with it, and the reader,
        # the socket's last user, closes the socket.
        frames = None
        try:
            frames = _Frames(self._ws.sock, _MAX_INBOUND_MESSAGE, self._ping_daemon)
            while not self._closed:
                opcode, payload = frames.next()
                if opcode == _TEXT:
                    try:
                        text = payload.decode("utf-8")
                    except UnicodeDecodeError:
                        raise _Violation(
                            "a text message from the daemon is not UTF-8"
                        ) from None
                    if text:
                        self._on_frame(text)
                elif opcode == _BINARY:
                    if payload:
                        self._on_frame(payload)
                elif opcode == _PING:
                    self._outbox.put_control(_Control(_PONG, payload))
                elif opcode == _CLOSE:
                    break  # the daemon is closing the connection
                # A pong only says the daemon is there.
        except _Violation as e:
            _log.error("%s; closing the connection", e)
        except _Silent:
            _log.warning(
                "the daemon has sent nothing for %s s, not even an answer to "
                "a ping; closing the connection",
                _SILENCE_LIMIT,
            )
        except Exception:
            pass  # the connection ended
        finally:
            self._reader_done.set()
            if frames is not None:
                frames.close()
            self._close()
            self._cut()
            try:
                self._ws.shutdown()
            except Exception:
                pass

    def _write_loop(self) -> None:
        # One request at a time, so that a call that times out can withdraw
        # a request not yet taken, and the control frames ahead of them. A
        # send that fails means the connection has; either way the client
        # closes, and the writer ends the connection as it leaves.
        try:
            while True:
                item = self._outbox.take()
                if item is None:
                    break
                if isinstance(item, _Call):
                    self._ws.send(item.text)
                elif item.opcode == _PING:
                    self._ws.ping(item.payload)
                else:
                    self._ws.pong(item.payload)
        except Exception:
            pass
        finally:
            self._close()
            self._hang_up()

    def _dispatch_loop(self) -> None:
        # One event at a time, in the order the events came. However the
        # loop ends, the client closes with it.
        try:
            while True:
                queued = self._events.take()
                if queued is None:
                    break
                event, size = queued
                try:
                    with self._lock:
                        callback = self._callbacks.get(event.subscription_id)
                    # None if unsubscribed since the event came.
                    if callback is not None:
                        try:
                            callback(event)
                        except Exception:
                            _log.exception(
                                "the callback of subscription %s raised on "
                                "envelope %s; dispatch goes on",
                                event.subscription_id,
                                event.envelope_id,
                            )
                finally:
                    # Its bytes count until its callback has run.
                    self._events.release(size)
        finally:
            self._close()

    def _on_frame(self, raw) -> None:
        """Handle one message from the daemon. A message the protocol does
        not allow is reported and otherwise ignored."""
        try:
            msg = json.loads(raw)
        except Exception as e:
            _log.error("a frame from the daemon is not JSON; ignored: %s", e)
            return
        if not isinstance(msg, dict):
            _log.error("a frame from the daemon is not a JSON object; ignored")
            return
        # Whatever the daemon says next, an error that answered no request
        # is no longer its last word.
        self._parting = None
        try:
            op = msg.get("op")
            if op in ("ack", "error"):
                self._on_reply(msg)
            elif op == "event":
                self._on_event(msg)
            # 'health' op (peer-state push) ignored in thin client v0
        except _Malformed as e:
            _log.error("a frame from the daemon is malformed; ignored: %s", e)
        except Exception:
            # Nothing a frame holds should get here; if something does, it
            # is reported and the reader goes on.
            _log.exception("a frame from the daemon could not be handled; ignored")

    def _on_reply(self, msg: dict) -> None:
        """Hand an ack or error to the call waiting for it. A reply to a
        call that timed out is dropped and counted, and the ack of a
        subscribe that timed out releases the subscription it names. An
        error that answers no other request is reported, and is the
        daemon's last word until it says more; an ack nobody waits for is
        dropped."""
        # The fields a call reads, checked before any call is answered.
        rid = _string(msg, "id", optional=True)
        error = None
        if msg["op"] == "ack":
            sub = _string(msg, "subscription_id", optional=True) or ""
            _string(msg, "envelope_id", optional=True)
        else:
            sub = ""
            error = f"daemon error [{_string(msg, 'code')}]: {_string(msg, 'message')}"
        with self._lock:
            call = None if rid is None else self._pending.pop(rid, None)
            late = None if rid is None or call is not None else self._abandoned.pop(rid, None)
            if call is not None:
                call.reply = msg
                if call.callback is not None and msg["op"] == "ack":
                    # Registered before the next frame is read, so no event
                    # of the subscription comes before its callback.
                    self._callbacks[sub] = call.callback
        if call is not None:
            call.done.set()
        elif late == "release":
            pass  # the client's own unsubscribe, whose reply goes nowhere
        elif late is not None:
            self._count_late(late)
            if late == "subscribe" and msg["op"] == "ack" and sub:
                self._release(sub)
        elif error is not None:
            self._parting = error
            _log.warning("an error from the daemon answers no request: %s", error)

    def _on_event(self, msg: dict) -> None:
        # Checked before anything else: an event whose payload is not the
        # one accepted form, or any field of which is not what the protocol
        # says, is never delivered.
        try:
            payload = decode_payload(msg.get("payload"))
        except ValueError as e:
            self._reject_malformed(msg, "event payload is not valid base64", e)
            return
        try:
            event = MeshEvent(
                subscription_id=_string(msg, "subscription_id"),
                envelope_id=_string(msg, "envelope_id"),
                channel=_string(msg, "channel"),
                type_id=_unsigned(msg, "type_id", 16, default=0),
                type_name=_string(msg, "type_name", optional=True),
                origin=_string(msg, "origin"),
                captured_at_unix_nanos=_unsigned(msg, "captured_at_unix_nanos", 64),
                payload=payload,
            )
        except _Malformed as e:
            self._reject_malformed(msg, "event is malformed", e)
            return
        with self._lock:
            subscribed = event.subscription_id in self._callbacks
        # Never waits: a callback that falls behind loses the newest events,
        # and the replies behind them still come. The size is counted here,
        # once, so that what a callback does to the event cannot change it.
        size = _event_bytes(event)
        if (
            subscribed
            and not self._events.put((event, size), size)
            and not self._events.closed
        ):
            with self._lock:
                self._dropped += 1
                n = self._dropped
            if n & (n - 1) == 0:
                _log.warning(
                    "event queue full; event dropped (subscription %s, %d so far)",
                    event.subscription_id,
                    n,
                )


def attach(
    name: str,
    *,
    rpc_timeout: float = _RPC_TIMEOUT,
    event_queue: int = _EVENT_QUEUE,
    event_queue_bytes: int = _EVENT_QUEUE_BYTES,
) -> Mesh:
    """Module-level convenience for `Mesh(name, ...)`."""
    return Mesh(
        name,
        rpc_timeout=rpc_timeout,
        event_queue=event_queue,
        event_queue_bytes=event_queue_bytes,
    )
