# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""The port protocol's golden frames, held against this client.

The frames live under mesh/mesh-port-protocol/fixtures, written by the Rust
types (the crate's `fixtures` test regenerates them). Every server frame
there decodes here to what the fixture says, and the frames this client
writes are the fixtures' frames, compared as parsed JSON: the request id,
which the client draws, is dropped from both, and a field the Rust types
write at its default (`capabilities: []`, `type_id: 0`, `flags: 0`) counts
as absent, since this client leaves it out and the daemon reads both the
same.

Run from clients/pms-py-thin:

    python3 -m unittest -v
"""

import base64
import json
import pathlib
import unittest

import pms
from tests.test_client import Attached, in_thread, wait_for



def _fixtures_dir():
    """The fixtures sit under mesh/mesh-port-protocol at the root of the tree this client is in, however deep
    the client sits (under peripheral/bindings/dev-thin in the integrated tree, under clients/ in the daemon's
    own repository): the first ancestor that holds them."""
    for d in pathlib.Path(__file__).resolve().parents:
        if (d / "mesh" / "mesh-port-protocol" / "fixtures").is_dir():
            return d / "mesh" / "mesh-port-protocol" / "fixtures"
    raise FileNotFoundError("mesh/mesh-port-protocol/fixtures above " + __file__)


FIXTURES = _fixtures_dir()


def fixtures(file):
    with open(FIXTURES / file, encoding="utf-8") as f:
        return {entry["name"]: entry["frame"] for entry in json.load(f)}


CLIENT = fixtures("client.json")
SERVER = fixtures("server.json")

DEFAULTS = {"capabilities": [], "type_id": 0, "flags": 0}


def canonical(frame):
    """The frame without its id and without fields at their default."""
    return {k: v for k, v in frame.items() if k != "id" and DEFAULTS.get(k, ...) != v}


class FixtureTest(Attached):
    """Attached as `worker`, the name the fixtures use, to a fake daemon."""

    def attached(self, configure=lambda daemon: None):
        self.connect(configure)
        mesh = pms.attach("worker")
        (daemon,) = self.daemons
        return mesh, daemon


class EncodeTest(FixtureTest):
    def test_the_client_writes_the_fixture_frames(self):
        mesh, daemon = self.attached()
        mesh.send("c", b"hi")
        mesh.send("c", b"hi", type_name="app/hi")
        mesh.tap(pms.TapFilter(), lambda event: None)
        mesh.tap(
            pms.TapFilter(
                channel="c",
                type_id=7,
                type_name="app/*",
                origin="worker@1a2b3c4d",
                health=True,
                snapshot=True,
            ),
            lambda event: None,
        )
        mesh.unsubscribe("sub-1")
        mesh.detach()
        wrote = [canonical(request) for request in daemon.requests]
        want = [
            canonical(CLIENT[name])
            for name in (
                "attach.minimal",
                "send.minimal",
                "send.named",
                "subscribe.empty_filter",
                "subscribe.full_filter",
                "unsubscribe",
                "detach.minimal",
            )
        ]
        self.assertEqual(wrote, want)

    def test_every_frame_the_client_writes_carries_an_id(self):
        mesh, daemon = self.attached()
        mesh.send("c", b"hi")
        mesh.detach()
        for request in daemon.requests:
            self.assertIsInstance(request.get("id"), str, request)


class DecodeTest(FixtureTest):
    def test_the_attach_ack_fixture_attaches_the_client(self):
        self.connect(lambda daemon: daemon.hold.add("attach"))
        attaching = in_thread(pms.attach, "worker")
        wait_for(lambda: self.daemons)
        (daemon,) = self.daemons
        wait_for(lambda: daemon.held)
        (reply,) = daemon.held
        daemon.held.clear()
        frame = dict(SERVER["ack.attach"], id=reply["id"])
        daemon.push(frame)
        mesh = attaching()
        self.assertIsInstance(mesh, pms.Mesh)
        mesh.detach()

    def test_every_event_fixture_is_delivered_as_the_fixture_says(self):
        mesh, daemon = self.attached()
        delivered = []
        self.assertEqual(mesh.on("c", delivered.append), "sub-1")
        for i, name in enumerate(("event.minimal", "event.full"), start=1):
            frame = SERVER[name]
            daemon.push(frame)
            wait_for(lambda: len(delivered) == i)
            event = delivered[-1]
            self.assertEqual(event.subscription_id, frame["subscription_id"], name)
            self.assertEqual(event.envelope_id, frame["envelope_id"], name)
            self.assertEqual(event.channel, frame["channel"], name)
            self.assertEqual(event.type_id, frame["type_id"], name)
            self.assertEqual(event.type_name, frame.get("type_name"), name)
            self.assertEqual(event.origin, frame["origin"], name)
            self.assertEqual(event.captured_at_unix_nanos, frame["captured_at_unix_nanos"], name)
            self.assertEqual(event.payload, base64.b64decode(frame["payload"], validate=True), name)
        mesh.detach()

    def test_the_send_ack_fixtures_resolve_a_send(self):
        # A send to a node's ack carries `delivered`, which this client ignores.
        names = ("ack.send", "ack.send.not_persisted", "ack.send.no_store", "ack.send.delivered", "ack.send.not_delivered")
        for name in names:
            with self.subTest(name=name):
                mesh, daemon = self.attached(lambda daemon: daemon.hold.add("send"))
                sending = in_thread(mesh.send, "c", b"hi")
                wait_for(lambda: daemon.held)
                (reply,) = daemon.held
                daemon.held.clear()
                frame = dict(SERVER[name], id=reply["id"])
                daemon.push(frame)
                self.assertEqual(sending(), frame["envelope_id"])
                mesh.detach()

    def test_the_subscribe_ack_fixture_names_the_subscription(self):
        mesh, daemon = self.attached(lambda daemon: daemon.hold.add("subscribe"))
        subscribing = in_thread(mesh.on, "c", lambda event: None)
        wait_for(lambda: daemon.held)
        (reply,) = daemon.held
        daemon.held.clear()
        frame = dict(SERVER["ack.subscribe"], id=reply["id"])
        daemon.push(frame)
        self.assertEqual(subscribing(), frame["subscription_id"])
        mesh.detach()

    def test_the_error_fixture_fails_the_call_with_its_code_and_message(self):
        mesh, daemon = self.attached(lambda daemon: daemon.hold.add("send"))
        sending = in_thread(mesh.send, "c", b"hi")
        wait_for(lambda: daemon.held)
        (reply,) = daemon.held
        daemon.held.clear()
        frame = dict(SERVER["error.with_id"], id=reply["id"])
        daemon.push(frame)
        error = sending()
        self.assertIsInstance(error, RuntimeError)
        self.assertIn(f"[{frame['code']}]", str(error))
        self.assertIn(frame["message"], str(error))
        mesh.detach()

    def test_the_health_fixtures_are_read_and_change_nothing(self):
        mesh, daemon = self.attached()
        delivered = []
        self.assertEqual(mesh.on("c", delivered.append), "sub-1")
        for name in ("health.minimal", "health.with_since"):
            daemon.push(SERVER[name])
        # The client reads on: a later call is answered and no event came.
        self.assertEqual(mesh.send("c", b"hi"), "e" * 32)
        self.assertEqual(delivered, [])
        mesh.detach()


if __name__ == "__main__":
    unittest.main()
