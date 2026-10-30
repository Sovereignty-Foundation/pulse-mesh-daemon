// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// The port protocol's golden frames, held against this client.
//
// The frames live under mesh/mesh-port-protocol/fixtures, written by the
// Rust types (the crate's `fixtures` test regenerates them). Every server
// frame there decodes here to what the fixture says, and the frames this
// client writes are the fixtures' frames, compared as parsed JSON: the
// request id, which the client draws, is dropped from both, and a field
// the Rust types write at its default (`capabilities: []`, `type_id: 0`,
// `flags: 0`) counts as absent, since this client leaves it out and the
// daemon reads both the same.
//
// Run from clients/pms-node-thin:
//
//     node --test

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { FakeDaemon, client } = require('./harness.js');

const { attach } = client;

// The fixtures sit under mesh/mesh-port-protocol at the root of the tree this
// client is in, however deep the client sits (under peripheral/bindings/dev-thin
// in the integrated tree, under clients/ in the daemon's own repository): the
// first ancestor that holds them.
const FIXTURES = (() => {
  for (let dir = __dirname; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, 'mesh', 'mesh-port-protocol', 'fixtures');
    if (fs.existsSync(candidate)) return candidate;
    if (path.dirname(dir) === dir) throw new Error(`mesh/mesh-port-protocol/fixtures not found above ${__dirname}`);
  }
})();

function fixtures(file) {
  const entries = JSON.parse(fs.readFileSync(path.join(FIXTURES, file), 'utf8'));
  return Object.fromEntries(entries.map((entry) => [entry.name, entry.frame]));
}

const CLIENT = fixtures('client.json');
const SERVER = fixtures('server.json');

const DEFAULTS = { capabilities: [], type_id: 0, flags: 0 };

/** The frame without its id and without fields at their default. */
function canonical(frame) {
  const out = {};
  for (const [key, value] of Object.entries(frame)) {
    if (key === 'id') continue;
    if (key in DEFAULTS && JSON.stringify(DEFAULTS[key]) === JSON.stringify(value)) continue;
    out[key] = value;
  }
  return out;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Whether `condition` holds within `ms`, polled. */
async function waitUntil(condition, ms = 5000) {
  const end = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > end) return false;
    await sleep(10);
  }
  return true;
}

/** Attach as `worker`, the name the fixtures use, to a fake daemon. */
async function attachedAs(configure = () => {}) {
  FakeDaemon.configure = configure;
  try {
    const mesh = await attach('worker');
    return { mesh, daemon: FakeDaemon.last };
  } finally {
    FakeDaemon.configure = () => {};
  }
}

/** The reply the daemon kept back, with its request id. */
async function heldReply(daemon) {
  assert.ok(await waitUntil(() => daemon.held.length > 0), 'the daemon holds the reply');
  const [reply] = daemon.held.splice(0);
  return reply;
}

test('the client writes the fixture frames', async () => {
  const { mesh, daemon } = await attachedAs();
  await mesh.send('c', 'hi');
  await mesh.send('c', 'hi', 'app/hi');
  await mesh.tap({}, () => {});
  await mesh.tap(
    { channel: 'c', type_id: 7, type_name: 'app/*', origin: 'worker@1a2b3c4d', health: true, snapshot: true },
    () => {},
  );
  await mesh.unsubscribe('sub-1');
  await mesh.detach();
  const wrote = daemon.requests.map(canonical);
  const want = [
    'attach.minimal',
    'send.minimal',
    'send.named',
    'subscribe.empty_filter',
    'subscribe.full_filter',
    'unsubscribe',
    'detach.minimal',
  ].map((name) => canonical(CLIENT[name]));
  assert.deepEqual(wrote, want);
});

test('every frame the client writes carries an id', async () => {
  const { mesh, daemon } = await attachedAs();
  await mesh.send('c', 'hi');
  await mesh.detach();
  for (const request of daemon.requests) assert.equal(typeof request.id, 'string', JSON.stringify(request));
});

test('the attach ack fixture attaches the client', async () => {
  FakeDaemon.configure = (daemon) => daemon.hold.add('attach');
  let attaching;
  try {
    attaching = attach('worker');
  } finally {
    FakeDaemon.configure = () => {};
  }
  const daemon = FakeDaemon.last;
  const reply = await heldReply(daemon);
  daemon.push({ ...SERVER['ack.attach'], id: reply.id });
  const mesh = await attaching;
  await mesh.detach();
});

test('every event fixture is delivered as the fixture says', async () => {
  const { mesh, daemon } = await attachedAs();
  const delivered = [];
  assert.equal(await mesh.on('c', (event) => delivered.push(event)), 'sub-1');
  for (const [i, name] of ['event.minimal', 'event.full'].entries()) {
    const frame = SERVER[name];
    daemon.push(frame);
    assert.ok(await waitUntil(() => delivered.length === i + 1), name);
    const event = delivered[i];
    assert.equal(event.subscriptionId, frame.subscription_id, name);
    assert.equal(event.envelopeId, frame.envelope_id, name);
    assert.equal(event.channel, frame.channel, name);
    assert.equal(event.typeId, frame.type_id, name);
    assert.equal(event.typeName, frame.type_name ?? null, name);
    assert.equal(event.origin, frame.origin, name);
    assert.equal(event.capturedAtUnixNanos, frame.captured_at_unix_nanos, name);
    assert.deepEqual(event.payload, Buffer.from(frame.payload, 'base64'), name);
  }
  await mesh.detach();
});

test('the send ack fixtures resolve a send', async () => {
  // A send to a node's ack carries `delivered`, which this client ignores.
  for (const name of [
    'ack.send',
    'ack.send.not_persisted',
    'ack.send.no_store',
    'ack.send.delivered',
    'ack.send.not_delivered',
  ]) {
    const { mesh, daemon } = await attachedAs((d) => d.hold.add('send'));
    const sending = mesh.send('c', 'hi');
    const reply = await heldReply(daemon);
    const frame = { ...SERVER[name], id: reply.id };
    daemon.push(frame);
    assert.equal(await sending, frame.envelope_id, name);
    await mesh.detach();
  }
});

test('the subscribe ack fixture names the subscription', async () => {
  const { mesh, daemon } = await attachedAs((d) => d.hold.add('subscribe'));
  const subscribing = mesh.on('c', () => {});
  const reply = await heldReply(daemon);
  const frame = { ...SERVER['ack.subscribe'], id: reply.id };
  daemon.push(frame);
  assert.equal(await subscribing, frame.subscription_id);
  await mesh.detach();
});

test('the error fixture fails the call with its code and message', async () => {
  const { mesh, daemon } = await attachedAs((d) => d.hold.add('send'));
  const sending = mesh.send('c', 'hi');
  const reply = await heldReply(daemon);
  const frame = { ...SERVER['error.with_id'], id: reply.id };
  daemon.push(frame);
  await assert.rejects(sending, (err) => err.message.includes(`[${frame.code}]`) && err.message.includes(frame.message));
  await mesh.detach();
});

test('the health fixtures are read and change nothing', async () => {
  const { mesh, daemon } = await attachedAs();
  const delivered = [];
  assert.equal(await mesh.on('c', (event) => delivered.push(event)), 'sub-1');
  for (const name of ['health.minimal', 'health.with_since']) daemon.push(SERVER[name]);
  // The client reads on: a later call is answered and no event came.
  assert.equal(await mesh.send('c', 'hi'), 'e'.repeat(32));
  assert.deepEqual(delivered, []);
  await mesh.detach();
});
