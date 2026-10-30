// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Tests for the thin Node client: its payload codec, which accepts only the
// padded standard base64 the daemon and the Rust client accept; what the
// client does with an event whose payload is in any other form, or a frame
// with a field of the wrong type; how it survives a callback that throws
// or rejects, and a daemon that refuses to attach it; and the bounds it
// keeps: on what it holds for a daemon that does not read, on the time an
// attach takes, on the frames and the time a message takes, however they
// split it, and on the silence it takes from the daemon.
//
// Run from clients/pms-node-thin:
//
//     node --test
//
// Nothing needs installing and no daemon needs running: a fake stands in
// for the `ws` package and its WebSocket.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');

const { FakeDaemon, client } = require('./harness.js');
const { MeshQueueFullError, MeshTimeoutError, attach, decodePayload, encodePayload, _limits } = client;

// RFC 4648 §10, and one more.
const VECTORS = [
  ['', ''],
  ['f', 'Zg=='],
  ['fo', 'Zm8='],
  ['foo', 'Zm9v'],
  ['foob', 'Zm9vYg=='],
  ['fooba', 'Zm9vYmE='],
  ['foobar', 'Zm9vYmFy'],
  ['hello', 'aGVsbG8='],
];

// Every form the daemon and the Rust client refuse, by the fault.
const REFUSED = {
  'padding missing': ['aGk', 'Zg', 'Zg=', 'aGVsbG8', 'Zm9vY'],
  'padding in mid-string': ['AA==AA==', 'Zm8=Zm8=', 'AA=A', '=AAA', 'AAAA=AAA'],
  'more padding than the length needs': ['A===', '====', 'AAAA====', 'Zg==='],
  whitespace: [' Zg==', 'Zm\r\nYmFy', 'Zm9v\tZg==', 'aGVsbG8=\n'],
  'the URL-safe alphabet': ['Zm-v', 'Zm_v'],
  'bytes outside the alphabet': ['Zm9*', '\0AAA', 'Zmé='],
  'bits set after the last byte': ['Zh==', 'Zm9=', 'AB==', 'AAB=', 'Zm9vZh=='],
};

/** Reproducible bytes (xorshift). */
function noise(seed, length) {
  let x = Math.imul(seed + 1, 0x9e3779b1) >>> 0 || 1;
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

test('decodePayload accepts padded standard base64', () => {
  for (const [plain, text] of VECTORS) {
    assert.deepEqual(decodePayload(text), Buffer.from(plain), text);
  }
});

test('decodePayload round-trips every length from 0 to 64', () => {
  for (let length = 0; length <= 64; length += 1) {
    for (const bytes of [Buffer.alloc(length), Buffer.alloc(length, 0xff), noise(length, length)]) {
      assert.deepEqual(decodePayload(encodePayload(bytes)), bytes);
    }
  }
});

test('decodePayload refuses every other form', () => {
  for (const [fault, texts] of Object.entries(REFUSED)) {
    for (const text of texts) {
      assert.throws(
        () => decodePayload(text),
        /not padded standard base64/,
        `${fault}: ${JSON.stringify(text)}`,
      );
    }
  }
});

test('decodePayload refuses what a MIME encoder writes', () => {
  // Line breaks every 76 characters, and one at the end.
  const text = noise(7, 60).toString('base64');
  const wrapped = `${text.slice(0, 76)}\n${text.slice(76)}\n`;
  assert.throws(() => decodePayload(wrapped), /not padded standard base64/);
});

test('decodePayload refuses what is not a string', () => {
  for (const value of [undefined, null, 5, Buffer.from('Zg=='), ['Zg=='], { payload: 'Zg==' }]) {
    assert.throws(() => decodePayload(value), /not a string/, String(value));
  }
});

test('encodePayload writes the one accepted form', () => {
  for (const [plain, text] of VECTORS) {
    assert.equal(encodePayload(Buffer.from(plain)), text);
  }
  for (let length = 0; length <= 64; length += 1) {
    const bytes = noise(100 + length, length);
    const text = encodePayload(bytes);
    assert.equal(text.length, Math.ceil(length / 3) * 4);
    assert.equal(text.split('=').length - 1, (3 - (length % 3)) % 3);
    assert.deepEqual(decodePayload(text), bytes);
  }
  assert.equal(encodePayload('hi'), 'aGk=', 'a string is sent as its UTF-8');
  assert.equal(encodePayload(new Uint8Array([104, 105])), 'aGk=');
});

/** Stands for an event's payload left out. */
const MISSING = Symbol('missing');

/** An event frame; a `payload` of `MISSING` leaves the payload out. */
function event(envelopeId, payload = 'aGk=', subscriptionId = 'sub-1') {
  const frame = {
    op: 'event',
    subscription_id: subscriptionId,
    envelope_id: envelopeId,
    channel: 'c',
    type_id: 0,
    origin: 'o@1',
    captured_at_unix_nanos: 0,
  };
  if (payload !== MISSING) frame.payload = payload;
  return frame;
}

/**
 * Attach to a fake daemon and subscribe to `c`: the events delivered
 * collect in `delivered`, and the client's warnings in `warnings`.
 */
async function attached(t, options) {
  const warnings = [];
  const onWarning = (warning) => {
    if (warning.name.startsWith('Pms')) warnings.push(warning);
  };
  process.on('warning', onWarning);
  const mesh = await attach('thin-test', options);
  const daemon = FakeDaemon.last;
  const delivered = [];
  assert.equal(await mesh.on('c', (ev) => delivered.push(ev)), 'sub-1');
  t.after(async () => {
    await mesh.detach();
    process.off('warning', onWarning);
  });
  return { mesh, daemon, delivered, warnings };
}

/** Let the process warnings, emitted on a later tick, arrive. */
function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('an event in the accepted form is delivered', async (t) => {
  const { mesh, daemon, delivered } = await attached(t);
  daemon.push(event('e1', 'aGk='));
  daemon.push(event('e2', ''));
  assert.deepEqual(
    delivered.map((ev) => [ev.envelopeId, ev.payload.toString()]),
    [['e1', 'hi'], ['e2', '']],
  );
  assert.equal(mesh.eventsMalformed, 0);
});

test('an event in any other form is reported and never delivered', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  const bad = ['aGk', 'AA==AA==', 'Zh==', 'aGk=\n', 'aGk_', MISSING, 5];
  bad.forEach((payload, i) => daemon.push(event(`bad-${i}`, payload)));
  daemon.push(event('good', 'aGk='));
  await settle();
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['good'], 'no wrong payload was delivered');
  assert.deepEqual(delivered[0].payload, Buffer.from('hi'));
  assert.equal(mesh.eventsMalformed, bad.length);
  // Reported at the first, second and fourth, as the Rust client reports its
  // count.
  assert.deepEqual(
    warnings.map((warning) => warning.code),
    ['PMS_MALFORMED_EVENT', 'PMS_MALFORMED_EVENT', 'PMS_MALFORMED_EVENT'],
  );
  assert.match(warnings[0].message, /not valid base64.*bad-0/);
});

test('a frame that is not a JSON object is reported and skipped', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  for (const frame of ['not json', 'null', '[1, 2]', '5']) daemon.push(frame);
  daemon.push(event('after'));
  await settle();
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['after']);
  assert.deepEqual(
    warnings.map((warning) => warning.code),
    ['PMS_MALFORMED_FRAME', 'PMS_MALFORMED_FRAME', 'PMS_MALFORMED_FRAME', 'PMS_MALFORMED_FRAME'],
  );
  assert.equal(mesh.eventsMalformed, 0);
});

test('send writes the one accepted form', async (t) => {
  const { mesh, daemon } = await attached(t);
  const payload = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.equal(await mesh.send('c', payload), 'e'.repeat(32));
  const sent = daemon.requests.at(-1);
  assert.equal(sent.op, 'send');
  assert.equal(sent.payload, payload.toString('base64'));
  assert.deepEqual(decodePayload(sent.payload), payload);
});

test('an event may leave out what the protocol makes optional', async (t) => {
  const { mesh, daemon, delivered } = await attached(t);
  const noTypeId = event('no-type-id');
  delete noTypeId.type_id;
  daemon.push(noTypeId);
  daemon.push({ ...event('null-type-name'), type_name: null });
  daemon.push({ ...event('widest'), type_id: 65535, type_name: 't', captured_at_unix_nanos: 2 ** 63 });
  assert.deepEqual(
    delivered.map((ev) => [ev.envelopeId, ev.typeId, ev.typeName]),
    [['no-type-id', 0, null], ['null-type-name', 0, null], ['widest', 65535, 't']],
  );
  assert.equal(delivered[2].capturedAtUnixNanos, 2 ** 63);
  assert.equal(mesh.eventsMalformed, 0);
});

test('an event with a field of the wrong type is reported and never delivered', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  const wrong = [
    ['type_id', null], // the review's case
    ['type_id', '5'],
    ['type_id', 1.5],
    ['type_id', true],
    ['type_id', -1],
    ['type_id', 65536],
    ['captured_at_unix_nanos', null],
    ['captured_at_unix_nanos', -1],
    ['captured_at_unix_nanos', 2 ** 64],
    ['captured_at_unix_nanos', '0'],
    ['subscription_id', ['sub-1']],
    ['subscription_id', { id: 'sub-1' }],
    ['subscription_id', null],
    ['envelope_id', 7],
    ['channel', null],
    ['origin', false],
    ['type_name', 5],
  ];
  const required = ['subscription_id', 'envelope_id', 'channel', 'origin', 'captured_at_unix_nanos'];
  // First, so it is reported: an id whose toString is no function, which
  // threw out of the report.
  daemon.push({ ...event('unprintable', 'aGk'), subscription_id: { toString: 1 } });
  wrong.forEach(([key, value], i) => daemon.push({ ...event(`bad-${i}`), [key]: value }));
  for (const key of required) {
    const frame = event(`without-${key}`);
    delete frame[key];
    daemon.push(frame);
  }
  daemon.push(event('good'));
  await settle();
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['good'], 'no malformed event was delivered');
  const dropped = 1 + wrong.length + required.length;
  assert.equal(mesh.eventsMalformed, dropped);
  // Reported at the first and at each doubling.
  assert.equal(warnings.length, Math.floor(Math.log2(dropped)) + 1);
  assert.ok(warnings.every((warning) => warning.code === 'PMS_MALFORMED_EVENT'));
  assert.match(warnings[0].message, /^event payload is not valid base64; event dropped \(subscription an object, envelope unprintable, 1 so far\)/);
  assert.match(warnings[1].message, /^event is malformed; .*type_id is null/);
});

test('a reply with a field of the wrong type is reported and ignored', async (t) => {
  const { mesh, daemon, warnings } = await attached(t);
  daemon.hold.add('send');
  const sending = mesh.send('c', 'x');
  const { id } = daemon.requests.at(-1);
  // A code whose toString is no function, which threw out of the client.
  daemon.push({ op: 'error', id, code: { toString: 1 }, message: 'm' });
  daemon.push({ op: 'ack', id: 5 });
  daemon.push({ op: 'ack', id: 'nobody', subscription_id: ['x'] });
  await settle();
  assert.deepEqual(
    warnings.map((warning) => warning.code),
    ['PMS_MALFORMED_FRAME', 'PMS_MALFORMED_FRAME', 'PMS_MALFORMED_FRAME'],
  );
  assert.match(warnings[0].message, /malformed; ignored: code is an object, not a string/);
  // The call still waits for its reply, and takes it.
  daemon.pushHeld();
  assert.equal(await sending, 'e'.repeat(32));
  assert.equal(mesh.eventsMalformed, 0);
});

test('a callback that throws is reported and the client reads on', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  const broken = () => {
    throw new Error('a bug in the callback');
  };
  assert.equal(await mesh.on('broken', broken), 'sub-2');
  // The throw escaped into `ws`: an uncaught exception, which ends the
  // process, or a deaf connection if the process catches it.
  daemon.push(event('e1', 'aGk=', 'sub-2'));
  daemon.push(event('e2'));
  await settle();
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['e2']);
  assert.deepEqual(warnings.map((warning) => [warning.name, warning.code]), [['PmsCallbackWarning', 'PMS_CALLBACK_THREW']]);
  assert.match(warnings[0].message, /subscription sub-2 threw on envelope e1; reading goes on: a bug in the callback/);
  assert.match(warnings[0].detail, /^Error: a bug in the callback\n/);
  assert.equal(await mesh.send('c', 'x'), 'e'.repeat(32));
});

test('a callback whose promise rejects is reported and the client reads on', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  // Its rejection went unhandled, which ends the process.
  assert.equal(await mesh.on('async', async () => Promise.reject(new Error('an async bug'))), 'sub-2');
  daemon.push(event('e1', 'aGk=', 'sub-2'));
  daemon.push(event('e2'));
  await settle();
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['e2']);
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_CALLBACK_THREW']);
  assert.match(warnings[0].message, /on envelope e1; reading goes on: an async bug/);
});

test('an event right behind the subscribe ack reaches the callback', async (t) => {
  const { mesh, daemon } = await attached(t);
  daemon.follow.set('subscribe', [event('first', 'aGk=', 'sub-2')]);
  const got = [];
  assert.equal(await mesh.on('d', (ev) => got.push(ev.envelopeId)), 'sub-2');
  assert.deepEqual(got, ['first']);
});

test('a client the daemon does not attach is closed', async () => {
  FakeDaemon.configure = (daemon) => daemon.refuse.set('attach', 'limit_exceeded');
  try {
    await assert.rejects(attach('refused'), /\[limit_exceeded\]/);
  } finally {
    FakeDaemon.configure = () => {};
  }
  assert.ok(FakeDaemon.last.closed, 'its connection no longer keeps the process alive');
});

test('when the connection ends, run() resolves and calls fail', async (t) => {
  // The client did this already: the pin keeps it so.
  const { mesh, daemon } = await attached(t);
  daemon.hold.add('send');
  const waiting = mesh.send('c', 'x');
  daemon.hangUp();
  await assert.rejects(waiting, /connection closed/);
  await mesh.run();
  await assert.rejects(mesh.send('c', 'y'), /connection closed/);
});

test('a call against a silent daemon rejects at its deadline', async (t) => {
  const { mesh, daemon } = await attached(t, { rpcTimeoutMs: 100 });
  daemon.silent = true;
  const started = Date.now();
  await assert.rejects(mesh.send('c', 'x'), (err) => {
    assert.ok(err instanceof MeshTimeoutError);
    assert.deepEqual([err.name, err.code, err.op], ['MeshTimeoutError', 'PMS_TIMEOUT', 'send']);
    return true;
  });
  const waited = Date.now() - started;
  assert.ok(waited >= 90 && waited < 1000, `rejected after ${waited} ms`);
  assert.equal(mesh._pending.size, 0, 'its entry is released');
});

test('an attach against a silent daemon rejects at its deadline and closes', async () => {
  FakeDaemon.configure = (daemon) => {
    daemon.silent = true;
  };
  try {
    await assert.rejects(attach('silent', { rpcTimeoutMs: 100 }), MeshTimeoutError);
  } finally {
    FakeDaemon.configure = () => {};
  }
  assert.ok(FakeDaemon.last.closed);
});

test('a reply after the deadline is counted, and a late subscribe released', async (t) => {
  const { mesh, daemon, warnings } = await attached(t, { rpcTimeoutMs: 100 });
  daemon.hold.add('subscribe');
  const ran = [];
  await assert.rejects(mesh.on('late', (ev) => ran.push(ev)), MeshTimeoutError);
  daemon.pushHeld(); // the ack, naming sub-2
  assert.equal(mesh.lateReplies, 1);
  const release = daemon.requests.at(-1);
  assert.deepEqual([release.op, release.subscription_id], ['unsubscribe', 'sub-2']);
  daemon.push(event('e1', 'aGk=', 'sub-2'));
  await settle();
  assert.deepEqual(ran, [], 'its callback never runs');
  assert.deepEqual(warnings.map((warning) => [warning.name, warning.code]), [['PmsLateReplyWarning', 'PMS_LATE_REPLY']]);
  assert.match(warnings[0].message, /^a reply to subscribe arrived after its call had timed out; dropped \(1 so far\)$/);
});

test('an unsubscribe removes its callback at once, and one that times out still goes', async (t) => {
  const { mesh, daemon, delivered } = await attached(t, { rpcTimeoutMs: 100 });
  daemon.hold.add('unsubscribe');
  const unsubscribing = mesh.unsubscribe('sub-1');
  // Before the daemon answers, the callback is gone.
  daemon.push(event('before-the-reply'));
  await assert.rejects(unsubscribing, MeshTimeoutError);
  assert.equal(daemon.requests.at(-1).op, 'unsubscribe');
  daemon.push(event('after-the-deadline'));
  daemon.pushHeld();
  assert.deepEqual(delivered, []);
  assert.equal(mesh.lateReplies, 1);
});

test('rpcTimeoutMs must be a delay the timers keep', async () => {
  for (const rpcTimeoutMs of [0, -1, Infinity, NaN, 2 ** 31, '100']) {
    await assert.rejects(attach('x', { rpcTimeoutMs }), RangeError, String(rpcTimeoutMs));
  }
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Whether `condition` holds within `ms`, polled. */
async function waitUntil(condition, ms) {
  const end = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > end) return false;
    await sleep(10);
  }
  return true;
}

/** The payloads of the sends the daemon has read, as text. */
function sent(daemon) {
  return daemon.requests.filter((r) => r.op === 'send').map((r) => decodePayload(r.payload).toString());
}

/** Shorten the silence limits for one test. */
function shortSilence(t, pingAfterMs = 50, silenceLimitMs = 150) {
  shortLimits(t, { pingAfterMs, silenceLimitMs });
}

/** Shorten any of the client's time limits for one test. */
function shortLimits(t, limits) {
  const saved = { ..._limits };
  Object.assign(_limits, limits);
  t.after(() => Object.assign(_limits, saved));
}

/** Attach to a fake daemon set up by `configure` first. */
async function attachedTo(t, configure, options) {
  FakeDaemon.configure = configure;
  try {
    return await attached(t, options);
  } finally {
    FakeDaemon.configure = () => {};
  }
}

test('a message over 16 MiB closes the connection, and is reported', async (t) => {
  const { mesh, daemon, warnings } = await attached(t);
  // `ws` refuses it at its header; by default it would take 100 MiB.
  assert.equal(daemon.options.maxPayload, 16 * 1024 * 1024);
  daemon.hold.add('send');
  const waiting = mesh.send('c', 'x');
  // As `ws` ends such a connection: an error, then the close.
  daemon.emit('error', new RangeError('Max payload size exceeded'));
  daemon.hangUp();
  await assert.rejects(waiting, /connection closed/);
  await settle();
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_CONNECTION_FAILED']);
  assert.match(warnings[0].message, /failed and closes: Max payload size exceeded$/);
});

test('a call is refused, with nothing sent, while the client holds over 16 MiB for the daemon', async (t) => {
  const { mesh, daemon } = await attached(t);
  const before = daemon.requests.length;
  daemon.bufferedAmount = 16 * 1024 * 1024 + 1;
  await assert.rejects(mesh.send('c', 'x'), (err) => {
    assert.ok(err instanceof MeshQueueFullError);
    assert.deepEqual([err.name, err.code, err.op], ['MeshQueueFullError', 'PMS_QUEUE_FULL', 'send']);
    assert.match(err.message, /^op='send' was not sent: the client holds 16777217 bytes of requests/);
    return true;
  });
  assert.equal(daemon.requests.length, before, 'nothing was sent');
  assert.equal(mesh._pending.size, 0);
  // At the cap, not over it, a call goes.
  daemon.bufferedAmount = 16 * 1024 * 1024;
  assert.equal(await mesh.send('c', 'x'), 'e'.repeat(32));
});

test('requests go to the socket one at a time, and one still waiting at its deadline never goes', async (t) => {
  const { mesh, daemon } = await attached(t, { rpcTimeoutMs: 100 });
  daemon.stalled = true;
  const first = mesh.send('c', 'first');
  const second = mesh.send('c', 'second');
  // The first is with the socket, the second waits for it to be written.
  assert.equal(daemon.unwritten.length, 1);
  assert.equal(mesh._outbox.size, 1);
  await assert.rejects(first, MeshTimeoutError);
  await assert.rejects(second, MeshTimeoutError);
  assert.equal(mesh._outbox.size, 0, 'the second was withdrawn');
  daemon.drain();
  assert.equal(await mesh.send('c', 'third'), 'e'.repeat(32));
  // The first had been begun, and goes, its reply late; the second never.
  assert.deepEqual(sent(daemon), ['first', 'third']);
  assert.equal(mesh.lateReplies, 1);
});

test('a burst of calls waits its turn and goes out in order', async (t) => {
  const { mesh, daemon } = await attached(t);
  const replies = await Promise.all(Array.from({ length: 50 }, (_, i) => mesh.send('c', `m${i}`)));
  assert.equal(replies.length, 50);
  assert.deepEqual(sent(daemon), Array.from({ length: 50 }, (_, i) => `m${i}`));
});

test('a daemon that stops reading costs the client at most 16 MiB and one request', async (t) => {
  // The review's case: 200 sends of 1 MiB buffered 265 MiB, and each
  // reached the daemon after its call had timed out.
  const { mesh, daemon } = await attached(t, { rpcTimeoutMs: 200 });
  daemon.stalled = true;
  const payload = Buffer.alloc(1 << 20, 7);
  const calls = Array.from({ length: 64 }, () => mesh.send('c', payload).then(() => 'ok', (err) => err.name));
  const request = Buffer.byteLength(JSON.stringify({ op: 'send', channel: 'c', payload: payload.toString('base64'), id: randomUUID() }));
  const held = mesh._outboxBytes + daemon.bufferedAmount;
  assert.ok(held <= 16 * 1024 * 1024 + request, `the client holds ${held} bytes`);
  const outcomes = await Promise.all(calls);
  // Twelve fit: the one with the socket and eleven waiting for it.
  assert.equal(outcomes.filter((outcome) => outcome === 'MeshTimeoutError').length, 12);
  assert.equal(outcomes.filter((outcome) => outcome === 'MeshQueueFullError').length, 52);
  assert.equal(mesh._outbox.size, 0, 'the calls that timed out withdrew their requests');
  daemon.drain();
  assert.equal(await mesh.send('c', 'after'), 'e'.repeat(32));
  // Only the request the socket had begun to write reached the daemon.
  assert.equal(sent(daemon).length, 2);
});

test('an unsubscribe of a subscription the client holds is never refused', async (t) => {
  // The review's case: made while the client held over 16 MiB for a
  // stalled daemon, it was refused with the sends, its callback already
  // gone, and never sent; the daemon kept the subscription, and went on
  // sending its events to a client that dropped them.
  const { mesh, daemon, delivered } = await attached(t);
  daemon.stalled = true;
  daemon.bufferedAmount = 16 * 1024 * 1024 + 1;
  await assert.rejects(mesh.send('c', 'x'), MeshQueueFullError);
  const unsubscribing = mesh.unsubscribe('sub-1');
  // One of a subscription the client no longer holds is refused as any
  // call is, having changed nothing.
  await assert.rejects(mesh.unsubscribe('sub-1'), MeshQueueFullError);
  daemon.drain();
  await unsubscribing;
  assert.deepEqual(daemon.requests.filter((r) => r.op === 'unsubscribe').map((r) => r.subscription_id), ['sub-1']);
  daemon.push(event('after'));
  assert.deepEqual(delivered, []);
});

test('an error that answers no request is reported, and is the reason the connection ended', async (t) => {
  // The daemon refuses a frame over its size limit so, unable to read its
  // id, and closes: the call waiting failed with nothing but "connection
  // closed", and nothing was reported.
  const { mesh, daemon, warnings } = await attached(t);
  daemon.hold.add('send');
  const refusal = 'frame of 1228891 bytes exceeds the 1048576 byte limit';
  const reason = `connection closed; the daemon's last word was [payload_too_large] ${refusal}`;
  const failed = assert.rejects(mesh.send('c', 'x'), (err) => {
    assert.equal(err.message, reason);
    return true;
  });
  daemon.push({ op: 'error', code: 'payload_too_large', message: refusal });
  daemon.hangUp();
  await failed;
  // And every call after gives it.
  await assert.rejects(mesh.send('c', 'y'), (err) => {
    assert.equal(err.message, reason);
    return true;
  });
  await settle();
  assert.deepEqual(warnings.map((warning) => [warning.name, warning.code]), [['PmsProtocolWarning', 'PMS_DAEMON_ERROR']]);
  assert.equal(warnings[0].message, `an error from the daemon answers no request: [payload_too_large] ${refusal}`);
});

test('an error that answers no request is no reason once the daemon says more', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  // An id no call waits for answers no request either.
  daemon.push({ op: 'error', id: 'nobody', code: 'bad_request', message: 'malformed JSON' });
  daemon.push(event('after'));
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['after']);
  daemon.hold.add('send');
  const failed = assert.rejects(mesh.send('c', 'x'), (err) => {
    assert.equal(err.message, 'connection closed');
    return true;
  });
  daemon.hangUp();
  await failed;
  await settle();
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_DAEMON_ERROR']);
});

test('an error that answers a release answers a request', async (t) => {
  // The client's own unsubscribe, releasing a subscription whose subscribe
  // timed out, is a request: an error in reply to it is not the daemon's
  // last word.
  const { mesh, daemon, warnings } = await attached(t, { rpcTimeoutMs: 100 });
  daemon.hold.add('subscribe');
  daemon.refuse.set('unsubscribe', 'unknown_subscription');
  await assert.rejects(mesh.on('late', () => {}), MeshTimeoutError);
  daemon.pushHeld(); // the ack, naming sub-2, and so the release
  await settle(); // and the daemon's refusal of the release
  assert.equal(daemon.requests.at(-1).op, 'unsubscribe');
  assert.equal(mesh._abandoned.size, 0);
  daemon.hold.add('send');
  const failed = assert.rejects(mesh.send('c', 'x'), (err) => {
    assert.equal(err.message, 'connection closed');
    return true;
  });
  daemon.hangUp();
  await failed;
  await settle();
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_LATE_REPLY']);
});

test('the opening and the attach share one deadline', async () => {
  FakeDaemon.configure = (daemon) => {
    daemon.openDelayMs = 400;
    daemon.silent = true;
  };
  const started = Date.now();
  try {
    await assert.rejects(attach('slow', { rpcTimeoutMs: 600 }), (err) => {
      assert.ok(err instanceof MeshTimeoutError);
      assert.equal(err.op, 'attach');
      return true;
    });
  } finally {
    FakeDaemon.configure = () => {};
  }
  // The attach had what the opening left of the deadline, not a deadline
  // of its own, which would have ended it after a second.
  const waited = Date.now() - started;
  assert.ok(waited >= 590 && waited < 900, `rejected after ${waited} ms`);
  assert.deepEqual(FakeDaemon.last.requests.map((r) => r.op), ['attach']);
  assert.ok(FakeDaemon.last.closed);
});

test('an opening that outlasts the deadline is cut', async () => {
  // A daemon that answered the upgrade a byte at a time restarted the
  // handshake timeout with each byte.
  FakeDaemon.configure = (daemon) => {
    daemon.neverOpen = true;
  };
  const started = Date.now();
  try {
    await assert.rejects(attach('trickled', { rpcTimeoutMs: 100 }), (err) => {
      assert.ok(err instanceof MeshTimeoutError);
      assert.match(err.message, /^no reply for op='attach' id='[0-9a-f-]{36}' within 100 ms$/);
      return true;
    });
  } finally {
    FakeDaemon.configure = () => {};
  }
  const waited = Date.now() - started;
  assert.ok(waited >= 90 && waited < 600, `rejected after ${waited} ms`);
  assert.ok(FakeDaemon.last.terminated, 'the opening is cut');
  assert.deepEqual(FakeDaemon.last.requests, []);
});

test('a silent daemon is pinged, and given up when the ping goes unanswered', async (t) => {
  shortSilence(t);
  const { mesh, daemon, warnings } = await attachedTo(t, (d) => {
    d.answerPings = false;
  });
  daemon.hold.add('send');
  const started = Date.now();
  await assert.rejects(mesh.send('c', 'x'), /connection closed/);
  assert.ok(Date.now() - started < 1000);
  assert.equal(daemon.pings, 1);
  assert.ok(daemon.terminated);
  await settle();
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_DAEMON_SILENT']);
  assert.match(warnings[0].message, /^the daemon has sent nothing for 0.15 s, not even an answer to a ping/);
});

test('a daemon that answers the ping is kept', async (t) => {
  shortSilence(t);
  const { mesh, daemon } = await attached(t);
  await sleep(500);
  assert.equal(mesh._closed, false);
  assert.ok(daemon.pings >= 3, `${daemon.pings} pings`);
  assert.equal(await mesh.send('c', 'x'), 'e'.repeat(32));
});

test('what the daemon sends keeps the client from pinging', async (t) => {
  shortSilence(t, 250, 750);
  const { mesh, daemon } = await attachedTo(t, (d) => {
    d.answerPings = false;
  });
  // The daemon's own pings, as it sends them every 30 seconds.
  for (let i = 0; i < 12; i += 1) {
    daemon.emit('ping', Buffer.alloc(0));
    await sleep(50);
  }
  assert.equal(mesh._closed, false);
  assert.equal(daemon.pings, 0);
});

test('a late ping still has the rest of the limit for its answer', async (t) => {
  // A client held up itself, its loop kept busy or its machine asleep,
  // finds the daemon silent past the limit: it pings, and waits.
  shortSilence(t, 50, 650);
  const { mesh, daemon } = await attachedTo(t, (d) => {
    d.answerPings = false;
  });
  clearTimeout(mesh._watchTimer);
  mesh._heard -= 10_000;
  mesh._watch();
  assert.equal(daemon.pings, 1);
  await sleep(100);
  assert.equal(mesh._closed, false, 'the answer has 600 ms from the ping');
  assert.ok(await waitUntil(() => mesh._closed, 3000), 'and then the daemon is given up');
});

/**
 * One frame as a daemon writes it (RFC 6455 §5.2); `length` announces
 * another length than the payload's.
 */
function wsFrame(payload = Buffer.alloc(0), opcode = 0x1, fin = true, length = payload.length) {
  const first = (fin ? 0x80 : 0) | opcode;
  let head;
  if (length < 126) {
    head = Buffer.from([first, length]);
  } else if (length < 2 ** 16) {
    head = Buffer.from([first, 126, 0, 0]);
    head.writeUInt16BE(length, 2);
  } else {
    head = Buffer.from([first, 127, 0, 0, 0, 0, 0, 0, 0, 0]);
    head.writeBigUInt64BE(BigInt(length), 2);
  }
  return Buffer.concat([head, payload]);
}

/** Reproducible numbers from 0 up to 1 (xorshift). */
function randomness(seed) {
  let x = Math.imul(seed + 1, 0x9e3779b1) | 0 || 1;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 2 ** 32;
  };
}

/** A whole number from `low` to `high`, both included. */
function int(random, low, high) {
  return low + Math.floor(random() * (high - low + 1));
}

function pick(random, choices) {
  return choices[Math.floor(random() * choices.length)];
}

/**
 * `message` as frames a daemon, or anything between, may split it into:
 * `pieces` of them, cut at random, empty ones among them, and a ping or a
 * pong now and then between two, which RFC 6455 allows.
 */
function split(random, message, opcode, pieces) {
  const cuts = Array.from({ length: pieces - 1 }, () => int(random, 0, message.length));
  const bounds = [0, ...cuts.sort((a, b) => a - b), message.length];
  const frames = [];
  for (let i = 0; i < pieces; i += 1) {
    frames.push(wsFrame(message.subarray(bounds[i], bounds[i + 1]), i === 0 ? opcode : 0x0, i === pieces - 1));
    if (i < pieces - 1 && random() < 0.1) {
      frames.push(wsFrame(noise(i, int(random, 0, 125)), pick(random, [0x9, 0xa])));
    }
  }
  return Buffer.concat(frames);
}

test('a flood of fragments closes the connection at the cap', async (t) => {
  // The review's flood: a message begun and never ended, then frames of
  // one byte, or of none, continuing it. `ws` counts only a message's
  // bytes: 4M of one byte held 4,000,001 fragments, +588 MiB, and 16M
  // ended a process with a heap of 1 GiB.
  for (const unit of [wsFrame(Buffer.from('x'), 0x0, false), wsFrame(Buffer.alloc(0), 0x0, false)]) {
    const { mesh, daemon, warnings } = await attached(t);
    daemon.hold.add('send');
    const waiting = mesh.send('c', 'x');
    const flood = Buffer.alloc(unit.length * 1_000_000, unit);
    daemon.pushRaw(Buffer.concat([wsFrame(Buffer.from('{'), 0x1, false), flood]));
    await assert.rejects(waiting, /connection closed/);
    await settle();
    assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_TOO_MANY_FRAGMENTS']);
    assert.match(warnings[0].message, /^a message from the daemon comes in more than 4096 frames; closing the connection$/);
    assert.ok(daemon.terminated, 'the connection is cut');
    // `ws` read on to the end of the read that brought the frame past the
    // cap, and no further: it held the cap's fragments and that read's.
    assert.equal(daemon.bytesRead, 65536);
    assert.ok(daemon.mostFragments <= 4096 + 65536 / 3, `${daemon.mostFragments} fragments held`);
  }
});

test('a message may come in 4,096 frames and no more', async (t) => {
  const { mesh, daemon, delivered, warnings } = await attached(t);
  const text = Buffer.from(JSON.stringify(event('e1')));
  const empty = wsFrame(Buffer.alloc(0), 0x0, false);
  // An event in 4,096 frames, all but two of them empty, is delivered.
  const middle = Buffer.alloc(empty.length * 4094, empty);
  daemon.pushRaw(Buffer.concat([wsFrame(text.subarray(0, 1), 0x1, false), middle, wsFrame(text.subarray(1), 0x0)]));
  assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['e1']);
  // The frame after 4,096 closes the connection at its header, before its
  // payload: this one announces 2^40 bytes.
  daemon.hold.add('send');
  const waiting = mesh.send('c', 'x');
  const more = Buffer.alloc(empty.length * 4095, empty);
  daemon.pushRaw(Buffer.concat([wsFrame(Buffer.from('['), 0x1, false), more, wsFrame(Buffer.alloc(0), 0x0, true, 2 ** 40)]));
  await assert.rejects(waiting, /connection closed/);
  await settle();
  assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_TOO_MANY_FRAGMENTS']);
});

test('a message not ended in time closes the connection', async (t) => {
  // A pong counts as hearing from the daemon: one that began a message and
  // then only answered pings, or trickled its frames, held the connection
  // open without end.
  shortLimits(t, { pingAfterMs: 200, silenceLimitMs: 600, messageTimeLimitMs: 1000 });
  {
    // A message whose frames all come within the limit is delivered.
    const { mesh, daemon, delivered } = await attached(t);
    const text = Buffer.from(JSON.stringify(event('in-time')));
    for (let i = 0; i < 5; i += 1) {
      daemon.pushRaw(wsFrame(text.subarray(i, i + 1), i ? 0x0 : 0x1, false));
      await sleep(100);
    }
    daemon.pushRaw(wsFrame(text.subarray(5), 0x0));
    assert.deepEqual(delivered.map((ev) => ev.envelopeId), ['in-time']);
    assert.equal(mesh._closed, false);
  }
  for (const trickled of [true, false]) {
    const { mesh, daemon, warnings } = await attached(t);
    daemon.hold.add('send');
    const failed = assert.rejects(mesh.send('c', 'x'), /connection closed/);
    const started = Date.now();
    daemon.pushRaw(wsFrame(Buffer.from('['), 0x1, false));
    while (!mesh._closed && Date.now() - started < 5000) {
      if (trickled) daemon.pushRaw(wsFrame(Buffer.from(' '), 0x0, false));
      await sleep(100);
    }
    await failed;
    assert.ok(Date.now() - started >= 990, `closed after ${Date.now() - started} ms`);
    await settle();
    assert.deepEqual(warnings.map((warning) => warning.code), ['PMS_MESSAGE_TOO_SLOW']);
    assert.match(warnings[0].message, /^a message from the daemon has not ended 1 s after its first frame/);
    if (!trickled) assert.ok(daemon.pings >= 2, `${daemon.pings} pings, each answered`);
  }
});

test('events split into any fragments arrive intact', async (t) => {
  // However a message is split, text or binary, into empty pieces or with
  // control frames between them, and however the socket's reads cut the
  // frames, the event arrives and the connection stays open.
  const { mesh, daemon, delivered, warnings } = await attached(t);
  const random = randomness(2026);
  const sent = [];
  for (let i = 0; i < 300; i += 1) {
    const payload = noise(i, pick(random, [0, int(random, 1, 200), int(random, 200, 70_000)]));
    const text = Buffer.from(JSON.stringify(event(`e${i}`, payload.toString('base64'))));
    // One of them in as many frames as a message may come in.
    const pieces = i === 150 ? 4096 : pick(random, [1, 1, 2, 3, int(random, 4, 12), int(random, 13, 300)]);
    const reads = () => pick(random, [1, 2, 3, 5, 14, 200, 4096, 65536]);
    daemon.pushRaw(split(random, text, pick(random, [0x1, 0x2]), pieces), reads);
    sent.push([`e${i}`, payload]);
  }
  assert.deepEqual(delivered.map((ev) => [ev.envelopeId, ev.payload]), sent);
  assert.equal(mesh._closed, false);
  assert.equal(mesh._fragments, 0, 'every message ended');
  await settle();
  assert.deepEqual(warnings, []);
  assert.equal(await mesh.send('c', 'x'), 'e'.repeat(32));
});
