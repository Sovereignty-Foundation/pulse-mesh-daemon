// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// The fake `ws` the thin client's tests connect through, and the client
// loaded with it installed: shared by client.test.js and fixtures.test.js.
// Nothing needs installing and no daemon needs running.

'use strict';

const { EventEmitter } = require('node:events');
const Module = require('node:module');

/**
 * Stands in for `ws`'s WebSocket: the far end of one connection. It answers
 * every request as a daemon would, naming subscriptions sub-1, sub-2 and
 * on, and answers the client's pings. A test pushes frames to the client
 * through it, has it keep replies back, refuse an op, follow a reply with
 * frames of its own or answer nothing at all, stall as a daemon that does
 * not read, or take its time over the opening; or it hangs up. As with
 * `ws`, a send's callback runs once the request is written out, never
 * during the send, and once closed a send fails through its callback.
 *
 * A test may also write the daemon's bytes, frames as they go on the wire,
 * into the socket the 'upgrade' event hands over. The fake reads them as
 * `ws` does, its reader on the socket before any other: it joins each
 * message's fragments, keeping each one that carries bytes as an object of
 * its own until the message ends, and hands on messages, pings and pongs.
 */
class FakeDaemon extends EventEmitter {
  constructor(url, protocols, options) {
    super();
    this.url = url;
    this.protocols = protocols;
    this.options = options;
    this.requests = [];
    // The ops whose replies are kept back, and the replies kept back.
    this.hold = new Set();
    this.held = [];
    // The ops refused, with the error code of the refusal.
    this.refuse = new Map();
    // The frames pushed right after the reply to an op, in the same tick.
    this.follow = new Map();
    // Whether it answers nothing at all.
    this.silent = false;
    // Whether the client closed the connection, or cut it.
    this.closed = false;
    this.terminated = false;
    this.open = true;
    this.subscriptions = 0;
    // What the socket buffers, as `ws` reports it; while the daemon stalls,
    // every request stays buffered, its write callback held back.
    this.bufferedAmount = 0;
    this.stalled = false;
    this.unwritten = [];
    // The client's pings, and whether they are answered.
    this.pings = 0;
    this.answerPings = true;
    // How long the opening takes, and whether it never ends.
    this.openDelayMs = 0;
    this.neverOpen = false;
    // The socket, the bytes read from it and not yet a whole frame, the
    // fragments of the message being read and its opcode, the most
    // fragments held at once, and how many bytes were read.
    this.socket = new EventEmitter();
    this.socket.on('data', (chunk) => this.receive(chunk));
    this.unread = Buffer.alloc(0);
    this.fragments = [];
    this.opcode = 0;
    this.mostFragments = 0;
    this.bytesRead = 0;
    FakeDaemon.configure(this);
    FakeDaemon.last = this;
    if (this.neverOpen) return;
    const open = () => {
      this.emit('upgrade', { socket: this.socket });
      this.emit('open');
    };
    if (this.openDelayMs) setTimeout(open, this.openDelayMs);
    else setImmediate(open);
  }

  // The client's side of the socket.

  send(text, callback) {
    if (!this.open) {
      if (callback) process.nextTick(callback, new Error('WebSocket is not open'));
      return;
    }
    if (this.stalled) {
      this.bufferedAmount += Buffer.byteLength(text);
      this.unwritten.push([text, callback]);
      return;
    }
    const request = JSON.parse(text);
    this.requests.push(request);
    const { op } = request;
    let reply;
    if (this.refuse.has(op)) {
      reply = { op: 'error', id: request.id, code: this.refuse.get(op), message: `${op} refused` };
    } else {
      reply = { op: 'ack', id: request.id };
      if (op === 'subscribe') {
        this.subscriptions += 1;
        reply.subscription_id = `sub-${this.subscriptions}`;
      }
      if (op === 'send') reply.envelope_id = 'e'.repeat(32);
    }
    if (this.silent) {
      // Read, and never answered.
    } else if (this.hold.has(op)) {
      this.held.push(reply);
    } else {
      setImmediate(() => {
        this.push(reply);
        for (const frame of this.follow.get(op) ?? []) this.push(frame);
      });
    }
    if (callback) process.nextTick(callback);
  }

  ping() {
    this.pings += 1;
    if (this.answerPings) setImmediate(() => this.emit('pong', Buffer.alloc(0)));
  }

  close() {
    this.closed = true;
    this.hangUp();
  }

  terminate() {
    this.terminated = true;
    this.hangUp();
  }

  /** A stalled daemon reads again: what the socket held is written. */
  drain() {
    this.stalled = false;
    this.bufferedAmount = 0;
    for (const [text, callback] of this.unwritten.splice(0)) this.send(text, callback);
  }

  // The test's side: `ws` hands the client each frame as a Buffer.

  push(frame) {
    const text = typeof frame === 'string' ? frame : JSON.stringify(frame);
    this.emit('message', Buffer.from(text));
  }

  /** Push the replies kept back, in the order of their requests. */
  pushHeld() {
    for (const reply of this.held.splice(0)) this.push(reply);
  }

  /**
   * Write the daemon's bytes into the socket in reads of `size` bytes (or
   * of what `size()` says, read by read), until the connection is cut.
   */
  pushRaw(data, size = 65536) {
    for (let at = 0; at < data.length && this.open; ) {
      const read = typeof size === 'function' ? size() : size;
      this.socket.emit('data', data.subarray(at, at + read));
      at += read;
    }
  }

  /** Read the socket's bytes as `ws` does (see the class's comment). */
  receive(chunk) {
    this.bytesRead += chunk.length;
    let data = Buffer.concat([this.unread, chunk]);
    while (data.length >= 2) {
      const short = data[1] & 0x7f;
      const at = short === 126 ? 4 : short === 127 ? 10 : 2;
      if (data.length < at) break;
      const length = short === 126 ? data.readUInt16BE(2) : short === 127 ? Number(data.readBigUInt64BE(2)) : short;
      if (data.length < at + length) break;
      const fin = (data[0] & 0x80) !== 0;
      const opcode = data[0] & 0x0f;
      const payload = data.subarray(at, at + length);
      data = data.subarray(at + length);
      if (opcode === 0x9) this.emit('ping', payload);
      else if (opcode === 0xa) this.emit('pong', payload);
      else {
        if (opcode !== 0x0) this.opcode = opcode;
        if (payload.length) this.fragments.push(payload);
        this.mostFragments = Math.max(this.mostFragments, this.fragments.length);
        if (fin) this.emit('message', Buffer.concat(this.fragments.splice(0)), this.opcode === 0x2);
      }
    }
    this.unread = data;
  }

  /** End the connection from the daemon's side. */
  hangUp() {
    if (!this.open) return;
    this.open = false;
    // What the socket still held is lost, and its writes fail.
    this.bufferedAmount = 0;
    for (const [, callback] of this.unwritten.splice(0)) {
      if (callback) process.nextTick(callback, new Error('socket destroyed'));
    }
    setImmediate(() => this.emit('close'));
  }
}

/** Set up each fake before the client attaches through it. */
FakeDaemon.configure = () => {};

// The client requires `ws`; it gets the fake instead, installed or not.
const load = Module._load;
Module._load = function loadWithFakeWs(request, ...rest) {
  return request === 'ws' ? FakeDaemon : load.call(this, request, ...rest);
};
process.env.PMS_DAEMON = 'ws://127.0.0.1:9';
const client = require('../index.js');

module.exports = { FakeDaemon, client };
