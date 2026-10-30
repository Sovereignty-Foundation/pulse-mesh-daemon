// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
// Pulse Mesh thin Node client — Universal Port Protocol v0 over WebSocket.
//
// Single dependency: `ws`. No native bindings, no compilation.
//
// A `wss://host:port` URL reaches a daemon started with `--ws-tls-cert`:
// `ws` verifies its certificate against Node's roots, which
// `NODE_EXTRA_CA_CERTS=<ca.pem>` extends.
//
// Key-proof attach is not supported here yet: this client attaches by name
// alone, never with a `key`, and does not answer a `challenge`. A daemon
// started with `--attach-keys` therefore refuses its attach on the
// WebSocket with `auth_failed`; the Rust client
// (`MeshOptions::with_identity`) proves a key.
//
// Nothing a frame from the daemon holds and nothing a callback does stops
// the client reading, or escapes into the process as an uncaught
// exception:
//
// - Payloads travel as padded standard base64 (RFC 4648 §4), the one form
//   the daemon and the Rust client accept: `encodePayload` writes it and
//   `decodePayload` accepts nothing else. An event whose payload is in any
//   other form, or that lacks a field the protocol requires or carries one
//   of the wrong type, is never delivered; `mesh.eventsMalformed` counts
//   such events. Like a frame that is not a JSON object, or a reply with a
//   field of the wrong type, it is reported as a process warning of type
//   `PmsProtocolWarning` (`process.on('warning')` sees it), and the
//   connection carries on.
// - A callback that throws, or returns a promise that rejects, is reported
//   as a process warning of type `PmsCallbackWarning`, and the client goes
//   on to the next frame.
//
// Every call has a deadline, `rpcTimeoutMs` (10,000 by default, the Python
// client's ten seconds), and rejects with a `MeshTimeoutError` when the
// daemon has not answered by then. The requests go to the socket one at a
// time, each once the one before it has been written out, so a request
// still waiting when its call times out is withdrawn and never reaches the
// daemon; one the socket had begun to write may. A reply after the
// deadline is dropped, counted by `mesh.lateReplies` and reported as a
// process warning of type `PmsLateReplyWarning` at the first and at each
// doubling, and a subscription whose subscribe timed out is released at
// once, its callback never run. An unsubscribe removes its callback at
// once, whatever the daemon answers, and one that releases a subscription
// the client holds is never refused nor withdrawn: the daemon always hears
// it, as it does the client's own releases.
//
// An error from the daemon that answers no request, having no id or one the
// client does not know, is reported as a process warning of type
// `PmsProtocolWarning`. The daemon says why it ends a connection this way
// (a frame over its size limit gets `payload_too_large`, and then the
// connection closes), so while such an error is the last thing the daemon
// said it is the reason the connection ended, as the Rust client has it:
// every call the close fails, and every call after, rejects with an error
// that gives it.
//
// The client bounds what it holds and how long it waits:
//
// - While the requests it holds for the daemon, waiting for the socket or
//   buffered by it, come to more than 16 MiB, a call is refused at once
//   with a `MeshQueueFullError`, having sent nothing; an unsubscribe of a
//   subscription the client holds excepted.
// - An attach takes at most `rpcTimeoutMs` in all: the connection's
//   opening and the attach's reply share the one deadline.
// - A message from the daemon longer than 16 MiB, the Rust client's limit,
//   closes the connection: `ws` refuses it at its header, as it does a
//   frame the protocol does not allow.
// - So does the frame that takes a message past 4,096 frames, empty ones
//   counted, which the client refuses at its header, and a message not
//   ended 90 seconds after its first frame.
// - A daemon that has sent nothing for 30 seconds is pinged, and one that
//   has sent nothing for 90, the ping's answer included, is given up: the
//   connection closes.
//
// A connection closed for any of the last three reasons is reported as a
// process warning of type `PmsProtocolWarning`, and every call waiting
// fails.

'use strict';

const WebSocket = require('ws');
const { randomUUID } = require('crypto');
const { performance } = require('perf_hooks');

const PROTOCOL_VERSION = 'v0';
const WS_SUBPROTOCOL = 'pms-universal-port-v0';

/** How long a call waits for the daemon's reply by default, in ms. */
const DEFAULT_RPC_TIMEOUT_MS = 10_000;

/**
 * Requests no call waits for the replies to: timed-out calls whose requests
 * may have reached the daemon, and the client's own releases. They are
 * remembered so that their replies are known: a late one is counted, the
 * subscription a late subscribe's ack names is released, and none is taken
 * for an error that answers no request. A conforming daemon answers every
 * request, which forgets it; one that stops answering costs at most this
 * many, the oldest forgotten first.
 */
const MAX_ABANDONED = 4096;

/**
 * Bytes of requests the client holds for the daemon, those waiting for the
 * socket and those the socket has buffered, past which a call is refused,
 * having sent nothing: a daemon that stops reading costs at most this and
 * one request more, however many calls are made, and an unsubscribe for
 * each subscription the client releases meanwhile, which is never refused.
 * 16 MiB is the daemon's own budget for what it queues toward one client,
 * and a burst of a dozen sends at its 1 MiB cap on a message, grown by
 * base64, which a daemon that keeps up drains in milliseconds.
 */
const MAX_BUFFERED = 16 * 1024 * 1024;

/**
 * The longest message the client takes from the daemon, and so the longest
 * frame: the Rust client's limit, where `ws` would take 100 MiB. An event
 * is about as long as the send that brought its payload in, which the
 * daemon caps at 1 MiB unless its --max-message-bytes says otherwise, so
 * this leaves room for a daemon configured sixteen times higher.
 */
const MAX_INBOUND_MESSAGE = 16 * 1024 * 1024;

/**
 * The most frames a message from the daemon may come in, empty ones
 * counted: the frame past it closes the connection at its header. `ws`
 * counts only a message's payload against `maxPayload`, and keeps each
 * fragment as an object of its own until the message ends, so a message in
 * millions of one-byte frames held hundreds of MiB (see `FrameHeaders`).
 * The daemon writes each message in one frame; this leaves room for
 * anything between that splits them, down to pieces of 4 KiB for a message
 * of 16 MiB.
 */
const MAX_FRAGMENTS = 4096;

/**
 * How long the daemon may be silent, in ms, before the client pings it, and
 * before it gives the daemon up, the ping's answer included. These are the
 * daemon's own defaults for its clients (--ping-interval-secs,
 * --idle-timeout-secs), and a healthy daemon always meets them: it pings
 * every 30 seconds unless told otherwise, and however it is configured it
 * answers a ping as soon as it reads one, a frame it writes taking at most
 * its write deadline (10 seconds by default) before it closes the
 * connection itself. And how long a message may take, in ms, from its
 * first frame to its last, as long as the daemon may be silent: a pong
 * counts as hearing from the daemon, so a daemon that began a message and
 * then only answered pings, or trickled its frames, would otherwise hold
 * the connection open without ever ending it. Internal; the tests shorten
 * them.
 */
const limits = { pingAfterMs: 30_000, silenceLimitMs: 90_000, messageTimeLimitMs: 90_000 };

/**
 * A call's deadline passed before the daemon answered it. Its request may
 * still reach the daemon, if the socket had begun to write it; a reply
 * that comes later is dropped and counted by `mesh.lateReplies`, and a
 * subscription made by a subscribe that timed out is released at once.
 */
class MeshTimeoutError extends Error {
  /**
   * @param {string} op the request's op
   * @param {string} id the request's id
   * @param {number} ms the deadline it missed
   */
  constructor(op, id, ms) {
    super(`no reply for op='${op}' id='${id}' within ${ms} ms`);
    this.name = 'MeshTimeoutError';
    /** @type {'PMS_TIMEOUT'} */
    this.code = 'PMS_TIMEOUT';
    this.op = op;
  }
}

/**
 * A call refused before anything was sent: the requests the client holds
 * for the daemon, waiting for the socket or buffered by it, came to more
 * than 16 MiB, as they do while the daemon reads more slowly than calls
 * are made, or not at all. Nothing changed; the call may be made again
 * once earlier ones have settled.
 */
class MeshQueueFullError extends Error {
  /**
   * @param {string} op the request's op
   * @param {number} held the bytes held for the daemon when it was refused
   */
  constructor(op, held) {
    super(
      `op='${op}' was not sent: the client holds ${held} bytes of requests ` +
        `for the daemon, more than its ${MAX_BUFFERED} byte cap`,
    );
    this.name = 'MeshQueueFullError';
    /** @type {'PMS_QUEUE_FULL'} */
    this.code = 'PMS_QUEUE_FULL';
    this.op = op;
  }
}

function discoverUrl() {
  const env = process.env.PMS_DAEMON;
  if (env) {
    if (env.startsWith('ws://') || env.startsWith('wss://')) return env;
    throw new Error(`PMS_DAEMON='${env}' — pms-node-thin only supports ws://`);
  }
  return 'ws://127.0.0.1:9876';
}

/**
 * Encode payload bytes as the port protocol carries them: standard base64
 * (RFC 4648 §4), padded with `=`, and nothing else in the text.
 * @param {Buffer|Uint8Array|string} payload bytes, or a string sent as its UTF-8
 * @returns {string}
 */
function encodePayload(payload) {
  const bytes = Buffer.isBuffer(payload)
    ? payload
    : typeof payload === 'string'
    ? Buffer.from(payload, 'utf8')
    : Buffer.from(payload);
  return bytes.toString('base64');
}

/**
 * Decode a payload as strictly as the daemon and the Rust client do. Only
 * padded standard base64 is accepted: no whitespace or line breaks, no
 * URL-safe alphabet, no missing padding, no `=` but the one or two that end
 * the text, and no bits set after the last byte. Each byte string has
 * exactly one such text, the one `encodePayload` writes.
 * @param {string} text
 * @returns {Buffer}
 * @throws {Error} for anything else, a value that is not a string included
 */
function decodePayload(text) {
  if (typeof text !== 'string') {
    throw new Error(`payload is ${text === null ? 'null' : typeof text}, not a string`);
  }
  // Buffer.from skips what it cannot read, so the text is accepted only if
  // it is the one an encoder writes for the bytes that were read.
  const bytes = Buffer.from(text, 'base64');
  if (bytes.toString('base64') !== text) {
    throw new Error('payload is not padded standard base64');
  }
  return bytes;
}

/**
 * Report something the daemon sent that the protocol does not allow. The
 * connection carries on.
 * @param {string} code
 * @param {string} message
 */
function protocolWarning(code, message) {
  process.emitWarning(message, { type: 'PmsProtocolWarning', code });
}

/**
 * Reads the frame headers (RFC 6455 §5.2) in the bytes the daemon sends,
 * beside `ws`, which parses the same bytes and offers no hook for a frame,
 * only for a whole message. `onFrame(fin, opcode)` is called as each
 * frame's header is complete; the payloads are skipped, never kept. A
 * malformed frame is `ws`'s to refuse, which ends the connection.
 */
class FrameHeaders {
  /** @param {(fin: boolean, opcode: number) => boolean} onFrame false to stop reading */
  constructor(onFrame) {
    this._onFrame = onFrame;
    // The header being read, how much of it has come and how long it is
    // (two bytes, then the extended length and the mask, if any), and how
    // much of the payload after it is still to come.
    this._head = Buffer.alloc(14);
    this._have = 0;
    this._need = 2;
    this._skip = 0;
  }

  /**
   * Read the next bytes the daemon sent.
   * @param {Buffer} chunk
   * @returns {boolean} false once `onFrame` said to stop
   */
  take(chunk) {
    let i = 0;
    while (i < chunk.length) {
      if (this._skip > 0) {
        const skipped = Math.min(this._skip, chunk.length - i);
        this._skip -= skipped;
        i += skipped;
        continue;
      }
      const head = this._head;
      head[this._have++] = chunk[i++];
      if (this._have === 2) {
        const length = head[1] & 0x7f;
        this._need = 2 + (length === 126 ? 2 : length === 127 ? 8 : 0) + (head[1] & 0x80 ? 4 : 0);
      }
      if (this._have < this._need) continue;
      let length = head[1] & 0x7f;
      if (length === 126) length = head.readUInt16BE(2);
      else if (length === 127) length = head.readUInt32BE(2) * 2 ** 32 + head.readUInt32BE(6);
      this._skip = length;
      this._have = 0;
      this._need = 2;
      if (!this._onFrame((head[0] & 0x80) !== 0, head[0] & 0x0f)) return false;
    }
    return true;
  }
}

/**
 * Report what a callback threw, or the reason its promise rejected with.
 * The connection carries on.
 * @param {MeshEvent} event
 * @param {unknown} err
 */
function callbackWarning(event, err) {
  let detail;
  try {
    if (err instanceof Error && typeof err.stack === 'string') detail = err.stack;
  } catch {}
  process.emitWarning(
    `the callback of subscription ${event.subscriptionId} threw on envelope ` +
      `${event.envelopeId}; reading goes on: ${describe(err)}`,
    { type: 'PmsCallbackWarning', code: 'PMS_CALLBACK_THREW', detail },
  );
}

/**
 * A thrown value as a report shows it: an error's message, a string as it
 * is, anything else as JSON. Never throws.
 * @param {unknown} value
 * @returns {string}
 */
function describe(value) {
  try {
    if (value instanceof Error) return String(value.message);
    if (typeof value === 'string') return value;
    return JSON.stringify(value) ?? String(value);
  } catch {
    return 'a value that cannot be shown';
  }
}

/** A field of a frame from the daemon that is not what the protocol says. */
class Malformed extends Error {}

/**
 * A field's value as a report shows it, cut short.
 * @param {unknown} value a value JSON.parse made
 * @returns {string}
 */
function preview(value) {
  if (Array.isArray(value)) return 'an array';
  if (value !== null && typeof value === 'object') return 'an object';
  const text = JSON.stringify(value);
  return text.length <= 64 ? text : `${text.slice(0, 61)}...`;
}

/**
 * An id as a report names it: a string as it is, anything else previewed.
 * @param {unknown} value
 * @returns {string}
 */
function label(value) {
  return typeof value === 'string' ? value : value === undefined ? 'undefined' : preview(value);
}

function has(msg, key) {
  return Object.prototype.hasOwnProperty.call(msg, key);
}

/**
 * `msg[key]`, which must be a string. An optional field may be missing or
 * null, and is then `undefined`.
 * @returns {string|undefined}
 */
function string(msg, key, optional = false) {
  if (!has(msg, key)) {
    if (optional) return undefined;
    throw new Malformed(`${key} is missing`);
  }
  const value = msg[key];
  if (value === null && optional) return undefined;
  if (typeof value !== 'string') throw new Malformed(`${key} is ${preview(value)}, not a string`);
  return value;
}

/**
 * `msg[key]`, which must be an integer that fits in `bits` unsigned bits.
 * A field with a fallback may be missing, but not null. A JSON number
 * reads as the nearest double, so the last 1,024 values of 64 bits read as
 * 2^64 and are refused.
 * @returns {number}
 */
function unsigned(msg, key, bits, fallback) {
  if (!has(msg, key)) {
    if (fallback !== undefined) return fallback;
    throw new Malformed(`${key} is missing`);
  }
  const value = msg[key];
  if (!Number.isInteger(value) || value < 0 || value >= 2 ** bits) {
    throw new Malformed(`${key} is ${preview(value)}, not an unsigned ${bits}-bit integer`);
  }
  return value;
}

/**
 * @typedef MeshEvent
 * @property {string} subscriptionId
 * @property {string} envelopeId
 * @property {string} channel
 * @property {number} typeId
 * @property {string|null} typeName
 * @property {string} origin
 * @property {number} capturedAtUnixNanos
 * @property {Buffer} payload
 */

/**
 * @typedef AttachOptions
 * @property {number} [rpcTimeoutMs] how long a call waits for the daemon's
 *   reply, in ms: 10,000 by default, at most 2,147,483,647
 */

class Mesh {
  /**
   * @param {string} name
   * @param {AttachOptions} [options]
   */
  constructor(name, options) {
    const ms = options?.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
    // setTimeout takes a longer delay, or none, as 1 ms.
    if (!(Number.isFinite(ms) && ms >= 1 && ms <= 2 ** 31 - 1)) {
      throw new RangeError(`rpcTimeoutMs is ${ms}, not a number of ms from 1 to 2147483647`);
    }
    this._rpcTimeoutMs = ms;
    this._name = name;
    this._url = discoverUrl();
    this._pending = new Map();
    /**
     * The ops of requests no call waits for the replies to, 'release' for a
     * release, by request id (see MAX_ABANDONED), oldest first.
     */
    this._abandoned = new Map();
    /**
     * The daemon's last word while it is an error that answered no request,
     * as `[code] message`: why the connection ended, if it ends next.
     * @type {string|undefined}
     */
    this._parting = undefined;
    this._callbacks = new Map();
    this._closed = false;
    this._readyResolvers = [];
    /**
     * Replies that came after their call had timed out. Such a reply is
     * dropped, not acted on; for a subscribe, the subscription it made is
     * released at once. Reported at the first and at each doubling.
     * @type {number}
     */
    this.lateReplies = 0;
    this._nextLateReport = 1;
    /**
     * Events dropped as malformed: a payload that is not padded standard
     * base64, or a field the protocol requires that is missing or of the
     * wrong type. A conforming daemon sends none; each is dropped rather
     * than handed to a callback, and reported at the first and at each
     * doubling.
     * @type {number}
     */
    this.eventsMalformed = 0;
    this._nextMalformedReport = 1;
    /**
     * The requests waiting for the socket, by request id, oldest first: the
     * calls' and the client's own (see `_pump`), and their bytes.
     * @type {Map<string, {text: string, bytes: number, sent: boolean}>}
     */
    this._outbox = new Map();
    this._outboxBytes = 0;
    /** Whether a request is with the socket and not yet written out. */
    this._writing = false;
    /**
     * When the daemon was last heard from, the `_heard` it was pinged at,
     * so that it is pinged once per silence, and when it is given up if
     * nothing comes (see `_watch`), on the clock of `performance.now()`.
     */
    this._heard = 0;
    this._pinged = -1;
    this._giveUp = 0;
    this._watchTimer = undefined;
    /**
     * The frames of the message the daemon is sending, 0 between messages,
     * and the timer that gives it up if it does not end in time.
     */
    this._fragments = 0;
    this._messageTimer = undefined;
  }

  async _connect() {
    const ms = this._rpcTimeoutMs;
    const started = performance.now();
    // The attach's id, which its timeout names whether or not the
    // connection opened.
    const id = randomUUID();
    // The opening and the attach's reply have the one deadline. `ws`'s own
    // handshake timeout restarts with every byte, which let a daemon that
    // answered a byte at a time hold an attach for as long as it liked.
    const ws = new WebSocket(this._url, [WS_SUBPROTOCOL], { maxPayload: MAX_INBOUND_MESSAGE });
    this._ws = ws;
    // The socket under the connection, which the upgrade's response names.
    let socket;
    ws.once('upgrade', (res) => {
      socket = res.socket;
    });
    const opening = (resolve, reject) => {
      const timer = setTimeout(() => reject(new MeshTimeoutError('attach', id, ms)), ms);
      ws.once('open', () => {
        clearTimeout(timer);
        this._countFrames(socket);
        resolve();
      });
      ws.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    };
    try {
      await new Promise(opening);
    } catch (err) {
      // What `ws` reports as it abandons the opening adds nothing.
      ws.on('error', () => {});
      this._closed = true;
      ws.terminate();
      throw err;
    }
    ws.removeAllListeners('error');
    // `ws` closes the connection after an error: a message over the limit,
    // a frame the protocol does not allow, a failed socket.
    ws.on('error', (err) => {
      protocolWarning('PMS_CONNECTION_FAILED', `the connection to the daemon failed and closes: ${describe(err)}`);
    });
    ws.on('message', (data) => {
      this._hear();
      this._onMessage(data);
    });
    ws.on('ping', () => this._hear());
    ws.on('pong', () => this._hear());
    ws.on('close', () => {
      this._closed = true;
      clearTimeout(this._watchTimer);
      clearTimeout(this._messageTimer);
      for (const [, p] of this._pending) {
        clearTimeout(p.timer);
        p.reject(this._closedError());
      }
      this._pending.clear();
      this._abandoned.clear();
      this._outbox.clear();
      this._outboxBytes = 0;
    });
    this._hear();
    this._watch();
    try {
      await this._roundtrip(
        { op: 'attach', id, name: this._name, protocol_version: PROTOCOL_VERSION },
        undefined,
        ms - (performance.now() - started),
      );
    } catch (err) {
      // A client the daemon does not attach is closed, so that its
      // connection does not keep the process alive.
      this._closed = true;
      clearTimeout(this._watchTimer);
      this._ws.close();
      throw err;
    }
  }

  /**
   * Send a request and wait for its reply, at most `rpcTimeoutMs`, or `ms`
   * when given. A subscribe passes its callback, which is registered as the
   * ack is read. Refused at once, with nothing sent, while the requests
   * held for the daemon come to more than MAX_BUFFERED bytes, unless it is
   * the `release` of a subscription the client held.
   */
  _roundtrip(msg, callback, ms = this._rpcTimeoutMs, release = false) {
    const id = msg.id ?? randomUUID();
    msg.id = id;
    if (this._closed) return Promise.reject(this._closedError());
    const held = this._outboxBytes + this._ws.bufferedAmount;
    if (held > MAX_BUFFERED && !release) return Promise.reject(new MeshQueueFullError(msg.op, held));
    const text = JSON.stringify(msg);
    return new Promise((resolve, reject) => {
      const call = { resolve, reject, callback, text, bytes: Buffer.byteLength(text), sent: false };
      call.timer = setTimeout(() => {
        this._pending.delete(id);
        if (!call.sent && msg.op !== 'unsubscribe') {
          // Still waiting for the socket: withdrawn, so the daemon never
          // sees it and no reply comes.
          this._outbox.delete(id);
          this._outboxBytes -= call.bytes;
        } else {
          // The socket had begun to write it, or it is an unsubscribe,
          // which goes regardless: a reply may still come, and is then
          // late.
          this._abandon(id, msg.op);
        }
        reject(new MeshTimeoutError(msg.op, id, this._rpcTimeoutMs));
      }, Math.max(1, ms));
      this._pending.set(id, call);
      this._enqueue(id, call);
    });
  }

  /**
   * The error of a call the connection's end fails: with the daemon's last
   * word, when that was an error that answered no request, as the reason.
   */
  _closedError() {
    const parting = this._parting;
    if (parting === undefined) return new Error('connection closed');
    return new Error(`connection closed; the daemon's last word was ${parting}`);
  }

  /** Remember a request whose reply no call waits for (see MAX_ABANDONED). */
  _abandon(id, op) {
    this._abandoned.set(id, op);
    if (this._abandoned.size > MAX_ABANDONED) {
      this._abandoned.delete(this._abandoned.keys().next().value);
    }
  }

  /** Queue a request for the socket behind those already waiting. */
  _enqueue(id, request) {
    this._outbox.set(id, request);
    this._outboxBytes += request.bytes;
    this._pump();
  }

  /**
   * Hand the oldest waiting request to the socket once the one before it
   * has been written out: one at a time, so that a request still waiting
   * when its call times out can be withdrawn, and the socket buffers one
   * request at most, not every request made while the daemon stalls.
   */
  _pump() {
    if (this._writing || this._closed) return;
    const next = this._outbox.entries().next();
    if (next.done) return;
    const [id, request] = next.value;
    this._outbox.delete(id);
    this._outboxBytes -= request.bytes;
    request.sent = true;
    this._writing = true;
    const written = (err) => {
      this._writing = false;
      if (err && this._pending.get(id) === request) {
        clearTimeout(request.timer);
        this._pending.delete(id);
        request.reject(err);
      }
      this._pump();
    };
    try {
      this._ws.send(request.text, written);
    } catch (err) {
      written(err);
    }
  }

  /** The daemon was heard from: a message, a ping or a pong. */
  _hear() {
    this._heard = performance.now();
  }

  /**
   * Read the frame headers in what the daemon sends (see `FrameHeaders`),
   * so as to count each message's frames and time it. Called as the
   * connection opens, before any of its bytes flow: `ws` has put its own
   * reader on the socket, and what came with the upgrade's response waits
   * in the socket for both. A listener put on earlier would set the socket
   * flowing, and take those bytes from `ws`.
   * @param {import('net').Socket | undefined} socket
   */
  _countFrames(socket) {
    if (!socket) return;
    const headers = new FrameHeaders((fin, opcode) => this._onFrame(fin, opcode));
    const onData = (chunk) => {
      if (this._closed || !headers.take(chunk)) socket.removeListener('data', onData);
    };
    socket.on('data', onData);
  }

  /**
   * One frame's header from the daemon: count it against its message's
   * frames, and time the message from its first. A message's frames count
   * whether or not they carry bytes; a control frame is part of no message.
   * @returns {boolean} false once the connection is given up
   */
  _onFrame(fin, opcode) {
    if (opcode >= 0x8) return true;
    if (opcode !== 0x0) {
      // A text or binary frame begins a message; `ws` refuses one that
      // begins inside another, and a continuation that continues none.
      this._fragments = 0;
      clearTimeout(this._messageTimer);
    }
    this._fragments += 1;
    if (this._fragments > MAX_FRAGMENTS) {
      this._cut(
        'PMS_TOO_MANY_FRAGMENTS',
        `a message from the daemon comes in more than ${MAX_FRAGMENTS} frames; closing the connection`,
      );
      return false;
    }
    if (fin) {
      this._fragments = 0;
      clearTimeout(this._messageTimer);
    } else if (this._fragments === 1) {
      this._messageTimer = setTimeout(() => {
        this._cut(
          'PMS_MESSAGE_TOO_SLOW',
          `a message from the daemon has not ended ${limits.messageTimeLimitMs / 1000} s after its ` +
            'first frame; closing the connection',
        );
      }, limits.messageTimeLimitMs);
      this._messageTimer.unref?.();
    }
    return true;
  }

  /**
   * Give the daemon up over what it sent, or did not: reported as a
   * `PmsProtocolWarning`, and the connection cut. The close fails the calls
   * waiting; a call made before it fails at once.
   */
  _cut(code, message) {
    if (this._closed) return;
    protocolWarning(code, message);
    this._closed = true;
    this._ws.terminate();
  }

  /**
   * Ping a daemon that has been silent `limits.pingAfterMs`, and give up
   * one that has been silent `limits.silenceLimitMs`, the ping's answer
   * included; then wake when the next of those falls due.
   */
  _watch() {
    if (this._closed) return;
    const now = performance.now();
    let wake;
    if (this._pinged !== this._heard) {
      wake = this._heard + limits.pingAfterMs;
      if (now >= wake) {
        this._pinged = this._heard;
        // The answer has the rest of the limit from the ping, however late
        // the ping: a client held up itself (a machine asleep, a loop kept
        // busy) does not give the daemon up unasked.
        this._giveUp = Math.max(
          this._heard + limits.silenceLimitMs,
          now + limits.silenceLimitMs - limits.pingAfterMs,
        );
        try {
          this._ws.ping();
        } catch {}
        wake = this._giveUp;
      }
    } else {
      wake = this._giveUp;
      if (now >= wake) {
        this._cut(
          'PMS_DAEMON_SILENT',
          `the daemon has sent nothing for ${limits.silenceLimitMs / 1000} s, not even an answer ` +
            'to a ping; closing the connection',
        );
        return;
      }
    }
    this._watchTimer = setTimeout(() => this._watch(), Math.max(1, wake - now));
    this._watchTimer.unref?.();
  }

  /**
   * Count a reply that came after its call had timed out, and report it at
   * the first and at each doubling, as the Rust client does.
   */
  _countLate(op) {
    this.lateReplies += 1;
    if (this.lateReplies === this._nextLateReport) {
      this._nextLateReport *= 2;
      process.emitWarning(
        `a reply to ${op} arrived after its call had timed out; dropped (${this.lateReplies} so far)`,
        { type: 'PmsLateReplyWarning', code: 'PMS_LATE_REPLY' },
      );
    }
  }

  /**
   * Release a subscription whose subscribe timed out: the daemon made it,
   * and nobody will run its events. The unsubscribe is the client's own,
   * and its reply goes nowhere.
   */
  _release(subscriptionId) {
    if (this._closed) return;
    const msg = { op: 'unsubscribe', id: randomUUID(), subscription_id: subscriptionId };
    const text = JSON.stringify(msg);
    // The client's own, and few: never refused, never withdrawn.
    this._abandon(msg.id, 'release');
    this._enqueue(msg.id, { text, bytes: Buffer.byteLength(text), sent: false });
  }

  /**
   * Handle one frame from the daemon. A frame the protocol does not allow
   * is reported and otherwise ignored; nothing escapes into `ws`, where a
   * throw would end the process or leave the connection deaf.
   */
  _onMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch (err) {
      protocolWarning('PMS_MALFORMED_FRAME', `a frame from the daemon is not JSON; ignored: ${describe(err)}`);
      return;
    }
    if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
      protocolWarning('PMS_MALFORMED_FRAME', 'a frame from the daemon is not a JSON object; ignored');
      return;
    }
    // Whatever the daemon says next, an error that answered no request is
    // no longer its last word.
    this._parting = undefined;
    try {
      if (msg.op === 'ack' || msg.op === 'error') this._onReply(msg);
      else if (msg.op === 'event') this._onEvent(msg);
      // 'health' op (peer-state push) ignored in thin client v0
    } catch (err) {
      protocolWarning(
        'PMS_MALFORMED_FRAME',
        err instanceof Malformed
          ? `a frame from the daemon is malformed; ignored: ${err.message}`
          : // Nothing a frame holds should get here; if something does, it
            // is reported and the client reads on.
            `a frame from the daemon could not be handled; ignored: ${describe(err)}`,
      );
    }
  }

  /**
   * Hand an ack or error to the call waiting for it. A reply to a call that
   * timed out is dropped and counted, and the ack of a subscribe that timed
   * out releases the subscription it names. An error that answers no other
   * request is reported, and is the daemon's last word until it says more;
   * an ack nobody waits for is dropped.
   */
  _onReply(msg) {
    // The fields a call reads, checked before any call is answered.
    const id = string(msg, 'id', true);
    let subscriptionId = '';
    let error;
    if (msg.op === 'ack') {
      subscriptionId = string(msg, 'subscription_id', true) ?? '';
      string(msg, 'envelope_id', true);
    } else {
      error = `[${string(msg, 'code')}] ${string(msg, 'message')}`;
    }
    const p = id === undefined ? undefined : this._pending.get(id);
    if (!p) {
      const op = id === undefined ? undefined : this._abandoned.get(id);
      if (op !== undefined) {
        this._abandoned.delete(id);
        // The client's own release, whose reply goes nowhere.
        if (op === 'release') return;
        this._countLate(op);
        if (op === 'subscribe' && msg.op === 'ack' && subscriptionId) this._release(subscriptionId);
      } else if (error !== undefined) {
        this._parting = error;
        protocolWarning('PMS_DAEMON_ERROR', `an error from the daemon answers no request: ${error}`);
      }
      return;
    }
    this._pending.delete(id);
    clearTimeout(p.timer);
    if (error !== undefined) {
      p.reject(new Error(error));
      return;
    }
    // Registered before the next frame is read, so no event of the
    // subscription comes before its callback.
    if (p.callback) this._callbacks.set(subscriptionId, p.callback);
    p.resolve(msg);
  }

  _onEvent(msg) {
    // Checked before anything else: an event whose payload is not the one
    // accepted form, or any field of which is not what the protocol says,
    // is never delivered.
    let payload;
    try {
      payload = decodePayload(msg.payload);
    } catch (err) {
      this._rejectMalformed(msg, 'event payload is not valid base64', err);
      return;
    }
    let event;
    try {
      event = {
        subscriptionId: string(msg, 'subscription_id'),
        envelopeId: string(msg, 'envelope_id'),
        channel: string(msg, 'channel'),
        typeId: unsigned(msg, 'type_id', 16, 0),
        typeName: string(msg, 'type_name', true) ?? null,
        origin: string(msg, 'origin'),
        capturedAtUnixNanos: unsigned(msg, 'captured_at_unix_nanos', 64),
        payload,
      };
    } catch (err) {
      if (!(err instanceof Malformed)) throw err;
      this._rejectMalformed(msg, 'event is malformed', err);
      return;
    }
    const callback = this._callbacks.get(event.subscriptionId);
    if (!callback) return;
    try {
      const result = callback(event);
      // An async callback's rejection is reported as a throw is, rather
      // than left to end the process as an unhandled rejection.
      if (typeof result?.then === 'function') {
        result.then(undefined, (err) => callbackWarning(event, err));
      }
    } catch (err) {
      callbackWarning(event, err);
    }
  }

  /**
   * Count an event dropped as malformed, and report it at the first and at
   * each doubling, as the Rust client does.
   */
  _rejectMalformed(msg, what, err) {
    this.eventsMalformed += 1;
    if (this.eventsMalformed === this._nextMalformedReport) {
      this._nextMalformedReport *= 2;
      protocolWarning(
        'PMS_MALFORMED_EVENT',
        `${what}; event dropped (subscription ${label(msg.subscription_id)}, ` +
          `envelope ${label(msg.envelope_id)}, ${this.eventsMalformed} so far): ${err.message}`,
      );
    }
  }

  /**
   * Publish a payload to a channel.
   * @param {string} channel
   * @param {Buffer|Uint8Array|string} payload
   * @param {string?} typeName
   * @returns {Promise<string>} envelope_id
   */
  async send(channel, payload, typeName) {
    const msg = { op: 'send', channel, payload: encodePayload(payload) };
    if (typeName) msg.type_name = typeName;
    const reply = await this._roundtrip(msg);
    return reply.envelope_id ?? '';
  }

  /**
   * Subscribe to a channel.
   * @param {string} channel
   * @param {(event: MeshEvent) => void | Promise<void>} callback
   * @returns {Promise<string>} subscription id
   */
  async on(channel, callback) {
    return this.tap({ channel }, callback);
  }

  /**
   * Subscribe with a full filter spec. The callback is registered as the
   * daemon's ack is read, so it sees every event of the subscription.
   * @param {object} filter
   * @param {(event: MeshEvent) => void | Promise<void>} callback
   * @returns {Promise<string>}
   */
  async tap(filter, callback) {
    const reply = await this._roundtrip({ op: 'subscribe', filter }, callback);
    return reply.subscription_id ?? '';
  }

  /**
   * Drop a subscription. Its callback is removed at once, whatever the
   * daemon answers, and runs for no event after that. The request goes to
   * the daemon even if the call times out, and a reply after the deadline
   * is counted by `lateReplies`. It is not refused while the client holds
   * more than 16 MiB for the daemon, if the client holds the subscription:
   * refused, it left the daemon sending the subscription's events to a
   * client that drops them. Each subscription is released so once, so
   * these are as few as the subscriptions.
   * @param {string} subscriptionId
   * @returns {Promise<void>}
   */
  async unsubscribe(subscriptionId) {
    const held = this._callbacks.delete(subscriptionId);
    await this._roundtrip({ op: 'unsubscribe', subscription_id: subscriptionId }, undefined, undefined, held);
  }

  async detach() {
    try {
      await this._roundtrip({ op: 'detach' });
    } catch {}
    this._closed = true;
    clearTimeout(this._watchTimer);
    this._ws?.close();
  }

  /**
   * Resolves when the connection closes.
   */
  run() {
    return new Promise((resolve) => {
      const tick = () => {
        if (this._closed) resolve();
        else setTimeout(tick, 250);
      };
      tick();
    });
  }
}

/**
 * Attach to a mesh-hub daemon under the given name.
 * @param {string} name
 * @param {AttachOptions} [options]
 * @returns {Promise<Mesh>}
 */
async function attach(name, options) {
  const mesh = new Mesh(name, options);
  await mesh._connect();
  return mesh;
}

module.exports = {
  Mesh,
  MeshQueueFullError,
  MeshTimeoutError,
  attach,
  decodePayload,
  encodePayload,
  // Internal: the silence limits, which the tests shorten.
  _limits: limits,
};
