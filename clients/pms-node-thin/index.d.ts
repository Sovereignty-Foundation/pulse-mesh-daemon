// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
// Pulse Mesh thin Node client — TypeScript definitions for the v0
// Universal Port Protocol.

export interface MeshEvent {
    subscriptionId: string;
    envelopeId: string;
    channel: string;
    typeId: number;
    typeName: string | null;
    origin: string;
    capturedAtUnixNanos: number;
    payload: Buffer;
}

export interface TapFilter {
    channel?: string;
    type_id?: number;
    type_name?: string;
    origin?: string;
    health?: boolean;
    snapshot?: boolean;
}

export interface AttachOptions {
    /**
     * How long a call waits for the daemon's reply, in ms: 10,000 by
     * default, the Python client's ten seconds, and from 1 to 2,147,483,647.
     * A call that waits longer rejects with a `MeshTimeoutError`. An attach
     * has this long in all, the connection's opening included.
     */
    rpcTimeoutMs?: number;
}

/**
 * A call's deadline passed before the daemon answered it. A request still
 * waiting for the socket then is withdrawn and never reaches the daemon;
 * one the socket had begun to write may, and a reply that comes later is
 * dropped and counted by `Mesh.lateReplies`, a subscription made by a
 * subscribe that timed out released at once, its callback never run.
 */
export class MeshTimeoutError extends Error {
    /**
     * @param op the request's op
     * @param id the request's id
     * @param ms the deadline it missed, in ms
     */
    constructor(op: string, id: string, ms: number);
    readonly name: 'MeshTimeoutError';
    readonly code: 'PMS_TIMEOUT';
    /** The op of the request that timed out. */
    readonly op: string;
}

/**
 * A call refused before anything was sent: the requests the client holds
 * for the daemon, waiting for the socket or buffered by it, came to more
 * than 16 MiB, as they do while the daemon reads more slowly than calls
 * are made, or not at all. Nothing changed; the call may be made again
 * once earlier ones have settled. An unsubscribe of a subscription the
 * client holds is never refused so.
 */
export class MeshQueueFullError extends Error {
    /**
     * @param op the request's op
     * @param held the bytes held for the daemon when it was refused
     */
    constructor(op: string, held: number);
    readonly name: 'MeshQueueFullError';
    readonly code: 'PMS_QUEUE_FULL';
    /** The op of the request that was refused. */
    readonly op: string;
}

/**
 * A connection to a mesh-hub daemon, made by `attach`, which opens it and
 * attaches: there is no other way to make one.
 */
export class Mesh {
    private constructor();

    /**
     * Replies that came after their call had timed out. Such a reply is
     * dropped, not acted on; for a subscribe, the subscription it made is
     * released at once. Reported as a `PmsLateReplyWarning` at the first and
     * at each doubling.
     */
    readonly lateReplies: number;

    /**
     * Events dropped as malformed: a payload that is not padded standard
     * base64, or a field the protocol requires that is missing or of the
     * wrong type. A conforming daemon sends none; each is dropped rather
     * than handed to a callback, and reported as a `PmsProtocolWarning` at
     * the first and at each doubling.
     */
    readonly eventsMalformed: number;

    /** Publish a payload to a channel. Returns the daemon's envelope_id. */
    send(channel: string, payload: Buffer | Uint8Array | string, typeName?: string): Promise<string>;

    /**
     * Subscribe to a channel. Returns the subscription id. A callback that
     * throws, or whose promise rejects, is reported as a
     * `PmsCallbackWarning`, and the client reads on.
     */
    on(channel: string, callback: (event: MeshEvent) => void | Promise<void>): Promise<string>;

    /**
     * Subscribe with a full filter spec. The callback is registered as the
     * daemon's ack is read, so it sees every event of the subscription.
     */
    tap(filter: TapFilter, callback: (event: MeshEvent) => void | Promise<void>): Promise<string>;

    /**
     * Drop a subscription. Its callback is removed at once, whatever the
     * daemon answers; the request goes even if the call times out, and a
     * reply after the deadline is counted by `lateReplies`. For a
     * subscription the client holds it is never refused with a
     * `MeshQueueFullError`: the daemon always hears it.
     */
    unsubscribe(subscriptionId: string): Promise<void>;

    /** Clean detach. */
    detach(): Promise<void>;

    /** Resolves when the connection closes. */
    run(): Promise<void>;
}

/**
 * Attach to a mesh-hub daemon under the given name. Every call on the
 * `Mesh`, the attach included, rejects with a `MeshTimeoutError` if the
 * daemon has not answered within `rpcTimeoutMs`, and with a
 * `MeshQueueFullError`, having sent nothing, while the client holds more
 * than 16 MiB of requests for the daemon (an unsubscribe of a subscription
 * it holds excepted). A message from the daemon longer than 16 MiB, in
 * more than 4,096 frames or not ended 90 seconds after its first frame, or
 * a daemon silent for 90 seconds after the client pinged it at 30, closes
 * the connection. An error from the daemon that answers no request is
 * reported as a `PmsProtocolWarning`; if the connection ends before the
 * daemon says more, every call the end fails, and every call after,
 * rejects with an error that gives it as the reason.
 */
export function attach(name: string, options?: AttachOptions): Promise<Mesh>;

/**
 * Encode payload bytes as the port protocol carries them: standard base64
 * (RFC 4648 §4), padded with `=`, and nothing else in the text. A string is
 * sent as its UTF-8.
 */
export function encodePayload(payload: Buffer | Uint8Array | string): string;

/**
 * Decode a payload as strictly as the daemon and the Rust client do: only
 * padded standard base64, the one text `encodePayload` writes for the
 * bytes. Throws for anything else.
 */
export function decodePayload(text: string): Buffer;
