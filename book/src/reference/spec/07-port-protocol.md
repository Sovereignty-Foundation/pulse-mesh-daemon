# 7. The Universal Port Protocol

<p class="pm-kind"><b>Reference · normative for the daemon's clients</b> · the JSON protocol between `mesh-hub` and anything that attaches to it, over a WebSocket or a Unix socket</p>

The daemon terminates one protocol on two transports. A client attaches under a name, publishes envelopes to channels, subscribes to filtered streams, and detaches; the daemon answers each request, pushes events, and enforces a connection policy that keeps a silent, slow or oversized peer from costing the others anything. The types are defined once, in `mesh-port-protocol`, and the daemon and the Rust client both use them; the thin Python and Node clients and the website's browser client speak the same JSON. Version `v0`.

## 7.1 Transports and framing

| Transport | Endpoint | Framing |
|---|---|---|
| WebSocket | `ws://127.0.0.1:9876` by default; the client MUST announce the subprotocol `pms-universal-port-v0` in `Sec-WebSocket-Protocol`, and the daemon echoes it or refuses the upgrade with 400; at the daemon's connection cap the upgrade is answered 503 Service Unavailable. | One JSON object per text frame. |
| Unix socket | `/tmp/pms.sock` by default, created with owner-only permissions. At the daemon's connection cap the client receives one unprompted `limit_exceeded` error frame naming `--max-connections`, and the socket closes. | A 4-byte big-endian length prefix, then that many bytes of JSON. A prefix that declares more than the size limit is refused as soon as the prefix is complete, and nothing is allocated for it; the daemon's transport and the Rust client drive one sans-IO decoder, so a read cancelled between pieces loses nothing. |

Both carry the same message stream. Every message is a JSON object whose `op` field names the kind. The frames of every kind, each optional field present in one frame and absent in another, are pinned under `mesh/mesh-port-protocol/fixtures/` (`client.json`, `server.json`) as the Rust types serialize them; the crate's tests keep the files current, and the Python and Node thin clients' tests decode every server frame from them and compare the frames they write with the client frames as parsed JSON. A daemon MUST refuse to bind a Unix socket path where another daemon is live (it probes the socket first and removes only a stale file), so a second daemon never steals a live one's clients.

## 7.2 Client messages

| `op` | Fields | Meaning |
|---|---|---|
| `attach` | `id?`, `name`, `protocol_version`, `capabilities?` | Register the connection under `name`. `protocol_version` MUST be `"v0"`. `capabilities` lists the surfaces the client wants; `v0` recognises `send`, `subscribe` and `tap`. |
| `detach` | `id?` | Release the name and every subscription, then close. |
| `send` | `id?`, `channel`, `type_id?`, `type_name?`, `payload`, `flags?` | Publish one envelope: `payload` is standard base64 (RFC 4648 §4: the `A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/` alphabet, padded with `=` to a multiple of four characters, nothing else in the text); anything else, whitespace, the URL-safe alphabet, missing or misplaced padding or a last symbol with stray bits, is refused with `bad_request` saying what is wrong and where, nothing is published, and the connection stays open. `type_id` defaults to `0` and `type_name` routes by name; `flags` defaults to `0`. |
| `subscribe` | `id?`, `filter?` | Open a server-pushed stream. `filter` is a `FilterSpec`; an empty filter admits everything. |
| `unsubscribe` | `id?`, `subscription_id` | Close one stream. |
| `health` | `state?` | A liveness signal from the client; the daemon records it and does not reply. |

`id` is echoed on the matching `ack` or `error`; a request without one gets a reply without one. A `FilterSpec` has six optional members that AND-combine: `channel` (exact or glob, `db/*`, `**/foo`), `type_id`, `type_name` (exact or glob), `origin` (the producer's `name@suffix`), `health` (also stream peer state changes), and `snapshot` (reserved; ignored by `v0`). Fields at their defaults are omitted on the wire.

## 7.3 Daemon messages

| `op` | Fields | Meaning |
|---|---|---|
| `ack` | `id?`, then the request's fields flattened into the same object | Success. After `attach`: `node_id`, `protocol_version`, `granted_capabilities`. After `send`: `envelope_id`, the content identifier as 32 hexadecimal characters, and, when the daemon has an envelope store, `persisted`: `true` when the store kept the envelope, `false` when it refused it (larger than a store entry, or no slot free), which the daemon counts and logs; delivery to subscribers does not depend on it. After `subscribe`: `subscription_id`. After `unsubscribe`: `events_dropped` when any event was dropped for that stream (7.5). After `detach`: the extension key `__detach: true`. |
| `error` | `id?`, `code`, `message` | Failure. `code` is one of 7.4; `message` is for logs, not for branching. |
| `event` | `subscription_id`, `envelope_id`, `channel`, `type_id`, `type_name?`, `origin`, `captured_at_unix_nanos`, `payload` | One envelope delivered to one subscription. `payload` is the same padded standard base64; `captured_at_unix_nanos` is a `u64`. |
| `health` | `node_id`, `state`, `since_unix_nanos` | A peer's state changed; sent on subscriptions whose filter set `health`. |

A client MUST ignore an `op` it does not know and an `ack` key it does not know, so a later revision can add either without breaking it; the existing clients do.

## 7.4 Error codes

An error that answers no request, one without an `id` or with one no request is waiting on, is the daemon's reason for the close that follows it, and a client reports it to every call still waiting and to whatever waits for the connection's end; a daemon that carries on after such an error, as after `bad_request` for a frame it could not parse, fails no call by it.

| Code | When |
|---|---|
| `version_unsupported` | The client announced a protocol version other than `v0`. |
| `not_attached` | The operation needs an `attach` that has not happened on this connection, or the connection is already attached. |
| `name_in_use` | Another attached connection holds the name. The name is released when that connection detaches or closes. |
| `bad_filter` | The subscribe filter could not be interpreted. |
| `unknown_subscription` | The id is not a subscription of this connection. |
| `payload_too_large` | The frame exceeded the connection policy's size limit; the daemon closes the connection after the reply. |
| `limit_exceeded` | A connection-policy limit refused the request. On `subscribe`: the connection holds `--max-subscriptions` already; it stays open and an `unsubscribe` frees a place. Unprompted on a Unix socket: the daemon is at `--max-connections`, and it closes the connection after the frame. The message names the limit and its flag. |
| `bad_request` | The message was malformed JSON, missed a required field, attached a connection twice, or carried a `payload` that is not padded standard base64; the message says what is wrong and, for base64, at which offset. |
| `internal` | The daemon failed while handling the request. |

The set grows: a later daemon may send a code this table does not list. A client keeps such a code as the text it arrived in and treats the reply as a refusal it cannot classify; the Rust client's `DevError::Daemon { code, .. }` holds the string, and `mesh_port_protocol::ErrorCode::parse` returns `None` for it.

## 7.5 The connection policy

The daemon enforces eight limits, four timers and four sizes, each a command-line flag with a default; zero disables a timer, and zero on either cap refuses everything:

| Limit | Default | Effect |
|---|---|---|
| `--ping-interval-secs` | 30 | The daemon pings a WebSocket client this often; a pong counts as activity. The Unix socket has no ping frame. |
| `--idle-timeout-secs` | 90 | A connection with no inbound frame and no pong for this long is closed. A Unix-socket client therefore MUST send something within the window; the Rust client sends a `health` frame every 30 seconds while idle. |
| `--write-timeout-secs` | 10 | An outbound write that takes longer than this closes the connection as unreadable, so a peer that stops reading cannot stall the daemon. |
| `--handshake-timeout-secs` | 5 | A WebSocket upgrade that does not complete in this time is dropped. |
| `--max-message-bytes` | 1,048,576 | The largest frame accepted on either transport; a larger one gets `payload_too_large` and the connection closes. A 64 KiB envelope is about 88 KiB of base64 plus its JSON. |
| `--subscriber-queue` | 1,024 | Events queued for one connection. When the queue is full the daemon drops the newest event, counts it, logs at the first drop and at each doubling, and reports the count as `events_dropped` in that subscription's `unsubscribe` ack. A slow subscriber therefore loses events rather than slowing publishers or other subscribers. |
| `--max-subscriptions` | 64 | Subscriptions one connection may hold at once. Every send is matched against every live subscription, so the cap bounds what one connection adds to the cost of each send; the subscribe beyond it gets `limit_exceeded`, the connection stays open, and an `unsubscribe` frees a place. |
| `--max-connections` | 256 | Connections the daemon holds at once across both transports, counted from accept (an upgrade in progress counts) until the connection's task ends. Beyond it a Unix-socket client gets one `limit_exceeded` frame and is closed, and a WebSocket upgrade is answered 503; refusals are counted (`connections_refused`), logged at the first and at each doubling, and printed in the exit log. |

Acknowledgements and errors are never dropped; only events are subject to the queue. When a connection ends for any reason the daemon releases its name and closes its subscriptions at once.

## 7.6 A session

```text
→ {"op":"attach","id":"1","name":"worker","protocol_version":"v0","capabilities":["send","subscribe","tap"]}
← {"op":"ack","id":"1","node_id":"worker@3f9a…","protocol_version":"v0","granted_capabilities":["send","subscribe","tap"]}
→ {"op":"subscribe","id":"2","filter":{"channel":"jobs/*"}}
← {"op":"ack","id":"2","subscription_id":"sub-default_hub-00000001"}
→ {"op":"send","id":"3","channel":"jobs/new","payload":"aGVsbG8="}
← {"op":"ack","id":"3","envelope_id":"9c1d…","persisted":true}
← {"op":"event","subscription_id":"sub-default_hub-00000001","envelope_id":"9c1d…","channel":"jobs/new","type_id":0,"origin":"worker@3f9a…","captured_at_unix_nanos":1758700000000000000,"payload":"aGVsbG8="}
→ {"op":"unsubscribe","id":"4","subscription_id":"sub-default_hub-00000001"}
← {"op":"ack","id":"4"}
→ {"op":"detach","id":"5"}
← {"op":"ack","id":"5","__detach":true}
```

## 7.7 What would refute this chapter

The protocol crate's round-trip tests pin every message shape; the daemon's tests attach, publish, subscribe and detach over both transports, refuse a second daemon on a live socket, close a silent connection after the idle window and a stalled one after the write window, keep a pinged client attached, reject an oversized frame with `payload_too_large`, show `events_dropped` in the unsubscribe ack of a subscriber that stopped reading, acknowledge a send the store refused with `persisted: false` while still delivering it to its subscribers, refuse a `send` whose payload is not padded standard base64 without publishing it, refuse the subscription past the cap with `limit_exceeded` and admit one again after an unsubscribe, and turn away the connection past the cap on both transports. A client that receives bytes this chapter does not describe, or a daemon that keeps a silent connection past its window, contradicts it.
