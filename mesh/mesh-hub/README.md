# `mesh-hub` — the daemon

The Pulse Mesh daemon: it terminates the Universal Port Protocol over a Unix socket and a WebSocket and bridges every connection to the embedded hub runtime. The book describes it in [Daemon design](https://pulse-mesh.net/docs/daemon/explanation/daemon-design.html) and lists its flags in [The mesh-hub daemon](https://pulse-mesh.net/docs/daemon/reference/daemon-reference.html). This page covers two things the book does not: links to other daemons, and the opt-in OpenTelemetry tracing.

## Links to other daemons

Daemons may link to each other over sealed UDP and forward their clients' sends one hop, to the peers whose subscribers may want them, or two through a relay (ADR-0021). Links are off unless a daemon is given all three of `--node-key FILE` (its X25519 node key, loaded, or generated into a file of mode 0600 on the first start), `--link-bind ADDR` (the UDP address every link uses) and one or more peers, each `--link-peer ADDR=PUBKEY` (a peer's link address and the public half of its node key as 64 hex digits) or `--link-peer-key PUBKEY` (the key alone, its address found by LAN announcement, below). At startup the daemon logs its daemon id, the fingerprint of its public key that names it across links, its public key, which its peers configure, its link address and its peers.

```sh
mesh-hub --node-key /var/lib/pms/node.key --link-bind 192.0.2.10:7400 \
  --link-peer 192.0.2.11:7400=<the other daemon's public key>
```

Only the configured peers' keys are admitted, each from its address's IP, and a datagram is taken as the peer's whose key opened it, whatever address it came from: one that claims another daemon's id, or forwards another daemon's client from a peer not trusted as a relay (below), is refused and counted. Each link starts with a Hello carrying the 48-byte capability Hello of `mesh-capability`, inside the sealed session. Each daemon then sends its peers a summary of its subscriptions, at most four times a second and again every five seconds, and forwards a send only to a peer whose summary may match it. A forwarded envelope reaches the receiving daemon's matching subscribers as an event whose `origin` is `name@` and the sending daemon's 16-digit id, and goes no further unless the receiver is a relay. It is not stored or signalled on the receiving hub's ring, so processes attached to that hub by name see their own host's sends alone. Delivery across a link is at most once, in no promised order, and nothing sent while a link is down is kept for later. An envelope whose canonical form is up to pulse-wire-udp's `MAX_MESSAGE` less the link's framing (87 bytes, the origin's name and the channel) crosses as a run of sealed fragments; a longer one is delivered at home, not forwarded, and counted.

Each daemon also announces its attached clients to its peers, by their qualified ids (`name@` and its 16-digit id, or for a client that proved a key `name@` and the key's 32 hex digits, then `@` and the id), paced as its summary is: on an attach or a detach, at most four times a second, and again every five seconds. An announcement too long for one link datagram is split into parts, up to 64, which the receiver takes once all have arrived. With it a client can send to one node with `to` (see the `mesh-port-protocol` crate's documentation, Destinations): a node on the same daemon gets the envelope on its own subscriptions that match it alone, and the ack says `delivered: true` or `false`; a node a peer announced is reached by a forward to that peer alone, and `delivered: true` then means forwarded; any other node is refused with `unknown_destination`. A send with `to` is checked by the hub's schemas and is neither stored, signalled on the ring, captured nor forwarded by interest.

Health crosses the links too. A daemon whose subscribers watch health (a filter with `health`) says so in its summary, and its peers report to it each change of their own clients' states, and their clients that are not healthy when its summary first asks; its watchers get the same `health` notices as for its own clients, with the qualified node id, and a new watcher's first notices include the peers' clients known not to be healthy. A client a peer stops announcing, and every client of a peer whose link goes silent or restarts, is reported `detached`.

A daemon whose node key is the lower of a pair spaces its attempts to make a sealed session with that peer at least two seconds apart, start to start, so that a peer reaching it from another port of its configured IP makes its session within about a second, where back-to-back attempts kept it waiting for several.

Daemons on one LAN can find each other's link endpoints instead of listing them. With `--link-announce GROUP:PORT` (an IPv4 multicast group and port, the group's first byte 224 to 239, and 239 the range a site uses for its own; off by default) a daemon sends the group, at startup and every five seconds, a 47-byte announcement naming its node key's public half and its link port, the address being the datagram's source, with a TTL of 1 by default (`--link-announce-ttl`), and hears the other daemons' announcements there. An announcement is a plaintext hint and is not signed, since a node key is an X25519 key and cannot sign. One from a key that is not a configured peer's is ignored and counted; one from a configured peer's key, while no sealed session to that peer exists, asks for a handshake, which then authenticates the key, at most one per peer every five seconds, so a forged announcement costs at most a handshake that fails. A `--link-peer-key` peer is tried at the address its announcement gives and admitted from any address its handshake comes from; a `--link-peer` keeps its configured address, whatever announcements say, and is admitted only from that address's IP. `--link-peer-key` needs `--link-announce`, and `--link-announce` an IPv4 `--link-bind`.

```sh
mesh-hub --node-key /var/lib/pms/node.key --link-bind 192.0.2.10:7400 \
  --link-announce <a multicast group>:7401 --link-peer-key <the other daemon's public key>
```

### Relays

**A relayed origin is only as trustworthy as the relay.** A link authenticates the daemon at its other end and nothing more: nothing signs an envelope, its origin or an announcement end to end, so the origin a relay reports for a send it passes on, and the clients it says it reaches, are what the relay says they are. A daemon takes such traffic only from a peer it names with `--link-trust-relay`; trusting a relay is trusting it to speak for the daemons behind it.

A daemon started with `--link-relay` relays for its peers, so that daemons not linked to each other reach one another through it (ADR-0021, item 9), and says so in its Hello. A send leaves its origin with a hop limit of two, in the forwarding pulse's `chain_step`; a relay delivers what a peer forwards it to its own subscribers, and passes it on once, a hop spent, to its other peers whose summaries may match it, never back to the peer it came from or to its origin's daemon. What came through a relay already, or has no hop left, goes no further, and a daemon that does not relay forwards nothing on, so a send crosses at most one relay; a copy that arrives directly and another through a relay are delivered once. A relay's summary to each peer is its own subscribers' together with the latest summaries of its other peers that are not relays, the receiving peer's own left out, remade whenever one changes and paced and coarsened as any summary is; relays do not sum one another's summaries up, so no summary covers more than one relay's neighbourhood and no loop feeds interest back. A daemon that does not relay sends its own subscribers' summary alone, as before.

A relay's announcement to each peer names its own clients and, as reached through it, the clients its other peers announce as their own, the receiving peer's left out (control message version 2, which a build before relays refuses). A daemon that trusts the relay takes them: a send with `to` goes to the node's own daemon when that daemon announced it directly, and otherwise to the relay, which forwards it to the node's daemon alone; a node no peer announces is refused with `unknown_destination`, as before. A node no peer announces any longer, as when the relay's link to its daemon goes down, is reported `detached`. A relay passes each peer's reports of its own clients' health on to the other peers whose summaries watch health.

`--link-trust-relay PUBKEY` (repeatable) names a configured peer, by its key, whose relayed traffic this daemon accepts: forwards of other daemons' clients, the clients announced as reached through it, and their health. The key must be a `--link-peer`'s or a `--link-peer-key`, or the command line is refused (exit status 2). From any other peer, relayed forwards and health reports are refused and counted, and the clients announced through it ignored; that a peer says it relays changes nothing of what is accepted from it.

```sh
# The relay, linked to A and C:
mesh-hub --node-key /var/lib/pms/node.key --link-bind 192.0.2.20:7400 --link-relay \
  --link-peer 192.0.2.10:7400=<A's public key> --link-peer 192.0.2.30:7400=<C's public key>
# A, linked to the relay alone and trusting it (C likewise):
mesh-hub --node-key /var/lib/pms/node.key --link-bind 192.0.2.10:7400 \
  --link-peer 192.0.2.20:7400=<the relay's public key> --link-trust-relay <the relay's public key>
```

The datagram layouts, the link's life (Hellos, heartbeats every second, a link taken down after five seconds of silence), the connector, and the rules for forwarding, announcements, LAN announcement, destinations, health and relays are in the `mesh_hub::link` module's documentation. The counts are at `/metrics` as `pms_daemon_links_configured`, `pms_daemon_links_up`, `pms_daemon_link_peer_nodes` (the clients the peers announce now, those trusted relays reach included), `pms_daemon_link_relay_interest_bytes` (for a relay, the largest summary it gives a peer, its other peers' summed up in it) and the `pms_daemon_link_*_total` counters: forwards sent, received and dropped, relayed forwards sent and received, relayed traffic refused from peers not trusted as relays, duplicates dropped, summaries sent and received, announcements sent and received, health reports sent and received, forwards addressed to a client no longer attached, handshakes refused, datagrams refused, LAN announcements sent, received and ignored, and the handshakes LAN announcements asked for (`pms_daemon_link_lan_connects_total`); `pms_daemon_remote_health_notices_total` counts the notices about peers' clients queued for watchers, and `pms_daemon_destination_sends_total{outcome="local"|"forwarded"|"unknown"}` the sends with `to`, with links or without.

## Traces over OpenTelemetry (the `otel` feature)

The daemon makes a span for each message a client sends and for each message it writes to a client. The spans are plain `tracing` spans at the trace level, compiled in whether the feature is on or not, and kept out of the log at every `MESH_HUB_LOG` level. With nothing installed to take them, a span costs a level check and records nothing, so a daemon built without the feature, or built with it and run without a collector, logs and behaves as it always has.

The `otel` feature adds the layer that takes them: it turns the daemon's spans into OpenTelemetry spans, batches them, and posts them to an OTLP collector as protobuf over HTTP. Without the feature nothing of OpenTelemetry is compiled in.

### Turning it on

Build with the feature, and name a collector in the environment:

```sh
cargo build --release -p mesh-hub --features otel
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 target/release/mesh-hub
```

At startup the daemon logs one line saying where the traces go:

```text
INFO exporting traces over OTLP/HTTP endpoint="http://127.0.0.1:4318/v1/traces"
```

When neither endpoint variable is set, the daemon exports nothing and logs no such line. A configuration the exporter cannot use (an endpoint that is not a URL, a header it cannot send) is logged at error level as `traces are not exported: ...`, and the daemon runs without exporting.

As the daemon exits, after SIGINT or SIGTERM, a displacement or a failed start, it exports the spans still batched before it returns its status. That wait is bounded by the export timeout (`OTEL_EXPORTER_OTLP_TIMEOUT`, 10 seconds by default, retries included); an export that fails is logged as a warning by the OpenTelemetry SDK and as `the last traces could not be exported: ...` by the daemon. A panic aborts the release build and loses what is batched.

### Transport

The export is OTLP/HTTP with protobuf bodies, over hyper's HTTP/1.1 client without TLS: the endpoint must be an `http://` URL, and the collector's OTLP/HTTP port is 4318 by convention (4317 is OTLP/gRPC, which the daemon does not speak). `OTEL_EXPORTER_OTLP_PROTOCOL` is not read; the protocol is always `http/protobuf`. To reach a collector over HTTPS, run a collector or an agent on the host and point the daemon at it.

### Environment variables

| Variable | What it does |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The collector's base URL; the traces go to it with `/v1/traces` after it. Setting it, or the next one, turns the export on. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | The traces URL, used as given; it wins over `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `OTEL_SERVICE_NAME` | The `service.name` resource attribute, `mesh-hub` unless this or a `service.name` in `OTEL_RESOURCE_ATTRIBUTES` names another. |
| `OTEL_RESOURCE_ATTRIBUTES` | More resource attributes, as `key=value,key=value`. |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` | Headers sent with each export, as `key=value,key=value` (an authorization token, say). |
| `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT` | Milliseconds one export may take, its retries included: 10,000 by default. |
| `OTEL_BSP_SCHEDULE_DELAY`, `OTEL_BSP_MAX_QUEUE_SIZE`, `OTEL_BSP_MAX_EXPORT_BATCH_SIZE` | The batching: an export every 5,000 ms, at most 2,048 spans waiting (the SDK drops the rest and warns once), at most 512 spans an export. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Which traces are kept: all of them by default; `traceidratio` and `0.01` keep one in a hundred. |

Every span carries the resource attributes `service.name`, `pulse_mesh.hub.name` (the daemon's `--hub-name`) and the SDK's `telemetry.sdk.*`, and the instrumentation scope `mesh-hub` at the crate's version.

### Spans

| Span | What it covers | Fields |
|---|---|---|
| `send` | A client's send, from storing the envelope and signalling it on the ring through queueing it for every subscription it matches; for a send to a node (`to`), from resolving the node through delivering or forwarding it. A send refused for a channel or type name too long makes no span. | `channel`; `type_id`; `payload_bytes`, the decoded payload's length; `origin`, the sender's node id (`name@suffix`); `matched`, the subscriptions whose filter matched, each offered the event, absent for a send forwarded to a peer's node; `persisted`, whether the store kept the envelope, absent without a store and for a send to a node; `to`, the destination as the send named it, for a send to a node. A send the hub refuses ends without `matched` and `persisted`. |
| `deliver` | One event or health notice written to a connection, the write and its deadline. | `subscription_id`, the subscription the event is for, absent for a health notice; `bytes`, the message's JSON. |
| `attach` | An attach message. | `name`, quoted to 128 bytes as an error message quotes it. |
| `detach` | A detach message, or the close of an attached connection that sent none. | `name`, absent for a detach before any attach. |
| `subscribe` | A subscribe message. | `subscription_id`, once the subscription is open. |
| `unsubscribe` | An unsubscribe message. | `subscription_id`, as the client sent it; `events_dropped`, the events dropped for the subscription, once it is closed. |

Counts are OpenTelemetry integers, `persisted` a boolean, and the rest strings. Each span is a trace of its own: a `deliver` is not linked to the `send` whose event it writes, and the two are matched by the subscription id and the time. The layer adds what `tracing-opentelemetry` adds to every span (`code.file.path`, `code.module.name`, `code.line.number`, `thread.id`, `thread.name`, `target`, and `busy_ns` and `idle_ns`), and takes a warning or an error the daemon logs inside a span as an event on that span, an error also marking the span's status as an error. The daemon's debug and info lines stay out of the traces.

### Embedding

A host that runs the daemon through `mesh_hub::embed::EmbeddedMesh` gets the same spans on the subscriber it installs. With the feature, `mesh_hub::otel::layer` turns them into OpenTelemetry spans for a tracer provider of the host's own, and `mesh_hub::otel::resource` gives the resource attributes above; `mesh_hub::otel::Traces::from_env` is what the binary uses.
