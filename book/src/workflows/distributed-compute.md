# Distributed compute: jobs across machines through linked daemons

<p class="pm-kind"><b>Workflow</b> · for anyone spreading one job over several machines, or putting an agent swarm across hosts; about twenty minutes, with the daemon repository</p>

<figure class="pm-art"><svg class="uc-diagram" viewBox="0 0 380 240" role="img" aria-label="Linked daemons forward what their subscribers want"><line x1="60" y1="130" x2="180" y2="50" class="uc-edge-dash"/><line x1="60" y1="130" x2="310" y2="90" class="uc-edge-dash"/><line x1="60" y1="130" x2="270" y2="195" class="uc-edge-dash"/><line x1="180" y1="50" x2="310" y2="90" class="uc-edge-dash"/><line x1="310" y1="90" x2="270" y2="195" class="uc-edge-dash"/><circle cx="60" cy="130" r="20" class="uc-node-strong"/><text x="60" y="168" class="uc-label">host a</text><circle cx="180" cy="50" r="26" class="uc-ring"/><circle cx="180" cy="50" r="14" class="uc-ring-dash"/><text x="180" y="94" class="uc-label">host b</text><circle cx="310" cy="90" r="26" class="uc-ring"/><circle cx="310" cy="90" r="14" class="uc-ring-dash"/><text x="310" y="134" class="uc-label">host c</text><circle cx="270" cy="195" r="26" class="uc-ring"/><circle cx="270" cy="195" r="14" class="uc-ring-dash"/><text x="270" y="239" class="uc-label">relay</text><circle class="uc-pulse" r="3"><animateMotion dur="2s" begin="0.0s" repeatCount="indefinite" path="M60,130 L180,50"/></circle><circle class="uc-pulse" r="3"><animateMotion dur="2s" begin="0.4s" repeatCount="indefinite" path="M60,130 L310,90"/></circle><circle class="uc-pulse" r="3"><animateMotion dur="2s" begin="0.8s" repeatCount="indefinite" path="M60,130 L270,195"/></circle></svg><figcaption>Linked daemons forward what their subscribers want</figcaption></figure>

**You will have:** two daemons linked to each other, on one machine here and on two by changing two addresses; a job published to one daemon arriving at a subscriber of the other, carrying its origin qualified by the daemon it came from; the link's counters showing the forward; and the path from here to the planner and workers of [An agent swarm](../examples/agent-swarm.md) spread over hosts, to discovery on a LAN, and to a relay.

**You need:** the daemon repository set up as [Start here](../start/onboard-your-agent.md) describes, with `pms` and `mesh-hub` installed. For two machines, UDP between them on the link ports you choose.

## Hand this to your agent

```text
Run the workflow "Distributed compute" from book/src/workflows/distributed-compute.md in the pulse-mesh-daemon repository, on this machine:
1. A daemon prints its node key's public half only when its links are configured, so bootstrap each key with a placeholder peer. Start daemon A in the background: mesh-hub --hub-name lnkA --no-uds --ws-bind 127.0.0.1:9876 --node-key ./a.key --link-bind 127.0.0.1:7400 --link-peer 127.0.0.1:7401=<64 zeros>; wait for its "links to other daemons configured" log line, record the public_key it prints, and stop it. Do the same for daemon B with --hub-name lnkB, --ws-bind 127.0.0.1:9877, --node-key ./b.key, --link-bind 127.0.0.1:7401 and a placeholder peer at 127.0.0.1:7400.
2. Start both again, each naming the other's public key in --link-peer, and wait for a "link up" log line from each.
3. Against B (PMS_DAEMON=ws://127.0.0.1:9877), run pms tap --channel 'jobs/*' in the background, wait for "tapped", then a second more, so B's interest summary has reached A.
4. Against A (PMS_DAEMON=ws://127.0.0.1:9876), run pms push jobs/new 'hello from daemon A'. Show me the envelope_id and the line the tap on B printed; its origin must end in @ followed by daemon A's 16-digit id, the daemon_id from A's log.
5. Stop everything and show me each daemon's "links at exit" line: A forwards_sent=1, B forwards_received=1.
Explain in plain words how the job crossed from A to B and what the qualified origin means. Stop and tell me if anything fails, and say which step.
```

## Or do it by hand

### 1. Give each daemon a node key

Links are authenticated by each daemon's X25519 node key, which the daemon generates into the file `--node-key` names on its first start, and whose public half it logs. It logs it only when its links are configured, so the first start names a placeholder peer. In a first terminal:

```bash
mesh-hub --hub-name lnkA --no-uds --ws-bind 127.0.0.1:9876 --node-key ./a.key \
  --link-bind 127.0.0.1:7400 \
  --link-peer 127.0.0.1:7401=0000000000000000000000000000000000000000000000000000000000000000
```

```text
INFO links to other daemons configured daemon_id=8f0882adae3fafa5 public_key=36ae5e96…f47a link_bind=127.0.0.1:7400 peers=… announce=None relay=false trusted_relays=…
INFO websocket bound bound=127.0.0.1:9876 scheme="ws"
```

Keep A's `public_key` (64 hex digits) and `daemon_id`, then stop it with Ctrl-C. In a second terminal do the same for B, with `--hub-name lnkB`, `--ws-bind 127.0.0.1:9877`, `--node-key ./b.key`, `--link-bind 127.0.0.1:7401` and the placeholder peer at `127.0.0.1:7400`; keep B's public key and stop it.

### 2. Link them

Start A again with B's key, and B with A's:

```bash
mesh-hub --hub-name lnkA --no-uds --ws-bind 127.0.0.1:9876 --node-key ./a.key \
  --link-bind 127.0.0.1:7400 --link-peer 127.0.0.1:7401=<B's public key>
```

```bash
mesh-hub --hub-name lnkB --no-uds --ws-bind 127.0.0.1:9877 --node-key ./b.key \
  --link-bind 127.0.0.1:7401 --link-peer 127.0.0.1:7400=<A's public key>
```

Each logs, within a second or two:

```text
INFO link up peer=83cec7bc66fe3ca8 addr=Some(127.0.0.1:7401) version=3 capabilities=0 registry_match=true relays=false trusted_as_relay=false
```

`peer` is the other daemon's id, the fingerprint of its public key. Each daemon's `--link-bind` is one UDP endpoint, whatever the number of its peers; the link between two daemons is one sealed session between their endpoints.

### 3. A worker on B, a job from A

In a third terminal, a subscriber on B:

```bash
PMS_DAEMON=ws://127.0.0.1:9877 pms tap --channel 'jobs/*'
```

```text
tapped; Ctrl-C to stop
```

Give it a second: B's summary of what its subscribers want reaches A a fraction of a second after the subscription. Then, in a fourth terminal, a job published to A:

```bash
PMS_DAEMON=ws://127.0.0.1:9876 pms push jobs/new 'hello from daemon A'
```

```text
envelope_id=c4ca9156f3946f9cb120990d488325d4
```

and the tap on B prints:

```text
            jobs/new |       19B | c4ca9156 | pms-cli-send@8f0882adae3fafa5
```

The origin is qualified: the publisher's name, `@`, and the 16-digit id of the daemon it attached to. A had forwarded the send to B because B had told A, in its interest summary, that a subscriber of its wanted `jobs/*`.

### 4. Stop, and read the counters

Ctrl-C the tap and both daemons. Each daemon's last lines include:

```text
INFO links at exit links_up=1 forwards_sent=1 forwards_received=0 duplicates_dropped=0 forwards_dropped=0
```

on A, and `forwards_sent=0 forwards_received=1` on B.

**Across two machines:** give each daemon its machine's address in `--link-bind` and the other machine's in `--link-peer`, open the two link ports for UDP between them, and keep `--ws-bind` on loopback on each machine; clients attach to the daemon on their own machine. Nothing else changes.

## Check it worked

| Check | Where | Pass |
|---|---|---|
| The daemons authenticated each other | Both logs | A `link up` line on each, naming the other's id |
| A job on A reached a subscriber on B | The tap on B | The `jobs/new` line, with `@` and A's `daemon_id` at the end of the origin |
| Exactly one forward | Both `links at exit` lines | `forwards_sent=1` on A, `forwards_received=1` on B, `duplicates_dropped=0` |
| The pushed envelope is the delivered one | `envelope_id` from `pms push` and the tap line | The same first eight characters |

If a daemon exits with status 2 saying links need `--node-key`, `--link-bind` and a peer, one of the three is missing: all three are required, which is why step 1 names a placeholder. If `link up` never appears, the keys are swapped or a port is blocked; a daemon admits a peer's key only from the IP of the address its `--link-peer` names. If the tap prints nothing, the subscription was made after the push, or the push came before B's interest summary reached A, a fraction of a second after the subscription; forwarding follows subscriptions, so subscribe first and give it a moment.

## What happened

- **Daemons link over sealed UDP.** Each `--link-bind` is one endpoint; a link between two daemons is a Noise IK session with ChaCha20-Poly1305, keyed by their X25519 node keys, and only the configured peers' keys are admitted, each from its address's IP. A link begins with a Hello carrying the capability Hello of `mesh-capability`, inside the session.
- **Forwarding follows interest.** Each daemon tells its peers a summary of what its subscribers want, paced so it is sent at most a few times a second. A client's send is forwarded once to each linked peer whose summary matches, and delivered there to the subscribers whose filters match. A daemon also announces its attached clients to its peers by qualified id, so a send with a destination can be routed to the daemon that holds it.
- **The origin travels.** Across a link a client is `name@` and its daemon's 16-digit id, so a worker on B knows which daemon a job came from, and a result published on B reaches a subscriber on A the same way, by B's forward.
- **One hop, or two through a relay.** A send leaves its daemon with a hop limit of two. Daemons not linked to each other reach one another through a daemon started with `--link-relay`, which forwards once more and announces the clients reached through it; a daemon accepts relayed traffic only from a peer it names with `--link-trust-relay`, because a relayed origin is only as trustworthy as the relay. There is no third hop.
- **Finding peers on a LAN.** With `--link-announce GROUP:PORT` a daemon multicasts its link endpoint every five seconds and hears the others', so `--link-peer-key` names a peer by key alone and its address is learned; the announcement is a hint, acted on only for a key already configured, and the handshake then authenticates it.

What this does not do yet: the link's sealing has not had the independent cryptographic review that ADR-0018 requires before sealed mode is recommended for production, so run linked daemons between machines you control; nothing signs an envelope or its origin end to end, which is why relays must be trusted by name; and forwarding is to subscribers, not to a chosen worker, so splitting a job across machines is done the way the agent swarm does it on one, by channel or by claim.

## Make it yours

- **The swarm across hosts.** Run the planner of [An agent swarm](../examples/agent-swarm.md) against the daemon on one machine, start the workers against daemons on others, and start every daemon with a basket. Jobs on `jobs/new` reach every worker's daemon; results on `results` come back the same way, each origin naming the worker's daemon; `pms-query` on the planner's basket sees them all.
- **Per-machine channels.** Workers on machine B tap `jobs/b/*`; the planner pushes to `jobs/b/new`; forwarding carries the job only to daemons whose subscribers want that channel.
- **A relay for a third machine.** Start a daemon with `--link-relay` linked to A and C, and name it in both with `--link-trust-relay`; A's jobs reach C's workers through it, one hop further.
- **Without a daemon.** For one sender and many receivers on a LAN, `pulse_wire_udp`'s `Receiver::bind_multicast` and `Sender::set_multicast` carry Pulses to a multicast group with no daemon between; [Across a network](/docs/examples/across-a-network.html) is the two-ended version.

## Next

- [An agent swarm](../examples/agent-swarm.md): the planner and workers this spreads across hosts.
- [Run the daemon as a service](../guides/run-the-daemon-as-a-service.md): the link flags beside the rest, and what a restart costs.
- [Trust boundaries](../explanation/trust-boundaries.md): what a link protects and what it does not.
- [The mesh-hub daemon](../reference/daemon-reference.md): every link flag with its default.

## Spoken walkthrough

*A script for the video and audio version of this page, about two minutes.*

Two daemons, two machines, one job.

Each daemon gets a key. It makes the key itself, the first time it starts, and prints the public half in its log. We give each daemon the other's public key and the other's address, and they link: one encrypted UDP session between them, and a line in each log saying the link is up and naming the other side.

Now a worker subscribes to the jobs channels on daemon B, and a planner pushes a job to daemon A. Watch the worker's terminal: the job arrives. Look at where it came from: the publisher's name, an at sign, and daemon A's id. The job crossed the link because B had told A that someone on its side wanted jobs.

When we stop the daemons, each prints its counters: A forwarded one, B received one, nothing duplicated.

To do this between real machines, change two addresses. To add a third machine that is not linked to the first, add a relay, and tell the others to trust it by name, because a relay's word is the only word you have about where a forwarded job came from.

And one plain statement: the link's encryption has not yet had the independent review the Foundation requires before it recommends it for production. Between machines you control, this is how a job crosses the room.
