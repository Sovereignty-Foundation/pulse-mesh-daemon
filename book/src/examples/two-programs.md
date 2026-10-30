# Two programs talk through the daemon

<p class="pm-kind"><b>Example</b> · for anyone running Pulse Mesh for the first time, in about fifteen minutes</p>

<figure class="pm-art"><svg class="uc-diagram" viewBox="0 0 380 240" role="img" aria-label="Four ways in, one daemon between them"><circle cx="190" cy="120" r="40" class="uc-ring"/><circle cx="190" cy="120" r="28" class="uc-ring-dash"/><circle cx="190" cy="120" r="5" class="uc-core"/><text x="190" y="178" class="uc-label">daemon</text><line x1="70" y1="60" x2="190" y2="120" class="uc-edge"/><rect x="48" y="49" width="44" height="22" rx="2" class="uc-node"/><text x="70" y="42" class="uc-label">pms</text><line x1="310" y1="60" x2="190" y2="120" class="uc-edge"/><rect x="288" y="49" width="44" height="22" rx="2" class="uc-node"/><text x="310" y="42" class="uc-label">rust</text><line x1="70" y1="180" x2="190" y2="120" class="uc-edge"/><rect x="48" y="169" width="44" height="22" rx="2" class="uc-node"/><text x="70" y="210" class="uc-label">python</text><line x1="310" y1="180" x2="190" y2="120" class="uc-edge"/><rect x="288" y="169" width="44" height="22" rx="2" class="uc-node"/><text x="310" y="210" class="uc-label">node</text><circle class="uc-pulse" r="3"><animateMotion dur="1.4s" begin="0s" repeatCount="indefinite" path="M70,60 L190,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.4s" begin="0.7s" repeatCount="indefinite" path="M190,120 L310,60"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.4s" begin="0.73s" repeatCount="indefinite" path="M190,120 L70,180"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.4s" begin="0.76s" repeatCount="indefinite" path="M190,120 L310,180"/></circle><text x="190" y="226" class="uc-label">one write in, every subscriber out</text></svg><figcaption>Four ways in, one daemon between them</figcaption></figure>

**You will have:** a daemon on your machine, and messages moving through it from the command line, from two Rust programs, and from a Python publisher to a Node subscriber. You will have seen every message named by a hash of its content, the same name on every side, and what a subscriber misses while it is away.

**You need:** the daemon repository set up as [Start here](../start/onboard-your-agent.md) describes, with `pms` and `mesh-hub` installed and the Rust toolchain. For the other-language step, Python 3 with `pip` and Node 22 or later with `npm`; nothing in that step is compiled.

## Hand this to your agent

```text
Run the example "Two programs talk through the daemon" from book/src/examples/two-programs.md in the pulse-mesh-daemon repository:
1. Start a daemon in the background: pms start. It prints the process id and its log file. Confirm the log shows "websocket listening".
2. In the background, run pms tap --channel 'jobs/*' and keep its output. Then run pms push jobs/new 'first job' and show me the envelope_id it prints and the line the tap printed; the eight characters after "jobs/new |" in the tap line must be the start of that envelope_id.
3. Run pms push jobs/new 'first job' again and confirm the envelope_id is identical. Run pms push jobs/other 'first job' and confirm it differs.
4. Build and run the two Rust programs: cargo run --release -p multi-process --bin receiver in the background, wait for "attached and subscribed", then cargo run --release -p multi-process --bin sender. Show me that each "sender: sent 'job-N' as envelope X" has a matching "receiver: got 'job-N' (envelope X, 5 bytes)".
5. Install the thin clients, pip install -e clients/pms-py-thin and npm install --prefix peripheral/clients/pms-node-thin. Run node examples/multi-lang/node_subscriber.js in the background, then python3 examples/multi-lang/python_publisher.py, and show me that the identifiers match across the two languages.
6. Run pms ring inspect default_hub --count 2 and tell me what the cursor says about how many Pulses the daemon has written.
7. Stop everything you started, including the daemon (kill the process id from step 1).
Explain in plain words what each step showed. Stop and tell me if anything fails, and say which step.
```

## Or do it by hand

### 1. Start the daemon

In a first terminal:

```bash
pms start --foreground
```

```text
INFO uds listening path=/tmp/pms.sock
INFO websocket listening addr=127.0.0.1:9876
```

Those are the two endpoints clients find on their own: `pms` and the Rust client try the Unix socket, then the WebSocket port, unless `PMS_DAEMON` names an endpoint (`unix:///path` or `ws://host:port`). Leave this terminal alone. Without `--foreground`, `pms start` detaches the daemon, prints its process id and log file (`~/.local/state/pms/mesh-hub.log`), and returns; stop a detached daemon with `kill` and that id.

### 2. Watch a channel

In a second terminal:

```bash
pms tap --channel 'jobs/*'
```

```text
tapped; Ctrl-C to stop
```

`tap` attaches under a generated name and subscribes to every channel matching `jobs/*`. It prints one line per event for as long as it runs. Leave it running.

### 3. Publish from the command line

In a third terminal:

```bash
pms push jobs/new 'first job'
```

```text
envelope_id=cb05c6b8f4b696551a0b7245b6f104a2
```

and the tap prints:

```text
            jobs/new |        9B | cb05c6b8 | @6b19f89f
```

Left to right: the channel, the payload size, the first eight characters of the envelope identifier, and the origin, the short form of the publisher's node id. Now publish three more:

```bash
pms push jobs/new 'first job'
pms push jobs/other 'first job'
pms push jobs/new 'first job' --type-name job.created
```

```text
envelope_id=cb05c6b8f4b696551a0b7245b6f104a2
envelope_id=329b893bbb06850cd40679fd0a2d98d5
envelope_id=759d3a7c705c4d63cba9a36194fc980c
```

The first identifier is the same as before, because the content is the same: the identifier is computed from the channel, the type name and the payload, and from nothing else. Change the channel and it changes; add a type name and it changes.

### 4. Two Rust programs

The two programs are in the checkout under `examples/multi-process/`. The receiver:

```rust
{{#include ../../../examples/multi-process/src/receiver.rs:3:}}
```

`Mesh::attach` connects to the daemon and registers the process under the name you give it. `mesh.on` subscribes to one channel and hands every event on it to the closure for as long as `mesh.run()` runs. The sender:

```rust
{{#include ../../../examples/multi-process/src/sender.rs:3:}}
```

`mesh.send` publishes the bytes on the channel and returns the identifier the daemon computed. Start the receiver in the third terminal:

```bash
cargo run --release -p multi-process --bin receiver
```

```text
receiver: attached and subscribed to 'jobs' (Ctrl-C to stop)
```

and the sender in a fourth:

```bash
cargo run --release -p multi-process --bin sender
```

```text
sender: attached
sender: sent 'job-0' as envelope 796abc6e
sender: sent 'job-1' as envelope 5fba33ce
sender: sent 'job-2' as envelope 4166531f
```

```text
receiver: got 'job-0' (envelope 796abc6e, 5 bytes)
receiver: got 'job-1' (envelope 5fba33ce, 5 bytes)
receiver: got 'job-2' (envelope 4166531f, 5 bytes)
```

The identifiers match line for line because both sides name the same envelope, and `job-0` has the same identifier on every run. After ten messages the sender prints `sender: done` and exits; the receiver keeps running.

### 5. The same exchange from Python and Node

Install the two thin clients, each a single file with six calls (`attach`, `send`, `on`, `tap`, `run`, `detach`) and no codec: the daemon computes every identifier.

```bash
pip install -e clients/pms-py-thin
npm install --prefix clients/pms-node-thin
```

Start the Node subscriber:

```bash
node examples/multi-lang/node_subscriber.js
```

```text
node: attached; listening on multi-lang/demo (Ctrl-C to stop)
```

and, in another terminal, the Python publisher:

```bash
python3 examples/multi-lang/python_publisher.py
```

```text
py: attached
py: sent b'hello-from-python-0' as fe531358
py: sent b'hello-from-python-1' as a2bcbef7
```

```text
node: got 'hello-from-python-0' (envelope fe531358)
node: got 'hello-from-python-1' (envelope a2bcbef7)
```

Run `pms push multi-lang/demo hello-from-python-0` and it prints the same identifier, `fe531358…`: three languages, one name for one content.

### 6. Look at the ring underneath

```bash
pms ring inspect default_hub --count 2
```

```text
ring          /pms-default_hub
capacity      64 slots
write_count   …
cursor        …
recent        2 pulse(s):
  slot=    …  inst=DATA        mono_ns=     …  has_envelope=true
  slot=    …  inst=DATA        mono_ns=     …  has_envelope=true
```

The ring is a shared-memory object named after the hub. Every envelope published through the daemon writes one 128-byte Pulse into it, and the cursor counts them. `has_envelope` is true on every slot: the Pulse carries the envelope's identifier, and a second process attached to the hub fetches the envelope from the store beside the ring by that identifier. That is how envelopes cross processes.

### 7. Stop the daemon

Ctrl-C in the first terminal. The daemon removes its socket and unlinks its shared memory as it exits.

## Check it worked

| Check | Command | Pass |
|---|---|---|
| The command line, Rust, Python and Node all name content the same way | Compare `pms push`'s `envelope_id`, the sender's and receiver's lines, and the Python and Node lines | The same eight characters on every side of each message |
| Identity is content | `pms push jobs/new 'first job'` twice, then on `jobs/other` | Identical identifiers, then a different one |
| The daemon counts what it carried | `pms ring inspect default_hub --count 2` | `cursor` equals the number of envelopes published since the daemon started |
| A subscriber away misses what was sent | Run the sender again; stop the receiver at `job-2`, wait two seconds, restart it | The receiver prints from `job-5` or `job-6` on, and nothing for the gap |

If `pms push` reports it cannot reach a daemon, none is running or `PMS_DAEMON` points elsewhere; the daemon's log names its endpoints. If the Node subscriber or Python publisher fails to connect, `PMS_DAEMON` must be a `ws://` address or unset: the thin clients speak WebSocket only.

## What happened

- **Identity is content.** The daemon names every envelope by the BLAKE3 hash of its canonical bytes: channel, type name and payload. Two envelopes with identical content share one name, in every language, so a receiver can check what it got without trusting who sent it.
- **A subscription is a live stream.** It delivers from the moment the daemon acknowledges the subscribe request, and the daemon keeps nothing for a subscriber that is not connected; the messages sent in a gap are gone for that subscriber. A subscriber that stays connected but stops reading is a different case: the daemon queues up to a fixed number of events for it (`--subscriber-queue`, 1,024 by default), drops newer ones beyond that, and reports how many when the subscription ends.
- **Every subscriber gets every matching message.** The daemon broadcasts to the subscriptions whose filter matches; it does not pick one.
- **The ring is the signal, the store is the content.** One 128-byte Pulse per envelope goes into the shared-memory ring; the envelope itself sits in the store beside it, fetched by identifier.

What the daemon does not do on its defaults: it authenticates no client and encrypts nothing, so it listens on loopback, where its WebSocket is still open to every user of the machine, and it authorises nobody per channel, with or without its optional TLS and key-proof attach ([Trust boundaries](../explanation/trust-boundaries.md)); it keeps no history for late subscribers (the basket, in [Capture envelopes and query them](../guides/capture-and-query.md), is the record); and `mesh_health` in the MCP server reports which names are attached, not whether they are alive.

## Make it yours

- **See a whole event:** stop the tap and start it with `--json`; each event is one JSON object with the channel, the identifier, the origin, the capture time and the payload size.
- **Speak the protocol yourself:** in a browser's console, open `new WebSocket('ws://127.0.0.1:9876', ['pms-universal-port-v0'])` and send three JSON frames, `attach`, `subscribe` and `send`, with a base64 payload; four come back, three acks and the event for your own envelope. [The port protocol](../reference/spec/07-port-protocol.md) is the whole contract.
- **Type your messages:** `--type-name` on `pms push`, or the `type_name` argument in any client, becomes part of the identifier and a filter a subscriber can use.

## Next

- [An agent swarm](agent-swarm.md): a planner and two workers on this daemon, every result checked against its job.
- [Capture envelopes and query them](../guides/capture-and-query.md): keep a record of what went through, and ask it questions.
- [Run the daemon as a service](../guides/run-the-daemon-as-a-service.md): flags, launchd and systemd, what a restart costs.
- [Daemon design](../explanation/daemon-design.md): why it is shaped this way.

## Spoken walkthrough

*A script for the video and audio version of this page, about two minutes.*

One daemon, and four ways to talk to it.

First the command line. We start the daemon, open a tap on the jobs channels, and push a message. The tap shows it arrive, and both sides print the same eight characters: the start of the message's identifier. Push the same message again and the identifier is the same. Push it on another channel and it changes. That identifier is a hash of the content, so identity is the content, not who sent it or when.

Next, two Rust programs, each about a screen long. The receiver attaches and subscribes. The sender attaches and publishes ten jobs. Every job the sender names, the receiver names the same way.

Now Python and Node. Two thin clients, no codec in either; the daemon does the naming. A Python publisher, a Node subscriber, and the identifiers still match.

Finally we look underneath. Every message put one 128-byte Pulse into a shared-memory ring, and the ring's cursor counts them. The Pulse carries the identifier; the content sits in a store beside the ring.

One thing to try: stop the receiver while the sender is running, then start it again. It picks up from the next job and never sees the ones sent while it was away. A subscription is a live stream. The record of what went by is the basket, which the next example uses.
