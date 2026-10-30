# An agent swarm: a planner hands out jobs, workers answer

<p class="pm-kind"><b>Example</b> · for anyone putting more than one agent or program on a mesh, in about ten minutes</p>

<figure class="pm-art"><svg class="uc-diagram" viewBox="0 0 380 240" role="img" aria-label="A planner hands out jobs; every worker hears every one"><circle cx="60" cy="120" r="22" class="uc-node-strong"/><text x="60" y="166" class="uc-label">planner</text><line x1="82" y1="120" x2="196" y2="120" class="uc-edge"/><line x1="196" y1="120" x2="212" y2="50" class="uc-edge"/><line x1="196" y1="120" x2="212" y2="85" class="uc-edge"/><line x1="196" y1="120" x2="212" y2="120" class="uc-edge"/><line x1="196" y1="120" x2="212" y2="155" class="uc-edge"/><line x1="196" y1="120" x2="212" y2="190" class="uc-edge"/><rect x="210" y="40" width="20" height="20" rx="2" class="uc-node"/><rect x="245" y="40" width="20" height="20" rx="2" class="uc-node"/><rect x="280" y="40" width="20" height="20" rx="2" class="uc-node"/><rect x="315" y="40" width="20" height="20" rx="2" class="uc-node"/><rect x="210" y="75" width="20" height="20" rx="2" class="uc-node"/><rect x="245" y="75" width="20" height="20" rx="2" class="uc-node"/><rect x="280" y="75" width="20" height="20" rx="2" class="uc-node"/><rect x="315" y="75" width="20" height="20" rx="2" class="uc-node"/><rect x="210" y="110" width="20" height="20" rx="2" class="uc-node"/><rect x="245" y="110" width="20" height="20" rx="2" class="uc-node"/><rect x="280" y="110" width="20" height="20" rx="2" class="uc-node"/><rect x="315" y="110" width="20" height="20" rx="2" class="uc-node"/><rect x="210" y="145" width="20" height="20" rx="2" class="uc-node"/><rect x="245" y="145" width="20" height="20" rx="2" class="uc-node"/><rect x="280" y="145" width="20" height="20" rx="2" class="uc-node"/><rect x="315" y="145" width="20" height="20" rx="2" class="uc-node"/><rect x="210" y="180" width="20" height="20" rx="2" class="uc-node"/><rect x="245" y="180" width="20" height="20" rx="2" class="uc-node"/><rect x="280" y="180" width="20" height="20" rx="2" class="uc-node"/><rect x="315" y="180" width="20" height="20" rx="2" class="uc-node"/><text x="272" y="226" class="uc-label">workers</text><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="0s" repeatCount="indefinite" path="M82,120 L196,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="0.25s" repeatCount="indefinite" path="M82,120 L196,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="0.5s" repeatCount="indefinite" path="M82,120 L196,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="0.75s" repeatCount="indefinite" path="M82,120 L196,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="1s" repeatCount="indefinite" path="M82,120 L196,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.5s" begin="1.25s" repeatCount="indefinite" path="M82,120 L196,120"/></circle></svg><figcaption>A planner hands out jobs; every worker hears every one</figcaption></figure>

**You will have:** a planner (your coding agent) and two worker programs attached to one daemon on your machine. The planner publishes jobs. Every worker receives every job and publishes a result. The planner reads the results and matches each one to the job it answers by the job's envelope identifier, which is a hash of the job's content.

**You need:** the daemon repository set up as [Start here](../start/onboard-your-agent.md) describes, with `pms` and `mesh-hub` installed; Python 3.9 or later with `pip`; and, for the agent path, a coding agent that can use MCP tools. Claude Code is shown. The by-hand path needs no agent.

## Hand this to your agent

```text
Run the agent-swarm example from book/src/examples/agent-swarm.md in the pulse-mesh-daemon repository:
1. Start a daemon with a basket: pms start --basket-path ~/.local/share/pms/basket.db
2. Install the Python thin client and the query tool: pip install -e clients/pms-py-thin -e tools/pms-query
3. Save the worker program from the page as worker.py. Start two workers in the background: python3 worker.py worker-1 and python3 worker.py worker-2. Wait for each to print "attached, waiting for jobs".
4. If pms-mcp is not among your MCP tools: cargo install --path tools/pms-mcp --locked, then register the command pms-mcp as an MCP server and reconnect.
5. With the mesh_send tool, as_name "planner", publish three jobs on channel jobs/new, each a short sentence, with type_name job.new. Keep the envelope_id each call returns.
6. With the mesh_query tool, list rows on channel results. Expect six rows, two per job, with origins worker-1@… and worker-2@….
7. For one result row, run pms-query get <id> in the shell, decode payload_b64, and show me the text. Its eight-character job prefix must match one of the envelope_ids from step 5.
Stop and tell me if anything fails, and say which step.
```

Steps 5 to 7 are the planner's work. If your agent has no MCP, it can do the same with `pms push` and `pms-query`, as the by-hand path below does.

## Or do it by hand

### 1. Start a daemon that keeps a record

In a first terminal:

```bash
pms start --foreground --basket-path ~/.local/share/pms/basket.db
```

The daemon prints where it listens (timestamps omitted):

```text
INFO uds listening path=/tmp/pms.sock
INFO websocket listening addr=127.0.0.1:9876
```

`--basket-path` makes the daemon capture every published envelope into a SQLite file, the basket. The planner reads results from it in step 5. Leave this terminal alone.

### 2. Write the worker

Install the Python thin client and the query tool, from the repository root:

```bash
pip install -e clients/pms-py-thin -e tools/pms-query
```

Save this as `worker.py`:

```python
# worker.py: attach under the name given, answer every job on jobs/new.
import sys
import pms

name = sys.argv[1] if len(sys.argv) > 1 else "worker"
mesh = pms.attach(name)


def answer(event):
    text = event.payload.decode("utf-8", errors="replace")
    result = f"{name}: {len(text.split())} words in job {event.envelope_id[:8]}"
    mesh.send("results", result.encode("utf-8"), type_name="job.done")
    print(result, flush=True)


mesh.on("jobs/new", answer)
print(f"{name}: attached, waiting for jobs", flush=True)
mesh.run()
```

The worker attaches to the daemon at `ws://127.0.0.1:9876` (or wherever `PMS_DAEMON` points), subscribes to `jobs/new`, and for each job publishes one result on `results` that names the job by the first eight characters of its envelope identifier.

### 3. Start two workers

In a second terminal:

```bash
python3 worker.py worker-1
```

```text
worker-1: attached, waiting for jobs
```

In a third terminal, the same with `worker-2`.

### 4. Publish a job

In a fourth terminal:

```bash
pms push jobs/new 'count the words in this job' --type-name job.new
```

The publisher prints the identifier the daemon gave the job:

```text
envelope_id=cb05c6b8f4b696551a0b7245b6f104a2
```

Both workers print a line, each with the same eight-character prefix:

```text
worker-1: 6 words in job cb05c6b8
```

```text
worker-2: 6 words in job cb05c6b8
```

Publish two more jobs with different sentences.

### 5. Read the results

```bash
pms-query rows --channel results --since 5min
```

```json
{
  "rows": [
    {
      "id": "…",
      "captured_at_unix_nanos": …,
      "channel": "results",
      "envelope_type": 0,
      "type_name": "job.done",
      "origin": "worker-2@…",
      "payload_hash": "…"
    },
    …
  ],
  "next_before": null
}
```

Six rows: two per job. Rows carry the result's identifier, origin and hash, not its text; fetch one result's text by its `id`:

```bash
pms-query get <id> | python3 -c 'import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)["payload_b64"]).decode())'
```

```text
worker-2: 6 words in job cb05c6b8
```

## Check it worked

| Check | Command | Pass |
|---|---|---|
| Every job was answered by every worker | `pms-query rows --channel results --since 5min` | Two rows per job you published, one per worker name in `origin` |
| Each result names its job | Decode one result's payload as in step 5 | The eight characters after `job` match the start of an `envelope_id` that `pms push` (or `mesh_send`) printed |
| The daemon kept the jobs too | `pms-query rows --channel jobs/new --since 5min` | One row per job, `type_name` `job.new` |

If `rows` is empty, the daemon was started without `--basket-path`, or `pms-query` is reading a different file: it uses `PMS_BASKET_DB`, else `~/.local/share/pms/basket.db`. If a worker prints nothing when you publish, it is attached to a different daemon: both read `PMS_DAEMON`, and the daemon's log names its WebSocket address.

## What happened

- **Broadcast is the default.** The daemon delivers each envelope to every subscriber attached at that moment. That is why two workers give two answers. To split work instead of duplicating it, give each worker its own channel (`jobs/worker-1`), or let workers claim jobs by publishing a claim before the answer. The daemon does not assign a job to exactly one worker.
- **Identifiers are hashes.** The envelope identifier `pms push` printed is the BLAKE3 hash of the job's canonical bytes. The same job content gives the same identifier everywhere, so a result that names it can be checked against the job without trusting the worker.
- **The planner reads the record, not the stream.** The MCP server publishes and queries; it has no tool that waits for events. Live listening is for programs, through the thin clients or the Rust client. The basket is the planner's view of what happened, and `mesh_query` rows carry identifiers, origins and hashes; payload text comes from `pms-query get`.
- **Nothing is kept for a worker that was not attached.** A job published before a worker starts is not delivered to it later. The basket still records it.

What the daemon does not do on its defaults: it authenticates no client and encrypts nothing, so keep it on loopback, which is its default, and remember that its WebSocket there is open to every user of the machine. Its optional TLS and key-proof attach ([Trust boundaries](../explanation/trust-boundaries.md)) need a client that proves a key, which today is the Rust client alone, so the Python workers here attach by name; and no layer authorises per channel; `mesh_health` reports which names are attached, not whether they are alive.

## Make it yours

- **More workers:** start `worker-3`; every job now gets three answers.
- **Specialists:** change the worker to subscribe to `jobs/<name>` and publish to `jobs/worker-1` from the planner. Each worker then sees only its own jobs.
- **Another language:** the Node thin client has the same `attach`, `on`, `send` and `run`; the Rust client in `mesh/mesh-client` has the same shape. [Two programs talk through the daemon](two-programs.md) shows a Node subscriber and a Python publisher side by side.
- **Replay a day's jobs:** `mesh_replay` republishes a captured channel, so a new worker can be tested against yesterday's jobs. It reaches live subscribers too, so run it against a daemon of its own.

## Next

- [Two programs talk through the daemon](two-programs.md): the same exchange from the command line, from Rust, and from Python and Node.
- [Capture envelopes and query them](../guides/capture-and-query.md): the basket's filters, aggregations and retention.
- [The MCP tools](../reference/mcp-tools.md): every tool's input and output.
- [Trust boundaries](../explanation/trust-boundaries.md): what the daemon protects, and what it leaves to the deployment around it.

## Spoken walkthrough

*A script for the video and audio version of this page, about ninety seconds.*

Here's a planner and two workers on one machine, talking through one daemon.

First, the daemon. We start it with a basket, which means it keeps a record of every message in a small database file. That record is how the planner will read results.

Next, the workers. Each one is fifteen lines of Python. It attaches to the daemon by name, subscribes to the jobs channel, and for every job it receives, it counts the words and publishes a result. The result names the job by the first eight characters of the job's identifier.

Now the planner publishes a job. Watch both workers: each prints an answer, and each answer carries the same eight characters. That identifier is a hash of the job's content, so the planner can check that a result belongs to a job without trusting the worker that sent it.

Finally the planner reads the results from the basket: two per job, one from each worker.

One thing to notice. Both workers answered, because the daemon broadcasts: every subscriber gets every message. If you want each job done once, give each worker its own channel. That's the whole example. The code on the page is everything you saw.
