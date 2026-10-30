# Inspect and clean shared memory

<p class="pm-kind"><b>How-to guide</b> · for anyone who wants to see what is in a ring, or to remove what a crashed daemon left behind</p>

## Read a ring

```bash
pms ring inspect default_hub
pms ring inspect default_hub --count 16 --json
```

A hub name resolves to the daemon's ring, `/pms-default_hub`; a raw shared-memory name, one starting with `/`, is read as given. Either way the ring's own header supplies its capacity and slot size, so nothing else is asked for:

```bash
pms ring inspect /pms-example-4242
```

The output is the ring's name, its capacity, the total number of writes and the cursor, then the most recent slots with their instruction, their clock reading and whether they reference an envelope. `inspect` attaches as a second reader and moves nothing; a slot whose writer died mid-write reads as absent until the next publish into it.

## The same from an agent

The MCP tools `mesh_list_rings` and `mesh_ring_peek` list the `/pms-*` objects (on Linux, where `/dev/shm` can be listed) and read a ring by hub name or raw name with the same two forms.

## Clean up

A daemon unlinks its objects when it exits cleanly. After a crash or a kill, on Linux the objects stay under `/dev/shm`:

```bash
ls /dev/shm/pms-*
just clean            # cargo clean, then removes /dev/shm/pms-* owned by you
```

On macOS shared-memory objects have no directory; they persist until a process unlinks them or the host reboots. A daemon started under the same hub name unlinks what it finds before creating its own ring and store, and its log names each object it replaced, so the way to clear a leftover on macOS is to start and stop a daemon with that hub name.

## A stale socket

`/tmp/pms.sock` left by a killed daemon is reclaimed by the next daemon on that path, which probes it first; a socket that answers is another live daemon and the new one refuses to start.
