# Capture envelopes and query them

<p class="pm-kind"><b>How-to guide</b> · for anyone who wants to ask a running mesh what went through it, without watching a live stream</p>

The daemon can capture every published envelope into a SQLite file, the basket, and three tools query it: the `pms-query` command, the MCP `mesh_query` tool, and any SQLite client, because the schema is one table.

## 1. Start the daemon with a basket

```bash
mesh-hub --basket-path ~/.local/share/pms/basket.db
```

or `pms start --basket-path <file>`. A retention sweep runs every 60 seconds (`--basket-retention-secs`) and keeps the file to 100 MB or 24 hours of envelopes, whichever is smaller.

The daemon writes the basket on a thread of its own, so a send never waits for SQLite. Captures wait for that thread in a queue of 1,024 envelopes and 64 MiB of payload; when the disk falls that far behind, a capture is dropped, the envelope is still delivered, and the daemon logs the count at the first drop and at each doubling. Stopping the daemon writes every capture still queued.

## 2. Query from the command line

`pms-query` is a small Python package under `tools/pms-query`; install it with `pip install -e tools/pms-query`. It reads the file at `PMS_BASKET_DB` or `~/.local/share/pms/basket.db` unless `--db` says otherwise.

```bash
pms-query rows --channel 'jobs/*' --since 5min --limit 20
pms-query rows --aggregate count-by-channel --since 1h
pms-query rows --aggregate time-bucket --bucket-secs 60 --since 1h
pms-query rows --origin 'worker@3f9a' --type-name event.fired
pms-query get cb05c6b8f4b696551a0b7245b6f104a2
```

`rows` takes filters that AND-combine, `--channel`, `--type-id`, `--type-name`, `--origin`, `--since` and `--until` (durations such as `5min`, `1h`, `1d`), and `--limit` (50 by default). `--aggregate` is one of `count`, `count-by-channel`, `distinct-channels`, `distinct-types` and `time-bucket` (with `--bucket-secs`). Output is JSON: rows with the envelope id, capture time, channel, type, origin and payload hash, or the aggregate, plus `next_before` for paging. `get` fetches one envelope by identifier with its payload base64-encoded.

## 3. Query from an agent

The MCP server's `mesh_query` tool takes the same filters and aggregations and answers with the same rows; `mesh_replay` republishes a captured range. See [Use the MCP server from an agent](mcp-with-an-agent.md).

## 4. Query with SQLite

One table, `envelopes`, with the columns `id`, `captured_at_unix_nanos`, `channel`, `envelope_type`, `type_name`, `origin`, `payload_hash` and `payload_bytes`. `sqlite3 basket.db 'select channel, count(*) from envelopes group by channel'` is a valid query. The `mesh-basket` crate owns the schema; the Python tool's tests assert the column list.

## Who can read the basket

Every row holds the whole envelope as it was published, payload included, until the retention sweep drops it, so the basket is created for the daemon's user alone, as its Unix socket is: the file and the `-wal`, `-shm` and `-journal` files SQLite keeps beside it are mode `0600`, and a directory the daemon creates for it is `0700`. A basket that an earlier version left readable by others is narrowed to its owner when the daemon next opens it, its rows kept.

A directory that exists already is left as it is: the files' own mode keeps their contents to their owner, and the directory's says who can see their names. To keep an existing location private, give the basket a directory only the daemon's user can enter (`chmod 700` on it), and check the files with `ls -l`; `chmod 600 basket.db*` narrows any that are open to others.

## What the basket is not

It is not the envelope store: the store is shared memory beside the ring, holds one copy per distinct envelope, and is unlinked when the daemon exits; the basket is a file, holds one row per publication, and persists. A Pulse's `envelope_ref` resolves against the store, never the basket.
