# Run the daemon as a service

<p class="pm-kind"><b>How-to guide</b> · for anyone keeping `mesh-hub` running for other processes on a machine</p>

`mesh-hub` runs in the foreground and stops on SIGINT or SIGTERM; a process supervisor keeps it up. Install the binary first ([Install pms outside the workspace](install-pms.md)).

## 1. Choose the flags

| Flag | Default | Use |
|---|---|---|
| `--hub-name` | `default_hub` | Names the shared-memory objects `/pms-<hub>` and `/pms-<hub>-envelopes`; at most 15 characters of letters, digits, `_`, `.` and `-`. One name per daemon on a host. |
| `--uds-path` | `/tmp/pms.sock` | The Unix socket, created with owner-only permissions. |
| `--ws-bind` | `127.0.0.1:9876` | The WebSocket address. On loopback it is plaintext and any user of the host can connect; an address off loopback is refused without TLS and attach keys, unless `--ws-allow-remote`. |
| `--ws-tls-cert`, `--ws-tls-key` | none | Serve the WebSocket as `wss://`, TLS 1.3 with this certificate chain and key. |
| `--attach-keys`, `--attach-keys-uds` | none, off | A file of Ed25519 public keys a WebSocket client must prove one of at attach; with `--attach-keys-uds`, the Unix socket's clients too. Only the Rust client proves a key today. |
| `--no-uds`, `--no-ws` | off | Disable one transport. |
| `--basket-path` | none | Capture every published envelope to a SQLite file for [structured queries](capture-and-query.md). |
| `--ping-interval-secs`, `--idle-timeout-secs`, `--write-timeout-secs`, `--handshake-timeout-secs`, `--max-message-bytes`, `--subscriber-queue` | 30, 90, 10, 5, 1048576, 1024 | The per-connection policy; the [generated reference](../reference/daemon-reference.md) lists each. |
| `--max-subscriptions`, `--max-connections` | 64, 256 | Subscriptions one connection may hold, and connections the daemon holds across both transports. Beyond either the request is refused with `limit_exceeded`; a refused connection is closed, a WebSocket upgrade past the cap is answered 503, and the exit log counts `connections_refused`. |

Logging goes to standard error and is controlled by `MESH_HUB_LOG` (for example `info,mesh_hub=debug`).

## 2. macOS: launchd

Save as `~/Library/LaunchAgents/org.sovfound.mesh-hub.plist`, then `launchctl load` it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.sovfound.mesh-hub</string>
  <key>ProgramArguments</key><array>
    <string>/Users/you/.cargo/bin/mesh-hub</string>
    <string>--hub-name</string><string>default_hub</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>MESH_HUB_LOG</key><string>info</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Users/you/Library/Logs/mesh-hub.log</string>
</dict></plist>
```

## 3. Linux: systemd

Save as `~/.config/systemd/user/mesh-hub.service`, then `systemctl --user enable --now mesh-hub`:

```ini
[Unit]
Description=Pulse Mesh daemon

[Service]
ExecStart=%h/.cargo/bin/mesh-hub --hub-name default_hub
Environment=MESH_HUB_LOG=info
Restart=on-failure

[Install]
WantedBy=default.target
```

## 4. Know what restarts cost

The shared-memory objects are unlinked when the daemon exits, so a restart begins with an empty ring and an empty store; the basket file, if any, persists. A daemon started while another is live on the same socket path refuses to start and says so; a socket file left by a daemon that was killed is reclaimed. Clients reconnect on their own terms: the Rust client's `wait()` returns `Disconnected`, and a subscriber re-attaches and re-subscribes.

On Linux the ring and the store live in the tmpfs behind `/dev/shm`, and the daemon reserves their pages when it creates them: about 17 MB per hub, a 256-slot store of 64 KiB entries plus the ring. Docker's default `/dev/shm` is 64 MB, room for three hubs; give a container more with `docker run --shm-size=256m`. Shared memory without room is refused when the daemon starts, with `could not reserve … bytes of shared memory` in the log, instead of a SIGBUS at the first page touched later; a store without room is logged and the daemon runs without persistence, so its send acknowledgements carry no `persisted` field.

## 5. Look at it

```bash
pms ring inspect default_hub
pms tap
```

The first reads the ring's header and its most recent slots; the second attaches and prints every event until you stop it.
