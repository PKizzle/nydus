# Failover and Upgrade (containerd-nydus v3)

The v3 snapshotter (`containerd-nydus`) is a **single binary**: nydusd runs in-process as a
library, so there is no separate nydusd process to babysit and no two-process handoff protocol.
"Failover" therefore means surviving a crash or restart of the snapshotter process itself —
running containers must keep their rootfs mounts working while the process bounces.

> Historical note: earlier releases paired the Go `containerd-nydus-grpc` with external `nydusd`
> child processes and used a dbs-snapshot/sendfd handoff between them. That design (and its
> `PUT /api/v1/nydusd/upgrade` endpoint) is gone; this document describes the in-process model.

## How failover works

1. When a nydus image is mounted with `recover_policy = "failover"`, the supervisor snapshots the
   daemon's state (`daemon.save()`), writes it atomically to
   `<root>/daemons/<slug>/upgrade.state`, and parks the mount's `/dev/fuse` descriptor in
   **systemd's file-descriptor store** via `sd_notify(FDSTORE=1, FDNAME=<slug>)`
   (`snapshotter/src/fdstore.rs`, `snapshotter/src/failover.rs`).
2. systemd — not the snapshotter — now co-owns the fd. If the snapshotter exits for any reason
   (upgrade, crash, `kill -9`, OOM), the kernel mount stays up and containers block on I/O
   instead of seeing `EIO`/`ENOTCONN`.
3. On the next start, systemd hands the stored fds back through the socket-activation protocol
   (`LISTEN_FDS`/`LISTEN_FDNAMES`). `DaemonSupervisor::restore_from_store` matches each fd to its
   persisted `upgrade.state` + daemon record, restores the in-process daemon around the live fd,
   and containers resume without a remount.

Every state file involved (`upgrade.state`, the per-daemon records under
`<root>/daemons/records/`, the tarfs verity sidecars) is written via temp-file + fsync + rename,
so a crash mid-write can never leave a truncated record that silently disables takeover.

## Requirements

### Snapshotter config

```toml
[snapshotter.daemon]
# "none", "restart", or "failover" (the default).
recover_policy = "failover"
```

### systemd unit

Failover only works under a `Type=notify` unit with a file-descriptor store. The load-bearing
directives (see the full unit in your deployment repo, or `misc/performance/nydus-snapshotter.service`):

```ini
[Service]
Type=notify
NotifyAccess=main
# One fd per concurrently mounted nydus image; 128 is generous headroom.
FileDescriptorStoreMax=128
# Keep stored fds across restarts (systemd >= 254 defaults to this for Type=notify).
# FileDescriptorStorePreserve=restart
Restart=always
KillMode=process
```

Without a notify socket (`NOTIFY_SOCKET` unset — e.g. running by hand), the snapshotter logs
that the fd store is unavailable and degrades gracefully: mounts still work, they just do not
survive a snapshotter restart.

## Upgrading the snapshotter binary

Because nydusd is in-process, upgrading nydusd **is** upgrading the snapshotter:

1. Install the new `containerd-nydus` binary.
2. `systemctl restart nydus-snapshotter`.

With the fd store armed, running containers keep their mounts across the restart; the new binary
adopts them via `restore_from_store`. This replaces the old "hot upgrade nydusd" flow entirely.

## Replacing live daemons via the API

The sysctl API (default socket `/run/containerd-nydus/containerd-nydus-api.sock`) exposes a
daemon-replacement endpoint, useful after changing backend/cache configuration:

```
POST /api/v1/daemons/upgrade          # all daemons
POST /api/v1/daemons/<id>/upgrade     # one daemon (slug or image ref)
```

Request body (optional):

```json
{ "allow_active": false }
```

Daemons whose snapshots are still referenced by running containers are **skipped** unless
`allow_active` is set — replacing an active daemon tears its mount down briefly, so it is opt-in.
The response reports `attempted`/`upgraded`/`skipped`/`failed` per daemon.

## Verifying

- `containerd-nydus healthcheck --ready --socket <sysctl socket>` — snapshotter up and serving.
- `curl --unix-socket <sysctl socket> http://localhost/api/v1/daemons/records` — per-daemon
  records, including whether failover is armed (`live`, `pid`).
- Kill test on a node: `systemctl kill -s KILL nydus-snapshotter`, then confirm a running
  container's rootfs is still readable and `journalctl -u nydus-snapshotter` shows
  `resumed nydus daemons from preserved fuse descriptors` after the restart.
- CI: the takeover smoke test (`.github/workflows/smoke.yml`, `takeover-test`) exercises the
  full kill/adopt loop with `recover_policy = "failover"` on every PR.
