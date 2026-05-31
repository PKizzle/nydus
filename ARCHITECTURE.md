# Nydus Architecture

> **Version:** 3.0 (Rust snapshotter rewrite)
> **Last updated:** 2026-05-26
> **Status:** Implementation in progress

## Overview

Nydus is a high-performance container image service that implements a content-addressable filesystem on the RAFS format. It enhances the OCI image specification with on-demand loading, chunk-level deduplication, and improved container startup performance.

Starting with v3.0, the **containerd remote snapshotter** (formerly a separate Go project at `containerd/nydus-snapshotter`) has been rewritten in Rust and merged into this repository as the `snapshotter/` crate. The snapshotter and nydusd daemon now ship as a **single binary** (`containerd-nydus`), with nydus-service linked in-process rather than spawned as a child process.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                  containerd-nydus  (single Rust binary)              │
│                                                                      │
│  ┌────────────────────┐   ┌────────────────────────────────────────┐ │
│  │ proxy-plugin gRPC  │   │           Daemon Supervisor            │ │
│  │ (containerd-       │   │  (in-process, async, state machine)    │ │
│  │  snapshots crate)  │   └──────────┬─────────────────────────────┘ │
│  └─────────┬──────────┘              │ spawns tasks, not processes   │
│            │                         ▼                               │
│  ┌─────────▼──────────┐   ┌────────────────────────────────────────┐ │
│  │  Snapshot Engine   │   │   nydus-service (linked library)       │ │
│  │  (overlayfs / blk) │   │  ┌────────────┐  ┌──────────────────┐  │ │
│  │  + sqlx metadata   │   │  │  fusedev   │  │ fanotify backend │  │ │
│  └─────────┬──────────┘   │  │  (fallback)│  │ (default ≥6.14)  │  │ │
│            │              │  └────────────┘  └──────────────────┘  │ │
│            ▼              │  blob_cache, block_device, singleton   │ │
│  ┌────────────────────┐   └────────────────────────────────────────┘ │
│  │ Backend Negotiator │  picks fanotify → fusedev → blockdev path    │
│  └────────────────────┘  via runtime capability probe                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Pluggable image sources: referrer · encryption · OCI blockdev  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Sidecar NRI plugins (optional, separate small binaries):            │
│   - nydus-optimizer (record access traces)                           │
│   - nydus-prefetch  (replay traces)                                  │
└──────────────────────────────────────────────────────────────────────┘
```

## Key Architectural Decisions

### 1. Single Binary, In-Process nydusd

The snapshotter links `nydus-service` as a library crate. `FsService`, `FanotifyHandler`, `FuseServer`, and `BlockDevice` are driven directly via Rust APIs — no `os/exec`, no PID tracking, no apisock juggling, no supervisor races. This eliminates the entire `pkg/daemon/command` shim from the Go snapshotter.

### 2. Backend Negotiator with Automatic Fallback

At startup, the **capability probe** (`snapshotter/src/probe/`) checks:
- Kernel version (fanotify requires ≥ 6.14)
- `FAN_CLASS_PRE_CONTENT` support (try `fanotify_init` + close)
- EROFS module availability (`/proc/filesystems`)
- FUSE module availability (`/dev/fuse`)
- Linux capabilities (`CAP_SYS_ADMIN` etc.)
- cgroup v2 delegation

The ordered `[[snapshotter.fs_drivers]]` list in the config declares the fallback chain. The first driver that passes the probe becomes the default. Per-image override is possible via the `containerd.io/snapshot/nydus-fs-driver` label.

**Fallback chain (default):**
```
fanotify (≥6.14, CAP_SYS_ADMIN) → fusedev (/dev/fuse) → blockdev (loop/NBD/uffd)
```

### 3. Async Core on Tokio

- gRPC server: `tonic` on a multi-thread tokio runtime
- FUSE/fanotify I/O: current-thread tokio runtime (required for io-uring compatibility)
- Metadata store: `sqlx` + SQLite with WAL mode (replaces bbolt)

### 4. Typed Errors and Self-Healing

Errors implement the `Recoverable` trait with four classifications:
- **Transient**: retry with exponential backoff (e.g. network timeout)
- **RecreatableMount**: re-mount on next access (e.g. stale FUSE fd)
- **NeedsFallback**: downgrade filesystem driver (e.g. fanotify → fusedev)
- **Fatal**: cannot recover automatically (e.g. corrupt bootstrap)

A **reconciler loop** (`snapshotter/src/recon/`) scans the snapshot DB periodically and repairs drift: orphan mounts, dead instances, stale sockets, partial commits.

### 5. Hot Upgrade via FD Passing

The single binary `exec()`s itself for hot upgrade, passing file descriptors (FUSE fd, fanotify fd, listener sockets) via `SCM_RIGHTS`. The `upgrade/` crate's state machine is reused.

### 6. Unified TOML Configuration

A single `/etc/nydus/config.toml` replaces the former separate snapshotter TOML + nydusd JSON pair. All storage backends are declared inline under `[backends.*]` sections. The fscache driver has been **removed entirely**.

### 7. Node-Local Acceleration (transparent, no tag change)

Standard OCI images are accelerated **on the node**, with no registry artifact and no tag change.
A gzip layer's OCI digest is exactly the nydus zran data-blob id and the containerd content-store
key, so the snapshotter converts the already-present gzip layers in place
(`snapshotter/src/local_accel.rs`: `nydus-image create --type targz-ref` per layer + `merge`),
producing only a merged bootstrap and tiny per-layer zran index blobs. The result is served through
the fanotify path with a `localfs` backend over the content store — gzip ranges are decompressed
lazily into the cache, so the container starts before the image is fully materialised. The win is
against containerd's full-layer *extraction*, not download (spegel already makes download P2P-fast).
The alternative referrer/tag-suffix approach was rejected: it changes the tag and the snapshotter
never consults referrers.

## Crate Layout

```
nydus/
├── api/              # Nydus API types and HTTP handlers
├── builder/          # Image building and conversion
├── rafs/             # RAFS filesystem implementation
├── service/          # Daemon and service management (linked in-process)
│   ├── src/fanotify.rs     # Fanotify pre-content handler (Linux ≥ 6.14)
│   ├── src/fusedev.rs      # FUSE daemon
│   ├── src/block_device.rs # Block device (NBD/loop/uffd)
│   ├── src/blob_cache.rs   # Blob cache manager
│   └── src/singleton.rs    # Singleton daemon controller
├── snapshotter/      # ★ NEW: Containerd remote snapshotter (Rust rewrite)
│   ├── src/
│   │   ├── bin/
│   │   │   ├── containerd-nydus.rs   # Main binary
│   │   │   └── nydus-migrate.rs     # Config migration tool
│   │   ├── config/    # Unified TOML config
│   │   ├── daemon/    # In-process daemon supervisor
│   │   ├── grpc/      # containerd proxy-plugin server
│   │   ├── overlay/   # Overlay filesystem engine
│   │   ├── probe/     # Kernel capability probe
│   │   ├── recon/     # Reconciler loop
│   │   ├── source/    # Image source detection (referrer, encryption)
│   │   └── store/     # SQLite snapshot metadata store
│   └── Cargo.toml
├── storage/          # Core storage subsystem
├── utils/            # Common utilities
└── upgrade/          # Hot upgrade state machine
```

## Data Flow

### Image Pull (fanotify path)

```
containerd ──gRPC──▶ NydusSnapshotter::prepare()
                          │
                    ┌─────▼──────┐
                    │ Probe      │  Is fanotify available?
                    │ (cached)   │
                    └─────┬──────┘
                          │ Yes
                    ┌─────▼──────────┐
                    │ Overlay Engine │  Create overlay dirs
                    │ + Snapshot DB  │  Record in SQLite
                    └─────┬──────────┘
                          │
                    ┌─────▼─────────────┐
                    │ Daemon Supervisor │  Ensure FanotifyHandler
                    │ (in-process)      │  for this image
                    └─────┬─────────────┘
                          │
                    ┌─────▼───────────┐
                    │ FanotifyHandler │  Mount EROFS, serve chunks
                    │ (nydus-service) │  via FAN_PRE_ACCESS
                    └─────────────────┘
```

The `FanotifyHandler` is self-contained: given a bootstrap + blob-cache config it self-stages the
EROFS device files (hardlinks to each data blob's `.blob.data` cache file, the same inode the kernel
reads), arms `FAN_PRE_ACCESS` marks **after** its workers are draining, and mounts EROFS with the
bootstrap as source and the data blobs as `device=` options. See the *fanotify on-demand* gotchas in
[CLAUDE.md](./CLAUDE.md) and the integration tests in `misc/fanotify/`.

### Node-Local Acceleration (standard OCI image)

Same fanotify serving path, but the snapshotter first converts the pulled gzip layers locally
(`local_accel::convert` → bootstrap + zran index blobs) and points the `localfs` backend at the
content store. No registry push, no tag change — see *Decision 7* above.

### Image Pull (fusedev fallback)

Same flow, but `FanotifyHandler` is replaced by `FusedevDaemon` and the mount is a FUSE mount instead of EROFS.

## Daemon Instance State Machine

```
Init ──▶ Probing ──▶ Ready ──▶ Serving ──▶ Upgrading ──▶ Serving
                         │         │                         │
                         │         │ (crash)                 │ (success)
                         │         ▼                         │
                         │     Failed ──▶ (restart/failover) │
                         │         │                         │
                         └─────────┘                         │
                                                             ▼
                                                          Stopped
```

## Persistence Schema (SQLite)

```sql
CREATE TABLE snapshots (
    key          TEXT PRIMARY KEY,
    parent      TEXT,
    kind        TEXT NOT NULL CHECK(kind IN ('kind_active', 'kind_committed', 'kind_prepared')),
    fs_driver   TEXT NOT NULL DEFAULT 'fusedev',
    image_ref   TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE labels (
    snapshot_key TEXT NOT NULL,
    label_key   TEXT NOT NULL,
    label_value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_key, label_key),
    FOREIGN KEY (snapshot_key) REFERENCES snapshots(key) ON DELETE CASCADE
);
```

## Security Model

- **Capabilities**: The snapshotter binary requires `CAP_SYS_ADMIN` for fanotify and mount operations. Fusedev-only mode requires only `/dev/fuse` access.
- **Credential management**: Registry auth is passed via environment variables (`IMAGE_PULL_AUTH`) and never written to disk.
- **Seccomp**: The binary is compatible with the default containerd seccomp profile.
- **cgroup v2**: Resource limits are applied per-namespace when `[snapshotter.cgroup]` is enabled.

## Breaking Changes (v3.0)

1. **fscache driver removed** — All `FsDriverFscache`, `nydusd-config.fscache.json`, `--fscache*` flags, and `fscache.*` annotations are gone. Hosts must use fanotify (≥6.14) or fusedev.
2. **Binary renamed** — `containerd-nydus-grpc` → `containerd-nydus`.
3. **Config merged** — Separate `nydusd-config.*.json` eliminated; `daemon_cfg_path` removed.
4. **Metadata store** — bbolt → SQLite; migration tool required.
5. **containerd v1.x dropped** — Only v2.x proxy-plugin API supported.
6. **Daemon modes simplified** — `multiple` alias removed; `none` retained for blockdev.
7. **API v2** — `/api/v1/daemons` → `/api/v2/instances`; `pid`/`apisock` fields replaced by `instance_id`/`fs_driver`/`state`.
8. **`nydus-overlayfs` removed** — Overlay logic is now a library call.
9. **EROFS mount options** — Always include `device=...` fanotify-style descriptors.

## Out of Scope (v1.0)

- tarfs driver (planned for v3.1)
- stargz adaptor
- Dragonfly P2P mirror integration
- Windows/macOS support
- nydusify rewrite (remains Go)