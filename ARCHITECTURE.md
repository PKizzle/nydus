# Nydus Architecture

> **Version:** 3.0 (Rust snapshotter rewrite)
> **Last updated:** 2026-07-09
> **Status:** Implementation in progress

## Overview

Nydus is a high-performance container image service that implements a content-addressable filesystem on the RAFS format. It enhances the OCI image specification with on-demand loading, chunk-level deduplication, and improved container startup performance.

Starting with v3.0, the **containerd remote snapshotter** (formerly a separate Go project at `containerd/nydus-snapshotter`) has been rewritten in Rust and merged into this repository as the `snapshotter/` crate. The snapshotter and nydusd daemon now ship as a **single binary** (`containerd-nydus`), with nydus-service linked in-process rather than spawned as a child process.

> To run it on a stock containerd host, see [docs/quickstart-containerd.md](./docs/quickstart-containerd.md).

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
│  │  + fjall metadata  │   │  │  fusedev   │  │ fanotify backend │  │ │
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

### 3. Async Core on compio (io_uring)

- **Snapshotter process**: the `containerd-nydus` binary runs on **compio** (`#[compio::main]`, a
  thread-per-core io_uring runtime — see `snapshotter/src/bin/containerd-nydus.rs`). mimalloc is the
  global allocator to cut compio's owned-buffer-per-op allocation overhead.
- **gRPC / HTTP server**: the containerd proxy-plugin `Snapshots` service and the standard
  `grpc.health.v1.Health` service are served by **cyper-axum** (hyper-on-compio) over a `tonic`
  `Routes` router — no tokio runtime, no second transport (`snapshotter/src/grpc/mod.rs`). The same
  hyper-on-compio server backs the sysctl UDS admin API (`snapshotter/src/sysctl.rs`).
- **In-process nydus-service (FUSE/fanotify) I/O**: still uses a **current-thread tokio** runtime,
  required for the FUSE/fanotify io-uring event loop (see CLAUDE.md gotcha #1). This is the
  `service/` crate linked in-process; only the FUSE/fanotify session thread is tokio, and it must
  never be handed a multi-thread tokio handle.
- **Metadata store**: **fjall** — an embedded LSM key/value store — one serialized snapshot record
  per key (`snapshotter/src/store/mod.rs`, on-disk dir `metadata.fjall`). Replaces the Go
  snapshotter's bbolt `MetaStore`; there is no SQL/relational schema and no SQLite. The journal is
  persisted with `PersistMode::SyncAll` on every mutation, and the binary calls `persist_now()` once
  more on graceful shutdown so an in-flight batch survives a `kill -9` on the failover path.

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

A single `/etc/nydus/config.toml` replaces the former separate snapshotter TOML + nydusd JSON pair.
All storage backends are declared inline under `[backends.*]` sections. The fscache driver has been
**removed entirely**.

**Deployment profiles.** `[snapshotter].profile` is `auto` | `k3s` | `containerd`. Resolution is
purely **in memory** (`SnapshotterConfig::resolve_profile`, `snapshotter/src/config/mod.rs`); it
never rewrites the config file. `auto` probes the well-known containerd sockets
(`/run/k3s/containerd/containerd.sock` → k3s, `/run/containerd/containerd.sock` → stock; an
ambiguous match is an error). The resolved profile fills only the fields the operator left unset —
the containerd socket + content-store root (`[snapshotter.containerd]`) and the peer-mirror preset.
**Explicit TOML values always win.**

**Storage backends.** `[backends.registry|s3|oss|http_proxy]` are wired into the in-process daemon
config (`snapshotter/src/daemon/config_builder.rs`); s3/oss/http_proxy were previously parsed but
silently ignored. `config.validate()` now **rejects** unwired or ambiguous backend configuration
(e.g. more than one pull backend, or an orphan `[backends.localfs]`, which is reserved for the
auto-accel sidecar path) instead of ignoring it.

**Peer mirror.** `[snapshotter.peer_mirror]` (serde alias `spegel_mirror` kept for back-compat) is
mirror-agnostic. It selects a `preset` (`k3s-spegel` | `spegel` | `none`), a `query_template` for
the mirror's `?ns=<registry>` parameter, and a `peer_discovery` mode. Spegel is the *reference*
preset, not a hardcoded assumption. Kubernetes peer-discovery defaults **off** except under the
`k3s-spegel` preset, where it is a documented workaround for the k3s-bundled Spegel `v0.4.0-k3s3`
DHT rot (removable once k3s ships Spegel ≥ v0.7.1 — tracked in BACKLOG.md).

**Environment overrides.** `containerd-nydus` reads `NYDUS_SNAPSHOTTER_{CONFIG,ADDRESS,ROOT,LOG_LEVEL,PROFILE}`
so the binary is configurable in a container with no mounted config file (clap precedence: explicit
flag > env var > TOML field > default). A Helm chart exposes `profile` and `peer_mirror`.

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

### 8. Referrer Detection (detection-only, default-off)

The snapshotter can detect *published* nydus images (the OCI-referrer distribution model nydusify /
the Go snapshotter produce) via the OCI referrers API, gated behind `[snapshotter.features].referrer_detect`
(**default off**, `snapshotter/src/source/referrer.rs`). When enabled it **only logs** that a
published nydus image was detected during `Prepare` and falls through to plain overlay — it does not
yet fetch the bootstrap or mount a daemon. Serving is deferred to backlog item **B4b** (see
[BACKLOG.md](./BACKLOG.md)). Note this is orthogonal to *transparent* node-local acceleration
(Decision 7), which never consults referrers.

### 9. Observability

- **Prometheus metrics**: always served over the sysctl UDS at `GET /metrics`; `[snapshotter.metrics].listen`
  (e.g. `"127.0.0.1:9110"`) additionally binds a TCP `GET /metrics` endpoint reusing the same
  renderer (`snapshotter/src/metrics.rs`, `grpc/mod.rs`), restoring parity with the Go snapshotter.
- **gRPC health**: the standard `grpc.health.v1.Health` service rides the same cyper-axum server as
  the `Snapshots` service, so containerd's proxy-plugin dialer and `grpc_health_probe` can check
  readiness (`snapshotter/src/grpc/mod.rs`).
- **Allocator / process-memory stats**: `GET /debug/allocator` on the sysctl UDS
  (`snapshotter/src/sysctl.rs`). See [docs/operations.md](./docs/operations.md) for the ops runbook
  (memory stats, CPU profiling with perf/samply).

### 10. Containerd Contract Fidelity

The proxy-plugin server honors the full containerd snapshotter contract: `Update` respects
field-masks, `List` respects Walk filters, and the `Cleanup` RPC is wired through `clear()` into the
reconciler (`snapshotter/src/grpc/mod.rs`).

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
│   │   └── store/     # fjall (LSM) snapshot metadata store (metadata.fjall)
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
                    │ + Snapshot DB  │  Record in fjall store
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

## Persistence Model (fjall)

There is **no relational schema** — the snapshot store is an embedded **fjall** LSM key/value store
(`snapshotter/src/store/mod.rs`, on-disk directory `metadata.fjall`), mirroring the bucket-shaped
model of the Go snapshotter's bbolt `MetaStore`. One serialized `SnapshotInfo` record is stored per
snapshot key in the `snapshots` keyspace; keys are iterated lexicographically for `list()`. Each
record carries the snapshot key, parent, kind (active/committed/prepared/view), fs driver, image
ref, labels, and created/updated timestamps.

Durability: opened with `manual_journal_persist(true)` and every mutating call
(create/commit/remove/update/set_image_ref/import) ends with `persist(PersistMode::SyncAll)`; the
`containerd-nydus` binary also calls `persist_now()` on graceful shutdown so an in-flight batch is
not lost if systemd `kill -9`s the successor mid-failover. `max_journaling_size` is pinned to 64 MiB
(fjall's documented minimum) to bound recovery-replay time on low-power nodes (e.g. a Pi 4).

## Security Model

- **Capabilities**: The snapshotter binary requires `CAP_SYS_ADMIN` for fanotify and mount operations. Fusedev-only mode requires only `/dev/fuse` access.
- **Credential management**: Registry auth is held in a small **in-memory runtime auth store**
  (`snapshotter/src/daemon/auth.rs::resolve_auth`), populated at runtime via the sysctl HTTP API
  (`PUT /api/v1/auth`) — typically fed by the `nydus-credential-bridge` binary wrapping a kubelet
  credential-provider plugin. The store holds only the Docker-style base64 `auth` value (never raw
  username/password) and is never written to disk. There is no `IMAGE_PULL_AUTH` env var, and no CRI
  keychain proxying (explicit non-goal). See [docs/credentials.md](./docs/credentials.md).
- **Seccomp**: The binary is compatible with the default containerd seccomp profile.
- **cgroup v2**: Resource limits are applied per-namespace when `[snapshotter.cgroup]` is enabled.

## Breaking Changes (v3.0)

1. **fscache driver removed** — All `FsDriverFscache`, `nydusd-config.fscache.json`, `--fscache*` flags, and `fscache.*` annotations are gone. Hosts must use fanotify (≥6.14) or fusedev.
2. **Binary renamed** — `containerd-nydus-grpc` → `containerd-nydus`.
3. **Config merged** — Separate `nydusd-config.*.json` eliminated; `daemon_cfg_path` removed.
4. **Metadata store** — bbolt → fjall (embedded LSM key/value store, `metadata.fjall`); migration tool (`nydus-migrate`) required.
5. **containerd v1.x dropped** — Only v2.x proxy-plugin API supported.
6. **Daemon modes simplified** — `multiple` alias removed; `none` retained for blockdev.
7. **API v2** — `/api/v1/daemons` → `/api/v2/instances`; `pid`/`apisock` fields replaced by `instance_id`/`fs_driver`/`state`.
8. **`nydus-overlayfs` removed** — Overlay logic is now a library call.
9. **EROFS mount options** — Always include `device=...` fanotify-style descriptors.

## Out of Scope (v1.0)

- tarfs driver (planned for v3.1)
- stargz adaptor
- Dragonfly P2P mirror integration
- Windows/macOS support (runtime path is Linux-only; build/convert tooling compiles on macOS)

## In Scope (v1.0): Rust nydusify converter

The Rust rewrite of **nydusify** — the `nydusify/` crate ("Rust rewrite of the Nydus image
conversion utility") — **is in scope for v1.0 and is the converter tool going forward**, replacing
the Go `nydusify`. Its containerd-converter backend is currently a stub and completing it is
tracked work for v1.0. Note this is the registry-side OCI→Nydus **push/convert** tool and is
distinct from the node-local, push-free acceleration path (`snapshotter/src/local_accel.rs`),
which does not use nydusify; the two serve different flows (registry-published nydus images vs.
transparent node-local acceleration).