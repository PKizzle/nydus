# Nydus Architecture

> **Version:** 3.0 (Rust snapshotter rewrite)
> **Last updated:** 2026-07-12
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
- **In-process nydus-service (FUSE/fanotify) I/O**: has **zero tokio** (see CLAUDE.md gotcha #1).
  This is the `service/` crate, linked in-process. The fanotify event loop is `mio`-poll plus
  blocking libc reads on its own OS thread (`service/src/fanotify.rs`); FUSE runs synchronous
  `svc_loop` std threads (`service/src/fusedev.rs`); blob io_uring reads (`blob_cache.rs`) and the
  block-device (uffd/nbd) event loops run on **compio**, using `async-broadcast` + `futures-util`
  in place of tokio's `select!`/broadcast/time. `service/Cargo.toml` carries no tokio dependency at
  all. `nydus-storage`'s default build is likewise tokio-free — `tokio` is `optional = true`,
  gated behind the non-default `backend-dragonfly-proxy` feature (own tokio runtime for the
  Dragonfly SDK proxy path only). The one deliberately-spawned tokio runtime is the isolated
  2-worker runtime in `snapshotter/src/content_store.rs` that drives the tonic *client* to
  containerd's Content/Images gRPC (tonic transport pins its futures to a tokio reactor); it is
  quarantined behind `blocking::unblock` + `handle.block_on` and dropped on teardown, so it never
  runs on a nydusd session thread and compio still owns the snapshotter's event loop. Otherwise the
  `tokio` crate shows up in `cargo tree` for the `containerd-nydus` binary only because
  `h2`/`hyper`/`tonic`/`cyper-axum` pull it in for trait/type compatibility — nothing else spawns a
  runtime. Never hand any nydusd session thread a tokio runtime handle.
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
preset, not a hardcoded assumption. **`peer_discovery` defaults to `off` for every preset**,
including `k3s-spegel`: live cluster testing (k3s v1.36.2, Spegel v0.7.1-k3s1) verified native
libp2p peer routing works once Spegel is healthy (bootstrap 0.3–6s, cross-node resolves passing).
Setting `peer_discovery = "kubernetes"` re-enables the snapshotter's own Kubernetes-API node
fan-out as an explicit, **deprecated** opt-in resilience fallback (a startup `warn!` fires when
it's set) — kept only because a misconfigured or unhealthy Spegel instance (e.g. a
`registries.yaml` typo, or a Cilium XDP path degrading etcd) can silently stop advertising a node's
content, and the fan-out routed around that class of failure during the same testing. It is
scheduled for removal after a production soak of default-off.

**Peer-mirror self-check.** When peer_mirror is enabled, `PeerMirrorSelfCheck`
(`snapshotter/src/peer_mirror_selfcheck.rs`) periodically probes the *local* mirror endpoint for a
digest already known to be in the *local* content store. A miss (404) means the node's embedded
registry mirror is not advertising local content — the silent-failure class that caused the
`registries.yaml` typo incident — and is surfaced two ways: a loud, actionable log naming the
concrete causes (mirror config typo, node/etcd health) and the `snapshotter_peer_mirror_selfcheck_ok`
Prometheus gauge (0/1), so it is diagnosable and alertable instead of silently degrading to
full-image pulls.

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

### 8. Referrer Detection and Serving (default-on)

The snapshotter detects and **serves** *published* nydus images (the OCI-referrer distribution
model nydusify / the Go snapshotter produce) via the OCI referrers API, gated behind
`[snapshotter.features].referrer_detect` (**default on**, `snapshotter/src/source/referrer.rs`).
Serving (backlog item **B4b**) is implemented and e2e-verified: on detecting a published nydus
image during `Prepare`, the snapshotter fetches the referrer artifact manifest, resolves the
bootstrap blob digest (detection and materialization share one priority selector — the
`nydus-bootstrap` annotation first, then the bootstrap media type — so a data blob can never be
mistaken for the bootstrap; a manifest with nydus blobs but no identifiable bootstrap classifies
as standard OCI and falls through safely), downloads and digest-verifies the bootstrap, then
mounts it via `DaemonSupervisor::ensure_instance` — including full registry-backend serving of the
data blobs.
Every failure in that path falls through to a plain overlay mount, so referrer resolution never
blocks a pod. Note this is orthogonal to *transparent* node-local acceleration (Decision 7), which
never consults referrers. The push side of the loop is the Rust `nydusify convert --with-referrer`
(see "In Scope (v1.0): Rust nydusify converter" below) — it publishes exactly the artifact shape
this section consumes.

### 9. Auto-Accel Timing (Two-Stage Conversion)

Node-local acceleration (Decision 7) never delays the pod that triggers it, and the window during
which peers see `NotFound` (and fall back to a plain, full-layer overlay pull) is bounded to
roughly one conversion, not one conversion *plus* a settle timer:

1. **First `prepare` for an eligible image**: `prepare()` is a linear fall-through
   (`snapshotter/src/grpc/mod.rs`) — if no sidecar exists yet, the pod gets a plain overlay mount
   immediately. The only auto-accel action is a non-blocking access-tracer attach
   (`AccessTracer::attach`). Nothing here blocks pod start.
2. **Base conversion, enqueued immediately** (`AutoZranStage::Base`): the same `prepare` call
   enqueues a base conversion job with an *empty* prefetch list (channel push only). A background
   worker thread (nice-19 / idle `SchedClass`, `snapshotter/src/auto_zran.rs`) runs
   `nydus-image create --type targz-ref` + `merge` with no access profile — `local_accel::convert`
   with empty `prefetch_files` produces a fully servable artifact (the optimize step is skipped).
   As soon as this lands, the sidecar Image record is created/updated
   (`images_upsert`) and peers can fetch it — the peer-visible window shrinks to ≈ the base
   conversion's duration alone, not conversion + tracer settle.
3. **Access tracing continues in parallel**: the fanotify `FAN_CLASS_NOTIF` tracer
   (`snapshotter/src/access_tracer.rs`) records first-access file order for the running container
   (order-preserving, `settle_idle` / `settle_max` bounded). A second source — the NRI optimizer
   plugin (`snapshotter/src/nri.rs`) — posts profiles to the sysctl API directly and force-settles
   on `StopContainer`.
4. **Optimize stage on settle** (`AutoZranStage::Optimize`): once the tracer (or NRI) settles, the
   *same* job key reuses stage 1's work directory — only `nydus-image optimize --prefetch-files`
   re-runs, replacing the bootstrap and staging a packed prefetch blob. The sidecar is re-uploaded
   and `images_upsert` **promotes** the Image record from the base manifest to the optimized one.
   Nodes that already fetched the base sidecar keep working; new fetches get the optimized
   artifact.
5. **Running pods are never switched over.** There is no remount mechanism by design — the
   daemon-mounted, accelerated path only benefits the *next* pod (and peers), never the pod whose
   own access pattern produced the profile.

The two-stage split means the fragile wiring point is the `AccessTracer` ↔ `AutoZranManager` link:
`AutoZranManager`'s `ConversionDeps` borrow the tracer, so the tracer is constructed first with an
empty `OnceLock`, and `AccessTracer::set_auto_zran` back-fills it once the manager exists
(`open_store_for_config`'s caller in `containerd-nydus.rs`). If that back-fill is ever skipped,
profiles still capture and persist to disk, but nothing enqueues a conversion job for them —
`flush_profile` (`access_tracer.rs`) now `warn!`s once per process when it observes this.

### 10. Observability

- **Prometheus metrics**: always served over the sysctl UDS at `GET /metrics`; `[snapshotter.metrics].listen`
  (e.g. `"127.0.0.1:9110"`) additionally binds a TCP `GET /metrics` endpoint reusing the same
  renderer (`snapshotter/src/metrics.rs`, `grpc/mod.rs`), restoring parity with the Go snapshotter.
- **gRPC health**: the standard `grpc.health.v1.Health` service rides the same cyper-axum server as
  the `Snapshots` service, so containerd's proxy-plugin dialer and `grpc_health_probe` can check
  readiness (`snapshotter/src/grpc/mod.rs`).
- **Allocator / process-memory stats**: `GET /debug/allocator` on the sysctl UDS
  (`snapshotter/src/sysctl.rs`). See [docs/operations.md](./docs/operations.md) for the ops runbook
  (memory stats, CPU profiling with perf/samply).

### 11. Containerd Contract Fidelity

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
│   │   │   └── nydus-migrate.rs     # Store migration tool (manual/advanced subcommands)
│   │   ├── config/    # Unified TOML config
│   │   ├── daemon/    # In-process daemon supervisor
│   │   ├── grpc/      # containerd proxy-plugin server
│   │   ├── overlay/   # Overlay filesystem engine
│   │   ├── probe/     # Kernel capability probe
│   │   ├── recon/     # Reconciler loop
│   │   ├── source/    # Image source detection (referrer, encryption)
│   │   ├── store/     # fjall (LSM) snapshot metadata store (metadata.fjall)
│   │   └── migrate.rs # Legacy bbolt→fjall auto-migration at startup (feature "migrate")
│   └── Cargo.toml
├── nydusify/         # Rust nydusify: convert/check/copy/mount CLI (registry-publish flow)
├── registry-client/  # OCI distribution client (pull+push, bearer auth) used by nydusify
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

The Rust rewrite of **nydusify** — the `nydusify/` crate — **is in scope for v1.0 and is the
converter tool going forward**, replacing the Go `nydusify`. All four subcommands are real,
working implementations, not stubs:

- **`convert`** — two modes. `--oci-ref` (zran): `nydus-image create --type targz-ref` per layer +
  `merge --original-blob-ids`, so the pushed data blobs are the *original gzip layers* (mounted
  from the source repo when target and source coincide, else re-pushed) plus tiny zran index
  blobs — the same artifact shape B4b consumes. Standard mode: `nydus-image create --type
  targz-rafs` + `merge`, producing new nydus data blobs. `--with-referrer` additionally pushes an
  OCI 1.1 referrer artifact (`subject` = the source manifest descriptor) to the source repo, by
  digest and under the `sha256-<hex>` fallback tag for registries without native referrers-API
  support.
- **`check`** — validates manifest/media-type/annotations, referrer linkage (fallback-tag lookup
  only today), downloads the bootstrap, and runs `nydus-image check` on it.
- **`copy`** — pulls and re-pushes an image between repositories with `HEAD`-based blob dedup and
  same-registry `mount_blob`.
- **`mount`** — pulls the bootstrap via `registry-client` and spawns a foreground `nydusd` fusedev
  process backed by a registry backend, unmounting on SIGINT/SIGTERM. Registry backend only today
  (oss/s3/localfs are validated-but-rejected, follow-up); Linux-only in practice, since `nydusd`'s
  FUSE serving path is part of the Linux-only runtime surface (see the platform note at the top of
  CLAUDE.md).

All four are built on the new `registry-client/` crate (bearer-auth OCI distribution client: pull,
push, `HEAD`/mount-blob dedup — the piece that never existed anywhere in the Rust workspace before)
and drive `nydus-image`/`nydusd` as subprocesses, mirroring the `local_accel.rs` convention. See
[docs/nydusify-rust.md](./docs/nydusify-rust.md) for usage and the ecosystem loop (`convert
--with-referrer` → the snapshotter's default-on referrer serving, Decision 8). Live end-to-end
verification against a real registry is still pending.

This is the registry-side OCI→Nydus **push/convert** tool and is distinct from the node-local,
push-free acceleration path (`snapshotter/src/local_accel.rs`), which does not use nydusify; the
two serve different flows (registry-published nydus images vs. transparent node-local
acceleration).