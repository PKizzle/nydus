# CLAUDE.md — AI Agent Guide for Nydus

> This file provides context for AI coding agents (Claude, Copilot, etc.) working on the Nydus project.

## Quick Start

```bash
# Build the entire workspace (including the new snapshotter)
cargo build --workspace

# Build only the snapshotter binary
cargo build -p nydus-snapshotter

# Run all tests
cargo test --workspace

# Run snapshotter-specific tests
cargo test -p nydus-snapshotter

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check

# Run the snapshotter locally (requires containerd socket)
cargo run -p nydus-snapshotter --bin containerd-nydus -- --config /etc/nydus/config.toml

# Fanotify/EROFS on-demand integration tests (Linux ≥ 6.14, root, non-tmpfs work dir)
sudo NYDUS_IMAGE=./target/release/nydus-image NYDUSD=./target/release/nydusd \
  misc/fanotify/runtime-test.sh         # plain blob fetch path
sudo misc/fanotify/zran-multilayer-test.sh   # node-local zran convert + merge + serve
sudo misc/fanotify/precontent-cases.sh       # fail-closed + strace ground truth (needs strace)
```

> **Linting is Linux-only in practice.** `service/src/fanotify*.rs` and the fanotify half of
> `singleton.rs` are entirely `cfg(target_os = "linux")`, so a macOS `cargo clippy` compiles none of
> it and will pass over real errors. Run the full gate in a Linux container before pushing:
> `docker run --rm -v "$PWD":/work -w /work rust:1.96-bookworm bash -c 'apt-get update -qq &&
> apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler && rustup component
> add clippy && cargo clippy --workspace --all-targets -- -D warnings'`. Note `--all-targets`:
> without it, `#[cfg(test)]` code is not linted.

> **Platform:** the runtime path (fanotify/EROFS, snapshotter, block device) is **Linux-only** and
> needs kernel ≥ 6.14. On macOS only the build/convert tooling (`nydus-image`, `nydusify`) and FUSE
> dev compile. Develop the Linux runtime in a Linux VM/host; Windows is supported only via WSL2.

## Project Structure

```
nydus/
├── api/              # Nydus API types, HTTP handlers, config structs
├── builder/          # Image building and conversion (nydus-image)
├── clib/             # C FFI bindings
├── rafs/             # RAFS filesystem implementation (v5 + v6)
├── service/          # Daemon and service management (nydusd core)
│   ├── src/fanotify.rs     # Fanotify pre-content handler (Linux ≥ 6.14)
│   ├── src/fanotify_sys.rs # Local FFI shim for the 6.14 pre-content ABI (nix lacks it)
│   ├── src/fusedev.rs      # FUSE daemon
│   ├── src/block_device.rs # Block device (NBD/loop/uffd)
│   ├── src/blob_cache.rs   # Blob cache manager
│   └── src/singleton.rs    # Singleton daemon controller (arms fanotify marks + mounts)
├── snapshotter/      # ★ Containerd remote snapshotter (Rust, v3.0)
│   ├── src/config/      # Unified TOML config (replaces Go snapshotter config + nydusd JSON)
│   ├── src/daemon/      # In-process daemon supervisor (state machine)
│   ├── src/grpc/        # containerd proxy-plugin gRPC server
│   ├── src/local_accel.rs # Node-local zran conversion (transparent accel; see below)
│   ├── src/overlay/     # Overlay filesystem engine
│   ├── src/probe/       # Kernel capability probe (fanotify/fusedev/blockdev)
│   ├── src/recon/       # Reconciler loop (self-healing)
│   ├── src/source/      # Image source detection (referrer, encryption)
│   ├── src/store/       # fjall (LSM) snapshot metadata store (metadata.fjall)
│   ├── src/migrate.rs   # Legacy bbolt→fjall auto-migration (library core; feature "migrate")
│   └── src/bin/         # containerd-nydus, nydus-migrate, nydus-credential-bridge, NRI plugins
├── nydusify/         # Rust nydusify: convert/check/copy/mount CLI (registry-publish flow)
├── registry-client/  # OCI distribution client (pull+push, bearer auth) used by nydusify
├── storage/          # Core storage subsystem (backends, caching)
├── utils/            # Common utilities (logging, metrics, etc.)
├── upgrade/          # Hot upgrade state machine
└── misc/fanotify/    # Root-only integration tests for the on-demand path (runtime/zran/multilayer)
```

## Coding Conventions

- **Language**: Rust, **edition 2024** (workspace `resolver = "3"`), MSRV rustc ≥ 1.96, declared once in `[workspace.package]` and inherited by every member (`rust-version.workspace = true`) so clippy's MSRV-aware lints actually apply; it tracks the `rust-toolchain.toml` pin. `#![deny(warnings)]` in all binary crates — including each `snapshotter/src/bin/*.rs` target (bin targets are separate compilation units, so the lib-level attribute does not cover them).
- **Error handling**: Use `anyhow::Result` in applications; `thiserror` for library error types.
- **Async runtime**: split by crate, and none of it is tokio-driven — with **one sanctioned exception** (below). The **snapshotter** (`containerd-nydus`) runs on **compio** (io_uring, `#[compio::main]`); its gRPC/health server and sysctl HTTP API are cyper-axum (hyper-on-compio). The **`service/` crate** (in-process nydus-service: FUSE + fanotify I/O) has **zero tokio**: the fanotify loop is `mio`-poll + blocking libc reads, FUSE runs sync `svc_loop` std threads, and blob io_uring reads plus block-device (uffd/nbd) event loops run on **compio** (`async-broadcast` + `futures-util` standing in for tokio's `select!`/broadcast) — see gotcha #1. `nydus-storage`'s default build is also tokio-free; `tokio` is `optional = true`, gated behind the `backend-dragonfly-proxy` feature (non-default). **`nydusctl`** runs on `#[compio::main]` and speaks HTTP/1 to the daemon's unix socket with `compio::net::UnixStream` + `cyper_core::HyperStream` + `hyper::client::conn::http1` — copy that pattern (also used by `storage/src/backend/http_proxy.rs`) for any new unix-socket HTTP client. Do **not** reach for `hyper-util`'s legacy `Client` or `hyperlocal`: both are tokio-bound, and pulling them in reintroduces a tokio runtime by the back door (this is exactly how `nydusctl` silently acquired `#[tokio::main]` and broke musl-static, where building the bins alone removed the feature unification that had been hiding it). **The one place a tokio runtime is deliberately spawned** is `snapshotter/src/content_store.rs`: an isolated 2-worker runtime that drives the tonic *client* to containerd's Content/Images gRPC (tonic's transport pins its futures to a tokio reactor). It is fully quarantined behind `blocking::unblock` + `handle.block_on` and torn down in `Drop`, so no tokio task ever runs on a nydusd session thread and compio still drives the snapshotter's own event loop. Apart from that, the tokio crate in `cargo tree` is only a type-compat dependency of `h2`/`hyper`/`tonic`/`cyper-axum` — nothing spawns a runtime. Do not hand any nydusd session thread a tokio runtime handle of any kind, and do not add a second tokio runtime elsewhere without the same quarantine.
- **Logging**: Use `tracing` macros (`info!`, `warn!`, `error!`, `debug!`, `trace!`). Never use `println!` in library code.
- **Naming**: Follow standard Rust conventions (snake_case, PascalCase).
- **Configuration**: All config types use `serde` with `Deserialize`/`Serialize`. The unified TOML config is in `snapshotter/src/config/`.
- **Testing**: Unit tests in `#[cfg(test)]` modules within source files. Integration tests in `tests/` directories.
- **Formatting**: Always run `cargo fmt` before committing. Follow `clippy` suggestions.

## Key Gotchas

1. **No tokio in `service/` or the default `storage/` build**: the FUSE/fanotify event loop is `mio`-poll + blocking libc reads on its own OS thread (`service/src/fanotify.rs`), FUSE uses sync `svc_loop` std threads (`service/src/fusedev.rs`), and block-device/blob io_uring I/O runs on **compio** (`service/src/blob_cache.rs`, `block_device.rs`) — never tokio. `service/Cargo.toml` has no tokio dependency at all; `storage/`'s tokio is `optional = true` behind the non-default `backend-dragonfly-proxy` feature. Never introduce a tokio runtime into any nydusd session thread.
2. **fscache is removed**: Do not add any fscache-related code. The `FsDriverFscache` type, `--fscache` flags, and `FscacheConfig` are gone. Use `FanotifyConfig` for the fanotify path.
3. **Fanotify requires Linux ≥ 6.14**: The `FAN_CLASS_PRE_CONTENT` / `FAN_PRE_ACCESS` API is only available in kernel 6.14+. The probe module (`snapshotter/src/probe/`) handles fallback to fusedev automatically.
4. **Fanotify ABI constants are hand-written** (`service/src/fanotify_sys.rs`, because `nix` doesn't expose the pre-content API) — they MUST match the kernel UAPI exactly, or the path fails silently/at mount: `FAN_PRE_ACCESS = 0x0010_0000`, `FAN_EVENT_INFO_TYPE_RANGE = 6`, `FAN_DENY_ERRNO(e) = FAN_DENY | ((e & 0xFF) << 24)`. Verify any change against `/usr/include/linux/fanotify.h` on a 6.14+ host.
5. **The fanotify on-demand path has strict runtime invariants** (all verified in `misc/fanotify/`; reproducing them is non-negotiable):
   - **`cache_type: "fanotify"` uses the file cache.** `storage/src/factory.rs` maps it to `FileCacheMgr` (not `DummyCacheMgr`), and `api/src/config.rs` mirrors the fanotify `work_dir` into `file_cache` so `get_filecache_config()` works. Each blob's `<work_dir>/<blob_id>.blob.data` cache file **is** the EROFS device the kernel reads.
   - **Device file ≡ cache file (same inode).** `FanotifyHandler::new()` self-stages the EROFS device files as hardlinks to each data blob's `.blob.data` (resolved via `/proc/self/fd`, sorted by blob index for multi-device order). Callers supply only a bootstrap + blob-cache config.
   - **EROFS mount form**: the bootstrap is the mount **source**; data blobs are `device=<path>` options in device-table order. `source=NULL` ("none") fails `EINVAL`. Flags are `MS_RDONLY | MS_NODEV | MS_NOSUID` (the image is untrusted), and the option string is capped at 4095 bytes — `mount(2)` silently truncates past one page, so a deep cache dir × many blobs is rejected up front instead of failing as a confusing EROFS error.
   - **Every permission event must be answered.** An unanswered event fd leaves its reader in `D` state until the group closes. Panics deny via `EventFdGuard::drop`; a structurally corrupt event buffer denies everything still parsable before failing; shutdown drains and denies the queue *before* the unmount, and the unmount must complete before the group fd drops (`fanotify_release()` fail-opens whatever is queued). A `FAN_Q_OVERFLOW` record is **fatal** — the kernel already fail-opened the events it dropped, so continuing means knowingly serving zeros.
   - **Ordering**: worker threads must be draining BEFORE marks are armed (`arm()`) and BEFORE `mount()`, or the daemon deadlocks in `D` state. Mark data blobs with `FAN_PRE_ACCESS` only (never `FAN_OPEN_PERM`).
   - **Backing fs**: `work_dir` must be on a fs that supports pre-content marks — ext4 works, **tmpfs returns `ENOTSUP`**. Block size must equal the host page size (4K/16K/64K all supported).
6. **In-process daemon**: The snapshotter links `nydus-service` as a library. Never spawn `nydusd` as a child process. Use `FsService`, `FanotifyHandler`, `FuseServer`, `BlockDevice` directly.
7. **fjall snapshot store**: The snapshot metadata store is an embedded **fjall** LSM key/value store (`snapshotter/src/store/mod.rs`, on-disk dir `metadata.fjall`), NOT SQLite. It uses `manual_journal_persist(true)` with a `PersistMode::SyncAll` after every mutation and `max_journaling_size` pinned to fjall's 64 MiB minimum. Do not reintroduce SQLite/sqlx or a relational schema **for the snapshot metadata store**. (This rule is scoped to the snapshotter store only. `rusqlite` still exists elsewhere in the workspace — the chunk-dedup CAS at `src/bin/nydus-image/deduplicate.rs` and `storage/src/cache/dedup/db.rs` behind the default `dedup` feature — which is a longstanding upstream nydus feature, unrelated to this store.) A legacy Go-snapshotter bbolt `metadata.db` is **auto-migrated at startup**: `open_store_for_config` (`snapshotter/src/grpc/mod.rs`) calls `migrate::auto_migrate_at_startup` (`snapshotter/src/migrate.rs`) whenever a `metadata.db` sits next to a *fresh/empty* fjall store — idempotent, never deletes the bbolt source, degrades to a warning on failure instead of blocking startup. This is a default feature (`migrate`) on every architecture now that `third_party/bbolt-rs` pins `aligners = { default-features = false }` unconditionally (no SIMD dependency, so ppc64le/riscv64 build cleanly too). `nydus-migrate` (the standalone binary) remains for the destructive/manual subcommands (`reconcile-snapshots`, `repair-labels`) that must never run automatically.
8. **Config format**: The unified TOML config replaces both the old snapshotter TOML and the nydusd JSON. Do not create separate config files.
9. **Nydus blob layers bypass stream processors**: `application/vnd.oci.image.layer.nydus.blob.v1` layers are NOT routed through a containerd stream processor. On `Prepare`, the snapshotter classifies the layer via `containerd.io/snapshot/nydus-blob`, commits the target snapshot directly, and returns gRPC `AlreadyExists` so containerd's image-unpacker skips extraction. See [snapshotter/src/source/labels.rs](snapshotter/src/source/labels.rs) and `OverlayEngine::prepare`.

## Node-local acceleration (transparent, no tag change)

The intended way to accelerate a **standard OCI image** is node-local and registry-free: no second
tag, no pushed artifact, `original:tag` is served faster than the original. Mechanism:

1. `original:tag` is pulled normally (P2P via spegel); its gzip layers land in containerd's content
   store keyed by digest. **An OCI gzip-layer digest is exactly the nydus zran data-blob id and the
   content-store key**, so a `localfs` backend over the content store serves layers with zero
   re-download.
2. `snapshotter/src/local_accel.rs::convert()` builds a RAFS v6 + zran artifact **locally**:
   `nydus-image create --type targz-ref --fs-version 6` per layer, then `nydus-image merge
   --original-blob-ids <digests>`. The only new blobs are the merged bootstrap and tiny per-layer
   zran index blobs.
3. The artifact is served on demand through the fanotify path (gzip ranges decompressed lazily into
   the cache), so the container starts before the image is fully materialised.

Status: **fully wired end-to-end.** The conversion + serving pipeline is verified (single +
multi-layer) via `misc/fanotify/`, and the snapshotter `Prepare` lifecycle integration exists: the
prepare path (`snapshotter/src/grpc/mod.rs`) resolves an existing accel sidecar
(`resolve_auto_accel_mount`), enqueues stage-1 base conversion for new images
(`AutoZranManager::try_enqueue_base`), and attaches the access tracer whose settle drives the
stage-2 optimize/prefetch upload — worker logic in `snapshotter/src/auto_zran.rs`, artifact
build in `local_accel.rs`, serving via `DaemonSupervisor::ensure_instance`. Still unverified in
automation: a live containerd-GC race against a slow peer fetch mid-promotion, a multi-node
spegel sidecar-fetch soak, and the fanotify path in CI (GitHub runners are kernel < 6.14;
`misc/fanotify/*.sh` covers it on a modern host — CI covers the fusedev loop via
`misc/snapshotter-e2e.sh`).

Do NOT reintroduce the tag-suffix / referrer-push approach for transparent accel — it was
explicitly rejected because it changes the tag and the snapshotter never consults referrers. Use
`SchedClass` (`local_accel.rs`) for any OS-portable low-priority background work instead of
hard-coding `ionice` (Linux-only; macOS uses `taskpolicy`).

## PR Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] New config fields have `#[serde(default)]` where appropriate
- [ ] No fscache references added
- [ ] If the fanotify path changed: ABI constants still match the kernel UAPI, and `misc/fanotify/*.sh` still pass on a 6.14+ host
- [ ] Error types use `thiserror` for library code, `anyhow` for application code
- [ ] `tracing` used instead of `log` in new code
- [ ] Documentation updated if public API changed

## Architecture Decisions

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design document.

## Related Projects

- **nydus-snapshotter (Go)**: The legacy Go snapshotter at `containerd/nydus-snapshotter`. Now in LTS mode; only critical bug fixes. All new development happens in `snapshotter/` here.
- **containerd/rust-extensions**: Provides the `containerd-snapshots` crate used for the gRPC proxy-plugin server.
- **nydusify**: registry-side OCI→Nydus conversion (push flow). The Rust `nydusify/` crate is **in scope for v1.0 and is the converter tool going forward**, replacing the Go nydusify. Every subcommand is implemented and real (not stubs): `convert` (both `--oci-ref`/zran and standard modes, `--with-referrer` artifact push, and `--source-archive`/`--target-archive` OCI-layout tar I/O), `check`, `copy` (registry-to-registry, or to/from a `file://` OCI-layout tarball), `mount`, `commit`, and `chunkdict generate` — driven by the new `registry-client/` crate (OCI pull+push, bearer auth) plus `nydus-image`/`nydusd` subprocesses. `commit` snapshots a running container's overlay `upperdir` into a new RAFS layer stacked on its base image; it inspects the container through containerd's `ctr` CLI (deliberately, so no tonic/tokio client stack enters a compio binary — see gotcha about the one sanctioned tokio runtime) and translates overlayfs whiteouts to OCI ones in `nydusify/src/engine/overlay_diff.rs`. `--with-path` additionally commits bind-mounted volumes, which never reach the upperdir, by tarring them out of the container's mount namespace with `nsenter`. Archive I/O is verified end-to-end against a live registry; `commit` is covered by `smoke/tests/commit_test.go` (needs containerd + the nydus snapshotter, so CI is its only test). Separate from the node-local accel path, which uses `snapshotter/src/local_accel.rs` (no push) — nydusify is the registry-publish flow, not the transparent accel flow. See [docs/nydusify-rust.md](./docs/nydusify-rust.md) for usage.