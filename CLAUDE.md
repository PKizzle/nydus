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
```

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
│   └── src/bin/         # containerd-nydus, nydus-migrate
├── storage/          # Core storage subsystem (backends, caching)
├── utils/            # Common utilities (logging, metrics, etc.)
├── upgrade/          # Hot upgrade state machine
└── misc/fanotify/    # Root-only integration tests for the on-demand path (runtime/zran/multilayer)
```

## Coding Conventions

- **Language**: Rust, edition 2021. `#![deny(warnings)]` in all binary crates.
- **Error handling**: Use `anyhow::Result` in applications; `thiserror` for library error types.
- **Async runtime**: split by crate. The **snapshotter** (`containerd-nydus`) runs on **compio** (io_uring, `#[compio::main]`); its gRPC/health server and sysctl HTTP API are cyper-axum (hyper-on-compio) — no tokio. The **`service/` crate** (in-process nydus-service: FUSE + fanotify I/O) uses a `current_thread` **tokio** runtime, required for io-uring compatibility — see gotcha #1. Do not conflate the two: never hand the FUSE/fanotify session thread a multi-thread tokio handle.
- **Logging**: Use `tracing` macros (`info!`, `warn!`, `error!`, `debug!`, `trace!`). Never use `println!` in library code.
- **Naming**: Follow standard Rust conventions (snake_case, PascalCase).
- **Configuration**: All config types use `serde` with `Deserialize`/`Serialize`. The unified TOML config is in `snapshotter/src/config/`.
- **Testing**: Unit tests in `#[cfg(test)]` modules within source files. Integration tests in `tests/` directories.
- **Formatting**: Always run `cargo fmt` before committing. Follow `clippy` suggestions.

## Key Gotchas

1. **Tokio runtime split**: The FUSE/fanotify event loop runs on a `current_thread` runtime. Never call `tokio::spawn` with a multi-thread runtime handle from inside the FUSE session thread — it will panic or deadlock.
2. **fscache is removed**: Do not add any fscache-related code. The `FsDriverFscache` type, `--fscache` flags, and `FscacheConfig` are gone. Use `FanotifyConfig` for the fanotify path.
3. **Fanotify requires Linux ≥ 6.14**: The `FAN_CLASS_PRE_CONTENT` / `FAN_PRE_ACCESS` API is only available in kernel 6.14+. The probe module (`snapshotter/src/probe/`) handles fallback to fusedev automatically.
4. **Fanotify ABI constants are hand-written** (`service/src/fanotify_sys.rs`, because `nix` doesn't expose the pre-content API) — they MUST match the kernel UAPI exactly, or the path fails silently/at mount: `FAN_PRE_ACCESS = 0x0010_0000`, `FAN_EVENT_INFO_TYPE_RANGE = 6`, `FAN_DENY_ERRNO(e) = FAN_DENY | ((e & 0xFF) << 24)`. Verify any change against `/usr/include/linux/fanotify.h` on a 6.14+ host.
5. **The fanotify on-demand path has strict runtime invariants** (all verified in `misc/fanotify/`; reproducing them is non-negotiable):
   - **`cache_type: "fanotify"` uses the file cache.** `storage/src/factory.rs` maps it to `FileCacheMgr` (not `DummyCacheMgr`), and `api/src/config.rs` mirrors the fanotify `work_dir` into `file_cache` so `get_filecache_config()` works. Each blob's `<work_dir>/<blob_id>.blob.data` cache file **is** the EROFS device the kernel reads.
   - **Device file ≡ cache file (same inode).** `FanotifyHandler::new()` self-stages the EROFS device files as hardlinks to each data blob's `.blob.data` (resolved via `/proc/self/fd`, sorted by blob index for multi-device order). Callers supply only a bootstrap + blob-cache config.
   - **EROFS mount form**: the bootstrap is the mount **source**; data blobs are `device=<path>` options in device-table order. `source=NULL` ("none") fails `EINVAL`.
   - **Ordering**: worker threads must be draining BEFORE marks are armed (`arm()`) and BEFORE `mount()`, or the daemon deadlocks in `D` state. Mark data blobs with `FAN_PRE_ACCESS` only (never `FAN_OPEN_PERM`).
   - **Backing fs**: `work_dir` must be on a fs that supports pre-content marks — ext4 works, **tmpfs returns `ENOTSUP`**. Block size must equal the host page size (4K/16K/64K all supported).
6. **In-process daemon**: The snapshotter links `nydus-service` as a library. Never spawn `nydusd` as a child process. Use `FsService`, `FanotifyHandler`, `FuseServer`, `BlockDevice` directly.
7. **fjall snapshot store**: The snapshot metadata store is an embedded **fjall** LSM key/value store (`snapshotter/src/store/mod.rs`, on-disk dir `metadata.fjall`), NOT SQLite. It uses `manual_journal_persist(true)` with a `PersistMode::SyncAll` after every mutation and `max_journaling_size` pinned to fjall's 64 MiB minimum. Do not reintroduce SQLite/sqlx or a relational schema; `nydus-migrate` handles legacy bbolt/SQLite import.
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

Status: the conversion + serving pipeline is verified end-to-end (single + multi-layer) via
`misc/fanotify/`. **Remaining**: the snapshotter `Prepare`/commit lifecycle wiring (detect a
complete standard-OCI image → gather content-store layers → `local_accel::convert` → build a
fanotify `BlobCacheList` → `DaemonSupervisor::ensure_instance` → return the daemon mount). That step
needs the containerd/k3s loop to implement and verify.

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
- **nydusify**: Go tool for registry-side OCI→Nydus conversion (push flow). A Rust crate (`nydusify/`) exists but its containerd-converter backend is still a stub — it is **not** on the node-local accel path, which uses `snapshotter/src/local_accel.rs` instead (no push).