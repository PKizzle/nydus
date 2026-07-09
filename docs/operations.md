# Operations: memory stats and CPU profiling for the Rust snapshotter

The Go snapshotter (`containerd/nydus-snapshotter`) exposes `net/http/pprof` for live
heap/goroutine/CPU profiling. The Rust snapshotter (`snapshotter/`) does **not** port that
endpoint. This document explains why, and what to use instead.

## Why pprof was not ported

- `net/http/pprof` is Go-runtime-specific: it profiles goroutines, the Go GC, and Go's own
  CPU sampler. None of that exists in the Rust binary.
- The snapshotter's hot paths (FUSE/fanotify event loop, gRPC server) run on
  [`compio`](https://github.com/compio-rs/compio) (io_uring), not `tokio`. `tokio-console` — the
  closest Rust analogue to a live-attach profiler — instruments the Tokio runtime and does not
  see compio's task/IO state, so it would only cover part of the process (the gRPC server, which
  does use a multi-thread Tokio runtime) and silently miss the FUSE/fanotify side, which is
  exactly the part most worth profiling.
- Building a bespoke live-sampling HTTP endpoint for a mixed compio/tokio process is real work
  for uncertain benefit when standard, well-maintained OS/user-space profilers already do the job
  without adding attack surface to a socket that already carries daemon-control, cache-GC, and
  auth endpoints.

Decision: keep the sysctl API for **cheap, structured, always-on** signals (see below), and use
external sampling profilers (`perf`, `samply`) for **on-demand, deep** CPU investigation. This
mirrors how the project already treats `/metrics` (Prometheus) vs. ad hoc debugging.

## `GET /debug/allocator` — allocator / process memory stats

The snapshotter binaries (`containerd-nydus`, `nydus-migrate`) link
[`mimalloc`](https://github.com/microsoft/mimalloc) as the global allocator (see the
`#[global_allocator]` in `snapshotter/src/bin/containerd-nydus.rs`) because compio's owned-buffer
completion I/O churns a lot of small allocations, and mimalloc's thread-local pools cut that
overhead noticeably versus the system allocator.

`GET /debug/allocator` on the sysctl Unix-socket API returns a small, cheap, read-only JSON
snapshot of process memory usage:

```json
{
  "source": "proc_self_status",
  "mimalloc_extended_stats_available": false,
  "current_rss_bytes": 41943040,
  "peak_rss_bytes": 52428800,
  "virtual_size_bytes": 838860800,
  "note": "portable RSS via /proc/self/status; mimalloc extended stats not enabled"
}
```

- `current_rss_bytes` / `peak_rss_bytes` / `virtual_size_bytes` come from `/proc/self/status`
  (`VmRSS`, `VmHWM`, `VmSize`) on Linux — no allocator-specific dependency required. On non-Linux
  builds (e.g. running the sysctl server under a macOS dev build) these are `null` and `source` is
  `"unavailable"`.
- `mimalloc_extended_stats_available` is currently always `false`. mimalloc's own richer stats
  (`mi_process_info`: peak/current commit, page faults, etc., and `mi_stats_print_out` /
  `stats_json()`) live behind the `mimalloc` crate's `extended` Cargo feature, which is **not**
  currently enabled for the `mimalloc` dependency in `Cargo.toml` / `snapshotter/Cargo.toml`.
  Turning it on is a small, isolated follow-up (add `features = ["extended"]` to the `mimalloc`
  dependency) but is out of scope here to avoid touching `Cargo.toml` alongside unrelated
  in-flight work; once enabled, this endpoint can report per-allocator page/committed/reserved
  stats instead of just process RSS.

The endpoint is intentionally minimal: no allocation-site tracking, no sampling, nothing that
scales with heap size — it is safe to poll frequently (e.g. from a sidecar or a cron job) without
measurable overhead.

### Querying it

The sysctl API is served on a Unix domain socket, not TCP — same as `/metrics`, `/api/v1/auth`,
etc. The default socket path is `/run/containerd-nydus/containerd-nydus-api.sock`
(`default_sysctl_address()` in `snapshotter/src/config/mod.rs`; overridable via
`[snapshotter.sysctl] address` in the TOML config).

```bash
curl --unix-socket /run/containerd-nydus/containerd-nydus-api.sock \
  http://localhost/debug/allocator
```

Pretty-printed with `jq`:

```bash
curl -s --unix-socket /run/containerd-nydus/containerd-nydus-api.sock \
  http://localhost/debug/allocator | jq .
```

## CPU profiling: `perf` and `samply`

For actual CPU profiling (where is the process spending time?), use a system sampling profiler
against the live `containerd-nydus` process instead of an in-process endpoint.

### `perf` (Linux, matches the runtime path's platform requirement anyway)

```bash
# Find the PID
pgrep -f containerd-nydus

# Record ~30s of stack samples at 99 Hz (avoids beating against periodic timers)
sudo perf record -F 99 -p <pid> -g -- sleep 30

# Interactive report
sudo perf report

# Or a flamegraph (requires github.com/brendangregg/FlameGraph on PATH)
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > containerd-nydus.svg
```

Notes specific to this codebase:

- Build with debug info for readable symbols. The workspace `[profile.release]` sets only
  `panic = "abort"` — it does **not** enable `debug`, so a plain `cargo build --release` ships
  **without** DWARF debug info and `perf`/`samply` stacks will show raw addresses instead of
  function names. For symbolized stacks, build with `CARGO_PROFILE_RELEASE_DEBUG=true cargo build
  --release` (keeps release optimizations, adds debuginfo) or use a `dev` build (`[profile.dev]`
  already sets `debug = true`).
- The FUSE/fanotify event loop runs on a `current_thread` compio runtime pinned to its own OS
  thread; `perf record -p <pid> -g` (whole-process, all threads) is what you want, not
  `--per-thread` unless you're specifically isolating that thread from the gRPC server's
  multi-thread pool.
- io_uring submission/completion shows up as time in the kernel (`io_uring_enter` syscalls) — that
  is expected and not itself a problem; look at what's runnable *between* completions.

### `samply` (cross-platform, including macOS dev boxes)

[`samply`](https://github.com/mstange/samply) is a good alternative when working on the
build/convert tooling (`nydus-image`, `nydusify`) on macOS, where `perf` isn't available and the
runtime path (fanotify/EROFS) doesn't run anyway:

```bash
cargo install samply
samply record ./target/release/nydus-image create --type targz-ref --fs-version 6 <args...>
```

`samply record` launches the process directly and opens an interactive flamegraph in the browser
(profile data stays local; `samply` only needs network access to serve the local viewer UI, not to
upload anything). To profile an already-running process instead of launching one:

```bash
samply record --pid <pid>
```

## What this does *not* give you

- No heap-allocation-site profiling (no `mi_heap_visit_blocks`-style tracking, no `jemalloc`
  `--enable-prof` equivalent). If a real leak investigation needs that, the right move is a
  temporary local build with `mimalloc`'s `debug`/`extended` features and `MIMALLOC_SHOW_STATS=1`,
  not a permanent HTTP endpoint.
- No goroutine-equivalent task dump. compio tasks aren't introspectable the way Tokio tasks are
  under `tokio-console`; `perf`/`samply` stack sampling is the practical substitute for "what is
  this process doing right now."
