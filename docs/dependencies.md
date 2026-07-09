# Dependency maintenance: vendored patches and git pins

This document tracks the workspace's non-crates.io dependencies: local patches to
third-party crates (`third_party/`, wired via `[patch]` in the root `Cargo.toml`)
and dependencies pinned to a specific git revision instead of a crates.io version
requirement. Both categories carry maintenance debt — a patch needs an upstream
PR filed and merged before it can be dropped; a git pin needs a tagged release to
move to before it can become a normal version requirement.

This is a living checklist. Update it whenever a patch's upstream PR is filed
(record the URL), merged, or released, or when a git-pinned dependency's upstream
cuts a release that lets us switch to a version requirement.

## Vendored/patched crates (`[patch]` in root `Cargo.toml`)

### compio-executor (patches 0.1.0)

- **Upstream**: https://github.com/compio-rs/compio
- **Local copy**: `third_party/compio-executor/`
- **Patch target**: `[patch.crates-io]` in `Cargo.toml` (root)
- **Bug fixed**: `Executor::tick()` iterates the hot-task linked list *live*
  while a polled task's wakers mutate that same list (move/remove tasks),
  invalidating the iteration cursor and causing a "prev exists" panic. This
  triggers in practice when a cyper HTTP connection task tears down and wakes
  its request task. The vendored copy snapshots the hot task ids before
  running them (`third_party/compio-executor/src/lib.rs`, see the "NYDUS LOCAL
  PATCH" comment around line 181) so the mutation during iteration is safe.
- **Upstream PR/issue status**: **NOT YET FILED.**
- **Drop trigger**: upstream fixes the tick() cursor invalidation and releases
  compio-executor > 0.1.0 with the fix; bump the workspace's `compio` version
  requirement past it and delete `third_party/compio-executor/` + the
  `[patch.crates-io]` entry.

### bbolt-rs (patches 1.3.10)

- **Upstream**: https://github.com/ambaxter/bbolt-rs
- **Local copy**: `third_party/bbolt-rs/`
- **Patch target**: `[patch.crates-io]` in `Cargo.toml` (root)
- **Bug fixed**: upstream `Bolt::new_db` hard-errors when
  `meta.free_list() == PGID_NO_FREE_LIST`, so it cannot open any bolt file
  produced by Go's bbolt with `NoFreelistSync` set — which is the default mode
  for containerd's `meta.db`. The patch rebuilds the in-memory freelist by
  scanning the page tree at open time (matching Go bbolt's `db.freepages()`
  recovery path), skips the freelist-page commit and stamps
  `PGID_NO_FREE_LIST` in meta when a new `no_freelist_sync()` builder option is
  set, and exposes that setter on `BoltOptionsBuilder` (previously
  `setter(skip)`). `nydus-migrate reconcile-snapshots` depends on this to read
  containerd's `meta.db` in-process instead of shelling out to a Go helper.
- **Upstream PR/issue status**: **NOT YET FILED.**
- **Drop trigger**: upstream merges `NoFreelistSync` support and releases
  bbolt-rs > 1.3.10 with it; bump the `bbolt-rs` version requirement in
  `snapshotter/Cargo.toml` past it and delete `third_party/bbolt-rs/` + the
  `[patch.crates-io]` entry.

### cyper-core (patches compio-rs/cyper @ `d1c8aff18dd81c4b1f817d0e8e0e05408c15a04c`)

- **Upstream**: https://github.com/compio-rs/cyper
- **Local copy**: `third_party/cyper-core/`
- **Patch target**: `[patch."https://github.com/compio-rs/cyper"]` in
  `Cargo.toml` (root)
- **Bug fixed**: a large-body read throughput regression in cyper-core's
  compio<->hyper stream adapter. compio drains the socket in 8 KiB chunks
  while hyper grows its read cursor toward ~400 KiB for large bodies; the
  upstream adapter zero-filled the *entire* cursor before every short read, so
  the memset scaled with the cursor size, not the bytes actually read — a
  body-size-scaled overhead that plateaued large-body throughput ~35-40% below
  reqwest. The vendored copy reads in 256 KiB chunks and bounds the zero-fill
  window to match (`third_party/cyper-core/src/stream.rs`).
- **Upstream PR/issue status**: **NOT YET FILED.**
- **Drop trigger**: upstream fixes the zero-fill window and cyper-core
  publishes a release at/after the fix commit; delete
  `third_party/cyper-core/` + the `[patch."https://github.com/compio-rs/cyper"]`
  entry (this also removes the need to git-pin cyper-core in
  `storage/Cargo.toml`, see below).

## Git-pinned dependencies (not on crates.io versions)

### containerd-snapshots

- **Pinned in**: `snapshotter/Cargo.toml`
- **Upstream**: https://github.com/containerd/rust-extensions
- **Pinned rev**: `7c1f39a9cd0a1d7a2a61196ad3c2bddd996893b9` (an unreleased
  `main` commit, not a tag)
- **Why pinned**: the last tagged crates.io release (0.3.0) is on tonic 0.9 /
  http 0.2. The snapshotter serves the containerd `Snapshots` gRPC service over
  compio via `cyper-axum` (hyper 1.x / axum 0.8), which requires tonic 0.14 /
  http 1.0 — only available on rust-extensions `main`, not in any tagged
  release yet.
- **Trigger to move to crates.io**: watch for the next tagged
  containerd/rust-extensions release; once it ships tonic >= 0.14, switch
  `containerd-snapshots` to a normal `version = "..."` requirement.

### cyper / cyper-axum

- **Pinned in**: `snapshotter/Cargo.toml` (`cyper`, `cyper-axum`),
  `storage/Cargo.toml` (`cyper`, `cyper-core`)
- **Upstream**: https://github.com/compio-rs/cyper
- **Pinned rev**: `d1c8aff18dd81c4b1f817d0e8e0e05408c15a04c` (a `master`
  commit, not a tag), identical across all four dependency entries
- **Why pinned**: cyper 0.9 (the version implied by `master`) tracks compio
  0.19, but the last crates.io release still targets compio 0.18. The
  workspace's compio usage (`compio = "0.19"` in `snapshotter/Cargo.toml` and
  `storage/Cargo.toml`) requires the newer cyper.
- **Trigger to move to crates.io**: cyper publishes a crates.io release built
  against compio 0.19+; switch all four entries (`cyper`, `cyper-axum` in
  `snapshotter/Cargo.toml`; `cyper`, `cyper-core` in `storage/Cargo.toml`) to a
  normal `version = "..."` requirement in the same change (they must stay on
  the same cyper version). Note `cyper-core` additionally carries the local
  zero-fill patch above — that patch has its own, independent drop trigger and
  may still be needed even after the git pin itself is dropped, until the
  patch's fix lands upstream too.

## How to upstream

The rationale comments next to each `[patch]` entry in `Cargo.toml` (root) and
the "Bug fixed" sections above are written to double as PR descriptions — they
already state the bug, the root cause, and the fix. Filing the actual PR/issue
against each upstream GitHub repo is a manual maintainer action (it requires
the maintainer's own GitHub identity to open and follow up on the PR), so it
cannot be automated here. Use this doc as the checklist:

1. For each vendored crate above marked **NOT YET FILED**, open a PR (or issue,
   if a full PR isn't feasible) against the listed upstream repo, using the
   "Bug fixed" text as the description, and link to the relevant file in
   `third_party/<crate>/src/`.
2. Once filed, replace **NOT YET FILED** in this doc with the PR/issue URL and
   its state (open / merged / released).
3. Once merged upstream *and* released to crates.io, update the corresponding
   `Cargo.toml` entries (drop the `[patch]`, switch to a version requirement)
   and delete the `third_party/<crate>/` copy in the same change.
4. For the two git-pinned dependencies, periodically check the upstream repo's
   release page/tags for a release that satisfies the "why pinned" constraint
   above, then switch to a version requirement as described.
