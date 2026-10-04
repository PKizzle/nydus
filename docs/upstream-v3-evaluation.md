# Evaluating upstream's `v3` branch

*Assessed against `upstream/v3` @ `3f9e12ed`, re-checked at tags `v3.0.0-alpha.1` and
`v3.0.0-beta.1` (`fc2c3dfc`), last at branch head `02156def` (240 commits). Re-check before acting
on any of this — the branch is still moving.*

> **Re-checked at `v3.0.0-beta.1` / `02156def`.** Beta was the trigger to revisit; the decision
> below still holds, because neither precondition for adopting v3 is met:
> - **(a) Accelerating an unmodified OCI tag without a push — not met.** The new "native" EROFS
>   layers (`c9c9f714`, `--compressor erofs-none|erofs-lz4|erofs-zstd`) are *re-encoded* full blobs
>   laid out `[layer data][bootstrap][footer]` with a `RAW_DEVICE` flag. Lazy-loading them is a
>   stated non-goal (`docs/nydus.md`), and the registry backend refuses them. `02953b94` lets a
>   *local* native blob be the kernel device directly, so the closest node-local recipe is a full
>   decompressed on-disk copy with no lazy loading — what an EROFS-unpack snapshotter already does.
>   Gzip support is **decode-only** (`flate2` `MultiGzDecoder` on build input); there is still no
>   zran. `02156def` normalises layer tars to match containerd's `archive.Apply` before building;
>   it does not change what is served.
> - **(b) Snapshotter integration — not met.** No snapshotter or proxy-plugin code exists. The
>   manifest layout is reused, but the blob format underneath is incompatible with a nydusd v2.
> - **Format stability.** The README still warns formats may change and it is not production-ready,
>   and the format broke again in this range: magics renamed `LP*` → `ND*` (`373215af`, old blobs
>   rejected), version fields replaced by compat/incompat feature bits (`a3a7c996`, the first real
>   extensibility story), and a new content-defined chunk-group layout (`1a69b3e9`).
> - **Tokio on the I/O path.** One lazy, process-wide registry runtime (`cb62e7c7`, 2 workers,
>   ≤ 8 blocking threads for DNS); synchronous FUSE/fanotify callers block on it for every remote
>   fetch. Still at odds with our no-tokio-in-`service/` rule.
>
> Re-run the same two checks next time: `git grep -i zran upstream/v3` (still empty) and
> `git grep -il snapshotter upstream/v3 -- '*.rs'` (still empty).

> **Re-checked at tag `v3.0.0-alpha.1`** (`upstream/v3`, 147 commits). The decision below
> is unchanged, and the zran gap that drives it still holds: `git grep -i zran upstream/v3` returns
> nothing, which is the cheapest single signal to re-run. What did change:
> - It is no longer near-single-author. The commit list is the core maintainers (Gaius, imeoer,
>   yansong.ys, Peng Tao) and there are now two alpha tags. Treat it as upstream's real next major,
>   **not** a side experiment — while still respecting its own "not ready for production" warning.
> - Layout moved on again: `nydus-accessor/` and the Go nydusify are gone, replaced by a workspace
>   split (`nydus`, `nydus-core`, `nydus-storage`, `nydus-backend`, `nydus-config`, `nydus-error`,
>   `nydus-format`, `nydus-telemetry`). Its workspace deps include `tokio`, against our
>   no-tokio-in-`service/` rule.
> - **CDC (content-defined chunking)** lives on `upstream/copilot/nydus-v3-chunk-digest-optimization`
>   (v3 + 8 commits). It is not a portable algorithm: every CDC type belongs to the `LPBLMETA` blob
>   metadata format and the new `LocalBlobCache` read path, neither of which exists here. Porting it
>   means adopting a second on-disk format beside RAFS v5/v6. **Out of scope for this fork.**
> - Items #3 and #5 below carry detailed assessments; #5 largely dissolves against our architecture.

## What it is

`dragonflyoss/nydus`'s `v3` branch is **not a v3 of this codebase**. It is an **orphan branch**:
86 commits, no common ancestor with `master` or with our fork (`git merge-base upstream/v3
upstream/master` returns nothing). It started life as a separate project named **`lepton`**
(`mkfs-erofs` → `lepton` → renamed to nydus in `9ac6354f`), is essentially single-author, and its
README carries an explicit *"On-disk formats, CLI interfaces and APIs may still change without
compatibility guarantees — it is not yet ready for production use."*

Layout: `nydus/` (Rust CLI: `build`, `check`, `merge`, `optimize`, `fuse`, `uffd`, `fanotify`),
`nydus-accessor/` (Rust runtime library), `nydusify/` (**Go**, shells out to the `nydus` binary).
No `rafs/`, no `service/`, no `storage/`, no snapshotter.

Its format family is new and deliberately incompatible — `docs/nydus.md` lists "preserve on-disk
compatibility with earlier Nydus image formats (RAFS v5/v6)" as an explicit **non-goal**. Bootstraps
are native EROFS images, not RAFS metadata. Magics: `NDFOOTER` (4 KiB footer at EOF), `NDBLMETA`
(blob meta), `NDGRPMAP` (runtime readiness bitmap) — `LP*` before `373215af`. Old artifacts are
rejected by magic check; there is no migration path.

## Decision: not adopting it

Against this fork, v3 is a large capability regression (v3 column as of `02156def`):

| | our fork | upstream v3 |
|---|---|---|
| containerd snapshotter | yes (`snapshotter/`) | **none** — no gRPC/proxy-plugin at all |
| zran / `targz-ref` | yes, end to end | **none** — gzip is decoded on build input only; every layer is re-encoded |
| backends | registry, localfs, oss, s3, localdisk, http-proxy, mirrors | `local`, `registry`, Dragonfly |
| compressors | lz4, zstd, gzip, none | `{none, zstd, lz4}` + native `erofs-{none,lz4,zstd}` |
| digesters | blake3, sha256 | `{blake3, none}` |
| hot upgrade / takeover | yes | none — start/SIGTERM/exit |
| multi-image per daemon | yes | one process, one image |
| cache invalidation | `invalidate()` (revoke chunk map, then punch) | none |
| chunk dictionary / cross-layer dedup | yes | explicit non-goal |

The zran gap is the decisive one. v3's `nydus build` accepts only a directory
(`ConversionType::DirNydus` is the sole variant), so every conversion fully extracts and re-encodes
each OCI layer. It cannot reference an unmodified gzip layer as its data blob, which is the entire
basis of our node-local acceleration path ([ARCHITECTURE.md](../ARCHITECTURE.md), *Node-Local Acceleration*).

**Do not rebase onto v3, and do not track it as a merge target.** Its value to us is as an
independent second implementation of the fanotify pre-content path to compare against.

## What we took from it

Four real defects on our side, found by that comparison and since fixed:

1. **`FAN_Q_OVERFLOW` was silently swallowed.** `EventFdGuard::new` marked `fd < 0` as answered and
   `process_event_buffer` never looked at the overflow record, so a kernel queue overflow — which
   fail-opens every dropped permission event, serving sparse-file zeros — produced no log line and
   no reaction. Now fatal and loud. ([service/src/fanotify.rs](../service/src/fanotify.rs))
2. **A malformed event stranded the rest of the batch.** A bad `vers` returned `Err` and a bogus
   `event_len` `break`ed, both abandoning every later record in the same `read()` with its fd
   neither answered nor closed — readers wedged in `D` state for the life of the daemon. Parse
   failures are now split into semantic (deny that event, keep walking) and structural (deny what
   is still accountable, then fail closed).
3. **Single unmount attempt at teardown.** One `libc::umount`, `warn!` on `EBUSY`, continue —
   leaving a live mount whose fanotify group fd was about to drop and fail-open. Now a bounded
   retry with a deny-drain between attempts, and the handler is dropped only after the unmount.
   ([service/src/singleton.rs](../service/src/singleton.rs))
4. **Untrusted image mounted with `flags = 0`** (no `nodev`, no `nosuid`) and an unbounded
   `device=` option string against `mount(2)`'s one-page limit, which truncates silently.

Two more from checking v3's beta fixes against the same areas here:

5. **Runtime prefetch never ran on fusedev mounts.** `[snapshotter.features] prefetch` defaulted on
   but nothing read it; the daemon config carried `prefetch.enable = false` for both the cache and
   RAFS sections, so the runtime prefetch list and the bootstrap's prefetch table were discarded.
   v3's "auto" prefetch scope (`6dff1f43`) is what prompted the check.
   ([snapshotter/src/daemon/config_builder.rs](../snapshotter/src/daemon/config_builder.rs))
6. **Unchecked 32-bit arithmetic in the v6 superblock writer.** A blob's end block address
   (`mapped_blkaddr + cnt`) could wrap where the running block-count check passed, and the root
   nid was truncated with `as u16`. Both now fail the build. v3's `74f703c7` is the analogue; its
   other layout fixes (`e26a629c` build-time field, `5ca6e942` symlink inlining, `4155bdda`
   compact-inode mtime, `c10fbbeb` hardlinks across merge) do not apply here.
   ([builder/src/core/v6.rs](../builder/src/core/v6.rs))

## Where we are ahead

Worth knowing so these do not get "fixed" toward v3's behaviour:

- **`FAN_DENY_ERRNO`** — we surface `ENOSPC`/`EDQUOT`/`EIO` honestly. v3 has only `FAN_ALLOW` and
  bare `FAN_DENY`, so a full cache filesystem is indistinguishable from a malformed event, and its
  own docs concede applications do not retry `EPERM`.
- **aarch64-musl correctness** — v3 passes `O_LARGEFILE` to `fanotify_init`, which is the `EINVAL`
  bug we fixed and documented at [service/src/fanotify.rs](../service/src/fanotify.rs) (the Rust
  `libc` value collides with `O_NOFOLLOW` on the aarch64 UAPI).
- **`EMFILE`/`ENFILE`/`ENOMEM` backoff** on the fanotify `read()`. v3 treats these as fatal.
- **Kernel floor.** v3 claims 6.15; every ABI element it uses is from the 6.14 pre-content series,
  and it uses strictly fewer of them than we do. Its own doc contradicts itself on the point. We
  stay at 6.14.
- **Fetch granularity.** We fetch chunk-granular; v3 fetches a whole 4 MiB group per fault with no
  runtime knob. That is read amplification, not a win.

## Ideas worth revisiting (not done)

Ranked. None of these require adopting v3's format.

1. **Skip arming fully-ready blobs — done.** A blob's mark is dropped once its cache is complete,
   restoring kernel readahead, and `FanotifyHandler::invalidate` re-arms the mark as step 0 before
   revoking readiness and discarding bytes (`invalidation_rearms_and_revokes_readiness_before_discarding_bytes`
   pins the order). v3 reached the same design independently at beta.
2. **Request coalescing** on `(blob, aligned_range)`. Container start has many tasks paging the same
   library; today each faulting reader issues its own `fetch_range_uncompressed`.
3. **Chunk/group decoupling.** v3 separates the dedup unit (`chunk_block_bits`, BLAKE3, 1 MiB) from
   the compression/IO unit (`group_block_bits`, zstd, 4 MiB). RAFS v6 conflates them, forcing a
   dedup-ratio vs read-amplification tradeoff. The most interesting architectural idea on the branch.

   We are **not** starting from zero: batch mode already decouples the two,
   but only for small chunks. [builder/src/core/node.rs:550](../builder/src/core/node.rs#L550) packs
   a chunk into a shared compression unit only when the file has exactly one chunk
   (`child_count() == 1`) **and** `d_size < batch_size / 2`; the read side is
   [storage/src/meta/batch.rs](../storage/src/meta/batch.rs) plus `chunk_info_v2.rs`. So it is a
   small-file packer, not a general IO unit, and the dedup granularity is still `chunk_size`.

   Two ports, very different in size:
   - **Cheap, builder-only, no format change**: lift the `child_count() == 1` and
     `d_size < batch_size / 2` restrictions so any run of chunks can share a compression unit.
     The v2 chunk-info format already carries the batch indirection, so nothing on disk changes
     shape. Measurable on real images via the convert cron.
   - **Full decoupling**: let `chunk_size` shrink for dedup while the compressed/IO unit stays
     large. That is a RAFS v6 blob-meta feature flag, builder rework, `cachedfile` read-path
     rework, and a back-compat story. Substantially larger, and it needs the cheap version's
     numbers first.

   **Tension to settle before either.** This document already records (see "Where we are ahead")
   that we fetch chunk-granular while v3 fetches a whole 4 MiB group per fault, and calls that
   "read amplification, not a win". Decoupling buys compression and dedup ratio by moving the IO
   unit **up** — the same direction. On the fanotify path, where a fault should pull the least
   possible, that is a regression unless the read unit stays independent of the compression unit.
   Do not port this as "match v3"; port it only with cold-start numbers on both axes.
4. **Trace-driven `optimize` redirect blob.** v3 records first-access `(blob, group)` order and emits
   a new layer whose groups redirect to `(source_blob_index, source_group_index)`, turning scattered
   cold-start range reads into one sequential fetch. Strictly stronger than the prefetch file list
   `snapshotter/src/prefetch_profile.rs` produces, and it composes with zran rather than conflicting.
5. **Cross-process prefetch election** — `MAP_SHARED` readiness bitmap plus a per-blob `flock` on a
   `.prefetch.lock`, so N concurrent cold starts result in exactly one warming stream.

   Mostly moot for us: our architecture already has what this buys.
   - **The bitmap half already exists.** v3's `nydus-storage/src/group_map.rs` (`LPGRPMAP`) is a
     re-derivation of our [storage/src/cache/state/persist_map.rs](../storage/src/cache/state/persist_map.rs):
     same `MAP_SHARED` mmap (via `utils/src/filemap.rs`), same 4096-byte header, same sticky
     all-ready latch (`MAGIC_ALL_READY` ↔ `GROUP_MAP_FLAG_ALL_READY`), same atomic bit array.
     Groups instead of chunks is the only difference. Nothing to port.
   - **The lock half is portable but buys us little.** v3's
     `nydus-storage/src/cache/group_lock.rs` is 245 lines depending on nothing but `std`, `libc`
     and `tracing` — OFD byte-range locks, one byte per group, per-blob lock file, released by the
     kernel if the holder dies. It is a clean, better design than the `flock` this item proposed.
     But its own doc states the precondition: *"Within a process the caller must already have
     elected a single fetcher"* — which is precisely what
     [storage/src/cache/state/blob_state_map.rs](../storage/src/cache/state/blob_state_map.rs)
     `check_ready_and_mark_pending` + `inflight_tracer` already does for us. v3 needs the
     cross-process layer because it is one process per image (see the capability table above);
     our snapshotter runs **one in-process daemon serving every image on the node**, so
     the second fetcher it would deduplicate does not exist.
   - **Residual value, not worth 245 lines today**: the hot-upgrade/takeover window where two
     daemons briefly share a cache dir, and `nydus-image`/nydusify subprocesses pointed at the
     same cache. Revisit only if takeover is measured re-fetching.
   - Cost if ever wanted: the file ports nearly verbatim; the hook is one `acquire` between
     `check_ready_and_mark_pending` returning not-ready and the backend read at
     [storage/src/cache/cachedfile.rs:1295](../storage/src/cache/cachedfile.rs#L1295). Note we
     are chunk-granular where v3 is 4 MiB-group-granular, so this is one `F_OFD_SETLKW` syscall
     per chunk on the cold path, not per group — measure before believing it is free.
6. **Test cases we lack**, from `tests/integration/fanotify_test.go`: range-boundedness measured via
   allocated blocks on the sparse cache, warm re-read allocating ~nothing, and a fanotify-vs-FUSE
   perf harness with cold-page columns.
7. **Build layer tars the way containerd applies them** (v3 `02156def`). The tarball builder
   diverges from `archive.Apply` in two places: `builder/src/tarball.rs` keeps `..` path
   components (`Path::components().as_path()` does not strip `ParentDir`), and
   `insert_into_tree` (`builder/src/lib.rs`) attaches a member `a/b/f` beneath a node `a` even
   when `a` is a symlink, where containerd resolves through it. On the transparent-accel path a
   silently different tree is the worst possible failure, so the cheap guard comes first: reject
   `..` components and members whose parent resolves to a symlink, and let the image fall back to
   plain overlay. Full `archive.Apply` fidelity (including which hardlink member's metadata wins
   on the shared inode) is the larger follow-up. Nydusify's own archive extraction already rejects
   `ParentDir` (`nydusify/src/engine/oci_archive.rs`).

Not worth porting: concurrent multi-blob reads (`c66b591b`; our per-blob loop in
`rafs/src/fs.rs` only matters for chunk-dict files spanning blobs, never on the fanotify path),
byte-offset readdir cookies (`3540f513`; ordinal cookies are stable on a read-only image), and
the runtime `fetch_size` knob (tied to v3's group layout).
