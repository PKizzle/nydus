# Evaluating upstream's `v3` branch

*Assessed 2026-07-25 against `upstream/v3` @ `3f9e12ed`. Re-check before acting on any of this —
the branch is young and moving.*

> **Re-checked 2026-08-16** (`upstream/v3`, 147 commits, tag `v3.0.0-alpha.1`). The decision below
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
>   means adopting a second on-disk format beside RAFS v5/v6. **Not doing it.**
> - Item #5 below has been costed and largely dissolved; item #3 has been costed. See both.

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
are native EROFS images, not RAFS metadata. Magics: `LPFOOTER` (4 KiB footer at EOF), `LPBLMETA`
(blob meta), `LPGRPMAP` (runtime readiness bitmap). Old artifacts are rejected by magic check; there
is no migration path.

## Decision: not adopting it

Against this fork, v3 is a large capability regression:

| | our fork | upstream v3 |
|---|---|---|
| containerd snapshotter | yes (`snapshotter/`) | **none** — no gRPC/proxy-plugin at all |
| zran / `targz-ref` | yes, end to end | **none**, and structurally impossible — no gzip/deflate dependency exists in the crate |
| backends | registry, localfs, oss, s3, localdisk, http-proxy, mirrors | `local` + `registry` only |
| compressors | lz4, zstd, gzip, none | `{none, zstd}` |
| digesters | blake3, sha256 | `{blake3}` |
| hot upgrade / takeover | yes | none — start/SIGTERM/exit |
| multi-image per daemon | yes | one process, one image |
| cache invalidation | `invalidate()` (revoke chunk map, then punch) | none |
| chunk dictionary / cross-layer dedup | yes | explicit non-goal |

The zran gap is the decisive one. v3's `nydus build` accepts only a directory
(`ConversionType::DirNydus` is the sole variant), so every conversion fully extracts and re-encodes
each OCI layer. It cannot reference an unmodified gzip layer as its data blob, which is the entire
basis of our node-local acceleration path ([CLAUDE.md](../CLAUDE.md#node-local-acceleration)).

**Do not rebase onto v3, and do not track it as a merge target.** Its value to us is as an
independent second implementation of the fanotify pre-content path to compare against.

## What we took from it

Four real defects on our side, found by that comparison and fixed in the same change as this
document:

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

1. **Skip arming fully-ready blobs.** A pre-content mark disables kernel readahead on that file, so
   dropping the mark once a blob is fully cached restores it — a larger win than any per-event
   saving. We already own the latch (`storage/src/cache/state/persist_map.rs`, `MAGIC_ALL_READY`)
   and simply never consult it from `handle_event`.

   This used to be listed as blocked on `cull_cache()`: an unmarked blob whose cache was later
   punched would serve zeros. That blocker is now **structural rather than incidental**, which makes
   the port tractable. `cull_cache` has been replaced by `FanotifyHandler::invalidate`, the single
   function through which cached bytes may be discarded, and it already owns the general invariant:
   *every promise that data is present must be revoked before the data goes away*. It revokes the
   chunk map first (`BlobObject::reset_data_ready`), then punches, under a per-blob `io_lock` that
   also excludes in-flight fetches.

   So a skip-arming port has one requirement: un-arming must be recorded on the `BlobBacking`, and
   `invalidate` must re-`fanotify_mark` as step 0, before the revoke. Landing it anywhere else
   reintroduces the hazard; landing it there cannot, because `invalidate` is the only path that
   discards bytes. See the ordering rationale on `invalidate` and the two `invalidate_in_order`
   tests, which pin the sequence and the fail-closed behaviour when the revoke fails.
2. **Request coalescing** on `(blob, aligned_range)`. Container start has many tasks paging the same
   library; today each faulting reader issues its own `fetch_range_uncompressed`.
3. **Chunk/group decoupling.** v3 separates the dedup unit (`chunk_block_bits`, BLAKE3, 1 MiB) from
   the compression/IO unit (`group_block_bits`, zstd, 4 MiB). RAFS v6 conflates them, forcing a
   dedup-ratio vs read-amplification tradeoff. The most interesting architectural idea on the branch.

   *Costed 2026-08-16.* We are **not** starting from zero: batch mode already decouples the two,
   but only for small chunks. [builder/src/core/node.rs:550](../builder/src/core/node.rs#L550) packs
   a chunk into a shared compression unit only when the file has exactly one chunk
   (`child_count() == 1`) **and** `d_size < batch_size / 2`; the read side is
   [storage/src/meta/batch.rs](../storage/src/meta/batch.rs) plus `chunk_info_v2.rs`. So it is a
   small-file packer, not a general IO unit, and the dedup granularity is still `chunk_size`.

   Two ports, very different in size:
   - **Cheap, builder-only, no format change**: lift the `child_count() == 1` and
     `d_size < batch_size / 2` restrictions so any run of chunks can share a compression unit.
     The v2 chunk-info format already carries the batch indirection, so nothing on disk changes
     shape. Measurable today on real images via the convert cron; a day's work plus numbers.
   - **Full decoupling**: let `chunk_size` shrink for dedup while the compressed/IO unit stays
     large. That is a RAFS v6 blob-meta feature flag, builder rework, `cachedfile` read-path
     rework, and a back-compat story. Weeks, and it needs the cheap version's numbers first.

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

   *Costed 2026-08-16 — mostly moot for us; do not schedule it.* Both halves were re-derived,
   and the conclusion is that our architecture already has what this buys.
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
     our snapshotter runs **one in-process daemon serving every image on the node**
     (CLAUDE.md gotcha #6), so the second fetcher it would deduplicate does not exist.
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

## Unrelated follow-up

Upstream `29ab52f7` fixed a tar path-traversal (Zip-Slip) in the Go nydusify we deleted. The commit
does not apply, but the bug class might: audit `nydusify/src/engine/artifact.rs` and
`snapshotter/src/local_accel.rs` for `../` sanitisation on tar entry names before extraction.
