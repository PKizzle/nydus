# Evaluating upstream's `v3` branch

*Assessed 2026-07-25 against `upstream/v3` @ `3f9e12ed`. Re-check before acting on any of this —
the branch is young and moving.*

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
| cache invalidation | `cull_cache()` | none |
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
   and simply never consult it from `handle_event`. **Blocker:** it interacts with `cull_cache()` —
   an unmarked blob whose cache is later punched would serve zeros, so any port must re-`fanotify_mark`
   inside `cull_cache` or gate the skip on culling being disabled.
2. **Request coalescing** on `(blob, aligned_range)`. Container start has many tasks paging the same
   library; today each faulting reader issues its own `fetch_range_uncompressed`.
3. **Chunk/group decoupling.** v3 separates the dedup unit (`chunk_block_bits`, BLAKE3, 1 MiB) from
   the compression/IO unit (`group_block_bits`, zstd, 4 MiB). RAFS v6 conflates them, forcing a
   dedup-ratio vs read-amplification tradeoff. The most interesting architectural idea on the branch.
4. **Trace-driven `optimize` redirect blob.** v3 records first-access `(blob, group)` order and emits
   a new layer whose groups redirect to `(source_blob_index, source_group_index)`, turning scattered
   cold-start range reads into one sequential fetch. Strictly stronger than the prefetch file list
   `snapshotter/src/prefetch_profile.rs` produces, and it composes with zran rather than conflicting.
5. **Cross-process prefetch election** — `MAP_SHARED` readiness bitmap plus a per-blob `flock` on a
   `.prefetch.lock`, so N concurrent cold starts result in exactly one warming stream.
6. **Test cases we lack**, from `tests/integration/fanotify_test.go`: range-boundedness measured via
   allocated blocks on the sparse cache, warm re-read allocating ~nothing, and a fanotify-vs-FUSE
   perf harness with cold-page columns.

## Unrelated follow-up

Upstream `29ab52f7` fixed a tar path-traversal (Zip-Slip) in the Go nydusify we deleted. The commit
does not apply, but the bug class might: audit `nydusify/src/engine/artifact.rs` and
`snapshotter/src/local_accel.rs` for `../` sanitisation on tar entry names before extraction.
