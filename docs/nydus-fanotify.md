# Nydus on-demand mounts with fanotify pre-content hooks

Nydus serves RAFS v6 images on demand by mounting them as in-kernel **EROFS** filesystems and
filling blob data lazily through **`fanotify` pre-content** events. This replaces the deprecated
EROFS + `fscache` (`cachefiles`) on-demand path, which has been removed.

> **Kernel floor:** Linux **≥ 6.14** with `CONFIG_FANOTIFY=y` and
> `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`. The `FAN_CLASS_PRE_CONTENT` / `FAN_PRE_ACCESS` API is
> only available from 6.14 onward. On older kernels, use the FUSE fallback (`nydusd fuse`).

## How it works

1. The daemon opens a fanotify group with `FAN_CLASS_PRE_CONTENT` and places a `FAN_PRE_ACCESS`
   mark — **only** that; never `FAN_OPEN_PERM`, which would block every open including the
   daemon's own — on each sparse data blob in the staging directory whose cache is not already
   complete. A blob that is already fully cached is left unmarked, and a blob is unmarked again
   as soon as its cache fills: a pre-content mark suppresses kernel readahead on the file it
   guards, so keeping one over a complete blob would slow down precisely the reads that no
   longer need the daemon. Marks are placed on the cache file's own descriptor rather than on
   the `blob_<i>` device path; the two are hardlinks to one inode.
2. It mounts the image with the in-kernel EROFS driver. The **bootstrap is the mount source**; the
   data blobs are `device=` options in device-table order, each set with its own `fsconfig(2)`
   call (`source=<bootstrap>`, `ro`, `device=<blob0>`, `device=<blob1>`, …), then `fsmount(2)`
   with `MOUNT_ATTR_RDONLY|NODEV|NOSUID` and `move_mount(2)`. A missing source fails with
   `EINVAL`, and the bootstrap is not itself a `device=` entry. `mount(2)` would silently
   truncate the joined option string at one page, which an image with ~45 layers under a deep
   cache directory exceeds; per-option `fsconfig` has no total limit, only 255 bytes per path.
3. When a process reads a region of the rootfs that is not yet present, the kernel raises a
   `FAN_PRE_ACCESS` event carrying the **byte range** (`offset`, `count`) and an fd to the backing
   blob file.
4. The handler resolves the fd to the owning blob, downloads + decompresses exactly that range via
   the blob cache (`fetch_range_uncompressed`) into the sparse file, then answers `FAN_ALLOW`.
   On a fetch/write failure it answers `FAN_DENY_ERRNO(e)` — passing through `ENOSPC`/`EDQUOT`/`EIO`
   so a full cache filesystem is distinguishable from an I/O error — and the consumer gets a real
   error instead of silently reading zeros.

   The **denial** is what the consumer depends on; the **errno** mostly does not reach it. Measured
   on Linux 7.0.11 (`misc/fanotify/precontent-cases.sh` C13): a process reading the marked blob file
   directly receives the exact errno, but a process reading through the EROFS mount always receives
   `EIO`, because EROFS pulls the backing file through the page cache and the outer read only sees
   that the folio is not uptodate. The specific errno is therefore an observability property today
   (daemon logs, direct readers) rather than something containers can branch on.

   **The fusedev path answers disk pressure the other way round**, because there the cache is only
   an accelerator rather than the device being read: `delay_persist_chunk_data` writes it from a
   detached task while the read is served out of the in-memory buffer, so a failed cache write never
   reaches the reader at all. The chunk is left not-ready instead of being marked ready, so a later
   read re-fetches rather than being served the sparse hole, and the only operator-visible signal is
   the daemon's log line — which is why that line names the errno. Covered by
   `misc/fusedev/disk-pressure.sh`.

Every permission event must be answered, and the daemon is written so that no path can leave one
outstanding: a panic during handling denies via `EventFdGuard::drop`, a structurally corrupt event
buffer denies everything still parsable before failing, and shutdown drains and denies whatever is
queued before the group fd closes. A `FAN_Q_OVERFLOW` record is treated as fatal — the kernel
fail-opens the events it dropped, so continuing would mean knowingly serving unfetched zeros.

### Fill validation

The kernel reads the cache file directly, so nothing checks its bytes on the way out; they are
checked on the way in. A fanotify cache (`cache_type = "fanotify"`) validates every chunk it fills
against its digest whatever `cache.validate` says, and a chunk that fails is never marked ready: the
event is denied with `EIO` and the next read fetches again. The digests are the bootstrap's own,
from its chunk table (`kernel_layout::chunk_digest_tables`), supplied by `FanotifyHandler` when it
is built, so zran, tar-ref and zstd-ref blobs, whose blob meta carries no digests, are validated
too. The digests are recorded next to the cache file (`<blob_id>.blob.data.digests`), so
construction fails when the chunk table records one chunk twice differently, when a chunk's extent
disagrees with the blob meta, or when any bootstrap sharing the blob, now or in an earlier daemon,
named another digest for a chunk. Chunks no bootstrap references are left out of fills, and a read
that needs one is denied.

Chunks already marked ready when a cache file is opened were not necessarily validated (a cache
filled by an older daemon or by a non-validating opener). A low-priority thread per handler checks
each of them once while serving goes on; a chunk that fails is revoked like an invalidation of that
one chunk (mark re-armed, ready bit cleared, bytes punched, under the blob's exclusive `io_lock`),
so a blob whose mark was already dropped is guarded again before anything is discarded. When every
ready chunk has passed, the chunk map header records the file as verified, which
`BlobObject::is_data_verified` reports; an opener that fills without validating clears it.

`kernel_layout::check_kernel_layout` proves the other half: that for each regular file the kernel's
chunk indexes (format, device id, block address, chunk size, device range) name exactly the chunks
the fill path validates. `nydus-image check` runs it.

Implementation: [`service/src/fanotify.rs`](../service/src/fanotify.rs) (`FanotifyHandler`) and the
local FFI shim [`service/src/fanotify_sys.rs`](../service/src/fanotify_sys.rs) (the `nix` crate does
not yet expose the pre-content API).

## On-disk layout

The staging directory passed to the daemon contains the bootstrap and the (initially sparse) data
blobs. The blob files must be the same files the EROFS mount reads, i.e. the blob cache's working
directory is the staging directory:

```
<blob_dir>/
├── bootstrap          # RAFS v6 metadata (fully materialized)
├── blob_<sha256-a>    # sparse data blob, filled on demand
├── blob_<sha256-b>
└── …
```

The bootstrap is always present; only `blob_*` files are filled lazily.

## Running the daemon

```bash
nydusd \
  --fanotify <blob_dir> \
  --fanotify-mountpoint <mountpoint> \
  --fanotify-threads 4 \
  --config /etc/nydus/nydusd-config.toml
```

- `--fanotify <blob_dir>` — staging directory holding `bootstrap` + `blob_*`.
- `--fanotify-mountpoint <path>` — where the EROFS filesystem is mounted.
- `--fanotify-threads <n>` — number of worker threads draining fanotify events.

## Block size and host page size

The EROFS logical block size may be smaller than or equal to the host page size; current kernels
mount sub-page blocks, but reject a block size larger than the page size. `4096`, the default of
`nydus-image create --block-size <bytes>`, is therefore the portable choice and mounts on every
host below. A page-sized block size is supported as well:

| Host page size | Mountable `--block-size` | Typical hosts |
| --- | --- | --- |
| 4 KiB  | `4096` | x86_64, Raspberry Pi 4 |
| 16 KiB | `4096`, `16384` | Apple Silicon, Raspberry Pi 5 (16K page config) |
| 64 KiB | `4096`, `16384`, `65536` | some aarch64 / ppc64le distros |

A single `nydusd` / `nydus-image` binary handles all three at runtime; the size is recorded in the
RAFS v6 superblock (`s_blkszbits`). The builder starts every chunk on a block boundary and sizes
each device table entry to cover its whole blob, since the kernel locates data only through block
addresses. `runtime-test.sh` and `export-block-test.sh` take `BLOCK_SIZE=` to verify a block size
in the kernel.

### File-backed EROFS partial-folio metadata bug

Linux 7.3 (from e587a984d332) reads the metadata of a file-backed EROFS mount one page-cache folio
at a time and fails the read with `EIO` ("failed to read inode meta block") when that folio runs
past the end of the image file. Fixed upstream by `52dceb88082b` ("erofs: fix metadata reads at the
end of file-backed images", 7.4-rc1, marked for stable); 7.3.1 does not carry it. The metadata
folio is always one page, so the trigger is any image whose length is not a multiple of the host
page size:

- 4 KiB-block images on 16K-page (arm64, LoongArch) and 64K-page (arm64, ppc64le) kernels;
- 512-byte-block (tarfs) images on every page size, 4K included.

An image whose block size equals the page size is safe, because its length is a block multiple.
Inodes in the last, partial page return `EIO` (a container then fails with errors like
`mkdir /etc: Input/output error`); an image smaller than one page does not mount at all. Data
reads are not affected: they are clamped to the inode size and never read past the extent they
map, and the data blobs (`device=`) carry no metadata, so the `.blob.data` cache files need nothing.

Mitigation, in `nydus_service::erofs_folio`:

| File-backed EROFS mount | Source | Handling |
| --- | --- | --- |
| Auto-accel / fanotify (snapshotter) | staged bootstrap copy | padded to a page multiple with a sparse hole (`stage_bootstrap`) |
| Blockdev and tarfs without dm-verity (snapshotter) | exported `image.erofs` | padded at export (`BlockDevice::export`) and before the mount (`mount_blockdev_erofs`), so a cached image that is not a page multiple is covered too |
| `nydus-image export --block` | the exported `.disk` | padded to a 64 KiB multiple (`EXPORT_ALIGNMENT`, the largest page size) at export, with or without `--verity`: EROFS reads only the blocks the superblock names, dm-verity only `--data-blocks` and the tree at `--hash-offset` |
| Tarfs with dm-verity | dm block device | not file-backed: unaffected |
| Regular nydus images (snapshotter) | FUSE | not EROFS: unaffected |
| `nydusd --fanotify` (standalone) | the caller's `bootstrap` | left untouched; when it is not a page multiple, `mount_erofs` mounts an anonymous padded copy (`O_TMPFILE` in the bootstrap's directory, named by its `/proc/self/fd` link), or, where `O_TMPFILE` or that link is unavailable, a named copy it removes once mounted. Nothing is left behind; the mount table shows `/proc/self/fd/<n>` as the source. |
| Live mounts adopted on restart | staged bootstrap or `image.erofs` | at startup, before adoption, the snapshotter pads every unaligned regular-file source of a live EROFS mount under its `daemons/` dir in place. The kernel retries a failed metadata read on the next access, so the live mount reads cleanly without a remount, and running containers keep working. |

The hole costs no disk blocks and reads back as zeros, which is what a fixed kernel substitutes for
the missing bytes, so padding is applied on every kernel. To tell whether a kernel is affected
(distros backport, so the version alone does not decide it), the snapshotter runs a self-test once
at startup in the cache `work_dir`: it mounts a crafted 2 KiB image (512-byte blocks, smaller than
any page) file-backed, once as is and once padded, and reads every inode. The unpadded image failing
while the padded one reads cleanly means affected. The result is logged (a `WARN` naming the
kernel, the page size and the fix when affected) and exported as
`nydus_snapshotter_erofs_partial_folio_bug{status="affected|unaffected|inconclusive"} 1`.
`inconclusive` means the probe could not mount at all (no privilege, no file-backed EROFS, or a
10 s timeout). The mount health probe reads both metadata and file data, so a mount that answers
with `EIO` for any other reason is reported as dead rather than passing.

[`misc/erofs-folio/qemu-test.sh`](../misc/erofs-folio/qemu-test.sh) boots an arm64 kernel in QEMU
and runs the self-test (`service/examples/erofs_folio_probe.rs`) in it, optionally walking an
EROFS image as is and padded, to check how a kernel build classifies.

CI (`.github/workflows/fanotify-vm.yml`) runs the self-test and walks an image from
`misc/erofs-folio/demo-image.sh` on every kernel it boots: the 4K-page amd64 matrix with a
512-byte-block image, and Ubuntu's 64K-page arm64 builds of 7.3.1 and 7.4-rc1 under QEMU with a
4K-block image. `misc/erofs-folio/expect.sh` fails the job unless the verdict is the one the matrix
lists for that kernel (affected for 7.3.1, unaffected for the others), the padded copy reads
cleanly, and the unpadded one fails exactly on an affected kernel.

## Cache eviction

`FanotifyHandler::cull_cache(blob_id)` punches holes
(`FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`) in a blob's sparse file, deallocating cached extents
while keeping the file size so later accesses re-fetch on demand.

## Runtime verification

[`misc/fanotify/runtime-test.sh`](../misc/fanotify/runtime-test.sh) is an end-to-end test: it builds
a RAFS v6 image, stages it so the EROFS device file and the blob cache's `.blob.data` file share one
inode, mounts via `nydusd --fanotify`, reads files back, and asserts the `sha256` matches the source
(and that the sparse cache file gained allocated blocks, proving the bytes were fetched on demand).
It needs root (for `mount(2)`), kernel ≥ 6.14, and a non-tmpfs work dir:

```bash
sudo NYDUS_IMAGE=./target/release/nydus-image NYDUSD=./target/release/nydusd \
  ROOT=/var/tmp/fan-rt misc/fanotify/runtime-test.sh
```

[`misc/fanotify/precontent-cases.sh`](../misc/fanotify/precontent-cases.sh) covers the two
behaviours a byte-comparison cannot: that a cold read **fails closed** when the backend is
unreachable (rather than hanging or leaking the sparse file's zeros), and — under `strace` — that
the daemon is mechanically on the read path (`fanotify_init`/`fanotify_mark` succeeded, events were
read off the group fd, responses were written back, and fetched bytes were `pwrite(2)`'d into the
blob cache file). Same requirements, plus `strace(1)`:

```bash
sudo NYDUS_IMAGE=./target/release/nydus-image NYDUSD=./target/release/nydusd \
  ROOT=/var/tmp/fan-precontent misc/fanotify/precontent-cases.sh
```

> **Layout invariant:** the kernel-visible EROFS device file *must be the same inode* as the blob
> cache's `<blob_id>.blob.data` file, or the on-demand fill will not be visible to the mount. The
> blob-cache `work_dir` is therefore the staging directory, and the producer must arrange the device
> file and the cache file to be one inode.

## Page cache sharing

`cache_config.erofs_inode_share_domain` mounts the image with
`inode_share,domain_id=<domain>`: on Linux 7.0+ files whose fingerprint xattrs are equal share
one page cache across all mounts of the domain, so a library used by many images is cached once.
The image needs fingerprints (`nydus-image merge --inode-share-fingerprint`); without them the
kernel mounts normally. A kernel that rejects the options (`EINVAL`, before 7.0) is mounted
without them. Shared mmaps need the fix "erofs: hold real inodes for shared files" (mainline
`7259fb011c14`, 7.4; or a backport): without it, a page fault on a mapping whose file was closed
and whose real inode was evicted dereferences a NULL inode, a kernel oops.
`misc/fanotify/inode-share-test.sh` checks the sharing in the kernel.

The snapshotter sets the domain only for auto-accel images this node built, under
`[snapshotter.features] erofs_inode_share` (`auto`, `on`, `off`). `auto` enables it when the
startup self-test (`nydus_service::erofs_ishare`) finds both:

- **support**: a tiny file-backed probe image mounts with `inode_share,domain_id=…`, and
  `inode_share` without `domain_id` fails `EINVAL` (a kernel built without
  `CONFIG_EROFS_FS_PAGE_CACHE_SHARE` ignores both options; one before 7.0 rejects both);
- **the fix**: `/proc/kallsyms` lists `erofs_ishare_backing_release`, the `release` hook the fix
  adds. Triggering the bug itself would oops the kernel, so the probe never does.

It does not compare kernel versions, so a backport counts as fixed. Without kallsyms the result is
`inconclusive` and `auto` stays off; `on` enables sharing regardless, and `off` skips the self-test.
The self-test runs in the background at startup; auto-accel mounts made before it finishes go
without sharing. The startup log and the `nydus_snapshotter_erofs_inode_share{status,mode,enabled}`
gauge report the outcome (`status` is `fix_present`, `fix_absent`, `unsupported` or
`inconclusive`).

## Troubleshooting

- **Reads return `EIO`** — the daemon failed to fetch a range (backend/network error). Check
  `nydusd` logs and backend connectivity.
- **`mount: erofs … wrong fs type`** — the bootstrap's block size is larger than the host page
  size; rebuild with `--block-size 4096` or the host's page size.
- **No events / hangs on first read** — the kernel is below 6.14 or
  `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is not enabled; fall back to `nydusd fuse`.
