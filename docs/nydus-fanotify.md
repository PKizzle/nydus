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
   data blobs are `device=` options in device-table order:
   `mount("<bootstrap>", <mountpoint>, "erofs", MS_RDONLY|MS_NODEV|MS_NOSUID,
   "device=<blob0>,device=<blob1>,…")`. A `NULL`/`"none"` source fails with `EINVAL`, and the
   bootstrap is not itself a `device=` entry. The option string is capped at one page, so a deep
   cache directory with many blobs is rejected up front rather than silently truncated.
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
without them. Shared mmaps need the 7.4 fix "erofs: hold real inodes for shared files" (or a
stable kernel carrying it). `misc/fanotify/inode-share-test.sh` checks the sharing in the kernel.

The snapshotter sets the domain only for auto-accel images this node built, under
`[snapshotter.features] erofs_inode_share` (`auto`: kernel 7.4+, `on`, `off`).

## Troubleshooting

- **Reads return `EIO`** — the daemon failed to fetch a range (backend/network error). Check
  `nydusd` logs and backend connectivity.
- **`mount: erofs … wrong fs type`** — the bootstrap's block size is larger than the host page
  size; rebuild with `--block-size 4096` or the host's page size.
- **No events / hangs on first read** — the kernel is below 6.14 or
  `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is not enabled; fall back to `nydusd fuse`.
