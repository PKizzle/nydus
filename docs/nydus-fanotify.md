# Nydus on-demand mounts with fanotify pre-content hooks

Nydus serves RAFS v6 images on demand by mounting them as in-kernel **EROFS** filesystems and
filling blob data lazily through **`fanotify` pre-content** events. This replaces the deprecated
EROFS + `fscache` (`cachefiles`) on-demand path, which has been removed.

> **Kernel floor:** Linux **≥ 6.14** with `CONFIG_FANOTIFY=y` and
> `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`. The `FAN_CLASS_PRE_CONTENT` / `FAN_PRE_ACCESS` API is
> only available from 6.14 onward. On older kernels, use the FUSE fallback (`nydusd fuse`).

## How it works

1. The daemon opens a fanotify group with `FAN_CLASS_PRE_CONTENT` and places a
   `FAN_PRE_ACCESS | FAN_OPEN_PERM` mark on every sparse blob file in the staging directory.
2. It mounts the image with the in-kernel EROFS driver, referencing the bootstrap and blobs as
   multiple devices:
   `mount("none", <mountpoint>, "erofs", 0, "device=<bootstrap>,device=<blob0>,device=<blob1>,…")`.
3. When a process reads a region of the rootfs that is not yet present, the kernel raises a
   `FAN_PRE_ACCESS` event carrying the **byte range** (`offset`, `count`) and an fd to the backing
   blob file.
4. The handler resolves the fd to the owning blob, downloads + decompresses exactly that range via
   the blob cache (`fetch_range_uncompressed`) into the sparse file, then answers `FAN_ALLOW`.
   On a fetch/write failure it answers `FAN_DENY_ERRNO(EIO)` so the consumer sees a real I/O error
   instead of silently reading zeros.

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

EROFS requires the filesystem logical block size to equal the host page size. Build the bootstrap
for the target host with `nydus-image create --block-size <bytes>`:

| Host page size | `--block-size` | Typical hosts |
| --- | --- | --- |
| 4 KiB  | `4096`  | x86_64, Raspberry Pi 4 |
| 16 KiB | `16384` | Apple Silicon, Raspberry Pi 5 (16K page config) |
| 64 KiB | `65536` | some aarch64 / ppc64le distros |

A single `nydusd` / `nydus-image` binary handles all three at runtime; the size is recorded in the
RAFS v6 superblock (`s_blkszbits`). Mounting a bootstrap whose block size does not match the host
page size is rejected by the EROFS driver, so build per target page size.

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

> **Layout invariant:** the kernel-visible EROFS device file *must be the same inode* as the blob
> cache's `<blob_id>.blob.data` file, or the on-demand fill will not be visible to the mount. The
> blob-cache `work_dir` is therefore the staging directory, and the producer must arrange the device
> file and the cache file to be one inode.

## Troubleshooting

- **Reads return `EIO`** — the daemon failed to fetch a range (backend/network error). Check
  `nydusd` logs and backend connectivity.
- **`mount: erofs … wrong fs type`** — the bootstrap's block size does not match the host page
  size; rebuild with the matching `--block-size`.
- **No events / hangs on first read** — the kernel is below 6.14 or
  `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is not enabled; fall back to `nydusd fuse`.
