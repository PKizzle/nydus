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
event is denied with `EIO`, the failure is logged with the blob id (as an error once a blob has had
more than three) and counted in the blob cache metric `digest_mismatches`, and the next read fetches
again. Legacy stargz and external blobs carry no digests, so a fanotify cache refuses them. The
digests are the bootstrap's own, from its chunk table (`kernel_layout::chunk_digest_tables`),
supplied by `FanotifyHandler` when it is built, so zran, tar-ref and zstd-ref blobs, whose blob meta
carries no digests, are validated too. Construction fails when the chunk table records one chunk
twice differently or a chunk's extent disagrees with the blob meta (checked again at every fill, as
the meta may not be loaded yet).

Chunks no bootstrap of the daemon references (the dead chunks of a layer whose files an upper layer
deleted or replaced) are never filled, validated or marked ready, and a read spanning one is served
once every referenced chunk it spans is ready: their bytes stay a hole, or an older fill nobody
validated, in the cache file, but they are never file data. EROFS maps a file's data only through
its chunk indexes, each to the device blocks of one referenced chunk (`check_kernel_layout`), and
zeroes what lies past them, so their bytes can reach the backing file's page cache but never a
file's pages. On a host with pages larger than the EROFS block, or under readahead, a pre-content
event routinely spans such a chunk next to a referenced one. A blob with unreferenced chunks never
counts as fully cached, so its mark stays armed. A chunk a bootstrap references at another extent
than the blob meta's still fails the read.

The digests are recorded next to the cache file (`<blob_id>.blob.data.digests`, checksummed; a
corrupt file is discarded and re-derived). A recorded digest binds only chunks that are ready, since
those were validated against it: a bootstrap, in this daemon or a later one, that names another
digest for a ready chunk fails construction, while one for a chunk not yet cached replaces it.

Chunks already marked ready when a cache file is opened were not necessarily validated (a cache
filled by an older release or by a non-validating opener). A low-priority thread per handler checks
each of them once while serving goes on. A chunk that fails is revoked: under the blob's exclusive
`io_lock` the mark is re-armed, then the storage layer clears the ready bit and punches the bytes
out while holding the chunk pending, so no fill of it can complete in between, and finally the
mounted files that use the chunk are dropped from the page cache (`POSIX_FADV_DONTNEED`). That last
step is needed: on Linux 7.2, a file-backed EROFS file keeps serving pages it read before its
backing range was punched, and only `DONTNEED` on the mounted file, not on the device file, evicts
them. Pages a process has mapped stay until it unmaps them. A ready chunk that no bootstrap of the
daemon references is left alone and keeps the blob unverified: the verified stamp outlives the
daemon, and a later bootstrap referencing the chunk would trust it unchecked.

Re-arming only works for a mount that opened the blob while it was marked: the kernel decides at
open whether a file raises pre-content events at all. So `arm()` leaves a complete blob unmarked
only once its cache is verified, a blob is unmarked after filling only once verified too, and
`mount()` records, per blob, the unique id of the mount that opened it marked
(`<blob_id>.blob.data.marked-mount`). A successor that takes the mount over (restart takeover,
in-place heal) can revoke exactly when the record names the live mount. Otherwise, as for a
verified blob the mount opened unmarked whose cache file was changed on disk since, a failing chunk
cannot be revoked without serving a hole: it is logged as an error with blob and chunk, counted in
`unrevoked_chunks`, the check goes on to report the others, the blob stays unverified, and the bad
bytes stay served until the image is mounted again. On-disk corruption of a verified, unmarked
blob therefore needs a remount.

When every ready chunk has passed, the chunk map header records the file as verified, which
`BlobObject::is_data_verified` and `FanotifyHandler::is_blob_verified` report (one `fstat` and a few
atomic loads). The record holds only while the header's count of ready chunks matches the bitmap
and the cache file's change time and size match a stamp this version refreshes after each of its
own writes, so a release that predates the record cannot fill, or invalidate and refill, the file
without it reading as unverified. Openers that fill without validating clear it.

### Seal and crash recovery

Cache data and chunk map reach the disk through writeback, in no particular order, so after a power
loss the map can claim chunks whose bytes never left the page cache, and the kernel would read
them as zeros. Every opener of a chunk map therefore records in its header (`unsealed_boot`) the
boot (`/proc/sys/kernel/random/boot_id`) in which it fills the cache, flushed before the first
ready bit of that boot, and a fanotify daemon seals the cache when it stops cleanly:

- **Fill.** Before a fanotify fill fetches anything, and before every ready bit any opener sets,
  the header must name the current boot with a flush in this process behind it; when it does not,
  it is set and the map flushed first, and a failure fails the fill with its errno (a failed flush
  is retried by the next ready bit). Checking costs two atomic loads; the flush happens once per
  blob per seal and process.
- **Seal** (`BlobObject::seal`, from `FanotifyHandler::seal`). The data file is flushed
  (`fdatasync`), then the header cleared and the map flushed. Ready bits wait for a seal in
  progress (a lock per map file, shared by every opener in the process), so none is set between
  the flush and the clearing; a fill after the seal unseals the map again first. Two processes
  filling the same cache at once are not supported: nothing orders one's seal against the other's
  ready bits. The verified stamp is refreshed at the same time, when the map is verified, its
  ready count is current and the file's change time is the latest this cache saw after its own
  writes: that repairs a stamp concurrent fills stored out of order, and leaves a file something
  else wrote since unverified. Any error leaves the cache unsealed. A daemon seals when its
  handlers stop (after the workers stop and before the queue is drained, so events raised during
  the flush are denied rather than allowed when the group closes) or are unregistered (after the
  unmount, draining again if it failed), and the snapshotter seals every instance whose group it
  parks for a successor at shutdown, so a clean reboot keeps the caches trusted. A failed handler
  is never sealed, nor one a heal or takeover suspends (its successor serves the same caches), nor
  anything from `Drop`.
- **Open.** A fanotify cache whose header names another boot, or whose map no release tracking
  boots created (header word `tracked` unset: an older release made it), forgets its ready chunks
  and its verified record, keeps the data file, turns on `recheck` in the header and marks the map
  tracked. One that names this boot (a killed or healed daemon, a takeover) keeps everything: the
  page cache still holds whatever was written. Other openers only record their boot.
- **Recheck.** While `recheck` is on, a fill of a chunk not ready first reads the bytes the data
  file already holds for it (an extent that is all hole is skipped with `SEEK_DATA`) and marks it
  ready without a backend request when they match the digest the bootstrap gives it; otherwise it
  fetches as usual. A chunk without a digest is never marked ready this way. `recheck` turns off
  once every chunk is ready.

Not detected: storage rolled back, or remounted with older contents, within one boot (the boot is
the same, so the cache is trusted); devices that acknowledge a flush without making the data
durable; and a root attacker, who can rewrite the cache file and the map alike (and the staged
bootstrap). A write to the cache file between a fill's write and its `fstat` is also folded into
that fill's stamp.

Older releases leave the header words alone and do not set them. A map an older release created
is rechecked once, on its first fanotify open by this release. A map this release sealed and an
older one filled afterwards still reads as sealed, so those fills are as exposed to a power loss
as they were with that release; a map left unsealed reads as another boot's after the next reboot
and is rechecked.

`kernel_layout::check_kernel_layout` proves the other half: that for each regular file the kernel's
chunk indexes (format, device id, block address, chunk size, device range) name exactly the chunks
the fill path validates. `nydus-image check` runs it; page cache sharing must run it at mount time,
together with `is_blob_verified` for every device.

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

## Which images the snapshotter mounts with fanotify

On a node whose active driver is fanotify, the snapshotter serves both node-local auto-accel
sidecars (localfs backend over containerd's content store) and nydus images pulled from a
registry or object store (the configured pull backend, with the same credentials, mirrors and
timeouts the FUSE path uses) through fanotify. A pulled image is checked first
(`serving_driver` and `kernel_mount_unfit`, `snapshotter/src/daemon/mod.rs`) at every start of
its daemon, including restarts, recoveries, rebuilds and upgrades, and takes FUSE instead when
any of these holds:

- a `containerd.io/snapshot/nydus-fs-driver` label asks for another driver. The label is kept in
  the daemon record, so a restarted daemon keeps the driver `Prepare` gave it;
- its bootstrap is RAFS v5, which EROFS cannot mount;
- its EROFS block size exceeds the host page size;
- it has data blobs but no EROFS device table;
- its chunk layout is not kernel-consistent: a chunk whose `blkaddr * block_size` differs from its
  uncompressed offset, or that runs past its device slot (`RafsSuper::check_v6_block_addrs`, the
  check `nydus-image check` runs). The kernel follows only the block address while FUSE reads the
  chunk table, so such an image would be misread silently; 16K/64K-block images built before chunk
  starts were padded to the block size have this layout;
- the snapshotter's `daemons` dir, which holds the fanotify caches, is on a filesystem without
  pre-content marks (probed once, on the first such start; the driver probe tests only the cache
  `work_dir`).

The reason is logged at `info` (at `warn` when a label asked for fanotify). A bootstrap that
cannot be read or loaded is not a reason: the start fails and is retried, since FUSE could not
serve it either.

A live fanotify mount at the image's mountpoint (its source is the staged bootstrap) always stays
on fanotify, whatever the label or check says: overlays may already sit on it, and FUSE stacked on
top would leave them reading unfilled holes. If fanotify cannot start there, the start fails and
the mount is detached. The FUSE path refuses to mount over any kernel mount.

An auto-accel sidecar's merged bootstrap is served as its producer built it: the snapshotter
checks that a sidecar names the image and that each blob matches its digest, but does not rebuild
the bootstrap from the image's layers. Every node that writes the sidecar image record
`nydus.auto-accel.local/sidecar:<subject manifest hex>` or serves it on the peer mirror is
trusted to produce sidecars for every image; containers cannot create that record through CRI.
The rules and deployment constraints are in "Sidecar trust model" in
[ARCHITECTURE.md](../ARCHITECTURE.md).

The cache of a fanotify daemon lives in its `daemons/<slug>/stage` dir, next to the staged
bootstrap. Cache GC and the cache-bytes metric count it (each inode once: the `blob_<i>` device
files are hardlinks to the `.blob.data` files) against `gc_max_bytes`, but never evict it; a dead
daemon's dir goes with the stale daemon-dir sweep, or is kept and evicted by [stage
retention](#stage-retention) when that is on. Cache accounting counts the bytes allocated on
disk (`st_blocks`), not file lengths: a sparse cache file counts only the chunks it holds, so
`gc_max_bytes` bounds real disk use. Both `/metrics` endpoints answer from a scan at most 60 s
old.

The slug is derived from the image ref, so after its tag moved to another image a start finds the
daemon dir of the image the ref named before. A fanotify stage dir whose `bootstrap` was staged
from another source (its `bootstrap.view-of` records another source, or it is no copy of the new
one) is emptied before the new source is staged, caches included. A blockdev or tarfs
`image.erofs` is served again only when `image.erofs.source` records the SHA-256 of the bootstrap
being served; otherwise the bootstrap is exported into a new file that is then moved into place,
and its source recorded. A mounted image is never replaced: a start that finds one exported from
another bootstrap fails.

A fanotify daemon's saved upgrade state carries its blob list without credentials. A takeover after
a restart and an in-place heal both rebuild the blob list with the credentials the runtime auth
store holds at that moment. When a daemon that fetched with credentials finds none (an expired
entry, or a store not yet repopulated after a restart), a warning names the image, and reads of
uncached data fail with `EIO` until credentials for it arrive. Every update of the runtime auth
store (`PUT /api/v1/auth`) schedules a pass, debounced so a burst of updates costs one, that heals
each such daemon in place once the store holds credentials for its image: the same fanotify group,
no remount, no unanswered event (`DaemonSupervisor::heal_daemons_missing_auth`). A daemon built
with credentials is never touched, so refreshing them churns nothing. FUSE daemons have no
equivalent: their registry credentials are part of the RAFS mount command, which the snapshotter
does not replace under a live FUSE mount, so a FUSE daemon started without credentials keeps failing until it
is restarted. These images get no page cache sharing domain: only bootstraps this node built
qualify.

A process that dies between reading a permission event and answering it (`kill -9`, an abort,
the OOM killer) leaves the event on the group, which systemd's fd store keeps alive, and its reader
blocked until killed: the kernel answers such an event only when the group closes, and no
interface lists it. The kernel matches a response to an event by the event's fd number alone, so
at startup, before any worker reads, the successor writes a `FAN_DENY_ERRNO(EIO)` response for
every fd number below the sweep bound to each parked group it is not told is clean
(`nydus_service::fanotify::deny_stranded_events`), repeating a number until no event is left
under it, since readers in successive dead processes can strand events under the same number.
Nothing else is answered. A stranded reader usually completes with correct data: most stranded
events come from EROFS readahead, and a denied readahead is retried by the read itself with an
event the successor serves. Only a denied synchronous page read fails its reader with `EIO`.

- **Which groups are clean.** A snapshotter stopping with an fd store (`preserve_for_failover`)
  first refuses every new daemon start, heal, recovery and upgrade, waits out those under way (each
  checks before it stops anything, holding its image's start lock or the `instances` write lock,
  and then runs to completion), stops and joins the workers of every armed daemon, and parks a
  token in the fd store: a memfd named `fanotify-events-answered` holding the process's nonce and
  those images' slugs, minus any whose group its own startup sweep failed. The successor takes
  the token out of the store before it serves anything and sweeps every parked group the token
  does not list. It trusts no token it cannot evict (no fd store) and none whose nonce differs
  from the one the predecessor recorded in `<root>/fanotify-nofile`, so a token an earlier
  process left behind never vouches for groups a later one read; without a trusted token it
  sweeps every parked group. A token lives in the fd store rather than the snapshotter root
  because releases v3.0.1 through v3.6.0 evict a parked fd that no daemon record names: after a
  downgrade, the older release drops the token, so a crash of it is swept after the next upgrade.
- **The sweep bound.** A reader takes event fds below its soft `RLIMIT_NOFILE`. Every start
  records its own soft limit and nonce in `<root>/fanotify-nofile` before any of its workers
  runs; the
  successor sweeps below the larger of the recorded limit (`RLIMIT_NOFILE_MAX`, 1,000,000, when
  there is none) and its own, capped at 2^20: fds are allocated lowest first, and the snapshotter
  never holds a million descriptors at once. Groups are swept in parallel, one thread per CPU at
  most. Measured on Linux 7.3 with 2^20 writes to one group and on four groups in four threads:
  a Raspberry Pi 4 takes 0.53 s per group (about 500 ns a write) and 1.4–1.7 s for the four
  groups, a Raspberry Pi 5 0.21 s and 0.26–0.34 s. Only restarts without a trusted token pay it.

Only `SIGTERM` and `SIGINT` stop the snapshotter gracefully. Every other signal that ends it
(`SIGHUP`, `SIGUSR1`, `SIGUSR2`, `SIGQUIT`, `SIGABRT` and an uncontained panic, which aborts) is a
crash as far as its groups go: no token, and the successor sweeps. Rust's stack-overflow handler
swallows the first `SIGSEGV` or `SIGBUS` sent with `kill`, `SIGPIPE` is ignored, and a stopped
snapshotter (`SIGSTOP`, a cgroup freeze) blocks its readers until it continues. A core dump keeps
the dying process, and so its groups, alive until the dump is written; the address space is
mostly reserved and unpopulated (about 1.9 GB virtual and 40 MB resident on an idle snapshotter),
but a pipe `core_pattern` such as `systemd-coredump` is sent its holes as zeros.

Without an fd store (the Helm chart's default `deploymentMode: pod`, or a snapshotter run by hand) a
group closes with the process, and `fanotify_release()` allows every event still queued and every
read after it: containers read zeros for data never fetched. FUSE without its daemon fails reads
with `ENOTCONN` instead. So the driver probe selects fanotify only when an fd store is present, and
otherwise takes the next viable driver in `fs_drivers` (blockdev or fusedev in the default list).
There is no setting to override this. The store counts as present when `$FDSTORE` is above zero
(systemd 254 and later set it to `FileDescriptorStoreMax=`), or, with `$NOTIFY_SOCKET` set, when
`systemctl show -p FileDescriptorStoreMax` reports more than zero for the service unit named in
`/proc/self/cgroup` (`nydus_snapshotter::fdstore::detect`). The unit needs `Type=notify` and
`FileDescriptorStoreMax=` above zero (`misc/performance/nydus-snapshotter.service`). Under
Kubernetes the chart's `deploymentMode: hostSystemd` installs such a unit on each node
(deploy/helm/nydus-snapshotter/README.md, "Deployment modes"). The startup log names the reason in
the fanotify `driver probe result` line.

Fanotify mounts already live when such a start finds no fd store (an upgrade from a release
without this rule, or a unit that lost its fd store) are still re-armed on fanotify
(`rebuild_from_records`, which keeps a live fanotify mount on fanotify whatever the node now
selects): detaching them would break the containers on them, and no other driver can serve them.
Each start of such a mount logs a warning; new images go to the selected driver, and the mount
leaves fanotify once its last container is gone.

A graceful stop without an fd store (`shutdown_all`) first refuses new daemon starts and waits out
those under way, as a stop with an fd store does, then unmounts every fanotify mount at once while
its group is still open, retrying a busy one for about 10 s, so the stop fits a 30 s termination
grace period. A mount still busy after that (a container's overlay holding it) keeps its daemon
record live, and so does every mount of a process that dies without a graceful stop. Such a mount
stays up without a group until the next start re-arms it in place (`rebuild_from_records`):
meanwhile reads of data never fetched return zeros, and EROFS may keep the zeros it read in its
page cache.

The fanotify path has no RAFS instance, so `[snapshotter.features] prefetch`, runtime prefetch
lists and `cache.disable_indexed` apply only to images served over FUSE; a fanotify daemon fetches
on demand only.

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

With pages larger than the block, a pre-content event spans several chunks, among them chunks the
image no longer references (see [Fill validation](#fill-validation)), so a change to the fanotify
or fill path must pass on a large-page kernel, not only on a 4K one. The gate is the
`erofs-folio-arm64` job of `.github/workflows/fanotify-vm.yml`: `misc/erofs-folio/qemu-test.sh`
boots Ubuntu's arm64 64K-page kernels under QEMU and, with `FANOTIFY_TESTS`, runs
`dead-chunk-test.sh`, `runtime-test.sh` and `zran-multilayer-test.sh` in the guest with static
`nydusd` and `nydus-image` builds, failing unless the guest really ran on 64K pages
(`EXPECT_PAGE_SIZE`). A release is canaried on a 16K-page host as well as on a 4K one. The other
`misc/fanotify` scripts need a full userland (perl, python3, strace, the snapshotter test binary)
and run only in the 4K-page virtme-ng job.

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
| Fanotify (snapshotter: auto-accel and pulled nydus images) | staged bootstrap copy | padded to a page multiple with a sparse hole (`stage_bootstrap`) |
| Blockdev and tarfs without dm-verity (snapshotter) | exported `image.erofs` | padded at export (`BlockDevice::export`) and before the mount (`mount_blockdev_erofs`), so a cached image that is not a page multiple is covered too |
| `nydus-image export --block` | the exported `.disk` | padded to a 64 KiB multiple (`EXPORT_ALIGNMENT`, the largest page size) at export, with or without `--verity`: EROFS reads only the blocks the superblock names, dm-verity only `--data-blocks` and the tree at `--hash-offset` |
| Tarfs with dm-verity | dm block device | not file-backed: unaffected |
| Nydus images the snapshotter serves over FUSE | FUSE | not EROFS: unaffected |
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

## Stage retention

When the last container of an image exits, its fanotify daemon stops and its mount goes. Without
retention, the reconciler then removes `daemons/<slug>/` (node view and caches) once it is older
than the reconcile period, so the next start of the image is cold. With retention on, the stage
stays, and the next start mounts the staged node view again and serves from the caches it holds.
Nothing else is kept: no daemon, mount or open file.

```toml
[snapshotter.cache]
retention = false               # default
retention_max_bytes = "10%"     # bytes ("20GiB") or a percentage of the filesystem holding daemons/
retention_min_free = "20%"      # same units
retention_idle_limit = "auto"   # or a duration such as "7d"
```

A stage is retained while its image has a stopped daemon record (`daemons/records/<slug>.json`,
`live = false`, `updated_at` is the stop time), a `stage` dir and no daemon. Daemon dirs without a
record, and blockdev or tarfs dirs (no `stage`), are swept as before. A snapshotter restart ignores
retained stages until their image starts again; the Cleanup RPC runs a normal reconcile pass and
keeps them too.

Every reconcile tick, the reconciler reads the records and the filesystem's free space (one
`statvfs`) and evicts, one stage at a time:

1. every retained stage idle longer than its limit;
2. then, while there is a deficit, the stage idle longest relative to its limit, the larger first on
   a tie. The deficit is the largest of: retained bytes over `retention_max_bytes`;
   `retention_min_free` over the space available to unprivileged users (`f_bavail`); and, on the
   slow pass with `gc_max_bytes` set (and `gc_dry_run` off), all cache bytes over `gc_max_bytes`.
   That pass runs before the cache GC, so retained stages go before any `work_dir` file.

The plan is made again after every eviction. A stage whose eviction fails or is refused still counts
against the limits but is not chosen again in that pass, so the next stage goes instead. If the
records cannot be read, the pass fails and no daemon dir is swept.

With `retention_idle_limit = "auto"`, each image learns its start gap `G` from its own starts:
every start after a release (the last holder of the image went; the stopped record carries
`released_at`) sets `G = max(now - released_at, 0.75 * G)`, so `G` follows a longer gap at
once and forgets it by a quarter per start. The limit is `2 * G`, at least 1 h and at most 30 days,
and 26 h while `G` is unknown. `G` is kept in the daemon record (`start_gap`, seconds), which the
records endpoint shows. A heal, replacement, upgrade, or start after a snapshotter shutdown keeps
`G` and is not counted as a warm or cold start.

A stage's files are measured (allocated blocks, each inode once) once after it became retained; a
stage that cannot be measured is counted at its last known size, or left out of that pass. An
eviction takes the image's start lock and checks again that no daemon serves the image, that the
record is unchanged and still stopped, and that nothing is mounted under the dir; a start that got
there first keeps its stage. The record outlives its stage. Stopped records without a stage are
deleted after 60 days idle, and beyond the newest 4096, so a gap longer than the stage lived can
still be learned. A stop time in the future (the clock stepped back) counts as idle for zero
seconds and teaches no gap.

A retained cache is trusted no more than any cache a stopped daemon left behind (see [Fill
validation](#fill-validation)): unless it still reads as verified, its ready chunks are checked
again while serving goes on.

## Borrowing

Every image keeps its own cache file per data blob: `daemons/<slug>/stage/<blob id>.blob.data` on
the fanotify path, `<cache.work_dir>/<slug>/<blob id>.blob.data` for FUSE and block devices. Two
images using one blob would each fetch and decompress the same chunks. With borrowing on, a cache
that misses a chunk first looks for the same byte range in another image's cache file of the same
blob on the node (a lender), and fetches from its backend only if that fails. Borrowing saves
fetches and decompression, not disk: the borrower writes the chunk into its own cache file.

```toml
[snapshotter.cache]
borrow = false   # default
```

The snapshotter passes every daemon, whatever its driver, the patterns
`<root>/daemons/*/stage` and `<cache.work_dir>/*` (`borrow_from` in the file cache config). When a
blob cache opens, it lists up to four lenders there: regular files named like its own cache file,
not symlinks, on the same filesystem, with the same owner, and not its own file. The list is made
once per open, so a cache opened before another image cached the blob does not see it.

**Trust.** A lender is untrusted data. An image can make its own cache hold anything while passing
its own validation, by naming the bytes it wants in its own bootstrap. So the borrower reads the
chunk's range at its own offset and length into memory, checks it against its own digest for the
chunk (the bootstrap's on the fanotify path, the chunk's own elsewhere), and only then writes it
into its own cache file and marks it ready, the way a fetched chunk is written, unsealed-boot mark
and verified stamp included. Nothing else the lender holds is used: not its chunk map, digests,
size or anything it asserts. A lender range that is a hole (`SEEK_DATA`/`SEEK_HOLE`) is skipped
without reading. A lender is never written, and unverified bytes never reach the borrower's file,
which on the fanotify path is the EROFS device the kernel reads. A chunk without a digest, a raw
(compressed) or encrypted cache, and a tarfs blob never borrow. A lender whose bytes fail the
digest three times is no longer used by that cache; a lender being filled at the same time can
fail once, a corrupt or hostile one fails every time.

**Authorization.** Two rules decide who may borrow from whom:

- *Same backend.* With borrowing on, the snapshotter writes the backend a cache dir is filled
  from into `borrow-identity` in that dir when it starts the image there, once: `registry
  <scheme>://<host>/<repository>` for a registry, `content-store <root>` for the auto-accel
  backend, which reads containerd's content store. Other backends (object stores, HTTP proxy)
  get no identity. A cache borrows only from dirs whose identity file is a regular file with the
  same owner and the same contents as its own; a dir without one neither lends nor borrows. An
  image whose bootstrap names another image's blob but whose backend is a registry or repository
  of its own choosing therefore gets nothing from that image's cache.
- *Own read first.* A cache borrows only after its own backend has served it chunk data at least
  once, so an image whose backend is the same repository but which cannot read the blob there
  (no credentials for it) gets nothing either.

Not covered: an image of the same repository whose own backend serves the blob gets the bytes,
as it could have fetched them. Within one repository, images are not told apart by tag or
credentials beyond that first read. All auto-accel images share one identity, the content store,
whose layers containerd shares between the images of the node anyway. Timing is a side channel:
a borrowed read is faster than a fetch, which tells an image that another image on the node holds
the blob and which of its chunks that image has read.

**Event-free descriptors.** A lender may be another image's live EROFS device, carrying that
image's `FAN_PRE_ACCESS` mark. An ordinary read of it would raise events in the other image's
handler, which would fetch the range, answer `EIO` if it has failed, or deadlock with a handler
borrowing back. Every lender is therefore opened once, through `open_without_events`
(`FMODE_NONOTIFY` via a private `FAN_OPEN_PERM` group), and shared by all caches of the process
for as long as the file is linked. Where fanotify permission events are unavailable (no fanotify,
a kernel without them, or no privilege to create a group) no pre-content mark can exist, and the
lender is opened plainly. `misc/fanotify/borrow-test.sh` checks that borrowing from a marked file,
and `SEEK_DATA` on it, raise no event on the marking group.

**Retention and eviction.** A retained stage lends like a live one. Before the snapshotter removes
a stage (retention eviction, the stale daemon-dir sweep, a wipe on a source change) or a cache
file (cache GC), it closes the lender descriptors under it, so a borrower does not keep the
deleted file's space allocated. A lender found unlinked is closed before use.

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
The handler asks for it only when the bootstrap declares fingerprints and every byte its caches
serve is verified (see below); otherwise, and when a kernel rejects the options (`EINVAL`, before
7.0), it mounts without them and logs why at `info`. Shared mmaps need the fix "erofs: hold real
inodes for shared files" (mainline `7259fb011c14`, 7.4; or a backport): without it, a page fault
on a mapping whose file was closed and whose real inode was evicted dereferences a NULL inode, a
kernel oops. `misc/fanotify/inode-share-test.sh` checks the sharing in the kernel.

### Trust model

The kernel shares a file's pages with every file of the domain whose fingerprint is byte-equal and
never compares the data, so a fingerprint is a claim the kernel takes on trust. The snapshotter
therefore computes every fingerprint in its domain itself, and serves each image, whatever its
origin, through a **node view** of its bootstrap (`nydus-image node-view`, see
[nydus-image.md](nydus-image.md#node-view)), built when the mount source is staged:

- **Computed where:** on the node, from the bootstrap alone (no layer data is read), in a
  subprocess confined like the auto-accel converter (`[snapshotter.auto_zran]` `nydus_image`,
  `sandbox`) that may write only a scratch dir, never the cache files beside it. It runs at
  normal priority, since the image's first mount waits for it, and is killed after 30 s plus
  1 s per MiB of bootstrap. The snapshotter then trusts nothing the subprocess claims: it
  recomputes every fingerprint from the view's chunk table and compares it with the xattr each
  inode stores (`kernel_layout::check_node_view`), and discards the view on any difference. The
  view is a RAFS v6 bootstrap at 4 KiB blocks; it replaces the image's own bootstrap as the EROFS
  mount source (padded to the page size as usual).
- **What is computed:** for each regular file, SHA-256 over a scheme tag, the chunk digest
  algorithm, the file size and each chunk's size and digest, taken from the view's chunk table.
  A file gets one only if `check_kernel_layout` proves, on the view as written, that the kernel
  reads exactly those chunk-table chunks for every byte of it; others are not shared.
- **Why shipped fingerprints are ignored:** a pushed image, a peer's sidecar or a registry
  nydus image could carry a copy of another image's fingerprint on a file with other content, and
  every mount of the domain would then read that file's pages for the other one. RAFS readers
  skip long-prefix xattrs, the only on-disk form of a fingerprint, so nothing a source ships
  reaches the view, and a source bootstrap staged as it is (no view could be built) is never
  given a domain.
- **Why equal fingerprints mean equal bytes:** equal fingerprints mean equal algorithm, size and
  chunk digest sequence. Every fill of a fanotify cache is validated against the digest in the
  chunk table of the bootstrap the kernel mounts, which is the view, and each image has its own
  cache files (`daemons/<image>/stage`). The handler joins the domain only when, for every blob,
  the chunks already marked ready have been checked against those digests, or none is ready yet,
  and the cache file has been written since only by validating fills
  (`BlobObject::is_served_data_verified`). So the bytes each kernel inode reads match the
  digests its fingerprint was computed from, in both images.

Residual risks: a kernel bug that corrupts a shared page corrupts it for every image of the
domain; a page mapped before a chunk is revoked (a cache file corrupted on disk after it was
verified) stays mapped in every process sharing it until unmapped; and the argument rests on the
chunk digest (SHA-256 or BLAKE3) and SHA-256 being collision resistant.

### Which images share, and when

Every image served through fanotify: auto-accel images built on this node or fetched from a peer,
and nydus images pulled from a registry. RAFS v5 images take FUSE and never share. A view is built
only when sharing is enabled (below), or when the image's own block size exceeds the page size or
its chunk addresses a kernel would misread at its own block size: such an image is served through
fanotify when its 4 KiB view passes the checks (the view built for that decision is the one
staged), and over FUSE when the image has no view. A failure that says nothing about the image
(spawn, sandbox, I/O, timeout) fails the start, which is retried; for an image fit as it is, it
only means mounting without sharing, logged once per image. With sharing disabled, a fit image is
staged as a padded copy of its own bootstrap and no view is built.

`inode_share` is fixed for a mount's life, and a takeover or in-place heal keeps the mount and
its staged view (the view is rebuilt only when the image's bootstrap changes, recorded in
`stage/bootstrap.view-of`). A fresh start of an image whose stage dir is still there mounts the
view staged before without building or checking it again only while `stage/bootstrap.view-of`
matches the SHA-256 of the image's bootstrap and `stage/bootstrap.view-checked` holds the SHA-256
of the staged view, the version of the running snapshotter and the host page size. That record is
written only after `check_node_view` and the layout checks passed, so the view a mount uses was
checked by this release, in this or an earlier process, padded to this page size, and its bytes
are unchanged since; anything else builds the view again. `bootstrap.view-of` stays while a view
is rebuilt, so an interrupted rebuild never makes the stage look staged from another source. A
staged padded copy of the bootstrap is likewise kept while it is still a copy of it, and padded to
the current page size. Sharing therefore starts with a fresh mount: a fresh cache qualifies
at once; a cache holding chunks nobody checked yet (filled by an older release) mounts without
sharing and qualifies on its next mount once the background verifier has recorded it verified.
`/proc/self/mounts` shows `inode_share,domain_id=nydus-node-local` on a sharing mount, and
`nydus_snapshotter_inode_share_mounts_total{result}` counts fresh mounts by decision: `shared`,
`no_view`, `unverified`, `no_fingerprints` or `disabled`.

The domain is set under `[snapshotter.features] erofs_inode_share` (`auto`, `on`, `off`). `auto`
enables it when the startup self-test (`nydus_service::erofs_ishare`) finds both:

- **support**: a tiny file-backed probe image mounts with `inode_share,domain_id=…`, and
  `inode_share` without `domain_id` fails `EINVAL` (a kernel built without
  `CONFIG_EROFS_FS_PAGE_CACHE_SHARE` ignores both options; one before 7.0 rejects both);
- **the fix**: `/proc/kallsyms` lists `erofs_ishare_backing_release`, the `release` hook the fix
  adds. Triggering the bug itself would oops the kernel, so the probe never does.

It does not compare kernel versions, so a backport counts as fixed. Without kallsyms the result is
`inconclusive` and `auto` stays off; `on` enables sharing regardless, and `off` skips the self-test.
The self-test runs in the background at startup; mounts made before it finishes go without
sharing. The startup log and the `nydus_snapshotter_erofs_inode_share{status,mode,enabled}`
gauge report the outcome (`status` is `fix_present`, `fix_absent`, `unsupported` or
`inconclusive`).

### Cache key encoding before 7.4

Kernels before the fix "erofs: delimit inode_share cache key components" (mainline
`96bf9831fbf4`, 7.4-rc1) key a shared inode by `fingerprint || domain_id` with no separator, so
two different (fingerprint, domain) pairs can concatenate to the same key; the fix makes it
`domain_id || '\0' || fingerprint`. The snapshotter cannot hit that: every fingerprint it writes is
exactly 32 bytes and every mount uses the one domain `nydus-node-local`, so all its keys split at
the same byte and equal keys mean equal fingerprints. Only a mount outside the snapshotter, with
another domain and a fingerprint of another length (which takes root), could build a colliding
key; nothing is gated on the fix.

## Troubleshooting

- **Reads return `EIO`** — the daemon failed to fetch a range (backend/network error). Check
  `nydusd` logs and backend connectivity.
- **`mount: erofs … wrong fs type`** — the bootstrap's block size is larger than the host page
  size; rebuild with `--block-size 4096` or the host's page size.
- **No events / hangs on first read** — the kernel is below 6.14 or
  `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is not enabled; fall back to `nydusd fuse`.
