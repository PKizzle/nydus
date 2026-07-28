// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to serve on-demand blob data through fanotify pre-content hooks.
//!
//! [`FanotifyHandler`] works by:
//! 1. Creating a fanotify group with `FAN_CLASS_PRE_CONTENT`.
//! 2. Placing marks (`FAN_PRE_ACCESS` **only** — never `FAN_OPEN_PERM`, which would
//!    block every open including the daemon's own) on the sparse data-blob device
//!    files (hardlinks of each blob's `.blob.data` cache file — same inode).
//! 3. Issuing a file-backed EROFS mount with the **bootstrap as the mount source**
//!    and the data blobs as `device=` options:
//!    `mount("<bootstrap>", mountpoint, "erofs", MS_RDONLY|MS_NODEV|MS_NOSUID,
//!    "device=blob_0,device=blob_1,...")` (a NULL/`none` source fails with `EINVAL`).
//! 4. Polling the fanotify fd; when a `FAN_PRE_ACCESS` event arrives, the handler
//!    fetches the missing chunk data from the [`BlobCacheMgr`], writes it into the
//!    sparse blob via `pwrite(2)`, and responds `FAN_ALLOW`.
//!
//! The kernel floor for this path is **Linux 6.14** (`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`).

use std::fs::File;
use std::io::{ErrorKind, Result};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::blob_cache::{BlobCacheMgr, DataBlob};
use crate::fanotify_sys::{
    FAN_CLASS_PRE_CONTENT, FAN_EVENT_INFO_TYPE_RANGE, FAN_NOFD, FAN_PRE_ACCESS, FAN_Q_OVERFLOW,
    fan_deny_errno, fanotify_event_info_header, fanotify_event_info_range,
};

const TOKEN_EVENT_WAKER: usize = 1;
const TOKEN_EVENT_FANOTIFY: usize = 2;

/// Default capacity of the event buffer (must be ≥ `fanotify(7)` minimum of 4096).
const EVENT_BUF_SIZE: usize = 256 * 1024;

/// Maximum number of events to process per poll wakeup.
const MAX_EVENTS_PER_POLL: usize = 64;

/// Allow response for fanotify permission events.
const FAN_ALLOW: u32 = 0x01;

/// Response structure written back to the fanotify fd.
#[repr(C)]
struct fanotify_response {
    fd: i32,
    response: u32,
}

/// Get the `(st_dev, st_ino)` identity of an open file descriptor.
///
/// Used to map a `FAN_PRE_ACCESS` event fd back to the [`DataBlob`] whose sparse backing file
/// it refers to, without depending on path names.
fn fd_identity(fd: RawFd) -> Result<(u64, u64)> {
    // SAFETY: `stat` is plain-old-data; `fstat` only writes into it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut st) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Scoped thread-safety assertion for [`DataBlob`].
///
/// `DataBlob` holds a compio `File` (an `Rc`-based `SharedFd`), which makes it `!Send + !Sync`.
/// Within the fanotify handler the compio handle is only ever used for `as_raw_fd()` (fd
/// identity, hardlink staging, `fallocate` cache culls) — its `Rc` refcount is touched solely
/// at construction (`assemble`, single-threaded) and on handler drop. Worker threads never
/// clone it or await on it. Keep it that way: do NOT call `async_read`/`async_fetch` (or
/// anything else that clones the compio fd) on a [`BlobBacking`] from `run_loop` workers —
/// range fills go through `blob().get_blob_object()` instead.
///
/// The assertion is scoped to this one field rather than a blanket
/// `unsafe impl Send/Sync for FanotifyHandler` (which would vouch for every present and future
/// field), so the compiler keeps checking the rest of the struct.
struct AssertBlobThreadSafe(DataBlob);

// SAFETY: see the type-level comment — raw-fd-only access from worker threads; the inner
// compio fd's refcount is never mutated concurrently.
unsafe impl Send for AssertBlobThreadSafe {}
unsafe impl Sync for AssertBlobThreadSafe {}

impl std::ops::Deref for AssertBlobThreadSafe {
    type Target = DataBlob;

    fn deref(&self) -> &DataBlob {
        &self.0
    }
}

/// A data blob whose sparse backing file is mounted as an EROFS device and serviced on demand.
///
/// `dev`/`ino` identify the backing cache file so an incoming event fd can be resolved to the
/// right blob; `blob` provides `fetch_range_uncompressed()` to populate the requested range.
struct BlobBacking {
    dev: u64,
    ino: u64,
    blob: AssertBlobThreadSafe,
    /// Excludes cache invalidation from in-flight fetches for *this* blob.
    ///
    /// Serving takes it shared (many worker threads fill ranges concurrently, which is the
    /// whole point of the worker pool); [`FanotifyHandler::invalidate`] takes it exclusively.
    ///
    /// Without it, a fetch that started before an invalidation can write its chunk *after* the
    /// hole punch and then mark that chunk ready — leaving the map claiming ready for bytes
    /// that were just discarded, which is served to the next reader as zeros. Per-blob rather
    /// than global so invalidating one blob does not stall reads of the others.
    io_lock: RwLock<()>,
}

/// Map a serve error to the errno carried in a `FAN_DENY_ERRNO` response.
///
/// Only errnos the kernel's fanotify UAPI documents as valid response
/// payloads are passed through; everything else collapses to `EIO`. The
/// distinction matters most for disk pressure: a full cache filesystem is
/// answered `ENOSPC`, not a generic I/O error.
///
/// How far that errno travels depends on how the data is being read, and the
/// answer is not the intuitive one (measured on Linux 7.0.11 by
/// `misc/fanotify/precontent-cases.sh` case C13):
///
/// - A process reading the **marked file directly** gets this exact errno from
///   its `read(2)`. The kernel honours `FAN_DENY_ERRNO` faithfully.
/// - A process reading through the **EROFS mount** — which is every container —
///   gets `EIO` regardless. EROFS pulls the marked backing file through the page
///   cache, and the outer read only learns that the folio is not uptodate.
///
/// So the payoff is not that a container can tell a full disk from an I/O error
/// -- today it cannot. It is still worth getting right: this is the errno the
/// daemon logs and reports, the one a direct reader of the cache file observes,
/// and the one containers would get for free if EROFS ever propagated it.
/// Answering `EIO` for a full disk throws it away at the only point where we
/// still hold it.
fn deny_errno_for(e: &std::io::Error) -> libc::c_int {
    // `source_errno`, not `raw_os_error`: the failure originates several layers down (a cache
    // `pwrite` in nydus-storage) and reaches here through typed errors. If any of them wraps
    // it in a `Custom` `io::Error` on the way, `raw_os_error()` reports `None` and a full disk
    // would be answered as a generic `EIO`. Walking the chain sees through that.
    match nydus_utils::source_errno(e) {
        Some(errno @ (libc::ENOSPC | libc::EDQUOT | libc::EIO)) => errno,
        _ => libc::EIO,
    }
}

/// Exactly-once owner of a permission event's fd between parse and answer.
///
/// A pre-content permission event MUST be answered: an event that is dropped
/// unanswered leaves the accessing task blocked in `D` state until the whole
/// group closes. The happy path calls [`finish`](Self::finish) with the
/// computed response; if event handling panics and unwinds past the guard,
/// `Drop` answers with `FAN_DENY_ERRNO(EIO)` and closes the fd so the reader
/// gets an honest error instead of a hang (pattern mined from upstream v3's
/// `PendingPermission`).
struct EventFdGuard<'a> {
    handler: &'a FanotifyHandler,
    fd: RawFd,
    answered: bool,
}

impl<'a> EventFdGuard<'a> {
    fn new(handler: &'a FanotifyHandler, fd: RawFd) -> Self {
        // Overflow/queue records carry fd == FAN_NOFD; nothing to answer.
        Self {
            handler,
            fd,
            answered: fd < 0,
        }
    }

    /// Answer the event with `response` and close its fd, consuming the guard.
    fn finish(mut self, response: u32) {
        if !self.answered {
            self.handler.write_response(self.fd, response);
            unsafe {
                libc::close(self.fd);
            }
            self.answered = true;
        }
    }
}

impl Drop for EventFdGuard<'_> {
    fn drop(&mut self) {
        if !self.answered {
            self.handler
                .write_response(self.fd, fan_deny_errno(libc::EIO));
            unsafe {
                libc::close(self.fd);
            }
            self.answered = true;
        }
    }
}

/// Handler that serves RAFS v6 blob data through fanotify pre-content hooks.
///
/// The lifetime mirrors the existing service handler pattern:
/// one `FanotifyHandler` per image, N worker threads each calling `run_loop()`.
pub struct FanotifyHandler {
    /// Set to `false` to signal workers to exit.
    active: AtomicBool,
    /// Barrier that workers must reach before `stop()` returns.
    barrier: Barrier,
    /// Number of worker threads.
    threads: usize,
    /// Fanotify notification fd (owned — `close(2)` on drop).
    fan_fd: OwnedFd,
    /// mio poll instance.
    poller: Mutex<Poll>,
    /// Waker to unblock poll when `stop()` is called.
    waker: Arc<Waker>,
    /// Directory containing sparse blob files (bootstrap + `blob_*`).
    blob_dir: PathBuf,
    /// EROFS mountpoint (where the filesystem will be visible).
    mountpoint: PathBuf,
    /// Reference to the blob cache manager (kept alive for the lifetime of the handler).
    _blob_cache_mgr: Arc<BlobCacheMgr>,
    /// Data blobs serviced on demand, indexed by their backing-file identity.
    blob_backings: Vec<BlobBacking>,

    /// Bootstrap file path.
    bootstrap_path: PathBuf,
    /// Device blob paths passed to the EROFS mount options.
    device_blobs: Vec<PathBuf>,
}

// Helper: open the blob directory and enumerate blob files.
fn discover_blobs(blob_dir: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let dir = std::path::absolute(blob_dir)?;
    if !dir.is_dir() {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("blob directory {:?} is not a directory", dir),
        ));
    }

    let mut bootstrap = None;
    let mut blobs = Vec::new();

    for entry in dir.read_dir()? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == "bootstrap" {
                bootstrap = Some(path);
            } else if name.starts_with("blob_") {
                blobs.push(path);
            }
        }
    }

    let bootstrap = bootstrap.ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::NotFound,
            format!("no bootstrap file in blob directory {:?}", dir),
        )
    })?;

    Ok((bootstrap, blobs))
}

/// Maximum size of the `mount(2)` data argument.
///
/// The kernel copies the options string with `copy_mount_options()`, which is bounded by one
/// page and NUL-terminates at the end — anything longer is **silently truncated**, so a deep
/// cache directory multiplied by a large device table turns into a baffling EROFS mount error
/// rather than an obvious "options too long". 4095 leaves room for the terminator on the
/// smallest supported page size.
const MOUNT_DATA_MAX: usize = 4095;

/// Build the `device=<path>,device=<path>,…` option string for a file-backed EROFS mount.
///
/// Split out from [`mount_erofs`] so the validation is unit-testable without root or a
/// 6.14 kernel. The option list is comma-separated and NUL-terminated by the kernel, so a
/// path containing either byte would silently change the meaning of the mount rather than
/// fail — both are rejected up front.
fn build_erofs_device_options(blobs: &[PathBuf]) -> Result<String> {
    for blob in blobs {
        let bytes = blob.as_os_str().as_encoded_bytes();
        if bytes.contains(&b',') {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "device path {:?} contains a comma, which would split the EROFS mount \
                     option list",
                    blob
                ),
            ));
        }
        if bytes.contains(&0) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("device path {:?} contains an interior NUL byte", blob),
            ));
        }
    }

    let options = blobs
        .iter()
        .map(|blob| format!("device={}", blob.display()))
        .collect::<Vec<_>>()
        .join(",");

    if options.len() > MOUNT_DATA_MAX {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "EROFS mount options are {} bytes for {} device(s), over the {}-byte kernel \
                 limit; use a shorter blob cache directory path",
                options.len(),
                blobs.len(),
                MOUNT_DATA_MAX
            ),
        ));
    }

    Ok(options)
}

// Issue a file-backed EROFS mount via `mount(2)` (kernel ≥ 6.12).
//
// The **bootstrap** is the mount source: it holds the EROFS superblock, inode metadata and the
// device table. The **data blobs** are the extra block devices that back file content; they are
// passed as `device=<path>` mount options in device-table order. The bootstrap itself is NOT a
// `device=` entry, and the source must be the bootstrap path — passing a NULL/`none` source fails
// with `EINVAL` ("special device none does not exist").
fn mount_erofs(bootstrap: &Path, blobs: &[PathBuf], mountpoint: &Path) -> Result<()> {
    let options = build_erofs_device_options(blobs)?;

    let source_c = std::ffi::CString::new(bootstrap.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
    let mountpoint_c = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
    let fstype = std::ffi::CString::new("erofs").unwrap();
    let opts = std::ffi::CString::new(options.as_bytes())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
    // An empty options string would still be a valid C string (""); pass NULL in that case.
    let opts_ptr = if options.is_empty() {
        std::ptr::null()
    } else {
        opts.as_ptr() as *const libc::c_void
    };

    // The mounted tree is an untrusted container image. EROFS is read-only anyway, but
    // `MS_RDONLY` states it rather than relying on the driver, and `MS_NODEV`/`MS_NOSUID`
    // stop a device node or setuid bit baked into the image from being honoured through
    // this mount.
    let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID;

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            mountpoint_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            opts_ptr,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl FanotifyHandler {
    /// Create a new [`FanotifyHandler`].
    ///
    /// # Arguments
    /// * `blob_dir` — directory containing bootstrap + sparse blob files.
    /// * `mountpoint` — where the EROFS filesystem will be mounted.
    /// * `blob_cache_mgr` — shared blob-cache manager for chunk fetching.
    /// * `threads` — number of worker threads.
    pub fn new(
        blob_dir: &str,
        mountpoint: &str,
        blob_cache_mgr: Arc<BlobCacheMgr>,
        threads: usize,
    ) -> Result<Self> {
        // Create the fanotify notification group with raw libc calls; the `nix` crate's
        // fanotify module does not expose the 6.14 pre-content API (see `fanotify_sys`).
        //
        // `FAN_REPORT_FID` is deliberately NOT set: pre-content fill needs a real file
        // descriptor on each event (to identify the target via `fstat` and to respond), whereas
        // `FAN_REPORT_FID` reports an opaque file handle and sets `metadata.fd` to `FAN_NOFD`.
        let init_flags = FAN_CLASS_PRE_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK;
        // `O_LARGEFILE` is deliberately NOT ORed in for the event_f_flags
        // arg even though the kernel's `FANOTIFY_INIT_FD_FLAGS` allowlist
        // accepts it: the Rust `libc` crate on `aarch64-unknown-linux-musl`
        // defines `O_LARGEFILE` as 0x8000 (the generic 32-bit value), but
        // on the aarch64 Linux UAPI 0x8000 is `O_NOFOLLOW` and
        // `O_LARGEFILE` is 0x20000. Passing `libc::O_LARGEFILE` on this
        // target therefore makes the kernel see `O_NOFOLLOW` (not in the
        // allowlist) and `fanotify_init` returns EINVAL on every aarch64
        // host — including kernels with `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`.
        // On 64-bit Linux `O_LARGEFILE` is implicit anyway, so the only
        // observable difference of leaving it off is that fanotify_init
        // succeeds where it previously failed. Same fix mirrored in
        // `snapshotter/src/probe/mod.rs::try_fanotify_init`.
        let raw_fd = unsafe { libc::fanotify_init(init_flags, libc::O_RDONLY as u32) };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fan_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Self::assemble(blob_dir, mountpoint, blob_cache_mgr, threads, fan_fd)
    }

    /// Rebuild a handler around a fanotify group fd preserved across a hot upgrade.
    ///
    /// The preserved fd (handed over via `SCM_RIGHTS` by the predecessor) still carries the live
    /// `FAN_PRE_ACCESS` marks and the EROFS mount is still up, so the successor must **not** call
    /// [`arm`](Self::arm) or [`mount`](Self::mount) again — it only re-derives the in-memory
    /// blob-backing/device state and re-registers the fd with a fresh poller. Reconstruction only
    /// opens (never reads) the marked backing files, so it cannot deadlock against the live marks.
    pub fn from_restored_fd(
        blob_dir: &str,
        mountpoint: &str,
        blob_cache_mgr: Arc<BlobCacheMgr>,
        threads: usize,
        fan_file: File,
    ) -> Result<Self> {
        Self::assemble(
            blob_dir,
            mountpoint,
            blob_cache_mgr,
            threads,
            OwnedFd::from(fan_file),
        )
    }

    /// Assemble the in-memory handler state around an already-created fanotify group `fan_fd`.
    ///
    /// Shared by [`new`](Self::new) (fresh group) and [`from_restored_fd`](Self::from_restored_fd)
    /// (group preserved across upgrade). Does not arm marks or mount — see those callers.
    fn assemble(
        blob_dir: &str,
        mountpoint: &str,
        blob_cache_mgr: Arc<BlobCacheMgr>,
        threads: usize,
        fan_fd: OwnedFd,
    ) -> Result<Self> {
        if threads == 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "fanotify worker thread count must be greater than zero",
            ));
        }

        let blob_dir_path = Path::new(blob_dir);
        // Only the bootstrap must pre-exist; the EROFS device files are derived from the blob
        // cache below (each data blob's `.blob.data` cache file, hardlinked to a stable `blob_<i>`
        // name) so callers do not have to pre-stage device files at the right inode.
        let (bootstrap_path, _preexisting_blobs) = discover_blobs(blob_dir_path)?;

        // Ensure the mountpoint exists.
        let mp = Path::new(mountpoint);
        if !mp.exists() {
            std::fs::create_dir_all(mp)?;
        }

        // NOTE: marks are *not* placed here. Arming the marks before the daemon has opened its own
        // backing files — and before the worker threads are draining events — would deadlock: the
        // `DataBlob::new` calls below open each blob's `.blob.data` file, which is the *same inode*
        // as the marked `blob_*` device file, so the daemon's own open would raise a pre-content
        // event that nothing can answer yet. Marks are armed later via `arm()`, after the workers
        // are running and after this constructor has finished opening every backing file.

        // mio poll setup.
        let poller = Poll::new().map_err(|e| std::io::Error::other(format!("mio poll: {}", e)))?;
        let waker = Waker::new(poller.registry(), Token(TOKEN_EVENT_WAKER))
            .map_err(|e| std::io::Error::other(format!("mio waker: {}", e)))?;
        poller
            .registry()
            .register(
                &mut SourceFd(&fan_fd.as_raw_fd()),
                Token(TOKEN_EVENT_FANOTIFY),
                Interest::READABLE,
            )
            .map_err(|e| std::io::Error::other(format!("mio register: {}", e)))?;

        // Build the set of on-demand data blobs from the shared blob cache manager. Each
        // `DataBlob` owns a handle to its sparse backing file; we record that file's identity so
        // an incoming event fd can be resolved back to the blob without relying on path names.
        let mut blob_backings = Vec::new();
        let runtime = compio::runtime::Runtime::new()
            .map_err(|e| std::io::Error::other(format!("fanotify: compio runtime: {}", e)))?;
        for cfg in blob_cache_mgr.get_all_data_blobs() {
            let blob = match runtime.block_on(DataBlob::new(&cfg)) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "fanotify: failed to open data blob {}: {}",
                        cfg.blob_info().blob_id(),
                        e
                    );
                    continue;
                }
            };
            match fd_identity(blob.file().as_raw_fd()) {
                Ok((dev, ino)) => blob_backings.push(BlobBacking {
                    dev,
                    ino,
                    blob: AssertBlobThreadSafe(blob),
                    io_lock: RwLock::new(()),
                }),
                Err(e) => warn!(
                    "fanotify: failed to stat backing file for blob {}: {}",
                    cfg.blob_info().blob_id(),
                    e
                ),
            }
        }

        // EROFS multi-device order must match the bootstrap's device table, i.e. blob index order.
        // `get_all_data_blobs` iterates a hash map, so sort before assigning `blob_<i>` device names.
        blob_backings.sort_by_key(|b| b.blob.blob_info().blob_index());

        // Materialise the EROFS device files from the cache. Each data blob's cache file
        // (`<work_dir>/<blob_id>.blob.data`) *is* the device the kernel reads on demand; hardlink it
        // to a stable `blob_<i>` name so `mount_erofs` and the event inode-match resolve to a single
        // inode. Resolving the path via `/proc/self/fd` avoids assuming `work_dir == blob_dir`.
        let mut device_blobs = Vec::with_capacity(blob_backings.len());
        for (i, backing) in blob_backings.iter().enumerate() {
            let cache_fd = backing.blob.file().as_raw_fd();
            let cache_path =
                std::fs::read_link(format!("/proc/self/fd/{}", cache_fd)).map_err(|e| {
                    std::io::Error::other(format!(
                        "fanotify: cannot resolve cache file path for blob {}: {}",
                        backing.blob.blob_info().blob_id(),
                        e
                    ))
                })?;
            let device_path = cache_path.with_file_name(format!("blob_{i}"));
            // Re-link defensively so a stale `blob_<i>` from a previous run cannot point at the
            // wrong inode. Removing the name is safe on both construction paths: on `new()` nothing
            // is mounted yet, and on `from_restored_fd()` (EROFS mount still live) the kernel holds
            // the device by inode, not by name — and the re-link targets that same inode.
            let _ = std::fs::remove_file(&device_path);
            std::fs::hard_link(&cache_path, &device_path).map_err(|e| {
                std::io::Error::other(format!(
                    "fanotify: failed to link device {:?} -> {:?}: {}",
                    device_path, cache_path, e
                ))
            })?;
            device_blobs.push(device_path);
        }

        Ok(FanotifyHandler {
            active: AtomicBool::new(true),
            barrier: Barrier::new(threads + 1),
            threads,
            fan_fd,
            poller: Mutex::new(poller),
            waker: Arc::new(waker),
            blob_dir: blob_dir_path.to_path_buf(),
            mountpoint: mp.to_path_buf(),
            _blob_cache_mgr: blob_cache_mgr,
            blob_backings,
            bootstrap_path,
            device_blobs,
        })
    }

    /// Arm `FAN_PRE_ACCESS` marks on the on-demand data-blob device files.
    ///
    /// Must be called **after** the worker threads are running (so events raised the instant a
    /// mark goes live can be drained) and **before** `mount()` (so the EROFS reads that follow the
    /// mount raise pre-content events). Only the sparse data blobs are marked — the bootstrap is
    /// fully materialised, so marking it would just add allow-only events on every metadata read.
    /// `FAN_OPEN_PERM` is deliberately *not* requested: only content reads need to block; making
    /// every open block would stall the mount and the daemon's own descriptors.
    pub fn arm(&self) -> Result<()> {
        let mask = FAN_PRE_ACCESS;
        let mark_flags = libc::FAN_MARK_ADD;
        for blob_path in self.device_blobs.iter() {
            // A missing device file is always pathological — assemble() just created
            // every entry in `device_blobs`. Skipping it would leave the sparse file
            // unmarked, and EROFS would then silently serve zeros for that blob (the
            // exact corruption class the pre-content path exists to prevent).
            if !blob_path.exists() {
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "fanotify: device file {:?} vanished before arming; refusing to \
                         serve a mount that would read zero-filled data",
                        blob_path
                    ),
                ));
            }
            let path_c = std::ffi::CString::new(blob_path.as_os_str().as_encoded_bytes())
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
            let ret = unsafe {
                libc::fanotify_mark(
                    self.fan_fd.as_raw_fd(),
                    mark_flags,
                    mask,
                    libc::AT_FDCWD,
                    path_c.as_ptr(),
                )
            };
            if ret != 0 {
                return Err(std::io::Error::other(format!(
                    "fanotify_mark on {:?} failed: {}",
                    blob_path,
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }

    /// Mount the EROFS filesystem after all marks are in place.
    ///
    /// This must be called **after** `new()`, **after** `arm()`, and **after** the workers start.
    pub fn mount(&self) -> Result<()> {
        mount_erofs(&self.bootstrap_path, &self.device_blobs, &self.mountpoint)
    }

    /// Number of worker threads.
    pub fn working_threads(&self) -> usize {
        self.threads
    }

    /// Signal all workers to stop and wait until they have exited, then deny
    /// any permission events still queued on the group.
    ///
    /// Between worker quiesce and the eventual close of the group fd, readers
    /// that raise new pre-content events would block in `D` state with nobody
    /// draining the queue. Answering the residue with `FAN_DENY_ERRNO(EIO)`
    /// converts that hang into an honest read error; whatever races in after
    /// the drain fails open when the fd finally closes, which is the kernel's
    /// own fallback semantic.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.waker.wake();
        self.barrier.wait();
        self.drain_deny_pending();
    }

    /// Answer every event still readable on the (non-blocking) group fd with
    /// `FAN_DENY_ERRNO(EIO)` and close its fd. Best-effort: stops at `EAGAIN`
    /// or any read error.
    ///
    /// Public because teardown needs to keep the queue drained between unmount
    /// attempts — see `ServiceController::unregister_fanotify_handler`.
    pub fn drain_deny_pending(&self) {
        let mut buf = vec![0u8; EVENT_BUF_SIZE];
        let mut denied = 0usize;
        loop {
            let n = unsafe {
                libc::read(
                    self.fan_fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            denied += self.deny_events_in_buffer(&buf[..n as usize]);
        }
        if denied > 0 {
            warn!(
                "fanotify: denied {} pending pre-content event(s) during shutdown",
                denied
            );
        }
    }

    /// Answer `event_fd` with `FAN_DENY_ERRNO(EIO)` and close it; no-op for `FAN_NOFD`.
    fn deny_event_fd(&self, event_fd: RawFd) {
        if event_fd < 0 {
            return;
        }
        self.write_response(event_fd, fan_deny_errno(libc::EIO));
        unsafe {
            libc::close(event_fd);
        }
    }

    /// Deny and close every parsable event in `buf`, returning how many were answered.
    ///
    /// Shared by the shutdown drain and by [`process_event_buffer`](Self::process_event_buffer)'s
    /// structural-failure path.
    fn deny_events_in_buffer(&self, buf: &[u8]) -> usize {
        let mut denied = 0usize;
        for_each_parsable_event(buf, |meta| {
            let event_fd = meta.fd as RawFd;
            if event_fd >= 0 {
                self.deny_event_fd(event_fd);
                denied += 1;
            }
        });
        denied
    }

    /// Get a clone of the underlying fanotify fd for upgrade/restore paths.
    ///
    /// Duplicated with `F_DUPFD_CLOEXEC` (plain `dup(2)` clears close-on-exec) so the
    /// copy cannot leak into spawned children such as `modprobe` or `nydus-image`;
    /// the upgrade path passes it explicitly via `SCM_RIGHTS` instead.
    pub fn get_file(&self) -> Result<File> {
        let raw = self.fan_fd.as_raw_fd();
        let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Get the EROFS mountpoint path.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Get the blob staging directory (bootstrap + sparse `blob_*` files).
    ///
    /// Used by the hot-upgrade path to record where to re-derive device files when rebuilding the
    /// handler around a preserved fanotify fd.
    pub fn blob_dir(&self) -> &Path {
        &self.blob_dir
    }

    /// Run the fanotify event loop on a single worker thread.
    ///
    /// Blocks until `stop()` is called or an unrecoverable error occurs.
    ///
    /// Every exit path — clean shutdown *and* error — participates in the shutdown
    /// barrier. The barrier is sized `threads + 1` and [`stop`](Self::stop) blocks on
    /// it, so a worker that returned early without waiting would deadlock `stop()`
    /// forever (and, because the singleton calls `stop()` while holding its handlers
    /// mutex, wedge every subsequent register/unregister daemon-wide). An erroring
    /// worker therefore logs, wakes a sibling, and parks on the barrier until
    /// `stop()` supplies the final waiter.
    pub fn run_loop(&self) -> Result<()> {
        // A panic anywhere in event handling must not skip the barrier: an
        // unwinding worker thread would otherwise die silently and wedge
        // `stop()` (and with it the singleton) forever. The per-event
        // `EventFdGuard` has already denied the in-flight event during the
        // unwind by the time we land here.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.run_loop_inner()))
                .unwrap_or_else(|_| {
                    Err(std::io::Error::other(
                        "fanotify worker panicked while handling events",
                    ))
                });
        if let Err(ref e) = result {
            error!(
                "fanotify: worker exiting on error ({}); remaining workers keep serving, \
                 parking on the shutdown barrier so stop() can complete",
                e
            );
            // The cascade wake below is for the *clean* path; on error the group is
            // still active, so this wake is a harmless no-op for siblings.
        }
        let _ = self.waker.wake();
        self.barrier.wait();
        result
    }

    fn run_loop_inner(&self) -> Result<()> {
        let mut events = Events::with_capacity(MAX_EVENTS_PER_POLL);
        let mut buf = vec![0u8; EVENT_BUF_SIZE];

        loop {
            match self.poller.lock().unwrap().poll(&mut events, None) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!("fanotify: poll failed: {}", e);
                    return Err(e);
                }
            }

            for event in events.iter() {
                if event.is_error() {
                    error!("fanotify: error event on poll");
                    continue;
                }
                match event.token() {
                    Token(TOKEN_EVENT_FANOTIFY) if event.is_readable() => {
                        self.drain_events(&mut buf)?;
                    }
                    Token(TOKEN_EVENT_WAKER) if !self.active.load(Ordering::Acquire) => {
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    /// Read and process all pending fanotify events in a non-blocking loop.
    ///
    /// The mio registration is edge-triggered, so this must keep reading until
    /// `EAGAIN` — returning early with events still queued would strand them until
    /// an unrelated new event re-arms the readiness edge.
    fn drain_events(&self, buf: &mut [u8]) -> Result<()> {
        loop {
            let n = unsafe {
                libc::read(
                    self.fan_fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            match n {
                0 => return Ok(()),
                n if n > 0 => self.process_event_buffer(&buf[..n as usize])?,
                _ => {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EAGAIN) => return Ok(()),
                        // Without FAN_REPORT_FD_ERROR the kernel fails the read()
                        // itself when it cannot allocate the per-event fd. fd/memory
                        // pressure is transient node sickness, not a broken group —
                        // killing the worker here would deadlock stop() and wedge the
                        // daemon (see run_loop). Back off briefly and retry so the
                        // still-queued permission events eventually get answered.
                        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOMEM) => {
                            // Stay responsive to stop(): the waker can't reach us
                            // while we're off the poll loop.
                            if !self.active.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            warn!(
                                "fanotify: transient {} reading events; retrying after backoff",
                                err
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        _ => return Err(err),
                    }
                }
            }
        }
    }

    /// Walk the raw event buffer, dispatch each metadata record, and answer the permission event.
    ///
    /// Parse failures fall into two classes, and conflating them is a hang:
    ///
    /// * **Semantic** — the record is well-formed but unusable (no `FAN_EVENT_INFO_TYPE_RANGE`
    ///   record, unresolvable backing file). [`handle_event`](Self::handle_event) returns `Err`,
    ///   that one event is denied, and the walk continues with the rest of the batch.
    /// * **Structural** — the record boundary itself is untrustworthy (bad `vers`, bogus
    ///   `event_len`). The remainder of the buffer cannot be walked, so the batch is abandoned —
    ///   but every fd we can still account for is denied first. An event fd that is neither
    ///   answered nor closed leaves its reader blocked in `D` state until the whole group closes.
    fn process_event_buffer(&self, buf: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= buf.len() {
            // SAFETY: we verified the buffer has enough bytes.
            let meta =
                unsafe { &*(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };

            // fanotify(7) mandates checking the metadata version before consuming an
            // event; a mismatched kernel ABI must fail loudly, not be misparsed.
            //
            // The fd field is deliberately NOT touched on mismatch: with an unknown
            // layout the value at that offset may be garbage, and answering on (or
            // closing) an arbitrary descriptor — possibly one of our own — is worse
            // than leaving the event unanswered. A version mismatch is a wrong-kernel
            // condition that shows up on the very first event, not a mid-flight hazard.
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                return Err(std::io::Error::other(format!(
                    "fanotify: metadata version {} != expected {}; kernel ABI mismatch",
                    meta.vers,
                    libc::FANOTIFY_METADATA_VERSION
                )));
            }

            // A `FAN_Q_OVERFLOW` record (fd == FAN_NOFD) means the kernel's event queue
            // filled and it DROPPED permission events. The kernel fail-opens what it
            // drops, so the readers behind those events have already been served
            // unfilled sparse holes as zeros — silent data corruption that we cannot
            // retroactively repair. There is nothing to answer here and no way to
            // recover the lost events, so surface it loudly and fail closed rather than
            // keep serving a stream we know has holes in it. `FAN_UNLIMITED_QUEUE` is
            // deliberately not set in `new()` so this safety valve stays reachable.
            if meta.fd == FAN_NOFD {
                let denied = self.deny_events_in_buffer(&buf[offset..]);
                error!(
                    "fanotify: kernel event queue overflowed (mask {:#x}) for mount {:?}; \
                     dropped pre-content events were fail-opened by the kernel and may have \
                     served zeros. Denied {} further event(s) in this batch and failing closed.",
                    meta.mask & FAN_Q_OVERFLOW,
                    self.mountpoint,
                    denied
                );
                return Err(std::io::Error::other(
                    "fanotify: event queue overflow; dropped permission events cannot be answered",
                ));
            }

            let meta_len = meta.event_len as usize;
            if meta_len < std::mem::size_of::<libc::fanotify_event_metadata>()
                || offset + meta_len > buf.len()
            {
                // The next record boundary is unknowable, so the rest of the buffer is
                // lost. This record's own fd is still trustworthy (the metadata version
                // checked out above), so answer it instead of stranding its reader, then
                // fail closed — a corrupt event stream must not be chewed on silently.
                self.deny_event_fd(meta.fd as RawFd);
                return Err(std::io::Error::other(format!(
                    "fanotify: bogus event_len {} at buffer offset {} (buffer {} bytes); \
                     denied the current event and abandoned the batch",
                    meta_len,
                    offset,
                    buf.len()
                )));
            }

            // Serve the event; the response reflects whether the content is now available.
            // The guard owns the event fd for exactly-once answering: if
            // `handle_event` panics and unwinds through here, its Drop denies
            // with EIO and closes the fd, so the blocked reader errors instead
            // of hanging in D-state behind an unanswerable event.
            let guard = EventFdGuard::new(self, meta.fd as RawFd);
            let response = match self.handle_event(meta, &buf[offset..offset + meta_len]) {
                Ok(()) => FAN_ALLOW,
                Err(e) => {
                    warn!("fanotify: failed to serve pre-content event: {}", e);
                    // Deny — never allow — so the reader gets an error instead of
                    // the unfetched hole's zeros. The errno is the most specific
                    // one we still hold (see `deny_errno_for`); EROFS flattens it
                    // to EIO for readers coming through the mount, but denying is
                    // what makes the read fail at all.
                    fan_deny_errno(deny_errno_for(&e))
                }
            };
            guard.finish(response);

            offset += meta_len;
        }
        Ok(())
    }

    /// Write a permission response (`FAN_ALLOW` / `FAN_DENY_ERRNO`) for `event_fd`.
    ///
    /// A response that never reaches the kernel leaves the accessing task blocked in
    /// `D` state indefinitely, so `EINTR` is retried rather than dropped; any other
    /// failure is logged loudly (there is no recovery — the fd is closed either way).
    fn write_response(&self, event_fd: RawFd, response: u32) {
        let resp = fanotify_response {
            fd: event_fd,
            response,
        };
        let resp_buf = unsafe {
            std::slice::from_raw_parts(
                &resp as *const fanotify_response as *const u8,
                std::mem::size_of::<fanotify_response>(),
            )
        };
        loop {
            let ret = unsafe {
                libc::write(
                    self.fan_fd.as_raw_fd(),
                    resp_buf.as_ptr() as *const libc::c_void,
                    resp_buf.len(),
                )
            };
            if ret >= 0 {
                return;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // A kernel that rejects a specific DENY errno payload (EINVAL)
            // must still get *a* response, or the reader stalls in D-state
            // forever. Retry once with the always-valid EIO form. The guard
            // excludes FAN_ALLOW: a rejected allow must not be flipped into a
            // spurious read error.
            if err.raw_os_error() == Some(libc::EINVAL)
                && response != FAN_ALLOW
                && response != fan_deny_errno(libc::EIO)
            {
                warn!(
                    "fanotify: kernel rejected deny response {:#x} for fd {}; retrying with EIO",
                    response, event_fd
                );
                self.write_response(event_fd, fan_deny_errno(libc::EIO));
                return;
            }
            error!(
                "fanotify: failed to write permission response for fd {}: {}; \
                 the blocked reader will stall until the group closes",
                event_fd, err
            );
            return;
        }
    }

    /// Extract the trailing `FAN_EVENT_INFO_TYPE_RANGE` record from a raw event buffer, if present.
    ///
    /// Pure function over the event bytes so it can be unit-tested without a live fanotify fd.
    fn parse_range(raw_buf: &[u8]) -> Option<fanotify_event_info_range> {
        let mut cursor = std::mem::size_of::<libc::fanotify_event_metadata>();
        while cursor + std::mem::size_of::<fanotify_event_info_header>() <= raw_buf.len() {
            // SAFETY: bounds checked by the loop condition.
            let hdr =
                unsafe { &*(raw_buf.as_ptr().add(cursor) as *const fanotify_event_info_header) };
            let hdr_len = hdr.len as usize;
            if hdr_len < std::mem::size_of::<fanotify_event_info_header>()
                || cursor + hdr_len > raw_buf.len()
            {
                break;
            }
            if hdr.info_type == FAN_EVENT_INFO_TYPE_RANGE
                && hdr_len >= std::mem::size_of::<fanotify_event_info_range>()
            {
                // SAFETY: verified the record is large enough for `fanotify_event_info_range`.
                return Some(unsafe {
                    *(raw_buf.as_ptr().add(cursor) as *const fanotify_event_info_range)
                });
            }
            cursor += hdr_len;
        }
        None
    }

    /// Whether this handler serves `blob_id`, i.e. that blob's cache file is one of the EROFS
    /// devices behind the live mount.
    pub fn serves_blob(&self, blob_id: &str) -> bool {
        self.blob_backings
            .iter()
            .any(|b| b.blob.blob_info().blob_id() == blob_id)
    }

    /// Resolve a backing-file identity to the data blob serving it.
    fn find_backing(&self, dev: u64, ino: u64) -> Option<&BlobBacking> {
        self.blob_backings
            .iter()
            .find(|b| b.dev == dev && b.ino == ino)
    }

    /// Inspect a single event and, for `FAN_PRE_ACCESS`, fetch + materialize the requested range.
    ///
    /// Returns `Ok(())` when the content is present (or the event needs no fill); the caller maps
    /// that to `FAN_ALLOW` and any error to `FAN_DENY_ERRNO(EIO)`.
    fn handle_event(&self, meta: &libc::fanotify_event_metadata, raw_buf: &[u8]) -> Result<()> {
        // Only pre-access content events need filling; FAN_OPEN_PERM and friends are allowed.
        if (meta.mask & FAN_PRE_ACCESS) == 0 {
            return Ok(());
        }
        let range = match Self::parse_range(raw_buf) {
            Some(r) => r,
            // Every 6.14+ pre-access read carries a RANGE record. An event
            // without one cannot be filled, and allowing it blind would let
            // the reader see unfilled sparse holes as zeros — the silent
            // corruption class this whole path exists to prevent. Deny loudly
            // instead (upstream v3 made the same call).
            None => {
                return Err(std::io::Error::other(
                    "pre-access event carries no range record; denying un-fillable access",
                ));
            }
        };
        // Defensive: `process_event_buffer` rejects `FAN_NOFD` before dispatching here, so
        // this should be unreachable. Kept because everything below dereferences the fd,
        // and a future second call site must not silently `fstat(-1)`.
        let event_fd = meta.fd as RawFd;
        if event_fd < 0 {
            return Ok(());
        }

        // Identify which blob's sparse file this event refers to. A match by (dev, ino) also
        // proves the blob's cache file *is* the EROFS-visible device file, so populating the
        // cache below makes the bytes visible to the kernel without an extra copy.
        let (dev, ino) = fd_identity(event_fd)?;
        let backing = match self.find_backing(dev, ino) {
            Some(b) => b,
            None => {
                // Unmanaged file (e.g. the fully-present bootstrap): nothing to fetch.
                trace!(
                    "fanotify: pre-access for unmanaged file dev={} ino={}, allowing",
                    dev, ino
                );
                return Ok(());
            }
        };

        trace!(
            "fanotify: pre-access blob={} offset={} count={}",
            backing.blob.blob_info().blob_id(),
            range.offset,
            range.count
        );

        // Clamp the kernel-reported range to the blob's uncompressed size before
        // fetching. fanotify(7) documents pre-content ranges as block-aligned and
        // possibly extending beyond EOF (and page-cache large-folio work keeps
        // widening read granularity), while `get_chunks_uncompressed` hard-errors on
        // any range past the end — without the clamp a legitimate read of the last
        // partial block would be answered FAN_DENY_ERRNO(EIO).
        let blob_size = backing.blob.blob_info().uncompressed_size();
        if range.offset >= blob_size {
            return Ok(());
        }
        let count = range.count.min(blob_size - range.offset);
        if count == 0 {
            // A zero-length range (the kernel can deliver count == 0) has
            // nothing to fill; don't push an empty request into the chunk
            // resolver, whose behavior for empty ranges is not a contract.
            return Ok(());
        }

        // Download and decompress the requested range into the sparse backing file.
        let obj = backing.blob.blob().get_blob_object().ok_or_else(|| {
            std::io::Error::other(format!(
                "fanotify: blob object unavailable for {}",
                backing.blob.blob_info().blob_id()
            ))
        })?;
        // Shared for the whole fetch: `fetch_range_uncompressed` both writes the bytes and
        // marks them ready, and an invalidation interleaved between those two steps would
        // leave the map promising data that was just punched away. Concurrent fetches of
        // other ranges (and of other blobs) are unaffected.
        let _serving = backing
            .io_lock
            .read()
            .map_err(|_| std::io::Error::other("fanotify: blob io lock poisoned"))?;
        obj.fetch_range_uncompressed(range.offset, count)?;

        Ok(())
    }

    /// Invalidate the on-demand cache for a blob, so its data is fetched afresh on next access.
    ///
    /// Two things make the cached data "present", and **both** have to be revoked, in this
    /// order:
    ///
    /// 1. the chunk map, which records which chunks have been fetched. The fetch path consults
    ///    it first ([`is_range_all_ready`] short-circuits, and every chunk goes through
    ///    `check_ready_and_mark_pending`), so a stale map means a `FAN_PRE_ACCESS` event is
    ///    answered without fetching anything;
    /// 2. the bytes themselves, deallocated with `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`
    ///    so the file keeps its size and reads still raise events.
    ///
    /// Clearing the map *before* punching is the whole correctness argument. The bad window in
    /// this order is "map says not-ready, bytes still there" — a wasted re-fetch, correct data.
    /// The reverse order's window is "map says ready, bytes gone", which the kernel serves to
    /// the reader as zeros: silent corruption, and precisely what the pre-content path exists
    /// to prevent. The `io_lock` closes the matching race against fetches already in flight.
    ///
    /// Note the mark itself is deliberately left armed. Should a future change stop arming
    /// fully-cached blobs (so the kernel can readahead them again), un-arming must be reversed
    /// *here*, before step 2 — an unmarked blob whose bytes are punched away raises no event
    /// and reads as zeros.
    ///
    /// [`is_range_all_ready`]: nydus_storage::cache::state::RangeMap::is_range_all_ready
    pub fn invalidate(&self, blob_id: String) -> Result<()> {
        let backing = self
            .blob_backings
            .iter()
            .find(|b| b.blob.blob_info().blob_id() == blob_id)
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::NotFound,
                    format!("fanotify: cannot invalidate unknown blob {}", blob_id),
                )
            })?;

        // Exclusive: no fetch may be between "wrote the bytes" and "marked them ready" while
        // the steps below run.
        let _invalidating = backing
            .io_lock
            .write()
            .map_err(|_| std::io::Error::other("fanotify: blob io lock poisoned"))?;

        let obj = backing.blob.blob().get_blob_object().ok_or_else(|| {
            std::io::Error::other(format!("fanotify: blob object unavailable for {}", blob_id))
        })?;
        let fd = backing.blob.file().as_raw_fd();

        invalidate_in_order(
            // Step 1 — revoke the readiness bookkeeping.
            || {
                obj.reset_data_ready().map_err(|e| {
                    std::io::Error::other(format!(
                        "fanotify: cannot revoke ready state for blob {}: {}; \
                         refusing to punch its cache (would serve zeros)",
                        blob_id, e
                    ))
                })
            },
            // Step 2 — discard the bytes.
            || {
                let len = fd_file_size(fd)?;
                if len == 0 {
                    return Ok(());
                }
                let ret = unsafe {
                    libc::fallocate(
                        fd,
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        0,
                        len as libc::off_t,
                    )
                };
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            },
        )?;

        info!("fanotify: invalidated cache for blob {}", blob_id);
        Ok(())
    }
}

/// Run a cache invalidation in the only safe order: revoke the readiness bookkeeping, *then*
/// discard the bytes.
///
/// Factored out of [`FanotifyHandler::invalidate`] so both the ordering and the fail-closed
/// behaviour are unit-testable without a live blob or a 6.14 kernel.
///
/// If readiness cannot be revoked the bytes MUST stay: punching them while the chunk map still
/// claims they are cached is exactly what makes a later reader see zeros. Leaving a populated
/// cache in place is merely wasteful, so the failure direction is the safe one.
fn invalidate_in_order(
    revoke_ready: impl FnOnce() -> Result<()>,
    discard_bytes: impl FnOnce() -> Result<()>,
) -> Result<()> {
    revoke_ready()?;
    discard_bytes()
}

/// Walk a raw fanotify event buffer, invoking `f` for every record that can be trusted.
///
/// Stops at the first unparsable record — an unknown metadata version or an `event_len` that
/// is too small or runs past the buffer means the *next* record boundary is guesswork, and a
/// misread `fd` field would have the caller answer on (or close) an arbitrary descriptor.
///
/// Only used off the hot path (shutdown drain, structural-failure recovery); the serving loop
/// in [`FanotifyHandler::process_event_buffer`] needs per-record error handling and does its
/// own walk.
fn for_each_parsable_event(buf: &[u8], mut f: impl FnMut(&libc::fanotify_event_metadata)) {
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= buf.len() {
        // SAFETY: we verified the buffer has enough bytes.
        let meta = unsafe { &*(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };
        let meta_len = meta.event_len as usize;
        if meta.vers != libc::FANOTIFY_METADATA_VERSION
            || meta_len < std::mem::size_of::<libc::fanotify_event_metadata>()
            || offset + meta_len > buf.len()
        {
            break;
        }
        f(meta);
        offset += meta_len;
    }
}

/// Get the current size of an open file descriptor.
fn fd_file_size(fd: RawFd) -> Result<u64> {
    // SAFETY: `stat` is plain-old-data; `fstat` only writes into it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut st) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.st_size as u64)
}

// The fanotify fd is closed when OwnedFd drops. `FanotifyHandler` derives Send/Sync
// automatically from its fields — do not add blanket `unsafe impl`s here: they would
// silently vouch for any future non-thread-safe field.

#[cfg(test)]
mod tests {
    #[test]
    fn deny_errno_passthrough_table() {
        use super::deny_errno_for;
        let e = |errno| std::io::Error::from_raw_os_error(errno);
        assert_eq!(deny_errno_for(&e(libc::ENOSPC)), libc::ENOSPC);
        assert_eq!(deny_errno_for(&e(libc::EDQUOT)), libc::EDQUOT);
        assert_eq!(deny_errno_for(&e(libc::EIO)), libc::EIO);
        // Everything else collapses to EIO — including errnos the kernel
        // would reject as deny payloads.
        assert_eq!(deny_errno_for(&e(libc::ENOENT)), libc::EIO);
        assert_eq!(
            deny_errno_for(&std::io::Error::other("no raw errno")),
            libc::EIO
        );

        // The shape the on-demand path actually produces: a cache `pwrite` that hit ENOSPC,
        // as a `StorageError`, converted at the storage boundary. The errno has to survive
        // -- answering EIO here tells a reader "I/O error" for a full disk, and answering
        // FAN_ALLOW would hand it an unfilled sparse hole full of zeros.
        let storage = nydus_storage::StorageError::cache_io(
            "pwrite",
            std::io::Error::from_raw_os_error(libc::ENOSPC),
        );
        assert_eq!(deny_errno_for(&std::io::Error::from(storage)), libc::ENOSPC);

        // ... and the same through a `Custom` wrapper, which `raw_os_error()` alone cannot see
        // through. This is the regression the switch to `source_errno` exists for.
        let storage = nydus_storage::StorageError::cache_io(
            "pwrite",
            std::io::Error::from_raw_os_error(libc::EDQUOT),
        );
        let wrapped = std::io::Error::other(crate::Error::from(storage));
        assert_eq!(
            wrapped.raw_os_error(),
            None,
            "precondition: wrapper hides the errno"
        );
        assert_eq!(deny_errno_for(&wrapped), libc::EDQUOT);
    }

    use super::*;

    /// Serialize a `fanotify_event_info_range` record to raw bytes.
    fn range_record(offset: u64, count: u64) -> Vec<u8> {
        let rec = fanotify_event_info_range {
            hdr: fanotify_event_info_header {
                info_type: FAN_EVENT_INFO_TYPE_RANGE,
                pad: 0,
                len: std::mem::size_of::<fanotify_event_info_range>() as u16,
            },
            pad: 0,
            offset,
            count,
        };
        // SAFETY: `rec` is a `#[repr(C)]` POD struct.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &rec as *const _ as *const u8,
                std::mem::size_of::<fanotify_event_info_range>(),
            )
        };
        bytes.to_vec()
    }

    /// Build an event buffer: a (zeroed) metadata header followed by `records`.
    fn event_with_records(records: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<libc::fanotify_event_metadata>()];
        buf.extend_from_slice(records);
        buf
    }

    #[test]
    fn test_parse_range_extracts_record() {
        let buf = event_with_records(&range_record(0x4000, 0x1000));
        let r = FanotifyHandler::parse_range(&buf).expect("range record should be parsed");
        assert_eq!(r.offset, 0x4000);
        assert_eq!(r.count, 0x1000);
    }

    #[test]
    fn test_parse_range_absent_returns_none() {
        let buf = event_with_records(&[]);
        assert!(FanotifyHandler::parse_range(&buf).is_none());
    }

    #[test]
    fn test_parse_range_truncated_returns_none() {
        // A record whose header claims the full length but whose body is truncated must be
        // rejected rather than read out of bounds.
        let mut rec = range_record(1, 2);
        rec.truncate(rec.len() - 4);
        let buf = event_with_records(&rec);
        assert!(FanotifyHandler::parse_range(&buf).is_none());
    }

    #[test]
    fn test_fan_deny_errno_encoding() {
        // Kernel macro: FAN_DENY (0x02) in the low bits, errno in the top 8 bits
        // (FAN_ERRNO_SHIFT = 32 - FAN_ERRNO_BITS = 24).
        let resp = fan_deny_errno(libc::EIO);
        assert_eq!(resp & 0x0000_ffff, 0x02);
        assert_eq!((resp >> 24) & 0xff, libc::EIO as u32);
        // Exact kernel-computed value for EIO (5): 0x02 | (5 << 24) = 0x0500_0002.
        assert_eq!(resp, 0x0500_0002);
    }

    // ---- mount option construction (Part 2d) ------------------------------

    #[test]
    fn test_device_options_join_in_order() {
        let blobs = vec![
            PathBuf::from("/cache/blob_0"),
            PathBuf::from("/cache/blob_1"),
        ];
        let opts = build_erofs_device_options(&blobs).expect("plain paths are accepted");
        // Device-table order is load-bearing: the Nth `device=` entry backs the Nth
        // slot in the EROFS device table.
        assert_eq!(opts, "device=/cache/blob_0,device=/cache/blob_1");
    }

    #[test]
    fn test_device_options_empty_is_empty_string() {
        // A bootstrap-only image has no data blobs; `mount_erofs` maps this to a NULL
        // data pointer rather than an empty C string.
        assert_eq!(
            build_erofs_device_options(&[]).expect("no devices is valid"),
            ""
        );
    }

    #[test]
    fn test_device_options_reject_comma_in_path() {
        // A comma would silently split one path into two bogus mount options.
        let blobs = vec![PathBuf::from("/cache/we,ird/blob_0")];
        let err = build_erofs_device_options(&blobs).expect_err("comma must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("comma"),
            "error should name the problem: {err}"
        );
    }

    #[test]
    fn test_device_options_reject_length_over_kernel_limit() {
        // The kernel truncates the mount data at one page instead of erroring, so a
        // deep cache dir + a large device table must be caught here.
        let deep = PathBuf::from(format!("/{}", "d".repeat(400)));
        let blobs = vec![deep; 12];
        let err =
            build_erofs_device_options(&blobs).expect_err("over-long options must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains("shorter blob cache directory"),
            "error should say how to fix it: {msg}"
        );
    }

    #[test]
    fn test_device_options_accept_up_to_the_limit() {
        // Exactly at the boundary must still mount: "device=" (7) + path length.
        let path = PathBuf::from(format!("/{}", "d".repeat(MOUNT_DATA_MAX - 8)));
        let opts = build_erofs_device_options(std::slice::from_ref(&path))
            .expect("a single device at exactly the limit is valid");
        assert_eq!(opts.len(), MOUNT_DATA_MAX);
    }

    // ---- event buffer walking (Parts 2a / 2b) ----------------------------

    /// Serialize a `fanotify_event_metadata` header with the given fd and mask.
    ///
    /// `event_len` covers the header plus `extra_len` trailing bytes.
    fn event_header(fd: i32, mask: u64, extra_len: usize) -> Vec<u8> {
        let meta = libc::fanotify_event_metadata {
            event_len: (std::mem::size_of::<libc::fanotify_event_metadata>() + extra_len) as u32,
            vers: libc::FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: std::mem::size_of::<libc::fanotify_event_metadata>() as u16,
            mask,
            fd,
            pid: 0,
        };
        // SAFETY: `fanotify_event_metadata` is a `#[repr(C)]` POD struct.
        unsafe {
            std::slice::from_raw_parts(
                &meta as *const _ as *const u8,
                std::mem::size_of::<libc::fanotify_event_metadata>(),
            )
        }
        .to_vec()
    }

    /// Offset of the `vers` field within `fanotify_event_metadata`.
    const VERS_OFFSET: usize = std::mem::offset_of!(libc::fanotify_event_metadata, vers);

    #[test]
    fn test_overflow_record_is_recognisable_by_nofd() {
        // The FAN_Q_OVERFLOW record is what `process_event_buffer` keys on to fail
        // closed. Guard the two properties that make it detectable.
        let buf = event_header(FAN_NOFD, FAN_Q_OVERFLOW, 0);
        let meta = unsafe { &*(buf.as_ptr() as *const libc::fanotify_event_metadata) };
        assert_eq!(meta.fd, FAN_NOFD);
        assert_ne!(meta.mask & FAN_Q_OVERFLOW, 0);
        assert_eq!(meta.vers, libc::FANOTIFY_METADATA_VERSION);
    }

    #[test]
    fn test_deny_walk_stops_at_bad_version() {
        // A record whose metadata version is unknown has an untrusted layout: the
        // walk must stop there rather than read an `fd` field that may be garbage.
        let hdr_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = event_header(7, FAN_PRE_ACCESS, 0);
        buf.extend_from_slice(&event_header(8, FAN_PRE_ACCESS, 0));
        buf[hdr_len + VERS_OFFSET] = libc::FANOTIFY_METADATA_VERSION.wrapping_add(1);

        assert_eq!(
            walk_deniable_events(&buf),
            vec![7],
            "the second record's fd must not be touched once the version is unknown"
        );
    }

    #[test]
    fn test_deny_walk_stops_at_bogus_event_len() {
        // event_len smaller than the fixed header makes the next boundary unknowable.
        let hdr_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = event_header(7, FAN_PRE_ACCESS, 0);
        buf.extend_from_slice(&event_header(8, FAN_PRE_ACCESS, 0));
        buf[hdr_len..hdr_len + 4].copy_from_slice(&4u32.to_ne_bytes());

        assert_eq!(walk_deniable_events(&buf), vec![7]);
    }

    #[test]
    fn test_deny_walk_stops_when_record_runs_past_buffer() {
        // A truncated read: the last record claims more bytes than were delivered.
        let hdr_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = event_header(7, FAN_PRE_ACCESS, 0);
        buf.extend_from_slice(&event_header(8, FAN_PRE_ACCESS, 64));
        assert!(buf.len() < 2 * hdr_len + 64);

        assert_eq!(walk_deniable_events(&buf), vec![7]);
    }

    #[test]
    fn test_deny_walk_covers_whole_batch_and_skips_nofd() {
        // The happy path for the structural-failure and shutdown drains: every fd in
        // the batch is accounted for, and the fd-less overflow record is skipped
        // rather than treated as a descriptor to close.
        let mut buf = event_header(7, FAN_PRE_ACCESS, 0);
        buf.extend_from_slice(&event_header(FAN_NOFD, FAN_Q_OVERFLOW, 0));
        buf.extend_from_slice(&event_header(9, FAN_PRE_ACCESS, 0));

        assert_eq!(walk_deniable_events(&buf), vec![7, 9]);
    }

    /// Collect the fds that [`FanotifyHandler::deny_events_in_buffer`] would answer.
    ///
    /// Drives the production walk ([`for_each_parsable_event`]) — the part whose
    /// termination rules strand readers in `D` state when they are wrong — without
    /// needing a live fanotify group (root + kernel ≥ 6.14). The `write`/`close` pair
    /// itself is covered by `misc/fanotify/*.sh`.
    fn walk_deniable_events(buf: &[u8]) -> Vec<RawFd> {
        let mut fds = Vec::new();
        for_each_parsable_event(buf, |meta| {
            if meta.fd >= 0 {
                fds.push(meta.fd as RawFd);
            }
        });
        fds
    }

    #[test]
    fn invalidation_revokes_readiness_before_discarding_bytes() {
        use std::cell::RefCell;

        // The reverse order leaves a window in which the chunk map claims data is cached and
        // the bytes are already gone — which the kernel serves to the reader as zeros.
        let log = RefCell::new(Vec::new());
        invalidate_in_order(
            || {
                log.borrow_mut().push("revoke");
                Ok(())
            },
            || {
                log.borrow_mut().push("discard");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*log.borrow(), vec!["revoke", "discard"]);
    }

    #[test]
    fn invalidation_keeps_the_bytes_when_readiness_cannot_be_revoked() {
        use std::cell::Cell;

        // Fail-closed: a cache that could not be marked stale must keep its data. Punching it
        // anyway would produce precisely the ready-map-over-a-hole state this ordering exists
        // to prevent.
        let discarded = Cell::new(false);
        let err = invalidate_in_order(
            || Err(std::io::Error::other("chunk map is read-only")),
            || {
                discarded.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            !discarded.get(),
            "bytes were discarded despite a failed revoke"
        );
        assert!(err.to_string().contains("read-only"), "unexpected: {err}");
    }
}
