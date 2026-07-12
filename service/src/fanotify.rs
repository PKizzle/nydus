// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Handler to serve on-demand blob data through fanotify pre-content hooks.
//!
//! [`FanotifyHandler`] replaces the deprecated fscache-based on-demand path.
//! It works by:
//! 1. Creating a fanotify group with `FAN_CLASS_PRE_CONTENT`.
//! 2. Placing marks (`FAN_PRE_ACCESS` **only** — never `FAN_OPEN_PERM`, which would
//!    block every open including the daemon's own) on the sparse data-blob device
//!    files (hardlinks of each blob's `.blob.data` cache file — same inode).
//! 3. Issuing a file-backed EROFS mount with the **bootstrap as the mount source**
//!    and the data blobs as `device=` options:
//!    `mount("<bootstrap>", mountpoint, "erofs", 0, "device=blob_0,device=blob_1,...")`
//!    (a NULL/`none` source fails with `EINVAL`).
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
use std::sync::{Arc, Barrier, Mutex};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::blob_cache::{BlobCacheMgr, DataBlob};
use crate::fanotify_sys::{
    FAN_CLASS_PRE_CONTENT, FAN_EVENT_INFO_TYPE_RANGE, FAN_PRE_ACCESS, fan_deny_errno,
    fanotify_event_info_header, fanotify_event_info_range,
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
/// This deliberately replaces the previous blanket `unsafe impl Send/Sync for FanotifyHandler`,
/// which vouched for every present and future field; scoping the assertion to the one field
/// that needs it keeps the compiler checking the rest.
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

// Issue a file-backed EROFS mount via `mount(2)` (kernel ≥ 6.12).
//
// The **bootstrap** is the mount source: it holds the EROFS superblock, inode metadata and the
// device table. The **data blobs** are the extra block devices that back file content; they are
// passed as `device=<path>` mount options in device-table order. The bootstrap itself is NOT a
// `device=` entry, and the source must be the bootstrap path — passing a NULL/`none` source fails
// with `EINVAL` ("special device none does not exist").
fn mount_erofs(bootstrap: &Path, blobs: &[PathBuf], mountpoint: &Path) -> Result<()> {
    let options = blobs
        .iter()
        .map(|blob| format!("device={}", blob.display()))
        .collect::<Vec<_>>()
        .join(",");

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

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            mountpoint_c.as_ptr(),
            fstype.as_ptr(),
            0,
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
        // Create the fanotify notification group.
        // These raw libc calls are used because nix 0.24 does not expose fanotify.
        //
        // We deliberately do NOT set `FAN_REPORT_FID`: pre-content fill needs a real file
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

    /// Signal all workers to stop and wait until they have exited.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.waker.wake();
        self.barrier.wait();
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
        let result = self.run_loop_inner();
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
    fn process_event_buffer(&self, buf: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= buf.len() {
            // SAFETY: we verified the buffer has enough bytes.
            let meta =
                unsafe { &*(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };

            // fanotify(7) mandates checking the metadata version before consuming an
            // event; a mismatched kernel ABI must fail loudly, not be misparsed.
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                return Err(std::io::Error::other(format!(
                    "fanotify: metadata version {} != expected {}; kernel ABI mismatch",
                    meta.vers,
                    libc::FANOTIFY_METADATA_VERSION
                )));
            }

            let meta_len = meta.event_len as usize;
            if meta_len == 0 || meta_len < std::mem::size_of::<libc::fanotify_event_metadata>() {
                warn!("fanotify: bogus event_len {}", meta_len);
                break;
            }
            if offset + meta_len > buf.len() {
                break;
            }

            // Serve the event; the response reflects whether the content is now available.
            let event_fd = meta.fd as RawFd;
            let response = match self.handle_event(meta, &buf[offset..offset + meta_len]) {
                Ok(()) => FAN_ALLOW,
                Err(e) => {
                    warn!("fanotify: failed to serve pre-content event: {}", e);
                    // Deny with EIO so the consumer sees an I/O error instead of zero-filled data.
                    fan_deny_errno(libc::EIO)
                }
            };

            // Permission events deliver an open fd that must be answered and then closed,
            // otherwise the daemon leaks a descriptor per access.
            if event_fd >= 0 {
                self.write_response(event_fd, response);
                unsafe {
                    libc::close(event_fd);
                }
            }

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
            // A pre-access event with no range record carries nothing to fill.
            None => return Ok(()),
        };
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

        // Download and decompress the requested range into the sparse backing file.
        let obj = backing.blob.blob().get_blob_object().ok_or_else(|| {
            std::io::Error::other(format!(
                "fanotify: blob object unavailable for {}",
                backing.blob.blob_info().blob_id()
            ))
        })?;
        obj.fetch_range_uncompressed(range.offset, count)?;

        Ok(())
    }

    /// Invalidate the on-demand cache for a blob by punching out its sparse backing file.
    ///
    /// `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` deallocates the cached extents while keeping
    /// the file size, so subsequent accesses raise fresh `FAN_PRE_ACCESS` events and are re-fetched
    /// — mirroring the eviction semantics of the old fscache handler.
    pub fn cull_cache(&self, blob_id: String) -> Result<()> {
        let backing = self
            .blob_backings
            .iter()
            .find(|b| b.blob.blob_info().blob_id() == blob_id)
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::NotFound,
                    format!("fanotify: cannot cull unknown blob {}", blob_id),
                )
            })?;

        let fd = backing.blob.file().as_raw_fd();
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
        info!("fanotify: culled cache for blob {}", blob_id);
        Ok(())
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
}
