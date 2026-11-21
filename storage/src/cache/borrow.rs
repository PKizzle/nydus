// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Chunk data borrowed from other images' cache files of the same blob.
//!
//! A cache entry that misses a chunk may read the chunk's byte range from a cache file another
//! image keeps for the same blob (a lender) and use it only when it matches the entry's own
//! digest. Lenders are untrusted data: nothing they say beyond those bytes is used, and they are
//! never written. Their descriptors raise no fanotify events, since a lender may be a live EROFS
//! device carrying another image's pre-content marks.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

/// Lenders listed per blob cache entry.
const MAX_LENDERS: usize = 4;
/// Digest mismatches after which a lender is no longer used by an entry.
const MAX_STRIKES: u32 = 3;

static BORROWED_CHUNKS: AtomicU64 = AtomicU64::new(0);
static BORROWED_BYTES: AtomicU64 = AtomicU64::new(0);
static LENDER_MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Lender descriptors of this process by `(st_dev, st_ino)`, with the path each was opened at.
/// One descriptor per lender, shared by every entry that borrows from it.
type Lenders = HashMap<(u64, u64), (PathBuf, Arc<File>)>;
static LENDERS: LazyLock<Mutex<Lenders>> = LazyLock::new(Default::default);

/// Process totals of borrowing, for metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BorrowCounters {
    /// Chunks filled from a lender.
    pub chunks: u64,
    /// Bytes of those chunks.
    pub bytes: u64,
    /// Lender reads that failed the borrower's digest.
    pub mismatches: u64,
}

/// The borrowing totals of this process.
pub fn borrow_counters() -> BorrowCounters {
    BorrowCounters {
        chunks: BORROWED_CHUNKS.load(Ordering::Relaxed),
        bytes: BORROWED_BYTES.load(Ordering::Relaxed),
        mismatches: LENDER_MISMATCHES.load(Ordering::Relaxed),
    }
}

/// Close the lender descriptors of files under `dir` (or `dir` itself), and of every lender
/// already unlinked. Call before deleting cache files, so a borrower's descriptor does not keep
/// their disk space allocated.
pub fn release_lenders_under(dir: &Path) {
    LENDERS
        .lock()
        .unwrap()
        .retain(|_, (path, file)| !path.starts_with(dir) && is_linked(file));
}

pub(crate) fn count_borrowed(bytes: u64) {
    BORROWED_CHUNKS.fetch_add(1, Ordering::Relaxed);
    BORROWED_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

fn is_linked(file: &File) -> bool {
    file.metadata().is_ok_and(|m| m.nlink() > 0)
}

/// A cache file of the same blob kept for another image, as one cache entry sees it.
pub(crate) struct Lender {
    path: PathBuf,
    id: (u64, u64),
    strikes: AtomicU32,
}

impl Lender {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The lender's descriptor, opened on first use. `None` once the lender is dropped: unlinked,
    /// released, replaced by another file, or struck out.
    pub(crate) fn file(&self) -> Option<Arc<File>> {
        if self.strikes.load(Ordering::Acquire) >= MAX_STRIKES {
            return None;
        }
        if let Some((_, file)) = LENDERS.lock().unwrap().get(&self.id)
            && is_linked(file)
        {
            return Some(file.clone());
        }
        // Opened outside the lock: a quiet open runs a helper thread and may take a while.
        let file = open_quiet(&self.path).filter(|f| {
            f.metadata()
                .is_ok_and(|m| (m.dev(), m.ino()) == self.id && m.nlink() > 0)
        });
        let Some(file) = file else {
            self.strikes.store(MAX_STRIKES, Ordering::Release);
            LENDERS.lock().unwrap().remove(&self.id);
            return None;
        };
        let mut lenders = LENDERS.lock().unwrap();
        match lenders.get(&self.id) {
            // Another entry opened it meanwhile.
            Some((_, f)) if is_linked(f) => Some(f.clone()),
            _ => {
                let file = Arc::new(file);
                lenders.insert(self.id, (self.path.clone(), file.clone()));
                Some(file)
            }
        }
    }

    /// Count a read of this lender that failed the borrower's digest; returns whether that
    /// dropped the lender.
    pub(crate) fn strike(&self) -> bool {
        LENDER_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        self.strikes.fetch_add(1, Ordering::AcqRel) + 1 == MAX_STRIKES
    }
}

/// Open `path` read-only without following a symlink, through a descriptor that raises no
/// fanotify events. Where no fanotify permission events are available no pre-content mark can
/// exist, and a plain descriptor is used.
fn open_quiet(path: &Path) -> Option<File> {
    let plain = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        match nydus_utils::fanotify::open_without_events(&[plain.as_raw_fd()], false) {
            Ok(mut fds) => fds.pop().map(File::from),
            // No fanotify, no permission events, or no right to create a group.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
                ) =>
            {
                Some(plain)
            }
            Err(e) => {
                warn!("cannot open lender {} without events: {e}", path.display());
                None
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    Some(plain)
}

/// The lenders of the cache file `own`, named `file_name`: regular files of that name, on the
/// same filesystem and with the same owner as `own`, in the directories `patterns` match. Each
/// pattern is a path with one `*` component, which matches directories only, never symlinks.
// shortcut: lenders are listed once per blob open, so an image that caches the blob later is
// not seen by entries already open; list again on a miss if that matters.
pub(crate) fn find_lenders(patterns: &[String], file_name: &str, own: &File) -> Vec<Lender> {
    let Ok(own) = own.metadata() else {
        return Vec::new();
    };
    let mut lenders = Vec::new();
    for pattern in patterns {
        let (prefix, suffix) = match pattern.strip_suffix("/*") {
            Some(prefix) => (prefix, ""),
            None => match pattern.split_once("/*/") {
                Some(split) => split,
                None => continue,
            },
        };
        let Ok(entries) = std::fs::read_dir(prefix) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let path = entry.path().join(suffix).join(file_name);
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let id = (md.dev(), md.ino());
            if !md.is_file()
                || md.dev() != own.dev()
                || md.uid() != own.uid()
                || id == (own.dev(), own.ino())
                || lenders.iter().any(|l: &Lender| l.id == id)
            {
                continue;
            }
            lenders.push(Lender {
                path,
                id,
                strikes: AtomicU32::new(0),
            });
            if lenders.len() == MAX_LENDERS {
                return lenders;
            }
        }
    }
    lenders
}

/// Whether `file` holds data over all of `[offset, offset + len)`: a hole costs one `lseek`.
pub(crate) fn has_data(file: &File, offset: u64, len: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `lseek` only takes integers; the file is open for the call.
        let data = unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, libc::SEEK_DATA) };
        if data < 0 || data as u64 != offset {
            return false;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, libc::SEEK_HOLE) };
        hole >= 0 && hole as u64 >= offset + len
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, offset, len);
        true
    }
}
