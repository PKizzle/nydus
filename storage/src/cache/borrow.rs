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
use std::time::{Duration, Instant};

/// Lenders listed per blob cache entry.
const MAX_LENDERS: usize = 4;
/// Digest mismatches after which a lender is no longer used by an entry.
const MAX_STRIKES: u32 = 3;
/// The longest wait before another open of a lender whose last open failed transiently.
const MAX_OPEN_BACKOFF: Duration = Duration::from_secs(60);

/// The file in a cache directory naming the backend its caches are filled from, written by
/// whoever creates the directory. Caches borrow only from directories that name the same one.
pub const BORROW_IDENTITY_FILE: &str = "borrow-identity";

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
    // Failed opens in a row, and when the next may be tried.
    open_failures: AtomicU32,
    next_open: Mutex<Option<Instant>>,
}

impl Lender {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The lender's descriptor, opened on first use. `None` once the lender is dropped
    /// (unlinked, released, replaced by another file, or struck out), and while an open that
    /// failed for a passing reason waits to be tried again.
    pub(crate) fn file(&self) -> Option<Arc<File>> {
        self.file_at(Instant::now(), open_quiet)
    }

    /// [`Self::file`] at the time `now`, opening with `open`.
    fn file_at(
        &self,
        now: Instant,
        open: impl Fn(&Path) -> Result<File, Open>,
    ) -> Option<Arc<File>> {
        if self.strikes.load(Ordering::Acquire) >= MAX_STRIKES {
            return None;
        }
        if let Some((path, file)) = LENDERS.lock().unwrap().get(&self.id)
            && *path == self.path
            && is_linked(file)
        {
            return Some(file.clone());
        }
        if self.next_open.lock().unwrap().is_some_and(|t| now < t) {
            return None;
        }
        // Opened outside the lock: a quiet open runs a helper thread and may take a while.
        let file = match open(&self.path) {
            Ok(file)
                if file
                    .metadata()
                    .is_ok_and(|m| (m.dev(), m.ino()) == self.id && m.nlink() > 0) =>
            {
                file
            }
            Err(Open::Transient(e)) => {
                let failures = self.open_failures.fetch_add(1, Ordering::AcqRel).min(6);
                let wait = Duration::from_secs(1 << failures).min(MAX_OPEN_BACKOFF);
                *self.next_open.lock().unwrap() = Some(now + wait);
                debug!(
                    "lender {}: open failed ({e}), retrying in {wait:?}",
                    self.path.display()
                );
                return None;
            }
            _ => {
                self.strikes.store(MAX_STRIKES, Ordering::Release);
                return None;
            }
        };
        self.open_failures.store(0, Ordering::Release);
        let mut lenders = LENDERS.lock().unwrap();
        match lenders.get(&self.id) {
            // Another entry opened it meanwhile.
            Some((path, f)) if *path == self.path && is_linked(f) => Some(f.clone()),
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

/// Why a lender could not be opened.
enum Open {
    /// The file is gone or is not one to read.
    Gone,
    /// A passing condition, such as a descriptor or fanotify group limit.
    Transient(std::io::Error),
}

/// Open `path` read-only without following a symlink, through a descriptor that raises no
/// fanotify events. Where no fanotify permission events are available no pre-content mark can
/// exist, and a plain descriptor is used.
fn open_quiet(path: &Path) -> Result<File, Open> {
    let plain = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR) => Open::Gone,
            _ => Open::Transient(e),
        })?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        match nydus_utils::fanotify::open_without_events(&[plain.as_raw_fd()], false) {
            Ok(mut fds) => fds.pop().map(File::from).ok_or(Open::Gone),
            // No fanotify, no permission events, or no right to create a group.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
                ) =>
            {
                Ok(plain)
            }
            Err(e) => Err(Open::Transient(e)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Ok(plain)
}

/// The backend identity a cache directory names, if its file is a regular file (not a symlink)
/// owned by `uid`.
fn identity_of(dir: &Path, uid: u32) -> Option<Vec<u8>> {
    let path = dir.join(BORROW_IDENTITY_FILE);
    let md = std::fs::symlink_metadata(&path).ok()?;
    if !md.is_file() || md.uid() != uid || md.len() > 4096 {
        return None;
    }
    std::fs::read(path).ok().filter(|id| !id.is_empty())
}

/// The lenders of the cache file `own` in the directory `own_dir`, named `file_name`: regular
/// files of that name, on the same filesystem and with the same owner as `own`, in the
/// directories `patterns` match that name the same backend identity as `own_dir`
/// ([`BORROW_IDENTITY_FILE`]). Each pattern is a path with one `*` component, which matches
/// directories only, never symlinks.
// shortcut: lenders are listed once per blob open, so an image that caches the blob later is
// not seen by entries already open, and the first four found keep their slots even when they
// hold little of the blob; list again on a miss if that matters.
pub(crate) fn find_lenders(
    patterns: &[String],
    own_dir: &Path,
    file_name: &str,
    own: &File,
) -> Vec<Lender> {
    let Ok(own) = own.metadata() else {
        return Vec::new();
    };
    let Some(identity) = identity_of(own_dir, own.uid()) else {
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
            // An empty cache file (a stale or never-filled one) lends nothing but would fill the cap.
            if !md.is_file()
                || md.blocks() == 0
                || md.dev() != own.dev()
                || md.uid() != own.uid()
                || id == (own.dev(), own.ino())
                || lenders.iter().any(|l: &Lender| l.id == id)
                || path
                    .parent()
                    .and_then(|dir| identity_of(dir, own.uid()))
                    .as_ref()
                    != Some(&identity)
            {
                continue;
            }
            lenders.push(Lender {
                path,
                id,
                strikes: AtomicU32::new(0),
                open_failures: AtomicU32::new(0),
                next_open: Mutex::new(None),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cache files with no allocated data do not take lender slots ahead of one that has data.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn empty_cache_files_take_no_lender_slot() {
        let root = tempfile::TempDir::new().unwrap();
        let name = "blob.blob.data";
        let cache_dir = |path: std::path::PathBuf| {
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join(BORROW_IDENTITY_FILE), "same").unwrap();
            path
        };
        let own_dir = cache_dir(root.path().join("own"));
        let own = File::create(own_dir.join(name)).unwrap();
        // Listed first: as many empty (sparse) cache files as there are slots.
        for i in 0..MAX_LENDERS {
            let dir = cache_dir(root.path().join("empty").join(i.to_string()));
            File::create(dir.join(name))
                .unwrap()
                .set_len(1 << 20)
                .unwrap();
        }
        let full = cache_dir(root.path().join("full").join("0"));
        std::fs::write(full.join(name), vec![7u8; 4096]).unwrap();
        let patterns = [
            format!("{}/empty/*", root.path().display()),
            format!("{}/full/*", root.path().display()),
        ];
        let lenders = find_lenders(&patterns, &own_dir, name, &own);
        let paths: Vec<_> = lenders.iter().map(|l| l.path.clone()).collect();
        assert_eq!(paths, vec![full.join(name)], "empty files took the slots");
    }

    /// An open that fails for a passing reason is no strike, is not tried again before its
    /// backoff ends, is tried again after it, and a success clears the failure count.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support file-backed mmap")]
    fn a_transient_open_failure_backs_off_without_a_strike() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("lender.blob.data");
        std::fs::write(&path, b"data").unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let lender = Lender {
            path: path.clone(),
            id: (md.dev(), md.ino()),
            strikes: AtomicU32::new(0),
            open_failures: AtomicU32::new(0),
            next_open: Mutex::new(None),
        };
        let opens = std::sync::atomic::AtomicUsize::new(0);
        let emfile = |_: &Path| {
            opens.fetch_add(1, Ordering::SeqCst);
            Err(Open::Transient(std::io::Error::from_raw_os_error(
                libc::EMFILE,
            )))
        };
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);

        assert!(lender.file_at(at(0), emfile).is_none());
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            lender.strikes.load(Ordering::SeqCst),
            0,
            "a passing failure struck"
        );
        // Within the first backoff (1 s): not tried again.
        assert!(lender.file_at(at(900), emfile).is_none());
        assert_eq!(
            opens.load(Ordering::SeqCst),
            1,
            "retried within the backoff"
        );
        // After it: tried again, and the next backoff doubles (2 s).
        assert!(lender.file_at(at(1_100), emfile).is_none());
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        assert!(lender.file_at(at(3_000), emfile).is_none());
        assert_eq!(
            opens.load(Ordering::SeqCst),
            2,
            "retried within the doubled backoff"
        );
        assert_eq!(lender.open_failures.load(Ordering::SeqCst), 2);

        let file = lender.file_at(at(3_200), |p| File::open(p).map_err(|_| Open::Gone));
        assert!(file.is_some(), "not opened once the backoff ended");
        assert_eq!(
            lender.open_failures.load(Ordering::SeqCst),
            0,
            "success kept the count"
        );
        assert_eq!(lender.strikes.load(Ordering::SeqCst), 0);
        release_lenders_under(dir.path());
    }
}
