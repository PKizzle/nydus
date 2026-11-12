// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! EROFS page cache sharing (`inode_share`): whether the running kernel supports it, and whether
//! it carries [`UPSTREAM_FIX`] ("erofs: hold real inodes for shared files").
//!
//! Without the fix, a mapping of a shared file pins only the anonymous shared inode, not any of
//! the real EROFS inodes behind it. Once the file's last fd is closed and its real inode is
//! evicted (memory pressure, or the image it came from being unmounted), the next page fault on
//! that mapping finds no real inode: `erofs_real_inode()` returns NULL (an uninitialised pointer
//! on kernels built without stack auto-init) and the read path dereferences it. That is a kernel
//! oops in the fault path, with the folio lock and `mmap_lock` still held, so it cannot be
//! triggered as a test.
//!
//! The fix adds `erofs_ishare_backing_release()` as the `release` hook of the shared files. Its
//! address is taken, so it is never inlined away and always has a symbol: its presence in
//! `/proc/kallsyms` is what [`self_test`] looks for. A stable or distro backport carries the same
//! function. A kernel without kallsyms, or one that later reworks the function away, is reported
//! as inconclusive or "fix absent", never as fixed, so `auto` errs on the side of not sharing.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io::{self, BufRead};

/// How a fresh fanotify mount decided on page cache sharing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountOutcome {
    /// Mounted asking for `inode_share`.
    Shared,
    /// Sharing is enabled, but the image has no node view to share through.
    NoView,
    /// A cache held data not verified against its digests yet.
    Unverified,
    /// The mounted bootstrap declares no fingerprints.
    NoFingerprints,
    /// Sharing is off: configuration, or the kernel self-test.
    Disabled,
}

impl MountOutcome {
    /// Every outcome, in [`MountOutcome::label`] order of the counters.
    pub const ALL: [MountOutcome; 5] = [
        Self::Shared,
        Self::NoView,
        Self::Unverified,
        Self::NoFingerprints,
        Self::Disabled,
    ];

    /// The metric label value.
    pub fn label(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::NoView => "no_view",
            Self::Unverified => "unverified",
            Self::NoFingerprints => "no_fingerprints",
            Self::Disabled => "disabled",
        }
    }
}

static MOUNTS: [std::sync::atomic::AtomicU64; 5] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 5];

/// Count one fresh mount's sharing decision.
pub fn record_mount(outcome: MountOutcome) {
    MOUNTS[outcome as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Fresh mounts per sharing decision since the process started.
pub fn mount_counts() -> [(MountOutcome, u64); 5] {
    MountOutcome::ALL.map(|o| {
        (
            o,
            MOUNTS[o as usize].load(std::sync::atomic::Ordering::Relaxed),
        )
    })
}

/// The upstream commit that makes shared mmaps keep their real inode alive.
pub const UPSTREAM_FIX: &str = "7259fb011c14";

/// Symbol added by [`UPSTREAM_FIX`].
const FIX_SYMBOL: &str = "erofs_ishare_backing_release";
/// Symbol every kernel with EROFS page cache sharing has: proves kallsyms lists EROFS at all.
const FEATURE_SYMBOL: &str = "erofs_ishare_file_open";

/// What [`self_test`] found about EROFS page cache sharing on the running kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InodeShareStatus {
    /// The kernel cannot share page caches: no `inode_share` option (before 7.0) or built without
    /// `CONFIG_EROFS_FS_PAGE_CACHE_SHARE`.
    Unsupported(String),
    /// `inode_share` works, but mmaps of shared files can oops once their real inode is evicted.
    FixAbsent,
    /// `inode_share` works and the kernel carries [`UPSTREAM_FIX`].
    FixPresent,
    /// The probe could not decide, e.g. no privilege to mount or no readable kallsyms.
    Inconclusive(String),
}

impl InodeShareStatus {
    /// Short, stable name for metrics and status endpoints.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "unsupported",
            Self::FixAbsent => "fix_absent",
            Self::FixPresent => "fix_present",
            Self::Inconclusive(_) => "inconclusive",
        }
    }

    /// Whether `erofs_inode_share = "auto"` may enable sharing.
    pub fn safe_to_share(&self) -> bool {
        *self == Self::FixPresent
    }
}

/// Classifies the kernel from three mounts of the probe image and a kallsyms scan, each run only
/// when the previous step leaves the answer open.
///
/// A kernel built without `CONFIG_EROFS_FS_PAGE_CACHE_SHARE` logs and ignores both options, and
/// one before 7.0 rejects `inode_share` as unknown (`EINVAL`), so a working `inode_share,domain_id`
/// mount alone proves nothing. `inode_share` without `domain_id` tells them apart: only a kernel
/// that implements it refuses that with `EINVAL`.
fn classify(
    plain: io::Result<()>,
    with_domain: impl FnOnce() -> io::Result<()>,
    without_domain: impl FnOnce() -> io::Result<()>,
    fix_symbol: impl FnOnce() -> io::Result<Option<bool>>,
) -> InodeShareStatus {
    if let Err(e) = plain {
        return InodeShareStatus::Inconclusive(format!(
            "file-backed EROFS probe mount failed: {e}"
        ));
    }
    match with_domain() {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            return InodeShareStatus::Unsupported(format!(
                "kernel refused inode_share,domain_id: {e}"
            ));
        }
        Err(e) => {
            return InodeShareStatus::Inconclusive(format!(
                "inode_share,domain_id probe mount failed: {e}"
            ));
        }
    }
    match without_domain() {
        Ok(()) => {
            return InodeShareStatus::Unsupported(
                "kernel ignores inode_share (built without CONFIG_EROFS_FS_PAGE_CACHE_SHARE)"
                    .into(),
            );
        }
        Err(e) if e.raw_os_error() != Some(libc::EINVAL) => {
            return InodeShareStatus::Inconclusive(format!(
                "inode_share without domain_id failed with {e}, not EINVAL"
            ));
        }
        Err(_) => {}
    }
    match fix_symbol() {
        Ok(Some(true)) => InodeShareStatus::FixPresent,
        Ok(Some(false)) => InodeShareStatus::FixAbsent,
        Ok(None) => InodeShareStatus::Inconclusive(format!(
            "/proc/kallsyms lists no {FEATURE_SYMBOL}, so the presence of {FIX_SYMBOL} cannot be \
             told (kernel without CONFIG_KALLSYMS?)"
        )),
        Err(e) => InodeShareStatus::Inconclusive(format!("failed to read /proc/kallsyms: {e}")),
    }
}

/// Scans kallsyms-format lines: `Some(true)` if [`FIX_SYMBOL`] is listed, `Some(false)` if only
/// [`FEATURE_SYMBOL`] is, `None` if neither. Compiler suffixes (`.llvm.<n>`, `.cfi`) are ignored.
fn scan_kallsyms(symbols: impl BufRead) -> io::Result<Option<bool>> {
    let mut feature = false;
    for line in symbols.lines() {
        let line = line?;
        let Some(name) = line.split_whitespace().nth(2) else {
            continue;
        };
        let name = name.split('.').next().unwrap_or(name);
        if name == FIX_SYMBOL {
            return Ok(Some(true));
        }
        feature |= name == FEATURE_SYMBOL;
    }
    Ok(feature.then_some(false))
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::erofs_folio::{SELF_TEST_TIMEOUT, run_probe, trial};
    use std::fs;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::Duration;

    static STATUS: OnceLock<InodeShareStatus> = OnceLock::new();

    /// Runs [`self_test`] in `dir` the first time it is called; later calls return that result.
    /// Concurrent callers wait for the first one.
    pub fn detect_once(dir: &Path) -> &'static InodeShareStatus {
        STATUS.get_or_init(|| self_test(dir, SELF_TEST_TIMEOUT))
    }

    /// The cached [`detect_once`] result, if the self-test has run.
    pub fn detected() -> Option<&'static InodeShareStatus> {
        STATUS.get()
    }

    /// Mounts the probe image file-backed with and without the `inode_share` options, then looks
    /// for [`UPSTREAM_FIX`]'s symbol in `/proc/kallsyms` (EROFS may be a module, which the probe
    /// mount has loaded by then). The image carries no fingerprints, so the kernel shares nothing
    /// from it. Needs `CAP_SYS_ADMIN`; without it the result is inconclusive, as is a probe that
    /// does not finish within `timeout`.
    pub fn self_test(dir: &Path, timeout: Duration) -> InodeShareStatus {
        run_probe(dir, "erofs-ishare-probe", timeout, |work, image| {
            classify(
                trial(image, &work.join("m0"), ""),
                || {
                    let share = crate::fanotify::erofs_inode_share_options("", "nydus-probe")?;
                    trial(image, &work.join("m1"), &share)
                },
                || trial(image, &work.join("m2"), "inode_share"),
                || scan_kallsyms(io::BufReader::new(fs::File::open("/proc/kallsyms")?)),
            )
        })
        .unwrap_or_else(InodeShareStatus::Inconclusive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(errno: i32) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(errno))
    }

    #[test]
    fn classification() {
        let unused = || -> io::Result<()> { unreachable!() };
        let no_syms = || -> io::Result<Option<bool>> { unreachable!() };
        let einval = || err(libc::EINVAL);

        let s = classify(err(libc::EPERM), unused, unused, no_syms);
        assert_eq!(s.label(), "inconclusive");
        // Before 7.0: `inode_share` is an unknown option.
        let s = classify(Ok(()), einval, unused, no_syms);
        assert_eq!(s.label(), "unsupported");
        let s = classify(Ok(()), || err(libc::ENOSPC), unused, no_syms);
        assert_eq!(s.label(), "inconclusive");
        // Built without CONFIG_EROFS_FS_PAGE_CACHE_SHARE: both options are ignored.
        let s = classify(Ok(()), || Ok(()), || Ok(()), no_syms);
        assert_eq!(s.label(), "unsupported");
        let s = classify(Ok(()), || Ok(()), || err(libc::ENOMEM), no_syms);
        assert_eq!(s.label(), "inconclusive");

        let supported =
            |syms: io::Result<Option<bool>>| classify(Ok(()), || Ok(()), einval, || syms);
        assert_eq!(supported(Ok(Some(true))), InodeShareStatus::FixPresent);
        assert_eq!(supported(Ok(Some(false))), InodeShareStatus::FixAbsent);
        assert_eq!(supported(Ok(None)).label(), "inconclusive");
        assert_eq!(
            supported(Err(io::Error::other("x"))).label(),
            "inconclusive"
        );
        assert!(supported(Ok(Some(true))).safe_to_share());
        assert!(!supported(Ok(Some(false))).safe_to_share());
    }

    #[test]
    fn kallsyms_scan() {
        let scan = |s: &str| scan_kallsyms(s.as_bytes()).unwrap();
        let unfixed = "0000000000000000 t erofs_ishare_file_open\t[erofs]\n\
                       0000000000000000 T erofs_iget\t[erofs]\n";
        assert_eq!(scan(unfixed), Some(false));
        let fixed = format!("{unfixed}0000000000000000 t erofs_ishare_backing_release\t[erofs]\n");
        assert_eq!(scan(&fixed), Some(true));
        // Built in, with an LTO suffix.
        assert_eq!(
            scan("ffff800080123456 t erofs_ishare_backing_release.llvm.1234\n"),
            Some(true)
        );
        // A prefix match is not a match.
        assert_eq!(scan("0 t erofs_ishare_file_open_x\n0 t foo\n"), None);
        assert_eq!(scan(""), None);
    }
}
