// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Reconciler loop.
//!
//! Periodically scans the snapshot database and daemon instances to detect
//! and repair drift: orphan mounts, dead instances, stale sockets, partial
//! commits. Errors are classified using the `Recoverable` trait to decide
//! whether to retry, recreate, fallback, or abort.

use crate::cache::{CacheGcPolicy, CacheManager};
use crate::daemon::DaemonSupervisor;
use crate::store::SnapshotStore;
use anyhow::{Context, Result};
use compio::time;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Classification of recoverable vs. fatal errors.
pub trait Recoverable: std::fmt::Display {
    /// Classify the error for the reconciler.
    fn classify(&self) -> ErrorClass {
        ErrorClass::Transient
    }
}

/// Error classification for the reconciler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Retry with exponential backoff.
    Transient,
    /// Recreate the mount on next access.
    RecreatableMount,
    /// Downgrade the filesystem driver (e.g. fanotify → fusedev).
    NeedsFallback,
    /// Fatal error that cannot recover automatically.
    Fatal,
}

/// Errors produced by low-level reconciler probes before they are classified
/// or wrapped by the public `anyhow::Result` API.
#[derive(Debug, thiserror::Error)]
enum ReconcileProbeError {
    #[error("failed to read /proc/mounts")]
    ReadProcMounts(#[source] std::io::Error),
}

/// Reconciler that periodically checks and repairs system state.
pub struct Reconciler {
    supervisor: Arc<DaemonSupervisor>,
    store: Arc<SnapshotStore>,
    cache_gc: Option<(CacheManager, CacheGcPolicy)>,
    auto_zran_sweep: Option<(PathBuf, Duration, Arc<crate::auto_zran::AutoZranManager>)>,
    interval: Duration,
}

impl Reconciler {
    /// Create a new reconciler.
    pub fn new(
        supervisor: Arc<DaemonSupervisor>,
        store: Arc<SnapshotStore>,
        interval: Duration,
    ) -> Self {
        Self {
            supervisor,
            store,
            cache_gc: None,
            auto_zran_sweep: None,
            interval,
        }
    }

    /// Enable a cache-GC pass as part of each reconciliation tick.
    pub fn with_cache_gc(mut self, manager: CacheManager, policy: CacheGcPolicy) -> Self {
        self.cache_gc = Some((manager, policy));
        self
    }

    /// Enable the auto-zran stale-job-dir sweep as part of each reconciliation
    /// tick. `work_dir` is `AutoZranConfig::work_dir`; `max_age` is how old a job
    /// dir's mtime must be before it's considered abandoned (a successful
    /// conversion removes its own dir -- see `auto_zran::run_conversion` step 6 --
    /// so anything that lingers past `max_age` is debris from a crash). `manager`
    /// is consulted every pass to exclude the currently-running job's directory
    /// regardless of its mtime.
    pub fn with_auto_zran_sweep(
        mut self,
        work_dir: PathBuf,
        max_age: Duration,
        manager: Arc<crate::auto_zran::AutoZranManager>,
    ) -> Self {
        self.auto_zran_sweep = Some((work_dir, max_age, manager));
        self
    }

    /// Run the reconciliation loop indefinitely.
    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            if let Err(e) = self.reconcile().await {
                error!(error = %e, "reconciliation pass failed");
            }
        }
    }

    /// Run a single reconciliation pass on demand and return its result to the
    /// caller (unlike [`Reconciler::run`], which loops and only logs errors).
    /// Wired to the containerd Cleanup RPC so an operator/containerd can force
    /// orphan reclamation synchronously instead of waiting for the next tick.
    ///
    /// May run concurrently with the background loop (both share one
    /// `Arc<Reconciler>`): every reconcile op must remain idempotent and
    /// read-mostly. There is deliberately no in-flight guard — a redundant
    /// overlapping pass is cheap and self-correcting; add a `try_lock` only if a
    /// future non-idempotent op needs it.
    pub async fn run_once(&self) -> Result<()> {
        self.reconcile().await
    }

    /// Perform a single reconciliation pass.
    async fn reconcile(&self) -> Result<()> {
        debug!("starting reconciliation pass");

        // 1. Recover failed daemon instances.
        self.supervisor.recover().await?;

        // 2. Check for orphan overlay mounts under the snapshots root.
        self.check_orphan_mounts().await?;

        // 3. Check for stale per-daemon state directories.
        self.check_stale_daemon_dirs().await?;

        // 4. Account for and optionally garbage-collect blob-cache artifacts.
        self.check_cache_gc().await?;

        // 5. Sweep orphaned auto-zran per-job scratch dirs left by a crash.
        self.check_stale_autozran_dirs().await?;

        debug!("reconciliation pass complete");
        Ok(())
    }

    /// Scan `/proc/mounts` for overlay or fuse mounts rooted under the
    /// snapshotter state directory and unmount any that no longer correspond
    /// to a live snapshot or active daemon mountpoint.
    async fn check_orphan_mounts(&self) -> Result<()> {
        let snapshots_root = self
            .supervisor
            .daemons_root()
            .parent()
            .map(Path::to_path_buf);
        let snapshotter_root = match snapshots_root {
            Some(p) => p,
            None => return Ok(()),
        };

        // Build the set of mountpoints we recognise as live: snapshot `fs/`
        // dirs that the store still knows about, plus active daemon mountpoints.
        let mut known: HashSet<PathBuf> = HashSet::new();
        match self.store.list() {
            Ok(snapshots) => {
                let fs_root = snapshotter_root.join("snapshots");
                for snap in snapshots {
                    let dir = fs_root.join(crate::overlay::snapshot_dir_name(&snap.key));
                    known.insert(dir.join("fs"));
                    known.insert(dir.join("work"));
                }
            }
            Err(e) => {
                warn!(error = %e, "recon: failed to list snapshots; skipping orphan-mount scan");
                return Ok(());
            }
        }
        for (_image_ref, mp) in self.supervisor.active_mountpoints().await {
            known.insert(mp);
        }

        let mounts = match read_proc_mounts() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "recon: /proc/mounts unreadable; skipping orphan scan");
                return Ok(());
            }
        };

        let mut orphans = 0usize;
        for entry in mounts {
            let under_root = entry.target.starts_with(&snapshotter_root);
            let interesting = matches!(entry.fs_type.as_str(), "overlay" | "fuse" | "fuse.nydus");
            if !under_root || !interesting {
                continue;
            }
            if known.contains(&entry.target) {
                continue;
            }
            orphans += 1;
            warn!(
                target = %entry.target.display(),
                fs_type = %entry.fs_type,
                "recon: detected orphan mount (not unmounting in v1; logging only)"
            );
        }
        if orphans > 0 {
            info!(orphans, "recon: orphan mount scan completed");
        } else {
            debug!("recon: orphan mount scan clean");
        }
        Ok(())
    }

    /// Remove `{root}/daemons/<slug>/` directories that no longer correspond
    /// to a live daemon instance. Avoids removing the mountpoint while it is
    /// in use by checking `/proc/mounts` first.
    async fn check_stale_daemon_dirs(&self) -> Result<()> {
        let daemons_root = self.supervisor.daemons_root();
        let entries = match std::fs::read_dir(&daemons_root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).context("recon: failed to read daemons root"),
        };

        let active = self.supervisor.active_slugs().await;
        let busy = read_proc_mounts()
            .map(|m| {
                m.into_iter()
                    .map(|e| e.target)
                    .collect::<HashSet<PathBuf>>()
            })
            .unwrap_or_default();

        let mut removed = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if active.contains(&name) {
                continue;
            }
            // Skip if anything under this dir is still mounted.
            if busy.iter().any(|m| m.starts_with(&path)) {
                warn!(
                    dir = %path.display(),
                    "recon: stale daemon dir still has active mount; leaving in place"
                );
                continue;
            }
            match std::fs::remove_dir_all(&path) {
                Ok(()) => {
                    removed += 1;
                    info!(dir = %path.display(), "recon: removed stale daemon dir");
                }
                Err(e) => warn!(
                    dir = %path.display(),
                    error = %e,
                    "recon: failed to remove stale daemon dir"
                ),
            }
        }
        if removed > 0 {
            info!(removed, "recon: stale daemon dir sweep completed");
        }
        Ok(())
    }

    /// Remove `{auto_zran.work_dir}/<job-key>/` scratch directories left behind by
    /// a crashed conversion. `local_accel::convert` already gives every
    /// `nydus-image` invocation a fresh per-layer subdirectory (see
    /// `local_accel::fresh_dir`), so leftovers here are always whole job dirs a
    /// prior process died before cleaning up, never a live worker's in-progress
    /// output.
    ///
    /// Staleness is judged by top-level job-dir mtime (which is bumped whenever a
    /// direct child -- `backend/`, `convert/`, the merged `bootstrap`,
    /// `prefetch.json` -- is created, i.e. at job start and at each pipeline
    /// stage) crossed with the manager's live `active_job_key()`, so a long-running
    /// conversion whose job dir hasn't been touched in a while (e.g. deep inside a
    /// single `nydus-image create` call) is never swept out from under it.
    async fn check_stale_autozran_dirs(&self) -> Result<()> {
        let Some((work_dir, max_age, manager)) = &self.auto_zran_sweep else {
            return Ok(());
        };
        let removed = sweep_stale_job_dirs(
            work_dir,
            *max_age,
            |name| manager.active_job_key().as_deref() == Some(name),
            std::time::SystemTime::now(),
        )?;
        if removed > 0 {
            info!(removed, "recon: auto-zran stale job dir sweep completed");
        }
        Ok(())
    }

    /// Run one configured cache-GC pass. With the default policy this only
    /// reports usage; eviction starts once `gc_max_age` or `gc_max_bytes` is
    /// configured.
    async fn check_cache_gc(&self) -> Result<()> {
        let Some((manager, policy)) = &self.cache_gc else {
            return Ok(());
        };
        manager
            .garbage_collect(policy)
            .with_context(|| format!("cache GC failed for {}", manager.root().display()))?;
        Ok(())
    }
}

/// Remove immediate subdirectories of `work_dir` whose mtime is at least `max_age`
/// old, skipping any dir the live worker is currently converting no matter how old
/// it looks. Returns the number of directories removed. Pulled out of
/// `Reconciler::check_stale_autozran_dirs` as a pure(-ish) function of its inputs
/// (plus `now`, so tests don't depend on wall-clock timing) so the sweep logic is
/// unit-testable without constructing a full `Reconciler` / `AutoZranManager`.
///
/// `is_active` is re-evaluated immediately before each `remove_dir_all`, NOT
/// snapshotted once up front. Job keys are deterministic (`job_key(image)`), so a
/// same-image conversion that starts mid-sweep reuses the exact dir we may have
/// already decided is stale by mtime. Re-checking at delete time closes that TOCTOU:
/// `mark_started()` (which flips `active_job_key()`) runs before the worker
/// (re)creates the dir, so the delete-time check either sees the now-live job and
/// skips, or the dir is still pure debris and is safe to remove (the worker will
/// recreate a fresh one via `fresh_dir`).
///
/// The whole sweep is best-effort/non-fatal: an unreadable `work_dir` and per-dir
/// removal failures are logged and skipped rather than propagated, so a transient
/// filesystem hiccup never aborts a reconciliation pass.
fn sweep_stale_job_dirs(
    work_dir: &Path,
    max_age: Duration,
    is_active: impl Fn(&str) -> bool,
    now: std::time::SystemTime,
) -> Result<usize> {
    let entries = match std::fs::read_dir(work_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            warn!(
                work_dir = %work_dir.display(),
                error = %e,
                "recon: failed to read auto-zran work dir; skipping sweep"
            );
            return Ok(0);
        }
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if is_active(&name) {
            continue;
        }
        let age = match entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|modified| now.duration_since(modified).unwrap_or_default())
        {
            Ok(age) => age,
            Err(_) => continue,
        };
        if age < max_age {
            continue;
        }
        // Re-check liveness right before deleting: a same-image job may have
        // started (and reused this exact dir) since we read it above.
        if is_active(&name) {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                removed += 1;
                info!(
                    dir = %path.display(),
                    age_secs = age.as_secs(),
                    "recon: removed stale auto-zran job dir"
                );
            }
            Err(e) => warn!(
                dir = %path.display(),
                error = %e,
                "recon: failed to remove stale auto-zran job dir"
            ),
        }
    }
    Ok(removed)
}

/// One row of `/proc/mounts` that the reconciler cares about.
#[derive(Clone, Debug)]
struct MountEntry {
    target: PathBuf,
    fs_type: String,
}

fn read_proc_mounts() -> std::result::Result<Vec<MountEntry>, ReconcileProbeError> {
    let contents =
        std::fs::read_to_string("/proc/mounts").map_err(ReconcileProbeError::ReadProcMounts)?;
    Ok(parse_mounts(&contents))
}

fn parse_mounts(contents: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let (_dev, target, fs_type) = match (parts.next(), parts.next(), parts.next()) {
            (Some(d), Some(t), Some(f)) => (d, t, f),
            _ => continue,
        };
        out.push(MountEntry {
            target: PathBuf::from(unescape_mount_field(target)),
            fs_type: fs_type.to_string(),
        });
    }
    out
}

/// `/proc/mounts` escapes spaces, tabs and backslashes as octal sequences.
fn unescape_mount_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let a = chars.next();
            let b = chars.next();
            let d = chars.next();
            if let (Some(a), Some(b), Some(d)) = (a, b, d)
                && let Ok(code) = u8::from_str_radix(&format!("{a}{b}{d}"), 8)
            {
                out.push(code as char);
                continue;
            }
            out.push('\\');
            if let Some(a) = a {
                out.push(a);
            }
            if let Some(b) = b {
                out.push(b);
            }
            if let Some(d) = d {
                out.push(d);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mounts_extracts_target_and_fs_type() {
        let text = "\
overlay /var/lib/containerd-nydus/snapshots/foo/fs overlay rw,lowerdir=...,upperdir=... 0 0
fuse.nydus /var/lib/containerd-nydus/daemons/abc/mnt fuse.nydus rw,user_id=0 0 0
proc /proc proc rw,nosuid 0 0
";
        let parsed = parse_mounts(text);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].fs_type, "overlay");
        assert_eq!(
            parsed[0].target,
            PathBuf::from("/var/lib/containerd-nydus/snapshots/foo/fs")
        );
        assert_eq!(parsed[1].fs_type, "fuse.nydus");
    }

    #[test]
    fn parse_mounts_unescapes_octal_spaces() {
        let text = "tmp /mnt/has\\040space tmpfs rw 0 0\n";
        let parsed = parse_mounts(text);
        assert_eq!(parsed[0].target, PathBuf::from("/mnt/has space"));
    }

    #[test]
    fn parse_mounts_ignores_malformed_lines() {
        let parsed = parse_mounts("garbage\n\n");
        assert!(parsed.is_empty());
    }

    fn touch_dir_with_age(root: &Path, name: &str, age: Duration) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let stale_time = std::time::SystemTime::now() - age;
        // `File::open` on a directory (read-only) + `set_modified` is portable on
        // Unix without pulling in a `filetime` dependency just for this test.
        let f = std::fs::File::open(&dir).unwrap();
        f.set_modified(stale_time).unwrap();
        dir
    }

    #[test]
    fn sweep_stale_job_dirs_removes_only_dirs_older_than_max_age() {
        let tmp = tempfile::tempdir().unwrap();
        let old = touch_dir_with_age(tmp.path(), "old-crash", Duration::from_secs(7200));
        let fresh = touch_dir_with_age(tmp.path(), "fresh-job", Duration::from_secs(60));

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |_| false,
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn sweep_stale_job_dirs_never_removes_the_active_job_regardless_of_age() {
        let tmp = tempfile::tempdir().unwrap();
        let active = touch_dir_with_age(tmp.path(), "running-job", Duration::from_secs(999_999));

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |n| n == "running-job",
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 0);
        assert!(active.exists());
    }

    #[test]
    fn sweep_stale_job_dirs_rechecks_liveness_at_delete_time() {
        // Simulate a same-image conversion that starts mid-sweep: `is_active`
        // returns false on the first (pre-mtime-filter) call but true on the
        // delete-time re-check. The stale-by-mtime dir must be spared.
        let tmp = tempfile::tempdir().unwrap();
        let dir = touch_dir_with_age(tmp.path(), "raced-job", Duration::from_secs(7200));
        let calls = std::cell::Cell::new(0u32);

        let removed = sweep_stale_job_dirs(
            tmp.path(),
            Duration::from_secs(3600),
            |name| {
                let n = calls.get();
                calls.set(n + 1);
                // First call (initial skip check): not yet active.
                // Second call (delete-time re-check): job just started.
                n >= 1 && name == "raced-job"
            },
            std::time::SystemTime::now(),
        )
        .unwrap();

        assert_eq!(removed, 0, "delete-time re-check must spare a now-live job");
        assert!(dir.exists());
        assert!(
            calls.get() >= 2,
            "liveness must be checked again before delete"
        );
    }

    #[test]
    fn sweep_stale_job_dirs_tolerates_a_missing_work_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let removed = sweep_stale_job_dirs(
            &missing,
            Duration::from_secs(3600),
            |_| false,
            std::time::SystemTime::now(),
        )
        .unwrap();
        assert_eq!(removed, 0);
    }
}
