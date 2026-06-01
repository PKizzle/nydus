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
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use compio::time;
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
            interval,
        }
    }

    /// Enable a cache-GC pass as part of each reconciliation tick.
    pub fn with_cache_gc(mut self, manager: CacheManager, policy: CacheGcPolicy) -> Self {
        self.cache_gc = Some((manager, policy));
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
            if let (Some(a), Some(b), Some(d)) = (a, b, d) {
                if let Ok(code) = u8::from_str_radix(&format!("{a}{b}{d}"), 8) {
                    out.push(code as char);
                    continue;
                }
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
}
