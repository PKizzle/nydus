// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Blob-cache accounting and garbage collection.
//!
//! This is the Rust snapshotter counterpart of the Go snapshotter's cache
//! manager.  It deliberately starts as a standalone component so it can be
//! invoked by the reconciler, a future system-controller API, or tests without
//! coupling cache policy to containerd gRPC calls.

use crate::config::SnapshotterConfig;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Result alias for cache-manager operations.
pub type CacheResult<T> = std::result::Result<T, CacheError>;

/// Cache manager errors that should remain typed at the module boundary.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("invalid duration {value:?}; expected a positive integer followed by s, m, h, or d")]
    InvalidDuration { value: String },
    #[error("cache root {path} is not a directory")]
    RootNotDirectory { path: PathBuf },
    #[error("failed to read cache directory {path}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to stat cache path {path}")]
    Stat {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// A cache artifact type understood by the GC scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheArtifactKind {
    BlobData,
    BlobMeta,
    ChunkMap,
    Bootstrap,
    Other,
}

/// One regular file in the cache tree.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub kind: CacheArtifactKind,
}

impl CacheEntry {
    fn eviction_time(&self) -> SystemTime {
        self.accessed
            .or(self.modified)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    fn age_at(&self, now: SystemTime) -> Duration {
        self.modified
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default()
    }
}

/// Aggregated cache usage.
#[derive(Clone, Debug, Default)]
pub struct CacheUsage {
    pub total_bytes: u64,
    pub total_files: usize,
    pub entries: Vec<CacheEntry>,
}

/// GC policy. If both `max_age` and `max_bytes` are `None`, collection only
/// reports usage and does not delete anything.
#[derive(Clone, Debug, Default)]
pub struct CacheGcPolicy {
    pub max_age: Option<Duration>,
    pub max_bytes: Option<u64>,
    pub dry_run: bool,
}

impl CacheGcPolicy {
    pub fn from_config(config: &SnapshotterConfig) -> CacheResult<Self> {
        Ok(Self {
            max_age: config
                .snapshotter
                .cache
                .gc_max_age
                .as_deref()
                .map(parse_duration)
                .transpose()?,
            max_bytes: config.snapshotter.cache.gc_max_bytes,
            dry_run: config.snapshotter.cache.gc_dry_run,
        })
    }
}

/// A file that was selected for deletion.
#[derive(Clone, Debug)]
pub struct CacheGcRemoval {
    pub path: PathBuf,
    pub size: u64,
    pub dry_run: bool,
}

/// A file that could not be deleted. GC continues after individual failures.
#[derive(Clone, Debug)]
pub struct CacheGcFailure {
    pub path: PathBuf,
    pub error: String,
}

/// Result of one GC pass.
#[derive(Clone, Debug, Default)]
pub struct CacheGcReport {
    pub scanned_files: usize,
    pub scanned_bytes: u64,
    pub removed_files: usize,
    pub removed_bytes: u64,
    /// Files the policy selected but GC spared because their slug belongs to a
    /// live daemon (in-memory instance or live persisted record).
    pub spared_files: usize,
    pub spared_bytes: u64,
    pub removals: Vec<CacheGcRemoval>,
    pub failures: Vec<CacheGcFailure>,
}

/// Cache manager rooted at the configured blob-cache work directory.
#[derive(Clone, Debug)]
pub struct CacheManager {
    root: PathBuf,
}

impl CacheManager {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_config(config: &SnapshotterConfig) -> Self {
        Self::new(config.snapshotter.cache.work_dir.clone())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Scan regular files under the cache root and return aggregate usage.
    /// Missing roots are treated as empty caches so first boot is cheap.
    pub fn scan(&self) -> CacheResult<CacheUsage> {
        if !self.root.exists() {
            return Ok(CacheUsage::default());
        }
        if !self.root.is_dir() {
            return Err(CacheError::RootNotDirectory {
                path: self.root.clone(),
            });
        }

        let mut usage = CacheUsage::default();
        self.scan_dir(&self.root, &mut usage)?;
        debug!(
            root = %self.root.display(),
            files = usage.total_files,
            bytes = usage.total_bytes,
            "cache scan complete"
        );
        Ok(usage)
    }

    /// Run one GC pass using the supplied policy.
    ///
    /// `protected_slugs` names the per-image cache directories that must never
    /// be collected: a live fanotify daemon's `.blob.data` file *is* the EROFS
    /// device the kernel reads, and a live persisted record's blobs are needed
    /// to rebuild after a restart. The signature makes exclusion mandatory —
    /// pass an empty set only when provably nothing is being served.
    pub fn garbage_collect(
        &self,
        policy: &CacheGcPolicy,
        protected_slugs: &HashSet<String>,
    ) -> CacheResult<CacheGcReport> {
        let usage = self.scan()?;
        let mut report = CacheGcReport {
            scanned_files: usage.total_files,
            scanned_bytes: usage.total_bytes,
            ..CacheGcReport::default()
        };

        let is_protected =
            |entry: &CacheEntry| entry_slug(entry).is_some_and(|s| protected_slugs.contains(s));

        let mut candidates =
            self.select_age_candidates(&usage.entries, policy.max_age, &is_protected, &mut report);
        self.select_size_candidates(
            &usage.entries,
            policy.max_bytes,
            &is_protected,
            &mut candidates,
            &mut report,
        );
        candidates.sort_by_key(|entry| (entry.eviction_time(), entry.relative_path.clone()));
        candidates.dedup_by(|a, b| a.path == b.path);

        for entry in candidates {
            self.remove_entry(entry, policy.dry_run, &mut report);
        }

        if !policy.dry_run && report.removed_files > 0 {
            self.prune_empty_dirs();
        }

        info!(
            root = %self.root.display(),
            scanned_files = report.scanned_files,
            scanned_bytes = report.scanned_bytes,
            removed_files = report.removed_files,
            removed_bytes = report.removed_bytes,
            spared_files = report.spared_files,
            spared_bytes = report.spared_bytes,
            failures = report.failures.len(),
            dry_run = policy.dry_run,
            "cache GC pass complete"
        );
        Ok(report)
    }

    fn scan_dir(&self, dir: &Path, usage: &mut CacheUsage) -> CacheResult<()> {
        let entries = fs::read_dir(dir).map_err(|source| CacheError::ReadDir {
            path: dir.to_path_buf(),
            source,
        })?;

        for entry in entries {
            let entry = entry.map_err(|source| CacheError::ReadDir {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| CacheError::Stat {
                path: path.clone(),
                source,
            })?;

            if metadata.is_dir() {
                self.scan_dir(&path, usage)?;
            } else if metadata.is_file() {
                let relative_path = path.strip_prefix(&self.root).unwrap_or(&path).to_path_buf();
                let size = metadata.len();
                usage.total_files += 1;
                usage.total_bytes += size;
                usage.entries.push(CacheEntry {
                    kind: classify_artifact(&path),
                    path,
                    relative_path,
                    size,
                    modified: metadata.modified().ok(),
                    accessed: metadata.accessed().ok(),
                });
            }
        }
        Ok(())
    }

    fn select_age_candidates<'a>(
        &self,
        entries: &'a [CacheEntry],
        max_age: Option<Duration>,
        is_protected: &impl Fn(&CacheEntry) -> bool,
        report: &mut CacheGcReport,
    ) -> Vec<&'a CacheEntry> {
        let Some(max_age) = max_age else {
            return Vec::new();
        };
        let now = SystemTime::now();
        let mut out = Vec::new();
        for entry in entries {
            if entry.age_at(now) < max_age {
                continue;
            }
            if is_protected(entry) {
                report.spared_files += 1;
                report.spared_bytes += entry.size;
                continue;
            }
            out.push(entry);
        }
        out
    }

    fn select_size_candidates<'a>(
        &self,
        entries: &'a [CacheEntry],
        max_bytes: Option<u64>,
        is_protected: &impl Fn(&CacheEntry) -> bool,
        out: &mut Vec<&'a CacheEntry>,
        report: &mut CacheGcReport,
    ) {
        let Some(max_bytes) = max_bytes else {
            return;
        };
        let mut total: u64 = entries.iter().map(|entry| entry.size).sum();
        if total <= max_bytes {
            return;
        }

        let mut by_lru: Vec<&CacheEntry> = entries.iter().collect();
        by_lru.sort_by_key(|entry| (entry.eviction_time(), entry.relative_path.clone()));
        let mut pinned: u64 = 0;
        for entry in by_lru {
            if total <= max_bytes {
                break;
            }
            if is_protected(entry) {
                // Live bytes stay in `total`: they genuinely occupy the
                // budget; evicting more unprotected files to compensate is
                // exactly the right pressure response.
                pinned = pinned.saturating_add(entry.size);
                report.spared_files += 1;
                report.spared_bytes += entry.size;
                continue;
            }
            total = total.saturating_sub(entry.size);
            out.push(entry);
        }
        if total > max_bytes {
            warn!(
                root = %self.root.display(),
                over_budget_bytes = total - max_bytes,
                pinned_bytes = pinned,
                "cache remains over its byte budget; the remainder is pinned by live daemons"
            );
        }
    }

    fn remove_entry(&self, entry: &CacheEntry, dry_run: bool, report: &mut CacheGcReport) {
        if !dry_run && let Err(e) = fs::remove_file(&entry.path) {
            warn!(
                path = %entry.path.display(),
                error = %e,
                "failed to remove cache file"
            );
            report.failures.push(CacheGcFailure {
                path: entry.path.clone(),
                error: e.to_string(),
            });
            return;
        }

        report.removed_files += 1;
        report.removed_bytes += entry.size;
        report.removals.push(CacheGcRemoval {
            path: entry.path.clone(),
            size: entry.size,
            dry_run,
        });
    }

    fn prune_empty_dirs(&self) {
        let mut dirs = Vec::new();
        collect_dirs(&self.root, &mut dirs);
        dirs.sort_by_key(|path| Reverse(path.components().count()));
        for dir in dirs {
            if dir == self.root {
                continue;
            }
            match fs::remove_dir(&dir) {
                Ok(()) => debug!(dir = %dir.display(), "removed empty cache directory"),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "failed to prune cache directory")
                }
            }
        }
    }
}

fn collect_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    out.push(dir.to_path_buf());
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_dirs(&path, out);
        }
    }
}

/// The per-image cache slug an entry belongs to: the first component of its
/// path relative to the cache root (layout: `<work_dir>/<slug>/<file>`).
/// Root-level files carry no slug and stay policy-eligible.
fn entry_slug(entry: &CacheEntry) -> Option<&str> {
    let mut components = entry.relative_path.components();
    let first = components.next()?;
    components.next()?;
    match first {
        std::path::Component::Normal(name) => name.to_str(),
        _ => None,
    }
}

fn classify_artifact(path: &Path) -> CacheArtifactKind {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name.ends_with(".blob.data") || name == "blob.data" {
        CacheArtifactKind::BlobData
    } else if name.ends_with(".blob.meta") || name == "blob.meta" {
        CacheArtifactKind::BlobMeta
    } else if name.ends_with(".chunk_map") || name == "chunk_map" {
        CacheArtifactKind::ChunkMap
    } else if name.ends_with(".boot") || name == "image.boot" {
        CacheArtifactKind::Bootstrap
    } else {
        CacheArtifactKind::Other
    }
}

/// Parse a compact duration string (`30s`, `10m`, `24h`, `7d`).
pub fn parse_duration(value: &str) -> CacheResult<Duration> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CacheError::InvalidDuration {
            value: value.to_string(),
        });
    }

    let suffix = trimmed
        .chars()
        .last()
        .ok_or_else(|| CacheError::InvalidDuration {
            value: value.to_string(),
        })?;
    let digits = &trimmed[..trimmed.len() - suffix.len_utf8()];
    let amount: u64 = digits.parse().map_err(|_| CacheError::InvalidDuration {
        value: value.to_string(),
    })?;
    let seconds = match suffix {
        's' => amount,
        'm' => amount.saturating_mul(60),
        'h' => amount.saturating_mul(60 * 60),
        'd' => amount.saturating_mul(24 * 60 * 60),
        _ => {
            return Err(CacheError::InvalidDuration {
                value: value.to_string(),
            });
        }
    };
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_cache_root_scans_as_empty() {
        let dir = tempdir().unwrap();
        let manager = CacheManager::new(dir.path().join("missing"));
        let usage = manager.scan().unwrap();
        assert_eq!(usage.total_files, 0);
        assert_eq!(usage.total_bytes, 0);
    }

    #[test]
    fn scan_counts_and_classifies_cache_artifacts() {
        let dir = tempdir().unwrap();
        let cache = dir.path().join("cache").join("image");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("abc.blob.data"), b"data").unwrap();
        fs::write(cache.join("abc.blob.meta"), b"meta").unwrap();
        fs::write(cache.join("abc.chunk_map"), b"map").unwrap();

        let manager = CacheManager::new(dir.path().join("cache"));
        let usage = manager.scan().unwrap();
        assert_eq!(usage.total_files, 3);
        assert_eq!(usage.total_bytes, 11);
        assert!(
            usage
                .entries
                .iter()
                .any(|entry| entry.kind == CacheArtifactKind::BlobData)
        );
        assert!(
            usage
                .entries
                .iter()
                .any(|entry| entry.kind == CacheArtifactKind::BlobMeta)
        );
        assert!(
            usage
                .entries
                .iter()
                .any(|entry| entry.kind == CacheArtifactKind::ChunkMap)
        );
    }

    #[test]
    fn dry_run_gc_reports_without_deleting() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("cache").join("abc.blob.data");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"data").unwrap();

        let manager = CacheManager::new(dir.path().join("cache"));
        let report = manager
            .garbage_collect(
                &CacheGcPolicy {
                    max_age: Some(Duration::from_secs(0)),
                    dry_run: true,
                    ..CacheGcPolicy::default()
                },
                &HashSet::new(),
            )
            .unwrap();

        assert_eq!(report.removed_files, 1);
        assert_eq!(report.removed_bytes, 4);
        assert!(report.removals[0].dry_run);
        assert!(file.exists());
    }

    #[test]
    fn age_gc_spares_protected_slugs() {
        let dir = tempdir().unwrap();
        let cache = dir.path().join("cache");
        fs::create_dir_all(cache.join("live-slug")).unwrap();
        fs::create_dir_all(cache.join("idle-slug")).unwrap();
        fs::write(cache.join("live-slug/a.blob.data"), b"live").unwrap();
        fs::write(cache.join("idle-slug/b.blob.data"), b"idle").unwrap();

        let protected = HashSet::from(["live-slug".to_string()]);
        let manager = CacheManager::new(&cache);
        let report = manager
            .garbage_collect(
                &CacheGcPolicy {
                    max_age: Some(Duration::from_secs(0)),
                    ..CacheGcPolicy::default()
                },
                &protected,
            )
            .unwrap();

        assert_eq!(report.removed_files, 1);
        assert_eq!(report.spared_files, 1);
        assert_eq!(report.spared_bytes, 4);
        assert!(cache.join("live-slug/a.blob.data").exists());
        assert!(!cache.join("idle-slug/b.blob.data").exists());
    }

    #[test]
    fn size_gc_spares_protected_slugs_and_reports_pinned_overage() {
        let dir = tempdir().unwrap();
        let cache = dir.path().join("cache");
        fs::create_dir_all(cache.join("live-slug")).unwrap();
        fs::create_dir_all(cache.join("idle-slug")).unwrap();
        fs::write(cache.join("live-slug/a.blob.data"), vec![0u8; 64]).unwrap();
        fs::write(cache.join("idle-slug/b.blob.data"), vec![0u8; 64]).unwrap();

        let protected = HashSet::from(["live-slug".to_string()]);
        let manager = CacheManager::new(&cache);
        // Budget 0: everything unprotected must go; the protected file stays
        // even though the budget remains unreachable.
        let report = manager
            .garbage_collect(
                &CacheGcPolicy {
                    max_bytes: Some(0),
                    ..CacheGcPolicy::default()
                },
                &protected,
            )
            .unwrap();

        assert_eq!(report.removed_files, 1);
        assert_eq!(report.spared_files, 1);
        assert!(cache.join("live-slug/a.blob.data").exists());
        assert!(!cache.join("idle-slug/b.blob.data").exists());
    }

    #[test]
    fn entry_slug_requires_a_directory_component() {
        let entry = |rel: &str| CacheEntry {
            kind: CacheArtifactKind::BlobData,
            path: PathBuf::from("/cache").join(rel),
            relative_path: PathBuf::from(rel),
            size: 0,
            modified: None,
            accessed: None,
        };
        assert_eq!(entry_slug(&entry("slug/a.blob.data")), Some("slug"));
        assert_eq!(entry_slug(&entry("slug/nested/a.blob.data")), Some("slug"));
        // Root-level files carry no slug and stay policy-eligible.
        assert_eq!(entry_slug(&entry("root.blob.data")), None);
    }

    #[test]
    fn size_gc_removes_files_until_under_limit() {
        let dir = tempdir().unwrap();
        let cache = dir.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("a.blob.data"), b"aaaa").unwrap();
        fs::write(cache.join("b.blob.data"), b"bbbb").unwrap();

        let manager = CacheManager::new(&cache);
        let report = manager
            .garbage_collect(
                &CacheGcPolicy {
                    max_bytes: Some(0),
                    ..CacheGcPolicy::default()
                },
                &HashSet::new(),
            )
            .unwrap();

        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.removed_files, 2);
        assert_eq!(manager.scan().unwrap().total_files, 0);
    }

    #[test]
    fn root_file_is_rejected() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("cache-file");
        fs::write(&file, b"not a dir").unwrap();
        let err = CacheManager::new(&file).scan().unwrap_err();
        assert!(matches!(err, CacheError::RootNotDirectory { .. }));
    }

    #[test]
    fn parses_cache_duration_strings() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
        assert!(matches!(
            parse_duration("tomorrow"),
            Err(CacheError::InvalidDuration { .. })
        ));
    }
}
