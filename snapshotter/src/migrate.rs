// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Legacy bbolt → fjall snapshot-metadata migration (library core).
//!
//! The legacy Go snapshotter persisted snapshot metadata in a bbolt
//! `metadata.db` under its root directory; the Rust snapshotter uses the
//! embedded fjall store (`metadata.fjall`). This module holds the migration
//! logic shared by two entry points:
//!
//! * `nydus-migrate store` — the operator-driven CLI with dry-run/commit
//!   semantics ([`migrate_store`]).
//! * automatic startup import — [`auto_migrate_at_startup`], called from
//!   `open_store_for_config` when a legacy `metadata.db` sits next to a
//!   *fresh* (empty) fjall store. The legacy file is never deleted, snapshot
//!   directories are copied (hardlinked where possible), never moved, and a
//!   failed import degrades to a warning so startup is never blocked — the
//!   operator can still run `nydus-migrate store` manually.
//!
//! Both paths are idempotent: [`SnapshotStore::import_snapshot`] refuses to
//! overwrite existing keys and the pre-check below counts those records as
//! `skipped_existing` instead of failing.

use crate::overlay::snapshot_dir_name;
use crate::store::{SnapshotInfo, SnapshotKind, SnapshotStore};
use anyhow::{Context, Result, bail};
use bbolt_rs::{Bolt, BucketApi, DbApi, TxApi};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const LABEL_SNAPSHOT_REF: &str = "containerd.io/snapshot.ref";
const LABEL_CONFIG_REF: &str = "containerd.io/gc.ref.content.config";
/// The CRI-stamped image reference — the only label that reliably carries a
/// human image ref (`docker.io/library/nginx:latest`) in real containerd
/// data. `containerd.io/snapshot.ref` is the target snapshot name (a chain
/// digest) and `gc.ref.content.config` is a config-blob digest; stamping
/// either into `image_ref` recreates the digest-as-image-ref corruption the
/// `set_image_ref` repair path exists to fix.
const LABEL_CRI_IMAGE_REF: &str = "containerd.io/snapshot/cri.image-ref";
const UNIX_TO_INTERNAL_SECONDS: i64 = (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400) * 86_400;

/// File name of the legacy Go snapshotter's bbolt metadata database, relative
/// to the snapshotter root (the Go snapshotter opened
/// `filepath.Join(root, "metadata.db")`).
pub const LEGACY_BBOLT_DB_FILE: &str = "metadata.db";

/// File name of the fjall metadata directory, relative to the snapshotter
/// root. Mirrors the path `open_store_for_config` opens.
pub const FJALL_DB_DIR: &str = "metadata.fjall";

/// Marker written next to the fjall store after a clean (error-free)
/// auto-migration, so later startups can tell "migration finished, the
/// operator just hasn't removed metadata.db yet" (quiet) apart from
/// "migration was interrupted and records are stranded in bbolt" (loud).
pub const MIGRATION_COMPLETE_MARKER: &str = ".bbolt-migration-complete";

/// A snapshot record decoded from the legacy bbolt metadata database.
#[derive(Debug)]
struct LegacySnapshot {
    key: String,
    id: u64,
    parent: Option<String>,
    kind: SnapshotKind,
    created_at: Option<i64>,
    updated_at: Option<i64>,
    labels: HashMap<String, String>,
}

/// Outcome summary for one store-migration run. Serialized as the JSON report
/// `nydus-migrate store` prints; logged field-by-field on the auto path.
#[derive(Debug, Default, Serialize)]
pub struct StoreMigrationReport {
    pub dry_run: bool,
    pub legacy_db: String,
    pub legacy_root: String,
    pub output_db: String,
    pub output_root: String,
    pub discovered: usize,
    pub importable: usize,
    pub imported: usize,
    pub skipped_existing: usize,
    pub copied_dirs: usize,
    pub reused_dirs: usize,
    pub missing_dirs: usize,
    pub errors: Vec<String>,
}

/// Inputs for [`migrate_store`]. `output_db` is display-only (the report
/// string); the destination store itself is passed as an already-open handle
/// because fjall is single-writer and the auto path must reuse the handle the
/// snapshotter just opened.
#[derive(Debug)]
pub struct StoreMigrationParams<'a> {
    /// Path to the legacy Go/containerd bbolt metadata database.
    pub bbolt_db: &'a Path,
    /// Legacy snapshotter root (contains `snapshots/<numeric-id>/`).
    pub legacy_root: &'a Path,
    /// Path of the destination fjall store, for the report only.
    pub output_db: &'a Path,
    /// New Rust snapshotter root (receives `snapshots/<stable-key>/`).
    pub output_root: &'a Path,
    /// Filesystem-driver label to stamp on imported records. This is a
    /// non-authoritative label only: the live mount driver a snapshot
    /// actually gets served with is always the node's probed/promoted
    /// driver (`DaemonSupervisor::active_fs_driver()`, i.e.
    /// `config.snapshotter.fs_drivers.first()`), never read back from a
    /// snapshot record. Callers should still pass the node's real resolved
    /// driver rather than a hardcoded guess, so operators reading the
    /// fjall record or the `nydus-migrate store` report see an accurate
    /// label instead of a stale one.
    pub fs_driver: &'a str,
    /// Write fjall records and copy/hardlink snapshot directories. When
    /// false (dry-run) nothing is mutated and would-be imports are counted
    /// in `importable`.
    pub commit: bool,
}

/// Import legacy bbolt snapshot metadata into `store` and relocate the
/// numeric snapshot directories to the Rust stable-key layout. Never deletes
/// or modifies the legacy database or the legacy snapshot directories.
pub fn migrate_store(
    store: &SnapshotStore,
    params: &StoreMigrationParams<'_>,
) -> Result<StoreMigrationReport> {
    let legacy_snapshots = read_legacy_snapshots(params.bbolt_db)?;
    let mut report = StoreMigrationReport {
        dry_run: !params.commit,
        legacy_db: params.bbolt_db.display().to_string(),
        legacy_root: params.legacy_root.display().to_string(),
        output_db: params.output_db.display().to_string(),
        output_root: params.output_root.display().to_string(),
        discovered: legacy_snapshots.len(),
        ..StoreMigrationReport::default()
    };

    for snapshot in legacy_snapshots {
        let source_dir = params
            .legacy_root
            .join("snapshots")
            .join(snapshot.id.to_string());
        let target_dir = params
            .output_root
            .join("snapshots")
            .join(snapshot_dir_name(&snapshot.key));

        let target_available = ensure_snapshot_dir(
            &snapshot,
            &source_dir,
            &target_dir,
            params.commit,
            &mut report,
        );

        if let Err(e) = target_available {
            report.errors.push(format!(
                "{}: failed to prepare snapshot directory: {e:#}",
                snapshot.key
            ));
            continue;
        }
        if !target_available? {
            continue;
        }

        if store.exists(&snapshot.key)? {
            report.skipped_existing += 1;
            continue;
        }

        let now = now_unix();
        let info = SnapshotInfo {
            key: snapshot.key.clone(),
            parent: snapshot.parent.clone(),
            kind: snapshot.kind.as_str().to_string(),
            fs_driver: params.fs_driver.to_string(),
            image_ref: image_ref(&snapshot.labels).map(str::to_string),
            created_at: snapshot.created_at.unwrap_or(now),
            updated_at: snapshot.updated_at.or(snapshot.created_at).unwrap_or(now),
            labels: snapshot.labels.clone(),
        };

        if params.commit {
            if let Err(e) = store.import_snapshot(info) {
                report.errors.push(format!(
                    "{}: failed to import metadata: {e:#}",
                    snapshot.key
                ));
                continue;
            }
            report.imported += 1;
        } else {
            report.importable += 1;
        }
    }

    Ok(report)
}

/// Automatic startup migration: if a legacy bbolt `metadata.db` exists under
/// `root` AND the fjall store is empty, import it (commit mode). Returns
/// `Ok(None)` when there is nothing to do (no legacy db, or the store already
/// has records — a populated store means migration already happened or the
/// node was born on the Rust snapshotter, and importing into it could
/// resurrect snapshots the new store deliberately removed).
///
/// Cost when no legacy db exists: a single `is_file` check. The legacy
/// database is never deleted; the operator removes it once satisfied.
///
/// `fs_driver` is the label stamped on every imported record (see
/// [`StoreMigrationParams::fs_driver`]) — pass the node's actual
/// probed/promoted driver (`config.snapshotter.fs_drivers.first()`), not a
/// hardcoded guess.
pub fn auto_migrate_if_needed(
    root: &Path,
    store: &SnapshotStore,
    fs_driver: &str,
) -> Result<Option<StoreMigrationReport>> {
    let bbolt_db = root.join(LEGACY_BBOLT_DB_FILE);
    if !bbolt_db.is_file() {
        return Ok(None);
    }
    if !store
        .is_empty()
        .context("failed to check whether the fjall store is empty")?
    {
        // Per-record imports fsync individually, so a crash mid-migration
        // leaves the store non-empty with records still stranded in bbolt —
        // and this branch used to skip them with only a debug!. The completion
        // marker distinguishes "migration finished cleanly" (quiet) from
        // "interrupted / errored" (loud, actionable).
        if root.join(MIGRATION_COMPLETE_MARKER).is_file() {
            debug!(
                legacy_db = %bbolt_db.display(),
                "legacy bbolt metadata present but migration already completed; \
                 remove metadata.db once verified"
            );
        } else {
            warn!(
                legacy_db = %bbolt_db.display(),
                "legacy bbolt metadata.db sits next to a NON-EMPTY fjall store with no \
                 migration-complete marker — a previous migration may have been \
                 interrupted, leaving records stranded in bbolt. Auto-migration only \
                 imports into an empty store; run `nydus-migrate store` to inspect and \
                 import the remainder, then remove metadata.db"
            );
        }
        return Ok(None);
    }

    let output_db = root.join(FJALL_DB_DIR);
    let params = StoreMigrationParams {
        bbolt_db: &bbolt_db,
        legacy_root: root,
        output_db: &output_db,
        output_root: root,
        fs_driver,
        commit: true,
    };
    let report = migrate_store(store, &params)?;
    if report.errors.is_empty()
        && let Err(e) = std::fs::write(root.join(MIGRATION_COMPLETE_MARKER), b"ok\n")
    {
        warn!(error = %e, "failed to write migration-complete marker");
    }
    Ok(Some(report))
}

/// Startup hook wrapper around [`auto_migrate_if_needed`] that logs the
/// outcome and never fails: a broken legacy database must not block the
/// snapshotter from serving (the store is empty either way, and the manual
/// tool remains available). See [`auto_migrate_if_needed`] for the meaning
/// of `fs_driver`.
pub fn auto_migrate_at_startup(root: &Path, store: &SnapshotStore, fs_driver: &str) {
    match auto_migrate_if_needed(root, store, fs_driver) {
        Ok(None) => {}
        Ok(Some(report)) => {
            if report.errors.is_empty() {
                info!(
                    legacy_db = %report.legacy_db,
                    discovered = report.discovered,
                    imported = report.imported,
                    skipped_existing = report.skipped_existing,
                    copied_dirs = report.copied_dirs,
                    reused_dirs = report.reused_dirs,
                    "auto-migrated legacy bbolt snapshot metadata into fjall \
                     (legacy metadata.db left in place; remove it once verified)"
                );
            } else {
                for error in &report.errors {
                    warn!(error = %error, "auto-migration record error");
                }
                warn!(
                    legacy_db = %report.legacy_db,
                    discovered = report.discovered,
                    imported = report.imported,
                    skipped_existing = report.skipped_existing,
                    missing_dirs = report.missing_dirs,
                    errors = report.errors.len(),
                    "auto-migration of legacy bbolt metadata completed with errors; \
                     run `nydus-migrate store` manually to inspect and retry"
                );
            }
        }
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "auto-migration of legacy bbolt metadata failed; continuing with an \
                 empty store (run `nydus-migrate store` manually)"
            );
        }
    }
}

/// Confirm `path` is an openable, well-formed legacy bbolt snapshot metadata
/// database (i.e. it opens and has a `v1/snapshots` bucket) without decoding
/// any records. Cheap fail-fast check for callers — namely the
/// `nydus-migrate store` CLI — that must validate `--bbolt-db` *before*
/// opening (and thereby creating) the destination fjall store, so a bad
/// legacy path never leaves behind an empty `metadata.fjall` directory.
pub fn validate_legacy_bbolt_db(path: &Path) -> Result<()> {
    let db = Bolt::open_ro(path).with_context(|| {
        format!(
            "failed to open legacy bbolt snapshot metadata at {}",
            path.display()
        )
    })?;
    let tx = db
        .begin()
        .context("failed to begin bbolt read transaction")?;
    let v1 = tx
        .bucket("v1")
        .context("legacy metadata is missing v1 bucket")?;
    v1.bucket("snapshots")
        .context("legacy metadata is missing v1/snapshots bucket")?;
    Ok(())
}

fn read_legacy_snapshots(path: &Path) -> Result<Vec<LegacySnapshot>> {
    let db = Bolt::open_ro(path).with_context(|| {
        format!(
            "failed to open legacy bbolt snapshot metadata at {}",
            path.display()
        )
    })?;
    let tx = db
        .begin()
        .context("failed to begin bbolt read transaction")?;
    let v1 = tx
        .bucket("v1")
        .context("legacy metadata is missing v1 bucket")?;
    let snapshots = v1
        .bucket("snapshots")
        .context("legacy metadata is missing v1/snapshots bucket")?;

    let mut legacy_snapshots = Vec::new();
    for (key_bytes, snapshot_bucket) in snapshots.iter_buckets() {
        let key = String::from_utf8_lossy(key_bytes).into_owned();
        let id = read_uvarint(
            snapshot_bucket
                .get("id")
                .with_context(|| format!("snapshot {key} is missing id"))?,
        )
        .with_context(|| format!("snapshot {key} has invalid id"))?;
        let kind = SnapshotKind::from_containerd_kind(
            *snapshot_bucket
                .get("kind")
                .and_then(|value| value.first())
                .with_context(|| format!("snapshot {key} is missing kind"))?,
        )
        .with_context(|| format!("snapshot {key} has unsupported kind"))?;
        let parent = snapshot_bucket
            .get("parent")
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .filter(|value| !value.is_empty());
        let labels = read_labels(&snapshot_bucket);
        let created_at = read_go_time_unix(snapshot_bucket.get("createdat"));
        let updated_at = read_go_time_unix(snapshot_bucket.get("updatedat"));

        legacy_snapshots.push(LegacySnapshot {
            key,
            id,
            parent,
            kind,
            created_at,
            updated_at,
            labels,
        });
    }

    Ok(legacy_snapshots)
}

fn read_labels<'tx, B: BucketApi<'tx>>(snapshot_bucket: &B) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    if let Some(labels_bucket) = snapshot_bucket.bucket("labels") {
        for (key, value) in labels_bucket.iter_entries() {
            labels.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
    }
    labels
}

fn ensure_snapshot_dir(
    snapshot: &LegacySnapshot,
    source_dir: &Path,
    target_dir: &Path,
    commit: bool,
    report: &mut StoreMigrationReport,
) -> Result<bool> {
    // An existing target dir is trustworthy because commits below copy into a
    // temp name and rename atomically — a crash mid-copy can no longer leave a
    // half-populated dir under the final name.
    if target_dir.is_dir() {
        report.reused_dirs += 1;
        return Ok(true);
    }

    if !source_dir.is_dir() {
        report.missing_dirs += 1;
        let message = format!(
            "{}: legacy snapshot directory {} is missing",
            snapshot.key,
            source_dir.display()
        );
        warn!("{message}");
        report.errors.push(message);
        return Ok(false);
    }

    if commit {
        let tmp_dir = PathBuf::from(format!("{}.migrate-tmp", target_dir.display()));
        if tmp_dir.exists() {
            // Debris from a previous interrupted run; start over.
            std::fs::remove_dir_all(&tmp_dir).with_context(|| {
                format!("failed to remove stale temp dir {}", tmp_dir.display())
            })?;
        }
        copy_dir_recursive(source_dir, &tmp_dir).with_context(|| {
            format!(
                "failed to copy legacy snapshot directory {} to {}",
                source_dir.display(),
                tmp_dir.display()
            )
        })?;
        std::fs::rename(&tmp_dir, target_dir).with_context(|| {
            format!(
                "failed to move copied snapshot directory into place at {}",
                target_dir.display()
            )
        })?;
        report.copied_dirs += 1;
    }

    Ok(true)
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        bail!("target path {} already exists", target.display());
    }

    let metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("failed to stat {}", source.display()))?;
    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        copy_symlink(source, target)?;
    } else if file_type.is_dir() {
        std::fs::create_dir_all(target)
            .with_context(|| format!("failed to create {}", target.display()))?;
        for entry in std::fs::read_dir(source)
            .with_context(|| format!("failed to read directory {}", source.display()))?
        {
            let entry = entry?;
            copy_dir_recursive(&entry.path(), &target.join(entry.file_name()))?;
        }
    } else if file_type.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        if std::fs::hard_link(source, target).is_err() {
            std::fs::copy(source, target).with_context(|| {
                format!(
                    "failed to copy file {} to {}",
                    source.display(),
                    target.display()
                )
            })?;
        }
    } else {
        bail!("unsupported file type at {}", source.display());
    }

    Ok(())
}

#[cfg(unix)]
fn copy_symlink(source: &Path, target: &Path) -> Result<()> {
    let link_target = std::fs::read_link(source)
        .with_context(|| format!("failed to read symlink {}", source.display()))?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::os::unix::fs::symlink(&link_target, target).with_context(|| {
        format!(
            "failed to create symlink {} -> {}",
            target.display(),
            link_target.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, _target: &Path) -> Result<()> {
    bail!(
        "cannot copy symlink {} on non-Unix platform",
        source.display()
    )
}

fn read_uvarint(bytes: &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte < 0x80 {
            if index > 9 || (index == 9 && byte > 1) {
                bail!("uvarint overflows u64");
            }
            return Ok(value | (u64::from(byte) << shift));
        }
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }

    bail!("truncated uvarint")
}

fn read_go_time_unix(bytes: Option<&[u8]>) -> Option<i64> {
    let bytes = bytes?;
    if bytes.len() < 15 || !matches!(bytes[0], 1 | 2) {
        return None;
    }
    let sec = i64::from_be_bytes(bytes[1..9].try_into().ok()?);
    Some(sec.saturating_sub(UNIX_TO_INTERNAL_SECONDS))
}

/// Extract a usable image reference from a legacy record's labels, or `None`.
///
/// Candidates are tried in order of trustworthiness, and any bare digest is
/// rejected: `containerd.io/snapshot.ref` holds the *chain digest* in real
/// containerd data (this repo's own `source/labels.rs` tests pin that), and
/// `gc.ref.content.config` is a config-blob digest — a migrated record with a
/// digest-valued `image_ref` is worse than one with none.
fn image_ref(labels: &HashMap<String, String>) -> Option<&str> {
    [LABEL_CRI_IMAGE_REF, LABEL_SNAPSHOT_REF, LABEL_CONFIG_REF]
        .iter()
        .filter_map(|key| labels.get(*key))
        .map(String::as_str)
        .find(|candidate| !is_bare_digest(candidate))
}

/// True for `sha256:<64 hex>` (any case) — a content digest, never an image ref.
fn is_bare_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use bbolt_rs::{BucketRwApi, DbRwAPI, TxRwRefApi};
    use tempfile::tempdir;

    const KIND_ACTIVE: u8 = 2;
    const KIND_COMMITTED: u8 = 3;

    struct FixtureSnapshot<'a> {
        key: &'a str,
        id: u64,
        kind: u8,
        parent: Option<&'a str>,
    }

    /// Write a bbolt database shaped like the legacy Go snapshotter's
    /// `metadata.db` (bucket `v1/snapshots/<key>` with `id` uvarint, `kind`
    /// byte, optional `parent`, and a `labels` sub-bucket).
    fn write_legacy_fixture(path: &Path, snapshots: &[FixtureSnapshot<'_>]) {
        let mut db = Bolt::open(path).unwrap();
        db.update(|mut tx| {
            for snapshot in snapshots {
                assert!(snapshot.id < 0x80, "fixture ids fit in one uvarint byte");
                let mut bucket = tx.create_bucket_path(&["v1", "snapshots", snapshot.key])?;
                bucket.put("id", [snapshot.id as u8])?;
                bucket.put("kind", [snapshot.kind])?;
                if let Some(parent) = snapshot.parent {
                    bucket.put("parent", parent)?;
                }
                let mut labels = bucket.create_bucket("labels")?;
                labels.put(LABEL_SNAPSHOT_REF, "docker.io/example/image:tag")?;
            }
            Ok(())
        })
        .unwrap();
    }

    fn seed_legacy_snapshot_dir(root: &Path, id: u64) {
        let dir = root.join("snapshots").join(id.to_string()).join("fs");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("marker"), id.to_string()).unwrap();
    }

    fn default_fixture(root: &Path) {
        write_legacy_fixture(
            &root.join(LEGACY_BBOLT_DB_FILE),
            &[
                FixtureSnapshot {
                    key: "sha256:aaaa",
                    id: 1,
                    kind: KIND_COMMITTED,
                    parent: None,
                },
                FixtureSnapshot {
                    key: "active-key",
                    id: 2,
                    kind: KIND_ACTIVE,
                    parent: Some("sha256:aaaa"),
                },
            ],
        );
        seed_legacy_snapshot_dir(root, 1);
        seed_legacy_snapshot_dir(root, 2);
    }

    #[test]
    fn image_ref_prefers_cri_label_and_rejects_bare_digests() {
        // Regression: real containerd data holds the CHAIN DIGEST under
        // containerd.io/snapshot.ref and a config-blob digest under
        // gc.ref.content.config; stamping either into image_ref recreated the
        // digest-as-image-ref corruption commit 77e3fdc3 repaired.
        let digest = "sha256:".to_string() + &"a".repeat(64);

        let mut labels = HashMap::new();
        labels.insert(LABEL_SNAPSHOT_REF.to_string(), digest.clone());
        labels.insert(LABEL_CONFIG_REF.to_string(), digest.clone());
        assert_eq!(image_ref(&labels), None, "digest-only labels yield None");

        labels.insert(
            LABEL_CRI_IMAGE_REF.to_string(),
            "docker.io/library/nginx:latest".to_string(),
        );
        assert_eq!(image_ref(&labels), Some("docker.io/library/nginx:latest"));

        // A genuine (non-digest) value in snapshot.ref is still usable when
        // the CRI label is absent.
        let mut tag_only = HashMap::new();
        tag_only.insert(
            LABEL_SNAPSHOT_REF.to_string(),
            "docker.io/example/image:tag".to_string(),
        );
        assert_eq!(image_ref(&tag_only), Some("docker.io/example/image:tag"));

        assert!(is_bare_digest(&digest));
        assert!(!is_bare_digest("docker.io/library/nginx:latest"));
        assert!(!is_bare_digest("sha256:zzzz"));
    }

    #[test]
    fn auto_migrate_writes_completion_marker_and_second_run_is_quiet() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        default_fixture(root);
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();

        let report = auto_migrate_if_needed(root, &store, "fanotify")
            .unwrap()
            .unwrap();
        assert!(report.errors.is_empty());
        assert!(
            root.join(MIGRATION_COMPLETE_MARKER).is_file(),
            "clean migration must write the completion marker"
        );

        // Second startup: store non-empty + marker present → clean skip.
        assert!(
            auto_migrate_if_needed(root, &store, "fanotify")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn auto_migrate_imports_legacy_into_empty_store() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        default_fixture(root);
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();

        // Use a driver other than the old hardcoded default ("fusedev") to
        // prove the resolved node driver is actually threaded through and
        // stamped, not a hardcoded guess.
        let report = auto_migrate_if_needed(root, &store, "fanotify")
            .unwrap()
            .unwrap();
        assert!(!report.dry_run);
        assert_eq!(report.discovered, 2);
        assert_eq!(report.imported, 2);
        assert_eq!(report.skipped_existing, 0);
        assert_eq!(report.copied_dirs, 2);
        assert!(report.errors.is_empty(), "{:?}", report.errors);

        let committed = store.stat("sha256:aaaa").unwrap();
        assert_eq!(committed.kind, SnapshotKind::Committed.as_str());
        assert_eq!(committed.fs_driver, "fanotify");
        assert_eq!(
            committed.image_ref.as_deref(),
            Some("docker.io/example/image:tag")
        );
        let active = store.stat("active-key").unwrap();
        assert_eq!(active.parent.as_deref(), Some("sha256:aaaa"));

        // Snapshot directories were copied to the stable-key layout; the
        // legacy source dirs and the bbolt db are untouched.
        for key in ["sha256:aaaa", "active-key"] {
            assert!(
                root.join("snapshots")
                    .join(snapshot_dir_name(key))
                    .join("fs")
                    .join("marker")
                    .is_file()
            );
        }
        assert!(root.join("snapshots").join("1").is_dir());
        assert!(root.join("snapshots").join("2").is_dir());
        assert!(root.join(LEGACY_BBOLT_DB_FILE).is_file());

        // Second startup: the store is populated now, so the gate skips.
        assert!(
            auto_migrate_if_needed(root, &store, "fanotify")
                .unwrap()
                .is_none()
        );
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn migrate_store_reruns_are_idempotent() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        default_fixture(root);
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();

        auto_migrate_if_needed(root, &store, "fanotify")
            .unwrap()
            .unwrap();

        // Manual re-run against the populated store: everything is skipped,
        // nothing is duplicated or overwritten.
        let bbolt_db = root.join(LEGACY_BBOLT_DB_FILE);
        let output_db = root.join(FJALL_DB_DIR);
        let report = migrate_store(
            &store,
            &StoreMigrationParams {
                bbolt_db: &bbolt_db,
                legacy_root: root,
                output_db: &output_db,
                output_root: root,
                fs_driver: "fanotify",
                commit: true,
            },
        )
        .unwrap();
        assert_eq!(report.imported, 0);
        assert_eq!(report.skipped_existing, 2);
        assert_eq!(report.reused_dirs, 2);
        assert_eq!(report.copied_dirs, 0);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn migrate_store_dry_run_mutates_nothing() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        default_fixture(root);
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();

        let bbolt_db = root.join(LEGACY_BBOLT_DB_FILE);
        let output_db = root.join(FJALL_DB_DIR);
        let report = migrate_store(
            &store,
            &StoreMigrationParams {
                bbolt_db: &bbolt_db,
                legacy_root: root,
                output_db: &output_db,
                output_root: root,
                fs_driver: "fusedev",
                commit: false,
            },
        )
        .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.importable, 2);
        assert_eq!(report.imported, 0);
        assert_eq!(report.copied_dirs, 0);
        assert!(store.is_empty().unwrap());
        assert!(
            !root
                .join("snapshots")
                .join(snapshot_dir_name("sha256:aaaa"))
                .exists()
        );
    }

    #[test]
    fn auto_migrate_skips_populated_store() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        default_fixture(root);
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();
        store
            .create(
                "existing-key",
                None,
                SnapshotKind::Active,
                "fanotify",
                None,
                &HashMap::new(),
            )
            .unwrap();

        assert!(
            auto_migrate_if_needed(root, &store, "fanotify")
                .unwrap()
                .is_none()
        );
        let records = store.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "existing-key");
    }

    #[test]
    fn auto_migrate_noop_without_legacy_db() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();
        assert!(
            auto_migrate_if_needed(root, &store, "fusedev")
                .unwrap()
                .is_none()
        );
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn auto_migrate_at_startup_survives_corrupt_legacy_db() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(LEGACY_BBOLT_DB_FILE), b"not a bolt database").unwrap();
        let store = SnapshotStore::open(&root.join(FJALL_DB_DIR)).unwrap();
        // Must not panic and must not block: the wrapper degrades to a warn.
        auto_migrate_at_startup(root, &store, "fusedev");
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn validate_legacy_bbolt_db_rejects_missing_and_garbage_files() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Nonexistent file.
        assert!(validate_legacy_bbolt_db(&root.join("missing.db")).is_err());

        // Garbage file (not a bbolt database at all).
        let garbage = root.join("garbage.db");
        std::fs::write(&garbage, b"not a bolt database").unwrap();
        assert!(validate_legacy_bbolt_db(&garbage).is_err());

        // Valid legacy fixture passes.
        let good = root.join(LEGACY_BBOLT_DB_FILE);
        write_legacy_fixture(
            &good,
            &[FixtureSnapshot {
                key: "sha256:aaaa",
                id: 1,
                kind: KIND_COMMITTED,
                parent: None,
            }],
        );
        assert!(validate_legacy_bbolt_db(&good).is_ok());
    }

    #[test]
    fn decodes_uvarint() {
        assert_eq!(read_uvarint(&[0]).unwrap(), 0);
        assert_eq!(read_uvarint(&[172, 2]).unwrap(), 300);
        assert!(read_uvarint(&[128]).is_err());
    }

    #[test]
    fn decodes_go_time_unix_seconds() {
        let unix = 1_700_000_000i64;
        let internal = unix + UNIX_TO_INTERNAL_SECONDS;
        let mut encoded = Vec::new();
        encoded.push(1);
        encoded.extend_from_slice(&internal.to_be_bytes());
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(&(-1i16).to_be_bytes());
        assert_eq!(read_go_time_unix(Some(&encoded)), Some(unix));
    }
}
