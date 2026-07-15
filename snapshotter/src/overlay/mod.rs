// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Overlay filesystem engine.
//!
//! Generates `mount.Mount` specs for containerd, manages overlay mounts,
//! and coordinates with the daemon supervisor to ensure RAFS backends are
//! serving before a mount is returned.

mod labels;
mod mounts;
mod paths;

use crate::config::SnapshotterConfig;
use crate::containerd_lookup::ContainerdLookup;
use crate::source::{
    CRI_IMAGE_REF, LayerKind, NYDUS_META_LAYER, classify_layer, target_snapshot_ref,
};
use crate::store::{SnapshotKind, SnapshotStore};
use anyhow::{Context, Result, bail};
use containerd_snapshots::api::types::Mount;
use labels::{bootstrap_digest_from_key, image_ref, is_image_ref_like, normalize_parent};
use mounts::{bind_mount, overlay_mount};
pub use paths::snapshot_dir_name;
use paths::{dir_usage, fs_dir, snapshot_dir, work_dir};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Outcome of a `Prepare` call, signalling whether containerd should mount
/// the returned filesystem or treat the layer as already extracted.
///
/// Mirrors the Go snapshotter's `skipHandler` / `defaultHandler` split in
/// `snapshot/process.go`: for Nydus blob (`application/vnd.oci.image.layer.nydus.blob.v1`)
/// layers the snapshotter commits the target snapshot itself and returns
/// `AlreadyExists`, which tells containerd's image unpacker that no
/// extraction (and no stream processor) is needed.
#[derive(Debug)]
pub enum PrepareOutcome {
    /// Containerd should mount these and proceed with normal unpack/IO.
    Mounts(Vec<Mount>),
    /// The target snapshot has been committed; containerd must treat the
    /// layer as already extracted and skip stream-processor lookup.
    AlreadyExists {
        target: String,
        commit_labels: HashMap<String, String>,
    },
}

/// Overlay engine coordinates snapshot lifecycle with mount generation.
/// `Clone` is cheap (a config clone plus an `Arc`) and lets gRPC handlers move
/// an engine into `blocking::unblock` closures for fs-heavy operations.
#[derive(Clone)]
pub struct OverlayEngine {
    config: SnapshotterConfig,
    /// Shared with the gRPC layer's async prepare path; this engine only
    /// reads the cache (`lookup_cached`) — sync code must never trigger
    /// an image-store walk.
    containerd_lookup: Option<Arc<ContainerdLookup>>,
}

impl OverlayEngine {
    /// Create a new overlay engine.
    pub fn new(config: SnapshotterConfig) -> Self {
        Self {
            config,
            containerd_lookup: None,
        }
    }

    /// Share the gRPC layer's `ContainerdLookup` so `nydus_meta_info`'s
    /// last-resort image-ref fallback can read the digest cache the async
    /// prepare path populates.
    pub fn with_containerd_lookup(mut self, lookup: Option<Arc<ContainerdLookup>>) -> Self {
        self.containerd_lookup = lookup;
        self
    }

    /// Return mounts for an existing active/view snapshot.
    pub fn mounts(&self, store: &SnapshotStore, key: &str) -> Result<Vec<Mount>> {
        let info = store.stat(key)?;
        match info.kind.as_str() {
            "kind_active" => self.mounts_for(key, info.parent.as_deref(), false, store),
            "kind_view" => self.mounts_for(key, info.parent.as_deref(), true, store),
            "kind_committed" => bail!("committed snapshot {key} does not have active mounts"),
            kind => bail!("unsupported snapshot kind {kind} for {key}"),
        }
    }

    /// Prepare an active snapshot (writable layer).
    ///
    /// Returns either the mount list for containerd or, for Nydus blob
    /// layers, an `AlreadyExists` outcome that signals containerd to skip
    /// the image unpack stage.
    pub fn prepare(
        &self,
        store: &SnapshotStore,
        key: &str,
        parent: &str,
        labels: &HashMap<String, String>,
    ) -> Result<PrepareOutcome> {
        debug!(key, parent, "prepare snapshot");
        let parent = normalize_parent(parent);
        self.validate_parent(store, parent)?;
        self.create_snapshot_dirs(key, false)?;
        let result = store.create(
            key,
            parent,
            SnapshotKind::Active,
            self.fs_driver_name(),
            image_ref(labels),
            labels,
        );
        if let Err(e) = result {
            let _ = fs::remove_dir_all(self.snapshot_dir(key));
            return Err(e);
        }

        if let (Some(target), LayerKind::NydusData) =
            (target_snapshot_ref(labels), classify_layer(labels))
        {
            info!(
                %key,
                target,
                "nydus blob layer detected; skipping containerd unpack"
            );
            return Ok(PrepareOutcome::AlreadyExists {
                target: target.to_string(),
                commit_labels: labels.clone(),
            });
        }

        self.mounts_for_created_snapshot(key, parent, false, store)
            .map(PrepareOutcome::Mounts)
    }

    /// Prepare a read-only view of a snapshot.
    /// Returns the mount list for containerd to mount.
    pub fn view(
        &self,
        store: &SnapshotStore,
        key: &str,
        parent: &str,
        labels: &HashMap<String, String>,
    ) -> Result<Vec<Mount>> {
        debug!(key, parent, "view snapshot");
        let parent = normalize_parent(parent);
        self.validate_parent(store, parent)?;
        self.create_snapshot_dirs(key, true)?;
        let result = store.create(
            key,
            parent,
            SnapshotKind::View,
            self.fs_driver_name(),
            image_ref(labels),
            labels,
        );
        if let Err(e) = result {
            let _ = fs::remove_dir_all(self.snapshot_dir(key));
            return Err(e);
        }

        self.mounts_for_created_snapshot(key, parent, true, store)
    }

    /// Commit an active snapshot into a read-only snapshot.
    pub fn commit(
        &self,
        store: &SnapshotStore,
        name: &str,
        key: &str,
        labels: &HashMap<String, String>,
    ) -> Result<()> {
        debug!(name, key, "commit snapshot");
        let info = store.stat(key)?;
        if info.kind != SnapshotKind::Active.as_str() {
            bail!("snapshot {key} is not active and cannot be committed");
        }

        let src = self.snapshot_dir(key);
        let dst = self.snapshot_dir(name);
        if dst.exists() {
            bail!(
                "snapshot directory for {name} already exists: {}",
                dst.display()
            );
        }

        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src, &dst).with_context(|| {
            format!(
                "failed to rename snapshot directory {} to {}",
                src.display(),
                dst.display()
            )
        })?;

        if let Err(e) = store.commit(name, key, labels) {
            let _ = fs::rename(&dst, &src);
            return Err(e);
        }

        Ok(())
    }

    /// Remove a snapshot.
    pub fn remove(&self, store: &SnapshotStore, key: &str) -> Result<()> {
        debug!(key, "remove snapshot");
        let dir = self.snapshot_dir(key);
        store.remove(key)?;
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| {
                format!("failed to remove snapshot directory {}", dir.display())
            })?;
        }
        Ok(())
    }

    /// Return disk usage for the snapshot's diff directory.
    pub fn usage(&self, store: &SnapshotStore, key: &str) -> Result<(i64, i64)> {
        let _ = store.stat(key)?;
        dir_usage(&self.fs_dir(key))
    }

    /// Walk the parent chain starting at `parent` and return Nydus meta info
    /// (bootstrap path + image ref) if any ancestor is a committed Nydus
    /// bootstrap layer.
    pub fn nydus_meta_info(
        &self,
        store: &SnapshotStore,
        parent: &str,
        call_labels: &HashMap<String, String>,
    ) -> Result<Option<NydusMetaInfo>> {
        if parent.is_empty() {
            return Ok(None);
        }
        let call_image_ref = call_labels.get(CRI_IMAGE_REF).cloned();
        for snap in store.parent_chain(parent)? {
            if !snap.labels.contains_key(NYDUS_META_LAYER) {
                continue;
            }
            let stored = snap.image_ref.clone().filter(|s| is_image_ref_like(s));
            let from_containerd = if call_image_ref.is_none() && stored.is_none() {
                // Cache-only: this is sync code on the gRPC runtime, so it
                // must never trigger an image-store walk. The cache is
                // shared with (and populated by) the async prepare path.
                // Guarded like `stored`: a cache populated by an older binary
                // can map a chain to a bare image-ID record (`sha256:…`), and
                // a daemon built from that fetches blobs from repo
                // "library/sha256" — every data read EIOs (the 0.2.9-nydus
                // mirrors incident).
                bootstrap_digest_from_key(&snap.key)
                    .and_then(|d| self.containerd_lookup.as_ref()?.lookup_cached(d))
                    .filter(|s| is_image_ref_like(s))
            } else {
                None
            };
            // Every candidate is digest-guarded: call/stored/from_containerd
            // via `is_image_ref_like`, the snapshot CRI label inline here.
            let image_ref = call_image_ref
                .clone()
                .filter(|s| is_image_ref_like(s))
                .or_else(|| stored.clone())
                .or_else(|| {
                    snap.labels
                        .get(CRI_IMAGE_REF)
                        .cloned()
                        .filter(|s| is_image_ref_like(s))
                })
                .or(from_containerd.clone());
            let Some(image_ref) = image_ref else {
                info!(
                    snap = %snap.key,
                    has_call_label = call_labels.contains_key(CRI_IMAGE_REF),
                    stored = ?snap.image_ref,
                    "nydus meta layer found but no usable image reference"
                );
                continue;
            };
            // Backfill bogus stored image_ref values written by older versions
            // (e.g. raw `sha256:…` digests) so reattach calls without a CRI
            // label can still resolve the right image.
            let has_authoritative = call_image_ref.is_some() || from_containerd.is_some();
            if stored.as_deref() != Some(image_ref.as_str())
                && has_authoritative
                && let Err(e) = store.set_image_ref(&snap.key, &image_ref)
            {
                warn!(snap = %snap.key, error = %e, "failed to persist image_ref backfill");
            }
            info!(snap = %snap.key, %image_ref, "resolved nydus image ref");
            let bootstrap = self.fs_dir(&snap.key).join("image").join("image.boot");
            if !bootstrap.is_file() {
                bail!(
                    "nydus meta snapshot {} is missing bootstrap at {}",
                    snap.key,
                    bootstrap.display()
                );
            }
            return Ok(Some(NydusMetaInfo {
                image_ref,
                bootstrap,
            }));
        }
        Ok(None)
    }

    /// Return the parent key recorded for an existing snapshot, if any.
    pub fn parent_of(&self, store: &SnapshotStore, key: &str) -> Result<Option<String>> {
        Ok(store.stat(key)?.parent)
    }

    /// Build a mount that uses the RAFS daemon mountpoint as the single
    /// readonly lower directory.
    ///
    /// * For a writable active snapshot this produces an overlay mount with
    ///   the snapshot's `fs/` as upperdir and `work/` as workdir.
    /// * For a readonly view this produces a `bind ro` mount of the daemon
    ///   mountpoint.
    pub fn mount_with_daemon(&self, key: &str, daemon_mountpoint: &Path, readonly: bool) -> Mount {
        if readonly {
            return bind_mount(daemon_mountpoint, true);
        }

        overlay_mount(
            &[daemon_mountpoint.to_path_buf()],
            Some(&self.fs_dir(key)),
            Some(&self.work_dir(key)),
        )
    }

    fn mounts_for(
        &self,
        key: &str,
        parent: Option<&str>,
        readonly: bool,
        store: &SnapshotStore,
    ) -> Result<Vec<Mount>> {
        let fs_dir = self.fs_dir(key);
        let parent = parent.unwrap_or_default();

        if parent.is_empty() {
            return Ok(vec![bind_mount(&fs_dir, readonly)]);
        }

        let lowerdirs = self.lower_dirs(store, parent)?;
        if lowerdirs.is_empty() {
            bail!("parent snapshot {parent} did not resolve to any lower directories");
        }

        if readonly && lowerdirs.len() == 1 {
            return Ok(vec![bind_mount(&lowerdirs[0], true)]);
        }

        mounts::ensure_lowerdir_budget(&lowerdirs)?;
        Ok(vec![overlay_mount(
            &lowerdirs,
            (!readonly).then_some(fs_dir.as_path()),
            (!readonly).then_some(self.work_dir(key)).as_deref(),
        )])
    }

    fn lower_dirs(&self, store: &SnapshotStore, parent: &str) -> Result<Vec<PathBuf>> {
        store
            .parent_chain(parent)?
            .iter()
            .map(|snapshot| {
                let path = self.fs_dir(&snapshot.key);
                if path.is_dir() {
                    Ok(path)
                } else {
                    bail!(
                        "snapshot {} is missing filesystem directory {}",
                        snapshot.key,
                        path.display()
                    )
                }
            })
            .collect()
    }

    fn validate_parent(&self, store: &SnapshotStore, parent: Option<&str>) -> Result<()> {
        if let Some(parent) = parent {
            let _ = store.parent_chain(parent)?;
        }
        Ok(())
    }

    fn mounts_for_created_snapshot(
        &self,
        key: &str,
        parent: Option<&str>,
        readonly: bool,
        store: &SnapshotStore,
    ) -> Result<Vec<Mount>> {
        match self.mounts_for(key, parent, readonly, store) {
            Ok(mounts) => Ok(mounts),
            Err(e) => {
                let _ = store.remove(key);
                let _ = fs::remove_dir_all(self.snapshot_dir(key));
                Err(e)
            }
        }
    }

    fn create_snapshot_dirs(&self, key: &str, readonly: bool) -> Result<()> {
        let snapshot_dir = self.snapshot_dir(key);
        fs::create_dir_all(self.fs_dir(key)).with_context(|| {
            format!(
                "failed to create snapshot filesystem directory {}",
                snapshot_dir.display()
            )
        })?;
        if !readonly {
            fs::create_dir_all(self.work_dir(key)).with_context(|| {
                format!(
                    "failed to create snapshot work directory {}",
                    snapshot_dir.display()
                )
            })?;
        }
        Ok(())
    }

    fn snapshot_dir(&self, key: &str) -> PathBuf {
        snapshot_dir(&self.config.snapshotter.root, key)
    }

    fn fs_dir(&self, key: &str) -> PathBuf {
        fs_dir(&self.config.snapshotter.root, key)
    }

    fn work_dir(&self, key: &str) -> PathBuf {
        work_dir(&self.config.snapshotter.root, key)
    }

    fn fs_driver_name(&self) -> &str {
        self.config
            .snapshotter
            .fs_drivers
            .first()
            .map(|driver| driver.driver_type.as_str())
            .unwrap_or("fusedev")
    }
}

/// Information about a Nydus meta (bootstrap) layer that the daemon supervisor
/// needs in order to mount the underlying RAFS filesystem.
#[derive(Clone, Debug)]
pub struct NydusMetaInfo {
    /// Image reference (`docker.io/library/nginx:latest`) passed to the daemon
    /// supervisor to look up registry auth and build the per-image cache dir.
    pub image_ref: String,
    /// On-disk path to `image.boot`, the RAFS bootstrap consumed by nydusd.
    pub bootstrap: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SnapshotterConfig;
    use tempfile::tempdir;

    fn test_engine(root: &Path) -> (OverlayEngine, SnapshotStore) {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = root.to_path_buf();
        let store = SnapshotStore::open(&root.join("metadata.fjall")).unwrap();
        (OverlayEngine::new(config), store)
    }

    fn expect_mounts(outcome: PrepareOutcome) -> Vec<Mount> {
        assert!(
            matches!(outcome, PrepareOutcome::Mounts(_)),
            "expected mounts"
        );
        match outcome {
            PrepareOutcome::Mounts(m) => m,
            PrepareOutcome::AlreadyExists { .. } => Vec::new(),
        }
    }

    #[test]
    fn prepare_empty_parent_returns_bind_mount() {
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let labels = HashMap::new();

        let mounts = expect_mounts(engine.prepare(&store, "active", "", &labels).unwrap());

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].r#type, "bind");
        assert!(mounts[0].options.contains(&"rw".to_string()));
        assert!(Path::new(&mounts[0].source).is_dir());
        assert_eq!(
            store.stat("active").unwrap().kind,
            SnapshotKind::Active.as_str()
        );
    }

    #[test]
    fn prepare_with_parent_returns_overlay_mount() {
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let labels = HashMap::new();

        engine.prepare(&store, "base-active", "", &labels).unwrap();
        engine
            .commit(&store, "base", "base-active", &HashMap::new())
            .unwrap();
        let mounts = expect_mounts(engine.prepare(&store, "child", "base", &labels).unwrap());

        assert_eq!(mounts[0].r#type, "overlay");
        assert!(
            mounts[0]
                .options
                .iter()
                .any(|opt| opt.starts_with("lowerdir="))
        );
        assert!(
            mounts[0]
                .options
                .iter()
                .any(|opt| opt.starts_with("upperdir="))
        );
        assert!(
            mounts[0]
                .options
                .iter()
                .any(|opt| opt.starts_with("workdir="))
        );
    }

    #[test]
    fn view_with_single_parent_returns_readonly_bind_mount() {
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let labels = HashMap::new();

        engine.prepare(&store, "base-active", "", &labels).unwrap();
        engine
            .commit(&store, "base", "base-active", &HashMap::new())
            .unwrap();
        let mounts = engine.view(&store, "view", "base", &labels).unwrap();

        assert_eq!(mounts[0].r#type, "bind");
        assert!(mounts[0].options.contains(&"ro".to_string()));
        assert!(
            !mounts[0]
                .options
                .iter()
                .any(|opt| opt.starts_with("upperdir="))
        );
    }

    #[test]
    fn remove_deletes_snapshot_directory() {
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let labels = HashMap::new();
        engine.prepare(&store, "active", "", &labels).unwrap();
        let snapshot_dir = engine.snapshot_dir("active");
        assert!(snapshot_dir.exists());

        engine.remove(&store, "active").unwrap();

        assert!(!snapshot_dir.exists());
        assert!(store.stat("active").is_err());
    }

    #[test]
    fn prepare_with_missing_parent_rolls_back() {
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let labels = HashMap::new();

        assert!(
            engine
                .prepare(&store, "child", "missing-parent", &labels)
                .is_err()
        );

        assert!(store.stat("child").is_err());
        assert!(!engine.snapshot_dir("child").exists());
    }

    #[test]
    fn prepare_nydus_blob_layer_returns_already_exists() {
        use crate::source::{NYDUS_DATA_LAYER, TARGET_SNAPSHOT_REF};
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let mut labels = HashMap::new();
        labels.insert(TARGET_SNAPSHOT_REF.to_string(), "sha256:target".to_string());
        labels.insert(NYDUS_DATA_LAYER.to_string(), "true".to_string());

        let outcome = engine.prepare(&store, "active", "", &labels).unwrap();
        assert!(
            matches!(outcome, PrepareOutcome::AlreadyExists { .. }),
            "expected AlreadyExists for nydus blob layer"
        );
        if let PrepareOutcome::AlreadyExists {
            target,
            commit_labels,
        } = outcome
        {
            assert_eq!(target, "sha256:target");
            assert_eq!(
                commit_labels.get(NYDUS_DATA_LAYER).map(String::as_str),
                Some("true")
            );
        }
        // Active row was still created so the caller can commit it to the target.
        assert_eq!(
            store.stat("active").unwrap().kind,
            SnapshotKind::Active.as_str()
        );
    }

    #[test]
    fn prepare_nydus_bootstrap_layer_returns_mounts() {
        use crate::source::{NYDUS_META_LAYER, TARGET_SNAPSHOT_REF};
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let mut labels = HashMap::new();
        labels.insert(TARGET_SNAPSHOT_REF.to_string(), "sha256:target".to_string());
        labels.insert(NYDUS_META_LAYER.to_string(), "true".to_string());

        let mounts = expect_mounts(engine.prepare(&store, "active", "", &labels).unwrap());
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].r#type, "bind");
    }

    #[test]
    fn prepare_plain_oci_layer_with_target_ref_returns_mounts() {
        use crate::source::TARGET_SNAPSHOT_REF;
        let dir = tempdir().unwrap();
        let (engine, store) = test_engine(dir.path());
        let mut labels = HashMap::new();
        labels.insert(TARGET_SNAPSHOT_REF.to_string(), "sha256:target".to_string());

        let mounts = expect_mounts(engine.prepare(&store, "active", "", &labels).unwrap());
        assert_eq!(mounts[0].r#type, "bind");
    }
}
