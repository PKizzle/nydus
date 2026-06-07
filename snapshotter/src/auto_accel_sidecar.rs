// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Sidecar discovery + backend-dir staging for the auto-accel read side.
//!
//! When `OverlayEngine::prepare` returns plain overlay mounts for a standard
//! OCI image, [`SidecarLocator::find`] asks containerd's content store
//! whether an auto-accel manifest exists for the image's manifest digest. If
//! one is mirrored locally (either because this node produced it or because
//! spegel replicated it from a peer), [`stage_backend`] symlinks the gzip
//! layers + per-layer zran indexes + optional prefetch blob into a fresh
//! `backend/` directory and copies the merged bootstrap into a `stage/`
//! directory. The result feeds straight into
//! `DaemonSupervisor::ensure_instance_local`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::{debug, info, warn};

use crate::auto_zran::AutoAccelManifest;
use crate::content_store::{ContentInfo, ContentStoreClient};

const LABEL_ROLE: &str = "containerd.io/snapshot/nydus.auto-accel.role";
const LABEL_SUBJECT: &str = "containerd.io/gc.ref.content.subject";

/// A resolved auto-accel sidecar with its on-disk paths ready for the fanotify
/// backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedSidecar {
    /// Copied merged bootstrap inside the per-image stage dir.
    pub bootstrap: PathBuf,
    /// Backend dir holding gzip-layer symlinks + zran index blobs + the
    /// optional prefetch blob.
    pub backend_dir: PathBuf,
    /// Root of the per-image scratch (parent of `bootstrap` and
    /// `backend_dir`). Removed by the supervisor on instance teardown.
    pub work_dir: PathBuf,
}

/// Sidecar lookup against containerd's content store. Cheap to clone.
#[derive(Clone)]
pub struct SidecarLocator {
    content_store: ContentStoreClient,
    /// Snapshotter root joined with `"auto-accel"`; per-image scratch dirs
    /// hang off this.
    stage_root: PathBuf,
}

impl SidecarLocator {
    pub fn new(content_store: ContentStoreClient, snapshotter_root: &Path) -> Self {
        Self {
            content_store,
            stage_root: snapshotter_root.join("auto-accel"),
        }
    }

    /// Find an auto-accel manifest for `manifest_digest` if one is present in
    /// the local content store (either because this node produced it or
    /// because spegel replicated a peer's). Returns `Ok(None)` when none
    /// exists — the caller falls back to overlay.
    pub async fn find(&self, manifest_digest: &str) -> Result<Option<AutoAccelManifest>> {
        // Fast path: ask containerd's Images service for the synthetic ref
        // we deterministically register on the producer side. Same name on
        // every node, so a peer's Image record visible locally via spegel
        // mirror lands here first; a label-filter scan only kicks in for
        // legacy artifacts uploaded before the image-record registration
        // landed.
        let image_name = crate::auto_zran::auto_accel_image_name(manifest_digest);
        let resolved = match self.content_store.images_get(&image_name).await {
            Ok(opt) => opt,
            Err(e) => {
                debug!(image_name = %image_name, error = %e, "auto-accel images.Get failed; falling back to label scan");
                None
            }
        };

        let blob = match resolved {
            Some(info) => info,
            None => {
                // containerd filter syntax: each filter is AND-ed.
                let filters = vec![format!(
                    "labels.\"{LABEL_SUBJECT}\"=={manifest_digest},labels.\"{LABEL_ROLE}\"==manifest"
                )];
                let blobs = self.content_store.list_with_filters(filters).await?;
                let Some(blob) = pick_latest_manifest(&blobs).cloned() else {
                    return Ok(None);
                };
                blob
            }
        };
        let bytes = self.content_store.fetch_bytes(&blob.digest).await?;
        let manifest: AutoAccelManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse auto-accel manifest blob {}", blob.digest))?;
        if manifest.subject_manifest_digest != manifest_digest {
            warn!(
                expected = manifest_digest,
                got = manifest.subject_manifest_digest,
                "auto-accel manifest subject mismatch; ignoring"
            );
            return Ok(None);
        }
        if manifest.version != 1 {
            debug!(
                version = manifest.version,
                "auto-accel manifest is newer than this snapshotter supports; ignoring"
            );
            return Ok(None);
        }
        info!(
            subject = manifest_digest,
            bootstrap = %manifest.bootstrap.digest,
            indexes = manifest.zran_indexes.len(),
            "auto-accel sidecar discovered"
        );
        Ok(Some(manifest))
    }

    /// Stage a backend directory with symlinks to all referenced blobs in
    /// containerd's content store, copy the merged bootstrap into a
    /// `stage/bootstrap` file. Idempotent: re-staging the same manifest
    /// is a no-op (the symlinks are recreated, the bootstrap is overwritten).
    pub async fn stage(
        &self,
        manifest_digest: &str,
        manifest: &AutoAccelManifest,
    ) -> Result<StagedSidecar> {
        let work_dir = self.stage_root.join(slug_for_digest(manifest_digest));
        let backend_dir = work_dir.join("backend");
        let stage_dir = work_dir.join("stage");
        std::fs::create_dir_all(&backend_dir)
            .with_context(|| format!("create auto-accel backend dir {}", backend_dir.display()))?;
        std::fs::create_dir_all(&stage_dir)
            .with_context(|| format!("create auto-accel stage dir {}", stage_dir.display()))?;

        // 1. Symlink each gzip layer (already in containerd's content store)
        //    into backend_dir/<bare-hex>. nydus's localfs backend keys blobs
        //    by their bare blob_id (no algorithm prefix).
        for layer in &manifest.zran_indexes {
            let layer_path = self.content_store.blob_path(&layer.layer_digest);
            ensure_present(&layer_path, "gzip layer")?;
            let link = backend_dir.join(strip_sha256(&layer.layer_digest));
            symlink_force(&layer_path, &link)?;

            // 2. Symlink each zran index blob the same way.
            let index_path = self.content_store.blob_path(&layer.digest);
            ensure_present(&index_path, "zran index")?;
            let index_link = backend_dir.join(strip_sha256(&layer.digest));
            symlink_force(&index_path, &index_link)?;
        }

        // 3. Symlink the optional prefetch blob.
        if let Some(prefetch) = &manifest.prefetch_blob {
            let path = self.content_store.blob_path(&prefetch.digest);
            ensure_present(&path, "prefetch blob")?;
            let link = backend_dir.join(strip_sha256(&prefetch.digest));
            symlink_force(&path, &link)?;
        }

        // 4. Copy the merged bootstrap into the stage dir under the
        //    `bootstrap` name the fanotify handler expects. We use copy
        //    (not symlink) because the bootstrap is small and copy avoids
        //    the fanotify handler ever resolving a dangling link.
        let bootstrap_src = self.content_store.blob_path(&manifest.bootstrap.digest);
        ensure_present(&bootstrap_src, "bootstrap")?;
        let bootstrap_dst = stage_dir.join("bootstrap");
        std::fs::copy(&bootstrap_src, &bootstrap_dst).with_context(|| {
            format!(
                "copy bootstrap {} -> {}",
                bootstrap_src.display(),
                bootstrap_dst.display()
            )
        })?;

        Ok(StagedSidecar {
            bootstrap: bootstrap_dst,
            backend_dir,
            work_dir,
        })
    }
}

/// When multiple auto-accel manifests claim the same subject (e.g. two nodes
/// converted with different prefetch profiles), prefer whichever blob has the
/// largest size — heuristically the most-complete profile. Fall back to the
/// lexicographically-largest digest for stable ordering when sizes match.
fn pick_latest_manifest(blobs: &[ContentInfo]) -> Option<&ContentInfo> {
    let mut best: Option<&ContentInfo> = None;
    for blob in blobs {
        match best {
            None => best = Some(blob),
            Some(prev) if blob.size > prev.size => best = Some(blob),
            Some(prev) if blob.size == prev.size && blob.digest > prev.digest => best = Some(blob),
            _ => {}
        }
    }
    best
}

fn ensure_present(path: &Path, kind: &str) -> Result<()> {
    if !path.is_file() {
        return Err(anyhow!(
            "{kind} {} missing from content store (spegel cache miss?)",
            path.display()
        ));
    }
    Ok(())
}

fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = std::fs::remove_file(link);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(target, link)
            .map(|_| ())
            .with_context(|| format!("copy {} -> {}", link.display(), target.display()))
    }
}

fn strip_sha256(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Per-manifest slug for staging dirs. Uses the bare hex (no `sha256:`
/// prefix) so the resulting path is short and `ls`-friendly.
fn slug_for_digest(manifest_digest: &str) -> String {
    let hex = strip_sha256(manifest_digest);
    // 16 chars is plenty for collision avoidance in the per-manifest scratch
    // namespace; the full digest already lives in the auto-accel manifest.
    hex[..hex.len().min(16)].to_string()
}

/// Top-level "owns" wrapper for the sidecar locator + the result of one
/// resolution. Constructed in `serve_with_supervisor` only when auto-accel
/// is enabled. Held in `Arc` so cloning is cheap.
#[derive(Clone)]
pub struct AutoAccelDiscovery {
    pub locator: Arc<SidecarLocator>,
}

impl AutoAccelDiscovery {
    pub fn new(content_store: ContentStoreClient, snapshotter_root: &Path) -> Self {
        Self {
            locator: Arc::new(SidecarLocator::new(content_store, snapshotter_root)),
        }
    }

    /// One-shot helper: find + stage in one call. Returns `Ok(None)` if no
    /// sidecar exists; the caller falls back to overlay.
    pub async fn resolve(&self, manifest_digest: &str) -> Result<Option<StagedSidecar>> {
        let Some(manifest) = self.locator.find(manifest_digest).await? else {
            return Ok(None);
        };
        let staged = self.locator.stage(manifest_digest, &manifest).await?;
        Ok(Some(staged))
    }
}

/// Convenience: the canonical label set the auto-zran worker stamps on each
/// uploaded artifact. Re-exported so callers can verify in tests or logs.
pub fn auto_accel_labels(subject: &str, role: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(LABEL_SUBJECT.to_string(), subject.to_string());
    m.insert(LABEL_ROLE.to_string(), role.to_string());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_latest_prefers_larger_size_then_digest() {
        let a = ContentInfo {
            digest: "sha256:aaa".into(),
            size: 10,
            labels: HashMap::new(),
        };
        let b = ContentInfo {
            digest: "sha256:bbb".into(),
            size: 20,
            labels: HashMap::new(),
        };
        let c = ContentInfo {
            digest: "sha256:ccc".into(),
            size: 20,
            labels: HashMap::new(),
        };
        let blobs = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(pick_latest_manifest(&blobs).unwrap().digest, "sha256:ccc");
        let blobs = vec![a, b];
        assert_eq!(pick_latest_manifest(&blobs).unwrap().digest, "sha256:bbb");
    }

    #[test]
    fn slug_for_digest_strips_prefix_and_truncates() {
        assert_eq!(
            slug_for_digest("sha256:abcdef1234567890abcdef1234567890"),
            "abcdef1234567890"
        );
        assert_eq!(slug_for_digest("abc"), "abc");
    }
}
