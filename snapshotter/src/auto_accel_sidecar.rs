// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Sidecar discovery + backend-dir staging for the auto-accel read side.
//!
//! When `OverlayEngine::prepare` returns plain overlay mounts for a standard
//! OCI image, [`SidecarLocator::resolve_or_pull`] asks containerd's content
//! store whether an auto-accel manifest exists for the image's manifest
//! digest. If one is mirrored locally (either because this node produced it
//! or because a peer's peer mirror served it), [`SidecarLocator::stage`]
//! symlinks the gzip layers + per-layer zran indexes + optional prefetch
//! blob into a fresh `backend/` directory and copies the merged bootstrap
//! into a `stage/` directory. The result feeds straight into
//! `DaemonSupervisor::ensure_instance_local`.
//!
//! The HTTP transport (endpoint failover, peer discovery, mTLS) lives in
//! [`crate::peer_mirror`]; this module owns the pull *protocol* — which paths
//! to fetch, how to label what lands in the content store, and when to fall
//! back to the label-filter scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::{debug, info, warn};

use crate::auto_accel_oci::{
    AUTO_ACCEL_BOOTSTRAP_MEDIATYPE, AUTO_ACCEL_CONFIG_MEDIATYPE,
    AUTO_ACCEL_LAYER_DIGEST_ANNOTATION, AUTO_ACCEL_PREFETCH_MEDIATYPE, OCI_MANIFEST_MEDIATYPE,
    OciImageManifest,
};
// `AUTO_ACCEL_INDEX_MEDIATYPE` is the producer's per-layer media type, used
// only by `role_for_media_type`'s test (#[cfg(test)] module below) — keep
// the import there rather than at the file top so a stale prod-side rename
// doesn't fail the build only in test mode.
use crate::auto_zran::AutoAccelManifest;
use crate::config::PeerMirrorConfig;
use crate::content_store::{ContentInfo, ContentStoreClient};
use crate::peer_mirror::{FetchResult, PeerMirror, PullOutcome, build_peer_mirror};

const LABEL_ROLE: &str = "containerd.io/snapshot/nydus.auto-accel.role";
const LABEL_SUBJECT: &str = "containerd.io/gc.ref.content.subject";
const LABEL_DISTRIBUTION_SOURCE: &str = "containerd.io/distribution.source.nydus.auto-accel.local";

/// Accept header used on every manifest GET. We accept both the OCI media
/// type our producer emits and the docker v2 manifest media type so a
/// mirror that's been asked to fall back to upstream (or that's serving a
/// manifest we converted with a docker media type for any reason) still
/// returns the body rather than 406.
const ACCEPT_MANIFEST: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json,",
    "application/vnd.docker.distribution.manifest.v2+json"
);

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
    /// Peer mirror transport. `None` when the mirror is disabled by
    /// config, or when the configured TLS material doesn't exist on disk
    /// at startup. When `None`, `peer_pull` is a no-op returning
    /// `PullOutcome::Disabled` so the locator falls through to the
    /// label-filter scan.
    peer_mirror: Option<Arc<PeerMirror>>,
    /// Per-manifest staging locks (shared across clones). Two pods of the same
    /// image scheduling together both reach `stage()` for the same manifest;
    /// without serialization their writes into the shared `work_dir` interleave.
    /// Entries are never evicted — the map is bounded by the number of distinct
    /// accelerated images on the node and each entry is a few dozen bytes.
    stage_locks: Arc<async_lock::Mutex<HashMap<String, Arc<async_lock::Mutex<()>>>>>,
}

impl SidecarLocator {
    pub fn new(
        content_store: ContentStoreClient,
        snapshotter_root: &Path,
        peer_mirror_config: &PeerMirrorConfig,
    ) -> Self {
        let peer_mirror = match build_peer_mirror(peer_mirror_config) {
            Ok(mirror) => mirror,
            Err(e) => {
                warn!(
                    error = ?e,
                    "peer mirror setup failed; cross-node auto-accel discovery disabled"
                );
                None
            }
        };
        if peer_mirror.is_none() && peer_mirror_config.is_enabled() {
            warn!(
                endpoint = %peer_mirror_config.endpoint(),
                ca = ?peer_mirror_config.ca_path(),
                "peer mirror enabled in config but client could not be constructed; \
                 cross-node auto-accel discovery disabled"
            );
        }
        Self {
            content_store,
            stage_root: snapshotter_root.join("auto-accel"),
            peer_mirror,
            stage_locks: Arc::default(),
        }
    }

    /// Resolve an auto-accel manifest for `manifest_digest`, pulling it
    /// from a peer via the peer mirror when not already local. Tries in order:
    ///
    /// 1. Local `images.Get(synthetic-ref)` — hit on the producer node and
    ///    on any peer that already pulled this sidecar.
    /// 2. Direct HTTPS GET against the local peer mirror, then every
    ///    discovered/configured peer mirror (see [`crate::peer_mirror`] for the
    ///    failover semantics). On a hit, the OCI manifest + its config +
    ///    every layer (bootstrap, zran indexes, prefetch blob) land in the
    ///    local content store and the Image record is registered. A
    ///    categorised pull failure distinguishes "no peer has it" (clean
    ///    miss) from "mirror / registry is broken" (warn + still fall
    ///    through, but operator sees the signal).
    /// 3. Label-filter scan on the content store — covers legacy artifacts
    ///    uploaded before the image-record registration landed.
    ///
    /// Returns `Ok(None)` when nothing matches — the caller falls back to
    /// overlay. Named for the actual behaviour (not just a read-only
    /// "find") so callers see the mutation.
    pub async fn resolve_or_pull(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<AutoAccelManifest>> {
        let image_name = crate::auto_zran::auto_accel_image_name(manifest_digest);

        let mut resolved = self
            .content_store
            .images_get(&image_name)
            .await
            .unwrap_or_else(|e| {
                debug!(image_name = %image_name, error = %e, "auto-accel images.Get failed; will try pull");
                None
            });

        if resolved.is_none() {
            // Drive a direct HTTPS pull through the peer mirror. If any mirror has
            // the image record, this brings everything down in one
            // transfer.
            match self.peer_pull(manifest_digest, &image_name).await {
                PullOutcome::Ok => {
                    info!(image_name = %image_name, "auto-accel pulled via peer mirror");
                    resolved = self
                        .content_store
                        .images_get(&image_name)
                        .await
                        .unwrap_or_else(|e| {
                            debug!(image_name = %image_name, error = %e, "post-pull images.Get failed");
                            None
                        });
                }
                PullOutcome::NotFound => {
                    debug!(image_name = %image_name, "no mirror has this sidecar; falling back to label scan");
                }
                PullOutcome::RegistryError { status, body } => {
                    // Real configuration failure — surface loudly. Without
                    // this every pod on a misconfigured-mirror node would
                    // silently degrade to overlay forever.
                    warn!(
                        image_name = %image_name,
                        status,
                        body = %body,
                        "auto-accel pull failed: registry/mirror error (peer mirror mTLS, auth, daemon down?). Cross-node discovery degraded until fixed."
                    );
                }
                PullOutcome::Disabled => {
                    debug!(image_name = %image_name, "peer mirror disabled or unconfigured; cross-node discovery skipped");
                }
            }
        }

        let blob = match resolved {
            Some(info) => info,
            None => {
                // Label-filter fallback (legacy artifacts).
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

        // The Image record points at the OCI manifest. Parse it, fetch the
        // referenced config blob (which is our AutoAccelManifest JSON), and
        // return that to the caller.
        let manifest_bytes = self.content_store.fetch_bytes(&blob.digest).await?;
        let oci: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parse oci wrapper for {}", blob.digest))?;
        let config_digest = oci
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("oci manifest {} missing config.digest", blob.digest))?
            .to_string();
        let config_bytes = self.content_store.fetch_bytes(&config_digest).await?;
        let manifest: AutoAccelManifest = serde_json::from_slice(&config_bytes)
            .with_context(|| format!("parse auto-accel config blob {config_digest}"))?;
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
    ///
    /// Serialized per manifest digest: the `work_dir` is shared and live (a
    /// just-started daemon may already be reading `backend/`), so all writes
    /// below are atomic (write-temp + rename) and concurrent stagings of the
    /// same manifest take turns instead of interleaving.
    pub async fn stage(
        &self,
        manifest_digest: &str,
        manifest: &AutoAccelManifest,
    ) -> Result<StagedSidecar> {
        let stage_lock = {
            let mut locks = self.stage_locks.lock().await;
            locks
                .entry(manifest_digest.to_string())
                .or_default()
                .clone()
        };
        let _guard = stage_lock.lock().await;

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
        copy_atomic(&bootstrap_src, &bootstrap_dst)?;
        // 5. The daemon's fanotify service discovers its inputs from the
        //    backend dir alone (`service/src/fanotify.rs::discover_blobs`
        //    requires a file literally named `bootstrap` next to the data
        //    blobs), so the bootstrap must ALSO live inside backend_dir —
        //    without it `ensure_instance_local` fails with "no bootstrap
        //    file in blob directory" on every node.
        let backend_bootstrap = backend_dir.join("bootstrap");
        copy_atomic(&bootstrap_src, &backend_bootstrap)?;

        Ok(StagedSidecar {
            bootstrap: bootstrap_dst,
            backend_dir,
            work_dir,
        })
    }

    /// Pull the auto-accel sidecar manifest + every referenced blob from
    /// the peer mirrors. Returns `PullOutcome::Disabled` when the
    /// mirror isn't configured (silent fallback to overlay), otherwise
    /// maps the HTTP responses into one of the four outcomes.
    async fn peer_pull(&self, manifest_digest: &str, synthetic_ref: &str) -> PullOutcome {
        let Some(mirror) = self.peer_mirror.as_ref() else {
            return PullOutcome::Disabled;
        };

        let (host, repo, tag) = match split_synthetic_ref(synthetic_ref) {
            Some(parts) => parts,
            None => {
                return PullOutcome::RegistryError {
                    status: 0,
                    body: format!("malformed synthetic ref {synthetic_ref}"),
                };
            }
        };

        // 1. Manifest fetch. The mirror's query template supplies the
        //    load-bearing query parameter (Spegel's `?ns=<registry>`); an
        //    empty template yields no query string.
        let manifest_path = with_query(
            &format!("/v2/{repo}/manifests/{tag}"),
            &mirror.artifact_query(&host),
        );
        let manifest_bytes = match mirror.fetch(&manifest_path, Some(ACCEPT_MANIFEST)).await {
            FetchResult::Ok(b) => b,
            FetchResult::Outcome(o) => return o,
            FetchResult::NotFound => return PullOutcome::NotFound,
            FetchResult::Error { status, body } => {
                return PullOutcome::RegistryError { status, body };
            }
        };
        // Verify before anything touches the content store: `write_bytes` computes
        // the store key from the *received* bytes, so without this check corrupt
        // peer data "succeeds" under its own digest, the Image record registers,
        // `resolve_or_pull` never re-pulls (record exists), and `stage()` fails on
        // the missing real digest forever — silently degrading the node to overlay.
        if let Err(e) = verify_sha256(&manifest_bytes, manifest_digest) {
            return PullOutcome::RegistryError {
                status: 0,
                body: format!("peer mirror returned corrupt manifest: {e}"),
            };
        }

        // 2. Parse the OCI wrapper first so the manifest write below can
        //    carry `gc.ref.content.config` + `gc.ref.content.l.<n>`
        //    labels pointing at every blob the manifest references.
        //    Without these labels containerd's GC orphans the just-
        //    written config + layer blobs the moment GC runs (it does
        //    NOT parse manifest JSON for GC walking — operators have to
        //    mirror the references into labels). The producer (auto_zran)
        //    mirrors the same pattern; consumer must match so the second
        //    pod on this node doesn't refetch.
        let oci: OciImageManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                return PullOutcome::RegistryError {
                    status: 0,
                    body: format!("parse oci manifest pulled from the peer mirror: {e}"),
                };
            }
        };
        if oci.media_type != OCI_MANIFEST_MEDIATYPE {
            return PullOutcome::RegistryError {
                status: 0,
                body: format!(
                    "unexpected manifest mediaType {}; expected {}",
                    oci.media_type, OCI_MANIFEST_MEDIATYPE
                ),
            };
        }

        let subject_labels = manifest_blob_labels(manifest_digest, synthetic_ref, &oci);
        let manifest_digest_in_store = match self
            .content_store
            .write_bytes(
                &manifest_bytes,
                &format!(
                    "nydus-auto-accel-peer-manifest:{}",
                    strip_sha256(manifest_digest)
                ),
                subject_labels,
            )
            .await
        {
            Ok(d) => d,
            Err(e) => {
                return PullOutcome::RegistryError {
                    status: 0,
                    body: format!("write manifest to content store failed: {e}"),
                };
            }
        };

        // 2a. Config blob.
        if let Err(o) = self
            .peer_pull_blob(
                mirror,
                manifest_digest,
                &host,
                &repo,
                &oci.config.digest,
                AUTO_ACCEL_CONFIG_MEDIATYPE,
                synthetic_ref,
                None,
            )
            .await
        {
            return o;
        }

        // 2b. Each layer blob (bootstrap, indexes, optional prefetch).
        for layer in &oci.layers {
            let role = role_for_media_type(&layer.media_type);
            let layer_digest = layer
                .annotations
                .get(AUTO_ACCEL_LAYER_DIGEST_ANNOTATION)
                .cloned();
            if let Err(o) = self
                .peer_pull_blob(
                    mirror,
                    manifest_digest,
                    &host,
                    &repo,
                    &layer.digest,
                    role,
                    synthetic_ref,
                    layer_digest,
                )
                .await
            {
                return o;
            }
        }

        // 3. Register the Image record locally so the next pod hits
        //    `images_get` straight away.
        if let Err(e) = self
            .content_store
            .images_create(
                synthetic_ref,
                &manifest_digest_in_store,
                manifest_bytes.len() as u64,
                OCI_MANIFEST_MEDIATYPE,
                image_record_labels(manifest_digest),
            )
            .await
        {
            // Non-fatal: blobs are written + GC-anchored. images_get
            // would miss but the label-scan fallback in `resolve_or_pull`
            // still finds the manifest. Log loud so operators see it.
            warn!(
                image_name = %synthetic_ref,
                error = ?e,
                "peer mirror pull wrote blobs but Image record registration failed"
            );
        }

        PullOutcome::Ok
    }

    /// Pull one blob by digest via the peer mirror and write it into the
    /// local content store with the right role + layer-digest labels. Returns
    /// `Ok(())` on success or the `PullOutcome` to propagate on failure.
    #[allow(clippy::too_many_arguments)]
    async fn peer_pull_blob(
        &self,
        mirror: &Arc<PeerMirror>,
        manifest_digest: &str,
        host: &str,
        repo: &str,
        blob_digest: &str,
        role: &str,
        synthetic_ref: &str,
        layer_digest: Option<String>,
    ) -> std::result::Result<(), PullOutcome> {
        let path = with_query(
            &format!("/v2/{repo}/blobs/{blob_digest}"),
            &mirror.artifact_query(host),
        );
        let bytes = match mirror.fetch(&path, None).await {
            FetchResult::Ok(b) => b,
            FetchResult::Outcome(o) => return Err(o),
            FetchResult::NotFound => return Err(PullOutcome::NotFound),
            FetchResult::Error { status, body } => {
                return Err(PullOutcome::RegistryError { status, body });
            }
        };
        // See peer_pull(): unverified bytes would be committed under their own
        // (wrong) digest and permanently poison this node's sidecar for the image.
        if let Err(e) = verify_sha256(&bytes, blob_digest) {
            return Err(PullOutcome::RegistryError {
                status: 0,
                body: format!("peer mirror returned corrupt blob: {e}"),
            });
        }
        let labels = labels_for_role(manifest_digest, role, synthetic_ref, layer_digest);
        self.content_store
            .write_bytes(
                &bytes,
                &format!(
                    "nydus-auto-accel-peer-{}:{}",
                    role,
                    strip_sha256(blob_digest)
                ),
                labels,
            )
            .await
            .map_err(|e| PullOutcome::RegistryError {
                status: 0,
                body: format!("write blob {blob_digest} to content store failed: {e}"),
            })?;
        Ok(())
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
            "{kind} {} missing from content store (peer mirror cache miss?)",
            path.display()
        ));
    }
    Ok(())
}

/// (Re)point `link` at `target` without any window where the name is missing:
/// the symlink is created under a temp name and `rename(2)`d over the final
/// one. A remove+create pair would briefly leave the blob name dangling for a
/// daemon that is already serving out of this backend dir.
fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let tmp = link.with_extension("tmp-link");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(target, &tmp)
            .with_context(|| format!("symlink {} -> {}", tmp.display(), target.display()))?;
        std::fs::rename(&tmp, link).with_context(|| {
            format!(
                "rename symlink {} into place at {}",
                tmp.display(),
                link.display()
            )
        })
    }
    #[cfg(not(unix))]
    {
        copy_atomic(target, link)
    }
}

/// Copy `src` to `dst` atomically (write to a temp name in the destination
/// directory, then `rename(2)`), so a reader never observes a half-written
/// `dst`. Callers serialize per destination via the stage lock, so the fixed
/// temp suffix cannot collide.
fn copy_atomic(src: &Path, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("tmp-copy");
    std::fs::copy(src, &tmp)
        .with_context(|| format!("copy {} -> {}", src.display(), tmp.display()))?;
    std::fs::rename(&tmp, dst)
        .with_context(|| format!("rename {} into place at {}", tmp.display(), dst.display()))
}

fn strip_sha256(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Verify that `bytes` hash to the expected `sha256:<hex>` digest. Peer-mirror
/// responses are untrusted input: everything pulled from a peer must pass this
/// before it is written to the content store or parsed further.
fn verify_sha256(bytes: &[u8], expected: &str) -> std::result::Result<(), String> {
    use sha2::{Digest, Sha256};
    let Some(want) = expected.strip_prefix("sha256:") else {
        return Err(format!(
            "unsupported digest algorithm in {expected}; only sha256 is supported"
        ));
    };
    let got = hex::encode(Sha256::digest(bytes));
    if got.eq_ignore_ascii_case(want) {
        Ok(())
    } else {
        Err(format!(
            "digest mismatch: expected {expected}, computed sha256:{got}"
        ))
    }
}

/// Map an OCI layer mediaType from our producer to the `role` label we
/// stamp on the corresponding content blob. Unknown mediaTypes fall back
/// to `"index"` to match the producer's per-layer default (zran indexes
/// are by far the most common layer kind in a sidecar).
fn role_for_media_type(media_type: &str) -> &'static str {
    match media_type {
        AUTO_ACCEL_BOOTSTRAP_MEDIATYPE => "bootstrap",
        AUTO_ACCEL_PREFETCH_MEDIATYPE => "prefetch-blob",
        // `index` covers the canonical zran-index mediaType AND any
        // unknown mediaType (defensive against a producer-side rename).
        _ => "index",
    }
}

/// Build the label set the local content store expects for a pulled
/// blob. Mirrors the producer side so an `images_get` after a
/// peer-mirror-pulled blob hands back the same shape a locally-converted blob
/// would.
fn labels_for_role(
    manifest_digest: &str,
    role: &str,
    synthetic_ref: &str,
    layer_digest: Option<String>,
) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(LABEL_SUBJECT.to_string(), manifest_digest.to_string());
    m.insert(LABEL_ROLE.to_string(), role.to_string());
    m.insert(LABEL_DISTRIBUTION_SOURCE.to_string(), "sidecar".to_string());
    if let Some(ld) = layer_digest {
        m.insert(
            "containerd.io/snapshot/nydus.auto-accel.layer-digest".to_string(),
            ld,
        );
    }
    // The synthetic ref is also kept as an annotation hint so logs +
    // `ctr content ls` show which sidecar this blob belongs to.
    m.insert(
        "containerd.io/snapshot/nydus.auto-accel.subject-image".to_string(),
        synthetic_ref.to_string(),
    );
    m
}

/// Labels for the OCI manifest blob itself: the `labels_for_role` base
/// plus one `gc.ref.content.*` edge per referenced blob so containerd's
/// GC keeps the config + layers alive exactly as long as the manifest.
/// Containerd does NOT parse manifest JSON when walking GC references —
/// without these labels every referenced blob is an orphan at the next
/// GC pass.
fn manifest_blob_labels(
    manifest_digest: &str,
    synthetic_ref: &str,
    oci: &OciImageManifest,
) -> HashMap<String, String> {
    let mut labels = labels_for_role(manifest_digest, "manifest", synthetic_ref, None);
    labels.insert(
        "containerd.io/gc.ref.content.config".to_string(),
        oci.config.digest.clone(),
    );
    for (i, layer) in oci.layers.iter().enumerate() {
        labels.insert(
            format!("containerd.io/gc.ref.content.l.{}", i),
            layer.digest.clone(),
        );
    }
    labels
}

/// Labels stamped on the Image record itself. The producer uses the same
/// shape — keep it identical so an `images_get` after a peer-mirror-pulled
/// record returns the same labels callers expect.
fn image_record_labels(manifest_digest: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(LABEL_SUBJECT.to_string(), manifest_digest.to_string());
    m.insert(LABEL_ROLE.to_string(), "manifest".to_string());
    m.insert(LABEL_DISTRIBUTION_SOURCE.to_string(), "sidecar".to_string());
    m
}

/// Append a peer-mirror query string to a `/v2/...` path. `None` (empty
/// query template) yields the bare path; `Some(q)` yields `<path>?<q>`.
/// The query is the mirror's [`PeerMirror::artifact_query`] output — for the
/// Spegel presets that is the load-bearing `ns=<registry>`.
fn with_query(path: &str, query: &Option<String>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// Split a synthetic ref `<host>/<repo>:<tag>` into its three components.
/// Returns `None` for any shape we can't parse — that surfaces as a
/// `RegistryError { status: 0, ... }` in `peer_pull`.
fn split_synthetic_ref(synthetic_ref: &str) -> Option<(String, String, String)> {
    let (host_and_repo, tag) = synthetic_ref.rsplit_once(':')?;
    let (host, repo) = host_and_repo.split_once('/')?;
    if host.is_empty() || repo.is_empty() || tag.is_empty() {
        return None;
    }
    Some((host.to_string(), repo.to_string(), tag.to_string()))
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
    pub fn new(
        content_store: ContentStoreClient,
        snapshotter_root: &Path,
        peer_mirror_config: &PeerMirrorConfig,
    ) -> Self {
        Self {
            locator: Arc::new(SidecarLocator::new(
                content_store,
                snapshotter_root,
                peer_mirror_config,
            )),
        }
    }

    /// One-shot helper: resolve-or-pull + stage in one call. Returns
    /// `Ok(None)` if no sidecar exists; the caller falls back to overlay.
    pub async fn resolve(&self, manifest_digest: &str) -> Result<Option<StagedSidecar>> {
        let Some(manifest) = self.locator.resolve_or_pull(manifest_digest).await? else {
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
    use crate::auto_accel_oci::{AUTO_ACCEL_INDEX_MEDIATYPE, OciDescriptor};

    #[test]
    fn verify_sha256_accepts_matching_and_rejects_corrupt_bytes() {
        // sha256("hello") — a peer-mirror response must match the digest it was
        // requested under before it may touch the content store.
        let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(b"hello", digest).is_ok());
        assert!(
            verify_sha256(b"hello", &digest.to_uppercase().replace("SHA256", "sha256")).is_ok()
        );
        let err = verify_sha256(b"corrupted", digest).unwrap_err();
        assert!(err.contains("digest mismatch"), "{err}");
        assert!(verify_sha256(b"hello", "sha512:abc").is_err());
    }

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

    /// `split_synthetic_ref` is the producer/consumer contract for the
    /// `<host>/<repo>:<tag>` shape. Pin it so a rename on either side
    /// fails at compile/test time, not at runtime when a pull lands on a
    /// peer node.
    #[test]
    fn split_synthetic_ref_parses_the_canonical_shape() {
        let (host, repo, tag) =
            split_synthetic_ref("nydus.auto-accel.local/sidecar:e6017bb").unwrap();
        assert_eq!(host, "nydus.auto-accel.local");
        assert_eq!(repo, "sidecar");
        assert_eq!(tag, "e6017bb");
    }

    #[test]
    fn split_synthetic_ref_rejects_missing_pieces() {
        assert!(split_synthetic_ref("nydus.auto-accel.local").is_none()); // no `:`
        assert!(split_synthetic_ref("nydus.auto-accel.local/sidecar").is_none()); // no `:`
        assert!(split_synthetic_ref(":e6017bb").is_none()); // no host/repo
        assert!(split_synthetic_ref("nydus.auto-accel.local/:e6017bb").is_none()); // empty repo
        assert!(split_synthetic_ref("nydus.auto-accel.local/sidecar:").is_none()); // empty tag
    }

    /// `role_for_media_type` is the mediaType → role translation the
    /// consumer uses when stamping labels on a peer-mirror-pulled blob. Keep
    /// it pinned so a producer-side mediaType rename fails here, not at
    /// runtime when the wrong label lands on a blob.
    #[test]
    fn role_for_media_type_maps_each_known_layer_kind() {
        assert_eq!(
            role_for_media_type(AUTO_ACCEL_BOOTSTRAP_MEDIATYPE),
            "bootstrap"
        );
        assert_eq!(role_for_media_type(AUTO_ACCEL_INDEX_MEDIATYPE), "index");
        assert_eq!(
            role_for_media_type(AUTO_ACCEL_PREFETCH_MEDIATYPE),
            "prefetch-blob"
        );
        assert_eq!(role_for_media_type("something/unknown"), "index");
    }

    fn descriptor(media_type: &str, digest: &str) -> OciDescriptor {
        OciDescriptor {
            media_type: media_type.to_string(),
            digest: digest.to_string(),
            size: 1,
            annotations: HashMap::new(),
        }
    }

    /// The GC-edge labels on the manifest blob are what keep the config
    /// and layer blobs alive across containerd GC passes. A missing edge
    /// here resurfaces as a peer-mirror 404 for a referenced blob on every
    /// consumer node — pin the full shape.
    #[test]
    fn manifest_blob_labels_carry_gc_edges_for_all_references() {
        let oci = OciImageManifest {
            schema_version: 2,
            media_type: OCI_MANIFEST_MEDIATYPE.to_string(),
            config: descriptor(AUTO_ACCEL_CONFIG_MEDIATYPE, "sha256:cfg"),
            layers: vec![
                descriptor(AUTO_ACCEL_BOOTSTRAP_MEDIATYPE, "sha256:boot"),
                descriptor(AUTO_ACCEL_INDEX_MEDIATYPE, "sha256:idx0"),
                descriptor(AUTO_ACCEL_PREFETCH_MEDIATYPE, "sha256:pf"),
            ],
            annotations: HashMap::new(),
        };
        let labels =
            manifest_blob_labels("sha256:subject", "nydus.auto-accel.local/sidecar:t", &oci);
        assert_eq!(
            labels.get("containerd.io/gc.ref.content.config").unwrap(),
            "sha256:cfg"
        );
        assert_eq!(
            labels.get("containerd.io/gc.ref.content.l.0").unwrap(),
            "sha256:boot"
        );
        assert_eq!(
            labels.get("containerd.io/gc.ref.content.l.1").unwrap(),
            "sha256:idx0"
        );
        assert_eq!(
            labels.get("containerd.io/gc.ref.content.l.2").unwrap(),
            "sha256:pf"
        );
        // Base labels still present.
        assert_eq!(labels.get(LABEL_SUBJECT).unwrap(), "sha256:subject");
        assert_eq!(labels.get(LABEL_ROLE).unwrap(), "manifest");
    }
}
