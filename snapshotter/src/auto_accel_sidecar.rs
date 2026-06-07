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
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use http::header::ACCEPT;
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
use crate::config::SpegelMirrorConfig;
use crate::content_store::{ContentInfo, ContentStoreClient};

const LABEL_ROLE: &str = "containerd.io/snapshot/nydus.auto-accel.role";
const LABEL_SUBJECT: &str = "containerd.io/gc.ref.content.subject";
const LABEL_DISTRIBUTION_SOURCE: &str = "containerd.io/distribution.source.nydus.auto-accel.local";

/// Accept header used on every manifest GET. We accept both the OCI media
/// type our producer emits and the docker v2 manifest media type so a
/// spegel that's been asked to fall back to upstream (or that's serving a
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
    /// Spegel HTTPS client + endpoint URL. `None` when the mirror is
    /// disabled by config, or when any of the configured cert files don't
    /// exist on disk at startup. When `None`, `spegel_pull` is a no-op
    /// returning `PullOutcome::NoBinary` so the locator falls through to
    /// the label-filter scan.
    spegel: Option<Arc<SpegelClient>>,
}

/// Send + Sync metadata bundle for the embedded spegel mirror. Holds
/// only Send + Sync state (an `Arc`-shared rustls config + the endpoint
/// list); the actual `cyper::Client` is `!Send + !Sync` because it
/// targets the compio current_thread runtime, so it is built per call
/// on a blocking pool thread driving its own thread-local compio
/// runtime (see `block_on_http`). This matches the per-thread cyper
/// pattern `storage/src/backend/connection.rs` uses for the registry
/// backend and keeps reqwest + tokio out of the snapshotter.
///
/// `endpoints[0]` is the primary (local spegel on `127.0.0.1`); the
/// rest are peer fallbacks for clusters where libp2p peer routing
/// fails ("empty list of address ports").
struct SpegelClient {
    tls: Arc<rustls::ClientConfig>,
    endpoints: Vec<String>,
}

thread_local! {
    /// Per-thread compio runtime used by `block_on_http` to drive cyper
    /// from inside `blocking::unblock`. cyper's HTTPS plumbing
    /// (hickory DNS resolver, hyper executor) needs `Runtime::current()`
    /// at client-build time and a `block_on` to run requests, so each
    /// blocking thread gets its own. Mirrors the per-thread runtime in
    /// `storage/src/backend/connection.rs`.
    static HTTP_RUNTIME: compio::runtime::Runtime = compio::runtime::Runtime::new()
        .expect("auto_accel_sidecar: failed to create compio HTTP runtime");
}

fn block_on_http<F: std::future::Future>(fut: F) -> F::Output {
    HTTP_RUNTIME.with(|rt| rt.block_on(fut))
}

impl SidecarLocator {
    pub fn new(
        content_store: ContentStoreClient,
        snapshotter_root: &Path,
        spegel_config: &SpegelMirrorConfig,
    ) -> Self {
        let spegel = match build_spegel_client(spegel_config) {
            Ok(client) => client.map(Arc::new),
            Err(e) => {
                warn!(
                    error = ?e,
                    "spegel mirror client setup failed; cross-node auto-accel discovery disabled"
                );
                None
            }
        };
        if spegel.is_none() && spegel_config.enable {
            warn!(
                endpoint = %spegel_config.endpoint,
                ca = %spegel_config.ca_path.display(),
                "spegel mirror enabled in config but client could not be constructed; \
                 cross-node auto-accel discovery disabled"
            );
        }
        Self {
            content_store,
            stage_root: snapshotter_root.join("auto-accel"),
            spegel,
        }
    }

    /// Resolve an auto-accel manifest for `manifest_digest`, pulling it
    /// from a peer via spegel when not already local. Tries in order:
    ///
    /// 1. Local `images.Get(synthetic-ref)` — hit on the producer node and
    ///    on any peer that already pulled this sidecar.
    /// 2. Direct HTTPS GET to k3s's embedded spegel mirror endpoint with
    ///    the required `?ns=<registry>` query parameter. spegel checks its
    ///    local content store first, then falls back to a libp2p peer
    ///    lookup; if a peer has the image record advertised, the OCI
    ///    manifest + its config + every layer (bootstrap, zran indexes,
    ///    prefetch blob) flow through the mirror in one transfer. After
    ///    success we retry `images.Get`. A categorised pull failure
    ///    distinguishes "no peer has it" (clean miss) from "mirror /
    ///    registry is broken" (warn + still fall through, but operator
    ///    sees the signal).
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
            // Drive a direct HTTPS pull through spegel. If a peer
            // advertises the image record, this brings everything down in
            // one transfer.
            match self.spegel_pull(manifest_digest, &image_name).await {
                PullOutcome::Ok => {
                    info!(image_name = %image_name, "auto-accel pulled via spegel mirror");
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
                    debug!(image_name = %image_name, "no peer advertised this sidecar; falling back to label scan");
                }
                PullOutcome::RegistryError { status, body } => {
                    // Real configuration failure — surface loudly. Without
                    // this every pod on a misconfigured-spegel node would
                    // silently degrade to overlay forever.
                    warn!(
                        image_name = %image_name,
                        status,
                        body = %body,
                        "auto-accel pull failed: registry/mirror error (spegel mTLS, auth, daemon down?). Cross-node discovery disabled until fixed."
                    );
                }
                PullOutcome::NoBinary => {
                    debug!(image_name = %image_name, "spegel mirror disabled or unconfigured; cross-node discovery skipped");
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

/// Categorised outcome of a containerd image-pull attempt for the
/// synthetic auto-accel ref. Discovery treats `NotFound` as a clean miss
/// (no peer advertised this sidecar — fall back to overlay) but logs
/// `RegistryError` at `warn!` so a broken spegel mirror or stale mTLS
/// doesn't silently disable every auto-accel mount cluster-wide.
#[derive(Debug, Clone, Eq, PartialEq)]
enum PullOutcome {
    /// Pull committed; the manifest + every referenced blob are now in
    /// the local content store and the Image record is registered.
    Ok,
    /// Spegel returned 404 — no peer has the sidecar locally and the
    /// libp2p DHT has no advertisement for it either. Expected on
    /// first-pod scheduling before any node has converted.
    NotFound,
    /// Spegel returned any other non-success status (401/403/5xx etc),
    /// or a transport-layer failure prevented the request from
    /// completing. Captured for triage so a misconfigured-spegel node
    /// doesn't silently disable every auto-accel mount cluster-wide.
    /// `status: 0` means the request never reached spegel (transport,
    /// TLS, malformed ref, write-to-content-store failure, etc.).
    RegistryError { status: u16, body: String },
    /// Mirror is disabled by config, or any of the cert files don't
    /// exist on disk. Quiet fallback — the locator falls through to its
    /// label-filter scan and the node behaves exactly as it did before
    /// the spegel-pull path landed.
    NoBinary,
}

impl SidecarLocator {
    /// Pull the auto-accel sidecar manifest + every referenced blob from
    /// k3s's embedded spegel mirror. Returns `PullOutcome::NoBinary` when
    /// the mirror isn't configured (silent fallback to overlay), otherwise
    /// maps spegel's HTTP response into one of the four outcomes.
    ///
    /// Spegel requires the `?ns=<registry>` query parameter on every
    /// request; its `distribution.go` parser reads the registry namespace
    /// from there and 404s every request that omits it — even for content
    /// that IS in the local content store. That's the entire reason we're
    /// here.
    async fn spegel_pull(&self, manifest_digest: &str, synthetic_ref: &str) -> PullOutcome {
        let Some(spegel) = self.spegel.as_ref() else {
            return PullOutcome::NoBinary;
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

        // 1. Manifest fetch (`?ns=` is the load-bearing query parameter).
        let manifest_path = format!("/v2/{}/manifests/{}?ns={}", repo, tag, host);
        let manifest_bytes = match spegel_fetch(spegel, &manifest_path, Some(ACCEPT_MANIFEST)).await
        {
            FetchResult::Ok(b) => b,
            FetchResult::Outcome(o) => return o,
            FetchResult::NotFound => return PullOutcome::NotFound,
            FetchResult::Error { status, body } => {
                return PullOutcome::RegistryError { status, body };
            }
        };
        let subject_labels = labels_for_role(manifest_digest, "manifest", synthetic_ref, None);
        let manifest_digest_in_store = match self
            .content_store
            .write_bytes(
                &manifest_bytes,
                &format!(
                    "nydus-auto-accel-spegel-manifest:{}",
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

        // 2. Parse the OCI wrapper, then fetch the config + every layer
        //    by digest through spegel (still with `?ns=`).
        let oci: OciImageManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                return PullOutcome::RegistryError {
                    status: 0,
                    body: format!("parse oci manifest pulled from spegel: {e}"),
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

        // 2a. Config blob.
        if let Err(o) = self
            .spegel_pull_blob(
                spegel,
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
                .spegel_pull_blob(
                    spegel,
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
                "spegel pull wrote blobs but Image record registration failed"
            );
        }

        PullOutcome::Ok
    }

    /// Pull one blob by digest via spegel and write it into the local
    /// content store with the right role + layer-digest labels. Returns
    /// `Ok(())` on success or the `PullOutcome` to propagate on failure.
    #[allow(clippy::too_many_arguments)]
    async fn spegel_pull_blob(
        &self,
        spegel: &SpegelClient,
        manifest_digest: &str,
        host: &str,
        repo: &str,
        blob_digest: &str,
        role: &str,
        synthetic_ref: &str,
        layer_digest: Option<String>,
    ) -> std::result::Result<(), PullOutcome> {
        let path = format!("/v2/{}/blobs/{}?ns={}", repo, blob_digest, host);
        let bytes = match spegel_fetch(spegel, &path, None).await {
            FetchResult::Ok(b) => b,
            FetchResult::Outcome(o) => return Err(o),
            FetchResult::NotFound => return Err(PullOutcome::NotFound),
            FetchResult::Error { status, body } => {
                return Err(PullOutcome::RegistryError { status, body });
            }
        };
        let labels = labels_for_role(manifest_digest, role, synthetic_ref, layer_digest);
        self.content_store
            .write_bytes(
                &bytes,
                &format!(
                    "nydus-auto-accel-spegel-{}:{}",
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
/// spegel-pulled blob hands back the same shape a locally-converted blob
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

/// Labels stamped on the Image record itself. The producer uses the same
/// shape — keep it identical so an `images_get` after a spegel-pulled
/// record returns the same labels callers expect.
fn image_record_labels(manifest_digest: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(LABEL_SUBJECT.to_string(), manifest_digest.to_string());
    m.insert(LABEL_ROLE.to_string(), "manifest".to_string());
    m.insert(LABEL_DISTRIBUTION_SOURCE.to_string(), "sidecar".to_string());
    m
}

/// Split a synthetic ref `<host>/<repo>:<tag>` into its three components.
/// Returns `None` for any shape we can't parse — that surfaces as a
/// `RegistryError { status: 0, ... }` in `spegel_pull`.
fn split_synthetic_ref(synthetic_ref: &str) -> Option<(String, String, String)> {
    let (host_and_repo, tag) = synthetic_ref.rsplit_once(':')?;
    let (host, repo) = host_and_repo.split_once('/')?;
    if host.is_empty() || repo.is_empty() || tag.is_empty() {
        return None;
    }
    Some((host.to_string(), repo.to_string(), tag.to_string()))
}

/// Intermediate result for a spegel HTTPS GET.
enum FetchResult {
    Ok(Vec<u8>),
    NotFound,
    Error {
        status: u16,
        body: String,
    },
    /// Catastrophic client-side failure that maps cleanly to a
    /// `PullOutcome` other than NotFound/Error.
    Outcome(PullOutcome),
}

/// GET + body read against the ordered spegel endpoints list. Pulled
/// out of `spegel_pull` so the same status-categorisation logic runs
/// for manifest + every blob, and so the fallback iteration happens
/// in one place.
///
/// Runs the cyper call inside `blocking::unblock` so the future this
/// returns IS `Send` (required because the containerd-snapshots
/// `Snapshotter` trait via `#[tonic::async_trait]` makes its method
/// futures `Send + 'static`) even though cyper's `Client` is
/// `!Send + !Sync` underneath. The blocking thread drives a
/// thread-local compio runtime and a one-shot cyper client; both are
/// dropped before the outer future resumes.
///
/// Iteration rules:
/// - The list is `[primary, peer1, peer2, ...]`. We always start at
///   the primary so single-node clusters keep the cheap local hit and
///   never touch the cross-node network.
/// - 2xx from any endpoint → `Ok(bytes)`, no further endpoints tried.
/// - 404 from one endpoint → try the next one. 404 across the entire
///   list → `NotFound` (real "nobody has it" signal).
/// - Any other status / transport error → remember it as a candidate
///   `Error` outcome but keep iterating: a peer further down the list
///   might still have the content. If every endpoint either errors or
///   404s and at least one errored, surface the LAST error (richest
///   triage data for the operator).
///
/// `path_and_query` MUST start with `/v2/...` and include the load-
/// bearing `?ns=<registry>` query parameter — see `spegel_pull` for
/// why.
async fn spegel_fetch(
    spegel: &SpegelClient,
    path_and_query: &str,
    accept: Option<&str>,
) -> FetchResult {
    let tls = spegel.tls.clone();
    let endpoints = spegel.endpoints.clone();
    let path = path_and_query.to_string();
    let accept = accept.map(str::to_string);
    blocking::unblock(move || {
        block_on_http(async move {
            let client = match cyper::Client::builder().use_rustls(tls).build() {
                Ok(c) => c,
                Err(e) => {
                    return FetchResult::Outcome(PullOutcome::RegistryError {
                        status: 0,
                        body: format!("build cyper client for spegel: {e}"),
                    });
                }
            };
            let mut last_error: Option<FetchResult> = None;
            let mut last_outcome: Option<FetchResult> = None;
            for endpoint in &endpoints {
                let url = format!("{endpoint}{path}");
                let req_builder = match client.get(&url) {
                    Ok(r) => r,
                    Err(e) => {
                        last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                            status: 0,
                            body: format!("invalid spegel URL {url}: {e}"),
                        }));
                        continue;
                    }
                };
                let req = if let Some(ref accept) = accept {
                    match req_builder.header(ACCEPT, accept.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("invalid Accept header for {url}: {e}"),
                            }));
                            continue;
                        }
                    }
                } else {
                    req_builder
                };
                let response =
                    match compio::time::timeout(Duration::from_secs(30), req.send()).await {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("transport error for {url}: {e}"),
                            }));
                            continue;
                        }
                        Err(_) => {
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: 0,
                                body: format!("spegel request timed out for {url}"),
                            }));
                            continue;
                        }
                    };
                let status = response.status();
                match http_status_to_outcome(status.as_u16()) {
                    StatusOutcome::Ok => match response.bytes().await {
                        Ok(b) => return FetchResult::Ok(b.to_vec()),
                        Err(e) => {
                            last_outcome = Some(FetchResult::Outcome(PullOutcome::RegistryError {
                                status: status.as_u16(),
                                body: format!("read body for {url}: {e}"),
                            }));
                        }
                    },
                    StatusOutcome::NotFound => {
                        // Try the next peer; keep going.
                    }
                    StatusOutcome::Error => {
                        let body = response.text().await.unwrap_or_default();
                        last_error = Some(FetchResult::Error {
                            status: status.as_u16(),
                            body,
                        });
                    }
                }
            }
            // No 2xx from any endpoint. Prefer surfacing a real Error
            // (operator wants to see 5xx / TLS / transport failure) over
            // a NotFound, since NotFound is the expected "nobody has it"
            // case.
            last_error.or(last_outcome).unwrap_or(FetchResult::NotFound)
        })
    })
    .await
}

/// Tri-state categorisation for one HTTP status code. Pulled out so unit
/// tests can pin the boundary (404 → NotFound vs 401/403/5xx → Error)
/// without spinning a real HTTP server.
fn http_status_to_outcome(status: u16) -> StatusOutcome {
    if (200..300).contains(&status) {
        StatusOutcome::Ok
    } else if status == 404 {
        StatusOutcome::NotFound
    } else {
        StatusOutcome::Error
    }
}

#[derive(Debug, Eq, PartialEq)]
enum StatusOutcome {
    Ok,
    NotFound,
    Error,
}

/// Build the rustls TLS config + endpoint list used for every spegel
/// call. Pure metadata: no cyper `Client` is constructed here because
/// cyper's client is `!Send + !Sync` (Rc-based for compio
/// current_thread). The actual client is built per call in
/// `spegel_fetch` on a blocking thread.
///
/// `Ok(None)` is returned when the mirror is disabled by config or any
/// of the configured cert files don't exist on disk — both map to
/// "skip the spegel-pull path" rather than an error, so a host without
/// an embedded spegel mirror runs the same as it did before.
fn build_spegel_client(cfg: &SpegelMirrorConfig) -> Result<Option<SpegelClient>> {
    if !cfg.enable {
        return Ok(None);
    }
    for path in [&cfg.ca_path, &cfg.client_cert_path, &cfg.client_key_path] {
        if !path.is_file() {
            debug!(
                ca = %cfg.ca_path.display(),
                cert = %cfg.client_cert_path.display(),
                key = %cfg.client_key_path.display(),
                missing = %path.display(),
                "spegel cert file missing; mirror client disabled"
            );
            return Ok(None);
        }
    }

    // 1. Custom root CA (the k3s server CA — system trust store is not
    //    used; the only thing we authenticate against is the embedded
    //    spegel + peer mirrors signed by this CA).
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = BufReader::new(
        File::open(&cfg.ca_path)
            .with_context(|| format!("open spegel CA cert {}", cfg.ca_path.display()))?,
    );
    let mut ca_added = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert =
            cert.with_context(|| format!("parse spegel CA cert {}", cfg.ca_path.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("add spegel CA to root store {}", cfg.ca_path.display()))?;
        ca_added += 1;
    }
    if ca_added == 0 {
        return Err(anyhow!(
            "no CA certificates found in {}",
            cfg.ca_path.display()
        ));
    }

    // 2. Client identity for mTLS (k3s controller cert + key — same
    //    identity k3s' own internal components use).
    let mut cert_reader =
        BufReader::new(File::open(&cfg.client_cert_path).with_context(|| {
            format!("open spegel client cert {}", cfg.client_cert_path.display())
        })?);
    let client_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<_, _>>()
            .with_context(|| {
                format!(
                    "parse spegel client cert {}",
                    cfg.client_cert_path.display()
                )
            })?;
    if client_certs.is_empty() {
        return Err(anyhow!(
            "no client certificates found in {}",
            cfg.client_cert_path.display()
        ));
    }

    let mut key_reader =
        BufReader::new(File::open(&cfg.client_key_path).with_context(|| {
            format!("open spegel client key {}", cfg.client_key_path.display())
        })?);
    let client_key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("parse spegel client key {}", cfg.client_key_path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", cfg.client_key_path.display()))?;

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .context("build rustls ClientConfig for spegel mirror")?;

    // Primary endpoint first, then operator-configured peer fallbacks
    // (workaround for libp2p "empty list of address ports" — see
    // `spegel_fetch` for the iteration semantics).
    let mut endpoints = Vec::with_capacity(1 + cfg.peer_endpoints.len());
    endpoints.push(cfg.endpoint.trim_end_matches('/').to_string());
    for peer in &cfg.peer_endpoints {
        let trimmed = peer.trim_end_matches('/').to_string();
        if !trimmed.is_empty() && !endpoints.contains(&trimmed) {
            endpoints.push(trimmed);
        }
    }

    Ok(Some(SpegelClient {
        tls: Arc::new(tls),
        endpoints,
    }))
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
        spegel_config: &SpegelMirrorConfig,
    ) -> Self {
        Self {
            locator: Arc::new(SidecarLocator::new(
                content_store,
                snapshotter_root,
                spegel_config,
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
    use crate::auto_accel_oci::AUTO_ACCEL_INDEX_MEDIATYPE;

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

    /// `http_status_to_outcome` is the critical categorisation that
    /// decides whether spegel's response is a clean "no peer has it"
    /// (silent fallback to overlay) or a real "mirror is broken" signal
    /// that needs operator attention. Pre-spegel-pull, the equivalent
    /// stderr-parsing version of this categorisation was missing and a
    /// busted spegel mTLS would have silently disabled every auto-accel
    /// mount on the node.
    #[test]
    fn http_status_to_outcome_404_is_not_found() {
        assert_eq!(http_status_to_outcome(404), StatusOutcome::NotFound);
    }

    #[test]
    fn http_status_to_outcome_2xx_is_ok() {
        assert_eq!(http_status_to_outcome(200), StatusOutcome::Ok);
        assert_eq!(http_status_to_outcome(204), StatusOutcome::Ok);
        assert_eq!(http_status_to_outcome(299), StatusOutcome::Ok);
    }

    #[test]
    fn http_status_to_outcome_auth_failures_are_registry_error() {
        // 401/403 → spegel mTLS misconfigured, client cert expired, etc.
        // Operator needs the signal — NOT a silent fallback.
        assert_eq!(http_status_to_outcome(401), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(403), StatusOutcome::Error);
    }

    #[test]
    fn http_status_to_outcome_5xx_is_registry_error() {
        // Daemon down, panic, OOM — same operator-needs-to-look story.
        assert_eq!(http_status_to_outcome(500), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(502), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(503), StatusOutcome::Error);
    }

    #[test]
    fn http_status_to_outcome_3xx_is_registry_error() {
        // We don't follow redirects through spegel — a peer that needs to
        // redirect us is a config bug to flag.
        assert_eq!(http_status_to_outcome(301), StatusOutcome::Error);
        assert_eq!(http_status_to_outcome(307), StatusOutcome::Error);
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
    /// consumer uses when stamping labels on a spegel-pulled blob. Keep
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
}
