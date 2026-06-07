// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Low-priority background node-local zran artifact generation.
//!
//! Triggered by structured prefetch profiles submitted to the sysctl API by the
//! access tracer (after pod-startup settle). The worker dequeues each job and
//! runs `local_accel::convert` to produce a RAFS v6 + zran artifact node-locally,
//! then uploads the artifact (merged bootstrap + per-layer zran indexes +
//! optional prefetch blob + a small auto-accel manifest JSON) into containerd's
//! content store with labels linking it to the original image manifest. Spegel
//! mirrors the artifact to peer nodes; subsequent pods of the same image on any
//! node get a fanotify-served mount of the converted bootstrap on top of the
//! original, unchanged gzip layers — no tag change, no sha256 churn.

use crate::access_tracer::AccessTracer;
use crate::config::{AutoZranConfig, ContainerdConfig, SchedClass as ConfigSchedClass};
use crate::containerd_lookup::ContainerdLookup;
use crate::content_store::ContentStoreClient;
use crate::local_accel::{self, LocalAccelConfig, SchedClass as AccelSchedClass};
use crate::prefetch_profile::PrefetchProfile;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_channel::{Receiver, Sender};
use tracing::{debug, info, warn};

/// Auto-accel sidecar manifest written into containerd's content store
/// alongside the bootstrap + zran index + prefetch blobs. The whole JSON is
/// itself a content blob (so spegel mirrors it), and we register it under
/// the well-known ref `nydus-auto-accel:v1:<subject_manifest_digest>` so
/// peer nodes can discover it without enumerating labels.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutoAccelManifest {
    pub version: u32,
    /// Original image manifest digest (the GC subject).
    pub subject_manifest_digest: String,
    /// Human-readable image ref hint (NOT load-bearing).
    pub image_ref: String,
    pub bootstrap: AutoAccelDescriptor,
    /// Per-layer zran index blobs (same order as the original gzip layers).
    pub zran_indexes: Vec<AutoAccelLayerDescriptor>,
    /// Optional packed prefetch blob (only set when convert had prefetch_files).
    pub prefetch_blob: Option<AutoAccelDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutoAccelDescriptor {
    pub digest: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutoAccelLayerDescriptor {
    /// Original gzip layer digest (== nydus zran data blob id).
    pub layer_digest: String,
    pub digest: String,
    pub size: u64,
}

// OCI image-manifest types + assembly helper now live in
// `crate::auto_accel_oci`. The producer and consumer share that module
// for a single wire-schema definition. Re-export the constants the
// producer below references so the rest of this file stays terse.
pub use crate::auto_accel_oci::{
    AUTO_ACCEL_BOOTSTRAP_MEDIATYPE, AUTO_ACCEL_CONFIG_MEDIATYPE, AUTO_ACCEL_INDEX_MEDIATYPE,
    AUTO_ACCEL_LAYER_DIGEST_ANNOTATION, AUTO_ACCEL_PREFETCH_MEDIATYPE,
    AUTO_ACCEL_SUBJECT_ANNOTATION, OCI_MANIFEST_MEDIATYPE, OciDescriptor, OciImageManifest,
    OciManifestInputs, build_oci_manifest,
};

/// Dependencies that the conversion worker needs in addition to the static
/// `AutoZranConfig`. Bundled so the manager's `start()` signature stays
/// terse and the worker_loop can take a single Arc.
#[derive(Clone)]
pub struct ConversionDeps {
    pub content_store: ContentStoreClient,
    pub containerd: ContainerdConfig,
    pub containerd_lookup: Arc<ContainerdLookup>,
    pub access_tracer: Arc<AccessTracer>,
}

/// Conversion job persisted in memory while waiting for the worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoZranJob {
    pub image: String,
    pub prefetch_files: Vec<String>,
}

impl AutoZranJob {
    pub fn from_profile(profile: &PrefetchProfile) -> Option<Self> {
        let prefetch_files = profile.prefetch_files();
        (!prefetch_files.is_empty()).then(|| Self {
            image: profile.image.clone(),
            prefetch_files,
        })
    }
}

/// Snapshot of auto-zran worker state for sysctl and Prometheus exposition.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoZranStatus {
    pub enabled: bool,
    pub queue_depth: usize,
    pub known_jobs: usize,
    pub running_jobs: u64,
    pub queued_total: u64,
    pub dropped_total: u64,
    pub skipped_total: u64,
    pub started_total: u64,
    pub succeeded_total: u64,
    pub failed_total: u64,
    pub active_image: Option<String>,
}

impl AutoZranStatus {
    pub fn disabled() -> Self {
        Self::default()
    }
}

#[derive(Default)]
struct AutoZranMetrics {
    queued_total: AtomicU64,
    dropped_total: AtomicU64,
    skipped_total: AtomicU64,
    started_total: AtomicU64,
    succeeded_total: AtomicU64,
    failed_total: AtomicU64,
    running_jobs: AtomicU64,
}

struct AutoZranState {
    queue_depth: usize,
    queued_or_done: Mutex<HashSet<String>>,
    active_image: Mutex<Option<String>>,
    metrics: AutoZranMetrics,
}

impl AutoZranState {
    fn new(queue_depth: usize) -> Self {
        Self {
            queue_depth,
            queued_or_done: Mutex::new(HashSet::new()),
            active_image: Mutex::new(None),
            metrics: AutoZranMetrics::default(),
        }
    }

    fn mark_started(&self, job: &AutoZranJob) {
        self.metrics.started_total.fetch_add(1, Ordering::Relaxed);
        self.metrics.running_jobs.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut active) = self.active_image.lock() {
            *active = Some(job.image.clone());
        }
    }

    fn mark_finished(&self, job: &AutoZranJob, success: bool) {
        self.metrics.running_jobs.fetch_sub(1, Ordering::Relaxed);
        if success {
            self.metrics.succeeded_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.failed_total.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut seen) = self.queued_or_done.lock() {
                seen.remove(&job_key(&job.image));
            }
        }
        if let Ok(mut active) = self.active_image.lock()
            && active.as_deref() == Some(job.image.as_str())
        {
            *active = None;
        }
    }

    fn status(&self) -> AutoZranStatus {
        AutoZranStatus {
            enabled: true,
            queue_depth: self.queue_depth,
            known_jobs: self
                .queued_or_done
                .lock()
                .map(|seen| seen.len())
                .unwrap_or_default(),
            running_jobs: self.metrics.running_jobs.load(Ordering::Relaxed),
            queued_total: self.metrics.queued_total.load(Ordering::Relaxed),
            dropped_total: self.metrics.dropped_total.load(Ordering::Relaxed),
            skipped_total: self.metrics.skipped_total.load(Ordering::Relaxed),
            started_total: self.metrics.started_total.load(Ordering::Relaxed),
            succeeded_total: self.metrics.succeeded_total.load(Ordering::Relaxed),
            failed_total: self.metrics.failed_total.load(Ordering::Relaxed),
            active_image: self
                .active_image
                .lock()
                .ok()
                .and_then(|active| active.clone()),
        }
    }
}

/// Queue manager for the single background zran conversion worker.
pub struct AutoZranManager {
    sender: Sender<AutoZranJob>,
    state: Arc<AutoZranState>,
}

impl AutoZranManager {
    /// Start the manager when configured. Returns `None` when auto-zran is
    /// disabled so callers can keep the fast path branch-free.
    pub fn start(config: &AutoZranConfig, deps: ConversionDeps) -> Option<Arc<Self>> {
        if !config.enable {
            return None;
        }

        let depth = config.queue_depth.max(1);
        let (sender, receiver) = async_channel::bounded(depth);
        let state = Arc::new(AutoZranState::new(depth));
        let manager = Arc::new(Self {
            sender,
            state: state.clone(),
        });
        let worker_config = config.clone();
        let worker_deps = deps;
        compio::runtime::spawn(async move {
            worker_loop(worker_config, worker_deps, receiver, state).await
        })
        .detach();
        info!(queue_depth = depth, "auto-zran worker started");
        Some(manager)
    }

    pub fn status(&self) -> AutoZranStatus {
        self.state.status()
    }

    /// Try to enqueue a profile without blocking the sysctl request path.
    pub fn try_enqueue_profile(&self, profile: &PrefetchProfile) {
        let Some(job) = AutoZranJob::from_profile(profile) else {
            self.state
                .metrics
                .skipped_total
                .fetch_add(1, Ordering::Relaxed);
            debug!(image = %profile.image, "auto-zran skipped empty prefetch profile");
            return;
        };

        let key = job_key(&job.image);
        match self.state.queued_or_done.lock() {
            Ok(mut seen) => {
                if !seen.insert(key.clone()) {
                    self.state
                        .metrics
                        .skipped_total
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(image = %job.image, "auto-zran job already queued");
                    return;
                }
            }
            Err(_) => {
                self.state
                    .metrics
                    .dropped_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!(image = %job.image, "auto-zran dedupe set lock poisoned; dropping job");
                return;
            }
        }

        if let Err(e) = self.sender.try_send(job) {
            self.state
                .metrics
                .dropped_total
                .fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "auto-zran queue is full or closed; dropping profile");
            if let Ok(mut seen) = self.state.queued_or_done.lock() {
                seen.remove(&key);
            }
        } else {
            self.state
                .metrics
                .queued_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn worker_loop(
    config: AutoZranConfig,
    deps: ConversionDeps,
    receiver: Receiver<AutoZranJob>,
    state: Arc<AutoZranState>,
) {
    while let Ok(job) = receiver.recv().await {
        state.mark_started(&job);
        let result = run_conversion(&config, &deps, &job).await;
        let success = result.is_ok();
        state.mark_finished(&job, success);
        if let Err(e) = result {
            warn!(image = %job.image, error = ?e, "auto-zran conversion failed");
        }
    }
}

/// Map our config-side scheduling enum to the local_accel-side one.
/// (Two enums exist because `SchedClass` was originally lower-level in
/// `local_accel`; the config-side enum is the public-facing one.)
fn map_sched(class: ConfigSchedClass) -> AccelSchedClass {
    match class {
        ConfigSchedClass::Idle => AccelSchedClass::Idle,
        ConfigSchedClass::Normal => AccelSchedClass::Normal,
    }
}

/// Drive a single conversion job end-to-end:
/// 1. Resolve the manifest digest + ordered gzip-layer paths via
///    `ContainerdLookup::manifest_info`.
/// 2. Skip if a sidecar for this manifest is already in the content store
///    (idempotent across racing pods on the same node).
/// 3. Run `local_accel::convert(cfg, layers, prefetch_files)` on a blocking
///    thread (CPU-bound; mustn't tie up the compio runtime).
/// 4. Upload bootstrap + zran indexes + (optional) prefetch blob via the
///    content_store client with `containerd.io/gc.ref.content.subject` +
///    auto-accel role labels.
/// 5. Build and upload the small auto-accel manifest JSON; register under the
///    deterministic ref `nydus-auto-accel:v1:<subject_manifest_digest>`.
/// 6. Tell the access tracer to stop capturing for this image and clean up
///    the per-image work_dir.
async fn run_conversion(
    config: &AutoZranConfig,
    deps: &ConversionDeps,
    job: &AutoZranJob,
) -> Result<()> {
    // (1) Resolve manifest + layers.
    let info = deps
        .containerd_lookup
        .manifest_info(&job.image, &deps.containerd.content_root)
        .with_context(|| format!("resolve manifest for {}", job.image))?;
    let manifest_digest = info.manifest_digest.clone();
    info!(
        image = %job.image,
        manifest = %manifest_digest,
        layers = info.layers.len(),
        prefetch_files = job.prefetch_files.len(),
        "auto-zran starting conversion"
    );

    // (2) Skip if already done — AND every referenced blob is still
    // present. The old version checked `info(auto_accel_manifest_ref)`,
    // but `info()` takes a digest not a ref, so the call always
    // returned NotFound and the skip path was dead code (every run
    // re-converted). The new check uses `images_get(synthetic_ref)` and
    // round-trips each referenced descriptor through `info()` so we
    // detect half-uploaded sidecars (snapshotter killed mid-write, GC
    // raced) rather than mark-accelerated-then-fail-to-mount.
    let image_name = auto_accel_image_name(&manifest_digest);
    match deps.content_store.images_get(&image_name).await {
        Ok(Some(existing)) => match completeness_check(deps, &existing.digest).await {
            Ok(true) => {
                info!(
                    image = %job.image,
                    image_name = %image_name,
                    manifest_digest = %existing.digest,
                    "auto-accel sidecar already present and complete; skipping conversion"
                );
                deps.access_tracer.mark_image_accelerated(&job.image);
                return Ok(());
            }
            Ok(false) => {
                warn!(
                    image = %job.image,
                    image_name = %image_name,
                    "auto-accel sidecar is present but some referenced blobs are missing; re-converting"
                );
            }
            Err(e) => {
                warn!(
                    image = %job.image,
                    error = ?e,
                    "auto-accel sidecar completeness check failed; re-converting to be safe"
                );
            }
        },
        Ok(None) => { /* no record yet — proceed with conversion */ }
        Err(e) => {
            warn!(
                image = %job.image,
                error = ?e,
                "auto-accel images.Get failed; proceeding with conversion"
            );
        }
    }

    // (3) Convert on a blocking thread.
    let work_dir = job_work_dir(config, &job.image);
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create work dir {}", work_dir.display()))?;
    let local_cfg = LocalAccelConfig {
        nydus_image: config.nydus_image.clone(),
        work_dir: work_dir.clone(),
        sched: map_sched(config.sched_class),
        nice: config.nice,
    };
    let layers = info.layers;
    let prefetch_files = job.prefetch_files.clone();
    let artifact =
        blocking::unblock(move || local_accel::convert(&local_cfg, &layers, &prefetch_files))
            .await
            .context("local_accel::convert failed")?;

    // (4) Upload artifacts. Labels:
    //   - gc.ref.content.subject  pins lifetime to the original manifest
    //   - nydus.auto-accel.role   identifies bootstrap / index / prefetch-blob
    //   - nydus.auto-accel.layer-digest (index/prefetch only) links to the
    //     original gzip layer the blob accelerates
    let subject = manifest_digest.clone();
    let base_labels = |role: &str| -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "containerd.io/gc.ref.content.subject".to_string(),
            subject.clone(),
        );
        m.insert(
            "containerd.io/snapshot/nydus.auto-accel.role".to_string(),
            role.to_string(),
        );
        m
    };

    let bootstrap_meta = std::fs::metadata(&artifact.bootstrap)
        .with_context(|| format!("stat bootstrap {}", artifact.bootstrap.display()))?;
    let bootstrap_digest = deps
        .content_store
        .write_blob(&artifact.bootstrap, base_labels("bootstrap"))
        .await
        .context("upload bootstrap")?;

    let mut zran_descriptors = Vec::with_capacity(artifact.zran_index_blob_ids.len());
    for (i, blob_id) in artifact.zran_index_blob_ids.iter().enumerate() {
        let layer_digest = artifact
            .layer_blob_ids
            .get(i)
            .map(|id| {
                if id.starts_with("sha256:") {
                    id.clone()
                } else {
                    format!("sha256:{id}")
                }
            })
            .unwrap_or_default();
        let path = artifact.backend_dir.join(blob_id);
        let size = std::fs::metadata(&path)
            .with_context(|| format!("stat zran index {}", path.display()))?
            .len();
        let mut labels = base_labels("index");
        labels.insert(
            "containerd.io/snapshot/nydus.auto-accel.layer-digest".to_string(),
            layer_digest.clone(),
        );
        let digest = deps
            .content_store
            .write_blob(&path, labels)
            .await
            .with_context(|| format!("upload zran index for layer {layer_digest}"))?;
        zran_descriptors.push(AutoAccelLayerDescriptor {
            layer_digest,
            digest,
            size,
        });
    }

    let prefetch_descriptor = if let Some(prefetch_id) = &artifact.prefetch_blob_id {
        let path = artifact.backend_dir.join(prefetch_id);
        let size = std::fs::metadata(&path)
            .with_context(|| format!("stat prefetch blob {}", path.display()))?
            .len();
        let digest = deps
            .content_store
            .write_blob(&path, base_labels("prefetch-blob"))
            .await
            .context("upload prefetch blob")?;
        Some(AutoAccelDescriptor { digest, size })
    } else {
        None
    };

    // (5) AutoAccelManifest goes up as the OCI image *config* blob.
    let manifest = AutoAccelManifest {
        version: 1,
        subject_manifest_digest: manifest_digest.clone(),
        image_ref: job.image.clone(),
        bootstrap: AutoAccelDescriptor {
            digest: bootstrap_digest.clone(),
            size: bootstrap_meta.len(),
        },
        zran_indexes: zran_descriptors.clone(),
        prefetch_blob: prefetch_descriptor.clone(),
    };
    let config_bytes = serde_json::to_vec(&manifest).context("serialize auto-accel config")?;
    // The ingest-time ref is just a label for the streaming Write; after
    // commit the blob is addressed by its content digest. Use a
    // distinguishable string so half-uploaded sidecars are debuggable
    // (`ctr -n k8s.io content ls` shows the ingest ref).
    let config_ingest_ref = format!("nydus-auto-accel-config:v1:{manifest_digest}");
    let config_digest = deps
        .content_store
        .write_bytes(&config_bytes, &config_ingest_ref, base_labels("config"))
        .await
        .context("upload auto-accel config")?;

    // (5a) Wrap the config + data blobs as a real OCI image manifest so
    // `ctr image pull <synthetic-ref>` pulls everything in one go via the
    // registries.yaml mirror chain (spegel). The assembly is in
    // `auto_accel_oci::build_oci_manifest` so the consumer parses the
    // exact same wire schema and the unit tests cover this code path
    // without an in-flight conversion.
    let bootstrap_descriptor = AutoAccelDescriptor {
        digest: bootstrap_digest.clone(),
        size: bootstrap_meta.len(),
    };
    let oci_manifest = build_oci_manifest(&OciManifestInputs {
        subject_manifest_digest: &manifest_digest,
        config_digest: &config_digest,
        config_size: config_bytes.len() as u64,
        bootstrap: &bootstrap_descriptor,
        zran_indexes: &zran_descriptors,
        prefetch_blob: prefetch_descriptor.as_ref(),
    });
    let manifest_bytes =
        serde_json::to_vec(&oci_manifest).context("serialize auto-accel oci manifest")?;
    let manifest_oci_ref = format!("nydus-auto-accel-oci:v1:{manifest_digest}");
    let manifest_digest_in_store = deps
        .content_store
        .write_bytes(&manifest_bytes, &manifest_oci_ref, base_labels("manifest"))
        .await
        .context("upload auto-accel oci manifest")?;

    // (5b) Register the containerd Image record at the OCI manifest. spegel
    // watches image records and advertises them to peers via libp2p; a peer
    // doing `ctr image pull <image_name>` resolves through registries.yaml's
    // mirror config → spegel → producer node → all blobs flow through the
    // registry-mirror path in one transfer. Without an Image record the
    // manifest blob sits in the content store but spegel has no name to
    // publish.
    let mut image_labels = base_labels("manifest");
    image_labels.insert(
        "containerd.io/snapshot/nydus.auto-accel.subject-image".to_string(),
        job.image.clone(),
    );
    let image_record_ok = match deps
        .content_store
        .images_create(
            &image_name,
            &manifest_digest_in_store,
            manifest_bytes.len() as u64,
            OCI_MANIFEST_MEDIATYPE,
            image_labels,
        )
        .await
    {
        Ok(_) => true,
        Err(e) => {
            warn!(
                image = %job.image,
                image_name = %image_name,
                error = ?e,
                "auto-zran image-record registration failed (cross-node spegel mirror disabled for this manifest)"
            );
            false
        }
    };

    info!(
        image = %job.image,
        subject = %manifest_digest,
        auto_accel_manifest = %manifest_digest_in_store,
        image_name = %image_name,
        image_record = image_record_ok,
        "auto-zran conversion complete"
    );

    // (6) Tell the tracer to stop capturing + clean up scratch — but
    // ONLY if the cross-node advertisement is also wired. With
    // image_record_ok=false this node would serve the next pod locally
    // via label scan, but peers can never discover it; marking the image
    // accelerated would also stop us from re-attempting the
    // image-record creation on subsequent capture cycles. Keep capture
    // alive so the next conversion retries the registration.
    if image_record_ok {
        deps.access_tracer.mark_image_accelerated(&job.image);
    }
    if let Err(e) = std::fs::remove_dir_all(&work_dir) {
        warn!(
            error = %e,
            work_dir = %work_dir.display(),
            "auto-zran work_dir cleanup failed (non-fatal)"
        );
    }
    Ok(())
}

/// Per-image scratch dir under `auto_zran.work_dir`. We use a sha256 of the
/// image ref so concurrent conversions of different images don't collide.
fn job_work_dir(config: &AutoZranConfig, image: &str) -> std::path::PathBuf {
    config.work_dir.join(job_key(image))
}

/// Verify every descriptor referenced by an OCI sidecar manifest is still
/// in the local content store. Used by the early-skip path in
/// `run_conversion`: a pre-existing Image record is only safe to skip on
/// if `config` + every `layer` blob still exists locally. Otherwise the
/// next pod's discovery will succeed at the manifest level but fail
/// during backend staging (`ensure_present` in auto_accel_sidecar.rs)
/// and degrade to overlay — silently if our log filter happens to miss
/// it. Catches: snapshotter killed mid-upload, containerd GC race after
/// a label-stripping bug, manual `ctr content rm` poking.
async fn completeness_check(deps: &ConversionDeps, manifest_digest: &str) -> Result<bool> {
    let manifest_bytes = match deps.content_store.fetch_bytes(manifest_digest).await {
        Ok(b) => b,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "completeness fetch_bytes({manifest_digest}): {e}"
            ));
        }
    };
    let oci: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse OCI manifest {manifest_digest}"))?;
    let mut descriptors: Vec<String> = Vec::new();
    if let Some(config) = oci
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
    {
        descriptors.push(config.to_string());
    } else {
        return Ok(false);
    }
    if let Some(layers) = oci.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(digest) = layer.get("digest").and_then(|d| d.as_str()) {
                descriptors.push(digest.to_string());
            } else {
                return Ok(false);
            }
        }
    } else {
        return Ok(false);
    }
    for digest in descriptors {
        if deps.content_store.info(&digest).await?.is_none() {
            debug!(missing = %digest, "auto-accel completeness check: blob missing");
            return Ok(false);
        }
    }
    Ok(true)
}

/// Synthetic registry-shaped image name we register the auto-accel manifest
/// under after upload. Containerd's embedded spegel watches image records
/// and advertises them to peers via libp2p; the host part
/// (`nydus.auto-accel.local`) deliberately doesn't resolve to a real
/// registry so the fallback path (when no peer has the manifest) is a
/// clean 404, not a noisy upstream DNS lookup.
///
/// `<bare-hex>` is the hex part of the subject manifest digest so peers can
/// derive this name themselves from the parent chain → original-image
/// manifest digest mapping that already feeds discovery.
pub fn auto_accel_image_name(subject_manifest_digest: &str) -> String {
    let hex = subject_manifest_digest
        .strip_prefix("sha256:")
        .unwrap_or(subject_manifest_digest);
    format!("nydus.auto-accel.local/sidecar:{hex}")
}

fn job_key(image: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nri::AccessProfileRecord;

    fn profile(image: &str) -> PrefetchProfile {
        PrefetchProfile::from_access_records(
            image,
            [AccessProfileRecord {
                container_id: "ctr".to_string(),
                image: image.to_string(),
                path: "/bin/app".to_string(),
                op: "open".to_string(),
                timestamp_unix: 1,
            }],
        )
    }

    #[test]
    fn job_from_profile_keeps_prefetch_order() {
        let profile = profile("registry.local/app:1");
        let job = AutoZranJob::from_profile(&profile).unwrap();
        assert_eq!(job.image, "registry.local/app:1");
        assert_eq!(job.prefetch_files, vec!["/bin/app"]);
    }

    #[test]
    fn state_tracks_started_success_and_failure_lifecycle() {
        let state = AutoZranState::new(8);
        let success_job = AutoZranJob {
            image: "registry.local/success:1".to_string(),
            prefetch_files: vec!["/bin/app".to_string()],
        };
        state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(job_key(&success_job.image));

        state.mark_started(&success_job);
        let status = state.status();
        assert_eq!(status.running_jobs, 1);
        assert_eq!(status.started_total, 1);
        assert_eq!(
            status.active_image.as_deref(),
            Some("registry.local/success:1")
        );

        state.mark_finished(&success_job, true);
        let status = state.status();
        assert_eq!(status.running_jobs, 0);
        assert_eq!(status.succeeded_total, 1);
        assert_eq!(status.failed_total, 0);
        assert_eq!(status.known_jobs, 1);
        assert!(status.active_image.is_none());

        let failed_job = AutoZranJob {
            image: "registry.local/fail:1".to_string(),
            prefetch_files: vec!["/bin/app".to_string()],
        };
        state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(job_key(&failed_job.image));
        state.mark_started(&failed_job);
        state.mark_finished(&failed_job, false);
        let status = state.status();

        assert_eq!(status.running_jobs, 0);
        assert_eq!(status.succeeded_total, 1);
        assert_eq!(status.failed_total, 1);
        assert_eq!(status.known_jobs, 1);
        assert!(status.active_image.is_none());
    }

    #[test]
    fn enqueue_profile_deduplicates_same_image() {
        let (sender, receiver) = async_channel::bounded(2);
        let state = Arc::new(AutoZranState::new(2));
        let manager = AutoZranManager {
            sender,
            state: state.clone(),
        };
        let profile = profile("registry.local/app:1");

        manager.try_enqueue_profile(&profile);
        manager.try_enqueue_profile(&profile);

        let queued = receiver.try_recv().unwrap();
        let status = manager.status();
        assert_eq!(queued.image, "registry.local/app:1");
        assert_eq!(status.queued_total, 1);
        assert_eq!(status.skipped_total, 1);
        assert_eq!(status.dropped_total, 0);
        assert_eq!(status.known_jobs, 1);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn enqueue_profile_drops_when_queue_is_full_and_rolls_back_dedupe_key() {
        let (sender, _receiver) = async_channel::bounded(1);
        let state = Arc::new(AutoZranState::new(1));
        let manager = AutoZranManager {
            sender,
            state: state.clone(),
        };

        manager.try_enqueue_profile(&profile("registry.local/first:1"));
        manager.try_enqueue_profile(&profile("registry.local/second:1"));

        let status = manager.status();
        assert_eq!(status.queued_total, 1);
        assert_eq!(status.dropped_total, 1);
        assert_eq!(status.known_jobs, 1);
        assert!(
            !state
                .queued_or_done
                .lock()
                .unwrap()
                .contains(&job_key("registry.local/second:1"))
        );
    }

    #[test]
    fn enqueue_profile_skips_empty_profiles() {
        let (sender, receiver) = async_channel::bounded(2);
        let state = Arc::new(AutoZranState::new(2));
        let manager = AutoZranManager { sender, state };
        let empty = PrefetchProfile::from_access_records(
            "registry.local/empty:1",
            Vec::<AccessProfileRecord>::new(),
        );

        manager.try_enqueue_profile(&empty);

        let status = manager.status();
        assert_eq!(status.queued_total, 0);
        assert_eq!(status.skipped_total, 1);
        assert_eq!(status.known_jobs, 0);
        assert!(receiver.try_recv().is_err());
    }
}
