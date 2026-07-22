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
use crate::local_accel::{
    self, LocalAccelConfig, NodeLocalArtifact, SchedClass as AccelSchedClass,
};
use crate::prefetch_profile::PrefetchProfile;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// OCI image config sentinel fields. Spegel's `FingerprintMediaType`
    /// only recognises a JSON blob as an OCI image config when the body
    /// contains `architecture`, `os`, AND `rootfs` keys (see
    /// spegel/pkg/oci/oci.go). A blob it can't classify gets served as
    /// 404 from `/v2/blobs` even when it's physically present in
    /// containerd's content store — that broke the cross-node config
    /// fetch with "response status=404 Not Found" while every layer blob
    /// served 200. These three fields are inert (linux/amd64 + empty layer
    /// list) and the only cost is ~30 bytes on the wire.
    ///
    /// Kept UNCONDITIONALLY: Spegel-gossip-specific, but harmless (inert
    /// metadata) to any non-Spegel peer mirror; removing them would break
    /// the Spegel preset's config fetch.
    #[serde(default = "default_oci_architecture")]
    pub architecture: String,
    #[serde(default = "default_oci_os")]
    pub os: String,
    #[serde(default = "default_oci_rootfs")]
    pub rootfs: OciConfigRootfs,
}

/// Minimal OCI image-config `rootfs` shape — exists only to satisfy
/// spegel's `FingerprintMediaType` heuristic. Contents are inert.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct OciConfigRootfs {
    #[serde(rename = "type")]
    pub kind: String,
    pub diff_ids: Vec<String>,
}

fn default_oci_architecture() -> String {
    "amd64".to_string()
}

fn default_oci_os() -> String {
    "linux".to_string()
}

fn default_oci_rootfs() -> OciConfigRootfs {
    OciConfigRootfs {
        kind: "layers".to_string(),
        diff_ids: Vec::new(),
    }
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

/// Which half of the two-stage conversion a job represents.
///
/// Both stages share one per-image on-disk `work_dir` (keyed by `job_key`), so
/// stage 2 can reuse stage 1's create+merge output. They are deduped
/// independently (see [`dedupe_key`]) so a `Base` enqueue at prepare and an
/// `Optimize` enqueue at tracer settle for the same image can both be queued.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AutoZranStage {
    /// create + merge with an EMPTY prefetch list → a fully servable sidecar
    /// (the optimize step is skipped, see `local_accel::convert`). Enqueued
    /// immediately at the first eligible `prepare` so peers can fetch a
    /// sidecar as soon as it lands, long before this pod's tracer settles.
    Base,
    /// The `nydus-image optimize` step (prefetch bootstrap + packed prefetch
    /// blob). Enqueued on tracer settle. Reuses the `Base` stage's on-disk
    /// `work_dir` when present (optimize only); otherwise runs the full
    /// pipeline once WITH prefetch (handles "settle arrived before base").
    Optimize,
}

impl AutoZranStage {
    /// Short, dedupe-key-safe discriminant tag.
    fn tag(self) -> &'static str {
        match self {
            AutoZranStage::Base => "base",
            AutoZranStage::Optimize => "opt",
        }
    }
}

/// Conversion job persisted in memory while waiting for the worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoZranJob {
    pub image: String,
    pub stage: AutoZranStage,
    /// Empty for [`AutoZranStage::Base`]; the captured access profile (in
    /// first-seen order) for [`AutoZranStage::Optimize`].
    pub prefetch_files: Vec<String>,
}

impl AutoZranJob {
    /// A stage-1 base job: empty prefetch, verified servable.
    pub fn base(image: String) -> Self {
        Self {
            image,
            stage: AutoZranStage::Base,
            prefetch_files: Vec::new(),
        }
    }

    /// A stage-2 optimize job from a settled prefetch profile. `None` when the
    /// profile captured no files (nothing to optimize for).
    pub fn from_profile(profile: &PrefetchProfile) -> Option<Self> {
        let prefetch_files = profile.prefetch_files();
        (!prefetch_files.is_empty()).then(|| Self {
            image: profile.image.clone(),
            stage: AutoZranStage::Optimize,
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

/// After this many consecutive conversion failures for one image, stop
/// enqueueing new jobs for it entirely (either stage). The negative cache is
/// memory-only: a snapshotter restart clears it, which is the intended manual
/// escape hatch for images that become convertible again (e.g. after a
/// `nydus-image` upgrade). Without this cap, a deterministically failing image
/// (zstd layers, a broken `nydus-image` binary, …) would re-run the full
/// conversion pipeline at EVERY pod prepare, forever — `try_enqueue_base`
/// fires on each prepare and a failed job releases its dedupe key.
const MAX_CONVERSION_FAILURES: u32 = 3;

/// Spacing between retries before [`MAX_CONVERSION_FAILURES`] is reached;
/// doubles per recorded failure (5m after the first failure, 10m after the
/// second), so transient failures (containerd hiccup, disk pressure) retry
/// soon-ish while a hard-failing image doesn't burn CPU on every pod start.
const FAILURE_BACKOFF_BASE: Duration = Duration::from_secs(5 * 60);

/// Per-image record of consecutive conversion failures (both stages share it:
/// a base failure and an optimize failure both count against the image).
struct ImageFailures {
    count: u32,
    last_failure: Instant,
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
    /// Negative cache: image → consecutive-failure record. Guards BOTH stages'
    /// enqueue paths (see [`MAX_CONVERSION_FAILURES`]). Memory-only by design.
    failures: Mutex<HashMap<String, ImageFailures>>,
    /// image ref → the manifest digest we last saw it resolve to. All other
    /// per-image state (`queued_or_done`, `failures`) is keyed by *ref*, so a
    /// tag repointed to new content would stay deduped/suppressed forever;
    /// [`AutoZranManager::note_sidecar_missing`] uses this map to detect the
    /// repoint and clear the stale state.
    last_manifest: Mutex<HashMap<String, String>>,
    metrics: AutoZranMetrics,
}

impl AutoZranState {
    fn new(queue_depth: usize) -> Self {
        Self {
            queue_depth,
            queued_or_done: Mutex::new(HashSet::new()),
            active_image: Mutex::new(None),
            failures: Mutex::new(HashMap::new()),
            last_manifest: Mutex::new(HashMap::new()),
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
            // Any successful stage resets the negative cache for the image.
            if let Ok(mut failures) = self.failures.lock() {
                failures.remove(&job.image);
            }
        } else {
            self.metrics.failed_total.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut seen) = self.queued_or_done.lock() {
                seen.remove(&dedupe_key(&job.image, job.stage));
            }
            self.record_failure(&job.image);
        }
        if let Ok(mut active) = self.active_image.lock()
            && active.as_deref() == Some(job.image.as_str())
        {
            *active = None;
        }
    }

    /// Bump the per-image consecutive-failure count. Logs at warn exactly once
    /// when the count crosses [`MAX_CONVERSION_FAILURES`]; subsequent
    /// suppressed enqueues only log at debug.
    fn record_failure(&self, image: &str) {
        let Ok(mut failures) = self.failures.lock() else {
            return;
        };
        let record = failures.entry(image.to_string()).or_insert(ImageFailures {
            count: 0,
            last_failure: Instant::now(),
        });
        record.count = record.count.saturating_add(1);
        record.last_failure = Instant::now();
        if record.count == MAX_CONVERSION_FAILURES {
            warn!(
                image = %image,
                failures = record.count,
                "auto-zran conversion keeps failing; image marked non-convertible until snapshotter restart"
            );
        }
    }

    /// Whether an enqueue for `image` is suppressed by the failure negative
    /// cache: permanently once [`MAX_CONVERSION_FAILURES`] is reached, or
    /// temporarily while inside the exponential backoff window between
    /// earlier failures. `now` is injected for testability.
    fn enqueue_suppressed(&self, image: &str, now: Instant) -> bool {
        let Ok(failures) = self.failures.lock() else {
            return false;
        };
        let Some(record) = failures.get(image) else {
            return false;
        };
        if record.count >= MAX_CONVERSION_FAILURES {
            return true;
        }
        let window = FAILURE_BACKOFF_BASE * 2u32.saturating_pow(record.count.saturating_sub(1));
        now.saturating_duration_since(record.last_failure) < window
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

    /// Directory-safe key of the job the (single) worker is currently converting,
    /// if any. The reconciler's stale-job-dir sweep (`recon::check_stale_autozran_dirs`)
    /// excludes this key so it never races the live worker: a long conversion's job
    /// dir can go a while without its own mtime changing (the worker writes into
    /// nested subdirs, which doesn't bump the parent's mtime), so mtime age alone
    /// isn't sufficient proof that a directory is abandoned.
    pub fn active_job_key(&self) -> Option<String> {
        self.state
            .active_image
            .lock()
            .ok()
            .and_then(|active| active.clone())
            .map(|image| job_key(&image))
    }

    /// Enqueue the stage-1 BASE conversion for `image` without blocking the
    /// caller (the gRPC `prepare` path). Non-blocking channel push; deduped by
    /// the base job key so repeated prepares of the same image enqueue at most
    /// one base job. A no-op (dropped, counted) when the queue is full.
    pub fn try_enqueue_base(&self, image: &str) {
        self.enqueue(AutoZranJob::base(image.to_string()));
    }

    /// Record that a `prepare` for `image` resolved to `manifest_digest` and
    /// found no sidecar. Returns `true` when this reveals a **tag repoint**
    /// (the ref previously resolved to different content): in that case the
    /// per-ref dedupe keys and failure backoff are cleared so the new content
    /// can be converted, instead of staying suppressed until a snapshotter
    /// restart. The caller should also clear the access tracer's skip entry.
    pub fn note_sidecar_missing(&self, image: &str, manifest_digest: &str) -> bool {
        let mut last = match self.state.last_manifest.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match last.insert(image.to_string(), manifest_digest.to_string()) {
            Some(prev) if prev != manifest_digest => {
                drop(last);
                info!(
                    image,
                    previous = %prev,
                    current = %manifest_digest,
                    "auto-zran: tag repointed to new content; clearing stale conversion state"
                );
                if let Ok(mut seen) = self.state.queued_or_done.lock() {
                    seen.remove(&dedupe_key(image, AutoZranStage::Base));
                    seen.remove(&dedupe_key(image, AutoZranStage::Optimize));
                }
                if let Ok(mut failures) = self.state.failures.lock() {
                    failures.remove(image);
                }
                true
            }
            _ => false,
        }
    }

    /// Enqueue the stage-2 OPTIMIZE conversion from a settled prefetch profile
    /// without blocking the sysctl request path. Deduped independently of the
    /// base stage, so this queues even when a base job for the same image is
    /// already queued/done.
    pub fn try_enqueue_profile(&self, profile: &PrefetchProfile) {
        let Some(job) = AutoZranJob::from_profile(profile) else {
            self.state
                .metrics
                .skipped_total
                .fetch_add(1, Ordering::Relaxed);
            debug!(image = %profile.image, "auto-zran skipped empty prefetch profile");
            return;
        };
        self.enqueue(job);
    }

    /// Shared, non-blocking enqueue path for both stages. Consults the
    /// per-image failure negative cache first (see
    /// [`MAX_CONVERSION_FAILURES`]), then dedupes on `(image, stage)` via
    /// `queued_or_done`, then `try_send`s onto the bounded channel, rolling
    /// the dedupe key back if the send fails so the job can be retried later.
    fn enqueue(&self, job: AutoZranJob) {
        if self.state.enqueue_suppressed(&job.image, Instant::now()) {
            self.state
                .metrics
                .skipped_total
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                image = %job.image,
                stage = job.stage.tag(),
                "auto-zran enqueue suppressed by failure backoff"
            );
            return;
        }
        let key = dedupe_key(&job.image, job.stage);
        match self.state.queued_or_done.lock() {
            Ok(mut seen) => {
                if !seen.insert(key.clone()) {
                    self.state
                        .metrics
                        .skipped_total
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(image = %job.image, stage = job.stage.tag(), "auto-zran job already queued");
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

        let image = job.image.clone();
        let stage = job.stage;
        if let Err(e) = self.sender.try_send(job) {
            self.state
                .metrics
                .dropped_total
                .fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, image = %image, stage = stage.tag(), "auto-zran queue is full or closed; dropping job");
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

/// Which servable form of a sidecar already exists in the content store for a
/// given subject manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SidecarState {
    /// No complete sidecar (absent, or present-but-missing-blobs → re-convert).
    Absent,
    /// A complete BASE sidecar (no prefetch blob): servable, upgradeable.
    Base,
    /// A complete OPTIMIZED sidecar (has a packed prefetch blob).
    Optimized,
}

/// Dispatch a job to its stage. Shared prologue: resolve the manifest + layers
/// and probe the existing sidecar state once, then hand off.
///
/// Ordering-race handling (both are correct):
/// * settle AFTER base done — the base job left `work_dir` + `artifact.json` on
///   disk, so the optimize stage runs ONLY `nydus-image optimize`.
/// * settle BEFORE base done — no base output on disk, so the optimize stage
///   runs the full pipeline once WITH prefetch (the profile is never lost).
async fn run_conversion(
    config: &AutoZranConfig,
    deps: &ConversionDeps,
    job: &AutoZranJob,
) -> Result<()> {
    // (1) Resolve manifest + layers.
    let info = deps
        .containerd_lookup
        .manifest_info(&job.image, &deps.containerd.content_root())
        .await
        .with_context(|| format!("resolve manifest for {}", job.image))?;
    let manifest_digest = info.manifest_digest.clone();
    let image_name = auto_accel_image_name(&manifest_digest);
    info!(
        image = %job.image,
        stage = job.stage.tag(),
        manifest = %manifest_digest,
        layers = info.layers.len(),
        prefetch_files = job.prefetch_files.len(),
        "auto-zran starting conversion"
    );

    // Probe whether a sidecar already exists (and, if so, whether it is
    // already optimized). Half-uploaded sidecars (snapshotter killed
    // mid-write, GC raced) read back as `Absent` so we re-convert rather
    // than mark-accelerated-then-fail-to-mount.
    let (existing, existing_manifest) = existing_sidecar_state(deps, &image_name).await;

    match job.stage {
        AutoZranStage::Base => {
            run_base_stage(
                config,
                deps,
                job,
                info.layers,
                &manifest_digest,
                &image_name,
                existing,
            )
            .await
        }
        AutoZranStage::Optimize => {
            run_optimize_stage(
                config,
                deps,
                job,
                info.layers,
                &manifest_digest,
                &image_name,
                existing,
                existing_manifest,
            )
            .await
        }
    }
}

/// Stage 1: create + merge with an EMPTY prefetch list → a fully servable base
/// sidecar. Uploads it, then RETAINS the work dir (and a serialized
/// `artifact.json`) so the optimize stage can reuse the create+merge output.
/// Deliberately does NOT mark the image accelerated: the access tracer must
/// keep capturing to drive stage 2.
#[allow(clippy::too_many_arguments)]
async fn run_base_stage(
    config: &AutoZranConfig,
    deps: &ConversionDeps,
    job: &AutoZranJob,
    layers: Vec<local_accel::GzipLayer>,
    manifest_digest: &str,
    image_name: &str,
    existing: SidecarState,
) -> Result<()> {
    if existing != SidecarState::Absent {
        // A base or optimized sidecar already exists — base is redundant.
        // Do NOT mark accelerated: leave the tracer capturing so the optimize
        // stage still fires (it will skip if already optimized).
        info!(image = %job.image, ?existing, "auto-zran base skip: sidecar already present");
        return Ok(());
    }

    let work_dir = job_work_dir(config, &job.image);
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create work dir {}", work_dir.display()))?;
    let local_cfg = local_accel_config(config, &work_dir);
    let artifact = blocking::unblock(move || local_accel::convert(&local_cfg, &layers, &[]))
        .await
        .context("local_accel::convert (base) failed")?;

    // Persist the base artifact so stage 2 can reuse it. Non-fatal on failure:
    // stage 2 falls back to the full pipeline when it can't reload the base.
    if let Err(e) = write_base_artifact(&work_dir, &artifact) {
        warn!(image = %job.image, error = ?e, "auto-zran failed to persist base artifact; optimize will re-run the full pipeline");
    }

    upload_artifact(deps, job, manifest_digest, image_name, &artifact, None).await?;

    // IMPORTANT: do NOT mark accelerated and do NOT remove work_dir — the
    // tracer keeps capturing, and stage 2 reuses this work_dir. A pod that
    // dies before settle leaves the dir for the recon stale-dir sweep.
    info!(image = %job.image, "auto-zran base conversion complete; work dir retained for optimize");
    Ok(())
}

/// Stage 2: run the `nydus-image optimize` step and re-upload the (now
/// optimized) sidecar, promoting the Image record from the base manifest to the
/// optimized one. Reuses stage 1's on-disk work dir when present (optimize
/// only); otherwise runs the full pipeline once WITH prefetch.
///
/// Known limitation (wedge-at-Base): this stage has exactly two drivers — the
/// access tracer's settle and the NRI `StopContainer` force-settle. If the
/// first pod dies before either fires, or the (single) settle-driven optimize
/// upload fails past the failure backoff, the image keeps serving the BASE
/// sidecar until the snapshotter restarts. Accepted: Base already beats plain
/// overlay, and a future recon-driven re-optimize trigger is tracked in
/// BACKLOG.md ("Two-stage auto-accel: re-optimize trigger for images stuck at
/// Base").
#[allow(clippy::too_many_arguments)]
async fn run_optimize_stage(
    config: &AutoZranConfig,
    deps: &ConversionDeps,
    job: &AutoZranJob,
    layers: Vec<local_accel::GzipLayer>,
    manifest_digest: &str,
    image_name: &str,
    existing: SidecarState,
    existing_manifest: Option<String>,
) -> Result<()> {
    if existing == SidecarState::Optimized {
        // A peer's (or an earlier local) optimize won the race; this node's
        // freshly captured profile is discarded — intentional: the first
        // settled profile wins, re-optimization is a BACKLOG item.
        info!(image = %job.image, "auto-zran optimize skip: sidecar already optimized");
        deps.access_tracer.mark_image_accelerated(&job.image);
        cleanup_work_dir(config, &job.image);
        return Ok(());
    }

    let work_dir = job_work_dir(config, &job.image);
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create work dir {}", work_dir.display()))?;
    let local_cfg = local_accel_config(config, &work_dir);
    let prefetch_files = job.prefetch_files.clone();

    let artifact = if let Some(base) = load_reusable_base_artifact(&work_dir) {
        if base.prefetch_blob_id.is_some() {
            // A prior optimize run already rewrote the merged bootstrap in
            // place and persisted the optimized artifact.json, but its upload
            // failed. Re-running `nydus-image optimize` against the
            // already-optimized bootstrap would be wrong, so go straight to
            // the (re-)upload with the persisted artifact.
            info!(image = %job.image, "auto-zran optimize: reusing already-optimized artifact (upload retry)");
            base
        } else {
            // Stage 1 output is on disk: run ONLY optimize (create/merge
            // skipped).
            info!(image = %job.image, "auto-zran optimize: reusing base work dir (create/merge skipped)");
            let optimized = blocking::unblock(move || {
                local_accel::optimize_existing(&local_cfg, &base, &prefetch_files)
            })
            .await
            .context("local_accel::optimize_existing failed")?;
            // `optimize_existing` replaced the merged bootstrap IN PLACE, so
            // persist the optimized artifact BEFORE the upload: if the upload
            // fails and the job is retried, artifact.json would otherwise
            // still claim `prefetch_blob_id: None` and the retry would
            // re-optimize an already-optimized bootstrap.
            if let Err(e) = write_base_artifact(&work_dir, &optimized) {
                warn!(image = %job.image, error = ?e, "auto-zran failed to persist optimized artifact; an upload-failure retry may re-optimize");
            }
            optimized
        }
    } else {
        // No reusable base (settle beat base, or the dir was swept): run the
        // full pipeline once WITH prefetch so the captured profile isn't lost.
        info!(image = %job.image, "auto-zran optimize: no reusable base work dir; running full pipeline with prefetch");
        blocking::unblock(move || local_accel::convert(&local_cfg, &layers, &prefetch_files))
            .await
            .context("local_accel::convert (optimize full) failed")?
    };

    // When a BASE sidecar record existed pre-promotion, pin its manifest tree
    // from the optimized manifest so a peer mid-pull of the base sidecar can't
    // have its blobs GC'd out from under it (see `manifest_gc_labels`).
    let base_manifest = (existing == SidecarState::Base)
        .then_some(existing_manifest)
        .flatten();
    let image_record_ok = upload_artifact(
        deps,
        job,
        manifest_digest,
        image_name,
        &artifact,
        base_manifest.as_deref(),
    )
    .await?;

    // Tell the tracer to stop capturing ONLY when the cross-node advertisement
    // is also wired (mirrors the original single-stage invariant): with
    // image_record_ok=false peers can never discover the sidecar, so keep
    // capture alive to retry the registration on a later cycle.
    if image_record_ok {
        deps.access_tracer.mark_image_accelerated(&job.image);
    }
    cleanup_work_dir(config, &job.image);
    Ok(())
}

/// Build a `LocalAccelConfig` for a job's per-image `work_dir`.
fn local_accel_config(config: &AutoZranConfig, work_dir: &Path) -> LocalAccelConfig {
    LocalAccelConfig {
        nydus_image: config.nydus_image.clone(),
        work_dir: work_dir.to_path_buf(),
        sched: map_sched(config.sched_class),
        nice: config.nice,
    }
}

/// Best-effort removal of a completed job's per-image work dir.
fn cleanup_work_dir(config: &AutoZranConfig, image: &str) {
    let work_dir = job_work_dir(config, image);
    if let Err(e) = std::fs::remove_dir_all(&work_dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(error = %e, work_dir = %work_dir.display(), "auto-zran work_dir cleanup failed (non-fatal)");
    }
}

/// File under a job's work dir holding the serialized base [`NodeLocalArtifact`].
const BASE_ARTIFACT_FILE: &str = "artifact.json";

fn base_artifact_path(work_dir: &Path) -> PathBuf {
    work_dir.join(BASE_ARTIFACT_FILE)
}

/// Persist a base-stage artifact so the optimize stage can reload it and skip
/// create/merge.
fn write_base_artifact(work_dir: &Path, artifact: &NodeLocalArtifact) -> Result<()> {
    let path = base_artifact_path(work_dir);
    let bytes = serde_json::to_vec(artifact).context("serialize base artifact")?;
    std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

/// Load a persisted base artifact IF its on-disk inputs (merged bootstrap +
/// backend dir, plus the prefetch blob when the artifact claims one) are
/// still present. This is the seam that decides stage-2 behavior: `Some` ⇒
/// reuse (optimize only — or upload-only when `prefetch_blob_id` is already
/// set by a prior optimize whose upload failed); `None` ⇒ run the full
/// pipeline.
fn load_reusable_base_artifact(work_dir: &Path) -> Option<NodeLocalArtifact> {
    let bytes = std::fs::read(base_artifact_path(work_dir)).ok()?;
    let artifact: NodeLocalArtifact = serde_json::from_slice(&bytes).ok()?;
    let prefetch_ok = artifact
        .prefetch_blob_id
        .as_ref()
        .is_none_or(|id| artifact.backend_dir.join(id).is_file());
    (artifact.bootstrap.is_file() && artifact.backend_dir.is_dir() && prefetch_ok)
        .then_some(artifact)
}

/// Probe whether a complete sidecar already exists for `image_name`, and if so
/// whether it already carries a prefetch blob (i.e. is optimized). Any RPC /
/// completeness failure resolves to `Absent` (re-convert) or `Base` (allow
/// optimize) so a transient error never wedges the pipeline.
///
/// The second tuple element is the existing sidecar OCI manifest digest (the
/// Image record's target) whenever a complete sidecar exists — the optimize
/// stage uses it to keep the pre-promotion BASE manifest tree GC-rooted (see
/// `manifest_gc_labels`).
async fn existing_sidecar_state(
    deps: &ConversionDeps,
    image_name: &str,
) -> (SidecarState, Option<String>) {
    let existing = match deps.content_store.images_get(image_name).await {
        Ok(Some(e)) => e,
        Ok(None) => return (SidecarState::Absent, None),
        Err(e) => {
            warn!(image_name = %image_name, error = ?e, "auto-accel images.Get failed; treating sidecar as absent");
            return (SidecarState::Absent, None);
        }
    };
    match completeness_check(deps, &existing.digest).await {
        Ok(true) => {}
        Ok(false) => {
            warn!(image_name = %image_name, "auto-accel sidecar present but some referenced blobs are missing; re-converting");
            return (SidecarState::Absent, None);
        }
        Err(e) => {
            warn!(image_name = %image_name, error = ?e, "auto-accel sidecar completeness check failed; re-converting to be safe");
            return (SidecarState::Absent, None);
        }
    }
    let state = match sidecar_has_prefetch(deps, &existing.digest).await {
        Ok(true) => SidecarState::Optimized,
        Ok(false) => SidecarState::Base,
        Err(e) => {
            // Conservative: treat as base so the optimize stage still runs.
            debug!(image_name = %image_name, error = ?e, "auto-accel prefetch-state probe failed; treating sidecar as base");
            SidecarState::Base
        }
    };
    (state, Some(existing.digest))
}

/// Parse an on-store OCI sidecar manifest → its config blob (our
/// `AutoAccelManifest`) → report whether it carries a prefetch blob.
async fn sidecar_has_prefetch(deps: &ConversionDeps, oci_manifest_digest: &str) -> Result<bool> {
    let manifest_bytes = deps.content_store.fetch_bytes(oci_manifest_digest).await?;
    let oci: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse OCI manifest {oci_manifest_digest}"))?;
    let config_digest = oci
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("oci manifest {oci_manifest_digest} missing config.digest")
        })?;
    let config_bytes = deps.content_store.fetch_bytes(config_digest).await?;
    let manifest: AutoAccelManifest = serde_json::from_slice(&config_bytes)
        .with_context(|| format!("parse auto-accel config blob {config_digest}"))?;
    Ok(manifest.prefetch_blob.is_some())
}

/// Upload a converted artifact as a content-store sidecar (bootstrap + zran
/// indexes + optional prefetch blob + config + OCI manifest) and create-or-
/// update the sidecar Image record. Shared by both stages. Returns whether the
/// Image record registration succeeded (`image_record_ok`).
///
/// The `images_upsert` at the end is what lets stage 2 PROMOTE the record from
/// the base manifest to the optimized one — `Images.Create` alone swallows
/// AlreadyExists without repointing the target. All blobs are content-addressed
/// (`write_blob`/`write_bytes`), so re-uploading never corrupts a
/// concurrently-fetched artifact; only the Image record's target moves.
///
/// `base_manifest_digest` (optimize stage only, when a BASE sidecar record
/// existed) pins the pre-promotion base manifest tree via a
/// `containerd.io/gc.ref.content.base` label on the new manifest.
async fn upload_artifact(
    deps: &ConversionDeps,
    job: &AutoZranJob,
    manifest_digest: &str,
    image_name: &str,
    artifact: &NodeLocalArtifact,
    base_manifest_digest: Option<&str>,
) -> Result<bool> {
    // Own the digest so the step-4/5 label helpers below can `.clone()` it.
    let manifest_digest = manifest_digest.to_string();

    // (4) Upload artifacts. Labels:
    //   - gc.ref.content.subject  is an OUTGOING GC edge (blob → referenced
    //     digest): it keeps the ORIGINAL manifest — and, via containerd's
    //     pull-time labels on that manifest, the original gzip layers — alive
    //     for as long as this sidecar blob exists. That direction is
    //     deliberate: the zran indexes read the original gzip layers out of
    //     the content store at serve time, so the sidecar must pin them. It
    //     does NOT make the sidecar follow the original's lifetime — the
    //     sidecar itself is rooted by its synthetic Image record, which the
    //     reconciler's sidecar sweep deletes once the subject image is gone
    //     (recon::check_orphan_sidecars); only then can GC collect the sidecar
    //     tree and, transitively, release the pinned original layers.
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
        // Spegel's containerd watcher only advertises blobs that carry a
        // `distribution.source.<host>` label, since that's the signal the
        // upstream OCI distribution conventions use to say "this blob
        // originates from this registry host." Without it Spegel logs the
        // image-record CREATE but never gossips the underlying digests over
        // libp2p, so peer nodes can't discover the sidecar via the mirror.
        // Kept UNCONDITIONALLY: Spegel-gossip-specific, but a harmless extra
        // label for any non-Spegel peer mirror; removing it breaks Spegel.
        m.insert(
            "containerd.io/distribution.source.nydus.auto-accel.local".to_string(),
            "sidecar".to_string(),
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
        // Data-less layers (directory/whiteout-only tars) have no zran index; the
        // sidecar manifest simply carries no descriptor for them.
        let Some(blob_id) = blob_id else { continue };
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
        architecture: default_oci_architecture(),
        os: default_oci_os(),
        rootfs: default_oci_rootfs(),
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
    let manifest_labels = manifest_gc_labels(
        base_labels("manifest"),
        &config_digest,
        &bootstrap_digest,
        &zran_descriptors,
        prefetch_descriptor.as_ref(),
        base_manifest_digest,
    );
    let manifest_digest_in_store = deps
        .content_store
        .write_bytes(&manifest_bytes, &manifest_oci_ref, manifest_labels)
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
        .images_upsert(
            image_name,
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
        "auto-zran sidecar uploaded"
    );

    // The stage caller decides whether to mark the image accelerated and clean
    // up the work dir (base retains it for stage 2; optimize tears it down).
    Ok(image_record_ok)
}

/// GC labels stamped onto the sidecar OCI manifest blob.
///
/// Containerd's GC roots a manifest blob through its Image record, then walks
/// the manifest's outgoing `gc.ref.content.*` labels to find its config +
/// layer blobs. Without these labels the just-written
/// config/bootstrap/index/prefetch blobs become orphans the moment GC runs
/// (which happens on every container/image churn), even though the manifest
/// body itself names them by digest — containerd does NOT parse the manifest
/// JSON for GC; it relies on operators to mirror those references into
/// labels. Adding them here keeps the artifact alive until the original image
/// (`gc.ref.content.subject`) is pruned.
///
/// `base_manifest_digest` covers the base→optimized promotion window: the
/// promotion repoints the sidecar Image record at the optimized manifest, so
/// nothing would root the BASE manifest anymore and a peer that resolved the
/// base digest just before promotion could 404 mid-pull after a GC pass.
/// `containerd.io/gc.ref.content.base` keeps the base manifest — and,
/// transitively via that manifest's own `gc.ref.content.*` labels, its whole
/// blob tree — GC-rooted for as long as the optimized sidecar lives.
fn manifest_gc_labels(
    mut labels: HashMap<String, String>,
    config_digest: &str,
    bootstrap_digest: &str,
    zran_descriptors: &[AutoAccelLayerDescriptor],
    prefetch_descriptor: Option<&AutoAccelDescriptor>,
    base_manifest_digest: Option<&str>,
) -> HashMap<String, String> {
    labels.insert(
        "containerd.io/gc.ref.content.config".to_string(),
        config_digest.to_string(),
    );
    labels.insert(
        "containerd.io/gc.ref.content.l.0".to_string(),
        bootstrap_digest.to_string(),
    );
    for (i, layer) in zran_descriptors.iter().enumerate() {
        labels.insert(
            format!("containerd.io/gc.ref.content.l.{}", i + 1),
            layer.digest.clone(),
        );
    }
    if let Some(prefetch) = prefetch_descriptor {
        labels.insert(
            format!(
                "containerd.io/gc.ref.content.l.{}",
                zran_descriptors.len() + 1
            ),
            prefetch.digest.clone(),
        );
    }
    if let Some(base) = base_manifest_digest {
        labels.insert(
            "containerd.io/gc.ref.content.base".to_string(),
            base.to_string(),
        );
    }
    labels
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

/// Dedupe key for the in-flight `queued_or_done` set. It carries the stage
/// discriminant so a `Base` and an `Optimize` job for the SAME image are
/// deduped independently (both can be queued), while repeated enqueues of the
/// same stage collapse. Distinct from `job_key` (which names the shared,
/// stage-agnostic on-disk work dir the recon sweep watches).
fn dedupe_key(image: &str, stage: AutoZranStage) -> String {
    format!("{}:{}", stage.tag(), job_key(image))
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
        assert_eq!(job.stage, AutoZranStage::Optimize);
        assert_eq!(job.prefetch_files, vec!["/bin/app"]);
    }

    #[test]
    fn base_job_has_empty_prefetch_and_base_stage() {
        // A base job carries no prefetch → `local_accel::convert` skips the
        // optimize step and produces a fully servable sidecar.
        let job = AutoZranJob::base("registry.local/app:1".to_string());
        assert_eq!(job.image, "registry.local/app:1");
        assert_eq!(job.stage, AutoZranStage::Base);
        assert!(job.prefetch_files.is_empty());
    }

    #[test]
    fn dedupe_key_separates_stages_but_is_stable_per_stage() {
        let img = "registry.local/app:1";
        assert_eq!(
            dedupe_key(img, AutoZranStage::Base),
            dedupe_key(img, AutoZranStage::Base)
        );
        assert_ne!(
            dedupe_key(img, AutoZranStage::Base),
            dedupe_key(img, AutoZranStage::Optimize)
        );
        // The stage-agnostic work-dir key (what the recon sweep watches) is the
        // same for both stages so they share one on-disk work dir.
        assert!(dedupe_key(img, AutoZranStage::Base).ends_with(&job_key(img)));
        assert!(dedupe_key(img, AutoZranStage::Optimize).ends_with(&job_key(img)));
    }

    #[test]
    fn note_sidecar_missing_clears_state_only_on_repoint() {
        let (sender, _receiver) = async_channel::bounded(1);
        let manager = AutoZranManager {
            sender,
            state: Arc::new(AutoZranState::new(1)),
        };
        let img = "registry.local/app:latest";

        // First sighting: records the digest, nothing to clear.
        assert!(!manager.note_sidecar_missing(img, "sha256:aaa"));

        // Simulate a completed conversion for digest aaa.
        manager
            .state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(dedupe_key(img, AutoZranStage::Base));
        manager
            .state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(dedupe_key(img, AutoZranStage::Optimize));
        manager.state.record_failure(img);

        // Same digest again: state untouched (still deduped).
        assert!(!manager.note_sidecar_missing(img, "sha256:aaa"));
        assert!(
            manager
                .state
                .queued_or_done
                .lock()
                .unwrap()
                .contains(&dedupe_key(img, AutoZranStage::Base))
        );

        // Tag repointed to new content: dedupe keys + failure backoff cleared
        // so the new manifest can be converted without a restart.
        assert!(manager.note_sidecar_missing(img, "sha256:bbb"));
        let seen = manager.state.queued_or_done.lock().unwrap();
        assert!(!seen.contains(&dedupe_key(img, AutoZranStage::Base)));
        assert!(!seen.contains(&dedupe_key(img, AutoZranStage::Optimize)));
        drop(seen);
        assert!(manager.state.failures.lock().unwrap().get(img).is_none());
    }

    #[test]
    fn state_tracks_started_success_and_failure_lifecycle() {
        let state = AutoZranState::new(8);
        let success_job = AutoZranJob {
            image: "registry.local/success:1".to_string(),
            stage: AutoZranStage::Optimize,
            prefetch_files: vec!["/bin/app".to_string()],
        };
        state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(dedupe_key(&success_job.image, success_job.stage));

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
            stage: AutoZranStage::Optimize,
            prefetch_files: vec!["/bin/app".to_string()],
        };
        state
            .queued_or_done
            .lock()
            .unwrap()
            .insert(dedupe_key(&failed_job.image, failed_job.stage));
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
    fn active_job_key_tracks_the_running_job_and_clears_on_finish() {
        let (sender, _receiver) = async_channel::bounded(2);
        let state = Arc::new(AutoZranState::new(2));
        let manager = AutoZranManager {
            sender,
            state: state.clone(),
        };
        assert!(manager.active_job_key().is_none());

        let job = AutoZranJob {
            image: "registry.local/app:1".to_string(),
            stage: AutoZranStage::Optimize,
            prefetch_files: vec!["/bin/app".to_string()],
        };
        state.mark_started(&job);
        // active_job_key is the stage-AGNOSTIC work-dir key (both stages share
        // one work dir), so the recon sweep can exclude it regardless of stage.
        assert_eq!(manager.active_job_key(), Some(job_key(&job.image)));

        state.mark_finished(&job, true);
        assert!(manager.active_job_key().is_none());
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
        assert!(!state.queued_or_done.lock().unwrap().contains(&dedupe_key(
            "registry.local/second:1",
            AutoZranStage::Optimize
        )));
    }

    #[test]
    fn enqueue_base_deduplicates_same_image() {
        let (sender, receiver) = async_channel::bounded(4);
        let state = Arc::new(AutoZranState::new(4));
        let manager = AutoZranManager {
            sender,
            state: state.clone(),
        };

        manager.try_enqueue_base("registry.local/app:1");
        manager.try_enqueue_base("registry.local/app:1");

        let queued = receiver.try_recv().unwrap();
        assert_eq!(queued.image, "registry.local/app:1");
        assert_eq!(queued.stage, AutoZranStage::Base);
        assert!(queued.prefetch_files.is_empty());
        let status = manager.status();
        assert_eq!(status.queued_total, 1);
        assert_eq!(status.skipped_total, 1);
        assert!(receiver.try_recv().is_err());
    }

    /// Base and optimize dedupe INDEPENDENTLY: a base enqueue at prepare and an
    /// optimize enqueue at settle for the same image both make it onto the
    /// queue. Verified for BOTH orderings (prepare-then-settle and the reverse
    /// race where settle wins).
    #[test]
    fn base_and_optimize_enqueue_independently_in_either_order() {
        for base_first in [true, false] {
            let (sender, receiver) = async_channel::bounded(4);
            let state = Arc::new(AutoZranState::new(4));
            let manager = AutoZranManager {
                sender,
                state: state.clone(),
            };
            let prof = profile("registry.local/app:1");

            if base_first {
                manager.try_enqueue_base("registry.local/app:1");
                manager.try_enqueue_profile(&prof);
            } else {
                manager.try_enqueue_profile(&prof);
                manager.try_enqueue_base("registry.local/app:1");
            }

            let status = manager.status();
            assert_eq!(
                status.queued_total, 2,
                "both stages queue (base_first={base_first})"
            );
            assert_eq!(status.skipped_total, 0);

            let mut stages: Vec<AutoZranStage> = Vec::new();
            while let Ok(job) = receiver.try_recv() {
                assert_eq!(job.image, "registry.local/app:1");
                stages.push(job.stage);
            }
            assert_eq!(stages.len(), 2);
            assert!(stages.contains(&AutoZranStage::Base));
            assert!(stages.contains(&AutoZranStage::Optimize));
        }
    }

    /// Stage-2 reuse seam: with a persisted base artifact whose referenced
    /// on-disk inputs exist, `load_reusable_base_artifact` returns `Some`
    /// (⇒ optimize-only path, create/merge SKIPPED); without them it returns
    /// `None` (⇒ full pipeline).
    #[test]
    fn load_reusable_base_artifact_gates_on_disk_inputs() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path();
        let backend = work_dir.join("backend");
        std::fs::create_dir_all(&backend).unwrap();
        let bootstrap = work_dir.join("bootstrap");
        std::fs::write(&bootstrap, b"merged-bootstrap").unwrap();

        let artifact = NodeLocalArtifact {
            bootstrap: bootstrap.clone(),
            backend_dir: backend.clone(),
            work_dir: work_dir.to_path_buf(),
            layer_blob_ids: vec!["deadbeef".to_string()],
            zran_index_blob_ids: vec![Some("cafef00d".to_string())],
            prefetch_blob_id: None,
        };

        // No artifact.json yet → full pipeline.
        assert!(load_reusable_base_artifact(work_dir).is_none());

        write_base_artifact(work_dir, &artifact).unwrap();
        let reused = load_reusable_base_artifact(work_dir).expect("base artifact reusable");
        assert_eq!(reused, artifact);
        assert!(
            reused.prefetch_blob_id.is_none(),
            "base has no prefetch blob"
        );

        // If the merged bootstrap is gone the base is NOT reusable even though
        // artifact.json remains → force the full pipeline rather than optimize
        // against a missing input.
        std::fs::remove_file(&bootstrap).unwrap();
        assert!(load_reusable_base_artifact(work_dir).is_none());
    }

    /// Fix for the "retry after failed optimize upload" seam: a persisted
    /// artifact that already claims a prefetch blob is only reusable when the
    /// blob file is actually present; otherwise stage 2 must fall back to the
    /// full pipeline instead of uploading a dangling reference.
    #[test]
    fn load_reusable_artifact_gates_on_prefetch_blob_presence() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path();
        let backend = work_dir.join("backend");
        std::fs::create_dir_all(&backend).unwrap();
        let bootstrap = work_dir.join("bootstrap");
        std::fs::write(&bootstrap, b"optimized-bootstrap").unwrap();

        let artifact = NodeLocalArtifact {
            bootstrap,
            backend_dir: backend.clone(),
            work_dir: work_dir.to_path_buf(),
            layer_blob_ids: vec!["deadbeef".to_string()],
            zran_index_blob_ids: vec![Some("cafef00d".to_string())],
            prefetch_blob_id: Some("prefetch01".to_string()),
        };
        write_base_artifact(work_dir, &artifact).unwrap();

        // artifact.json claims a prefetch blob that is not on disk → None.
        assert!(load_reusable_base_artifact(work_dir).is_none());

        std::fs::write(backend.join("prefetch01"), b"packed-chunks").unwrap();
        let reused = load_reusable_base_artifact(work_dir).expect("optimized artifact reusable");
        assert_eq!(reused, artifact);
        assert!(reused.prefetch_blob_id.is_some());
    }

    /// Fix 1 (negative cache): after `MAX_CONVERSION_FAILURES` consecutive
    /// failures for an image, BOTH stages' enqueue paths are suppressed; any
    /// subsequent success for the image resets the count.
    #[test]
    fn enqueue_suppressed_after_max_failures_until_a_success_resets() {
        let (sender, receiver) = async_channel::bounded(8);
        let state = Arc::new(AutoZranState::new(8));
        let manager = AutoZranManager {
            sender,
            state: state.clone(),
        };
        let image = "registry.local/broken:1";
        let job = AutoZranJob::base(image.to_string());

        // Simulate MAX consecutive failures through the real worker path
        // (mark_finished(false) both releases the dedupe key and records the
        // failure).
        for _ in 0..MAX_CONVERSION_FAILURES {
            state.mark_started(&job);
            state.mark_finished(&job, false);
        }

        // Both stages are suppressed permanently (no temporal component once
        // the cutoff is reached).
        manager.try_enqueue_base(image);
        manager.try_enqueue_profile(&profile(image));
        assert!(
            receiver.try_recv().is_err(),
            "suppressed image must not queue"
        );
        let status = manager.status();
        assert_eq!(status.queued_total, 0);
        assert_eq!(status.skipped_total, 2);

        // Unrelated images are unaffected.
        manager.try_enqueue_base("registry.local/healthy:1");
        assert_eq!(
            receiver.try_recv().unwrap().image,
            "registry.local/healthy:1"
        );

        // A success (e.g. a queued-before-cutoff job completing) resets the
        // negative cache → enqueue works again immediately.
        state.mark_started(&job);
        state.mark_finished(&job, true);
        manager.try_enqueue_base(image);
        let queued = receiver.try_recv().expect("reset image queues again");
        assert_eq!(queued.image, image);
        assert_eq!(queued.stage, AutoZranStage::Base);
    }

    /// Fix 1 (backoff spacing): before the permanent cutoff, retries are
    /// spaced exponentially (base, 2×base) from the last failure.
    #[test]
    fn failure_backoff_spacing_is_exponential_before_permanent_cutoff() {
        let state = AutoZranState::new(2);
        let image = "registry.local/flaky:1";
        let job = AutoZranJob::base(image.to_string());
        let last_failure = |state: &AutoZranState| {
            state
                .failures
                .lock()
                .unwrap()
                .get(image)
                .expect("failure recorded")
                .last_failure
        };

        state.mark_started(&job);
        state.mark_finished(&job, false); // count = 1 → window = base
        let failed_at = last_failure(&state);
        assert!(state.enqueue_suppressed(image, failed_at));
        assert!(state.enqueue_suppressed(
            image,
            failed_at + FAILURE_BACKOFF_BASE - Duration::from_secs(1)
        ));
        assert!(!state.enqueue_suppressed(image, failed_at + FAILURE_BACKOFF_BASE));

        state.mark_started(&job);
        state.mark_finished(&job, false); // count = 2 → window = 2×base
        let failed_at = last_failure(&state);
        assert!(state.enqueue_suppressed(image, failed_at + FAILURE_BACKOFF_BASE));
        assert!(!state.enqueue_suppressed(image, failed_at + 2 * FAILURE_BACKOFF_BASE));

        state.mark_started(&job);
        state.mark_finished(&job, false); // count = 3 → permanent
        let failed_at = last_failure(&state);
        assert!(
            state.enqueue_suppressed(image, failed_at + Duration::from_secs(365 * 24 * 60 * 60))
        );

        // Images without a failure record are never suppressed.
        assert!(!state.enqueue_suppressed("registry.local/other:1", failed_at));
    }

    /// Fix 2 (GC pinning across promotion): the manifest GC labels reference
    /// config + every data blob, and — only when a base record existed —
    /// carry `gc.ref.content.base` pointing at the pre-promotion base
    /// manifest so its tree stays GC-rooted while the optimized sidecar
    /// lives.
    #[test]
    fn manifest_gc_labels_pin_blobs_and_optionally_the_base_manifest() {
        let zran = vec![AutoAccelLayerDescriptor {
            layer_digest: "sha256:aaa".to_string(),
            digest: "sha256:idx0".to_string(),
            size: 1,
        }];
        let prefetch = AutoAccelDescriptor {
            digest: "sha256:pf".to_string(),
            size: 2,
        };

        // Optimize-stage shape: prefetch blob + pre-existing base manifest.
        let labels = manifest_gc_labels(
            HashMap::new(),
            "sha256:cfg",
            "sha256:boot",
            &zran,
            Some(&prefetch),
            Some("sha256:base-manifest"),
        );
        assert_eq!(labels["containerd.io/gc.ref.content.config"], "sha256:cfg");
        assert_eq!(labels["containerd.io/gc.ref.content.l.0"], "sha256:boot");
        assert_eq!(labels["containerd.io/gc.ref.content.l.1"], "sha256:idx0");
        assert_eq!(labels["containerd.io/gc.ref.content.l.2"], "sha256:pf");
        assert_eq!(
            labels["containerd.io/gc.ref.content.base"],
            "sha256:base-manifest"
        );

        // Base-stage shape: no prefetch blob, no base pin.
        let labels = manifest_gc_labels(
            HashMap::new(),
            "sha256:cfg",
            "sha256:boot",
            &zran,
            None,
            None,
        );
        assert_eq!(labels["containerd.io/gc.ref.content.l.1"], "sha256:idx0");
        assert!(!labels.contains_key("containerd.io/gc.ref.content.l.2"));
        assert!(!labels.contains_key("containerd.io/gc.ref.content.base"));
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
