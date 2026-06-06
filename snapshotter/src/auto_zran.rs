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

use crate::config::AutoZranConfig;
use crate::prefetch_profile::PrefetchProfile;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_channel::{Receiver, Sender};
use tracing::{debug, info, warn};

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
    pub fn start(config: &AutoZranConfig) -> Option<Arc<Self>> {
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
        compio::runtime::spawn(async move { worker_loop(worker_config, receiver, state).await })
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
    receiver: Receiver<AutoZranJob>,
    state: Arc<AutoZranState>,
) {
    while let Ok(job) = receiver.recv().await {
        state.mark_started(&job);
        let result = run_conversion(&config, &job).await;
        let success = result.is_ok();
        state.mark_finished(&job, success);
        if let Err(e) = result {
            warn!(image = %job.image, error = %e, "auto-zran conversion failed");
        }
    }
}

/// Drive a single conversion job end-to-end. Phase 6 fills in the body:
/// resolve the original manifest digest + gzip-layer paths via
/// `ContainerdLookup`, call `local_accel::convert(cfg, layers, &job.prefetch_files)`,
/// upload the artifacts to containerd's content store with auto-accel labels,
/// register the deterministic `nydus-auto-accel:v1:<subject_digest>` ref, then
/// mark the image accelerated in the access tracer. For now this is a no-op so
/// the queue/state machinery compiles and runs cleanly while the surrounding
/// phases land.
async fn run_conversion(_config: &AutoZranConfig, job: &AutoZranJob) -> Result<()> {
    info!(
        image = %job.image,
        prefetch_files = job.prefetch_files.len(),
        "auto-zran conversion queued (no-op until phase 6 wires the pipeline)"
    );
    Ok(())
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
