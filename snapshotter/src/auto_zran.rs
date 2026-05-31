// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Low-priority background zran artifact generation.
//!
//! This is the first P5 integration point: once the optimizer NRI plugin submits
//! a structured runtime access profile, the snapshotter can enqueue a low
//! priority `nydusify convert --oci-ref` job for the original OCI image. The
//! generated zran artifact reuses the original gzip layers, so mirrors such as
//! spegel can serve an accelerated artifact to other nodes without storing a
//! second full native RAFS image.

use crate::config::AutoZranConfig;
use crate::prefetch_profile::PrefetchProfile;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc;
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
        if let Ok(mut active) = self.active_image.lock() {
            if active.as_deref() == Some(job.image.as_str()) {
                *active = None;
            }
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
    sender: mpsc::Sender<AutoZranJob>,
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
        let (sender, receiver) = mpsc::channel(depth);
        let state = Arc::new(AutoZranState::new(depth));
        let manager = Arc::new(Self {
            sender,
            state: state.clone(),
        });
        let worker_config = config.clone();
        tokio::spawn(async move { worker_loop(worker_config, receiver, state).await });
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
        if should_skip_image(&job.image) {
            self.state
                .metrics
                .skipped_total
                .fetch_add(1, Ordering::Relaxed);
            debug!(image = %job.image, "auto-zran skipped already accelerated image");
            return;
        }

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
    mut receiver: mpsc::Receiver<AutoZranJob>,
    state: Arc<AutoZranState>,
) {
    while let Some(job) = receiver.recv().await {
        state.mark_started(&job);
        let result = run_conversion(&config, &job).await;
        let success = result.is_ok();
        state.mark_finished(&job, success);
        if let Err(e) = result {
            warn!(image = %job.image, error = %e, "auto-zran conversion failed");
        }
    }
}

async fn run_conversion(config: &AutoZranConfig, job: &AutoZranJob) -> Result<()> {
    std::fs::create_dir_all(&config.work_dir).with_context(|| {
        format!(
            "failed to create auto-zran work dir {}",
            config.work_dir.display()
        )
    })?;

    let spec = CommandSpec::for_job(config, job);
    info!(image = %job.image, program = ?spec.program, args = ?spec.args, "starting auto-zran conversion");
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("failed to spawn auto-zran converter")?;
    if let Some(mut stdin) = child.stdin.take() {
        let prefetch = job.prefetch_files.join("\n") + "\n";
        stdin
            .write_all(prefetch.as_bytes())
            .await
            .context("failed to write auto-zran prefetch profile to converter stdin")?;
    }

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait for auto-zran converter")?;
    if !output.status.success() {
        anyhow::bail!(
            "converter exited with {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    info!(image = %job.image, "auto-zran conversion completed");
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandSpec {
    program: OsString,
    args: Vec<OsString>,
}

impl CommandSpec {
    fn for_job(config: &AutoZranConfig, job: &AutoZranJob) -> Self {
        let mut converter_args = vec![
            config.nydusify.as_os_str().to_os_string(),
            OsString::from("convert"),
            OsString::from("--oci-ref"),
            OsString::from("--source"),
            OsString::from(&job.image),
            OsString::from("--target-suffix"),
            OsString::from(&config.target_suffix),
            OsString::from("--fs-version"),
            OsString::from("6"),
            OsString::from("--prefetch-patterns"),
            OsString::from("--work-dir"),
            job_work_dir(config, &job.image).into_os_string(),
        ];

        if config.plain_http {
            converter_args.push(OsString::from("--plain-http"));
        }
        if config.source_insecure {
            converter_args.push(OsString::from("--source-insecure"));
        }
        if config.target_insecure {
            converter_args.push(OsString::from("--target-insecure"));
        }

        let mut nice_args = vec![
            OsString::from("-n"),
            OsString::from(config.nice.clamp(0, 19).to_string()),
        ];
        nice_args.extend(converter_args);

        if config.ionice_idle {
            let mut args = vec![
                OsString::from("-c"),
                OsString::from("3"),
                OsString::from("nice"),
            ];
            args.extend(nice_args);
            return Self {
                program: OsString::from("ionice"),
                args,
            };
        }

        Self {
            program: OsString::from("nice"),
            args: nice_args,
        }
    }
}

fn should_skip_image(image: &str) -> bool {
    image.ends_with("-nydus-oci-ref") || image.contains("-nydus-oci-ref@")
}

fn job_work_dir(config: &AutoZranConfig, image: &str) -> PathBuf {
    config.work_dir.join(job_key(image))
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
        let (sender, mut receiver) = mpsc::channel(2);
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
        let (sender, _receiver) = mpsc::channel(1);
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
        assert!(!state
            .queued_or_done
            .lock()
            .unwrap()
            .contains(&job_key("registry.local/second:1")));
    }

    #[test]
    fn enqueue_profile_skips_empty_and_already_accelerated_profiles() {
        let (sender, mut receiver) = mpsc::channel(2);
        let state = Arc::new(AutoZranState::new(2));
        let manager = AutoZranManager { sender, state };
        let empty = PrefetchProfile::from_access_records(
            "registry.local/empty:1",
            Vec::<AccessProfileRecord>::new(),
        );
        let accelerated = profile("registry.local/app:1-nydus-oci-ref");

        manager.try_enqueue_profile(&empty);
        manager.try_enqueue_profile(&accelerated);

        let status = manager.status();
        assert_eq!(status.queued_total, 0);
        assert_eq!(status.skipped_total, 2);
        assert_eq!(status.known_jobs, 0);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn command_spec_uses_low_priority_nydusify_oci_ref() {
        let config = AutoZranConfig {
            enable: true,
            nydusify: PathBuf::from("/usr/bin/nydusify"),
            target_suffix: "-zran".to_string(),
            queue_depth: 4,
            nice: 99,
            ionice_idle: true,
            work_dir: PathBuf::from("/tmp/auto-zran"),
            plain_http: true,
            source_insecure: true,
            target_insecure: false,
        };
        let job = AutoZranJob {
            image: "registry.local/app:1".to_string(),
            prefetch_files: vec!["/bin/app".to_string()],
        };
        let spec = CommandSpec::for_job(&config, &job);
        let args = spec
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(spec.program, OsString::from("ionice"));
        assert_eq!(
            args[0..6],
            ["-c", "3", "nice", "-n", "19", "/usr/bin/nydusify"]
        );
        assert!(args
            .windows(2)
            .any(|w| w == ["--source", "registry.local/app:1"]));
        assert!(args.windows(2).any(|w| w == ["--target-suffix", "-zran"]));
        assert!(args.contains(&"--oci-ref".to_string()));
        assert!(args.contains(&"--prefetch-patterns".to_string()));
        assert!(args.contains(&"--plain-http".to_string()));
        assert!(args.contains(&"--source-insecure".to_string()));
        assert!(!args.contains(&"--target-insecure".to_string()));
    }

    #[test]
    fn command_spec_can_disable_ionice_for_non_linux_hosts() {
        let config = AutoZranConfig {
            enable: true,
            nydusify: PathBuf::from("nydusify"),
            target_suffix: "-zran".to_string(),
            queue_depth: 4,
            nice: 10,
            ionice_idle: false,
            work_dir: PathBuf::from("/tmp/auto-zran"),
            plain_http: false,
            source_insecure: false,
            target_insecure: false,
        };
        let job = AutoZranJob {
            image: "registry.local/app:1".to_string(),
            prefetch_files: vec!["/bin/app".to_string()],
        };
        let spec = CommandSpec::for_job(&config, &job);
        assert_eq!(spec.program, OsString::from("nice"));
    }

    #[test]
    fn skips_already_accelerated_images() {
        assert!(should_skip_image("registry.local/app:1-nydus-oci-ref"));
        assert!(should_skip_image(
            "registry.local/app@sha256:abc-nydus-oci-ref@"
        ));
        assert!(!should_skip_image("registry.local/app:1"));
    }
}
