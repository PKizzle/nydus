// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! In-process daemon supervisor.
//!
//! Wraps `nydus-service` types as in-process tasks rather than spawned child
//! processes. Each Nydus image is mounted at a stable path under
//! `{root}/daemons/<slug>/mnt` and the returned [`MountHandle`] tracks reference
//! counts so the snapshotter can release the daemon once no more containers
//! depend on the image.

pub(crate) mod auth;
pub mod config_builder;
pub mod image_ref;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use async_lock::{Mutex, RwLock};
use mio::{Poll, Token, Waker};
use nydus_api::BuildTimeInfo;
use nydus_service::Error as ServiceError;
use nydus_service::daemon::{
    DaemonState, DaemonStateMachineInput, DaemonStateMachineSubscriber, NydusDaemon,
};
use nydus_service::upgrade::FailoverPolicy;
use nydus_service::{FsBackendMountCmd, FsBackendType, create_fuse_daemon, create_vfs_backend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::{FsDriverType, SnapshotterConfig};
use crate::daemon::config_builder::{build_blob_cache_entry, build_registry_config};
use crate::daemon::image_ref::{ImageRef, parse_image_ref};
use crate::prefetch_profile::runtime_prefetch_for_image;

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use nydus_service::block_device::BlockDevice;

/// Persisted and live daemon status exposed through the system controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonStatusRecord {
    pub image_ref: String,
    pub slug: String,
    pub mountpoint: PathBuf,
    pub bootstrap: PathBuf,
    pub refcount: usize,
    pub state: String,
    pub live: bool,
    pub updated_at: i64,
}

/// Outcome for one daemon recovery attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonRecoveryOutcome {
    pub image_ref: String,
    pub slug: String,
    pub status: String,
    pub before_state: String,
    pub after_state: Option<String>,
    pub error: Option<String>,
}

/// Summary returned by the reconciler-facing recovery hook.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonRecoveryReport {
    pub checked: usize,
    pub restarted: usize,
    pub failed: usize,
    pub outcomes: Vec<DaemonRecoveryOutcome>,
}

/// Options for in-process daemon replacement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonUpgradeOptions {
    /// Restart daemons that still have active snapshot references. Disabled by
    /// default because the Rust snapshotter runs daemons in-process and a safe
    /// FD handoff requires service-layer support.
    #[serde(default)]
    pub allow_active: bool,
}

/// Outcome for one daemon upgrade/replacement attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonUpgradeOutcome {
    pub image_ref: String,
    pub slug: String,
    pub status: String,
    pub before_state: String,
    pub after_state: Option<String>,
    pub refcount: usize,
    pub error: Option<String>,
}

/// Summary returned by the system-controller upgrade API.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaemonUpgradeReport {
    pub attempted: usize,
    pub upgraded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub records: Vec<DaemonStatusRecord>,
    pub outcomes: Vec<DaemonUpgradeOutcome>,
}

/// Handle returned to callers for a live mounted image.
///
/// Dropping the handle does **not** unmount - the supervisor owns the lifetime.
/// Callers must call [`DaemonSupervisor::release`] to decrement the refcount.
pub struct MountHandle {
    image_ref: String,
    mountpoint: PathBuf,
    daemon: Arc<dyn NydusDaemon>,
}

impl MountHandle {
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    pub fn image_ref(&self) -> &str {
        &self.image_ref
    }

    pub fn state(&self) -> DaemonState {
        self.daemon.get_state()
    }
}

/// A single in-process FUSE daemon instance, one per image reference.
struct DaemonInstance {
    image_ref: String,
    mountpoint: PathBuf,
    bootstrap: PathBuf,
    daemon: Arc<dyn NydusDaemon>,
    refcount: AtomicUsize,
    /// Mio poller kept alive for the entire lifetime of the daemon - the
    /// `Waker` we pass into `create_fuse_daemon` borrows its registry.
    _poll: Arc<Mutex<Poll>>,
}

/// Lightweight daemon facade for the host-mounted blockdev/EROFS path.
struct BlockdevDaemon {
    id: String,
    mountpoint: PathBuf,
    build_info: BuildTimeInfo,
    state: AtomicI32,
}

impl BlockdevDaemon {
    fn new(id: String, mountpoint: PathBuf, build_info: BuildTimeInfo) -> Self {
        Self {
            id,
            mountpoint,
            build_info,
            state: AtomicI32::new(DaemonState::RUNNING as i32),
        }
    }
}

impl DaemonStateMachineSubscriber for BlockdevDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> nydus_service::Result<()> {
        match event {
            DaemonStateMachineInput::Mount => self.set_state(DaemonState::READY),
            DaemonStateMachineInput::Start => self.set_state(DaemonState::RUNNING),
            DaemonStateMachineInput::Stop | DaemonStateMachineInput::Exit => {
                self.set_state(DaemonState::STOPPED)
            }
            DaemonStateMachineInput::Takeover => self.set_state(DaemonState::READY),
        }
        Ok(())
    }
}

impl NydusDaemon for BlockdevDaemon {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }

    fn version(&self) -> BuildTimeInfo {
        self.build_info.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn start(&self) -> nydus_service::Result<()> {
        self.set_state(DaemonState::RUNNING);
        Ok(())
    }

    fn umount(&self) -> nydus_service::Result<()> {
        unmount_blockdev_erofs(&self.mountpoint).map_err(service_io_error)
    }

    fn stop(&self) {
        self.set_state(DaemonState::STOPPED);
    }

    fn wait(&self) -> nydus_service::Result<()> {
        Ok(())
    }

    fn supervisor(&self) -> Option<String> {
        None
    }

    fn save(&self) -> nydus_service::Result<()> {
        Ok(())
    }

    fn restore(&self) -> nydus_service::Result<()> {
        Ok(())
    }
}

/// The daemon supervisor manages all in-process nydus-service instances.
pub struct DaemonSupervisor {
    config: SnapshotterConfig,
    build_info: BuildTimeInfo,
    instances: RwLock<HashMap<String, Arc<DaemonInstance>>>,
    startup_timeout: Duration,
}

impl DaemonSupervisor {
    pub fn new(config: SnapshotterConfig) -> Self {
        Self {
            config,
            build_info: BuildTimeInfo {
                package_ver: env!("CARGO_PKG_VERSION").to_string(),
                git_commit: String::new(),
                build_time: String::new(),
                profile: if cfg!(debug_assertions) {
                    "debug".into()
                } else {
                    "release".into()
                },
                rustc: String::new(),
            },
            instances: RwLock::new(HashMap::new()),
            startup_timeout: Duration::from_secs(30),
        }
    }

    /// Start or retrieve a FUSE daemon serving `image_ref` from `bootstrap`.
    ///
    /// Increments the reference count on every call.
    pub async fn ensure_instance(
        &self,
        image_ref: &str,
        bootstrap: &Path,
    ) -> Result<Arc<MountHandle>> {
        if image_ref.is_empty() {
            bail!("image reference must be non-empty to mount a Nydus image");
        }
        if !bootstrap.is_file() {
            bail!(
                "bootstrap {} is missing - is the meta layer extracted?",
                bootstrap.display()
            );
        }

        {
            let instances = self.instances.read().await;
            if let Some(inst) = instances.get(image_ref)
                && inst.bootstrap == bootstrap
                && matches!(
                    inst.daemon.get_state(),
                    DaemonState::RUNNING | DaemonState::READY
                )
            {
                inst.refcount.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = self.persist_instance_record(inst, true) {
                    warn!(image_ref, error = %e, "failed to persist daemon record");
                }
                return Ok(Arc::new(MountHandle {
                    image_ref: image_ref.to_string(),
                    mountpoint: inst.mountpoint.clone(),
                    daemon: inst.daemon.clone(),
                }));
            }
        }

        let mut instances = self.instances.write().await;
        if let Some(inst) = instances.get(image_ref)
            && inst.bootstrap == bootstrap
            && matches!(
                inst.daemon.get_state(),
                DaemonState::RUNNING | DaemonState::READY
            )
        {
            inst.refcount.fetch_add(1, Ordering::SeqCst);
            if let Err(e) = self.persist_instance_record(inst, true) {
                warn!(image_ref, error = %e, "failed to persist daemon record");
            }
            return Ok(Arc::new(MountHandle {
                image_ref: image_ref.to_string(),
                mountpoint: inst.mountpoint.clone(),
                daemon: inst.daemon.clone(),
            }));
        }

        let instance = self
            .start_instance(image_ref, bootstrap)
            .await
            .with_context(|| format!("failed to start nydus daemon for {image_ref}"))?;
        instance.refcount.fetch_add(1, Ordering::SeqCst);
        let handle = MountHandle {
            image_ref: image_ref.to_string(),
            mountpoint: instance.mountpoint.clone(),
            daemon: instance.daemon.clone(),
        };
        instances.insert(image_ref.to_string(), instance);
        if let Some(inst) = instances.get(image_ref)
            && let Err(e) = self.persist_instance_record(inst, true)
        {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Ok(Arc::new(handle))
    }

    /// Explicitly spawn a daemon without acquiring a snapshot reference.
    ///
    /// This is used by the system-controller API to pre-warm or recover a
    /// daemon. It is idempotent for the same `(image_ref, bootstrap)` pair and
    /// does not increment the refcount used by container lifecycle paths.
    pub async fn spawn_instance(
        &self,
        image_ref: &str,
        bootstrap: &Path,
    ) -> Result<DaemonStatusRecord> {
        validate_spawn_request(image_ref, bootstrap)?;

        let mut instances = self.instances.write().await;
        if let Some(inst) = instances.get(image_ref) {
            if inst.bootstrap != bootstrap {
                bail!(
                    "daemon {image_ref} is already serving bootstrap {}; refusing to replace it with {}",
                    inst.bootstrap.display(),
                    bootstrap.display()
                );
            }
            if is_healthy_state(inst.daemon.get_state()) {
                if let Err(e) = self.persist_instance_record(inst, true) {
                    warn!(image_ref, error = %e, "failed to persist daemon record");
                }
                return Ok(self.record_for_instance(inst, true));
            }
        }

        if let Some(old) = instances.remove(image_ref) {
            warn!(
                image_ref,
                "replacing unhealthy daemon during explicit spawn"
            );
            if let Err(e) = stop_instance(&old) {
                warn!(image_ref, error = %e, "failed to stop unhealthy daemon before respawn");
            }
            if let Err(e) = self.persist_instance_record(&old, false) {
                warn!(image_ref, error = %e, "failed to persist stopped daemon record");
            }
        }

        let instance = self
            .start_instance(image_ref, bootstrap)
            .await
            .with_context(|| format!("failed to spawn nydus daemon for {image_ref}"))?;
        let record = self.record_for_instance(&instance, true);
        instances.insert(image_ref.to_string(), instance);
        if let Some(inst) = instances.get(image_ref)
            && let Err(e) = self.persist_instance_record(inst, true)
        {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Ok(record)
    }

    /// Decrement the reference count and tear the daemon down if no callers
    /// remain.
    pub async fn release(&self, image_ref: &str) -> Result<()> {
        let mut instances = self.instances.write().await;
        let should_stop = if let Some(inst) = instances.get(image_ref) {
            let prev = inst.refcount.load(Ordering::SeqCst);
            if prev == 0 {
                false
            } else {
                inst.refcount.fetch_sub(1, Ordering::SeqCst) <= 1
            }
        } else {
            return Ok(());
        };

        if should_stop {
            if let Some(inst) = instances.remove(image_ref) {
                if let Err(e) = stop_instance(&inst) {
                    warn!(image_ref, error = %e, "failed to stop nydus daemon cleanly");
                }
                if let Err(e) = self.persist_instance_record(&inst, false) {
                    warn!(image_ref, error = %e, "failed to persist stopped daemon record");
                }
            }
        } else if let Some(inst) = instances.get(image_ref)
            && let Err(e) = self.persist_instance_record(inst, true)
        {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Ok(())
    }

    /// Reconciler hook: re-check daemon health and restart failed instances.
    pub async fn recover(&self) -> Result<DaemonRecoveryReport> {
        let candidates = {
            let instances = self.instances.read().await;
            instances
                .iter()
                .filter_map(|(image_ref, inst)| {
                    let state = inst.daemon.get_state();
                    (!is_healthy_state(state)).then(|| image_ref.clone())
                })
                .collect::<Vec<_>>()
        };

        let mut report = DaemonRecoveryReport {
            checked: candidates.len(),
            ..DaemonRecoveryReport::default()
        };
        if candidates.is_empty() {
            return Ok(report);
        }

        let mut instances = self.instances.write().await;
        for image_ref in candidates {
            let Some(old) = instances.remove(&image_ref) else {
                continue;
            };
            let slug = slug_for(&image_ref);
            let before_state = format!("{:?}", old.daemon.get_state());
            let bootstrap = old.bootstrap.clone();
            let refcount = old.refcount.load(Ordering::SeqCst);
            warn!(image_ref, state = %before_state, "recovering unhealthy nydus daemon");

            if let Err(e) = stop_instance(&old) {
                warn!(image_ref, error = %e, "failed to stop unhealthy daemon during recovery");
            }
            if let Err(e) = self.persist_instance_record(&old, false) {
                warn!(image_ref, error = %e, "failed to persist stopped daemon record");
            }

            match self.start_instance(&image_ref, &bootstrap).await {
                Ok(instance) => {
                    instance.refcount.store(refcount, Ordering::SeqCst);
                    let after_state = format!("{:?}", instance.daemon.get_state());
                    if let Err(e) = self.persist_instance_record(&instance, true) {
                        warn!(image_ref, error = %e, "failed to persist recovered daemon record");
                    }
                    instances.insert(image_ref.clone(), instance);
                    report.restarted += 1;
                    report.outcomes.push(DaemonRecoveryOutcome {
                        image_ref,
                        slug,
                        status: "restarted".to_string(),
                        before_state,
                        after_state: Some(after_state),
                        error: None,
                    });
                }
                Err(e) => {
                    report.failed += 1;
                    report.outcomes.push(DaemonRecoveryOutcome {
                        image_ref,
                        slug,
                        status: "failed".to_string(),
                        before_state,
                        after_state: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Replace every live daemon according to the supplied upgrade options.
    pub async fn upgrade_instances(
        &self,
        options: DaemonUpgradeOptions,
    ) -> Result<DaemonUpgradeReport> {
        let targets = {
            let instances = self.instances.read().await;
            instances.keys().cloned().collect::<Vec<_>>()
        };
        self.upgrade_selected_instances(targets, options).await
    }

    /// Replace a daemon addressed by slug or exact image reference.
    pub async fn upgrade_instance(
        &self,
        id: &str,
        options: DaemonUpgradeOptions,
    ) -> Result<DaemonUpgradeReport> {
        let target = {
            let instances = self.instances.read().await;
            instances
                .iter()
                .find(|(image_ref, _inst)| image_ref.as_str() == id || slug_for(image_ref) == id)
                .map(|(image_ref, _inst)| image_ref.clone())
        };
        let Some(target) = target else {
            bail!("daemon {id} not found");
        };
        self.upgrade_selected_instances(vec![target], options).await
    }

    /// Snapshot of currently-live (image_ref → mountpoint) pairs. Used by the
    /// reconciler to distinguish active mounts from orphans.
    pub async fn active_mountpoints(&self) -> Vec<(String, PathBuf)> {
        let instances = self.instances.read().await;
        instances
            .iter()
            .map(|(image_ref, inst)| (image_ref.clone(), inst.mountpoint.clone()))
            .collect()
    }

    /// Return live and persisted daemon records. Live records take precedence
    /// over older persisted records with the same slug.
    pub async fn daemon_records(&self) -> Vec<DaemonStatusRecord> {
        let mut records = self.read_persisted_records();
        let instances = self.instances.read().await;
        for inst in instances.values() {
            let live = self.record_for_instance(inst, true);
            if let Some(existing) = records.iter_mut().find(|r| r.slug == live.slug) {
                *existing = live;
            } else {
                records.push(live);
            }
        }
        records.sort_by(|a, b| a.slug.cmp(&b.slug));
        records
    }

    /// Return one daemon record by slug or exact image reference.
    pub async fn daemon_record(&self, id: &str) -> Option<DaemonStatusRecord> {
        self.daemon_records()
            .await
            .into_iter()
            .find(|record| record.slug == id || record.image_ref == id)
    }

    /// Persist records for every live daemon. This is the safe checkpoint used
    /// by the first sysctl upgrade hook before real FD handoff is added.
    pub async fn checkpoint_records(&self) -> Result<Vec<DaemonStatusRecord>> {
        let instances = self.instances.read().await;
        let mut records = Vec::with_capacity(instances.len());
        for inst in instances.values() {
            self.persist_instance_record(inst, true)?;
            records.push(self.record_for_instance(inst, true));
        }
        Ok(records)
    }

    /// Snapshot of currently-live per-daemon directory slugs (relative to
    /// `{root}/daemons/`). Used to detect stale daemon state directories left
    /// over from prior snapshotter runs.
    pub async fn active_slugs(&self) -> std::collections::HashSet<String> {
        let instances = self.instances.read().await;
        instances.keys().map(|r| slug_for(r)).collect()
    }

    /// Root directory under which per-daemon state lives (`{root}/daemons/`).
    pub fn daemons_root(&self) -> PathBuf {
        self.config.snapshotter.root.join("daemons")
    }

    /// Unmount every running instance. Called on graceful shutdown.
    pub async fn shutdown_all(&self) {
        let mut instances = self.instances.write().await;
        for (image_ref, inst) in instances.drain() {
            info!(image_ref, "shutting down nydus daemon");
            if let Err(e) = stop_instance(&inst) {
                warn!(image_ref, error = %e, "shutdown_all: failed to stop daemon");
            }
            if let Err(e) = self.persist_instance_record(&inst, false) {
                warn!(image_ref, error = %e, "failed to persist stopped daemon record");
            }
        }
    }

    async fn start_instance(
        &self,
        image_ref_str: &str,
        bootstrap: &Path,
    ) -> Result<Arc<DaemonInstance>> {
        let parsed = parse_image_ref(image_ref_str)
            .with_context(|| format!("invalid image reference '{image_ref_str}'"))?;
        let slug = slug_for(image_ref_str);

        let daemon_root = self.config.snapshotter.root.join("daemons").join(&slug);
        let mountpoint = daemon_root.join("mnt");
        let cache_dir = self.config.snapshotter.cache.work_dir.join(&slug);
        let active_driver = self.active_fs_driver();
        fs::create_dir_all(&mountpoint).with_context(|| {
            format!(
                "failed to create daemon mountpoint {}",
                mountpoint.display()
            )
        })?;
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("failed to create blob cache dir {}", cache_dir.display()))?;

        let auth = self.resolve_auth(&parsed);
        let threads = self.config.snapshotter.daemon.threads.max(1) as u32;
        let bti = self.build_info.clone();
        let daemon_id = slug.clone();

        // Keep a poller alive for consistency with daemon instance lifetime.
        // FUSE needs it for the Waker; blockdev does not actively use it.
        let poll = Poll::new().context("failed to create mio Poll for daemon waker")?;
        let waker =
            Arc::new(Waker::new(poll.registry(), Token(1)).context("failed to create mio Waker")?);
        let poll = Arc::new(Mutex::new(poll));

        if active_driver == FsDriverType::Blockdev {
            let blockdev_dir = daemon_root.join("blockdev");
            fs::create_dir_all(&blockdev_dir).with_context(|| {
                format!(
                    "failed to create blockdev directory {}",
                    blockdev_dir.display()
                )
            })?;
            let disk_image = blockdev_dir.join("image.erofs");
            let entry = build_blob_cache_entry(
                &self.config,
                &parsed,
                &cache_dir,
                auth,
                &daemon_id,
                bootstrap,
            )
            .context("failed to build blob cache entry for blockdev export")?;

            let export_disk = disk_image.clone();
            blocking::unblock(move || export_blockdev_image(entry, export_disk, threads))
                .await
                .context("blockdev export failed")?;

            let mount_disk = disk_image.clone();
            let mount_target = mountpoint.clone();
            blocking::unblock(move || mount_blockdev_erofs(mount_disk, mount_target))
                .await
                .context("blockdev mount failed")?;

            let daemon: Arc<dyn NydusDaemon> =
                Arc::new(BlockdevDaemon::new(daemon_id, mountpoint.clone(), bti));

            info!(
                image_ref = %image_ref_str,
                mountpoint = %mountpoint.display(),
                disk = %disk_image.display(),
                "nydus blockdev EROFS mount ready"
            );

            return Ok(Arc::new(DaemonInstance {
                image_ref: image_ref_str.to_string(),
                mountpoint,
                bootstrap: bootstrap.to_path_buf(),
                daemon,
                refcount: AtomicUsize::new(0),
                _poll: poll,
            }));
        }

        let cfg_v2 = build_registry_config(&self.config, &parsed, &cache_dir, auth, &slug);
        let cfg_json =
            serde_json::to_string(&cfg_v2).context("failed to serialise ConfigV2 for nydusd")?;

        let vfs = create_vfs_backend(FsBackendType::Rafs, true, false)
            .context("failed to create RAFS VFS backend")?;

        let mount_cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: bootstrap.display().to_string(),
            config: cfg_json,
            // This is the *virtual* mount path inside fuse-backend-rs' VFS,
            // not the OS FUSE mount directory. Mounting the RAFS backend at
            // the physical path would expose `/var/lib/.../mnt` as directories
            // under the container root. Keep the RAFS tree rooted at `/`.
            mountpoint: "/".to_string(),
            prefetch_files: runtime_prefetch_for_image(image_ref_str),
        };

        let mountpoint_str = mountpoint.display().to_string();

        let daemon = create_fuse_daemon(
            &mountpoint_str,
            vfs,
            None,
            Some(daemon_id),
            threads,
            waker,
            None::<&Path>,
            false,
            true,
            FailoverPolicy::Flush,
            Some(mount_cmd),
            bti,
        )
        .with_context(|| format!("failed to create fuse daemon at {}", mountpoint.display()))?;

        wait_for_running(&*daemon, self.startup_timeout)
            .with_context(|| format!("nydus daemon for {image_ref_str} never reached RUNNING"))?;

        info!(
            image_ref = %image_ref_str,
            mountpoint = %mountpoint.display(),
            "nydus daemon ready"
        );

        Ok(Arc::new(DaemonInstance {
            image_ref: image_ref_str.to_string(),
            mountpoint,
            bootstrap: bootstrap.to_path_buf(),
            daemon,
            refcount: AtomicUsize::new(0),
            _poll: poll,
        }))
    }

    fn active_fs_driver(&self) -> FsDriverType {
        self.config
            .snapshotter
            .fs_drivers
            .first()
            .map(|driver| driver.driver_type.clone())
            .unwrap_or(FsDriverType::Fusedev)
    }

    async fn upgrade_selected_instances(
        &self,
        targets: Vec<String>,
        options: DaemonUpgradeOptions,
    ) -> Result<DaemonUpgradeReport> {
        let mut report = DaemonUpgradeReport {
            attempted: targets.len(),
            ..DaemonUpgradeReport::default()
        };
        if targets.is_empty() {
            report.records = self.daemon_records().await;
            return Ok(report);
        }

        let mut instances = self.instances.write().await;
        for image_ref in targets {
            let Some(old) = instances.remove(&image_ref) else {
                report.skipped += 1;
                report.outcomes.push(DaemonUpgradeOutcome {
                    image_ref: image_ref.clone(),
                    slug: slug_for(&image_ref),
                    status: "missing".to_string(),
                    before_state: "UNKNOWN".to_string(),
                    after_state: None,
                    refcount: 0,
                    error: None,
                });
                continue;
            };

            let slug = slug_for(&image_ref);
            let before_state = format!("{:?}", old.daemon.get_state());
            let refcount = old.refcount.load(Ordering::SeqCst);
            if refcount > 0 && !options.allow_active {
                instances.insert(image_ref.clone(), old);
                report.skipped += 1;
                report.outcomes.push(DaemonUpgradeOutcome {
                    image_ref,
                    slug,
                    status: "skipped_active".to_string(),
                    before_state,
                    after_state: None,
                    refcount,
                    error: None,
                });
                continue;
            }

            if let Err(e) = old.daemon.save() {
                instances.insert(image_ref.clone(), old);
                report.failed += 1;
                report.outcomes.push(DaemonUpgradeOutcome {
                    image_ref,
                    slug,
                    status: "save_failed".to_string(),
                    before_state,
                    after_state: None,
                    refcount,
                    error: Some(e.to_string()),
                });
                continue;
            }

            let bootstrap = old.bootstrap.clone();
            if let Err(e) = stop_instance(&old) {
                warn!(image_ref, error = %e, "failed to stop daemon during upgrade");
            }
            if let Err(e) = self.persist_instance_record(&old, false) {
                warn!(image_ref, error = %e, "failed to persist stopped daemon record");
            }

            match self.start_instance(&image_ref, &bootstrap).await {
                Ok(instance) => {
                    instance.refcount.store(refcount, Ordering::SeqCst);
                    let after_state = format!("{:?}", instance.daemon.get_state());
                    if let Err(e) = self.persist_instance_record(&instance, true) {
                        warn!(image_ref, error = %e, "failed to persist upgraded daemon record");
                    }
                    instances.insert(image_ref.clone(), instance);
                    report.upgraded += 1;
                    report.outcomes.push(DaemonUpgradeOutcome {
                        image_ref,
                        slug,
                        status: "restarted".to_string(),
                        before_state,
                        after_state: Some(after_state),
                        refcount,
                        error: None,
                    });
                }
                Err(e) => {
                    report.failed += 1;
                    report.outcomes.push(DaemonUpgradeOutcome {
                        image_ref,
                        slug,
                        status: "start_failed".to_string(),
                        before_state,
                        after_state: None,
                        refcount,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        drop(instances);
        report.records = self.daemon_records().await;
        Ok(report)
    }

    fn resolve_auth(&self, _image_ref: &ImageRef) -> Option<String> {
        auth::resolve_auth(&self.config, _image_ref)
    }

    fn record_dir(&self) -> PathBuf {
        self.daemons_root().join("records")
    }

    fn record_path(&self, slug: &str) -> PathBuf {
        self.record_dir().join(format!("{slug}.json"))
    }

    fn record_for_instance(&self, inst: &DaemonInstance, live: bool) -> DaemonStatusRecord {
        DaemonStatusRecord {
            image_ref: inst.image_ref.clone(),
            slug: slug_for(&inst.image_ref),
            mountpoint: inst.mountpoint.clone(),
            bootstrap: inst.bootstrap.clone(),
            refcount: if live {
                inst.refcount.load(Ordering::SeqCst)
            } else {
                0
            },
            state: if live {
                format!("{:?}", inst.daemon.get_state())
            } else {
                "STOPPED".to_string()
            },
            live,
            updated_at: unix_now(),
        }
    }

    fn persist_instance_record(&self, inst: &DaemonInstance, live: bool) -> Result<()> {
        let record = self.record_for_instance(inst, live);
        fs::create_dir_all(self.record_dir()).with_context(|| {
            format!(
                "failed to create daemon record directory {}",
                self.record_dir().display()
            )
        })?;
        let encoded =
            serde_json::to_vec_pretty(&record).context("failed to encode daemon record")?;
        fs::write(self.record_path(&record.slug), encoded).with_context(|| {
            format!(
                "failed to persist daemon record {}",
                self.record_path(&record.slug).display()
            )
        })
    }

    fn read_persisted_records(&self) -> Vec<DaemonStatusRecord> {
        let entries = match fs::read_dir(self.record_dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                warn!(error = %e, "failed to read daemon records directory");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            match fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<DaemonStatusRecord>(&bytes).ok())
            {
                Some(record) => out.push(record),
                None => warn!(path = %entry.path().display(), "failed to decode daemon record"),
            }
        }
        out
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn validate_spawn_request(image_ref: &str, bootstrap: &Path) -> Result<()> {
    if image_ref.trim().is_empty() {
        bail!("image reference must be non-empty to mount a Nydus image");
    }
    if !bootstrap.is_file() {
        bail!(
            "bootstrap {} is missing - is the meta layer extracted?",
            bootstrap.display()
        );
    }
    Ok(())
}

fn is_healthy_state(state: DaemonState) -> bool {
    matches!(state, DaemonState::RUNNING | DaemonState::READY)
}

fn service_io_error(error: io::Error) -> ServiceError {
    ServiceError::WaitDaemon(error)
}

#[cfg(target_os = "linux")]
fn export_blockdev_image(
    entry: nydus_api::BlobCacheEntry,
    disk_image: PathBuf,
    threads: u32,
) -> Result<()> {
    if disk_image.is_file() && disk_image.metadata().map(|m| m.len()).unwrap_or(0) > 0 {
        return Ok(());
    }
    if let Some(parent) = disk_image.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create blockdev disk image directory {}",
                parent.display()
            )
        })?;
    }
    BlockDevice::export(
        entry,
        Some(disk_image.display().to_string()),
        None,
        threads,
        false,
    )
    .with_context(|| {
        format!(
            "failed to export blockdev disk image {}",
            disk_image.display()
        )
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn export_blockdev_image(
    _entry: nydus_api::BlobCacheEntry,
    _disk_image: PathBuf,
    _threads: u32,
) -> Result<()> {
    bail!("blockdev EROFS export requires Linux")
}

#[cfg(target_os = "linux")]
fn mount_blockdev_erofs(disk_image: PathBuf, mountpoint: PathBuf) -> Result<()> {
    fs::create_dir_all(&mountpoint).with_context(|| {
        format!(
            "failed to create blockdev EROFS mountpoint {}",
            mountpoint.display()
        )
    })?;
    if is_mounted_at(&mountpoint) {
        return Ok(());
    }
    let status = Command::new("mount")
        .args(["-t", "erofs", "-o", "ro,loop"])
        .arg(&disk_image)
        .arg(&mountpoint)
        .status()
        .with_context(|| format!("failed to execute mount for {}", disk_image.display()))?;
    if !status.success() {
        bail!(
            "mount -t erofs -o ro,loop {} {} failed with {}",
            disk_image.display(),
            mountpoint.display(),
            status
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_blockdev_erofs(_disk_image: PathBuf, _mountpoint: PathBuf) -> Result<()> {
    bail!("blockdev EROFS mount requires Linux")
}

#[cfg(target_os = "linux")]
fn unmount_blockdev_erofs(mountpoint: &Path) -> io::Result<()> {
    if !is_mounted_at(mountpoint) {
        return Ok(());
    }
    let status = Command::new("umount").arg(mountpoint).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "umount {} failed with {}",
            mountpoint.display(),
            status
        )))
    }
}

#[cfg(not(target_os = "linux"))]
fn unmount_blockdev_erofs(_mountpoint: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_mounted_at(mountpoint: &Path) -> bool {
    let target = mountpoint.display().to_string();
    let escaped = target.replace(' ', "\\040");
    fs::read_to_string("/proc/self/mounts")
        .map(|mounts| {
            mounts.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|path| path == target || path == escaped)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn stop_instance(inst: &DaemonInstance) -> Result<()> {
    debug!(image_ref = %inst.image_ref, "stopping nydus daemon");
    if let Err(e) = inst.daemon.trigger_stop() {
        warn!(image_ref = %inst.image_ref, error = %e, "trigger_stop failed");
    }
    if let Err(e) = inst.daemon.umount() {
        warn!(image_ref = %inst.image_ref, error = %e, "umount failed");
    }
    if let Err(e) = inst.daemon.wait() {
        warn!(image_ref = %inst.image_ref, error = %e, "wait failed");
    }
    if let Err(e) = fs::remove_dir(&inst.mountpoint) {
        debug!(
            image_ref = %inst.image_ref,
            error = %e,
            "could not remove daemon mountpoint (likely already gone)"
        );
    }
    Ok(())
}

fn wait_for_running(daemon: &dyn NydusDaemon, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match daemon.get_state() {
            DaemonState::RUNNING => return Ok(()),
            DaemonState::INIT | DaemonState::READY => {}
            other => bail!("nydus daemon entered unexpected state {:?}", other),
        }
        if Instant::now() >= deadline {
            bail!("nydus daemon did not reach RUNNING within {:?}", timeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stable filesystem-safe slug for a per-image directory name.
pub fn slug_for(image_ref: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image_ref.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let sanitized: String = image_ref
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    if sanitized.is_empty() {
        hex
    } else {
        format!("{hex}-{sanitized}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_deterministic_and_sanitised() {
        let a = slug_for("docker.io/library/nginx:latest");
        let b = slug_for("docker.io/library/nginx:latest");
        assert_eq!(a, b);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        );
        assert_ne!(
            slug_for("docker.io/library/nginx:1"),
            slug_for("docker.io/library/nginx:2")
        );
    }

    #[test]
    fn supervisor_uses_promoted_fs_driver() {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.fs_drivers.swap(0, 1);
        let supervisor = DaemonSupervisor::new(config);

        assert_eq!(supervisor.active_fs_driver(), FsDriverType::Blockdev);
    }

    #[test]
    fn blockdev_daemon_state_transitions_are_safe() {
        let daemon = BlockdevDaemon::new(
            "blockdev-test".to_string(),
            PathBuf::from("/tmp/nydus-blockdev-test"),
            BuildTimeInfo {
                package_ver: "test".to_string(),
                git_commit: String::new(),
                build_time: String::new(),
                profile: "test".to_string(),
                rustc: String::new(),
            },
        );

        assert_eq!(daemon.get_state(), DaemonState::RUNNING);
        daemon.on_event(DaemonStateMachineInput::Stop).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::STOPPED);
        daemon.on_event(DaemonStateMachineInput::Mount).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::READY);
        daemon.on_event(DaemonStateMachineInput::Start).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::RUNNING);
        assert!(daemon.save().is_ok());
        assert!(daemon.restore().is_ok());
    }
}
