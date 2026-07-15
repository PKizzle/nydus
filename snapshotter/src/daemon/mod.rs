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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
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
use nydus_service::{
    FsBackendMountCmd, FsBackendType, create_daemon, create_fuse_daemon, create_vfs_backend,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::{FsDriverType, SnapshotterConfig};
use crate::daemon::config_builder::{
    build_auto_accel_config, build_blob_cache_entry, build_daemon_config,
};
use crate::daemon::image_ref::{ImageRef, parse_image_ref};
use crate::prefetch_profile::runtime_prefetch_for_image;

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
    /// PID to target for failover (`kill -9`) of this daemon. The Rust
    /// snapshotter runs daemons in-process, so a live daemon's PID is the
    /// snapshotter's own PID (0 when stopped). Serialized as `pid` for the
    /// system-controller API; `#[serde(default)]` keeps older on-disk records
    /// (written before this field existed) loadable.
    #[serde(default)]
    pub pid: u32,
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
    /// Snapshot keys currently holding a reference on this daemon. Acquisition
    /// is idempotent per key (`acquire_holder`): repeated `Mounts` RPCs for the
    /// same snapshot must not inflate `refcount`, or the daemon becomes
    /// immortal. `refcount` can exceed `holders.len()` after a restore: the
    /// persisted record carries only a count, not the keys, so the difference
    /// is "ballast" that `release_holder` drains on releases for unknown keys
    /// (pre-restart holders being removed).
    holders: StdMutex<HashSet<String>>,
    /// Mio poller kept alive for the entire lifetime of the daemon - the
    /// `Waker` passed into `create_fuse_daemon` borrows its registry.
    _poll: Arc<Mutex<Poll>>,
    /// Whether this daemon's `/dev/fuse` fd was parked in systemd's store, i.e.
    /// a successor can take its mount over. When false, the mount must be
    /// unmounted on shutdown rather than left held (which would wedge in D-state).
    failover_armed: AtomicBool,
}

impl DaemonInstance {
    /// Idempotently register `holder` (a snapshot key) as a user of this
    /// daemon. Only the first acquisition per key bumps `refcount`.
    fn acquire_holder(&self, holder: &str) {
        let mut holders = self.holders.lock().unwrap();
        if holders.insert(holder.to_string()) {
            self.refcount.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Drop `holder`'s reference and return the remaining refcount.
    ///
    /// A release for a key that never acquired is a no-op — unless `refcount`
    /// still exceeds the tracked holder count, in which case the release drains
    /// restore ballast (see the `holders` field docs) so restored daemons can
    /// still reach zero and tear down.
    fn release_holder(&self, holder: &str) -> usize {
        let mut holders = self.holders.lock().unwrap();
        let tracked = holders.remove(holder);
        let current = self.refcount.load(Ordering::SeqCst);
        if tracked || current > holders.len() {
            if current == 0 {
                return 0;
            }
            self.refcount
                .fetch_sub(1, Ordering::SeqCst)
                .saturating_sub(1)
        } else {
            current
        }
    }
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

/// Platform-agnostic mirror of `nydus_service::block_device::BlockDeviceVerityInfo`
/// (which is Linux-only). Kept local so the tarfs serving branch and its helpers
/// — which compile on every platform — never name the Linux-gated type; only the
/// `#[cfg(target_os = "linux")]` export path converts from it.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct TarfsVerityParams {
    data_block_size: u64,
    data_blocks: u32,
    hash_offset: u64,
    root_digest: String,
}

/// What was set up to back a tarfs mount, tracked so teardown can undo it in
/// the reverse order (umount → veritysetup close → losetup detach).
#[derive(Clone, Debug, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct TarfsMount {
    /// Loop device the `.disk` was attached to (verity path only; the plain
    /// path lets the kernel attach the loop implicitly at mount time).
    loop_dev: Option<String>,
    /// dm-verity mapping name opened over the loop device (verity path only).
    verity_name: Option<String>,
}

/// Lightweight daemon facade for the host-mounted tarfs/EROFS(+dm-verity) path.
/// Like [`BlockdevDaemon`] it is just a lifecycle shell over a kernel mount, but
/// its `umount()` additionally tears down the dm-verity mapping and loop device.
struct TarfsDaemon {
    id: String,
    mountpoint: PathBuf,
    build_info: BuildTimeInfo,
    state: AtomicI32,
    mount: TarfsMount,
    config: crate::config::TarfsConfig,
}

impl TarfsDaemon {
    fn new(
        id: String,
        mountpoint: PathBuf,
        build_info: BuildTimeInfo,
        mount: TarfsMount,
        config: crate::config::TarfsConfig,
    ) -> Self {
        Self {
            id,
            mountpoint,
            build_info,
            state: AtomicI32::new(DaemonState::RUNNING as i32),
            mount,
            config,
        }
    }
}

impl DaemonStateMachineSubscriber for TarfsDaemon {
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

impl NydusDaemon for TarfsDaemon {
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
        teardown_tarfs_mount(&self.config, &self.mount, &self.mountpoint).map_err(service_io_error)
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
    /// Per-image startup serialization. Daemon startup (mount syscalls plus a
    /// wait-for-RUNNING loop of up to `startup_timeout`) must never run while
    /// holding the global `instances` write lock — that would stall every other
    /// gRPC RPC behind one slow daemon. Instead, concurrent ensures of the
    /// *same* image take turns on its entry here while ensures of other images
    /// proceed untouched. Entries are never evicted; the map is bounded by the
    /// number of distinct images the node has served.
    start_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
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
            start_locks: Mutex::new(HashMap::new()),
            startup_timeout: Duration::from_secs(30),
        }
    }

    /// Take the per-image startup lock for `image_ref` (see `start_locks`).
    async fn start_lock(&self, image_ref: &str) -> Arc<Mutex<()>> {
        let mut locks = self.start_locks.lock().await;
        locks.entry(image_ref.to_string()).or_default().clone()
    }

    /// Fast path shared by the `ensure_*` entry points: if a healthy daemon for
    /// `image_ref` already serves `bootstrap`, register `holder` on it and
    /// return a handle. `None` means the caller must take the slow (startup)
    /// path.
    async fn try_reuse_instance(
        &self,
        image_ref: &str,
        bootstrap: &Path,
        holder: &str,
    ) -> Option<Arc<MountHandle>> {
        let instances = self.instances.read().await;
        let inst = instances.get(image_ref)?;
        if inst.bootstrap != bootstrap
            || !matches!(
                inst.daemon.get_state(),
                DaemonState::RUNNING | DaemonState::READY
            )
        {
            return None;
        }
        inst.acquire_holder(holder);
        if let Err(e) = self.persist_instance_record(inst, true) {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Some(Arc::new(MountHandle {
            image_ref: image_ref.to_string(),
            mountpoint: inst.mountpoint.clone(),
            daemon: inst.daemon.clone(),
        }))
    }

    /// Slow-path guard shared by the `ensure_*` entry points, run under the
    /// per-image start lock: refuse to replace a *healthy* daemon that serves
    /// different content (its mount is live — replacing would leak its FUSE
    /// threads and stack a new mount over the held one), and stop + remove an
    /// unhealthy one before the caller starts a replacement. Mirrors
    /// `spawn_instance`.
    async fn evict_replaceable_instance(&self, image_ref: &str, bootstrap: &Path) -> Result<()> {
        let mut instances = self.instances.write().await;
        if let Some(inst) = instances.get(image_ref) {
            if is_healthy_state(inst.daemon.get_state()) {
                bail!(
                    "daemon {image_ref} is already serving bootstrap {}; refusing to replace it \
                     with {} while it is healthy",
                    inst.bootstrap.display(),
                    bootstrap.display()
                );
            }
            if let Some(old) = instances.remove(image_ref) {
                warn!(image_ref, "replacing unhealthy daemon");
                if let Err(e) = stop_instance(&old) {
                    warn!(image_ref, error = %e, "failed to stop unhealthy daemon before replacement");
                }
                if let Err(e) = self.persist_instance_record(&old, false) {
                    warn!(image_ref, error = %e, "failed to persist stopped daemon record");
                }
            }
        }
        Ok(())
    }

    /// Start or retrieve a FUSE daemon serving `image_ref` from `bootstrap`.
    ///
    /// `holder` is the snapshot key requesting the mount; acquisition is
    /// idempotent per key, so repeated calls for the same snapshot (containerd
    /// re-issues `Mounts` on every container restart) do not inflate the
    /// refcount. Balance with [`release`](Self::release) using the same key.
    /// `driver_override` forces a specific fs driver for this image (from the
    /// per-image `containerd.io/snapshot/nydus-fs-driver` label); `None` uses
    /// the node's promoted default. Only honored on the fresh-start path — a
    /// reused instance keeps whatever driver it was started with.
    pub async fn ensure_instance(
        &self,
        image_ref: &str,
        bootstrap: &Path,
        holder: &str,
        driver_override: Option<FsDriverType>,
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

        if let Some(handle) = self.try_reuse_instance(image_ref, bootstrap, holder).await {
            return Ok(handle);
        }

        // Startup path: serialize per image, never under the global lock.
        let start_lock = self.start_lock(image_ref).await;
        let _guard = start_lock.lock().await;

        if let Some(handle) = self.try_reuse_instance(image_ref, bootstrap, holder).await {
            return Ok(handle);
        }
        self.evict_replaceable_instance(image_ref, bootstrap)
            .await?;

        let instance = self
            .start_instance(image_ref, bootstrap, driver_override)
            .await
            .with_context(|| format!("failed to start nydus daemon for {image_ref}"))?;
        instance.acquire_holder(holder);
        let handle = MountHandle {
            image_ref: image_ref.to_string(),
            mountpoint: instance.mountpoint.clone(),
            daemon: instance.daemon.clone(),
        };
        let mut instances = self.instances.write().await;
        instances.insert(image_ref.to_string(), instance);
        if let Some(inst) = instances.get(image_ref)
            && let Err(e) = self.persist_instance_record(inst, true)
        {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Ok(Arc::new(handle))
    }

    /// Ensure an **auto-accel** daemon for `image_ref` is mounted, then return
    /// its mountpoint handle. This is the read side of the node-local
    /// acceleration flow: the bootstrap was produced by `local_accel::convert`
    /// and the `backend_dir` already contains symlinks to the gzip layers in
    /// containerd's content store plus the per-layer zran index blobs (and an
    /// optional packed prefetch blob).
    ///
    /// Dedup is by `image_ref`, same as `ensure_instance`. A daemon already
    /// running with a different mount source for the same image (e.g. a
    /// *registry*-backend daemon from the referrer path) is never replaced
    /// while healthy — `evict_replaceable_instance` bails and the caller falls
    /// back to the overlay path; an unhealthy one is stopped and replaced.
    /// `holder` follows the same idempotent-per-snapshot-key contract as
    /// [`ensure_instance`](Self::ensure_instance).
    pub async fn ensure_instance_local(
        &self,
        image_ref: &str,
        bootstrap: &Path,
        backend_dir: &Path,
        holder: &str,
    ) -> Result<Arc<MountHandle>> {
        if image_ref.is_empty() {
            bail!("image reference must be non-empty to mount an auto-accel sidecar");
        }
        if !bootstrap.is_file() {
            bail!(
                "auto-accel bootstrap {} is missing - was local_accel::convert run?",
                bootstrap.display()
            );
        }
        if !backend_dir.is_dir() {
            bail!(
                "auto-accel backend dir {} is missing",
                backend_dir.display()
            );
        }

        if let Some(handle) = self.try_reuse_instance(image_ref, bootstrap, holder).await {
            return Ok(handle);
        }

        let start_lock = self.start_lock(image_ref).await;
        let _guard = start_lock.lock().await;

        if let Some(handle) = self.try_reuse_instance(image_ref, bootstrap, holder).await {
            return Ok(handle);
        }
        self.evict_replaceable_instance(image_ref, bootstrap)
            .await?;

        let instance = self
            .start_local_instance(image_ref, bootstrap, backend_dir)
            .await
            .with_context(|| format!("failed to start auto-accel daemon for {image_ref}"))?;
        instance.acquire_holder(holder);
        let handle = MountHandle {
            image_ref: image_ref.to_string(),
            mountpoint: instance.mountpoint.clone(),
            daemon: instance.daemon.clone(),
        };
        let mut instances = self.instances.write().await;
        instances.insert(image_ref.to_string(), instance);
        if let Some(inst) = instances.get(image_ref)
            && let Err(e) = self.persist_instance_record(inst, true)
        {
            warn!(image_ref, error = %e, "failed to persist daemon record");
        }
        Ok(Arc::new(handle))
    }

    /// Spawn an in-process auto-accel daemon. Mirrors the FUSE start path in
    /// `start_instance` but uses `nydus_service::create_daemon` (the
    /// fanotify-singleton flavour) instead of `create_fuse_daemon`. The
    /// resulting daemon mounts EROFS directly via fanotify; gzip-layer reads
    /// are served on demand by `FanotifyHandler` which decompresses the
    /// per-layer zran ranges into the file cache.
    async fn start_local_instance(
        &self,
        image_ref_str: &str,
        bootstrap: &Path,
        backend_dir: &Path,
    ) -> Result<Arc<DaemonInstance>> {
        let slug = slug_for(image_ref_str);
        let daemon_root = self.config.snapshotter.root.join("daemons").join(&slug);
        let mountpoint = daemon_root.join("mnt");
        // The fanotify cache `work_dir` doubles as the EROFS staging dir: the
        // fanotify handler self-stages device files as hardlinks to the
        // per-layer cache files inside it (CLAUDE.md §"Fanotify on-demand
        // runtime constraints"). Keep it next to the daemon dir so per-image
        // cleanup is one `rm -rf`.
        let stage_dir = daemon_root.join("stage");
        fs::create_dir_all(&mountpoint).with_context(|| {
            format!(
                "failed to create daemon mountpoint {}",
                mountpoint.display()
            )
        })?;
        fs::create_dir_all(&stage_dir).with_context(|| {
            format!(
                "failed to create fanotify stage dir {}",
                stage_dir.display()
            )
        })?;
        // Copy the bootstrap into the stage dir so the fanotify handler finds
        // it under the expected `bootstrap` filename (see
        // `service/src/fanotify.rs::discover_blobs`).
        let staged_bootstrap = stage_dir.join("bootstrap");
        fs::copy(bootstrap, &staged_bootstrap).with_context(|| {
            format!(
                "failed to stage bootstrap {} -> {}",
                bootstrap.display(),
                staged_bootstrap.display()
            )
        })?;

        let threads = self.config.snapshotter.daemon.threads.max(1) as u32;
        let bti = self.build_info.clone();
        let daemon_id = slug.clone();

        let poll = Poll::new().context("failed to create mio Poll for daemon waker")?;
        let waker =
            Arc::new(Waker::new(poll.registry(), Token(1)).context("failed to create mio Waker")?);
        let poll = Arc::new(Mutex::new(poll));

        let cfg_v2 = build_auto_accel_config(backend_dir, &stage_dir, &mountpoint, &daemon_id);
        let cfg_json =
            serde_json::to_value(&cfg_v2).context("failed to serialise auto-accel ConfigV2")?;

        let supervisor_sock = supervisor_sock_path(&slug);
        let backend_dir_str = backend_dir.display().to_string();
        let mountpoint_str = mountpoint.display().to_string();
        let threads_str = threads.to_string();
        let daemon = create_daemon(
            Some(daemon_id.clone()),
            Some(supervisor_sock.display().to_string()),
            Some(&backend_dir_str),
            Some(&mountpoint_str),
            Some(threads_str.as_str()),
            Some(cfg_json),
            bti,
            waker,
            None::<&Path>,
            false,
        )
        .map_err(|e| anyhow::anyhow!("failed to create auto-accel fanotify daemon: {e}"))?;

        wait_for_running_off_reactor(daemon.clone(), self.startup_timeout)
            .await
            .with_context(|| {
                format!("auto-accel daemon for {image_ref_str} never reached RUNNING")
            })?;

        info!(
            image_ref = %image_ref_str,
            mountpoint = %mountpoint.display(),
            backend = %backend_dir.display(),
            "auto-accel fanotify daemon ready"
        );

        // Failover armed via fdstore — same code path the registry-backed
        // FUSE start uses; the snapshot also covers the fanotify group fd
        // because the FanotifyHandler is registered in the singleton's
        // ServiceController before READY.
        let armed = self
            .park_failover_state(&slug, &daemon, &supervisor_sock, &daemon_root)
            .await;

        Ok(Arc::new(DaemonInstance {
            image_ref: image_ref_str.to_string(),
            mountpoint,
            bootstrap: bootstrap.to_path_buf(),
            daemon,
            refcount: AtomicUsize::new(0),
            holders: StdMutex::new(HashSet::new()),
            failover_armed: AtomicBool::new(armed),
            _poll: poll,
        }))
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
            .start_instance(image_ref, bootstrap, None)
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

    /// Drop `holder`'s reference on the daemon serving `image_ref` and tear the
    /// daemon down if no holders remain. A release for a key that never
    /// acquired is a no-op (modulo restore ballast — see `DaemonInstance::holders`),
    /// so double-removes cannot underflow another snapshot's reference.
    pub async fn release(&self, image_ref: &str, holder: &str) -> Result<()> {
        let mut instances = self.instances.write().await;
        let should_stop = if let Some(inst) = instances.get(image_ref) {
            inst.release_holder(holder) == 0
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

            match self.start_instance(&image_ref, &bootstrap, None).await {
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

    /// Persist records for every live daemon. Backs the system-controller
    /// checkpoint API; failover restore pairs these records with fds preserved
    /// in systemd's store.
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

    /// Name of the subdirectory of [`Self::daemons_root`] that holds persisted
    /// [`DaemonStatusRecord`] JSONs. It is not a per-image slug directory, so
    /// the reconciler's stale-daemon-dir sweep must never remove it — failover
    /// restore pairs these records with preserved fds after a crash.
    pub const RECORDS_DIRNAME: &'static str = "records";

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

    /// Prepare for a failover restart: leave mounts whose fuse fd is parked in
    /// systemd's store held (the successor takes them over), but unmount any
    /// daemon that is NOT armed — leaving an unrecoverable mount held would wedge
    /// any container that touches it in uninterruptible (D) state. The caller
    /// must then exit *without* running destructors so the armed mounts survive.
    pub async fn preserve_for_failover(&self) {
        let instances = self.instances.read().await;
        for (image_ref, inst) in instances.iter() {
            if inst.failover_armed.load(Ordering::SeqCst) {
                debug!(image_ref, "leaving mount held for failover takeover");
            } else {
                info!(
                    image_ref,
                    "failover not armed for this image; unmounting to avoid a stuck mount"
                );
                if let Err(e) = stop_instance(inst) {
                    warn!(image_ref, error = %e, "failed to unmount un-armed daemon on shutdown");
                }
            }
        }
    }

    async fn start_instance(
        &self,
        image_ref_str: &str,
        bootstrap: &Path,
        driver_override: Option<FsDriverType>,
    ) -> Result<Arc<DaemonInstance>> {
        let parsed = parse_image_ref(image_ref_str)
            .with_context(|| format!("invalid image reference '{image_ref_str}'"))?;
        let slug = slug_for(image_ref_str);

        let daemon_root = self.config.snapshotter.root.join("daemons").join(&slug);
        let mountpoint = daemon_root.join("mnt");
        let cache_dir = self.config.snapshotter.cache.work_dir.join(&slug);
        let active_driver = driver_override.unwrap_or_else(|| self.active_fs_driver());
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
                holders: StdMutex::new(HashSet::new()),
                _poll: poll,
                // Blockdev/EROFS export has no fuse fd to preserve.
                failover_armed: AtomicBool::new(false),
            }));
        }

        if active_driver == FsDriverType::Tarfs {
            let tarfs_cfg = self.config.snapshotter.tarfs.clone();
            let tarfs_dir = daemon_root.join("tarfs");
            fs::create_dir_all(&tarfs_dir).with_context(|| {
                format!("failed to create tarfs directory {}", tarfs_dir.display())
            })?;
            let disk_image = tarfs_dir.join("image.erofs");
            // The bootstrap must be a tarfs (TARTFS_MODE) RAFS v6 image; the
            // 512-byte block mode is auto-detected downstream from that flag, so
            // the export/mount below are byte-compatible with an upstream
            // `nydus-image export --block` artifact.
            let entry = build_blob_cache_entry(
                &self.config,
                &parsed,
                &cache_dir,
                auth,
                &daemon_id,
                bootstrap,
            )
            .context("failed to build blob cache entry for tarfs export")?;

            let export_disk = disk_image.clone();
            let verity = tarfs_cfg.verity;
            let verity_info =
                blocking::unblock(move || export_tarfs_image(entry, export_disk, threads, verity))
                    .await
                    .context("tarfs export failed")?;

            let dm_name = tarfs_dm_name(&slug);
            let mount_disk = disk_image.clone();
            let mount_target = mountpoint.clone();
            let cfg_for_mount = tarfs_cfg.clone();
            let dm_for_mount = dm_name.clone();
            let verity_for_mount = verity_info.clone();
            let tarfs_mount = blocking::unblock(move || {
                setup_and_mount_tarfs(
                    &cfg_for_mount,
                    &mount_disk,
                    &mount_target,
                    &dm_for_mount,
                    verity_for_mount.as_ref(),
                )
            })
            .await
            .context("tarfs mount failed")?;

            let daemon: Arc<dyn NydusDaemon> = Arc::new(TarfsDaemon::new(
                daemon_id,
                mountpoint.clone(),
                bti,
                tarfs_mount,
                tarfs_cfg,
            ));

            info!(
                image_ref = %image_ref_str,
                mountpoint = %mountpoint.display(),
                disk = %disk_image.display(),
                verity = verity_info.is_some(),
                "nydus tarfs EROFS mount ready"
            );

            return Ok(Arc::new(DaemonInstance {
                image_ref: image_ref_str.to_string(),
                mountpoint,
                bootstrap: bootstrap.to_path_buf(),
                daemon,
                refcount: AtomicUsize::new(0),
                holders: StdMutex::new(HashSet::new()),
                _poll: poll,
                // Tarfs is a kernel mount; there is no fuse fd to preserve.
                failover_armed: AtomicBool::new(false),
            }));
        }

        let cfg_v2 = build_daemon_config(&self.config, &parsed, &cache_dir, auth, &slug)?;
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

        // Give the daemon a supervisor socket so its upgrade manager records
        // mount state and holds the `/dev/fuse` fd. `save()` is driven into
        // that socket right after start to snapshot the fd + state for failover.
        let supervisor_sock = supervisor_sock_path(&slug);
        let daemon = create_fuse_daemon(
            &mountpoint_str,
            vfs,
            Some(supervisor_sock.display().to_string()),
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

        wait_for_running_off_reactor(daemon.clone(), self.startup_timeout)
            .await
            .with_context(|| format!("nydus daemon for {image_ref_str} never reached RUNNING"))?;

        info!(
            image_ref = %image_ref_str,
            mountpoint = %mountpoint.display(),
            "nydus daemon ready"
        );

        // Snapshot the daemon's fuse fd + serialized state and park them so the
        // mount survives a snapshotter restart / kill -9 (see `failover` /
        // `fdstore`). Best-effort: a failure here only disables failover for this
        // image, it must not fail the mount the container is waiting on.
        let armed = self
            .park_failover_state(&slug, &daemon, &supervisor_sock, &daemon_root)
            .await;

        Ok(Arc::new(DaemonInstance {
            image_ref: image_ref_str.to_string(),
            mountpoint,
            bootstrap: bootstrap.to_path_buf(),
            daemon,
            refcount: AtomicUsize::new(0),
            holders: StdMutex::new(HashSet::new()),
            failover_armed: AtomicBool::new(armed),
            _poll: poll,
        }))
    }

    /// Path of the on-disk serialized upgrade state for a daemon slug.
    fn failover_state_path(&self, slug: &str) -> PathBuf {
        self.daemons_root().join(slug).join("upgrade.state")
    }

    /// Capture a daemon's `/dev/fuse` fd + serialized state (by driving `save()`
    /// into a one-shot supervisor socket) and park them in systemd's fd store +
    /// on disk, so a successor process can take the mount over. Best-effort.
    ///
    /// Returns `true` when the fd was actually parked in systemd's store (so the
    /// mount can be taken over later); `false` means failover is not armed for
    /// this image and the caller must unmount it on shutdown rather than leave a
    /// kernel mount no successor can recover.
    async fn park_failover_state(
        &self,
        slug: &str,
        daemon: &Arc<dyn NydusDaemon>,
        supervisor_sock: &Path,
        daemon_root: &Path,
    ) -> bool {
        if let Some(parent) = supervisor_sock.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            warn!(slug, error = %e, dir = %parent.display(), "failed to create failover socket dir; failover disabled for this image");
            return false;
        }

        let daemon = daemon.clone();
        let sock = supervisor_sock.to_path_buf();
        let captured = blocking::unblock(move || {
            crate::failover::capture_on_save(&sock, || {
                daemon
                    .save()
                    .map_err(|e| anyhow::anyhow!("daemon save(): {e}"))
            })
        })
        .await;

        let (fuse_fd, state) = match captured {
            Ok(parts) => parts,
            Err(e) => {
                warn!(slug, error = %e, "failed to snapshot daemon state; failover disabled for this image");
                return false;
            }
        };

        let state_path = daemon_root.join("upgrade.state");
        if let Err(e) = fs::write(&state_path, &state) {
            warn!(slug, error = %e, "failed to persist failover state blob; failover disabled for this image");
            return false;
        }
        match crate::fdstore::store_fd(slug, fuse_fd.as_raw_fd()) {
            Ok(true) => {
                info!(slug, "parked fuse fd in systemd fd store for failover");
                true
            }
            Ok(false) => {
                debug!(
                    slug,
                    "no systemd fd store (NOTIFY_SOCKET unset); failover unavailable"
                );
                let _ = fs::remove_file(&state_path);
                false
            }
            Err(e) => {
                warn!(slug, error = %e, "failed to store fuse fd in systemd fd store");
                false
            }
        }
        // `fuse_fd` (the local copy) is dropped here; systemd holds its own dup.
    }

    /// Resume daemons whose `/dev/fuse` fds systemd preserved across our restart
    /// (or `kill -9`), so containers never see their mount disappear. Returns the
    /// number of daemons restored. Best-effort per daemon; call once at startup
    /// before serving gRPC.
    pub async fn restore_from_store(&self) -> usize {
        let stored = crate::fdstore::take_stored_fds();
        if stored.is_empty() {
            return 0;
        }
        let records = self.read_persisted_records();
        let by_slug: HashMap<&str, &DaemonStatusRecord> = records
            .iter()
            .filter(|r| r.live)
            .map(|r| (r.slug.as_str(), r))
            .collect();

        let mut restored = 0;
        for (slug, fds) in &stored {
            let Some(record) = by_slug.get(slug.as_str()) else {
                warn!(slug, "preserved fd has no live daemon record; dropping it");
                continue;
            };
            let Some(fd) = fds.first() else { continue };
            match self.restore_instance(record, fd.as_raw_fd()).await {
                Ok(()) => {
                    restored += 1;
                    info!(slug, image_ref = %record.image_ref, "took over nydus mount from preserved fuse fd");
                }
                Err(e) => {
                    warn!(slug, image_ref = %record.image_ref, error = %e, "failed to take over mount; it may be stale");
                }
            }
        }
        restored
    }

    /// Recreate a fusedev daemon in upgrade mode and drive it through the
    /// `Takeover -> Restore -> Start` path, adopting the preserved `fuse_fd` and
    /// the on-disk state blob, so it resumes serving the still-mounted image.
    async fn restore_instance(
        &self,
        record: &DaemonStatusRecord,
        fuse_fd: std::os::fd::RawFd,
    ) -> Result<()> {
        if self.active_fs_driver() != FsDriverType::Fusedev {
            bail!("failover restore is only supported for the fusedev driver");
        }
        let image_ref_str = record.image_ref.as_str();
        let slug = record.slug.as_str();
        let bootstrap = record.bootstrap.clone();
        if !bootstrap.is_file() {
            bail!(
                "bootstrap {} for {image_ref_str} is gone",
                bootstrap.display()
            );
        }
        let state_path = self.failover_state_path(slug);
        let state = fs::read(&state_path)
            .with_context(|| format!("read failover state {}", state_path.display()))?;

        let parsed = parse_image_ref(image_ref_str)
            .with_context(|| format!("invalid image reference '{image_ref_str}'"))?;
        let daemon_root = self.daemons_root().join(slug);
        let mountpoint = daemon_root.join("mnt");
        let cache_dir = self.config.snapshotter.cache.work_dir.join(slug);
        fs::create_dir_all(&mountpoint)?;
        fs::create_dir_all(&cache_dir)?;

        let auth = self.resolve_auth(&parsed);
        let threads = self.config.snapshotter.daemon.threads.max(1) as u32;
        let bti = self.build_info.clone();

        let poll = Poll::new().context("failed to create mio Poll for daemon waker")?;
        let waker =
            Arc::new(Waker::new(poll.registry(), Token(1)).context("failed to create mio Waker")?);
        let poll = Arc::new(Mutex::new(poll));

        let cfg_v2 = build_daemon_config(&self.config, &parsed, &cache_dir, auth, slug)?;
        let cfg_json = serde_json::to_string(&cfg_v2).context("serialise ConfigV2 for nydusd")?;
        let vfs = create_vfs_backend(FsBackendType::Rafs, true, false)
            .context("create RAFS VFS backend")?;
        let mount_cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: bootstrap.display().to_string(),
            config: cfg_json,
            mountpoint: "/".to_string(),
            prefetch_files: runtime_prefetch_for_image(image_ref_str),
        };

        let mountpoint_str = mountpoint.display().to_string();
        let supervisor_sock = daemon_root.join("supervisor.sock");
        // `upgrade=true` together with a `Some(api_sock)` makes create_fuse_daemon
        // skip the fresh mount and leave the daemon in INIT, ready for takeover.
        let api_sock = daemon_root.join("api.sock");
        let daemon = create_fuse_daemon(
            &mountpoint_str,
            vfs,
            Some(supervisor_sock.display().to_string()),
            Some(slug.to_string()),
            threads,
            waker,
            Some(api_sock.as_path()),
            true,
            true,
            FailoverPolicy::Flush,
            Some(mount_cmd),
            bti,
        )
        .with_context(|| format!("create upgrade fuse daemon at {}", mountpoint.display()))?;

        // Replay (fd, state) into the daemon's restore() over the supervisor
        // socket, then start it serving on the existing kernel mount.
        let daemon_for_takeover = daemon.clone();
        let state_owned = state;
        blocking::unblock(move || {
            crate::failover::serve_on_restore(&supervisor_sock, fuse_fd, state_owned, || {
                daemon_for_takeover
                    .trigger_takeover()
                    .map_err(|e| anyhow::anyhow!("trigger_takeover: {e}"))
            })
        })
        .await
        .context("replay preserved fuse fd into daemon")?;

        daemon
            .trigger_start()
            .map_err(|e| anyhow::anyhow!("trigger_start: {e}"))?;
        wait_for_running_off_reactor(daemon.clone(), self.startup_timeout)
            .await
            .with_context(|| {
                format!("restored daemon for {image_ref_str} never reached RUNNING")
            })?;

        let instance = Arc::new(DaemonInstance {
            image_ref: image_ref_str.to_string(),
            mountpoint,
            bootstrap,
            daemon,
            refcount: AtomicUsize::new(record.refcount.max(1)),
            holders: StdMutex::new(HashSet::new()),
            _poll: poll,
            // The fd stays in systemd's store across restarts, so this daemon is
            // still recoverable by the next successor.
            failover_armed: AtomicBool::new(true),
        });
        self.instances
            .write()
            .await
            .insert(image_ref_str.to_string(), instance);
        Ok(())
    }

    fn active_fs_driver(&self) -> FsDriverType {
        self.config
            .snapshotter
            .fs_drivers
            .first()
            .map(|driver| driver.driver_type)
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

            match self.start_instance(&image_ref, &bootstrap, None).await {
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
        self.daemons_root().join(Self::RECORDS_DIRNAME)
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
            // In-process daemon: failover targets the snapshotter process itself,
            // so `kill -9` restarts it and the successor takes the mount over.
            pid: if live { std::process::id() } else { 0 },
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
    // Use the nix wrapper around `mount(2)` directly instead of shelling
    // out to `/sbin/mount`. Avoids arg-escaping foot-guns and lifts a
    // dependency on the host's mount CLI being on PATH. `MS_RDONLY`
    // covers the `-o ro` option; loop-back attachment for the disk image
    // happens inside the kernel for `erofs` when the source is a file.
    nix::mount::mount(
        Some(disk_image.as_path()),
        &mountpoint,
        Some("erofs"),
        nix::mount::MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "mount -t erofs -o ro,loop {} {} failed",
            disk_image.display(),
            mountpoint.display()
        )
    })?;
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
    nix::mount::umount(mountpoint).map_err(|errno| {
        io::Error::other(format!(
            "umount {} failed with {errno}",
            mountpoint.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn unmount_blockdev_erofs(_mountpoint: &Path) -> io::Result<()> {
    Ok(())
}

/// dm-verity mapping name for a tarfs image (`/dev/mapper/<name>`). Slug is
/// already filesystem-safe (alnum + `.-_`) and short, so it is a valid dm name.
fn tarfs_dm_name(slug: &str) -> String {
    format!("nydus-tarfs-{slug}")
}

/// Export the tarfs RAFS v6 bootstrap to a flat EROFS `.disk`, generating the
/// dm-verity hash tree when `verity` is set. Returns the verity parameters
/// (`Some`) when verity was generated, else `None`.
///
/// Idempotent + restart-safe: the verity parameters (which include the root
/// hash) are persisted next to the disk as `<disk>.verity.json`, so a
/// snapshotter restart can re-activate an existing image's dm-verity mapping
/// without re-exporting. The export itself is byte-compatible with an upstream
/// `nydus-image export --block --verity` artifact.
#[cfg(target_os = "linux")]
fn export_tarfs_image(
    entry: nydus_api::BlobCacheEntry,
    disk_image: PathBuf,
    threads: u32,
    verity: bool,
) -> Result<Option<TarfsVerityParams>> {
    let sidecar = verity_sidecar_path(&disk_image);
    let disk_ready =
        disk_image.is_file() && disk_image.metadata().map(|m| m.len()).unwrap_or(0) > 0;
    if disk_ready {
        if !verity {
            return Ok(None);
        }
        if let Some(info) = load_verity_sidecar(&sidecar) {
            return Ok(Some(info));
        }
        // Disk present but no cached verity params — fall through and re-export
        // to regenerate them (the export overwrites the disk in place).
    }
    if let Some(parent) = disk_image.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create tarfs disk directory {}", parent.display())
        })?;
    }
    let info = BlockDevice::export(
        entry,
        Some(disk_image.display().to_string()),
        None,
        threads,
        verity,
    )
    .with_context(|| format!("failed to export tarfs disk image {}", disk_image.display()))?
    .map(|v| TarfsVerityParams {
        data_block_size: v.data_block_size,
        data_blocks: v.data_blocks,
        hash_offset: v.hash_offset,
        root_digest: v.root_digest,
    });
    if let Some(info) = info.as_ref() {
        store_verity_sidecar(&sidecar, info);
    }
    Ok(info)
}

#[cfg(not(target_os = "linux"))]
fn export_tarfs_image(
    _entry: nydus_api::BlobCacheEntry,
    _disk_image: PathBuf,
    _threads: u32,
    _verity: bool,
) -> Result<Option<TarfsVerityParams>> {
    bail!("tarfs EROFS export requires Linux")
}

#[cfg(target_os = "linux")]
fn verity_sidecar_path(disk_image: &Path) -> PathBuf {
    let mut name = disk_image.as_os_str().to_os_string();
    name.push(".verity.json");
    PathBuf::from(name)
}

#[cfg(target_os = "linux")]
fn load_verity_sidecar(path: &Path) -> Option<TarfsVerityParams> {
    let bytes = fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(TarfsVerityParams {
        data_block_size: v.get("data_block_size")?.as_u64()?,
        data_blocks: v.get("data_blocks")?.as_u64()? as u32,
        hash_offset: v.get("hash_offset")?.as_u64()?,
        root_digest: v.get("root_digest")?.as_str()?.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn store_verity_sidecar(path: &Path, info: &TarfsVerityParams) {
    let json = serde_json::json!({
        "data_block_size": info.data_block_size,
        "data_blocks": info.data_blocks,
        "hash_offset": info.hash_offset,
        "root_digest": info.root_digest,
    });
    if let Err(e) = serde_json::to_vec(&json)
        .map_err(io::Error::other)
        .and_then(|b| fs::write(path, b))
    {
        warn!(path = %path.display(), error = %e, "failed to persist tarfs verity sidecar; a restart will re-export");
    }
}

/// Attach + verity-open (if `verity_info` is `Some`) and mount the tarfs EROFS
/// image read-only. On the verity path the `.disk` is attached to a loop
/// device, `veritysetup open` maps `/dev/mapper/<dm_name>` over it (using the
/// standard upstream parameters), and that dm device is mounted; the returned
/// [`TarfsMount`] records both so teardown can reverse them. On the plain path
/// the kernel attaches the loop implicitly at `mount -t erofs` time, exactly
/// like the blockdev driver.
#[cfg(target_os = "linux")]
fn setup_and_mount_tarfs(
    cfg: &crate::config::TarfsConfig,
    disk_image: &Path,
    mountpoint: &Path,
    dm_name: &str,
    verity_info: Option<&TarfsVerityParams>,
) -> Result<TarfsMount> {
    fs::create_dir_all(mountpoint).with_context(|| {
        format!(
            "failed to create tarfs EROFS mountpoint {}",
            mountpoint.display()
        )
    })?;
    if is_mounted_at(mountpoint) {
        // Already mounted (e.g. a crash-recovery re-entry). The loop/dm
        // identities can't be recovered here; teardown still umounts, and the
        // leftover loop/dm are cleaned by the reconciler / next boot.
        return Ok(TarfsMount::default());
    }

    let Some(verity) = verity_info else {
        // Plain path: kernel-loop erofs mount of the .disk, no dm-verity.
        mount_blockdev_erofs(disk_image.to_path_buf(), mountpoint.to_path_buf())?;
        return Ok(TarfsMount::default());
    };

    // 1. Attach the .disk to a loop device (veritysetup needs a block device).
    let loop_dev = losetup_attach(cfg, disk_image)?;
    let mut mount = TarfsMount {
        loop_dev: Some(loop_dev.clone()),
        verity_name: None,
    };

    // 2. veritysetup open over the loop device (hash tree is in the same file).
    if let Err(e) = veritysetup_open(cfg, &loop_dev, dm_name, verity) {
        let _ = teardown_tarfs_mount(cfg, &mount, mountpoint);
        return Err(e);
    }
    mount.verity_name = Some(dm_name.to_string());

    // 3. Mount the verified dm device read-only.
    let dm_path = PathBuf::from(format!("/dev/mapper/{dm_name}"));
    if let Err(e) = mount_blockdev_erofs(dm_path, mountpoint.to_path_buf()) {
        let _ = teardown_tarfs_mount(cfg, &mount, mountpoint);
        return Err(e);
    }
    Ok(mount)
}

#[cfg(not(target_os = "linux"))]
fn setup_and_mount_tarfs(
    _cfg: &crate::config::TarfsConfig,
    _disk_image: &Path,
    _mountpoint: &Path,
    _dm_name: &str,
    _verity_info: Option<&TarfsVerityParams>,
) -> Result<TarfsMount> {
    bail!("tarfs mount requires Linux")
}

#[cfg(target_os = "linux")]
fn losetup_attach(cfg: &crate::config::TarfsConfig, disk_image: &Path) -> Result<String> {
    let output = std::process::Command::new(&cfg.losetup_path)
        .args(["--find", "--show", "--read-only"])
        .arg(disk_image)
        .output()
        .with_context(|| format!("failed to spawn {}", cfg.losetup_path.display()))?;
    if !output.status.success() {
        bail!(
            "losetup --find --show {} failed ({}): {}",
            disk_image.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dev.is_empty() {
        bail!("losetup returned an empty loop device path");
    }
    Ok(dev)
}

#[cfg(target_os = "linux")]
fn veritysetup_open(
    cfg: &crate::config::TarfsConfig,
    loop_dev: &str,
    dm_name: &str,
    v: &TarfsVerityParams,
) -> Result<()> {
    // Standard upstream parameters (see docs/nydus-image.md): data device and
    // hash device are the same loop device; the hash tree lives after
    // `hash_offset` in that file. Positional args: <data_dev> <name> <hash_dev> <root>.
    let output = std::process::Command::new(&cfg.veritysetup_path)
        .args([
            "open",
            "--no-superblock",
            "--format=1",
            "-s",
            "",
            "--hash=sha256",
            &format!("--data-block-size={}", v.data_block_size),
            "--hash-block-size=4096",
            &format!("--data-blocks={}", v.data_blocks),
            &format!("--hash-offset={}", v.hash_offset),
            loop_dev,
            dm_name,
            loop_dev,
            &v.root_digest,
        ])
        .output()
        .with_context(|| format!("failed to spawn {}", cfg.veritysetup_path.display()))?;
    if !output.status.success() {
        bail!(
            "veritysetup open {dm_name} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Reverse [`setup_and_mount_tarfs`]: umount, close the dm-verity mapping, then
/// detach the loop device. Every step is best-effort and independent so a
/// failure in one still attempts the rest.
#[cfg(target_os = "linux")]
fn teardown_tarfs_mount(
    cfg: &crate::config::TarfsConfig,
    mount: &TarfsMount,
    mountpoint: &Path,
) -> io::Result<()> {
    let mut first_err: Option<io::Error> = None;
    if let Err(e) = unmount_blockdev_erofs(mountpoint) {
        warn!(mountpoint = %mountpoint.display(), error = %e, "tarfs umount failed");
        first_err.get_or_insert(e);
    }
    if let Some(name) = mount.verity_name.as_deref() {
        let out = std::process::Command::new(&cfg.veritysetup_path)
            .args(["close", name])
            .output();
        match out {
            Ok(o) if !o.status.success() => {
                warn!(
                    dm = name,
                    "veritysetup close failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => warn!(dm = name, error = %e, "failed to spawn veritysetup close"),
            _ => {}
        }
    }
    if let Some(dev) = mount.loop_dev.as_deref() {
        let out = std::process::Command::new(&cfg.losetup_path)
            .args(["-d", dev])
            .output();
        match out {
            Ok(o) if !o.status.success() => {
                warn!(
                    loop_dev = dev,
                    "losetup -d failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => warn!(loop_dev = dev, error = %e, "failed to spawn losetup -d"),
            _ => {}
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn teardown_tarfs_mount(
    _cfg: &crate::config::TarfsConfig,
    _mount: &TarfsMount,
    _mountpoint: &Path,
) -> io::Result<()> {
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

/// Poll the daemon state machine until RUNNING (or failure/timeout).
///
/// This can spin for up to `timeout` (30 s) and the ensure paths run on the
/// shared compio gRPC runtime, so callers MUST go through
/// [`wait_for_running_off_reactor`] — a `thread::sleep` inline on the reactor
/// would stall every in-flight RPC behind one slow daemon start.
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

/// Run [`wait_for_running`] on the blocking pool. Deliberately NOT a
/// `compio::time::sleep` loop: compio futures are `!Send`, and the ensure
/// paths must stay `Send` for the tonic `Snapshots` trait's futures.
async fn wait_for_running_off_reactor(
    daemon: Arc<dyn NydusDaemon>,
    timeout: Duration,
) -> Result<()> {
    blocking::unblock(move || wait_for_running(&*daemon, timeout)).await
}

/// Runtime directory for failover supervisor sockets. Kept short and on a
/// tmpfs (`/run`) because AF_UNIX paths are capped at ~108 bytes — the per-image
/// daemon dir `{root}/daemons/<slug>/` already blows past that, so the socket
/// can't live there.
const FAILOVER_SOCK_DIR: &str = "/run/nydus-failover";

/// Path of a daemon's transient failover supervisor socket (used only during
/// capture-at-mount and replay-at-restore). Short by construction so the bind
/// stays under the AF_UNIX `sun_path` limit.
fn supervisor_sock_path(slug: &str) -> PathBuf {
    PathBuf::from(FAILOVER_SOCK_DIR).join(format!("{slug}.sock"))
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

    fn test_instance() -> DaemonInstance {
        let daemon: Arc<dyn NydusDaemon> = Arc::new(BlockdevDaemon::new(
            "holder-test".to_string(),
            PathBuf::from("/tmp/nydus-holder-test"),
            BuildTimeInfo {
                package_ver: "test".to_string(),
                git_commit: String::new(),
                build_time: String::new(),
                profile: "test".to_string(),
                rustc: String::new(),
            },
        ));
        DaemonInstance {
            image_ref: "img".into(),
            mountpoint: PathBuf::from("/tmp/nydus-holder-test"),
            bootstrap: PathBuf::from("/tmp/bootstrap"),
            daemon,
            refcount: AtomicUsize::new(0),
            holders: StdMutex::new(HashSet::new()),
            _poll: Arc::new(Mutex::new(Poll::new().unwrap())),
            failover_armed: AtomicBool::new(false),
        }
    }

    #[test]
    fn holder_acquisition_is_idempotent_per_key() {
        // Regression guard: repeated Mounts RPCs for the same snapshot must
        // not inflate the refcount — that drift makes daemons immortal.
        let inst = test_instance();
        inst.acquire_holder("snap-a");
        inst.acquire_holder("snap-a");
        inst.acquire_holder("snap-a");
        inst.acquire_holder("snap-b");
        assert_eq!(inst.refcount.load(Ordering::SeqCst), 2);

        // Releasing an unknown key is a no-op (no ballast present).
        assert_eq!(inst.release_holder("never-acquired"), 2);
        assert_eq!(inst.release_holder("snap-a"), 1);
        // Double-release of the same key cannot underflow another key's ref.
        assert_eq!(inst.release_holder("snap-a"), 1);
        assert_eq!(inst.release_holder("snap-b"), 0);
    }

    #[test]
    fn release_drains_restore_ballast_for_unknown_keys() {
        // A restored record carries only a count; releases for pre-restart
        // keys (which are not individually known) must still drain it to zero
        // so restored daemons can tear down.
        let inst = test_instance();
        inst.refcount.store(2, Ordering::SeqCst);
        assert_eq!(inst.release_holder("old-snap-1"), 1);
        assert_eq!(inst.release_holder("old-snap-2"), 0);
        assert_eq!(inst.release_holder("old-snap-3"), 0);
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

    fn sample_record(bootstrap: PathBuf) -> DaemonStatusRecord {
        DaemonStatusRecord {
            image_ref: "registry.local/team/app:1".to_string(),
            slug: "abc-app".to_string(),
            mountpoint: PathBuf::from("/tmp/nydus-x/mnt"),
            bootstrap,
            refcount: 1,
            state: "RUNNING".to_string(),
            live: true,
            updated_at: 0,
            pid: 0,
        }
    }

    #[test]
    fn failover_state_path_is_under_daemon_slug() {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.root = PathBuf::from("/var/lib/nydus");
        let supervisor = DaemonSupervisor::new(config);
        assert_eq!(
            supervisor.failover_state_path("abc-app"),
            PathBuf::from("/var/lib/nydus/daemons/abc-app/upgrade.state"),
        );
    }

    #[test]
    fn restore_from_store_returns_zero_without_preserved_fds() {
        // No systemd socket-activation env => nothing to take over. Guard on the
        // env being genuinely absent so we never clobber a real activation
        // environment and stay race-free under nextest's process-per-test model.
        if std::env::var_os("LISTEN_FDS").is_some() {
            return;
        }
        let supervisor = DaemonSupervisor::new(SnapshotterConfig::default());
        let restored = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(supervisor.restore_from_store());
        assert_eq!(restored, 0);
    }

    #[test]
    fn restore_instance_rejects_non_fusedev_driver() {
        // Default driver chain is [Fanotify, Blockdev, Fusedev] -> active=Fanotify,
        // so failover restore (fusedev-only) must bail before touching the fd.
        let supervisor = DaemonSupervisor::new(SnapshotterConfig::default());
        assert_ne!(supervisor.active_fs_driver(), FsDriverType::Fusedev);
        let record = sample_record(PathBuf::from("/nonexistent/bootstrap.boot"));
        let err = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(supervisor.restore_instance(&record, -1))
            .unwrap_err();
        assert!(
            err.to_string().contains("fusedev"),
            "expected fusedev-driver guard, got: {err}"
        );
    }

    #[test]
    fn restore_instance_bails_on_missing_bootstrap() {
        let mut config = SnapshotterConfig::default();
        config.snapshotter.fs_drivers.swap(0, 2); // promote Fusedev to active
        let supervisor = DaemonSupervisor::new(config);
        assert_eq!(supervisor.active_fs_driver(), FsDriverType::Fusedev);
        let record = sample_record(PathBuf::from("/nonexistent/bootstrap.boot"));
        let err = compio::runtime::Runtime::new()
            .unwrap()
            .block_on(supervisor.restore_instance(&record, -1))
            .unwrap_err();
        assert!(
            err.to_string().contains("bootstrap") && err.to_string().contains("gone"),
            "expected missing-bootstrap guard, got: {err}"
        );
    }
}
